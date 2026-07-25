package coremodel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxResponseBytes = 4 << 20
const maxRequestBytes = 2 << 20

var (
	ErrProviderUnavailable = errors.New("model provider is unavailable")
	ErrInvalidResponse     = errors.New("invalid model provider response")
	ErrStreamTruncated     = errors.New("model provider stream terminated before completion")
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}
type ClientOption func(*httpOptions)
type httpOptions struct {
	client  HTTPClient
	timeout time.Duration
}

func WithHTTPClient(c HTTPClient) ClientOption {
	return func(o *httpOptions) {
		if c != nil {
			o.client = c
		}
	}
}
func WithTimeout(d time.Duration) ClientOption {
	return func(o *httpOptions) {
		if d > 0 {
			o.timeout = d
		}
	}
}

type providerClient struct {
	profile Profile
	http    HTTPClient
	timeout time.Duration
}

func NewClient(profile Profile, options ...ClientOption) (Client, error) {
	p, err := ValidateProfile(profile)
	if err != nil {
		return nil, err
	}
	opts := httpOptions{timeout: 90 * time.Second}
	for _, o := range options {
		if o != nil {
			o(&opts)
		}
	}
	if opts.client == nil {
		opts.client = &http.Client{Timeout: opts.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return &providerClient{profile: p, http: opts.client, timeout: opts.timeout}, nil
}

func NewConnectionTester(options ...ClientOption) ConnectionTester {
	opts := httpOptions{timeout: 15 * time.Second}
	for _, o := range options {
		if o != nil {
			o(&opts)
		}
	}
	if opts.client == nil {
		opts.client = &http.Client{Timeout: opts.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return &connectionTester{http: opts.client, timeout: opts.timeout}
}

type connectionTester struct {
	http    HTTPClient
	timeout time.Duration
}

func (t *connectionTester) TestConnection(ctx context.Context, profile Profile) error {
	if t.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.timeout)
		defer cancel()
	}
	p, err := ValidateProfile(profile)
	if err != nil {
		return err
	}
	endpoint := connectionURL(p)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ErrProviderUnavailable
	}
	setHeaders(req, p)
	resp, err := t.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrProviderUnavailable
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ErrProviderUnavailable
	}
	return nil
}

func connectionURL(p Profile) string {
	switch p.Provider {
	case ProviderOpenAICompatible:
		return joinURL(p.BaseURL, "models")
	case ProviderAnthropic:
		if strings.HasSuffix(strings.TrimRight(p.BaseURL, "/"), "/v1") {
			return joinURL(p.BaseURL, "models")
		}
		return joinURL(p.BaseURL, "v1/models")
	case ProviderGemini:
		return joinURL(p.BaseURL, "v1beta/models/"+url.PathEscape(p.Model))
	default:
		return p.BaseURL
	}
}

func joinURL(base, suffix string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(suffix, "/")
}

func setHeaders(req *http.Request, p Profile) {
	switch p.Provider {
	case ProviderAnthropic:
		req.Header.Set("x-api-key", p.APIKey)
		req.Header.Set("anthropic-version", "2023-06-01")
	case ProviderGemini:
		req.Header.Set("x-goog-api-key", p.APIKey)
	default:
		req.Header.Set("Authorization", "Bearer "+p.APIKey)
	}
}

func (c *providerClient) endpoint(stream bool) string {
	switch c.profile.Provider {
	case ProviderAnthropic:
		path := "v1/messages"
		if strings.HasSuffix(c.profile.BaseURL, "/v1") {
			path = "messages"
		}
		return joinURL(c.profile.BaseURL, path)
	case ProviderGemini:
		suffix := "v1beta/models/" + url.PathEscape(c.profile.Model) + ":generateContent"
		if stream {
			suffix = "v1beta/models/" + url.PathEscape(c.profile.Model) + ":streamGenerateContent?alt=sse"
		}
		return joinURL(c.profile.BaseURL, suffix)
	default:
		return joinURL(c.profile.BaseURL, "chat/completions")
	}
}

func (c *providerClient) Generate(ctx context.Context, request CompletionRequest) (Completion, error) {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	if err := validateRawRequestBudget(c.profile, request); err != nil {
		return Completion{}, err
	}
	if err := ValidateCompletionRequest(request); err != nil {
		return Completion{}, err
	}
	if err := validateRequestBudget(c.profile, request); err != nil {
		return Completion{}, err
	}
	payload, err := c.payload(request, false)
	if err != nil {
		return Completion{}, err
	}
	body, status, headers, err := c.do(ctx, payload, false)
	if err != nil {
		return Completion{}, err
	}
	if status < 200 || status >= 300 {
		return Completion{}, ErrProviderUnavailable
	}
	return decodeCompletion(c.profile.Provider, body, headers)
}

func (c *providerClient) Stream(ctx context.Context, request CompletionRequest) (Stream, error) {
	var streamCtx context.Context
	var cancel context.CancelFunc
	if c.timeout > 0 {
		streamCtx, cancel = context.WithTimeout(ctx, c.timeout)
	} else {
		streamCtx, cancel = context.WithCancel(ctx)
	}
	defer func() {
		if cancel != nil {
			cancel()
		}
	}()
	if err := validateRawRequestBudget(c.profile, request); err != nil {
		cancel()
		return nil, err
	}
	if err := ValidateCompletionRequest(request); err != nil {
		cancel()
		return nil, err
	}
	if err := validateRequestBudget(c.profile, request); err != nil {
		cancel()
		return nil, err
	}
	payload, err := c.payload(request, true)
	if err != nil {
		cancel()
		return nil, err
	}
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(streamCtx, http.MethodPost, c.endpoint(true), bytes.NewReader(reqBody))
	if err != nil {
		cancel()
		return nil, ErrProviderUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	setHeaders(req, c.profile)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := c.http.Do(req)
	if err != nil {
		cancel()
		if streamCtx.Err() != nil {
			return nil, streamCtx.Err()
		}
		return nil, ErrProviderUnavailable
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		cancel()
		resp.Body.Close()
		return nil, ErrProviderUnavailable
	}
	source := &countingReader{r: io.LimitReader(resp.Body, maxResponseBytes+1)}
	stream := &sseStream{reader: bufio.NewReader(source), body: resp.Body, provider: c.profile.Provider, cancel: cancel, source: source}
	cancel = nil // ownership transfers to the returned stream
	return stream, nil
}

func (c *providerClient) do(ctx context.Context, payload any, stream bool) ([]byte, int, http.Header, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(stream), bytes.NewReader(b))
	if err != nil {
		return nil, 0, nil, ErrProviderUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	setHeaders(req, c.profile)
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, nil, ctx.Err()
		}
		return nil, 0, nil, ErrProviderUnavailable
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, 0, nil, ErrProviderUnavailable
	}
	if len(body) > maxResponseBytes {
		return nil, 0, nil, ErrProviderUnavailable
	}
	return body, resp.StatusCode, resp.Header, nil
}

func (c *providerClient) payload(r CompletionRequest, stream bool) (any, error) {
	switch c.profile.Provider {
	case ProviderAnthropic:
		return anthropicPayload(c.profile, r, stream), nil
	case ProviderGemini:
		return geminiPayload(c.profile, r), nil
	default:
		return openAIPayload(c.profile, r, stream), nil
	}
}

func openAIPayload(p Profile, r CompletionRequest, stream bool) map[string]any {
	messages := r.Messages
	if p.SystemPrompt != "" {
		messages = append([]Message{{Role: RoleSystem, Content: p.SystemPrompt}}, messages...)
	}
	m := map[string]any{"model": p.Model, "messages": openAIMessages(messages), "stream": stream}
	if p.Temperature != nil {
		m["temperature"] = *p.Temperature
	}
	if p.TopP != nil {
		m["top_p"] = *p.TopP
	}
	if p.MaxOutputTokens > 0 {
		m["max_tokens"] = p.MaxOutputTokens
	}
	if p.ReasoningEffort != "" {
		m["reasoning_effort"] = p.ReasoningEffort
	}
	if len(r.Tools) > 0 {
		m["tools"] = openAITools(r.Tools)
	}
	return m
}
func openAIMessages(messages []Message) []any {
	out := make([]any, 0, len(messages))
	for _, msg := range messages {
		entry := map[string]any{"role": string(msg.Role), "content": msg.Content}
		if msg.Name != "" {
			entry["name"] = msg.Name
		}
		if msg.ToolCallID != "" {
			entry["tool_call_id"] = msg.ToolCallID
		}
		if len(msg.ToolCalls) > 0 {
			calls := make([]any, 0, len(msg.ToolCalls))
			for _, call := range msg.ToolCalls {
				callType := call.Type
				if callType == "" {
					callType = "function"
				}
				calls = append(calls, map[string]any{"id": call.ID, "type": callType, "function": map[string]any{"name": call.Function.Name, "arguments": call.Function.Arguments}})
			}
			entry["tool_calls"] = calls
		}
		out = append(out, entry)
	}
	return out
}
func openAITools(tools []Tool) []any {
	out := make([]any, 0, len(tools))
	for _, t := range tools {
		out = append(out, map[string]any{"type": "function", "function": map[string]any{"name": t.Name, "description": t.Description, "parameters": t.InputSchema}})
	}
	return out
}

func anthropicPayload(p Profile, r CompletionRequest, stream bool) map[string]any {
	messages := make([]map[string]any, 0, len(r.Messages))
	system := p.SystemPrompt
	for _, m := range r.Messages {
		if m.Role == RoleSystem {
			if system != "" {
				system += "\n"
			}
			system += m.Content
			continue
		}
		switch m.Role {
		case RoleTool:
			messages = append(messages, map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": m.ToolCallID, "content": m.Content}}})
		case RoleAssistant:
			blocks := make([]any, 0, len(m.ToolCalls)+1)
			if m.Content != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": m.Content})
			}
			for _, call := range m.ToolCalls {
				var input map[string]any
				if json.Unmarshal([]byte(call.Function.Arguments), &input) != nil {
					input = map[string]any{}
				}
				id := call.ID
				if id == "" {
					id = fmt.Sprintf("tool-%d", len(blocks))
				}
				blocks = append(blocks, map[string]any{"type": "tool_use", "id": id, "name": call.Function.Name, "input": input})
			}
			messages = append(messages, map[string]any{"role": "assistant", "content": blocks})
		default:
			messages = append(messages, map[string]any{"role": string(m.Role), "content": m.Content})
		}
	}
	m := map[string]any{"model": p.Model, "messages": messages, "max_tokens": p.MaxOutputTokens, "stream": stream}
	if m["max_tokens"] == 0 {
		m["max_tokens"] = 1024
	}
	if system != "" {
		m["system"] = system
	}
	if p.Temperature != nil {
		m["temperature"] = *p.Temperature
	}
	if p.TopP != nil {
		m["top_p"] = *p.TopP
	}
	if len(r.Tools) > 0 {
		ts := make([]any, 0, len(r.Tools))
		for _, t := range r.Tools {
			ts = append(ts, map[string]any{"name": t.Name, "description": t.Description, "input_schema": t.InputSchema})
		}
		m["tools"] = ts
	}
	return m
}

func geminiPayload(p Profile, r CompletionRequest) map[string]any {
	contents := make([]any, 0, len(r.Messages))
	systemParts := make([]any, 0, 1)
	if p.SystemPrompt != "" {
		systemParts = append(systemParts, map[string]any{"text": p.SystemPrompt})
	}
	for _, m := range r.Messages {
		if m.Role == RoleSystem {
			systemParts = append(systemParts, map[string]any{"text": m.Content})
			continue
		}
		role := "user"
		if m.Role == RoleAssistant {
			role = "model"
		}
		parts := make([]any, 0, len(m.ToolCalls)+1)
		if m.Content != "" {
			parts = append(parts, map[string]any{"text": m.Content})
		}
		if m.Role == RoleTool {
			var response map[string]any
			if json.Unmarshal([]byte(m.Content), &response) != nil {
				response = map[string]any{"content": m.Content}
			}
			name := m.Name
			if name == "" {
				name = m.ToolCallID
			}
			parts = []any{map[string]any{"functionResponse": map[string]any{"name": name, "response": response}}}
			role = "user"
		}
		for _, call := range m.ToolCalls {
			var args map[string]any
			if json.Unmarshal([]byte(call.Function.Arguments), &args) != nil {
				args = map[string]any{}
			}
			parts = append(parts, map[string]any{"functionCall": map[string]any{"name": call.Function.Name, "args": args}})
		}
		contents = append(contents, map[string]any{"role": role, "parts": parts})
	}
	m := map[string]any{"contents": contents}
	if len(systemParts) > 0 {
		m["systemInstruction"] = map[string]any{"parts": systemParts}
	}
	gc := map[string]any{}
	if p.Temperature != nil {
		gc["temperature"] = *p.Temperature
	}
	if p.TopP != nil {
		gc["topP"] = *p.TopP
	}
	if p.MaxOutputTokens > 0 {
		gc["maxOutputTokens"] = p.MaxOutputTokens
	}
	if len(gc) > 0 {
		m["generationConfig"] = gc
	}
	if len(r.Tools) > 0 {
		fds := make([]any, 0, len(r.Tools))
		for _, t := range r.Tools {
			fds = append(fds, map[string]any{"name": t.Name, "description": t.Description, "parameters": t.InputSchema})
		}
		m["tools"] = []any{map[string]any{"functionDeclarations": fds}}
	}
	return m
}

func decodeCompletion(provider ModelProvider, body []byte, _ http.Header) (Completion, error) {
	var root map[string]any
	if json.Unmarshal(body, &root) != nil {
		return Completion{}, ErrInvalidResponse
	}
	switch provider {
	case ProviderAnthropic:
		var msg struct {
			Content []struct {
				Type  string         `json:"type"`
				Text  string         `json:"text"`
				ID    string         `json:"id"`
				Name  string         `json:"name"`
				Input map[string]any `json:"input"`
			} `json:"content"`
			Usage struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(body, &msg) != nil {
			return Completion{}, ErrInvalidResponse
		}
		var text string
		var calls []ToolCall
		for i, b := range msg.Content {
			if b.Type == "text" {
				text += b.Text
				continue
			}
			if b.Type == "tool_use" {
				a, _ := json.Marshal(b.Input)
				id := b.ID
				if id == "" {
					id = fmt.Sprintf("tool-%d", i)
				}
				calls = append(calls, ToolCall{ID: id, Type: "function", Function: FunctionCall{Name: b.Name, Arguments: string(a)}})
			}
		}
		return Completion{Message: Message{Role: RoleAssistant, Content: text, ToolCalls: calls}, Usage: Usage{InputTokens: msg.Usage.InputTokens, OutputTokens: msg.Usage.OutputTokens, TotalTokens: msg.Usage.InputTokens + msg.Usage.OutputTokens}}, nil
	case ProviderGemini:
		var g struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text         string `json:"text"`
						FunctionCall *struct {
							Name string         `json:"name"`
							Args map[string]any `json:"args"`
						} `json:"functionCall"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
			Usage struct {
				PromptTokenCount     int `json:"promptTokenCount"`
				CandidatesTokenCount int `json:"candidatesTokenCount"`
			} `json:"usageMetadata"`
		}
		if json.Unmarshal(body, &g) != nil || len(g.Candidates) == 0 {
			return Completion{}, ErrInvalidResponse
		}
		var msg Message
		msg.Role = RoleAssistant
		for i, part := range g.Candidates[0].Content.Parts {
			msg.Content += part.Text
			if part.FunctionCall != nil {
				a, _ := json.Marshal(part.FunctionCall.Args)
				msg.ToolCalls = append(msg.ToolCalls, ToolCall{ID: fmt.Sprintf("tool-%d", i), Type: "function", Function: FunctionCall{Name: part.FunctionCall.Name, Arguments: string(a)}})
			}
		}
		return Completion{Message: msg, Usage: Usage{InputTokens: g.Usage.PromptTokenCount, OutputTokens: g.Usage.CandidatesTokenCount, TotalTokens: g.Usage.PromptTokenCount + g.Usage.CandidatesTokenCount}}, nil
	default:
		var o struct {
			Choices []struct {
				Message struct {
					Role      string `json:"role"`
					Content   any    `json:"content"`
					ToolCalls []struct {
						ID       string `json:"id"`
						Type     string `json:"type"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"message"`
			} `json:"choices"`
			Usage struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
				TotalTokens      int `json:"total_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(body, &o) != nil || len(o.Choices) == 0 {
			return Completion{}, ErrInvalidResponse
		}
		ch := o.Choices[0].Message
		content, _ := ch.Content.(string)
		msg := Message{Role: RoleAssistant, Content: content}
		for _, tc := range ch.ToolCalls {
			msg.ToolCalls = append(msg.ToolCalls, ToolCall{ID: tc.ID, Type: tc.Type, Function: FunctionCall{Name: tc.Function.Name, Arguments: tc.Function.Arguments}})
		}
		return Completion{Message: msg, Usage: Usage{InputTokens: o.Usage.PromptTokens, OutputTokens: o.Usage.CompletionTokens, TotalTokens: o.Usage.TotalTokens}}, nil
	}
}

type sseStream struct {
	reader     *bufio.Reader
	body       io.ReadCloser
	provider   ModelProvider
	closed     bool
	toolIDs    map[int]string
	nextToolID int
	cancel     context.CancelFunc
	source     *countingReader
	terminal   bool
}

type countingReader struct {
	r io.Reader
	n int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += int64(n)
	return n, err
}

func (s *sseStream) Close() error {
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	return s.body.Close()
}
func (s *sseStream) finish() {
	if !s.closed {
		s.closed = true
		if s.cancel != nil {
			s.cancel()
		}
		_ = s.body.Close()
	}
}
func (s *sseStream) Recv() (Delta, error) {
	for {
		if s.closed {
			return Delta{}, io.EOF
		}
		if s.terminal {
			s.finish()
			return Delta{}, io.EOF
		}
		line, err := s.reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				s.finish()
				if s.source != nil && s.source.n > maxResponseBytes {
					return Delta{}, ErrStreamTruncated
				}
				if !s.terminal {
					return Delta{}, ErrStreamTruncated
				}
				return Delta{}, io.EOF
			}
			s.finish()
			return Delta{}, ErrProviderUnavailable
		}
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			if s.provider != ProviderOpenAICompatible {
				s.finish()
				return Delta{}, ErrProviderUnavailable
			}
			s.terminal = true
			s.finish()
			return Delta{}, io.EOF
		}
		var event map[string]any
		if json.Unmarshal([]byte(data), &event) != nil {
			s.finish()
			return Delta{}, ErrInvalidResponse
		}
		if _, ok := event["error"]; ok {
			s.finish()
			return Delta{}, ErrProviderUnavailable
		}
		if typ, _ := event["type"].(string); typ == "error" {
			s.finish()
			return Delta{}, ErrProviderUnavailable
		}
		if streamTerminal(s.provider, event) {
			s.terminal = true
		}
		if s.toolIDs == nil {
			s.toolIDs = make(map[int]string)
		}
		if d, ok := decodeDeltaStateCounter(s.provider, []byte(data), s.toolIDs, &s.nextToolID); ok {
			return d, nil
		}
		if s.terminal {
			s.finish()
			return Delta{}, io.EOF
		}
	}
}

func streamTerminal(provider ModelProvider, event map[string]any) bool {
	switch provider {
	case ProviderAnthropic:
		typ, _ := event["type"].(string)
		return typ == "message_stop"
	case ProviderGemini:
		candidates, _ := event["candidates"].([]any)
		if len(candidates) == 0 {
			return false
		}
		c, _ := candidates[0].(map[string]any)
		if reason, ok := c["finishReason"].(string); ok && reason != "" {
			return true
		}
	}
	return false
}
func decodeDelta(provider ModelProvider, body []byte) (Delta, bool) {
	return decodeDeltaState(provider, body, make(map[int]string))
}

func decodeDeltaState(provider ModelProvider, body []byte, toolIDs map[int]string) (Delta, bool) {
	next := 0
	return decodeDeltaStateCounter(provider, body, toolIDs, &next)
}

func decodeDeltaStateCounter(provider ModelProvider, body []byte, toolIDs map[int]string, nextToolID *int) (Delta, bool) {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return Delta{}, false
	}
	switch provider {
	case ProviderAnthropic:
		typ, _ := m["type"].(string)
		if typ == "content_block_start" {
			idx, _ := m["index"].(float64)
			block, _ := m["content_block"].(map[string]any)
			if block["type"] != "tool_use" {
				return Delta{}, false
			}
			id, _ := block["id"].(string)
			if id == "" {
				id = fmt.Sprintf("tool-%d", *nextToolID)
				(*nextToolID)++
			}
			toolIDs[int(idx)] = id
			name, _ := block["name"].(string)
			return Delta{ToolCalls: []ToolCall{{Index: int(idx), ID: id, Type: "function", Function: FunctionCall{Name: name}}}}, true
		}
		if typ == "content_block_delta" {
			idx, _ := m["index"].(float64)
			d, _ := m["delta"].(map[string]any)
			t, _ := d["text"].(string)
			if t != "" {
				return Delta{Content: t}, true
			}
			partial, _ := d["partial_json"].(string)
			if partial != "" {
				id := toolIDs[int(idx)]
				if id == "" {
					id = fmt.Sprintf("tool-%d", *nextToolID)
					(*nextToolID)++
					toolIDs[int(idx)] = id
				}
				return Delta{ToolCalls: []ToolCall{{Index: int(idx), ID: id, Type: "function", Function: FunctionCall{Arguments: partial}}}}, true
			}
		}
		return Delta{}, false
	case ProviderGemini:
		c, _ := m["candidates"].([]any)
		if len(c) == 0 {
			return Delta{}, false
		}
		var content strings.Builder
		calls := make([]ToolCall, 0)
		if len(c) > 1 {
			c = c[:1]
		}
		for _, rawCandidate := range c {
			cm, _ := rawCandidate.(map[string]any)
			cont, _ := cm["content"].(map[string]any)
			parts, _ := cont["parts"].([]any)
			for _, rawPart := range parts {
				part, _ := rawPart.(map[string]any)
				if text, _ := part["text"].(string); text != "" {
					content.WriteString(text)
				}
				fc, _ := part["functionCall"].(map[string]any)
				if fc == nil {
					continue
				}
				name, _ := fc["name"].(string)
				args, _ := json.Marshal(fc["args"])
				idx := *nextToolID
				id := fmt.Sprintf("tool-%d", idx)
				(*nextToolID)++
				calls = append(calls, ToolCall{Index: idx, ID: id, Type: "function", Function: FunctionCall{Name: name, Arguments: string(args)}})
			}
		}
		if content.Len() > 0 || len(calls) > 0 {
			return Delta{Content: content.String(), ToolCalls: calls}, true
		}
		return Delta{}, false
	default:
		ch, _ := m["choices"].([]any)
		if len(ch) == 0 {
			return Delta{}, false
		}
		cm, _ := ch[0].(map[string]any)
		d, _ := cm["delta"].(map[string]any)
		t, _ := d["content"].(string)
		calls, _ := d["tool_calls"].([]any)
		out := make([]ToolCall, 0, len(calls))
		for _, raw := range calls {
			c, _ := raw.(map[string]any)
			idxf, _ := c["index"].(float64)
			idx := int(idxf)
			id, _ := c["id"].(string)
			if id == "" {
				id = toolIDs[idx]
				if id == "" {
					id = fmt.Sprintf("tool-%d", *nextToolID)
					(*nextToolID)++
				}
			}
			toolIDs[idx] = id
			typ, _ := c["type"].(string)
			fn, _ := c["function"].(map[string]any)
			name, _ := fn["name"].(string)
			args, _ := fn["arguments"].(string)
			out = append(out, ToolCall{Index: idx, ID: id, Type: typ, Function: FunctionCall{Name: name, Arguments: args}})
		}
		if t == "" && len(out) == 0 {
			return Delta{}, false
		}
		return Delta{Content: t, ToolCalls: out}, true
	}
}

var _ Client = (*providerClient)(nil)
var _ ConnectionTester = (*connectionTester)(nil)
