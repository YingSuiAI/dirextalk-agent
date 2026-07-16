package mcphttp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
)

type clientSession struct {
	provider        *Provider
	server          configuredServer
	sessionID       string
	protocolVersion string
	nextID          atomic.Uint64
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      uint64 `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

type initializeResult struct {
	ProtocolVersion string                     `json:"protocolVersion"`
	Capabilities    map[string]json.RawMessage `json:"capabilities"`
}

func (p *Provider) initialize(ctx context.Context, server configuredServer) (*clientSession, error) {
	session := &clientSession{provider: p, server: server, protocolVersion: protocolVersion}
	result, responseSessionID, err := session.request(ctx, "initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "dirextalk-agent",
			"version": "0.1.0",
		},
	}, false)
	if err != nil {
		return nil, err
	}
	var initialized initializeResult
	if err := json.Unmarshal(result, &initialized); err != nil {
		return nil, ErrProtocol
	}
	if !supportedProtocolVersion(initialized.ProtocolVersion) {
		return nil, ErrProtocol
	}
	if _, supportsTools := initialized.Capabilities["tools"]; !supportsTools {
		return nil, ErrProtocol
	}
	if responseSessionID != "" && !validSessionID(responseSessionID) {
		return nil, ErrProtocol
	}
	session.sessionID = responseSessionID
	session.protocolVersion = initialized.ProtocolVersion
	if err := session.notify(ctx, "notifications/initialized", map[string]any{}); err != nil {
		return nil, err
	}
	return session, nil
}

func supportedProtocolVersion(version string) bool {
	switch strings.TrimSpace(version) {
	case "2025-03-26", protocolVersion:
		return true
	default:
		return false
	}
}

func validSessionID(sessionID string) bool {
	return sessionID == strings.TrimSpace(sessionID) && len(sessionID) <= 512 && !strings.ContainsAny(sessionID, "\r\n\x00")
}

func (s *clientSession) listTools(ctx context.Context) ([]remoteTool, error) {
	var tools []remoteTool
	seenTools := make(map[string]struct{})
	seenCursors := make(map[string]struct{})
	cursor := ""
	for page := 0; page < maxToolPages; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		result, _, err := s.request(ctx, "tools/list", params, true)
		if err != nil {
			return nil, err
		}
		var listed struct {
			Tools      []remoteTool `json:"tools"`
			NextCursor string       `json:"nextCursor"`
		}
		if err := json.Unmarshal(result, &listed); err != nil || listed.Tools == nil {
			return nil, ErrProtocol
		}
		for _, candidate := range listed.Tools {
			validated, err := validateRemoteTool(candidate)
			if err != nil {
				return nil, err
			}
			if _, duplicate := seenTools[validated.Name]; duplicate {
				return nil, ErrInvalidToolDefinition
			}
			seenTools[validated.Name] = struct{}{}
			tools = append(tools, validated)
			if len(tools) > maxTools {
				return nil, ErrInvalidToolDefinition
			}
		}
		cursor = strings.TrimSpace(listed.NextCursor)
		if cursor == "" {
			return tools, nil
		}
		if len(cursor) > 512 {
			return nil, ErrProtocol
		}
		if _, repeated := seenCursors[cursor]; repeated {
			return nil, ErrProtocol
		}
		seenCursors[cursor] = struct{}{}
	}
	return nil, ErrProtocol
}

func (s *clientSession) callTool(ctx context.Context, name string, arguments map[string]any) (runtimeapi.ToolResult, error) {
	result, _, err := s.request(ctx, "tools/call", map[string]any{
		"name": name, "arguments": arguments,
	}, true)
	if err != nil {
		return runtimeapi.ToolResult{}, err
	}
	return decodeCallToolResult(result)
}

func decodeCallToolResult(data json.RawMessage) (runtimeapi.ToolResult, error) {
	var result struct {
		Content []json.RawMessage `json:"content"`
		IsError bool              `json:"isError"`
	}
	if err := json.Unmarshal(data, &result); err != nil || result.Content == nil {
		return runtimeapi.ToolResult{}, ErrProtocol
	}
	texts := make([]string, 0, len(result.Content))
	for _, rawContent := range result.Content {
		var content struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(rawContent, &content); err != nil {
			return runtimeapi.ToolResult{}, ErrProtocol
		}
		if content.Type == "text" {
			texts = append(texts, content.Text)
		}
	}
	return runtimeapi.ToolResult{
		Content: sanitizeToolResult(strings.Join(texts, "\n")),
		IsError: result.IsError,
	}, nil
}

func (s *clientSession) request(ctx context.Context, method string, params any, negotiated bool) (json.RawMessage, string, error) {
	id := s.nextID.Add(1)
	payload, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	if err != nil {
		return nil, "", ErrProtocol
	}
	version := ""
	if negotiated {
		version = s.protocolVersion
	}
	body, contentType, responseSessionID, err := s.provider.post(ctx, s.server, s.sessionID, version, payload, true)
	if err != nil {
		return nil, "", err
	}
	result, err := parseRPCResponse(body, contentType, id)
	if err != nil {
		return nil, "", err
	}
	return result, responseSessionID, nil
}

func (s *clientSession) notify(ctx context.Context, method string, params any) error {
	payload, err := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		Params  any    `json:"params,omitempty"`
	}{JSONRPC: "2.0", Method: method, Params: params})
	if err != nil {
		return ErrProtocol
	}
	_, _, _, err = s.provider.post(ctx, s.server, s.sessionID, s.protocolVersion, payload, false)
	return err
}

func (p *Provider) post(
	ctx context.Context,
	server configuredServer,
	sessionID string,
	version string,
	payload []byte,
	expectResponse bool,
) ([]byte, string, string, error) {
	requestCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	if err := p.policy.Validate(requestCtx, cloneURL(server.endpoint)); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, "", "", ctxErr
		}
		if requestErr := requestCtx.Err(); requestErr != nil {
			return nil, "", "", requestErr
		}
		return nil, "", "", ErrEndpointDenied
	}
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, server.endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, "", "", ErrInvalidConfig
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		request.Header.Set("Mcp-Session-Id", sessionID)
	}
	if version != "" {
		request.Header.Set("MCP-Protocol-Version", version)
	}

	credential, err := p.resolveCredential(requestCtx, server.secretRef)
	if err != nil {
		return nil, "", "", err
	}
	defer zeroBytes(credential)
	if len(credential) > 0 {
		request.Header.Set("Authorization", "Bearer "+string(credential))
	}
	defer request.Header.Del("Authorization")

	response, err := p.client.Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, "", "", ctxErr
		}
		if requestErr := requestCtx.Err(); requestErr != nil {
			return nil, "", "", requestErr
		}
		return nil, "", "", ErrProviderUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, "", "", ErrProviderUnavailable
	}
	body, err := readBounded(response.Body, maxResponseBytes)
	if err != nil {
		return nil, "", "", err
	}
	body = redactCredentialPayload(body, response.Header.Get("Content-Type"), credential)
	responseSessionID := strings.TrimSpace(response.Header.Get("Mcp-Session-Id"))
	if responseSessionID != "" && !validSessionID(responseSessionID) {
		return nil, "", "", ErrProtocol
	}
	if !expectResponse {
		return nil, "", responseSessionID, nil
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, "", "", ErrProtocol
	}
	return body, response.Header.Get("Content-Type"), responseSessionID, nil
}

func (p *Provider) resolveCredential(ctx context.Context, secretRef string) ([]byte, error) {
	if secretRef == "" {
		return nil, nil
	}
	if p.secrets == nil {
		return nil, ErrCredentialUnavailable
	}
	credential, err := p.secrets.ResolveSecret(ctx, secretRef)
	if err != nil || len(bytes.TrimSpace(credential)) == 0 || len(credential) > 16<<10 {
		zeroBytes(credential)
		return nil, ErrCredentialUnavailable
	}
	return credential, nil
}

func readBounded(reader io.Reader, limit int) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	if len(data) > limit {
		return nil, ErrResponseTooLarge
	}
	return data, nil
}

func parseRPCResponse(body []byte, contentType string, requestID uint64) (json.RawMessage, error) {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, ErrProtocol
	}
	var messages [][]byte
	switch strings.ToLower(mediaType) {
	case "application/json":
		messages = [][]byte{body}
	case "text/event-stream":
		messages, err = parseSSEMessages(body)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrProtocol
	}
	expectedID := strconv.FormatUint(requestID, 10)
	for _, message := range messages {
		var response rpcResponse
		if err := json.Unmarshal(message, &response); err != nil || response.JSONRPC != "2.0" {
			continue
		}
		if string(bytes.TrimSpace(response.ID)) != expectedID {
			continue
		}
		if len(response.Error) > 0 && string(bytes.TrimSpace(response.Error)) != "null" {
			return nil, ErrProviderUnavailable
		}
		if len(response.Result) == 0 {
			return nil, ErrProtocol
		}
		return append(json.RawMessage(nil), response.Result...), nil
	}
	return nil, ErrProtocol
}

func parseSSEMessages(body []byte) ([][]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), maxResponseBytes)
	var messages [][]byte
	var dataLines []string
	flush := func() {
		if len(dataLines) == 0 {
			return
		}
		messages = append(messages, []byte(strings.Join(dataLines, "\n")))
		dataLines = nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, ErrProtocol
	}
	flush()
	if len(messages) == 0 {
		return nil, ErrProtocol
	}
	return messages, nil
}

func cloneURL(source *url.URL) *url.URL {
	if source == nil {
		return nil
	}
	cloned := *source
	return &cloned
}
