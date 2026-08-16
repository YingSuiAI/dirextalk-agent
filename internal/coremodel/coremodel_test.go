package coremodel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func validProfile(provider ModelProvider, base, key string) Profile {
	return Profile{ID: "11111111-1111-4111-8111-111111111111", DisplayName: "Test profile", Provider: provider, BaseURL: base, Model: "test-model", APIKey: key}
}

func TestNormalizeBaseURLDefaultsAndStrictHTTPS(t *testing.T) {
	got, err := NormalizeBaseURL(ProviderOpenAICompatible, "")
	if err != nil || got != "https://api.openai.com/v1" {
		t.Fatalf("openai default: %q %v", got, err)
	}
	got, err = NormalizeBaseURL(ProviderAnthropic, "https://api.anthropic.com///")
	if err != nil || got != "https://api.anthropic.com" {
		t.Fatalf("anthropic normalize: %q %v", got, err)
	}
	for _, raw := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com?a=1", "https://example.com#frag", "//example.com"} {
		if _, err := NormalizeBaseURL(ProviderGemini, raw); err == nil {
			t.Errorf("accepted invalid URL %q", raw)
		}
	}
}

func TestOpenRouterProviderAliasNormalizesToOpenAICompatible(t *testing.T) {
	got, err := NormalizeBaseURL(ModelProvider("openrouter"), "")
	if err != nil || got != "https://openrouter.ai/api/v1" {
		t.Fatalf("OpenRouter default: %q %v", got, err)
	}
	p, err := ValidateProfile(Profile{ID: "11111111-1111-4111-8111-111111111111", DisplayName: "OpenRouter", Provider: ModelProvider("openrouter"), Model: "openai/gpt-4o-mini", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Provider != ProviderOpenAICompatible || p.BaseURL != "https://openrouter.ai/api/v1" {
		t.Fatalf("normalized profile=%+v", p)
	}
	custom, err := ValidateProfile(Profile{ID: "22222222-2222-4222-8222-222222222222", DisplayName: "DeepSeek", Provider: ModelProvider("deepseek"), BaseURL: "https://gateway.example/v1/", Model: "deepseek-chat", APIKey: "k"})
	if err != nil || custom.Provider != ProviderOpenAICompatible || custom.BaseURL != "https://gateway.example/v1" {
		t.Fatalf("custom alias profile=%+v err=%v", custom, err)
	}
}

func TestSpeechProfileAcceptsMetadataWithoutGenericAPIKey(t *testing.T) {
	p, err := ValidateProfile(Profile{ID: "33333333-3333-4333-8333-333333333333", DisplayName: "Volc Speech", Provider: ProviderVolcVoice, ModelKind: ModelKindSpeech, ProviderConfig: map[string]any{"app_id": "app"}})
	if err != nil {
		t.Fatalf("speech profile: %v", err)
	}
	if p.ModelKind != ModelKindSpeech || p.Model != "volc_voice" || p.BaseURL != "" {
		t.Fatalf("speech normalization = %#v", p)
	}
	public := p.Public()
	if public.APIKeyConfigured || public.ProviderSecretStatus != nil {
		t.Fatalf("speech public projection leaked credential state: %#v", public)
	}
}

func TestValidateProfileRejectsNilUUID(t *testing.T) {
	if _, err := ValidateProfile(Profile{ID: "00000000-0000-0000-0000-000000000000", DisplayName: "x", Provider: ProviderGemini, Model: "gemini-test", APIKey: "k"}); err == nil {
		t.Fatal("accepted nil UUID")
	}
}

func TestProfileRedactionAndUpdatePreservesKey(t *testing.T) {
	key := "super-secret-key"
	p, err := NewProfile(ProfileSpec{ID: "11111111-1111-4111-8111-111111111111", DisplayName: "Test profile", Provider: ProviderGemini, Model: "gemini-1.5", APIKey: &key})
	if err != nil {
		t.Fatal(err)
	}
	pub := p.Public()
	if !pub.APIKeyConfigured || strings.Contains(stringify(pub), key) {
		t.Fatalf("secret leaked in projection: %#v", pub)
	}
	updated, err := UpdateProfile(p, ProfileSpec{ID: p.ID, DisplayName: "renamed", Provider: p.Provider, Model: p.Model})
	if err != nil || updated.APIKey != key {
		t.Fatalf("key not preserved: %#v %v", updated, err)
	}
	empty := ""
	if _, err := UpdateProfile(p, ProfileSpec{APIKey: &empty}); err == nil {
		t.Fatal("accepted explicitly empty key")
	}
}

func stringify(v any) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(toJSON(v)), " ", ""))
}
func toJSON(v any) string { b, _ := jsonMarshal(v); return string(b) }

// Small indirection keeps this test independent of formatting details.
func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

func TestConnectionHeadersAndOpenAIGenerate(t *testing.T) {
	const key = "openai-secret"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/models" {
			if r.Header.Get("Authorization") != "Bearer "+key {
				t.Errorf("authorization header mismatch")
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"data":[]}`)
			return
		}
		if r.URL.Path != "/chat/completions" {
			t.Errorf("path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+key {
			t.Errorf("chat authorization mismatch")
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"hello"}}]}`)
	}))
	defer server.Close()
	p := validProfile(ProviderOpenAICompatible, server.URL, key)
	tester := NewConnectionTester(WithHTTPClient(server.Client()))
	if err := tester.TestConnection(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(p, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	completion, err := client.Generate(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	if err != nil || completion.Message.Content != "hello" {
		t.Fatalf("completion=%#v err=%v", completion, err)
	}
}

func TestGeminiUsesNativeEndpointAndHeader(t *testing.T) {
	const key = "gemini-secret"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1beta/models/test-model:generateContent" {
			t.Errorf("unexpected Gemini path %s", r.URL.Path)
		}
		if r.Header.Get("x-goog-api-key") != key {
			t.Errorf("missing Gemini key header")
		}
		_, _ = io.WriteString(w, `{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}`)
	}))
	defer server.Close()
	p := validProfile(ProviderGemini, server.URL, key)
	client, err := NewClient(p, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Generate(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	if err != nil || got.Message.Content != "ok" {
		t.Fatalf("got=%#v err=%v", got, err)
	}
}

func TestAnthropicUsesNativeEndpointHeadersAndPayload(t *testing.T) {
	const key = "anthropic-secret"
	var sawMessage bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != key || r.Header.Get("anthropic-version") != "2023-06-01" {
			t.Errorf("Anthropic auth headers mismatch: x-api-key=%q version=%q", r.Header.Get("x-api-key"), r.Header.Get("anthropic-version"))
		}
		switch r.URL.Path {
		case "/v1/models":
			if r.Method != http.MethodGet {
				t.Errorf("models method=%s", r.Method)
			}
			_, _ = io.WriteString(w, `{"data":[]}`)
		case "/v1/messages":
			if r.Method != http.MethodPost {
				t.Errorf("messages method=%s", r.Method)
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode payload: %v", err)
			}
			if payload["model"] != "claude-test" || payload["system"] != "saved system" {
				t.Errorf("unexpected payload: %#v", payload)
			}
			messages, _ := payload["messages"].([]any)
			if len(messages) != 1 {
				t.Errorf("messages=%#v", messages)
			}
			sawMessage = true
			_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"hello"}],"usage":{"input_tokens":2,"output_tokens":1}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	p := validProfile(ProviderAnthropic, server.URL, key)
	p.Model = "claude-test"
	p.SystemPrompt = "saved system"
	tester := NewConnectionTester(WithHTTPClient(server.Client()))
	if err := tester.TestConnection(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(p, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	completion, err := client.Generate(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	if err != nil || completion.Message.Content != "hello" || !sawMessage {
		t.Fatalf("completion=%#v err=%v sawMessage=%v", completion, err, sawMessage)
	}
}

func TestProviderPayloadsMapToolExchanges(t *testing.T) {
	r := CompletionRequest{Messages: []Message{
		{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "call-1", Type: "function", Function: FunctionCall{Name: "lookup", Arguments: `{"q":"x"}`}}}},
		{Role: RoleTool, ToolCallID: "call-1", Name: "lookup", Content: `{"value":1}`},
	}, Tools: []Tool{{Name: "lookup", Description: "look up", InputSchema: map[string]any{"type": "object"}}}}
	openProfile := validProfile(ProviderOpenAICompatible, "https://example.com", "k")
	openProfile.ReasoningEffort = "high"
	open := openAIPayload(openProfile, r, false)
	data, _ := json.Marshal(open)
	text := string(data)
	for _, want := range []string{`"role":"assistant"`, `"tool_calls"`, `"tool_call_id":"call-1"`, `"reasoning_effort":"high"`} {
		if !strings.Contains(text, want) {
			t.Errorf("OpenAI payload missing %s: %s", want, text)
		}
	}
	ant := anthropicPayload(validProfile(ProviderAnthropic, "https://example.com", "k"), r, false)
	data, _ = json.Marshal(ant)
	text = string(data)
	for _, want := range []string{`"type":"tool_use"`, `"type":"tool_result"`, `"tool_use_id":"call-1"`} {
		if !strings.Contains(text, want) {
			t.Errorf("Anthropic payload missing %s: %s", want, text)
		}
	}
	gem := geminiPayload(validProfile(ProviderGemini, "https://example.com", "k"), r)
	data, _ = json.Marshal(gem)
	text = string(data)
	for _, want := range []string{`"functionCall"`, `"functionResponse"`} {
		if !strings.Contains(text, want) {
			t.Errorf("Gemini payload missing %s: %s", want, text)
		}
	}
}

func TestProviderSafeIntrinsicNamesRoundTripPayloadsAndResponses(t *testing.T) {
	for _, name := range []string{IntrinsicScheduleCreateToolName, IntrinsicCloudWorkerProposeToolName, IntrinsicCloudWorkerDestroyToolName, IntrinsicStaticSitePublishToolName} {
		if !toolNamePattern.MatchString(name) || strings.Contains(name, ".") {
			t.Fatalf("intrinsic tool name is not provider-safe: %q", name)
		}
	}
	name := IntrinsicScheduleCreateToolName
	request := CompletionRequest{
		Messages: []Message{{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "call-1", Type: "function", Function: FunctionCall{Name: name, Arguments: `{}`}}}}},
		Tools:    []Tool{{Name: name, InputSchema: map[string]any{"type": "object"}}},
	}
	for provider, payload := range map[ModelProvider]any{
		ProviderOpenAICompatible: openAIPayload(validProfile(ProviderOpenAICompatible, "https://example.test", "key"), request, false),
		ProviderAnthropic:        anthropicPayload(validProfile(ProviderAnthropic, "https://example.test", "key"), request, false),
		ProviderGemini:           geminiPayload(validProfile(ProviderGemini, "https://example.test", "key"), request),
	} {
		raw, err := json.Marshal(payload)
		if err != nil || !strings.Contains(string(raw), `"`+name+`"`) {
			t.Fatalf("provider %q payload=%s err=%v", provider, raw, err)
		}
	}

	responses := map[ModelProvider]string{
		ProviderOpenAICompatible: `{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call-1","type":"function","function":{"name":"` + name + `","arguments":"{}"}}]}}]}`,
		ProviderAnthropic:        `{"content":[{"type":"tool_use","id":"call-1","name":"` + name + `","input":{}}]}`,
		ProviderGemini:           `{"candidates":[{"content":{"parts":[{"functionCall":{"name":"` + name + `","args":{}}}]}}]}`,
	}
	for provider, body := range responses {
		completion, err := decodeCompletion(provider, []byte(body), nil)
		if err != nil || len(completion.Message.ToolCalls) != 1 || completion.Message.ToolCalls[0].Function.Name != name {
			t.Fatalf("provider %q completion=%#v err=%v", provider, completion, err)
		}
	}

	streamBodies := map[ModelProvider]string{
		ProviderOpenAICompatible: `{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"` + name + `","arguments":"{}"}}]}}]}`,
		ProviderAnthropic:        `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"call-1","name":"` + name + `"}}`,
		ProviderGemini:           `{"candidates":[{"content":{"parts":[{"functionCall":{"name":"` + name + `","args":{}}}]}}]}`,
	}
	for provider, body := range streamBodies {
		delta, ok := decodeDeltaState(provider, []byte(body), map[int]string{})
		if !ok || len(delta.ToolCalls) != 1 || delta.ToolCalls[0].Function.Name != name {
			t.Fatalf("provider %q delta=%#v ok=%v", provider, delta, ok)
		}
	}
}

func TestSystemPromptOrdering(t *testing.T) {
	p := validProfile(ProviderOpenAICompatible, "https://example.com", "k")
	p.SystemPrompt = "saved system"
	payload := openAIPayload(p, CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hello"}}}, false)
	messages := payload["messages"].([]any)
	if len(messages) != 2 || messages[0].(map[string]any)["role"] != string(RoleSystem) || messages[0].(map[string]any)["content"] != p.SystemPrompt {
		t.Fatalf("system ordering: %#v", messages)
	}
	gem := geminiPayload(Profile{Provider: ProviderGemini, Model: "gemini-test", SystemPrompt: p.SystemPrompt}, CompletionRequest{Messages: []Message{{Role: RoleSystem, Content: "request system"}, {Role: RoleUser, Content: "hello"}}})
	parts := gem["systemInstruction"].(map[string]any)["parts"].([]any)
	if len(parts) != 2 || parts[0].(map[string]any)["text"] != p.SystemPrompt || parts[1].(map[string]any)["text"] != "request system" {
		t.Fatalf("Gemini system ordering: %#v", parts)
	}
}

func TestStreamToolDeltasHaveStableIDs(t *testing.T) {
	ids := map[int]string{}
	open, ok := decodeDeltaState(ProviderOpenAICompatible, []byte(`{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"lookup","arguments":"{"}}]}}]}`), ids)
	if !ok || len(open.ToolCalls) != 1 || open.ToolCalls[0].ID != "tool-0" {
		t.Fatalf("OpenAI delta=%#v ok=%v", open, ok)
	}
	ant, ok := decodeDeltaState(ProviderAnthropic, []byte(`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","name":"lookup"}}`), ids)
	if !ok || len(ant.ToolCalls) != 1 || ant.ToolCalls[0].ID != "tool-0" {
		t.Fatalf("Anthropic delta=%#v ok=%v", ant, ok)
	}
	gem, ok := decodeDeltaState(ProviderGemini, []byte(`{"candidates":[{"content":{"parts":[{"functionCall":{"name":"lookup","args":{"q":"x"}}}]}}]}`), ids)
	if !ok || len(gem.ToolCalls) != 1 || gem.ToolCalls[0].ID == "" {
		t.Fatalf("Gemini delta=%#v ok=%v", gem, ok)
	}
	multi, ok := decodeDeltaState(ProviderGemini, []byte(`{"candidates":[{"content":{"parts":[{"text":"a"},{"functionCall":{"name":"one","args":{}}}]}},{"content":{"parts":[{"text":"b"},{"functionCall":{"name":"two","args":{}}}]}}]}`), ids)
	if !ok || multi.Content != "a" || len(multi.ToolCalls) != 1 {
		t.Fatalf("Gemini multi delta=%#v ok=%v", multi, ok)
	}
	state := map[int]string{}
	next := 0
	first, _ := decodeDeltaStateCounter(ProviderGemini, []byte(`{"candidates":[{"content":{"parts":[{"functionCall":{"name":"one","args":{}}}]}}]}`), state, &next)
	second, _ := decodeDeltaStateCounter(ProviderGemini, []byte(`{"candidates":[{"content":{"parts":[{"functionCall":{"name":"two","args":{}}}]}}]}`), state, &next)
	if len(first.ToolCalls) != 1 || len(second.ToolCalls) != 1 || first.ToolCalls[0].ID == second.ToolCalls[0].ID || first.ToolCalls[0].Index == second.ToolCalls[0].Index {
		t.Fatalf("cross-chunk IDs not monotonic: %#v %#v", first, second)
	}
}

func TestOpenAIMixedDeltaPreservesContentAndTools(t *testing.T) {
	delta, ok := decodeDeltaState(ProviderOpenAICompatible, []byte(`{"choices":[{"delta":{"content":"text","tool_calls":[{"index":0,"function":{"name":"lookup","arguments":"{}"}}]}}]}`), map[int]string{})
	if !ok || delta.Content != "text" || len(delta.ToolCalls) != 1 || delta.ToolCalls[0].Function.Name != "lookup" {
		t.Fatalf("mixed delta=%#v ok=%v", delta, ok)
	}
}

func TestOpenAIReasoningRoundTripsThroughMessagesAndResponses(t *testing.T) {
	payload := openAIPayload(
		validProfile(ProviderOpenAICompatible, "https://example.com", "k"),
		CompletionRequest{Messages: []Message{{Role: RoleAssistant, Content: "answer", ReasoningContent: "prior reasoning"}}},
		false,
	)
	messages := payload["messages"].([]any)
	if len(messages) != 1 || messages[0].(map[string]any)["reasoning_content"] != "prior reasoning" {
		t.Fatalf("reasoning request payload=%#v", messages)
	}
	completion, err := decodeCompletion(ProviderOpenAICompatible, []byte(`{"choices":[{"message":{"role":"assistant","content":"answer","reasoning_content":"full reasoning"}}]}`), nil)
	if err != nil || completion.Message.Content != "answer" || completion.Message.ReasoningContent != "full reasoning" {
		t.Fatalf("reasoning completion=%#v err=%v", completion, err)
	}
	delta, ok := decodeDeltaState(ProviderOpenAICompatible, []byte(`{"choices":[{"delta":{"reasoning_content":"reasoning chunk"}}]}`), map[int]string{})
	if !ok || delta.Content != "" || delta.ReasoningContent != "reasoning chunk" {
		t.Fatalf("reasoning delta=%#v ok=%v", delta, ok)
	}
}

func TestUpdateProfileFullReplacementAndMultilinePrompt(t *testing.T) {
	key := "k"
	old := validProfile(ProviderOpenAICompatible, "https://custom.example/v1", key)
	old.DisplayName = "Old"
	old.SystemPrompt = "old"
	old.Temperature = ptrFloat(0.7)
	old.TopP = ptrFloat(0.8)
	old.MaxOutputTokens = 99
	old.ContextWindow = 8192
	old.ReasoningEffort = "high"
	updated, err := UpdateProfile(old, ProfileSpec{ID: old.ID, DisplayName: "New", Provider: ProviderAnthropic, Model: "claude-test", APIKey: nil, SystemPrompt: "line one\n\tline two", TemperatureClear: true, TopPClear: true})
	if err != nil {
		t.Fatal(err)
	}
	if updated.BaseURL != "https://api.anthropic.com" || updated.SystemPrompt != "line one\n\tline two" || updated.Temperature != nil || updated.TopP != nil || updated.MaxOutputTokens != DefaultConversationMaxOutputTokens || updated.ContextWindow != 8192 || updated.ReasoningEffort != "high" || updated.APIKey != key {
		t.Fatalf("replacement mismatch: %#v", updated)
	}
	updated, err = UpdateProfile(updated, ProfileSpec{ID: old.ID, DisplayName: "New", Provider: ProviderAnthropic, Model: "claude-test", ContextWindow: 16384, ContextWindowSet: true, ReasoningEffort: "low", ReasoningEffortSet: true})
	if err != nil || updated.ContextWindow != 16384 || updated.ReasoningEffort != "low" {
		t.Fatalf("reasoning parameter patch mismatch: %#v %v", updated, err)
	}
	updated, err = UpdateProfile(updated, ProfileSpec{ID: old.ID, ContextWindow: 32768, ContextWindowSet: true})
	if err != nil || updated.ContextWindow != 32768 || updated.DisplayName != "New" || updated.Provider != ProviderAnthropic {
		t.Fatalf("single parameter preserve mismatch: %#v %v", updated, err)
	}
}

func ptrFloat(v float64) *float64 { return &v }

func TestInvalidToolArgumentsRejectedBeforeHTTP(t *testing.T) {
	called := false
	httpClient := roundTripFunc(func(*http.Request) (*http.Response, error) { called = true; return nil, io.ErrUnexpectedEOF })
	client, err := NewClient(validProfile(ProviderOpenAICompatible, "https://example.com", "k"), WithHTTPClient(httpClient))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Generate(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hi"}, {Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "c1", Type: "function", Function: FunctionCall{Name: "lookup", Arguments: "not-json"}}}}}})
	if err == nil || called {
		t.Fatalf("invalid request reached HTTP: err=%v called=%v", err, called)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestInjectedClientHonorsTimeoutAndStreamCloses(t *testing.T) {
	blocking := roundTripFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	client, err := NewClient(validProfile(ProviderOpenAICompatible, "https://example.com", "k"), WithHTTPClient(blocking), WithTimeout(20*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = client.Generate(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("timeout not honored: err=%v elapsed=%v", err, time.Since(start))
	}

	body := &closeTrackingBody{Reader: strings.NewReader("data: [DONE]\n\n")}
	streamClient, err := NewClient(validProfile(ProviderOpenAICompatible, "https://example.com", "k"), WithHTTPClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	stream, err := streamClient.Stream(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	if err != io.EOF || !body.closed {
		t.Fatalf("stream body not closed: err=%v closed=%v", err, body.closed)
	}
}

func TestStreamCloseCancelsOwnedTimeout(t *testing.T) {
	cancelled := make(chan struct{})
	body := &contextBody{ctxDone: cancelled}
	client, err := NewClient(validProfile(ProviderOpenAICompatible, "https://example.com", "k"), WithHTTPClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body.ctx = r.Context()
		go func() { <-r.Context().Done(); close(cancelled) }()
		return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
	})), WithTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.Stream(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("stream close did not cancel request context")
	}
}

func TestStreamIdleTimeoutResetsOnProviderBytesPastTotalInterval(t *testing.T) {
	body := &delayedStreamBody{
		delay: 30 * time.Millisecond,
		chunks: []string{
			"data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n",
			"data: {\"choices\":[{\"delta\":{\"content\":\"b\"}}]}\n\n",
			"data: [DONE]\n\n",
		},
	}
	client, err := NewClient(validProfile(ProviderOpenAICompatible, "https://example.com", "k"),
		WithHTTPClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
			body.ctx = r.Context()
			return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
		})),
		WithStreamIdleTimeout(70*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	stream, err := client.Stream(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"a", "b"} {
		delta, recvErr := stream.Recv()
		if recvErr != nil || delta.Content != want {
			t.Fatalf("delta=%#v err=%v want=%q", delta, recvErr, want)
		}
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("terminal err=%v", err)
	}
	if elapsed := time.Since(started); elapsed <= 70*time.Millisecond {
		t.Fatalf("stream did not outlive one idle interval: %s", elapsed)
	}
}

func TestStreamIdleTimeoutRemovesOnlyDefaultHTTPStreamDeadline(t *testing.T) {
	client, err := NewClient(validProfile(ProviderOpenAICompatible, "https://example.com", "k"), WithStreamIdleTimeout(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	provider := client.(*providerClient)
	httpClient := provider.http.(*http.Client)
	if httpClient.Timeout != 0 {
		t.Fatalf("stream-capable HTTP client total timeout=%s", httpClient.Timeout)
	}
	if provider.timeout != 90*time.Second || provider.streamIdleTimeout != time.Minute {
		t.Fatalf("generate timeout=%s stream idle timeout=%s", provider.timeout, provider.streamIdleTimeout)
	}
}

func TestStreamIdleTimeoutCoversResponseHeadersAndSilentBody(t *testing.T) {
	for _, tc := range []struct {
		name string
		do   roundTripFunc
	}{
		{
			name: "headers",
			do: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				<-r.Context().Done()
				return nil, r.Context().Err()
			}),
		},
		{
			name: "body",
			do: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: &contextBody{ctx: r.Context()}, Header: make(http.Header)}, nil
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewClient(validProfile(ProviderOpenAICompatible, "https://example.com", "k"), WithHTTPClient(tc.do), WithStreamIdleTimeout(20*time.Millisecond))
			if err != nil {
				t.Fatal(err)
			}
			stream, err := client.Stream(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
			if tc.name == "headers" {
				if !errors.Is(err, ErrStreamIdleTimeout) || !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("header idle error=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if _, err := stream.Recv(); !errors.Is(err, ErrStreamIdleTimeout) || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("body idle error=%v", err)
			}
		})
	}
}

type contextBody struct {
	ctx     context.Context
	ctxDone chan struct{}
	closed  bool
}

func (b *contextBody) Read([]byte) (int, error) { <-b.ctx.Done(); return 0, b.ctx.Err() }
func (b *contextBody) Close() error             { b.closed = true; return nil }

type delayedStreamBody struct {
	ctx    context.Context
	delay  time.Duration
	chunks []string
	index  int
	closed bool
}

func (b *delayedStreamBody) Read(p []byte) (int, error) {
	if b.index >= len(b.chunks) {
		return 0, io.EOF
	}
	select {
	case <-time.After(b.delay):
	case <-b.ctx.Done():
		return 0, b.ctx.Err()
	}
	n := copy(p, b.chunks[b.index])
	b.index++
	return n, nil
}

func (b *delayedStreamBody) Close() error {
	b.closed = true
	return nil
}

func TestStreamProviderErrorAndResponseLimit(t *testing.T) {
	for _, bodyText := range []string{"data: {\"error\":{\"message\":\"bad\"}}\n\n", "data: {\"type\":\"error\",\"error\":{}}\n\n"} {
		body := &closeTrackingBody{Reader: strings.NewReader(bodyText)}
		client, err := NewClient(validProfile(ProviderOpenAICompatible, "https://example.com", "k"), WithHTTPClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
		})))
		if err != nil {
			t.Fatal(err)
		}
		stream, err := client.Stream(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = stream.Recv(); err == nil || err == io.EOF || !body.closed {
			t.Fatalf("provider error not surfaced: %v closed=%v", err, body.closed)
		}
	}
	large := &closeTrackingBody{Reader: strings.NewReader(strings.Repeat("x", maxResponseBytes+1))}
	client, err := NewClient(validProfile(ProviderOpenAICompatible, "https://example.com", "k"), WithHTTPClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: large, Header: make(http.Header)}, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.Stream(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Recv(); err == nil || err == io.EOF || !large.closed {
		t.Fatalf("response limit not surfaced: %v closed=%v", err, large.closed)
	}
}

func TestProviderStreamsRejectRawEOFWithoutTerminalMarker(t *testing.T) {
	cases := []struct {
		provider ModelProvider
		event    string
	}{
		{ProviderOpenAICompatible, `{"choices":[{"delta":{"content":"x"}}]}`},
		{ProviderAnthropic, `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"x"}}`},
		{ProviderGemini, `{"candidates":[{"content":{"parts":[{"text":"x"}]}}]}`},
	}
	for _, tc := range cases {
		for _, suffix := range []string{"\n\n", ""} {
			body := &closeTrackingBody{Reader: strings.NewReader("data: " + tc.event + suffix)}
			client, err := NewClient(validProfile(tc.provider, "https://example.com", "k"), WithHTTPClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
			})))
			if err != nil {
				t.Fatal(err)
			}
			stream, err := client.Stream(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = stream.Recv(); err != nil {
				t.Fatalf("first delta %s suffix=%q: %v", tc.provider, suffix, err)
			}
			if _, err = stream.Recv(); err == nil || err == io.EOF || !body.closed {
				t.Fatalf("truncated %s suffix=%q: err=%v closed=%v", tc.provider, suffix, err, body.closed)
			}
		}
	}
}

func TestOpenAIFinishReasonTerminatesAfterFinalContentAndToolDelta(t *testing.T) {
	for _, suffix := range []string{"\n\n", ""} {
		body := &closeTrackingBody{Reader: strings.NewReader(
			"data: {\"choices\":[{\"delta\":{\"content\":\"last text\",\"tool_calls\":[{\"index\":0,\"id\":\"call-1\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{}\"}}]},\"finish_reason\":\"tool_calls\"}]}" + suffix,
		)}
		client, err := NewClient(validProfile(ProviderOpenAICompatible, "https://example.com", "k"), WithHTTPClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
		})))
		if err != nil {
			t.Fatal(err)
		}
		stream, err := client.Stream(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
		if err != nil {
			t.Fatal(err)
		}
		delta, err := stream.Recv()
		if err != nil || delta.Content != "last text" || len(delta.ToolCalls) != 1 || delta.ToolCalls[0].Function.Name != "lookup" || delta.ToolCalls[0].Function.Arguments != "{}" {
			t.Fatalf("suffix=%q final delta=%#v err=%v", suffix, delta, err)
		}
		if _, err = stream.Recv(); err != io.EOF || !body.closed {
			t.Fatalf("suffix=%q finish_reason not terminal: err=%v closed=%v", suffix, err, body.closed)
		}
	}
}

func TestConversationProfileDefaultsNonPositiveMaxOutputTokensInSnapshot(t *testing.T) {
	for _, value := range []int{0, -1} {
		profile := validProfile(ProviderOpenAICompatible, "https://example.com", "k")
		profile.MaxOutputTokens = value
		normalized, err := ValidateProfile(profile)
		if err != nil {
			t.Fatalf("value=%d: %v", value, err)
		}
		if normalized.MaxOutputTokens != DefaultConversationMaxOutputTokens {
			t.Fatalf("value=%d normalized=%d", value, normalized.MaxOutputTokens)
		}
		snapshot := SnapshotFromProfile(profile)
		if snapshot.MaxOutputTokens != DefaultConversationMaxOutputTokens || snapshot.Profile().MaxOutputTokens != DefaultConversationMaxOutputTokens {
			t.Fatalf("value=%d snapshot=%+v", value, snapshot)
		}
	}
	embedding := validProfile(ProviderOpenAICompatible, "https://example.com", "k")
	embedding.ModelKind = ModelKindEmbedding
	embedding.MaxOutputTokens = 0
	normalized, err := ValidateProfile(embedding)
	if err != nil || normalized.MaxOutputTokens != 0 {
		t.Fatalf("embedding profile=%+v err=%v", normalized, err)
	}
}

func TestGeminiFinishMarkerTerminatesAfterDelta(t *testing.T) {
	body := &closeTrackingBody{Reader: strings.NewReader("data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"x\"}]},\"finishReason\":\"STOP\"}]}\n\n")}
	client, err := NewClient(validProfile(ProviderGemini, "https://example.com", "k"), WithHTTPClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.Stream(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	if err != nil {
		t.Fatal(err)
	}
	if delta, err := stream.Recv(); err != nil || delta.Content != "x" {
		t.Fatalf("finish delta=%#v err=%v", delta, err)
	}
	if _, err := stream.Recv(); err != io.EOF || !body.closed {
		t.Fatalf("finish marker not terminal: err=%v closed=%v", err, body.closed)
	}
}

func TestGeminiIgnoresAlternativeCandidateFinish(t *testing.T) {
	body := &closeTrackingBody{Reader: strings.NewReader("data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"x\"}]}},{\"finishReason\":\"STOP\"}]}\n\n")}
	client, err := NewClient(validProfile(ProviderGemini, "https://example.com", "k"), WithHTTPClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.Stream(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	if err != nil {
		t.Fatal(err)
	}
	if delta, err := stream.Recv(); err != nil || delta.Content != "x" {
		t.Fatalf("alternative finish delta=%#v err=%v", delta, err)
	}
	if _, err := stream.Recv(); err == nil || err == io.EOF {
		t.Fatalf("alternative candidate incorrectly terminated stream: %v", err)
	}
}

func TestRequestBudgetBoundary(t *testing.T) {
	p := validProfile(ProviderOpenAICompatible, "https://example.com", "k")
	client, err := NewClient(p, WithHTTPClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("HTTP called over request budget")
		return nil, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Generate(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: strings.Repeat("x", 1<<20)}, {Role: RoleUser, Content: strings.Repeat("y", 1<<20)}}})
	if err == nil || !errors.Is(err, ErrCompletionRequestTooLarge) {
		t.Fatalf("budget error=%v", err)
	}
}

type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (b *closeTrackingBody) Close() error { b.closed = true; return nil }
