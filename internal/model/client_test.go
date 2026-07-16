package model

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientResolvesCredentialOutsideProfileAndPayload(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		provider   Provider
		wantPath   string
		wantHeader string
		response   string
	}{
		{
			name:       "openai-compatible",
			provider:   ProviderOpenAICompatible,
			wantPath:   "/v1/chat/completions",
			wantHeader: "Authorization",
			response:   `{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`,
		},
		{
			name:       "deepseek",
			provider:   ProviderDeepSeek,
			wantPath:   "/chat/completions",
			wantHeader: "Authorization",
			response:   `{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`,
		},
		{
			name:       "anthropic",
			provider:   ProviderAnthropic,
			wantPath:   "/v1/messages",
			wantHeader: "x-api-key",
			response:   `{"content":[{"type":"text","text":"ok"}]}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			secret := generatedCredential(t)
			resolverBuffer := append([]byte(nil), secret...)
			var sawCredential bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != test.wantPath {
					t.Errorf("request path = %q, want %q", r.URL.Path, test.wantPath)
				}
				header := r.Header.Get(test.wantHeader)
				if test.wantHeader == "Authorization" {
					sawCredential = header == "Bearer "+string(secret)
				} else {
					sawCredential = header == string(secret)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read request: %v", err)
				}
				if strings.Contains(string(body), string(secret)) || strings.Contains(string(body), "secret:model") {
					t.Error("credential or secret reference entered the model payload")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, test.response)
			}))
			defer server.Close()

			client, err := NewClient(Profile{
				Provider:          test.provider,
				Model:             "test-model",
				BaseURL:           server.URL + basePathForTest(test.provider),
				SecretRef:         "secret:model",
				AllowInsecureHTTP: true,
			}, SecretResolverFunc(func(context.Context, string) ([]byte, error) {
				return resolverBuffer, nil
			}), WithHTTPClient(server.Client()))
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Generate(context.Background(), CompletionRequest{
				Messages: []Message{{Role: RoleUser, Content: "hello"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.Message.Content != "ok" || !sawCredential {
				t.Fatalf("unexpected completion or authorization state: content=%q authorized=%v", result.Message.Content, sawCredential)
			}
			for _, value := range resolverBuffer {
				if value != 0 {
					t.Fatal("resolved credential buffer was not zeroed")
				}
			}
		})
	}
}

func TestProviderErrorIsStructuredBoundedAndRedacted(t *testing.T) {
	t.Parallel()

	secret := generatedCredential(t)
	providerToken := generatedCredential(t)
	message := "provider rejected credential " + string(secret) + " token=" + string(providerToken) + " " + strings.Repeat("x", providerErrorMessageLimit*2)
	encoded, err := json.Marshal(map[string]any{"error": map[string]any{"code": "bad_auth", "message": message}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("x-request-id", strings.Repeat("r", providerRequestIDLimit*2))
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(encoded)
	}))
	defer server.Close()

	client, err := NewClient(Profile{
		Provider:          ProviderOpenAICompatible,
		Model:             "test-model",
		BaseURL:           server.URL + "/v1",
		SecretRef:         "secret:model",
		AllowInsecureHTTP: true,
	}, SecretResolverFunc(func(context.Context, string) ([]byte, error) {
		return append([]byte(nil), secret...), nil
	}), WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Generate(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hello"}}})
	if err == nil {
		t.Fatal("expected provider error")
	}
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) {
		t.Fatalf("error type = %T, want *ProviderError", err)
	}
	if providerErr.StatusCode != http.StatusUnauthorized || providerErr.Code != "bad_auth" {
		t.Fatalf("unexpected provider error metadata: %#v", providerErr)
	}
	if len([]rune(providerErr.Message)) > providerErrorMessageLimit || len([]rune(providerErr.RequestID)) > providerRequestIDLimit {
		t.Fatal("provider error fields exceeded their public limits")
	}
	formatted := err.Error()
	if strings.Contains(formatted, string(secret)) || strings.Contains(formatted, string(providerToken)) {
		t.Fatal("provider error exposed credential material")
	}
	if !strings.Contains(formatted, redactedMarker) {
		t.Fatalf("provider error did not mark redaction: %q", formatted)
	}
}

func TestSecretResolverFailureDoesNotPropagateSensitiveCause(t *testing.T) {
	t.Parallel()

	secret := generatedCredential(t)
	client, err := NewClient(Profile{
		Provider:  ProviderDeepSeek,
		Model:     "test-model",
		SecretRef: "secret:model",
	}, SecretResolverFunc(func(context.Context, string) ([]byte, error) {
		return nil, errors.New("backend included " + string(secret))
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Generate(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hello"}}})
	if !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("error = %v, want ErrSecretUnavailable", err)
	}
	if strings.Contains(err.Error(), string(secret)) {
		t.Fatal("resolver cause leaked through the model boundary")
	}
}

func TestTransportFailureDoesNotPropagateSensitiveCause(t *testing.T) {
	t.Parallel()

	secret := generatedCredential(t)
	client, err := NewClient(Profile{
		Provider:  ProviderDeepSeek,
		Model:     "test-model",
		SecretRef: "secret:model",
	}, SecretResolverFunc(func(context.Context, string) ([]byte, error) {
		return append([]byte(nil), secret...), nil
	}), WithHTTPClient(httpClientFunc(func(request *http.Request) (*http.Response, error) {
		return nil, errors.New("transport included " + request.Header.Get("Authorization"))
	})))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Generate(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hello"}}})
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("error = %v, want ErrProviderUnavailable", err)
	}
	if strings.Contains(err.Error(), string(secret)) {
		t.Fatal("transport cause leaked through the model boundary")
	}
}

func TestCanceledContextIsPreservedAcrossSecretBoundary(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client, err := NewClient(Profile{
		Provider:  ProviderDeepSeek,
		Model:     "test-model",
		SecretRef: "secret:model",
	}, SecretResolverFunc(func(context.Context, string) ([]byte, error) {
		return nil, errors.New("resolver canceled")
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Generate(ctx, CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hello"}}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestOpenAICompatibleToolCallAndStream(t *testing.T) {
	t.Parallel()

	secret := generatedCredential(t)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if payload["model"] != "test-model" || len(payload["tools"].([]any)) != 1 {
			t.Errorf("unexpected payload: %#v", payload)
		}
		if requests == 1 {
			_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call-1","type":"function","function":{"name":"lookup","arguments":"{\"q\":\"x\"}"}}]}}]}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"think\"}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"answer\"}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":2,\"id\":\"call-stream\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{\"}}]}}]}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer server.Close()

	client := mustTestClient(t, Profile{
		Provider:          ProviderOpenAICompatible,
		Model:             "test-model",
		BaseURL:           server.URL + "/v1",
		SecretRef:         "secret:model",
		AllowInsecureHTTP: true,
	}, secret)
	request := CompletionRequest{
		Messages: []Message{{Role: RoleUser, Content: "hello"}},
		Tools: []Tool{{Name: "lookup", Description: "lookup", InputSchema: map[string]any{
			"type": "object", "properties": map[string]any{"q": map[string]any{"type": "string"}},
		}}},
	}
	completion, err := client.Generate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(completion.Message.ToolCalls) != 1 || completion.Message.ToolCalls[0].Function.Name != "lookup" {
		t.Fatalf("unexpected tool call: %#v", completion.Message.ToolCalls)
	}

	stream, err := client.Stream(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	first, err := stream.Recv()
	if err != nil || first.ReasoningContent != "think" {
		t.Fatalf("first delta = %#v, err=%v", first, err)
	}
	second, err := stream.Recv()
	if err != nil || second.Content != "answer" {
		t.Fatalf("second delta = %#v, err=%v", second, err)
	}
	third, err := stream.Recv()
	if err != nil || len(third.ToolCalls) != 1 || third.ToolCalls[0].Index != 2 || third.ToolCalls[0].Function.Name != "lookup" {
		t.Fatalf("third delta = %#v, err=%v", third, err)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("stream end error = %v, want EOF", err)
	}
}

func TestAnthropicToolCallAndStream(t *testing.T) {
	t.Parallel()

	secret := generatedCredential(t)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if payload["system"] != "system policy" || payload["model"] != "test-model" {
			t.Errorf("unexpected payload: %#v", payload)
		}
		if requests == 1 {
			_, _ = io.WriteString(w, `{"content":[{"type":"tool_use","id":"call-1","name":"lookup","input":{"q":"x"}},{"type":"text","text":"done"}]}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"think\"}}\n\n")
		_, _ = io.WriteString(w, "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"answer\"}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer server.Close()

	client := mustTestClient(t, Profile{
		Provider:          ProviderAnthropic,
		Model:             "test-model",
		BaseURL:           server.URL,
		SecretRef:         "secret:model",
		AllowInsecureHTTP: true,
	}, secret)
	request := CompletionRequest{
		Messages: []Message{
			{Role: RoleSystem, Content: "system policy"},
			{Role: RoleUser, Content: "hello"},
		},
		Tools: []Tool{{Name: "lookup", InputSchema: map[string]any{"type": "object"}}},
	}
	completion, err := client.Generate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if completion.Message.Content != "done" || len(completion.Message.ToolCalls) != 1 || completion.Message.ToolCalls[0].Function.Arguments != `{"q":"x"}` {
		t.Fatalf("unexpected completion: %#v", completion.Message)
	}
	stream, err := client.Stream(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	first, err := stream.Recv()
	if err != nil || first.ReasoningContent != "think" {
		t.Fatalf("first delta = %#v, err=%v", first, err)
	}
	second, err := stream.Recv()
	if err != nil || second.Content != "answer" {
		t.Fatalf("second delta = %#v, err=%v", second, err)
	}
}

func TestStreamDoneTerminatesWithoutWaitingForConnectionClose(t *testing.T) {
	t.Parallel()

	secret := generatedCredential(t)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-release
	}))
	defer server.Close()
	defer close(release)

	client := mustTestClient(t, Profile{
		Provider:          ProviderOpenAICompatible,
		Model:             "test-model",
		BaseURL:           server.URL + "/v1",
		SecretRef:         "secret:model",
		AllowInsecureHTTP: true,
	}, secret)
	stream, err := client.Stream(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hello"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	result := make(chan error, 1)
	go func() {
		_, recvErr := stream.Recv()
		result <- recvErr
	}()
	select {
	case recvErr := <-result:
		if !errors.Is(recvErr, io.EOF) {
			t.Fatalf("stream end error = %v, want EOF", recvErr)
		}
	case <-time.After(time.Second):
		t.Fatal("stream waited for the provider connection after [DONE]")
	}
}

func TestStreamProviderErrorDoesNotExposeEventBody(t *testing.T) {
	t.Parallel()

	secret := generatedCredential(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		data, _ := json.Marshal(map[string]any{"error": map[string]any{"message": "provider echoed " + string(secret)}})
		_, _ = io.WriteString(w, "data: "+string(data)+"\n\n")
	}))
	defer server.Close()

	client := mustTestClient(t, Profile{
		Provider:          ProviderOpenAICompatible,
		Model:             "test-model",
		BaseURL:           server.URL + "/v1",
		SecretRef:         "secret:model",
		AllowInsecureHTTP: true,
	}, secret)
	stream, err := client.Stream(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "hello"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_, err = stream.Recv()
	if !errors.Is(err, ErrProviderUnavailable) || strings.Contains(err.Error(), string(secret)) {
		t.Fatalf("unsafe stream error: %v", err)
	}
}

func generatedCredential(t *testing.T) []byte {
	t.Helper()
	value := make([]byte, 36)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(value)))
	base64.RawURLEncoding.Encode(encoded, value)
	return encoded
}

func basePathForTest(provider Provider) string {
	if provider == ProviderOpenAICompatible {
		return "/v1"
	}
	return ""
}

func mustTestClient(t *testing.T, profile Profile, secret []byte) Client {
	t.Helper()
	client, err := NewClient(profile, SecretResolverFunc(func(context.Context, string) ([]byte, error) {
		return append([]byte(nil), secret...), nil
	}), WithHTTPClient(&http.Client{Timeout: defaultHTTPTimeout}))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type httpClientFunc func(*http.Request) (*http.Response, error)

func (f httpClientFunc) Do(request *http.Request) (*http.Response, error) {
	return f(request)
}
