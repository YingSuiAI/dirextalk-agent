package coremodel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenAICompatibleToolRoundReplaysReasoningContent(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request %d: %v", calls, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if calls == 1 {
			_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"search first\",\"tool_calls\":[{\"index\":0,\"id\":\"call-1\",\"type\":\"function\",\"function\":{\"name\":\"web_search\",\"arguments\":\"{\\\"query\\\":\\\"GitHub trending\\\"}\"}}]}}]}\n\n")
			_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n")
			return
		}
		messages, _ := payload["messages"].([]any)
		if len(messages) != 3 {
			t.Errorf("second request messages=%#v", messages)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		assistant, _ := messages[1].(map[string]any)
		if assistant["reasoning_content"] != "search first" || assistant["reasoning"] != nil {
			t.Errorf("assistant tool message=%#v", assistant)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"done\"}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n")
	}))
	defer server.Close()

	profile := validProfile(ProviderOpenAICompatible, server.URL, "key")
	client, err := NewClient(profile, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.Stream(context.Background(), CompletionRequest{
		Messages: []Message{{Role: RoleUser, Content: "GitHub trending"}},
		Tools:    []Tool{{Name: "web_search", InputSchema: map[string]any{"type": "object"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var reasoning string
	var toolCalls []ToolCall
	for {
		delta, recvErr := first.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			t.Fatal(recvErr)
		}
		reasoning += delta.ReasoningContent
		toolCalls = append(toolCalls, delta.ToolCalls...)
	}
	_ = first.Close()
	if reasoning != "search first" || len(toolCalls) != 1 {
		t.Fatalf("first response reasoning=%q tool_calls=%#v", reasoning, toolCalls)
	}

	second, err := client.Stream(context.Background(), CompletionRequest{
		Messages: []Message{
			{Role: RoleUser, Content: "GitHub trending"},
			{Role: RoleAssistant, ReasoningContent: reasoning, ToolCalls: toolCalls},
			{Role: RoleTool, ToolCallID: "call-1", Name: "web_search", Content: `{"items":[]}`},
		},
		Tools: []Tool{{Name: "web_search", InputSchema: map[string]any{"type": "object"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	delta, err := second.Recv()
	if err != nil || delta.Content != "done" || calls != 2 {
		t.Fatalf("second response=%#v calls=%d err=%v", delta, calls, err)
	}
	_ = second.Close()
}

func TestSafeFailureClassDistinguishesProviderFailureKinds(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	client, err := NewClient(validProfile(ProviderOpenAICompatible, server.URL, "private-key"), WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	_, httpErr := client.Generate(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "private prompt"}}})
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{name: "request", err: ErrProviderUnavailable, want: "provider_request_failure"},
		{name: "http", err: httpErr, want: "provider_http_4xx"},
		{name: "invalid response", err: ErrInvalidResponse, want: "provider_invalid_response"},
		{name: "truncated stream", err: ErrStreamTruncated, want: "provider_stream_truncated"},
		{name: "unrelated", err: errors.New("private detail"), want: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := SafeFailureClass(test.err); got != test.want {
				t.Fatalf("SafeFailureClass()=%q, want %q", got, test.want)
			}
		})
	}
	if !errors.Is(httpErr, ErrProviderUnavailable) {
		t.Fatalf("HTTP status error no longer preserves ErrProviderUnavailable: %v", httpErr)
	}
}
