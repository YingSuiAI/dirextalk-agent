package coremodel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	const responseSecret = "private-provider-response"
	for _, test := range []struct {
		name   string
		status int
		class  string
		kind   error
	}{
		{name: "rejected", status: http.StatusBadRequest, class: "provider_http_4xx", kind: ErrProviderRejected},
		{name: "rate limited", status: http.StatusTooManyRequests, class: "provider_http_4xx", kind: ErrProviderRateLimited},
		{name: "server", status: http.StatusServiceUnavailable, class: "provider_http_5xx", kind: ErrProviderServerFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := validProfile(ProviderOpenAICompatible, "https://example.test", "private-key")
			providerHTTP := roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(responseSecret)), Header: make(http.Header)}, nil
			})
			client, err := NewClient(profile, WithHTTPClient(providerHTTP))
			if err != nil {
				t.Fatal(err)
			}
			tester := NewConnectionTester(WithHTTPClient(providerHTTP))
			request := CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "private prompt"}}}
			for operation, run := range map[string]func() error{
				"connection": func() error { return tester.TestConnection(context.Background(), profile) },
				"generate":   func() error { _, runErr := client.Generate(context.Background(), request); return runErr },
				"stream":     func() error { _, runErr := client.Stream(context.Background(), request); return runErr },
			} {
				gotErr := run()
				if !errors.Is(gotErr, ErrProviderUnavailable) || !errors.Is(gotErr, test.kind) || SafeFailureClass(gotErr) != test.class {
					t.Fatalf("%s status=%d err=%v class=%q", operation, test.status, gotErr, SafeFailureClass(gotErr))
				}
				if strings.Contains(gotErr.Error(), responseSecret) || strings.Contains(gotErr.Error(), "private-key") || strings.Contains(gotErr.Error(), "private prompt") {
					t.Fatalf("%s status error leaked secrets: %v", operation, gotErr)
				}
			}
		})
	}

	timeoutClient, err := NewClient(validProfile(ProviderOpenAICompatible, "https://example.test", "private-key"), WithHTTPClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})), WithTimeout(10*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	_, timeoutErr := timeoutClient.Generate(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "private prompt"}}})
	if !errors.Is(timeoutErr, ErrProviderTimeout) || !errors.Is(timeoutErr, context.DeadlineExceeded) || SafeFailureClass(timeoutErr) != "provider_timeout" {
		t.Fatalf("timeout err=%v class=%q", timeoutErr, SafeFailureClass(timeoutErr))
	}
	if strings.Contains(timeoutErr.Error(), "private-key") || strings.Contains(timeoutErr.Error(), "private prompt") {
		t.Fatalf("timeout error leaked secrets: %v", timeoutErr)
	}
	_, streamTimeoutErr := timeoutClient.Stream(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "private prompt"}}})
	if !errors.Is(streamTimeoutErr, ErrProviderTimeout) || !errors.Is(streamTimeoutErr, context.DeadlineExceeded) || SafeFailureClass(streamTimeoutErr) != "provider_timeout" {
		t.Fatalf("stream timeout err=%v class=%q", streamTimeoutErr, SafeFailureClass(streamTimeoutErr))
	}
	transportTimeoutClient, err := NewClient(validProfile(ProviderOpenAICompatible, "https://example.test", "private-key"), WithHTTPClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, timeoutTestError("private transport detail")
	})))
	if err != nil {
		t.Fatal(err)
	}
	_, transportTimeoutErr := transportTimeoutClient.Generate(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "private prompt"}}})
	if !errors.Is(transportTimeoutErr, ErrProviderTimeout) || !errors.Is(transportTimeoutErr, context.DeadlineExceeded) || strings.Contains(transportTimeoutErr.Error(), "private transport detail") {
		t.Fatalf("transport timeout err=%v class=%q", transportTimeoutErr, SafeFailureClass(transportTimeoutErr))
	}

	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{name: "request", err: ErrProviderUnavailable, want: "provider_request_failure"},
		{name: "idle timeout", err: ErrStreamIdleTimeout, want: "provider_timeout"},
		{name: "invalid response", err: ErrInvalidResponse, want: "provider_invalid_response"},
		{name: "tool call format", err: ErrModelToolCallFormatInvalid, want: "model_tool_call_format_invalid"},
		{name: "truncated stream", err: ErrStreamTruncated, want: "provider_stream_truncated"},
		{name: "unrelated", err: errors.New("private detail"), want: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := SafeFailureClass(test.err); got != test.want {
				t.Fatalf("SafeFailureClass()=%q, want %q", got, test.want)
			}
		})
	}
}

func TestPreOutputRetryMetadataAllowlistAndRetryAfter(t *testing.T) {
	if retry := PreOutputRetryMetadata(ErrModelToolCallFormatInvalid); !retry.Retryable || retry.RateLimited || retry.RetryAfter != 0 {
		t.Fatalf("tool-call format retry=%+v", retry)
	}
	date := time.Now().UTC().Add(time.Hour).Format(http.TimeFormat)
	tests := []struct {
		status      int
		retryAfter  string
		want        bool
		rateLimited bool
		wantDelay   time.Duration
	}{
		{status: 408, want: true},
		{status: 429, retryAfter: "7", want: true, rateLimited: true, wantDelay: 7 * time.Second},
		{status: 502, want: true},
		{status: 503, retryAfter: date, want: true, wantDelay: 30 * time.Second},
		{status: 504, want: true},
		{status: 429, retryAfter: "9223372036854775807", want: true, rateLimited: true, wantDelay: 30 * time.Second},
		{status: 500, want: false},
		{status: 400, want: false},
	}
	for _, test := range tests {
		header := make(http.Header)
		header.Set("Retry-After", test.retryAfter)
		got := PreOutputRetryMetadata(providerHTTPStatusFailure(test.status, header))
		if got.Retryable != test.want || got.RateLimited != test.rateLimited || got.RetryAfter != test.wantDelay {
			t.Fatalf("status=%d metadata=%+v", test.status, got)
		}
	}
}

func TestPreOutputRetryMetadataOnlyAcceptsConfirmedDialFailure(t *testing.T) {
	dial := providerRequestFailure(context.Background(), &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("refused")})
	if got := PreOutputRetryMetadata(dial); !got.Retryable {
		t.Fatalf("dial metadata=%+v err=%v", got, dial)
	}
	generic := providerRequestFailure(context.Background(), errors.New("ambiguous transport failure"))
	if got := PreOutputRetryMetadata(generic); got.Retryable {
		t.Fatalf("ambiguous transport metadata=%+v err=%v", got, generic)
	}
}

type timeoutTestError string

func (e timeoutTestError) Error() string { return string(e) }
func (timeoutTestError) Timeout() bool   { return true }
