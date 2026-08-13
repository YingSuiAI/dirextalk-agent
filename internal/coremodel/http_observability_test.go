package coremodel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
