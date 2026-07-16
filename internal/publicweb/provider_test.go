package publicweb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
)

const (
	testRequestID      = "785f27b7-17cf-4ad1-96c4-d6a1449fa166"
	testOwnerID        = "project-owner"
	testConversationID = "conversation-1"
	testToolCallID     = "tool-call-1"
)

func TestProviderFetchesOfficialSourceAsDeSecretedPlainText(t *testing.T) {
	t.Parallel()
	body := []byte(`<!doctype html><html><head><title>Official Guide</title><script>steal()</script></head><body><h1>Install</h1><p>Use the signed release.</p><style>.hidden{}</style></body></html>`)
	var calls atomic.Int32
	provider := testProvider(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		if request.Method != http.MethodGet {
			t.Fatalf("method = %q, want GET", request.Method)
		}
		if request.Header.Get("Authorization") != "" || request.Header.Get("Proxy-Authorization") != "" {
			t.Fatal("fetch request must never carry credentials")
		}
		return response(http.StatusOK, "text/html; charset=utf-8", body), nil
	}))
	provider.now = func() time.Time { return time.Date(2026, 7, 16, 3, 4, 5, 0, time.UTC) }

	tool := fetchTool(t, provider, validToolRequest())
	if tool.Definition.Name != ToolName {
		t.Fatalf("tool name = %q, want %q", tool.Definition.Name, ToolName)
	}
	properties, _ := tool.Definition.InputSchema["properties"].(map[string]any)
	if len(properties) != 1 || properties["url"] == nil {
		t.Fatalf("input schema must expose only url: %#v", tool.Definition.InputSchema)
	}

	result, err := tool.Run(context.Background(), validInvocation(`{"url":"https://docs.example.com/guide"}`))
	if err != nil {
		t.Fatalf("run tool: %v", err)
	}
	if result.IsError {
		t.Fatal("successful fetch was marked as an error")
	}
	var got fetchResult
	if err := json.Unmarshal([]byte(result.Content), &got); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	wantDigest := sha256.Sum256(body)
	if got.URL != "https://docs.example.com/guide" || got.RetrievedAt != "2026-07-16T03:04:05Z" || got.ContentDigest != "sha256:"+hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("unexpected provenance: %#v", got)
	}
	evidence, err := ParseEvidenceResult(result.Content)
	if err != nil || evidence.URL != got.URL || evidence.RetrievedAt.Format(time.RFC3339Nano) != got.RetrievedAt || evidence.ContentDigest != got.ContentDigest {
		t.Fatalf("parse durable evidence = %#v, err=%v", evidence, err)
	}
	if !strings.Contains(got.Content, "Official Guide") || !strings.Contains(got.Content, "Use the signed release.") {
		t.Fatalf("missing safe source text: %q", got.Content)
	}
	for _, forbidden := range []string{"steal()", ".hidden{}", "<script", "<style"} {
		if strings.Contains(got.Content, forbidden) {
			t.Fatalf("unsafe HTML content retained %q: %q", forbidden, got.Content)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("transport calls = %d, want 1", calls.Load())
	}
}

func TestParseEvidenceResultRejectsForgedOrIncompleteProvenance(t *testing.T) {
	t.Parallel()
	valid := `{"url":"https://docs.example.com/guide","retrieved_at":"2026-07-16T03:04:05Z","content_digest":"sha256:` + strings.Repeat("a", 64) + `","content":"official"}`
	if _, err := ParseEvidenceResult(valid); err != nil {
		t.Fatalf("valid evidence rejected: %v", err)
	}
	for _, raw := range []string{
		`{"url":"https://docs.example.com/guide","retrieved_at":"2026-07-16T03:04:05Z","content":"official"}`,
		`{"url":"https://docs.example.com/guide","retrieved_at":"2026-07-16T03:04:05Z","content_digest":"sha256:bad","content":"official"}`,
		`{"url":"https://127.0.0.1/guide","retrieved_at":"2026-07-16T03:04:05Z","content_digest":"sha256:` + strings.Repeat("a", 64) + `","content":"official"}`,
		valid + `{}`,
	} {
		if _, err := ParseEvidenceResult(raw); !errors.Is(err, ErrResponseRejected) {
			t.Fatalf("forged evidence error = %v, want ErrResponseRejected", err)
		}
	}
}

func TestProviderBindsEveryInvocationFieldToAuthenticatedToolRequest(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	provider := testProvider(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return response(http.StatusOK, "text/plain", []byte("official")), nil
	}))
	tool := fetchTool(t, provider, validToolRequest())

	tests := []struct {
		name   string
		mutate func(*runtimeapi.ToolInvocation)
	}{
		{name: "request", mutate: func(v *runtimeapi.ToolInvocation) { v.RequestID = "other" }},
		{name: "owner", mutate: func(v *runtimeapi.ToolInvocation) { v.OwnerID = "other" }},
		{name: "conversation", mutate: func(v *runtimeapi.ToolInvocation) { v.ConversationID = "other" }},
		{name: "tool call", mutate: func(v *runtimeapi.ToolInvocation) { v.ToolCallID = "" }},
		{name: "name", mutate: func(v *runtimeapi.ToolInvocation) { v.Name = "other" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invocation := validInvocation(`{"url":"https://docs.example.com/guide"}`)
			test.mutate(&invocation)
			if _, err := tool.Run(context.Background(), invocation); !errors.Is(err, ErrInvocationScopeMismatch) {
				t.Fatalf("error = %v, want ErrInvocationScopeMismatch", err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("scope failures reached transport %d times", calls.Load())
	}
}

func TestProviderRejectsSSRFAndCredentialBearingURLsBeforeTransport(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	provider := testProvider(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return response(http.StatusOK, "text/plain", []byte("unexpected")), nil
	}))
	provider.resolver = staticResolver{addresses: []netip.Addr{netip.MustParseAddr("10.0.0.8")}}
	tool := fetchTool(t, provider, validToolRequest())

	denied := []string{
		`{"url":"http://docs.example.com/guide"}`,
		`{"url":"file:///etc/passwd"}`,
		`{"url":"https://user:password@docs.example.com/guide"}`,
		`{"url":"https://docs.example.com/guide#private"}`,
		`{"url":"https://docs.example.com/guide?access_token=value"}`,
		`{"url":"https://docs.example.com/guide?secret=value"}`,
		`{"url":"https://docs.example.com/guide?authorization=value"}`,
		`{"url":"https://docs.example.com/guide?apiKey=value"}`,
		`{"url":"https://docs.example.com/guide?X-Amz-Signature=value"}`,
		`{"url":"https://127.0.0.1/guide"}`,
		`{"url":"https://169.254.169.254/latest/meta-data"}`,
		`{"url":"https://localhost/guide"}`,
		`{"url":"https://docs.example.com/guide"}`,
	}
	for _, arguments := range denied {
		if _, err := tool.Run(context.Background(), validInvocation(arguments)); !errors.Is(err, ErrURLDenied) {
			t.Fatalf("arguments %s error = %v, want ErrURLDenied", arguments, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("denied URLs reached transport %d times", calls.Load())
	}

	for _, arguments := range []string{
		`{"url":"https://docs.example.com","authorization":"Bearer raw"}`,
		`{"url":"https://docs.example.com","method":"POST"}`,
		`{"url":"https://docs.example.com"} {}`,
		`[]`,
	} {
		if _, err := tool.Run(context.Background(), validInvocation(arguments)); !errors.Is(err, ErrInvalidArguments) {
			t.Fatalf("arguments %s error = %v, want ErrInvalidArguments", arguments, err)
		}
	}
}

func TestProviderDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	provider := testProvider(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		response := response(http.StatusFound, "text/plain", nil)
		response.Header.Set("Location", "https://127.0.0.1/private")
		return response, nil
	}))
	tool := fetchTool(t, provider, validToolRequest())
	_, err := tool.Run(context.Background(), validInvocation(`{"url":"https://docs.example.com/guide"}`))
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("error = %v, want ErrResponseRejected", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("redirect caused %d requests, want exactly 1", calls.Load())
	}
}

func TestProviderRejectsOversizeAndUnsupportedResponsesWithoutLeakingBody(t *testing.T) {
	t.Parallel()
	secretCanary := "sk-this-provider-error-must-never-escape"
	tests := []struct {
		name string
		rt   http.RoundTripper
		want error
	}{
		{
			name: "declared oversize",
			rt: roundTripFunc(func(*http.Request) (*http.Response, error) {
				result := response(http.StatusOK, "text/plain", []byte("small"))
				result.ContentLength = maxResponseBytes + 1
				return result, nil
			}),
			want: ErrResponseTooLarge,
		},
		{
			name: "streamed oversize",
			rt: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return response(http.StatusOK, "text/plain", bytes.Repeat([]byte("a"), maxResponseBytes+1)), nil
			}),
			want: ErrResponseTooLarge,
		},
		{
			name: "unsupported",
			rt: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return response(http.StatusOK, "application/octet-stream", []byte(secretCanary)), nil
			}),
			want: ErrUnsupportedContentType,
		},
		{
			name: "request failure",
			rt: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New(secretCanary + " https://private.example")
			}),
			want: ErrFetchFailed,
		},
		{
			name: "body read failure",
			rt: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(failingReader{err: errors.New(secretCanary + " https://private.example")})}, nil
			}),
			want: ErrFetchFailed,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := testProvider(test.rt)
			tool := fetchTool(t, provider, validToolRequest())
			_, err := tool.Run(context.Background(), validInvocation(`{"url":"https://docs.example.com/guide"}`))
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), secretCanary) || strings.Contains(err.Error(), "private.example") || strings.Contains(err.Error(), "docs.example.com") {
				t.Fatalf("stable error leaked provider detail: %v", err)
			}
		})
	}
}

func TestProviderHonorsCancellation(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	provider := testProvider(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		close(started)
		<-request.Context().Done()
		return nil, request.Context().Err()
	}))
	tool := fetchTool(t, provider, validToolRequest())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := tool.Run(ctx, validInvocation(`{"url":"https://docs.example.com/guide"}`))
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fetch did not stop after cancellation")
	}
}

func TestProviderTimeoutAlsoBoundsDNSResolution(t *testing.T) {
	t.Parallel()
	provider := New()
	provider.timeout = 10 * time.Millisecond
	provider.resolver = blockingResolver{}
	tool := fetchTool(t, provider, validToolRequest())
	started := time.Now()
	_, err := tool.Run(context.Background(), validInvocation(`{"url":"https://docs.example.com/guide"}`))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("DNS resolution exceeded the provider deadline")
	}
}

func TestProviderRedactsRawSecretsFromFetchedContent(t *testing.T) {
	t.Parallel()
	canaries := []string{
		"sk-abcdefghijklmnopqrstuvwxyz123456",
		"AKIAABCDEFGHIJKLMNOP",
		"top-secret-password",
		"private-key-canary",
		"generic-secret-canary",
	}
	body := []byte("model=" + canaries[0] + " access=" + canaries[1] + " password=" + canaries[2] + " secret=" + canaries[4] + "\n-----BEGIN PRIVATE KEY-----\n" + canaries[3] + "\n-----END PRIVATE KEY-----")
	provider := testProvider(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, "text/plain", body), nil
	}))
	tool := fetchTool(t, provider, validToolRequest())
	result, err := tool.Run(context.Background(), validInvocation(`{"url":"https://docs.example.com/guide"}`))
	if err != nil {
		t.Fatalf("run tool: %v", err)
	}
	for _, canary := range canaries {
		if strings.Contains(result.Content, canary) {
			t.Fatalf("result retained secret canary %q", canary)
		}
	}
	if !strings.Contains(strings.ToLower(result.Content), "redacted") {
		t.Fatalf("result did not preserve a redaction marker: %s", result.Content)
	}
}

func TestDNSRebindingIsRejectedByDialTimeResolution(t *testing.T) {
	t.Parallel()
	resolver := &sequenceResolver{answers: [][]netip.Addr{
		{netip.MustParseAddr("93.184.216.34")},
		{netip.MustParseAddr("127.0.0.1")},
	}}
	if err := validateResolvedHost(context.Background(), resolver, "docs.example.com"); err != nil {
		t.Fatalf("preflight validation: %v", err)
	}
	connector := &recordingDialer{}
	dialer := &publicDialer{resolver: resolver, dialer: connector}
	if _, err := dialer.DialContext(context.Background(), "tcp", "docs.example.com:443"); !errors.Is(err, ErrURLDenied) {
		t.Fatalf("dial error = %v, want ErrURLDenied", err)
	}
	if connector.calls.Load() != 0 {
		t.Fatalf("unsafe rebound address reached network dialer %d times", connector.calls.Load())
	}
}

func TestDefaultTransportDisablesEnvironmentProxy(t *testing.T) {
	t.Parallel()
	transport, ok := newSecureTransport(net.DefaultResolver).(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", transport)
	}
	if transport.Proxy != nil {
		t.Fatal("secure transport must not consult environment proxies")
	}
}

func testProvider(transport http.RoundTripper) *Provider {
	provider := New()
	provider.resolver = staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	provider.client = &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return provider
}

func fetchTool(t *testing.T, provider *Provider, request runtimeapi.ToolRequest) runtimeapi.Tool {
	t.Helper()
	tools, err := provider.Tools(context.Background(), request)
	if err != nil {
		t.Fatalf("load tools: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("tool count = %d, want 1", len(tools))
	}
	return tools[0]
}

func validToolRequest() runtimeapi.ToolRequest {
	return runtimeapi.ToolRequest{RequestID: testRequestID, OwnerID: testOwnerID, ConversationID: testConversationID, EnabledNames: []string{ToolName}}
}

func validInvocation(arguments string) runtimeapi.ToolInvocation {
	return runtimeapi.ToolInvocation{
		RequestID:      testRequestID,
		OwnerID:        testOwnerID,
		ConversationID: testConversationID,
		ToolCallID:     testToolCallID,
		Name:           ToolName,
		Arguments:      json.RawMessage(arguments),
	}
}

func response(status int, contentType string, body []byte) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Header:        http.Header{"Content-Type": []string{contentType}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type staticResolver struct {
	addresses []netip.Addr
	err       error
}

type blockingResolver struct{}

func (blockingResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (r staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r.addresses...), r.err
}

type sequenceResolver struct {
	mu      sync.Mutex
	answers [][]netip.Addr
	index   int
}

func (r *sequenceResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.index >= len(r.answers) {
		return nil, errors.New("no more DNS answers")
	}
	answer := append([]netip.Addr(nil), r.answers[r.index]...)
	r.index++
	return answer, nil
}

type recordingDialer struct {
	calls atomic.Int32
}

func (d *recordingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.calls.Add(1)
	return nil, errors.New("network disabled in test")
}

type failingReader struct {
	err error
}

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }
