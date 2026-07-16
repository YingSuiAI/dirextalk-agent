package mcphttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
)

const testCredential = "mcp-secret-canary-123456789"

func TestProviderNegotiatesStreamableHTTPAndCallsTool(t *testing.T) {
	t.Parallel()

	harness := &mcpHarness{
		t:          t,
		credential: testCredential,
		tools: []map[string]any{{
			"name":        "search",
			"description": "Search the trusted documentation service.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"query": map[string]any{"type": "string"}},
				"required":   []string{"query"},
			},
		}},
		callResult: map[string]any{
			"content": []map[string]any{{"type": "text", "text": "trusted result"}},
		},
		streamListResponse: true,
	}
	server := httptest.NewTLSServer(http.HandlerFunc(harness.handle))
	t.Cleanup(server.Close)

	resolver := &recordingResolver{value: []byte(testCredential)}
	capture := &capturingTransport{base: server.Client().Transport}
	provider, err := New([]ServerConfig{{
		ID:        "docs",
		Endpoint:  server.URL + "/mcp",
		SecretRef: "secret://mcp/docs",
	}}, resolver, WithEndpointPolicy(allowEndpointPolicy), WithRoundTripper(capture))
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	tools, err := provider.Tools(context.Background(), runtimeapi.ToolRequest{
		RequestID: "request-1", OwnerID: "owner-1", ConversationID: "conversation-1",
	})
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected one tool, got %d", len(tools))
	}
	if tools[0].Definition.Name != "mcp__docs__search" {
		t.Fatalf("unexpected exposed tool name %q", tools[0].Definition.Name)
	}
	if tools[0].Definition.InputSchema["type"] != "object" {
		t.Fatalf("missing input schema: %#v", tools[0].Definition.InputSchema)
	}

	result, err := tools[0].Run(context.Background(), runtimeapi.ToolInvocation{
		RequestID: "request-1", OwnerID: "owner-1", ConversationID: "conversation-1",
		ToolCallID: "call-1", Name: tools[0].Definition.Name,
		Arguments: json.RawMessage(`{"query":"durable tasks"}`),
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if result.IsError || result.Content != "trusted result" {
		t.Fatalf("unexpected tool result: %#v", result)
	}

	methods := harness.methodSnapshot()
	wantMethods := []string{"initialize", "notifications/initialized", "tools/list", "tools/call"}
	if fmt.Sprint(methods) != fmt.Sprint(wantMethods) {
		t.Fatalf("unexpected protocol sequence: got %v want %v", methods, wantMethods)
	}
	if resolver.callCount() != len(wantMethods) {
		t.Fatalf("credential should be resolved per request, got %d resolutions", resolver.callCount())
	}
	resolver.assertReturnedBuffersZeroed(t)
	capture.assertAuthorizationRemoved(t)
}

func TestProviderCancellationAndTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ctx     func() (context.Context, context.CancelFunc)
		options []Option
		want    error
	}{
		{
			name: "caller cancellation",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
			want: context.Canceled,
		},
		{
			name: "provider timeout",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			options: []Option{WithRequestTimeout(15 * time.Millisecond)},
			want:    context.DeadlineExceeded,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				<-request.Context().Done()
				return nil, request.Context().Err()
			})
			options := append([]Option{WithEndpointPolicy(allowEndpointPolicy), WithRoundTripper(transport)}, test.options...)
			provider, err := New([]ServerConfig{{ID: "blocked", Endpoint: "https://mcp.example.test/mcp"}}, nil, options...)
			if err != nil {
				t.Fatalf("new provider: %v", err)
			}
			ctx, cancel := test.ctx()
			defer cancel()
			_, err = provider.Tools(ctx, runtimeapi.ToolRequest{RequestID: "request"})
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestProviderErrorsNeverExposeCredentialOrProviderDetails(t *testing.T) {
	t.Parallel()

	t.Run("transport error", func(t *testing.T) {
		resolver := &recordingResolver{value: []byte(testCredential)}
		provider, err := New(
			[]ServerConfig{{ID: "broken", Endpoint: "https://mcp.example.test/mcp", SecretRef: "secret://broken"}},
			resolver,
			WithEndpointPolicy(allowEndpointPolicy),
			WithRoundTripper(roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, fmt.Errorf("upstream included %s in its failure", testCredential)
			})),
		)
		if err != nil {
			t.Fatalf("new provider: %v", err)
		}

		_, err = provider.Tools(context.Background(), runtimeapi.ToolRequest{RequestID: "request"})
		assertProviderErrorRedacted(t, err)
		resolver.assertReturnedBuffersZeroed(t)
	})

	t.Run("JSON-RPC error", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			var rpcRequest testRPCRequest
			if err := json.NewDecoder(request.Body).Decode(&rpcRequest); err != nil {
				t.Errorf("decode request: %v", err)
			}
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0", "id": json.RawMessage(rpcRequest.ID),
				"error": map[string]any{"code": -32000, "message": "provider leaked " + testCredential},
			})
		}))
		defer server.Close()
		resolver := &recordingResolver{value: []byte(testCredential)}
		provider, err := New(
			[]ServerConfig{{ID: "broken", Endpoint: server.URL + "/mcp", SecretRef: "secret://broken"}}, resolver,
			WithEndpointPolicy(allowEndpointPolicy), WithRoundTripper(server.Client().Transport),
		)
		if err != nil {
			t.Fatalf("new provider: %v", err)
		}
		_, err = provider.Tools(context.Background(), runtimeapi.ToolRequest{RequestID: "request"})
		assertProviderErrorRedacted(t, err)
		resolver.assertReturnedBuffersZeroed(t)
	})
}

func assertProviderErrorRedacted(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected provider unavailable, got %v", err)
	}
	if strings.Contains(err.Error(), testCredential) || strings.Contains(err.Error(), "upstream included") || strings.Contains(err.Error(), "provider leaked") {
		t.Fatalf("provider error leaked details: %v", err)
	}
}

func TestProviderRejectsUnsafeEndpointsRedirectsAndTransports(t *testing.T) {
	t.Parallel()

	t.Run("private endpoint is denied before credential resolution", func(t *testing.T) {
		resolver := &recordingResolver{value: []byte(testCredential)}
		provider, err := New([]ServerConfig{{
			ID: "private", Endpoint: "https://127.0.0.1/mcp", SecretRef: "secret://private",
		}}, resolver, WithRoundTripper(roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("transport must not run for a private endpoint")
			return nil, nil
		})))
		if err != nil {
			t.Fatalf("new provider: %v", err)
		}
		_, err = provider.Tools(context.Background(), runtimeapi.ToolRequest{RequestID: "request"})
		if !errors.Is(err, ErrEndpointDenied) {
			t.Fatalf("expected endpoint denial, got %v", err)
		}
		if resolver.callCount() != 0 {
			t.Fatalf("credential resolved before endpoint validation")
		}
	})

	t.Run("redirect is not followed", func(t *testing.T) {
		var redirected int
		target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			redirected++
		}))
		defer target.Close()
		source := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			http.Redirect(writer, request, target.URL+"/mcp", http.StatusTemporaryRedirect)
		}))
		defer source.Close()

		provider, err := New(
			[]ServerConfig{{ID: "redirect", Endpoint: source.URL + "/mcp"}}, nil,
			WithEndpointPolicy(allowEndpointPolicy), WithRoundTripper(source.Client().Transport),
		)
		if err != nil {
			t.Fatalf("new provider: %v", err)
		}
		_, err = provider.Tools(context.Background(), runtimeapi.ToolRequest{RequestID: "request"})
		if !errors.Is(err, ErrProviderUnavailable) {
			t.Fatalf("expected redirect failure, got %v", err)
		}
		if redirected != 0 {
			t.Fatalf("redirect target was contacted %d times", redirected)
		}
	})

	for _, transport := range []string{"stdio", "sse", "npx", "npm"} {
		transport := transport
		t.Run("transport_"+transport, func(t *testing.T) {
			_, err := New([]ServerConfig{{ID: "unsafe", Endpoint: "https://mcp.example.test/mcp", Transport: transport}}, nil)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("expected invalid config for %q, got %v", transport, err)
			}
		})
	}

	for _, endpoint := range []string{
		"http://mcp.example.test/mcp",
		"https://user:password@mcp.example.test/mcp",
		"https://mcp.example.test/mcp?token=raw",
		"https://mcp.example.test/mcp#fragment",
	} {
		endpoint := endpoint
		t.Run("endpoint_"+url.PathEscape(endpoint), func(t *testing.T) {
			_, err := New([]ServerConfig{{ID: "unsafe", Endpoint: endpoint}}, nil)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("expected invalid config for %q, got %v", endpoint, err)
			}
		})
	}
}

func TestProviderRejectsDuplicateToolsInvalidSchemasAndRawCredentialArguments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		tools []map[string]any
	}{
		{
			name: "duplicate tool",
			tools: []map[string]any{
				{"name": "lookup", "inputSchema": map[string]any{"type": "object"}},
				{"name": "lookup", "inputSchema": map[string]any{"type": "object"}},
			},
		},
		{
			name:  "missing object type",
			tools: []map[string]any{{"name": "lookup", "inputSchema": map[string]any{"type": "string"}}},
		},
		{
			name: "credential field in schema",
			tools: []map[string]any{{
				"name": "lookup",
				"inputSchema": map[string]any{
					"type": "object", "properties": map[string]any{"secret_ref": map[string]any{"type": "string"}},
				},
			}},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			harness := &mcpHarness{t: t, tools: test.tools}
			server := httptest.NewTLSServer(http.HandlerFunc(harness.handle))
			defer server.Close()
			provider := newTestProvider(t, server, nil)
			_, err := provider.Tools(context.Background(), runtimeapi.ToolRequest{RequestID: "request"})
			if !errors.Is(err, ErrInvalidToolDefinition) {
				t.Fatalf("expected invalid tool definition, got %v", err)
			}
		})
	}

	t.Run("raw credential arguments never reach provider", func(t *testing.T) {
		harness := &mcpHarness{
			t: t,
			tools: []map[string]any{{
				"name": "lookup", "inputSchema": map[string]any{"type": "object"},
			}},
			callResult: map[string]any{"content": []map[string]any{{"type": "text", "text": "should not run"}}},
		}
		server := httptest.NewTLSServer(http.HandlerFunc(harness.handle))
		defer server.Close()
		provider := newTestProvider(t, server, nil)
		tools, err := provider.Tools(context.Background(), runtimeapi.ToolRequest{RequestID: "request"})
		if err != nil {
			t.Fatalf("list tools: %v", err)
		}
		_, err = tools[0].Run(context.Background(), runtimeapi.ToolInvocation{
			RequestID: "request", ToolCallID: "call", Name: tools[0].Definition.Name,
			Arguments: json.RawMessage(`{"query":"ok","secret_ref":"attacker-controlled","authorization":"Bearer raw"}`),
		})
		if !errors.Is(err, ErrUnsafeToolArguments) {
			t.Fatalf("expected unsafe arguments error, got %v", err)
		}
		if harness.methodCount("tools/call") != 0 {
			t.Fatalf("unsafe arguments reached the MCP server")
		}
	})
}

func TestProviderRedactsAndBoundsToolResults(t *testing.T) {
	t.Parallel()

	unsafeText := strings.Repeat("x", maxToolResultBytes+1024) +
		" authorization=Bearer " + testCredential +
		" api_key=sk-abcdefghijklmnopqrstuvwxyz123456" +
		" aws=AKIA1234567890ABCDEF password=hunter2"
	harness := &mcpHarness{
		t:          t,
		credential: testCredential,
		tools: []map[string]any{{
			"name": "lookup", "inputSchema": map[string]any{"type": "object"},
		}},
		callResult: map[string]any{
			"content": []map[string]any{{"type": "text", "text": unsafeText}},
			"isError": true,
		},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(harness.handle))
	defer server.Close()
	resolver := &recordingResolver{value: []byte(testCredential)}
	provider := newTestProvider(t, server, resolver)
	tools, err := provider.Tools(context.Background(), runtimeapi.ToolRequest{RequestID: "request"})
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	result, err := tools[0].Run(context.Background(), runtimeapi.ToolInvocation{
		RequestID: "request", ToolCallID: "call", Name: tools[0].Definition.Name,
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if !result.IsError {
		t.Fatalf("MCP isError flag was not preserved")
	}
	if len(result.Content) > maxToolResultBytes || !utf8.ValidString(result.Content) {
		t.Fatalf("result was not safely bounded: %d bytes", len(result.Content))
	}
	for _, forbidden := range []string{testCredential, "sk-abcdefghijklmnopqrstuvwxyz123456", "AKIA1234567890ABCDEF", "hunter2"} {
		if strings.Contains(result.Content, forbidden) {
			t.Fatalf("result leaked %q", forbidden)
		}
	}
}

func TestProviderBoundsProtocolResponses(t *testing.T) {
	t.Parallel()

	provider, err := New(
		[]ServerConfig{{ID: "huge", Endpoint: "https://mcp.example.test/mcp"}}, nil,
		WithEndpointPolicy(allowEndpointPolicy),
		WithRoundTripper(roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), maxResponseBytes+1))),
			}, nil
		})),
	)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	_, err = provider.Tools(context.Background(), runtimeapi.ToolRequest{RequestID: "request"})
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("expected response size error, got %v", err)
	}
}

func newTestProvider(t *testing.T, server *httptest.Server, resolver runtimeapi.SecretResolver) *Provider {
	t.Helper()
	secretRef := ""
	if resolver != nil {
		secretRef = "secret://mcp/test"
	}
	provider, err := New(
		[]ServerConfig{{ID: "test", Endpoint: server.URL + "/mcp", SecretRef: secretRef}}, resolver,
		WithEndpointPolicy(allowEndpointPolicy), WithRoundTripper(server.Client().Transport),
	)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	return provider
}

var allowEndpointPolicy = EndpointPolicyFunc(func(context.Context, *url.URL) error { return nil })

type recordingResolver struct {
	mu       sync.Mutex
	value    []byte
	returned [][]byte
}

func (r *recordingResolver) ResolveSecret(context.Context, string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	value := append([]byte(nil), r.value...)
	r.returned = append(r.returned, value)
	return value, nil
}

func (r *recordingResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.returned)
}

func (r *recordingResolver) assertReturnedBuffersZeroed(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for index, value := range r.returned {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatalf("resolved credential buffer %d was not zeroed", index)
		}
	}
}

type capturingTransport struct {
	base http.RoundTripper
	mu   sync.Mutex
	reqs []*http.Request
}

func (t *capturingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Header.Get("Authorization") != "Bearer "+testCredential {
		return nil, fmt.Errorf("missing authorization")
	}
	t.mu.Lock()
	t.reqs = append(t.reqs, request)
	t.mu.Unlock()
	return t.base.RoundTrip(request)
}

func (t *capturingTransport) assertAuthorizationRemoved(testingT *testing.T) {
	testingT.Helper()
	t.mu.Lock()
	defer t.mu.Unlock()
	for index, request := range t.reqs {
		if got := request.Header.Get("Authorization"); got != "" {
			testingT.Fatalf("request %d retained authorization header", index)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type testRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type mcpHarness struct {
	t                  *testing.T
	credential         string
	tools              []map[string]any
	callResult         map[string]any
	streamListResponse bool

	mu      sync.Mutex
	methods []string
}

func (h *mcpHarness) handle(writer http.ResponseWriter, request *http.Request) {
	h.t.Helper()
	if h.credential != "" && request.Header.Get("Authorization") != "Bearer "+h.credential {
		h.t.Errorf("missing credential for MCP request")
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	if request.Method != http.MethodPost {
		h.t.Errorf("unexpected method %s", request.Method)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	data, err := io.ReadAll(request.Body)
	if err != nil {
		h.t.Errorf("read request: %v", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	var rpcRequest testRPCRequest
	if err := json.Unmarshal(data, &rpcRequest); err != nil {
		h.t.Errorf("decode request: %v", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	h.mu.Lock()
	h.methods = append(h.methods, rpcRequest.Method)
	h.mu.Unlock()

	if rpcRequest.Method != "initialize" {
		if request.Header.Get("Mcp-Session-Id") != "session-1" {
			h.t.Errorf("missing MCP session ID for %s", rpcRequest.Method)
		}
		if request.Header.Get("MCP-Protocol-Version") != protocolVersion {
			h.t.Errorf("missing negotiated protocol version for %s", rpcRequest.Method)
		}
	}

	switch rpcRequest.Method {
	case "initialize":
		writer.Header().Set("Mcp-Session-Id", "session-1")
		h.writeResult(writer, rpcRequest.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "test-server", "version": "1.0.0"},
		}, false)
	case "notifications/initialized":
		writer.WriteHeader(http.StatusAccepted)
	case "tools/list":
		h.writeResult(writer, rpcRequest.ID, map[string]any{"tools": h.tools}, h.streamListResponse)
	case "tools/call":
		var params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(rpcRequest.Params, &params); err != nil {
			h.t.Errorf("decode tool params: %v", err)
		}
		if params.Name == "" || params.Arguments == nil {
			h.t.Errorf("invalid tool call params: %#v", params)
		}
		h.writeResult(writer, rpcRequest.ID, h.callResult, false)
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}

func (h *mcpHarness) writeResult(writer http.ResponseWriter, id json.RawMessage, result any, stream bool) {
	h.t.Helper()
	payload, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "result": result})
	if err != nil {
		h.t.Fatalf("encode response: %v", err)
	}
	if stream {
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(writer, "event: message\ndata: %s\n\n", payload)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write(payload)
}

func (h *mcpHarness) methodSnapshot() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.methods...)
}

func (h *mcpHarness) methodCount(method string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	count := 0
	for _, candidate := range h.methods {
		if candidate == method {
			count++
		}
	}
	return count
}
