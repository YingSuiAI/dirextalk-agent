package coremodel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

type compatibilityClient struct {
	generateRequests []CompletionRequest
	streamRequests   []CompletionRequest
	completions      []Completion
	generateErrors   []error
	stream           Stream
	streamError      error
}

func (c *compatibilityClient) Generate(_ context.Context, request CompletionRequest) (Completion, error) {
	c.generateRequests = append(c.generateRequests, request)
	index := len(c.generateRequests) - 1
	if index < len(c.generateErrors) && c.generateErrors[index] != nil {
		return Completion{}, c.generateErrors[index]
	}
	if index >= len(c.completions) {
		return Completion{}, ErrInvalidResponse
	}
	return c.completions[index], nil
}

func (c *compatibilityClient) Stream(_ context.Context, request CompletionRequest) (Stream, error) {
	c.streamRequests = append(c.streamRequests, request)
	return c.stream, c.streamError
}

type compatibilityStream struct {
	deltas []Delta
	err    error
	index  int
	closed bool
}

func (s *compatibilityStream) Recv() (Delta, error) {
	if s.index < len(s.deltas) {
		delta := s.deltas[s.index]
		s.index++
		return delta, nil
	}
	if s.err != nil {
		return Delta{}, s.err
	}
	return Delta{}, io.EOF
}

func (s *compatibilityStream) Close() error {
	s.closed = true
	return nil
}

func TestToolCompatibilityProbePassesAllProtocolStages(t *testing.T) {
	call := ToolCall{Index: 0, ID: "call-1", Type: "function", Function: FunctionCall{Name: toolProbeName, Arguments: `{"value":"probe-ok"}`}}
	stream := &compatibilityStream{deltas: []Delta{
		{ToolCalls: []ToolCall{{Index: 0, ID: "call-2", Type: "function", Function: FunctionCall{Name: toolProbeName, Arguments: `{"value":"`}}}},
		{ToolCalls: []ToolCall{{Index: 0, Function: FunctionCall{Arguments: `probe-ok"}`}}}},
	}}
	client := &compatibilityClient{
		completions: []Completion{
			{Message: Message{Role: RoleAssistant, ToolCalls: []ToolCall{call}}},
			{Message: Message{Role: RoleAssistant, Content: toolProbeCompletionMarker}},
		},
		stream: stream,
	}

	result := runToolCompatibility(context.Background(), client)
	if result.Status != ToolCompatibilityCompatible || len(result.Probes) != 3 {
		t.Fatalf("result=%#v", result)
	}
	for _, probe := range result.Probes {
		if probe.Status != ToolProbePassed || probe.ErrorCode != "" {
			t.Fatalf("probe=%#v", probe)
		}
	}
	if !stream.closed || len(client.generateRequests) != 2 || len(client.streamRequests) != 1 {
		t.Fatalf("closed=%t generate=%d stream=%d", stream.closed, len(client.generateRequests), len(client.streamRequests))
	}
	first := client.generateRequests[0]
	if first.ForcedToolName != toolProbeName || len(first.Tools) != 1 || first.Tools[0].Name != toolProbeName {
		t.Fatalf("first request=%#v", first)
	}
	continuation := client.generateRequests[1]
	if continuation.ForcedToolName != "" || continuation.ToolChoice != ToolChoiceAuto || len(continuation.Messages) != 3 ||
		continuation.Messages[1].Role != RoleAssistant || continuation.Messages[2].Role != RoleTool || continuation.Messages[2].ToolCallID != call.ID {
		t.Fatalf("continuation request=%#v", continuation)
	}
}

func TestToolCompatibilityProbeStopsOnInvalidStructuredCall(t *testing.T) {
	client := &compatibilityClient{completions: []Completion{{Message: Message{Role: RoleAssistant, Content: `<tool_call>{"name":"dirextalk_compatibility_echo"}</tool_call>`}}}}

	result := runToolCompatibility(context.Background(), client)
	want := ToolCompatibilityResult{Status: ToolCompatibilityIncompatible, Probes: []ToolCompatibilityProbeResult{{Name: toolProbeNonStreaming, Status: ToolProbeFailed, ErrorCode: "structured_tool_call_count"}}}
	if !reflect.DeepEqual(result, want) || len(client.streamRequests) != 0 {
		t.Fatalf("result=%#v stream_requests=%d", result, len(client.streamRequests))
	}
}

func TestToolCompatibilityProbeKeepsTransientFailureInconclusive(t *testing.T) {
	client := &compatibilityClient{generateErrors: []error{providerHTTPStatusFailure(429, nil)}}

	result := runToolCompatibility(context.Background(), client)
	if result.Status != ToolCompatibilityInconclusive || len(result.Probes) != 1 ||
		result.Probes[0].Status != ToolProbeInconclusive || result.Probes[0].ErrorCode != "provider_http_4xx" {
		t.Fatalf("result=%#v", result)
	}
}

func TestToolCompatibilityProbeRejectsBadContinuation(t *testing.T) {
	call := ToolCall{ID: "call-1", Type: "function", Function: FunctionCall{Name: toolProbeName, Arguments: `{"value":"probe-ok"}`}}
	client := &compatibilityClient{
		completions: []Completion{
			{Message: Message{Role: RoleAssistant, ToolCalls: []ToolCall{call}}},
			{Message: Message{Role: RoleAssistant, Content: "almost complete"}},
		},
		stream: &compatibilityStream{deltas: []Delta{{ToolCalls: []ToolCall{call}}}},
	}

	result := runToolCompatibility(context.Background(), client)
	if result.Status != ToolCompatibilityIncompatible || len(result.Probes) != 3 || result.Probes[2].ErrorCode != "continuation_content_invalid" {
		t.Fatalf("result=%#v", result)
	}
}

func TestToolCompatibilityProbeClassifiesStreamFailureAndCloses(t *testing.T) {
	call := ToolCall{ID: "call-1", Type: "function", Function: FunctionCall{Name: toolProbeName, Arguments: `{"value":"probe-ok"}`}}
	stream := &compatibilityStream{err: ErrStreamTruncated}
	client := &compatibilityClient{completions: []Completion{{Message: Message{Role: RoleAssistant, ToolCalls: []ToolCall{call}}}}, stream: stream}

	result := runToolCompatibility(context.Background(), client)
	if result.Status != ToolCompatibilityInconclusive || len(result.Probes) != 2 || result.Probes[1].Status != ToolProbeInconclusive || result.Probes[1].ErrorCode != "provider_stream_truncated" || !stream.closed {
		t.Fatalf("result=%#v closed=%t", result, stream.closed)
	}
}

func TestHTTPToolCompatibilityProbeExercisesOpenAIWireProtocol(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
			t.Errorf("request %d method=%s path=%s", calls, r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request %d: %v", calls, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch calls {
		case 1:
			if payload["stream"] != false || payload["tools"] == nil || payload["tool_choice"] == nil {
				t.Errorf("non-stream payload=%#v", payload)
			}
			_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call-1","type":"function","function":{"name":"dirextalk_compatibility_echo","arguments":"{\"value\":\"probe-ok\"}"}}]}}]}`)
		case 2:
			if payload["stream"] != true {
				t.Errorf("stream payload=%#v", payload)
			}
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call-2\",\"type\":\"function\",\"function\":{\"name\":\"dirextalk_compatibility_echo\",\"arguments\":\"{\\\"value\\\":\\\"probe-\"}}]}}]}\n\n")
			_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"ok\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n")
		case 3:
			messages, _ := payload["messages"].([]any)
			if payload["stream"] != false || len(messages) != 3 || payload["tool_choice"] != "auto" {
				t.Errorf("continuation payload=%#v", payload)
			}
			_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"DIREXTALK_PROBE_COMPLETE"}}]}`)
		default:
			t.Errorf("unexpected request %d", calls)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	profile := validProfile(ProviderOpenAICompatible, server.URL, "key")
	tester := NewConnectionTester(WithHTTPClient(server.Client()))
	prober, ok := tester.(ToolCompatibilityTester)
	if !ok {
		t.Fatal("connection tester does not expose tool compatibility")
	}
	result := prober.TestToolCompatibility(context.Background(), profile)
	if result.Status != ToolCompatibilityCompatible || len(result.Probes) != 3 || calls != 3 {
		t.Fatalf("result=%#v calls=%d", result, calls)
	}
}

func TestToolCompatibilityProbeSkipsNonConversationProfiles(t *testing.T) {
	tester := &connectionTester{}
	result := tester.TestToolCompatibility(context.Background(), Profile{ModelKind: ModelKindEmbedding})
	if result.Status != ToolCompatibilityNotRun || len(result.Probes) != 0 {
		t.Fatalf("result=%#v", result)
	}
}

var _ Client = (*compatibilityClient)(nil)
var _ Stream = (*compatibilityStream)(nil)
