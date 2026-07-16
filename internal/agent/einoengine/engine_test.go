package einoengine

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
)

func TestGenerateRunsToolAndReturnsFinalAssistant(t *testing.T) {
	t.Parallel()

	client := &scriptedClient{completions: []modelapi.Completion{
		{Message: modelapi.Message{Role: modelapi.RoleAssistant, ToolCalls: []modelapi.ToolCall{{
			ID: "call-1", Type: "function", Function: modelapi.FunctionCall{Name: "lookup", Arguments: `{"q":"x"}`},
		}}}},
		{Message: modelapi.Message{Role: modelapi.RoleAssistant, Content: "finished"}},
	}}
	invocations := 0
	result, err := New().Generate(context.Background(), runtimeapi.EngineRequest{
		Client:   client,
		Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "find x"}},
		Tools: []modelapi.Tool{{
			Name: "lookup", Description: "look up a value", InputSchema: map[string]any{"type": "object"},
		}},
		MaxSteps: 4,
		InvokeTool: func(_ context.Context, call modelapi.ToolCall) (runtimeapi.ToolExecution, error) {
			invocations++
			if call.ID != "call-1" || call.Function.Name != "lookup" || call.Function.Arguments != `{"q":"x"}` {
				t.Fatalf("unexpected tool call: %#v", call)
			}
			return runtimeapi.ToolExecution{ToolCallID: call.ID, Name: call.Function.Name, Content: `{"value":"found"}`}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Message.Content != "finished" || invocations != 1 {
		t.Fatalf("unexpected result: %#v invocations=%d", result, invocations)
	}
	if len(result.Produced) != 3 || result.Produced[0].ToolCalls[0].ID != "call-1" || result.Produced[1].Role != modelapi.RoleTool || result.Produced[2].Content != "finished" {
		t.Fatalf("unexpected produced messages: %#v", result.Produced)
	}
	if len(result.Steps) != 4 || result.Steps[0].Kind != runtimeapi.StepModel || result.Steps[1].Kind != runtimeapi.StepToolCall || result.Steps[2].Kind != runtimeapi.StepToolResult || result.Steps[3].Kind != runtimeapi.StepModel {
		t.Fatalf("unexpected steps: %#v", result.Steps)
	}
	requests := client.recordedRequests()
	if len(requests) != 2 || len(requests[1].Messages) != 3 || requests[1].Messages[1].ToolCalls[0].ID != "call-1" || requests[1].Messages[2].ToolCallID != "call-1" {
		t.Fatalf("tool result was not fed back to the model: %#v", requests)
	}
}

func TestGenerateEnforcesModelStepBudget(t *testing.T) {
	t.Parallel()

	client := &scriptedClient{completions: []modelapi.Completion{{Message: modelapi.Message{
		Role: modelapi.RoleAssistant,
		ToolCalls: []modelapi.ToolCall{{
			ID: "call-1", Type: "function", Function: modelapi.FunctionCall{Name: "lookup", Arguments: `{}`},
		}},
	}}}}
	_, err := New().Generate(context.Background(), runtimeapi.EngineRequest{
		Client:   client,
		Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "loop"}},
		Tools:    []modelapi.Tool{{Name: "lookup", InputSchema: map[string]any{"type": "object"}}},
		MaxSteps: 1,
		InvokeTool: func(_ context.Context, call modelapi.ToolCall) (runtimeapi.ToolExecution, error) {
			return runtimeapi.ToolExecution{ToolCallID: call.ID, Name: call.Function.Name, Content: `{}`}, nil
		},
	})
	if !errors.Is(err, runtimeapi.ErrStepLimit) {
		t.Fatalf("error = %v, want ErrStepLimit", err)
	}
	if got := len(client.recordedRequests()); got != 1 {
		t.Fatalf("model calls = %d, want 1", got)
	}
}

func TestGeneratePropagatesCancellation(t *testing.T) {
	t.Parallel()

	client := &blockingClient{started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := New().Generate(ctx, runtimeapi.EngineRequest{
			Client:   client,
			Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "wait"}},
			MaxSteps: 2,
		})
		done <- err
	}()
	<-client.started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestStreamSuppressesRawReasoningAndRedactsToolEvents(t *testing.T) {
	t.Parallel()

	first := &scriptedStream{deltas: []modelapi.Delta{
		{ReasoningContent: "considering"},
		{ToolCalls: []modelapi.ToolCall{{Index: 0, ID: "call-1", Type: "function", Function: modelapi.FunctionCall{Name: "lookup", Arguments: `{"q":"x"}`}}}},
	}}
	second := &scriptedStream{deltas: []modelapi.Delta{{ReasoningContent: "verified"}, {Content: "finished"}}}
	client := &scriptedClient{streams: []*scriptedStream{first, second}}
	var events []runtimeapi.StreamEvent
	result, err := New().Stream(context.Background(), runtimeapi.EngineRequest{
		Client:   client,
		Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "find x"}},
		Tools:    []modelapi.Tool{{Name: "lookup", Description: "look up a value", InputSchema: map[string]any{"type": "object"}}},
		MaxSteps: 4,
		InvokeTool: func(_ context.Context, call modelapi.ToolCall) (runtimeapi.ToolExecution, error) {
			return runtimeapi.ToolExecution{ToolCallID: call.ID, Name: call.Function.Name, Content: `{"value":"found"}`}, nil
		},
	}, func(event runtimeapi.StreamEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Message.Content != "finished" || result.Message.ReasoningContent != "" {
		t.Fatalf("unexpected final message: %#v", result.Message)
	}
	var content, reasoning string
	var sawCall, sawResult bool
	for _, event := range events {
		if event.Kind == runtimeapi.StreamEventDelta {
			content += event.Delta.Content
			reasoning += event.Delta.ReasoningContent
		}
		if event.Kind == runtimeapi.StreamEventToolCall {
			sawCall = true
			if event.ToolCall.ID != "call-1" || event.ToolCall.Function.Name != "lookup" || event.ToolCall.Function.Arguments != "" {
				t.Fatalf("tool call event was not redacted: %#v", event.ToolCall)
			}
		}
		if event.Kind == runtimeapi.StreamEventToolResult {
			sawResult = true
			if event.ToolResult.ToolCallID != "call-1" || event.ToolResult.Name != "lookup" || event.ToolResult.Content != "" {
				t.Fatalf("tool result event was not redacted: %#v", event.ToolResult)
			}
		}
	}
	if content != "finished" || reasoning != "" || !sawCall || !sawResult {
		t.Fatalf("unexpected events: content=%q reasoning=%q call=%v result=%v events=%#v", content, reasoning, sawCall, sawResult, events)
	}
	if len(result.Produced) != 3 || !first.isClosed() || !second.isClosed() {
		t.Fatalf("stream did not finish cleanly: produced=%#v closed=%v/%v", result.Produced, first.isClosed(), second.isClosed())
	}
}

type scriptedClient struct {
	mu          sync.Mutex
	completions []modelapi.Completion
	streams     []*scriptedStream
	requests    []modelapi.CompletionRequest
}

func (s *scriptedClient) Generate(ctx context.Context, request modelapi.CompletionRequest) (modelapi.Completion, error) {
	if err := ctx.Err(); err != nil {
		return modelapi.Completion{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, cloneRequest(request))
	if len(s.completions) == 0 {
		return modelapi.Completion{}, errors.New("unexpected Generate")
	}
	result := s.completions[0]
	s.completions = s.completions[1:]
	return result, nil
}

func (s *scriptedClient) Stream(ctx context.Context, request modelapi.CompletionRequest) (modelapi.Stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, cloneRequest(request))
	if len(s.streams) == 0 {
		return nil, errors.New("unexpected Stream")
	}
	result := s.streams[0]
	s.streams = s.streams[1:]
	return result, nil
}

func (s *scriptedClient) recordedRequests() []modelapi.CompletionRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]modelapi.CompletionRequest, len(s.requests))
	for i := range s.requests {
		result[i] = cloneRequest(s.requests[i])
	}
	return result
}

type scriptedStream struct {
	mu     sync.Mutex
	deltas []modelapi.Delta
	closed bool
}

func (s *scriptedStream) Recv() (modelapi.Delta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.deltas) == 0 {
		return modelapi.Delta{}, io.EOF
	}
	result := s.deltas[0]
	s.deltas = s.deltas[1:]
	return result, nil
}

func (s *scriptedStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *scriptedStream) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

type blockingClient struct {
	started chan struct{}
	once    sync.Once
}

func (b *blockingClient) Generate(ctx context.Context, _ modelapi.CompletionRequest) (modelapi.Completion, error) {
	b.once.Do(func() { close(b.started) })
	<-ctx.Done()
	return modelapi.Completion{}, ctx.Err()
}

func (b *blockingClient) Stream(context.Context, modelapi.CompletionRequest) (modelapi.Stream, error) {
	return nil, errors.New("unexpected Stream")
}

func cloneRequest(request modelapi.CompletionRequest) modelapi.CompletionRequest {
	result := modelapi.CompletionRequest{
		Messages: append([]modelapi.Message(nil), request.Messages...),
		Tools:    append([]modelapi.Tool(nil), request.Tools...),
	}
	for i := range result.Messages {
		result.Messages[i].ToolCalls = append([]modelapi.ToolCall(nil), request.Messages[i].ToolCalls...)
	}
	return result
}
