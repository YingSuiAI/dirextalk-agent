package coreconversation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type toolArgumentRepairModel struct {
	results     []ModelRunResult
	requests    []ModelRunRequest
	runCalls    int
	streamCalls int
}

func (m *toolArgumentRepairModel) Run(_ context.Context, request ModelRunRequest) (ModelRunResult, error) {
	m.requests = append(m.requests, request)
	m.runCalls++
	return m.results[len(m.requests)-1], nil
}

func (m *toolArgumentRepairModel) Stream(_ context.Context, request ModelRunRequest, _ func(ModelDelta) error) (ModelRunResult, error) {
	m.requests = append(m.requests, request)
	m.streamCalls++
	return m.results[len(m.requests)-1], nil
}

func toolCallResult(calls ...ToolCall) ModelRunResult {
	return ModelRunResult{
		Message: Message{
			ID:        uuid.NewString(),
			Role:      RoleAssistant,
			ToolCalls: append([]ToolCall(nil), calls...),
			CreatedAt: time.Now().UTC(),
		},
		ToolCalls: append([]ToolCall(nil), calls...),
	}
}

func TestModelResultNeedsToolArgumentRepair(t *testing.T) {
	valid := ToolCall{ID: "valid", Name: "tool", Arguments: `{"value":1}`}
	tests := []struct {
		name   string
		result ModelRunResult
		want   bool
	}{
		{name: "no calls", result: ModelRunResult{}, want: false},
		{name: "valid call", result: toolCallResult(valid), want: false},
		{name: "invalid json", result: toolCallResult(ToolCall{ID: "bad-json", Name: "tool", Arguments: `{"value":`}), want: true},
		{name: "non object", result: toolCallResult(ToolCall{ID: "array", Name: "tool", Arguments: `[]`}), want: true},
		{name: "valid and repairable", result: toolCallResult(valid, ToolCall{ID: "bad-json", Name: "tool", Arguments: `{`}), want: true},
		{name: "missing id fails closed", result: toolCallResult(ToolCall{Name: "tool", Arguments: `{`}), want: false},
		{name: "mixed unsafe error fails closed", result: toolCallResult(ToolCall{ID: "bad-json", Name: "tool", Arguments: `{`}, ToolCall{Name: "tool", Arguments: `{}`}), want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := modelResultNeedsToolArgumentRepair(test.result); got != test.want {
				t.Fatalf("modelResultNeedsToolArgumentRepair()=%v want=%v", got, test.want)
			}
		})
	}
}

func TestRunModelWithToolArgumentRepairRetriesOnceBeforeExecution(t *testing.T) {
	bad := ToolCall{ID: "bad-json", Name: "tool", Arguments: `{"value":`}
	good := ToolCall{ID: "good-json", Name: "tool", Arguments: `{"value":1}`}
	model := &toolArgumentRepairModel{results: []ModelRunResult{toolCallResult(bad), toolCallResult(good)}}
	service := &Service{models: model}
	request := ModelRunRequest{Profile: ResolvedProfile{SystemPrompt: "base prompt"}}

	result, err := service.runModelWithToolArgumentRepair(context.Background(), request, func(ModelDelta) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(model.requests) != 2 {
		t.Fatalf("model calls=%d want=2", len(model.requests))
	}
	if model.streamCalls != 1 || model.runCalls != 1 {
		t.Fatalf("stream calls=%d run calls=%d", model.streamCalls, model.runCalls)
	}
	if model.requests[0].Profile.SystemPrompt != "base prompt" {
		t.Fatalf("first prompt changed: %q", model.requests[0].Profile.SystemPrompt)
	}
	if !strings.Contains(model.requests[1].Profile.SystemPrompt, toolArgumentRepairInstruction) {
		t.Fatalf("repair instruction missing: %q", model.requests[1].Profile.SystemPrompt)
	}
	if len(model.requests[1].Conversation.Messages) != 1 {
		t.Fatalf("invalid argument diagnostic missing: %+v", model.requests[1].Conversation.Messages)
	}
	_, diagnosticJSON, found := strings.Cut(model.requests[1].Conversation.Messages[0].Content, "Diagnostic data: ")
	var diagnostics []struct {
		ToolName           string `json:"tool_name"`
		AttemptedArguments string `json:"attempted_arguments"`
	}
	if !found || json.Unmarshal([]byte(diagnosticJSON), &diagnostics) != nil || len(diagnostics) != 1 || diagnostics[0].ToolName != bad.Name || diagnostics[0].AttemptedArguments != bad.Arguments {
		t.Fatalf("invalid argument diagnostic=%q", diagnosticJSON)
	}
	if got := modelResultToolCalls(result); len(got) != 1 || got[0].ID != good.ID {
		t.Fatalf("unexpected repaired result: %+v", got)
	}
}

func TestRunModelWithToolArgumentRepairDoesNotLoop(t *testing.T) {
	bad := ToolCall{ID: "bad-json", Name: "tool", Arguments: `{`}
	model := &toolArgumentRepairModel{results: []ModelRunResult{toolCallResult(bad), toolCallResult(bad)}}
	service := &Service{models: model}

	result, err := service.runModelWithToolArgumentRepair(context.Background(), ModelRunRequest{}, func(ModelDelta) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(model.requests) != 2 || !modelResultNeedsToolArgumentRepair(result) {
		t.Fatalf("calls=%d result=%+v", len(model.requests), result)
	}
}
