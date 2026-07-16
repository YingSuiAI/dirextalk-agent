package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const (
	toolArgumentsLimit = 64 << 10
	toolResultLimit    = 64 << 10
)

type toolSet struct {
	definitions []modelapi.Tool
	byName      map[string]Tool
	request     ToolRequest
}

func loadToolSet(ctx context.Context, provider ToolProvider, request ToolRequest) (toolSet, error) {
	enabled := make(map[string]struct{}, len(request.EnabledNames))
	for _, name := range request.EnabledNames {
		if name = strings.TrimSpace(name); name != "" {
			enabled[name] = struct{}{}
		}
	}
	if provider == nil || len(enabled) == 0 {
		return toolSet{byName: map[string]Tool{}, request: request}, nil
	}
	tools, err := provider.Tools(ctx, request)
	if err != nil {
		return toolSet{}, err
	}
	result := toolSet{definitions: make([]modelapi.Tool, 0, len(tools)), byName: make(map[string]Tool, len(tools)), request: request}
	for _, tool := range tools {
		name := strings.TrimSpace(tool.Definition.Name)
		if name == "" || tool.Run == nil {
			return toolSet{}, fmt.Errorf("invalid model-callable tool definition")
		}
		if _, ok := enabled[name]; !ok {
			continue
		}
		if _, duplicate := result.byName[name]; duplicate {
			return toolSet{}, fmt.Errorf("duplicate model-callable tool %q", name)
		}
		tool.Definition.Name = name
		result.byName[name] = tool
		result.definitions = append(result.definitions, tool.Definition)
	}
	return result, nil
}

func validateToolCalls(calls []modelapi.ToolCall) error {
	seen := make(map[string]struct{}, len(calls))
	for _, call := range calls {
		id := strings.TrimSpace(call.ID)
		name := strings.TrimSpace(call.Function.Name)
		if id == "" || name == "" {
			return ErrInvalidToolCall
		}
		if _, duplicate := seen[id]; duplicate {
			return ErrInvalidToolCall
		}
		seen[id] = struct{}{}
	}
	return nil
}

func runTool(ctx context.Context, call modelapi.ToolCall, tools toolSet) ToolExecution {
	execution := ToolExecution{ToolCallID: strings.TrimSpace(call.ID), Name: strings.TrimSpace(call.Function.Name)}
	tool, ok := tools.byName[execution.Name]
	if !ok {
		execution.Content = `{"error":"tool is unavailable"}`
		execution.IsError = true
		return execution
	}
	arguments := strings.TrimSpace(call.Function.Arguments)
	if arguments == "" {
		arguments = "{}"
	}
	if len(arguments) > toolArgumentsLimit || !json.Valid([]byte(arguments)) {
		execution.Content = `{"error":"tool arguments are invalid"}`
		execution.IsError = true
		return execution
	}
	var object map[string]any
	if err := json.Unmarshal([]byte(arguments), &object); err != nil || object == nil {
		execution.Content = `{"error":"tool arguments must be an object"}`
		execution.IsError = true
		return execution
	}
	result, err := tool.Run(ctx, ToolInvocation{
		RequestID:      tools.request.RequestID,
		OwnerID:        tools.request.OwnerID,
		ConversationID: tools.request.ConversationID,
		ToolCallID:     execution.ToolCallID,
		Name:           execution.Name,
		Arguments:      json.RawMessage(arguments),
	})
	if err != nil {
		// The underlying error can contain provider or capability secrets. It is
		// deliberately not model-visible and not stored in the conversation.
		execution.Content = `{"error":"tool execution failed"}`
		execution.IsError = true
		return execution
	}
	execution.Content = boundedToolResult(result.Content)
	execution.IsError = result.IsError
	if !execution.IsError {
		taskIDs, taskErr := normalizeRelatedEntityIDs(result.RelatedTaskIDs)
		planIDs, planErr := normalizeRelatedEntityIDs(result.RelatedPlanIDs)
		if taskErr != nil || planErr != nil {
			execution.Content = `{"error":"tool result is invalid"}`
			execution.IsError = true
			return execution
		}
		execution.RelatedTaskIDs = taskIDs
		execution.RelatedPlanIDs = planIDs
	}
	return execution
}

func boundedToolResult(content string) string {
	content = strings.TrimSpace(security.RedactText(content))
	if content == "" {
		return "{}"
	}
	runes := []rune(content)
	if len(runes) > toolResultLimit {
		return string(runes[:toolResultLimit-1]) + "…"
	}
	return content
}
