package einoengine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
	"github.com/eino-contrib/jsonschema"
)

type invokableTool struct {
	definition modelapi.Tool
	executor   *toolExecutor
}

var _ tool.InvokableTool = (*invokableTool)(nil)

func (t *invokableTool) Info(context.Context) (*schema.ToolInfo, error) {
	result := &schema.ToolInfo{Name: t.definition.Name, Desc: t.definition.Description}
	if len(t.definition.InputSchema) == 0 {
		return result, nil
	}
	encoded, err := json.Marshal(t.definition.InputSchema)
	if err != nil {
		return nil, fmt.Errorf("%w: encode tool schema", runtimeapi.ErrInvalidDependencies)
	}
	parameterSchema := &jsonschema.Schema{}
	if err := json.Unmarshal(encoded, parameterSchema); err != nil {
		return nil, fmt.Errorf("%w: decode tool schema", runtimeapi.ErrInvalidDependencies)
	}
	result.ParamsOneOf = schema.NewParamsOneOfByJSONSchema(parameterSchema)
	return result, nil
}

func (t *invokableTool) InvokableRun(ctx context.Context, arguments string, _ ...tool.Option) (string, error) {
	return t.executor.run(ctx, t.definition.Name, arguments)
}

type toolExecutor struct {
	invoke    runtimeapi.ToolInvoker
	collector *messageCollector
	emit      runtimeapi.StreamEmitter
}

func (e *toolExecutor) runUnknown(ctx context.Context, name, arguments string) (string, error) {
	return e.run(ctx, name, arguments)
}

func (e *toolExecutor) run(ctx context.Context, name, arguments string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	call := modelapi.ToolCall{
		ID:   strings.TrimSpace(compose.GetToolCallID(ctx)),
		Type: "function",
		Function: modelapi.FunctionCall{
			Name: strings.TrimSpace(name), Arguments: arguments,
		},
	}
	if call.ID == "" || call.Function.Name == "" || e.invoke == nil {
		return "", runtimeapi.ErrInvalidToolCall
	}
	e.collector.recordToolCall(call)
	if e.emit != nil {
		if err := e.emit(runtimeapi.StreamEvent{
			Kind: runtimeapi.StreamEventToolCall,
			ToolCall: modelapi.ToolCall{
				ID: call.ID, Type: call.Type, Function: modelapi.FunctionCall{Name: call.Function.Name},
			},
		}); err != nil {
			return "", err
		}
	}
	execution, err := e.invoke(ctx, call)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		// Capability errors can contain provider details. The typed Runtime
		// adapter converts expected failures to model-safe ToolExecution; an
		// unexpected adapter error is deliberately collapsed here.
		return "", fmt.Errorf("typed tool invocation failed: %w", runtimeapi.ErrInvalidToolCall)
	}
	if execution.ToolCallID == "" {
		execution.ToolCallID = call.ID
	}
	if execution.Name == "" {
		execution.Name = call.Function.Name
	}
	if execution.ToolCallID != call.ID || execution.Name != call.Function.Name {
		return "", runtimeapi.ErrInvalidToolCall
	}
	e.collector.recordToolResult(execution)
	if e.emit != nil {
		if err := e.emit(runtimeapi.StreamEvent{
			Kind: runtimeapi.StreamEventToolResult,
			ToolResult: runtimeapi.ToolExecution{
				ToolCallID: execution.ToolCallID,
				Name:       execution.Name,
				IsError:    execution.IsError,
			},
		}); err != nil {
			return "", err
		}
	}
	return execution.Content, nil
}
