package einoengine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	einomodel "github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

type chatModelAdapter struct {
	client      modelapi.Client
	definitions map[string]modelapi.Tool
	tools       []modelapi.Tool
	budget      *modelCallBudget
	collector   *messageCollector
	emit        runtimeapi.StreamEmitter
}

var _ einomodel.ToolCallingChatModel = (*chatModelAdapter)(nil)

func (a *chatModelAdapter) WithTools(infos []*schema.ToolInfo) (einomodel.ToolCallingChatModel, error) {
	bound := *a
	bound.tools = make([]modelapi.Tool, 0, len(infos))
	seen := make(map[string]struct{}, len(infos))
	for _, info := range infos {
		if info == nil {
			return nil, runtimeapi.ErrInvalidDependencies
		}
		definition, ok := a.definitions[info.Name]
		if !ok {
			return nil, fmt.Errorf("%w: Eino bound an unknown tool", runtimeapi.ErrInvalidDependencies)
		}
		if _, duplicate := seen[info.Name]; duplicate {
			return nil, runtimeapi.ErrInvalidDependencies
		}
		seen[info.Name] = struct{}{}
		bound.tools = append(bound.tools, definition)
	}
	return &bound, nil
}

func (a *chatModelAdapter) Generate(ctx context.Context, input []*schema.Message, _ ...einomodel.Option) (*schema.Message, error) {
	if err := a.budget.take(ctx); err != nil {
		return nil, err
	}
	completion, err := a.client.Generate(ctx, modelapi.CompletionRequest{
		Messages: fromEinoMessages(input),
		Tools:    cloneModelTools(a.tools),
	})
	if err != nil {
		return nil, err
	}
	message, err := normalizedAssistant(completion.Message)
	if err != nil {
		return nil, err
	}
	a.collector.recordModel(message)
	return toEinoMessage(message), nil
}

func (a *chatModelAdapter) Stream(ctx context.Context, input []*schema.Message, _ ...einomodel.Option) (*schema.StreamReader[*schema.Message], error) {
	if err := a.budget.take(ctx); err != nil {
		return nil, err
	}
	source, err := a.client.Stream(ctx, modelapi.CompletionRequest{
		Messages: fromEinoMessages(input),
		Tools:    cloneModelTools(a.tools),
	})
	if err != nil {
		return nil, err
	}
	if source == nil {
		return nil, runtimeapi.ErrInvalidDependencies
	}
	reader, writer := schema.Pipe[*schema.Message](1)
	go a.forwardStream(ctx, source, writer)
	return reader, nil
}

func (a *chatModelAdapter) forwardStream(ctx context.Context, source modelapi.Stream, writer *schema.StreamWriter[*schema.Message]) {
	defer writer.Close()
	defer source.Close()
	chunks := make([]*schema.Message, 0, 8)
	for {
		if err := ctx.Err(); err != nil {
			writer.Send(nil, err)
			return
		}
		delta, err := source.Recv()
		if errors.Is(err, io.EOF) {
			if len(chunks) == 0 {
				writer.Send(nil, runtimeapi.ErrInvalidModelResponse)
				return
			}
			message, concatErr := schema.ConcatMessages(chunks)
			if concatErr != nil {
				writer.Send(nil, concatErr)
				return
			}
			normalized, normalizeErr := normalizedAssistant(fromEinoMessage(message))
			if normalizeErr != nil {
				writer.Send(nil, normalizeErr)
				return
			}
			a.collector.recordModel(normalized)
			return
		}
		if err != nil {
			writer.Send(nil, err)
			return
		}
		if delta.Content != "" && a.emit != nil {
			if emitErr := a.emit(runtimeapi.StreamEvent{
				Kind:  runtimeapi.StreamEventDelta,
				Delta: modelapi.Delta{Content: delta.Content},
			}); emitErr != nil {
				writer.Send(nil, emitErr)
				return
			}
		}
		chunk := deltaToEinoMessage(delta)
		chunks = append(chunks, chunk)
		if writer.Send(chunk, nil) {
			return
		}
	}
}

type modelCallBudget struct {
	mu        sync.Mutex
	remaining int
}

func (b *modelCallBudget) take(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.remaining <= 0 {
		return runtimeapi.ErrStepLimit
	}
	b.remaining--
	return nil
}

func normalizedAssistant(message modelapi.Message) (modelapi.Message, error) {
	if message.Role == "" {
		message.Role = modelapi.RoleAssistant
	}
	if message.Role != modelapi.RoleAssistant || (strings.TrimSpace(message.Content) == "" && len(message.ToolCalls) == 0) {
		return modelapi.Message{}, fmt.Errorf("%w: expected a non-empty assistant message", runtimeapi.ErrInvalidModelResponse)
	}
	seen := make(map[string]struct{}, len(message.ToolCalls))
	for _, call := range message.ToolCalls {
		if strings.TrimSpace(call.ID) == "" || strings.TrimSpace(call.Function.Name) == "" {
			return modelapi.Message{}, runtimeapi.ErrInvalidToolCall
		}
		if _, duplicate := seen[call.ID]; duplicate {
			return modelapi.Message{}, runtimeapi.ErrInvalidToolCall
		}
		seen[call.ID] = struct{}{}
	}
	return cloneModelMessage(message), nil
}

func toEinoMessages(messages []modelapi.Message) []*schema.Message {
	result := make([]*schema.Message, 0, len(messages))
	for _, message := range messages {
		result = append(result, toEinoMessage(message))
	}
	return result
}

func toEinoMessage(message modelapi.Message) *schema.Message {
	result := &schema.Message{
		Role:             toEinoRole(message.Role),
		Content:          message.Content,
		ReasoningContent: message.ReasoningContent,
		Name:             message.Name,
		ToolCallID:       message.ToolCallID,
		ToolName:         message.Name,
	}
	if len(message.ToolCalls) > 0 {
		result.ToolCalls = make([]schema.ToolCall, 0, len(message.ToolCalls))
		for _, call := range message.ToolCalls {
			index := call.Index
			result.ToolCalls = append(result.ToolCalls, schema.ToolCall{
				Index: &index,
				ID:    call.ID,
				Type:  call.Type,
				Function: schema.FunctionCall{
					Name: call.Function.Name, Arguments: call.Function.Arguments,
				},
			})
		}
	}
	return result
}

func deltaToEinoMessage(delta modelapi.Delta) *schema.Message {
	return toEinoMessage(modelapi.Message{
		Role:             modelapi.RoleAssistant,
		Content:          delta.Content,
		ReasoningContent: delta.ReasoningContent,
		ToolCalls:        delta.ToolCalls,
	})
}

func fromEinoMessages(messages []*schema.Message) []modelapi.Message {
	result := make([]modelapi.Message, 0, len(messages))
	for _, message := range messages {
		if message != nil {
			result = append(result, fromEinoMessage(message))
		}
	}
	return result
}

func fromEinoMessage(message *schema.Message) modelapi.Message {
	if message == nil {
		return modelapi.Message{}
	}
	result := modelapi.Message{
		Role:             fromEinoRole(message.Role),
		Content:          message.Content,
		ReasoningContent: message.ReasoningContent,
		Name:             message.Name,
		ToolCallID:       message.ToolCallID,
	}
	if result.Name == "" {
		result.Name = message.ToolName
	}
	if len(message.ToolCalls) > 0 {
		result.ToolCalls = make([]modelapi.ToolCall, 0, len(message.ToolCalls))
		for position, call := range message.ToolCalls {
			index := position
			if call.Index != nil {
				index = *call.Index
			}
			result.ToolCalls = append(result.ToolCalls, modelapi.ToolCall{
				Index: index,
				ID:    call.ID,
				Type:  call.Type,
				Function: modelapi.FunctionCall{
					Name: call.Function.Name, Arguments: call.Function.Arguments,
				},
			})
		}
	}
	return result
}

func toEinoRole(role modelapi.Role) schema.RoleType {
	switch role {
	case modelapi.RoleSystem:
		return schema.System
	case modelapi.RoleUser:
		return schema.User
	case modelapi.RoleAssistant:
		return schema.Assistant
	case modelapi.RoleTool:
		return schema.Tool
	default:
		return schema.RoleType(role)
	}
}

func fromEinoRole(role schema.RoleType) modelapi.Role {
	switch role {
	case schema.System:
		return modelapi.RoleSystem
	case schema.User:
		return modelapi.RoleUser
	case schema.Assistant:
		return modelapi.RoleAssistant
	case schema.Tool:
		return modelapi.RoleTool
	default:
		return modelapi.Role(role)
	}
}

func cloneModelMessage(message modelapi.Message) modelapi.Message {
	message.ToolCalls = append([]modelapi.ToolCall(nil), message.ToolCalls...)
	return message
}

func cloneModelTools(tools []modelapi.Tool) []modelapi.Tool {
	return append([]modelapi.Tool(nil), tools...)
}
