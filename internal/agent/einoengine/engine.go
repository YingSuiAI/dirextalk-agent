// Package einoengine provides the single native Eino ReAct execution path for
// the generic Agent runtime. It receives already-authorized typed tools and
// never resolves secrets or exposes a shell/AWS SDK capability.
package einoengine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/flow/agent/react"
	"github.com/cloudwego/eino/schema"
)

type Engine struct{}

func New() *Engine { return &Engine{} }

var _ runtimeapi.Engine = (*Engine)(nil)

func (e *Engine) Generate(ctx context.Context, request runtimeapi.EngineRequest) (runtimeapi.EngineResult, error) {
	run, err := newRun(ctx, request, nil)
	if err != nil {
		return runtimeapi.EngineResult{}, err
	}
	message, err := run.agent.Generate(ctx, toEinoMessages(request.Messages))
	if err != nil {
		return runtimeapi.EngineResult{}, normalizeRunError(ctx, err)
	}
	final, err := normalizedAssistant(fromEinoMessage(message))
	if err != nil {
		return runtimeapi.EngineResult{}, err
	}
	if len(final.ToolCalls) != 0 {
		return runtimeapi.EngineResult{}, fmt.Errorf("%w: ReAct returned an unfinished tool call", runtimeapi.ErrInvalidModelResponse)
	}
	final.ReasoningContent = ""
	return run.collector.result(final), nil
}

func (e *Engine) Stream(ctx context.Context, request runtimeapi.EngineRequest, emit runtimeapi.StreamEmitter) (runtimeapi.EngineResult, error) {
	if emit == nil {
		return runtimeapi.EngineResult{}, runtimeapi.ErrInvalidRequest
	}
	run, err := newRun(ctx, request, emit)
	if err != nil {
		return runtimeapi.EngineResult{}, err
	}
	stream, err := run.agent.Stream(ctx, toEinoMessages(request.Messages))
	if err != nil {
		return runtimeapi.EngineResult{}, normalizeRunError(ctx, err)
	}
	message, err := collectEinoStream(stream)
	if err != nil {
		return runtimeapi.EngineResult{}, normalizeRunError(ctx, err)
	}
	final, err := normalizedAssistant(fromEinoMessage(message))
	if err != nil {
		return runtimeapi.EngineResult{}, err
	}
	if len(final.ToolCalls) != 0 {
		return runtimeapi.EngineResult{}, fmt.Errorf("%w: ReAct returned an unfinished tool call", runtimeapi.ErrInvalidModelResponse)
	}
	final.ReasoningContent = ""
	return run.collector.result(final), nil
}

type executionRun struct {
	agent     *react.Agent
	collector *messageCollector
}

func newRun(ctx context.Context, request runtimeapi.EngineRequest, emit runtimeapi.StreamEmitter) (executionRun, error) {
	if request.Client == nil || request.MaxSteps < 1 {
		return executionRun{}, runtimeapi.ErrInvalidDependencies
	}
	collector := &messageCollector{}
	executor := &toolExecutor{invoke: request.InvokeTool, collector: collector, emit: emit}
	baseTools := make([]tool.BaseTool, 0, len(request.Tools))
	definitions := make(map[string]modelapi.Tool, len(request.Tools))
	for _, definition := range request.Tools {
		if definition.Name == "" {
			return executionRun{}, runtimeapi.ErrInvalidDependencies
		}
		if _, duplicate := definitions[definition.Name]; duplicate {
			return executionRun{}, runtimeapi.ErrInvalidDependencies
		}
		definitions[definition.Name] = definition
		baseTools = append(baseTools, &invokableTool{definition: definition, executor: executor})
	}
	if len(baseTools) > 0 && request.InvokeTool == nil {
		return executionRun{}, runtimeapi.ErrInvalidDependencies
	}

	adapter := &chatModelAdapter{
		client:      request.Client,
		definitions: definitions,
		budget:      &modelCallBudget{remaining: request.MaxSteps},
		collector:   collector,
		emit:        emit,
	}
	config := &react.AgentConfig{
		ToolCallingModel: adapter,
		ToolsConfig: compose.ToolsNodeConfig{
			Tools:               baseTools,
			ExecuteSequentially: true,
			UnknownToolsHandler: executor.runUnknown,
		},
		MaxStep:               graphStepLimit(request.MaxSteps),
		StreamToolCallChecker: scanStreamForToolCalls,
		GraphName:             "DirextalkAgentRuntime",
	}
	if request.RewriteMessages != nil {
		config.MessageRewriter = func(_ context.Context, messages []*schema.Message) []*schema.Message {
			return toEinoMessages(request.RewriteMessages(fromEinoMessages(messages)))
		}
	}
	agent, err := react.NewAgent(ctx, config)
	if err != nil {
		return executionRun{}, normalizeRunError(ctx, err)
	}
	return executionRun{agent: agent, collector: collector}, nil
}

func graphStepLimit(modelSteps int) int {
	// ReAct graph steps alternate model and tool nodes. The separate model call
	// budget preserves RuntimeConfig.MaxSteps semantics exactly.
	if modelSteps > (int(^uint(0)>>1)-2)/2 {
		return int(^uint(0) >> 1)
	}
	return modelSteps*2 + 2
}

func scanStreamForToolCalls(_ context.Context, stream *schema.StreamReader[*schema.Message]) (bool, error) {
	if stream == nil {
		return false, runtimeapi.ErrInvalidModelResponse
	}
	defer stream.Close()
	found := false
	for {
		message, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return found, nil
		}
		if err != nil {
			return false, err
		}
		if message != nil && len(message.ToolCalls) > 0 {
			found = true
		}
	}
}

func collectEinoStream(stream *schema.StreamReader[*schema.Message]) (*schema.Message, error) {
	if stream == nil {
		return nil, runtimeapi.ErrInvalidModelResponse
	}
	defer stream.Close()
	chunks := make([]*schema.Message, 0, 8)
	for {
		message, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, message)
	}
	if len(chunks) == 0 {
		return nil, runtimeapi.ErrInvalidModelResponse
	}
	return schema.ConcatMessages(chunks)
}

func normalizeRunError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, runtimeapi.ErrStepLimit) || errors.Is(err, compose.ErrExceedMaxSteps) {
		return runtimeapi.ErrStepLimit
	}
	return err
}

type messageCollector struct {
	mu       sync.Mutex
	produced []modelapi.Message
	steps    []runtimeapi.Step
}

func (c *messageCollector) recordModel(message modelapi.Message) {
	message = cloneModelMessage(message)
	message.ReasoningContent = ""
	c.mu.Lock()
	defer c.mu.Unlock()
	c.produced = append(c.produced, message)
	c.steps = append(c.steps, runtimeapi.Step{Kind: runtimeapi.StepModel})
}

func (c *messageCollector) recordToolCall(call modelapi.ToolCall) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.steps = append(c.steps, runtimeapi.Step{Kind: runtimeapi.StepToolCall, ToolCall: call})
}

func (c *messageCollector) recordToolResult(result runtimeapi.ToolExecution) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.produced = append(c.produced, modelapi.Message{
		Role:       modelapi.RoleTool,
		Content:    result.Content,
		Name:       result.Name,
		ToolCallID: result.ToolCallID,
	})
	c.steps = append(c.steps, runtimeapi.Step{Kind: runtimeapi.StepToolResult, ToolResult: result})
}

func (c *messageCollector) result(final modelapi.Message) runtimeapi.EngineResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	produced := make([]modelapi.Message, len(c.produced))
	for index := range c.produced {
		produced[index] = cloneModelMessage(c.produced[index])
	}
	return runtimeapi.EngineResult{
		Message:  cloneModelMessage(final),
		Produced: produced,
		Steps:    append([]runtimeapi.Step(nil), c.steps...),
	}
}
