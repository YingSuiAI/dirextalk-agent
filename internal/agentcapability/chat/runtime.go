package chat

import (
	"context"
	"io"
	"strings"

	einotool "github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/flow/agent/react"
	"github.com/cloudwego/eino/schema"
)

// Runtime provides the core Agent execution environment
type Runtime struct {
	graphManager *compose.GraphManager
}

// NewRuntime creates a new Agent runtime
func NewRuntime() *Runtime {
	return &Runtime{
		graphManager: compose.NewGraphManager(),
	}
}

// StreamMessage executes an agent turn with streaming output
func (r *Runtime) StreamMessage(
	ctx context.Context,
	messages []*schema.Message,
	tools []einotool.BaseTool,
	maxSteps int,
) (<-chan *MessageChunk, error) {
	// Build agent graph
	agentRunner, err := r.buildAgent(ctx, tools, maxSteps)
	if err != nil {
		return nil, err
	}

	// Start streaming
	futureOpt, _ := react.WithMessageFuture()
	stream, err := agentRunner.Stream(ctx, messages, futureOpt)
	if err != nil {
		return nil, err
	}

	// Convert to our channel
	outChan := make(chan *MessageChunk, 10)
	go func() {
		defer close(outChan)
		defer stream.Close()

		for {
			chunk, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				outChan <- &MessageChunk{Error: err}
				break
			}
			if chunk == nil {
				continue
			}

			outChan <- &MessageChunk{
				Content:           chunk.Content,
				ReasoningContent:  chunk.ReasoningContent,
			}
		}
	}()

	return outChan, nil
}

// MessageChunk represents a streaming response chunk
type MessageChunk struct {
	Content          string
	ReasoningContent string
	Error            error
}

func (r *Runtime) buildAgent(ctx context.Context, tools []einotool.BaseTool, maxSteps int) (*react.Agent, error) {
	// Build agent graph with React pattern
	graph := compose.NewGraph[map[string]any]()

	// Configure agent options
	options := []react.Option{
		react.WithMaxSteps(maxSteps),
		react.WithTools(tools),
	}

	// Create and compile agent
	agent, err := react.NewAgent(graph, options...)
	if err != nil {
		return nil, err
	}

	return agent, nil
}

// ExecuteAgentTurn runs a complete agent turn with tool calling
func (r *Runtime) ExecuteAgentTurn(
	ctx context.Context,
	messages []*schema.Message,
	profile *ModelProfile,
	tools []einotool.BaseTool,
	session *SessionState,
	maxSteps int,
) (string, []map[string]any, error) {
	agentRunner, err := r.buildAgent(ctx, tools, maxSteps)
	if err != nil {
		return "", nil, err
	}

	// Execute synchronously
	result, err := agentRunner.Generate(ctx, messages)
	if err != nil {
		return "", nil, err
	}

	// Extract tool calls
	toolCalls := extractToolCalls(result)

	return result.Content, toolCalls, nil
}

type ModelProfile struct {
	Provider    string
	Model       string
	Temperature float64
	MaxTokens   int
}

type SessionState struct {
	ConversationID string
	TurnCount      int
	Memory         map[string]interface{}
}

func extractToolCalls(msg *schema.Message) []map[string]any {
	calls := []map[string]any{}
	// TODO: Extract from message tool calls
	return calls
}
