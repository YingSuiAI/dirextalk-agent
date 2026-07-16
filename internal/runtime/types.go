package runtime

import (
	"errors"
	"time"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
)

var (
	ErrInvalidDependencies  = errors.New("invalid runtime dependencies")
	ErrInvalidRequest       = errors.New("invalid chat request")
	ErrInvalidConversation  = errors.New("invalid conversation state")
	ErrInvalidModelResponse = errors.New("invalid model response")
	ErrInvalidToolCall      = errors.New("invalid model tool call")
	ErrStepLimit            = errors.New("model tool loop exceeded its step limit")
)

type RuntimeConfig struct {
	Revision            int64
	ModelProfile        modelapi.Profile
	ProjectProfile      string
	ContextMessageLimit int
	MemoryMessageLimit  int
	MaxSteps            int
	MemoryDisabled      bool
	EnabledTools        []string
	KnowledgeRefs       []string
	MCPServerIDs        []string
	RecipeIDs           []string
}

type Conversation struct {
	OwnerID        string
	ConversationID string
	Summary        string
	Messages       []modelapi.Message
	Revision       int64
	UpdatedAt      time.Time
}

type ChatRequest struct {
	RequestID                    string
	OwnerID                      string
	ConversationID               string
	ExpectedConversationRevision int64
	Messages                     []modelapi.Message
	MemoryDisabled               bool
	// MemoryModeBound is set only by the durable application coordinator after
	// it has fenced this request and persisted the effective memory mode. It is
	// deliberately excluded from request hashing and every public contract.
	MemoryModeBound bool `json:"-"`
}

type ChatResult struct {
	Message                      modelapi.Message
	Steps                        []Step
	RelatedTaskIDs               []string
	RelatedPlanIDs               []string
	ConversationRevision         int64
	PendingConversation          *Conversation `json:"-"`
	ExpectedConversationRevision int64         `json:"-"`
}

type StepKind string

const (
	StepModel      StepKind = "model"
	StepToolCall   StepKind = "tool_call"
	StepToolResult StepKind = "tool_result"
)

type Step struct {
	Kind       StepKind
	ToolCall   modelapi.ToolCall
	ToolResult ToolExecution
}

type ToolExecution struct {
	ToolCallID     string
	Name           string
	Content        string
	IsError        bool
	RelatedTaskIDs []string
	RelatedPlanIDs []string
}

type StreamEventKind string

const (
	StreamEventDelta      StreamEventKind = "delta"
	StreamEventToolCall   StreamEventKind = "tool_call"
	StreamEventToolResult StreamEventKind = "tool_result"
	StreamEventDone       StreamEventKind = "done"
)

type StreamEvent struct {
	Kind       StreamEventKind
	Delta      modelapi.Delta
	ToolCall   modelapi.ToolCall
	ToolResult ToolExecution
	Result     *ChatResult
}

type StreamEmitter func(StreamEvent) error
