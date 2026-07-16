package runtime

import (
	"context"
	"encoding/json"
	"time"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
)

// ModelFactory binds a non-secret profile to the runtime's opaque secret
// resolver. Implementations must not copy resolved credential material into a
// profile, prompt, trace, event, or error.
type ModelFactory interface {
	CreateModel(context.Context, modelapi.Profile, SecretResolver) (modelapi.Client, error)
}

type ModelFactoryFunc func(context.Context, modelapi.Profile, SecretResolver) (modelapi.Client, error)

func (f ModelFactoryFunc) CreateModel(ctx context.Context, profile modelapi.Profile, secrets SecretResolver) (modelapi.Client, error) {
	return f(ctx, profile, secrets)
}

// SecretResolver is deliberately identical to the model package boundary but
// remains a runtime port so the service composition root owns secret access.
type SecretResolver interface {
	ResolveSecret(context.Context, string) ([]byte, error)
}

type RuntimeConfigRepository interface {
	LoadRuntimeConfig(context.Context, string) (RuntimeConfig, error)
}

type ConversationRepository interface {
	LoadConversation(context.Context, string, string) (Conversation, bool, error)
}

type ToolProvider interface {
	Tools(context.Context, ToolRequest) ([]Tool, error)
}

type ToolProviderFunc func(context.Context, ToolRequest) ([]Tool, error)

func (f ToolProviderFunc) Tools(ctx context.Context, request ToolRequest) ([]Tool, error) {
	return f(ctx, request)
}

type Tool struct {
	Definition modelapi.Tool
	Run        func(context.Context, ToolInvocation) (ToolResult, error)
}

// ToolResult.Content is model-visible and must already be de-secreted by the
// typed capability adapter. Runtime-generated execution failures never include
// the underlying error text.
type ToolResult struct {
	Content        string
	IsError        bool
	RelatedTaskIDs []string
	RelatedPlanIDs []string
}

type ToolRequest struct {
	RequestID      string
	OwnerID        string
	ConversationID string
	EnabledNames   []string
	KnowledgeRefs  []string
	MCPServerIDs   []string
	RecipeIDs      []string
}

// ToolInvocation binds every model tool call to the authenticated chat
// request. Capability adapters use RequestID + ToolCallID as their durable
// idempotency scope; the runtime never invents a new key during retries.
type ToolInvocation struct {
	RequestID      string
	OwnerID        string
	ConversationID string
	ToolCallID     string
	Name           string
	Arguments      json.RawMessage
}

// Engine is the single model/tool execution boundary used by Runtime. The
// service composition root injects one implementation (the native Eino
// engine); Runtime never falls back to a second hand-written tool loop.
type Engine interface {
	Generate(context.Context, EngineRequest) (EngineResult, error)
	Stream(context.Context, EngineRequest, StreamEmitter) (EngineResult, error)
}

type ToolInvoker func(context.Context, modelapi.ToolCall) (ToolExecution, error)

// MessageRewriter keeps conversation compaction policy owned by Runtime while
// allowing the engine to apply it before every model round.
type MessageRewriter func([]modelapi.Message) []modelapi.Message

type EngineRequest struct {
	Client          modelapi.Client
	Messages        []modelapi.Message
	Tools           []modelapi.Tool
	MaxSteps        int
	InvokeTool      ToolInvoker
	RewriteMessages MessageRewriter
}

type EngineResult struct {
	Message  modelapi.Message
	Produced []modelapi.Message
	Steps    []Step
}

type Clock func() time.Time

type Dependencies struct {
	Engine        Engine
	Models        ModelFactory
	Tools         ToolProvider
	Configs       RuntimeConfigRepository
	Conversations ConversationRepository
	Secrets       SecretResolver
	Clock         Clock
}
