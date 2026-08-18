package mcphttp

import (
	"context"
	"encoding/json"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

// SecretResolver is the narrow credential boundary used by MCP transports.
// Resolved bytes remain inside the outbound request path and are never exposed
// through tool metadata or results.
type SecretResolver interface {
	ResolveSecret(context.Context, string) ([]byte, error)
}

// ToolProvider exposes only the fixed, trusted MCP server set configured by
// the service owner. Model output cannot select endpoints or credentials.
type ToolProvider interface {
	Tools(context.Context) ([]Tool, error)
}

type ToolProviderFunc func(context.Context) ([]Tool, error)

func (f ToolProviderFunc) Tools(ctx context.Context) ([]Tool, error) {
	return f(ctx)
}

type Tool struct {
	Definition coremodel.Tool
	Effect     ToolEffect
	Run        func(context.Context, ToolInvocation) (ToolResult, error)
}

// ToolEffect is the conservative execution class derived from the complete
// standard MCP tool annotations. Only an internally consistent, fully
// annotated read is safe to replay. Every incomplete or contradictory
// annotation set is an unsafe mutation.
type ToolEffect string

const (
	ToolEffectReadOnly       ToolEffect = "read_only"
	ToolEffectUnsafeMutation ToolEffect = "unsafe_mutation"
)

func (e ToolEffect) ReadOnly() bool { return e == ToolEffectReadOnly }

// ToolInvocation binds a call to its model tool name and canonical arguments.
type ToolInvocation struct {
	Name      string
	Arguments json.RawMessage
}

// ToolResult is model-visible output after capability-level redaction and
// bounded serialization. StructuredContent is an ephemeral, bounded copy for
// trusted adapters that project known fields into their own validated domain
// types; it must not be persisted or exposed wholesale.
type ToolResult struct {
	Content           string
	StructuredContent json.RawMessage
	IsError           bool
}
