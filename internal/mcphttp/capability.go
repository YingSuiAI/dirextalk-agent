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
	Run        func(context.Context, ToolInvocation) (ToolResult, error)
}

// ToolInvocation binds a call to its model tool name and canonical arguments.
type ToolInvocation struct {
	Name      string
	Arguments json.RawMessage
}

// ToolResult is model-visible output after capability-level redaction and
// bounded serialization.
type ToolResult struct {
	Content string
	IsError bool
}
