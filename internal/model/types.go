// Package model provides a provider-neutral model boundary for the Agent
// runtime. Credentials are resolved only while constructing an outbound
// request and are never part of Profile, CompletionRequest, or model output.
package model

import (
	"context"
	"errors"
	"net/http"
)

type Provider string

const (
	ProviderOpenAICompatible Provider = "openai_compatible"
	ProviderDeepSeek         Provider = "deepseek"
	ProviderAnthropic        Provider = "anthropic"
)

type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

var (
	ErrInvalidProfile      = errors.New("invalid model profile")
	ErrSecretUnavailable   = errors.New("model credential is unavailable")
	ErrProviderUnavailable = errors.New("model provider is unavailable")
	ErrResponseTooLarge    = errors.New("model provider response exceeds the allowed size")
)

// Profile contains only non-secret model configuration. SecretRef is an
// opaque reference resolved immediately before an outbound provider request.
type Profile struct {
	// ProfileID selects immutable, server-owned provider configuration. Public
	// callers may tune only the bounded sampling fields below.
	ProfileID       string
	Provider        Provider
	Model           string
	BaseURL         string
	SecretRef       string
	Temperature     *float64
	TopP            *float64
	MaxOutputTokens int
	ContextWindow   int
	ReasoningEffort string
	// AllowInsecureHTTP is test-only and is honored only together with an
	// explicitly injected HTTPClient. It never weakens the default transport.
	AllowInsecureHTTP bool
}

type Message struct {
	Role             Role
	Content          string
	ReasoningContent string
	Name             string
	ToolCallID       string
	ToolCalls        []ToolCall
}

type ToolCall struct {
	Index    int
	ID       string
	Type     string
	Function FunctionCall
}

type FunctionCall struct {
	Name      string
	Arguments string
}

type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
}

type CompletionRequest struct {
	Messages []Message
	Tools    []Tool
}

type Completion struct {
	Message Message
	Usage   Usage
}

type Usage struct {
	InputTokens  int
	OutputTokens int
	TotalTokens  int
}

type Delta struct {
	Content          string
	ReasoningContent string
	ToolCalls        []ToolCall
}

type Stream interface {
	Recv() (Delta, error)
	Close() error
}

type Client interface {
	Generate(context.Context, CompletionRequest) (Completion, error)
	Stream(context.Context, CompletionRequest) (Stream, error)
}

// SecretResolver returns a caller-owned credential buffer. The model client
// zeroes that buffer after the HTTP request has been dispatched. Resolver
// errors are intentionally collapsed to ErrSecretUnavailable so backend
// details cannot enter logs, events, or model-visible errors.
type SecretResolver interface {
	ResolveSecret(context.Context, string) ([]byte, error)
}

type SecretResolverFunc func(context.Context, string) ([]byte, error)

func (f SecretResolverFunc) ResolveSecret(ctx context.Context, ref string) ([]byte, error) {
	return f(ctx, ref)
}

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}
