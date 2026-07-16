// Package mcphttp adapts trusted Streamable HTTP MCP servers to the generic
// Agent runtime tool boundary. Server endpoints and credential references are
// control-plane configuration; model output can never select or override them.
package mcphttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
)

const (
	protocolVersion    = "2025-06-18"
	defaultTimeout     = 15 * time.Second
	maxResponseBytes   = 1 << 20
	maxToolResultBytes = 32 << 10
	maxSchemaBytes     = 64 << 10
	maxToolArguments   = 64 << 10
	maxToolPages       = 32
	maxTools           = 256
)

var (
	ErrInvalidConfig         = errors.New("invalid MCP HTTP configuration")
	ErrEndpointDenied        = errors.New("MCP endpoint is denied")
	ErrCredentialUnavailable = errors.New("MCP credential is unavailable")
	ErrProviderUnavailable   = errors.New("MCP provider is unavailable")
	ErrProtocol              = errors.New("invalid MCP protocol response")
	ErrResponseTooLarge      = errors.New("MCP response exceeds the allowed size")
	ErrInvalidToolDefinition = errors.New("invalid MCP tool definition")
	ErrUnsafeToolArguments   = errors.New("unsafe MCP tool arguments")
)

var serverIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// ServerConfig contains only trusted, non-secret MCP routing information.
// Callers provide already-enabled servers; local process transports and raw
// authorization headers are intentionally not representable.
type ServerConfig struct {
	ID        string `json:"id"`
	Endpoint  string `json:"endpoint"`
	SecretRef string `json:"secret_ref"`
	Transport string `json:"transport,omitempty"`
}

// EndpointPolicy is evaluated before every request and before resolving a
// credential. Production uses a public-network-only policy. Tests may inject a
// narrower explicit policy together with a test transport.
type EndpointPolicy interface {
	Validate(context.Context, *url.URL) error
}

type EndpointPolicyFunc func(context.Context, *url.URL) error

func (f EndpointPolicyFunc) Validate(ctx context.Context, endpoint *url.URL) error {
	return f(ctx, endpoint)
}

type Option func(*options)

type options struct {
	policy    EndpointPolicy
	transport http.RoundTripper
	timeout   time.Duration
}

func WithEndpointPolicy(policy EndpointPolicy) Option {
	return func(options *options) { options.policy = policy }
}

func WithRoundTripper(transport http.RoundTripper) Option {
	return func(options *options) { options.transport = transport }
}

func WithRequestTimeout(timeout time.Duration) Option {
	return func(options *options) { options.timeout = timeout }
}

type configuredServer struct {
	id        string
	endpoint  *url.URL
	secretRef string
	transport string
}

// Provider implements runtime.ToolProvider for a fixed trusted server set.
// It keeps neither resolved credentials nor model-provided routing state.
type Provider struct {
	servers []configuredServer
	secrets runtimeapi.SecretResolver
	policy  EndpointPolicy
	client  *http.Client
	timeout time.Duration
}

var _ runtimeapi.ToolProvider = (*Provider)(nil)

func New(configs []ServerConfig, secrets runtimeapi.SecretResolver, optionValues ...Option) (*Provider, error) {
	opts := options{timeout: defaultTimeout}
	for _, option := range optionValues {
		if option != nil {
			option(&opts)
		}
	}
	if opts.timeout <= 0 {
		return nil, ErrInvalidConfig
	}
	if opts.policy == nil {
		opts.policy = newPublicEndpointPolicy()
	}
	if opts.transport == nil {
		opts.transport = newSecureTransport()
	}
	if opts.policy == nil || opts.transport == nil {
		return nil, ErrInvalidConfig
	}

	servers := make([]configuredServer, 0, len(configs))
	seenIDs := make(map[string]struct{}, len(configs))
	for _, config := range configs {
		server, err := normalizeServerConfig(config)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seenIDs[server.id]; duplicate {
			return nil, fmt.Errorf("%w: duplicate server id", ErrInvalidConfig)
		}
		seenIDs[server.id] = struct{}{}
		if server.secretRef != "" && secrets == nil {
			return nil, fmt.Errorf("%w: credential resolver is required", ErrInvalidConfig)
		}
		servers = append(servers, server)
	}

	client := &http.Client{
		Transport: opts.transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Provider{servers: servers, secrets: secrets, policy: opts.policy, client: client, timeout: opts.timeout}, nil
}

func normalizeServerConfig(config ServerConfig) (configuredServer, error) {
	id := strings.TrimSpace(config.ID)
	if !serverIDPattern.MatchString(id) {
		return configuredServer{}, fmt.Errorf("%w: invalid server id", ErrInvalidConfig)
	}
	transport := strings.ToLower(strings.TrimSpace(config.Transport))
	if transport == "" {
		transport = "streamable_http"
	}
	if transport != "streamable_http" && transport != "streamable-http" {
		return configuredServer{}, fmt.Errorf("%w: unsupported transport", ErrInvalidConfig)
	}
	endpoint, err := parseTrustedEndpoint(config.Endpoint)
	if err != nil {
		return configuredServer{}, err
	}
	secretRef := strings.TrimSpace(config.SecretRef)
	if len(secretRef) > 512 || strings.ContainsAny(secretRef, "\r\n\x00") {
		return configuredServer{}, fmt.Errorf("%w: invalid credential reference", ErrInvalidConfig)
	}
	return configuredServer{id: id, endpoint: endpoint, secretRef: secretRef, transport: transport}, nil
}

func (p *Provider) Tools(ctx context.Context, request runtimeapi.ToolRequest) ([]runtimeapi.Tool, error) {
	if p == nil || p.client == nil || p.policy == nil {
		return nil, ErrInvalidConfig
	}
	tools := make([]runtimeapi.Tool, 0)
	exposedNames := make(map[string]struct{})
	for _, server := range p.servers {
		session, err := p.initialize(ctx, server)
		if err != nil {
			return nil, err
		}
		remoteTools, err := session.listTools(ctx)
		if err != nil {
			return nil, err
		}
		for _, remote := range remoteTools {
			exposedName := "mcp__" + server.id + "__" + remote.Name
			if len(exposedName) > 64 || !modelToolNamePattern.MatchString(exposedName) {
				return nil, ErrInvalidToolDefinition
			}
			if _, duplicate := exposedNames[exposedName]; duplicate {
				return nil, ErrInvalidToolDefinition
			}
			exposedNames[exposedName] = struct{}{}
			remoteName := remote.Name
			toolName := exposedName
			toolSession := session
			tools = append(tools, runtimeapi.Tool{
				Definition: modelapi.Tool{
					Name:        toolName,
					Description: remote.Description,
					InputSchema: cloneSchema(remote.InputSchema),
				},
				Run: func(callCtx context.Context, invocation runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
					if strings.TrimSpace(invocation.Name) != toolName {
						return runtimeapi.ToolResult{}, ErrUnsafeToolArguments
					}
					arguments, err := validateToolArguments(invocation.Arguments)
					if err != nil {
						return runtimeapi.ToolResult{}, err
					}
					return toolSession.callTool(callCtx, remoteName, arguments)
				},
			})
		}
	}
	return tools, nil
}

type remoteTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

var modelToolNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func validateRemoteTool(tool remoteTool) (remoteTool, error) {
	tool.Name = strings.TrimSpace(tool.Name)
	tool.Description = sanitizeToolMetadata(tool.Description)
	if tool.Name == "" || len(tool.Name) > 48 || !modelToolNamePattern.MatchString(tool.Name) {
		return remoteTool{}, ErrInvalidToolDefinition
	}
	if err := validateInputSchema(tool.InputSchema); err != nil {
		return remoteTool{}, err
	}
	tool.InputSchema = cloneSchema(tool.InputSchema)
	return tool, nil
}

func cloneSchema(schema map[string]any) map[string]any {
	data, err := json.Marshal(schema)
	if err != nil {
		return nil
	}
	var cloned map[string]any
	if err := json.Unmarshal(data, &cloned); err != nil {
		return nil
	}
	return cloned
}
