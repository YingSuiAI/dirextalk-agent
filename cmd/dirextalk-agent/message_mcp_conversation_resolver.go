package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/mcphttp"
	"github.com/google/uuid"
)

const (
	messageMCPServerID  = "message"
	messageMCPSecretRef = "mounted:message-mcp-token"
)

type messageMCPConversationResolver struct {
	base     coreconversation.ExtensionResolver
	provider mcphttp.ToolProvider
	endpoint string
}

type mountedMessageMCPToken struct{ path string }

// ResolveSecret reads a fresh private buffer for each request. mcphttp clears
// that buffer after removing the Authorization header from the request.
func (r mountedMessageMCPToken) ResolveSecret(_ context.Context, ref string) ([]byte, error) {
	if ref != messageMCPSecretRef || config.ValidateMountedSecretFile(r.path) != nil {
		return nil, mcphttp.ErrCredentialUnavailable
	}
	file, err := os.Open(r.path)
	if err != nil {
		return nil, mcphttp.ErrCredentialUnavailable
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 16<<10+1))
	if err != nil || len(raw) == 0 || len(raw) > 16<<10 || !bytes.Equal(raw, bytes.TrimSpace(raw)) || bytes.ContainsAny(raw, "\r\n\x00") {
		clear(raw)
		return nil, mcphttp.ErrCredentialUnavailable
	}
	return raw, nil
}

func newMessageMCPProvider(endpoint, tokenFile string) (*mcphttp.Provider, error) {
	return mcphttp.NewTrustedInternal(mcphttp.ServerConfig{
		ID: messageMCPServerID, Endpoint: endpoint, SecretRef: messageMCPSecretRef,
	}, mountedMessageMCPToken{path: tokenFile})
}

func (r *messageMCPConversationResolver) ResolveExtensions(ctx context.Context, selections []coreconversation.ExtensionSelection) ([]coreconversation.ResolvedExtension, error) {
	var resolved []coreconversation.ResolvedExtension
	if r != nil && r.base != nil {
		base, err := r.base.ResolveExtensions(ctx, selections)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, base...)
	}
	if r == nil || r.provider == nil || strings.TrimSpace(r.endpoint) == "" {
		return resolved, nil
	}
	remoteTools, err := r.provider.Tools(ctx)
	if err != nil {
		return nil, fmt.Errorf("message MCP tools unavailable: %w", err)
	}
	sort.Slice(remoteTools, func(i, j int) bool { return remoteTools[i].Definition.Name < remoteTools[j].Definition.Name })
	tools := make([]coremodel.Tool, 0, len(remoteTools))
	runners := make(map[string]mcphttp.Tool, len(remoteTools))
	allowed := make([]string, 0, len(remoteTools))
	for _, remote := range remoteTools {
		name := strings.TrimSpace(remote.Definition.Name)
		if name == "" {
			return nil, fmt.Errorf("message MCP advertised an invalid tool")
		}
		if _, duplicate := runners[name]; duplicate {
			return nil, fmt.Errorf("message MCP advertised duplicate tool %q", name)
		}
		tools = append(tools, remote.Definition)
		allowed = append(allowed, name)
		runners[name] = remote
	}
	if len(tools) == 0 {
		return resolved, nil
	}
	contentDigest := messageMCPToolDigest(r.endpoint, tools)
	selection := coreconversation.ExtensionSelection{
		Kind:    coreconversation.ExtensionMCP,
		ID:      uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk:message-mcp:"+contentDigest)).String(),
		Version: "1.0.0", Digest: contentDigest, AllowedTools: append([]string(nil), allowed...),
	}
	artifactDigest := digestBytes([]byte("message-mcp-artifact:" + r.endpoint))
	schemaDigest := productToolsSchemaDigest(tools)
	resolved = append(resolved, coreconversation.ResolvedExtension{
		Selection: selection,
		Snapshot: coreconversation.ExtensionExecutionSnapshot{
			Selection: selection, InstallationID: selection.ID, VersionID: selection.Version,
			Source: "message-mcp", ContentDigest: contentDigest, ArtifactDigest: artifactDigest,
			ToolSchemaDigest: schemaDigest, ToolNames: append([]string(nil), allowed...),
			// Core's inline path records dispatch before the network call and never
			// replays a dispatched call after restart. This coarse flag is required
			// for synthetic tools even though this catalog includes mutations.
			ReadOnly: true,
		},
		Tools: tools,
		Execute: func(callCtx context.Context, request coreconversation.ToolExecutionRequest) (coreconversation.ToolResult, error) {
			tool, ok := runners[request.Call.Name]
			if !ok {
				return coreconversation.ToolResult{}, fmt.Errorf("message MCP tool %q is unavailable", request.Call.Name)
			}
			arguments := json.RawMessage(request.Call.Arguments)
			if len(arguments) == 0 {
				arguments = json.RawMessage(`{}`)
			}
			result, runErr := tool.Run(callCtx, mcphttp.ToolInvocation{Name: request.Call.Name, Arguments: arguments})
			if runErr != nil {
				if messageMCPMutationTool(request.Call.Name) {
					return coreconversation.ToolResult{
						CallID: request.Call.ID, ToolName: request.Call.Name, IsError: true,
						Content: "Message operation completion is unknown. Read authoritative state before deciding whether to retry; do not retry blindly.",
					}, nil
				}
				return coreconversation.ToolResult{}, runErr
			}
			return coreconversation.ToolResult{CallID: request.Call.ID, ToolName: request.Call.Name, Content: result.Content, IsError: result.IsError}, nil
		},
	})
	return resolved, nil
}

func messageMCPToolDigest(endpoint string, tools []coremodel.Tool) string {
	ordered := append([]coremodel.Tool(nil), tools...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	raw, _ := json.Marshal(struct {
		Endpoint string           `json:"endpoint"`
		Tools    []coremodel.Tool `json:"tools"`
	}{Endpoint: endpoint, Tools: ordered})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func messageMCPMutationTool(name string) bool {
	return strings.HasSuffix(name, "__dirextalk_messages_send") || strings.HasSuffix(name, "__dirextalk_channel_comments_create")
}
