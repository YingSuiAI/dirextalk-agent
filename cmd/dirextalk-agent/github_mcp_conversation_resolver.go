package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coregithub"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/mcphttp"
	"github.com/google/uuid"
)

const githubMCPEndpoint = "https://api.githubcopilot.com/mcp/x/all"
const githubMCPSecretRef = "agent:github:pat"

type githubMCPConversationResolver struct {
	base    coreconversation.ExtensionResolver
	service *coregithub.Service
	factory func(context.Context, coregithub.ResolvedConfig) (mcphttp.ToolProvider, error)
}

func (r *githubMCPConversationResolver) ResolveExtensions(ctx context.Context, selections []coreconversation.ExtensionSelection) ([]coreconversation.ResolvedExtension, error) {
	var out []coreconversation.ResolvedExtension
	if r != nil && r.base != nil {
		v, e := r.base.ResolveExtensions(ctx, selections)
		if e != nil {
			return nil, e
		}
		out = append(out, v...)
	}
	if r == nil || r.service == nil {
		return out, nil
	}
	p, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || p == nil {
		return out, nil
	}
	owner := strings.TrimSpace(p.GetAuthenticatedOwnerId())
	gen := p.GetAccountGeneration()
	snap, e := r.service.Resolve(ctx, owner, gen)
	if errors.Is(e, coregithub.ErrNotConfigured) || errors.Is(e, coregithub.ErrDisabled) {
		return out, nil
	}
	if e != nil {
		return nil, e
	}
	if !snap.Enabled {
		return out, nil
	}
	snap.GitHubToken = ""
	factory := r.factory
	if factory == nil {
		factory = func(_ context.Context, snap coregithub.ResolvedConfig) (mcphttp.ToolProvider, error) {
			return githubMCPProvider(r.service, snap)
		}
	}
	provider, e := factory(ctx, snap)
	if e != nil {
		return out, nil
	}
	tools, e := provider.Tools(ctx)
	if e != nil {
		return out, nil
	}
	selected := make([]mcphttp.Tool, 0, len(tools))
	seen := make(map[string]struct{}, len(tools))
	for _, t := range tools {
		name := strings.TrimSpace(t.Definition.Name)
		if name == "" || name != t.Definition.Name || t.Run == nil {
			return out, nil
		}
		if _, duplicate := seen[name]; duplicate {
			return out, nil
		}
		seen[name] = struct{}{}
		if t.Effect != mcphttp.ToolEffectReadOnly && t.Effect != mcphttp.ToolEffectUnsafeMutation {
			// Missing or unknown provider annotations are never assumed safe to
			// retry. The shared MCP adapter normally performs this normalization;
			// keep the resolver boundary conservative for injected providers too.
			t.Effect = mcphttp.ToolEffectUnsafeMutation
		}
		if t.AdvertisedReadOnly {
			// Preserve generic strict classification, but retain a
			// non-contradictory advertised read at this exact trusted boundary
			// even when optional MCP annotations are omitted.
			t.Effect = mcphttp.ToolEffectReadOnly
			selected = append(selected, t)
			continue
		}
		if t.Effect.ReadOnly() {
			selected = append(selected, t)
			continue
		}
		if githubMCPLightweightMutation(name) {
			selected = append(selected, t)
		}
	}
	if len(selected) == 0 {
		return out, nil
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Definition.Name < selected[j].Definition.Name })
	names := make([]string, 0, len(selected))
	model := make([]coremodel.Tool, 0, len(selected))
	runs := map[string]mcphttp.Tool{}
	for _, t := range selected {
		names = append(names, t.Definition.Name)
		model = append(model, t.Definition)
		runs[t.Definition.Name] = t
	}
	type digestTool struct {
		Definition coremodel.Tool     `json:"definition"`
		Effect     mcphttp.ToolEffect `json:"effect"`
	}
	digestTools := make([]digestTool, 0, len(selected))
	for _, tool := range selected {
		digestTools = append(digestTools, digestTool{Definition: tool.Definition, Effect: tool.Effect})
	}
	digestInput, _ := json.Marshal(struct {
		Endpoint string       `json:"endpoint"`
		Tools    []digestTool `json:"tools"`
	}{Endpoint: githubMCPEndpoint, Tools: digestTools})
	sum := sha256.Sum256(digestInput)
	digest := hex.EncodeToString(sum[:])
	sel := coreconversation.ExtensionSelection{Kind: coreconversation.ExtensionMCP, ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk:github-mcp:"+digest)).String(), Version: fmt.Sprintf("config-%d-%s", snap.Revision, digest[:12]), Digest: digest, AllowedTools: names}
	out = append(out, coreconversation.ResolvedExtension{Selection: sel, Snapshot: coreconversation.ExtensionExecutionSnapshot{
		Selection: sel, InstallationID: sel.ID, VersionID: sel.Version, Source: "github-mcp",
		ContentDigest: digest, ArtifactDigest: digest, ToolSchemaDigest: digest, ToolNames: names,
		// Synthetic MCP tools execute through Core's dispatch-recorded inline
		// path. Per-tool replay safety is enforced from Tool.Effect below.
		ReadOnly: true, RequiresConfirmation: false,
	}, Tools: model, Execute: func(c context.Context, q coreconversation.ToolExecutionRequest) (coreconversation.ToolResult, error) {
		t, ok := runs[q.Call.Name]
		if !ok {
			return coreconversation.ToolResult{}, coregithub.ErrInvalid
		}
		readOnly := t.Effect.ReadOnly()
		result, e := t.Run(c, mcphttp.ToolInvocation{Name: q.Call.Name, Arguments: []byte(q.Call.Arguments)})
		if e != nil {
			if !readOnly {
				return coreconversation.ToolResult{CallID: q.Call.ID, ToolName: q.Call.Name, Content: "GitHub operation completion is unknown. Read authoritative state before deciding whether to retry.", IsError: true}.
					WithObservation(coreconversation.ToolOutcomeUnknownMutation, "GitHub operation completion is unknown", coreconversation.ToolMutationUnknown), nil
			}
			if errors.Is(e, mcphttp.ErrProviderUnavailable) {
				return coreconversation.ToolResult{}, coreconversation.NewToolExecutionError(coreconversation.ToolOutcomeRetryable, "GitHub MCP unavailable", 0, e)
			}
			return coreconversation.ToolResult{}, coreconversation.NewToolExecutionError(coreconversation.ToolOutcomeFatal, "GitHub MCP failed", 0, e)
		}
		toolResult := coreconversation.ToolResult{CallID: q.Call.ID, ToolName: q.Call.Name, Content: result.Content, IsError: result.IsError}
		if result.IsError && !readOnly {
			return toolResult.WithObservation(coreconversation.ToolOutcomeUnknownMutation, "GitHub operation completion is unknown", coreconversation.ToolMutationUnknown), nil
		}
		if result.IsError {
			return toolResult.WithObservation(coreconversation.ToolOutcomeFatal, "GitHub MCP reported a failure", coreconversation.ToolMutationNone), nil
		}
		if readOnly {
			return toolResult.WithObservation(coreconversation.ToolOutcomeSuccess, "GitHub read completed", coreconversation.ToolMutationNone), nil
		}
		toolResult.StateChanged = true
		return toolResult.WithObservation(coreconversation.ToolOutcomeSuccess, "GitHub operation completed", coreconversation.ToolMutationChanged), nil
	}})
	return out, nil
}

// githubMCPLightweightMutation is Dirextalk's immutable mutation allowlist.
// These names match the official GitHub MCP documentation. Repository code/
// ref/content writes and pull-request creation stay on the confirmation-gated
// Cloud Worker path.
func githubMCPLightweightMutation(name string) bool {
	switch name {
	case "mcp__github__add_issue_comment", "mcp__github__issue_write", "mcp__github__merge_pull_request":
		return true
	default:
		return false
	}
}

type githubMCPSecret struct {
	service  *coregithub.Service
	snapshot coregithub.ResolvedConfig
}

func (s githubMCPSecret) ResolveSecret(ctx context.Context, ref string) ([]byte, error) {
	if ref != githubMCPSecretRef {
		return nil, mcphttp.ErrCredentialUnavailable
	}
	p, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || p == nil {
		return nil, mcphttp.ErrCredentialUnavailable
	}
	var out []byte
	e := s.service.WithTokenResolved(ctx, strings.TrimSpace(p.GetAuthenticatedOwnerId()), p.GetAccountGeneration(), s.snapshot, func(v string) error { out = []byte(v); return nil })
	return out, e
}

// WithSecret holds coregithub's exact-binding fence across the actual HTTP
// dispatch when mcphttp supports dispatch-scoped credentials.
func (s githubMCPSecret) WithSecret(ctx context.Context, ref string, fn func([]byte) error) error {
	if ref != githubMCPSecretRef || fn == nil {
		return mcphttp.ErrCredentialUnavailable
	}
	p, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || p == nil {
		return mcphttp.ErrCredentialUnavailable
	}
	return s.service.WithTokenResolved(ctx, strings.TrimSpace(p.GetAuthenticatedOwnerId()), p.GetAccountGeneration(), s.snapshot, func(value string) error {
		secret := []byte(value)
		defer clear(secret)
		return fn(secret)
	})
}
func githubMCPProvider(service *coregithub.Service, s coregithub.ResolvedConfig) (mcphttp.ToolProvider, error) {
	return mcphttp.New([]mcphttp.ServerConfig{githubMCPServerConfig()}, githubMCPSecret{service: service, snapshot: s})
}

func githubMCPServerConfig() mcphttp.ServerConfig {
	return mcphttp.ServerConfig{ID: "github", Endpoint: githubMCPEndpoint, SecretRef: githubMCPSecretRef}
}
