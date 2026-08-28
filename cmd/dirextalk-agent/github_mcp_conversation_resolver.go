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

const githubMCPEndpoint = "https://api.githubcopilot.com/mcp/"
const githubMCPSecretRef = "agent:github:pat"

var githubMCPAllowed = map[string]struct{}{
	"mcp__github__get_file_contents": {}, "mcp__github__list_branches": {}, "mcp__github__list_commits": {}, "mcp__github__get_commit": {}, "mcp__github__search_repositories": {}, "mcp__github__list_pull_requests": {}, "mcp__github__pull_request_read": {}, "mcp__github__search_pull_requests": {},
}

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
		if _, allowed := githubMCPAllowed[name]; allowed {
			// GitHub's readonly endpoint and explicit header are an additional
			// contract: its current read tools can omit idempotency annotations.
			// Do not change generic MCP effect classification; only this exact
			// curated allowlist is normalized to an observation-only operation.
			t.Effect = mcphttp.ToolEffectReadOnly
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
	digestInput, _ := json.Marshal(digestTools)
	sum := sha256.Sum256(digestInput)
	digest := hex.EncodeToString(sum[:])
	sel := coreconversation.ExtensionSelection{Kind: coreconversation.ExtensionMCP, ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk:github-mcp:"+digest)).String(), Version: fmt.Sprintf("config-%d-%s", snap.Revision, digest[:12]), Digest: digest, AllowedTools: names}
	out = append(out, coreconversation.ResolvedExtension{Selection: sel, Snapshot: coreconversation.ExtensionExecutionSnapshot{Selection: sel, InstallationID: sel.ID, VersionID: sel.Version, Source: "github-mcp", ContentDigest: digest, ArtifactDigest: digest, ToolSchemaDigest: digest, ToolNames: names, ReadOnly: true, RequiresConfirmation: false}, Tools: model, Execute: func(c context.Context, q coreconversation.ToolExecutionRequest) (coreconversation.ToolResult, error) {
		t, ok := runs[q.Call.Name]
		if !ok {
			return coreconversation.ToolResult{}, coregithub.ErrInvalid
		}
		result, e := t.Run(c, mcphttp.ToolInvocation{Name: q.Call.Name, Arguments: []byte(q.Call.Arguments)})
		if e != nil {
			if errors.Is(e, mcphttp.ErrProviderUnavailable) {
				return coreconversation.ToolResult{}, coreconversation.NewToolExecutionError(coreconversation.ToolOutcomeRetryable, "GitHub MCP unavailable", 0, e)
			}
			return coreconversation.ToolResult{}, coreconversation.NewToolExecutionError(coreconversation.ToolOutcomeFatal, "GitHub MCP failed", 0, e)
		}
		if result.IsError {
			return coreconversation.ToolResult{CallID: q.Call.ID, ToolName: q.Call.Name, Content: result.Content, IsError: true}.WithObservation(coreconversation.ToolOutcomeFatal, "GitHub MCP reported a failure", coreconversation.ToolMutationNone), nil
		}
		return coreconversation.ToolResult{CallID: q.Call.ID, ToolName: q.Call.Name, Content: result.Content}.WithObservation(coreconversation.ToolOutcomeSuccess, "GitHub read completed", coreconversation.ToolMutationNone), nil
	}})
	return out, nil
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
	return mcphttp.New([]mcphttp.ServerConfig{{ID: "github", Endpoint: githubMCPEndpoint, SecretRef: githubMCPSecretRef, Headers: map[string]string{"X-MCP-Toolsets": "repos,pull_requests", "X-MCP-Readonly": "true"}}}, githubMCPSecret{service: service, snapshot: s})
}
