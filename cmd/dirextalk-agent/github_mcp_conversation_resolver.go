package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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

var githubMCPDirectTools = []string{
	"add_issue_comment",
	"get_commit",
	"get_file_contents",
	"get_me",
	"issue_read",
	"issue_write",
	"list_branches",
	"list_commits",
	"list_issues",
	"list_pull_requests",
	"merge_pull_request",
	"pull_request_read",
	"search_code",
	"search_issues",
	"search_pull_requests",
	"search_repositories",
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
	// A group turn carries no capability permission: its scope comes from the
	// authenticated group origin, so the group keeps its own GitHub credential.
	var owner string
	var gen int64
	origin, groupTurn := coreconversation.GroupOriginFromContext(ctx)
	if groupTurn {
		if origin.Validate() != nil {
			return nil, coreconversation.ErrGroupAuthorization
		}
		owner, gen = origin.OwnerID, int64(origin.AccountGeneration)
	} else {
		p, ok := capabilityclient.PermissionFromContext(ctx)
		if !ok || p == nil {
			return out, nil
		}
		owner, gen = strings.TrimSpace(p.GetAuthenticatedOwnerId()), p.GetAccountGeneration()
	}
	snap, e := r.service.Resolve(ctx, githubScopeForTurn(ctx, owner, gen))
	if errors.Is(e, coregithub.ErrNotConfigured) || errors.Is(e, coregithub.ErrDisabled) {
		return out, nil
	}
	if e != nil {
		// A group turn must never lose its answer because one scoped credential
		// is unreadable: log it and continue without the GitHub tools.
		if _, group := coreconversation.GroupOriginFromContext(ctx); group {
			slog.Warn("[github-mcp] group credential unavailable; continuing without GitHub tools", "error", groupAgentErrorSummary(e))
			return out, nil
		}
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
		slog.Warn("[github-mcp] provider unavailable", "error", groupAgentErrorSummary(e))
		return out, nil
	}
	tools, e := provider.Tools(ctx)
	if e != nil {
		slog.Warn("[github-mcp] tool catalog unavailable", "error", groupAgentErrorSummary(e))
		return out, nil
	}
	selected, ok := selectGitHubMCPTools(tools, groupTurn)
	if !ok {
		return out, nil
	}
	if len(selected) == 0 {
		slog.Warn("[github-mcp] no direct tools selected from the provider catalog", "catalog", len(tools))
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
		// Defence in depth for a turn admitted before this boundary existed: a
		// group turn never writes through the owner's group credential.
		if _, group := coreconversation.GroupOriginFromContext(c); group && !githubMCPToolReadOnly(t) {
			return coreconversation.ToolResult{CallID: q.Call.ID, ToolName: q.Call.Name, IsError: true,
				Content: "This group Ying can only read GitHub with the group credential. Writing or merging needs the group owner's private approval: ask the owner to run it, or request a Worker task for the owner to confirm."}.
				WithObservation(coreconversation.ToolOutcomeFatal, "GitHub write requires the owner's private approval", coreconversation.ToolMutationNone), nil
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

// selectGitHubMCPTools applies Dirextalk's immutable GitHub tool policy to one
// provider catalog. A group turn keeps only reads: any member may ask the group
// Ying a question, but nobody may write, comment or merge with the owner's
// group credential. Those actions stay on the owner's private confirmation path
// (the group can still request a Worker, which the owner approves personally).
//
// The second result is false when the catalog itself is untrustworthy, which
// drops the whole extension instead of a subset.
func selectGitHubMCPTools(tools []mcphttp.Tool, groupTurn bool) ([]mcphttp.Tool, bool) {
	selected := make([]mcphttp.Tool, 0, len(tools))
	seen := make(map[string]struct{}, len(tools))
	for _, t := range tools {
		name := strings.TrimSpace(t.Definition.Name)
		if name == "" || name != t.Definition.Name || t.Run == nil {
			return nil, false
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, false
		}
		seen[name] = struct{}{}
		if !githubMCPDirectTool(name) {
			continue
		}
		if groupTurn && !githubMCPToolReadOnly(t) {
			continue
		}
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
	return selected, true
}

func githubMCPDirectTool(name string) bool {
	remoteName := strings.TrimPrefix(name, "mcp__github__")
	if remoteName == name {
		return false
	}
	for _, allowed := range githubMCPDirectTools {
		if remoteName == allowed {
			return true
		}
	}
	return false
}

// githubMCPToolReadOnly reports whether one provider tool is treated as a read
// at this trusted boundary. It mirrors the selection rules below exactly, so a
// group turn can never be handed a tool that the read-only group boundary
// would reject anyway.
func githubMCPToolReadOnly(t mcphttp.Tool) bool {
	return t.AdvertisedReadOnly || t.Effect.ReadOnly()
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
	scope, ok := githubSecretScope(ctx)
	if !ok {
		return nil, mcphttp.ErrCredentialUnavailable
	}
	var out []byte
	e := s.service.WithTokenResolved(ctx, scope, s.snapshot, func(v string) error { out = []byte(v); return nil })
	return out, e
}

// WithSecret holds coregithub's exact-binding fence across the actual HTTP
// dispatch when mcphttp supports dispatch-scoped credentials.
func (s githubMCPSecret) WithSecret(ctx context.Context, ref string, fn func([]byte) error) error {
	if ref != githubMCPSecretRef || fn == nil {
		return mcphttp.ErrCredentialUnavailable
	}
	scope, ok := githubSecretScope(ctx)
	if !ok {
		return mcphttp.ErrCredentialUnavailable
	}
	return s.service.WithTokenResolved(ctx, scope, s.snapshot, func(value string) error {
		secret := []byte(value)
		defer clear(secret)
		return fn(secret)
	})
}
func githubMCPProvider(service *coregithub.Service, s coregithub.ResolvedConfig) (mcphttp.ToolProvider, error) {
	return mcphttp.New([]mcphttp.ServerConfig{githubMCPServerConfig()}, githubMCPSecret{service: service, snapshot: s})
}

func githubMCPServerConfig() mcphttp.ServerConfig {
	return mcphttp.ServerConfig{
		ID:        "github",
		Endpoint:  githubMCPEndpoint,
		SecretRef: githubMCPSecretRef,
		Headers:   map[string]string{"X-MCP-Tools": strings.Join(githubMCPDirectTools, ",")},
	}
}

// githubScopeForTurn selects the credential scope: a group turn always uses
// that group's independent credential set; every other turn uses the owner's
// personal set. The scope comes from the authenticated turn origin, never from
// a tool argument or member input.
func githubScopeForTurn(ctx context.Context, ownerID string, accountGeneration int64) coregithub.Scope {
	if origin, ok := coreconversation.GroupOriginFromContext(ctx); ok && origin.Validate() == nil && strings.TrimSpace(origin.RoomID) != "" {
		return coregithub.GroupScope(ownerID, accountGeneration, origin.RoomID)
	}
	return coregithub.PersonalScope(ownerID, accountGeneration)
}

// githubSecretScope resolves the credential scope for one dispatch: a group turn
// uses that group's own credential set (no capability permission is present),
// every other turn uses the owner's personal set.
func githubSecretScope(ctx context.Context) (coregithub.Scope, bool) {
	if origin, group := coreconversation.GroupOriginFromContext(ctx); group {
		if origin.Validate() != nil || strings.TrimSpace(origin.OwnerID) == "" {
			return coregithub.Scope{}, false
		}
		return coregithub.GroupScope(origin.OwnerID, int64(origin.AccountGeneration), origin.RoomID), true
	}
	p, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || p == nil {
		return coregithub.Scope{}, false
	}
	return coregithub.PersonalScope(strings.TrimSpace(p.GetAuthenticatedOwnerId()), p.GetAccountGeneration()), true
}
