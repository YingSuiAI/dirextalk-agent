package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	"mcp__github__get_repository": {}, "mcp__github__search_repositories": {}, "mcp__github__get_file_contents": {}, "mcp__github__list_branches": {}, "mcp__github__list_commits": {}, "mcp__github__list_pull_requests": {}, "mcp__github__get_pull_request": {},
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
	for _, t := range tools {
		if _, ok := githubMCPAllowed[t.Definition.Name]; !ok || t.Run == nil {
			return out, nil
		}
	}
	if len(tools) == 0 {
		return out, nil
	}
	names := make([]string, 0, len(tools))
	model := make([]coremodel.Tool, 0, len(tools))
	runs := map[string]mcphttp.Tool{}
	for _, t := range tools {
		names = append(names, t.Definition.Name)
		model = append(model, t.Definition)
		runs[t.Definition.Name] = t
	}
	sum := sha256.Sum256([]byte(strings.Join(names, "\x00")))
	digest := hex.EncodeToString(sum[:])
	sel := coreconversation.ExtensionSelection{Kind: coreconversation.ExtensionMCP, ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk:github-mcp")).String(), Version: fmt.Sprintf("config-%d", snap.Revision), Digest: digest, AllowedTools: names}
	out = append(out, coreconversation.ResolvedExtension{Selection: sel, Snapshot: coreconversation.ExtensionExecutionSnapshot{Selection: sel, InstallationID: sel.ID, VersionID: sel.Version, Source: "github-mcp", ContentDigest: digest, ArtifactDigest: digest, ToolSchemaDigest: digest, ToolNames: names, ReadOnly: true, RequiresConfirmation: true}, Tools: model, Execute: func(c context.Context, q coreconversation.ToolExecutionRequest) (coreconversation.ToolResult, error) {
		t, ok := runs[q.Call.Name]
		if !ok {
			return coreconversation.ToolResult{}, coregithub.ErrInvalid
		}
		result, e := t.Run(c, mcphttp.ToolInvocation{Name: q.Call.Name, Arguments: []byte(q.Call.Arguments)})
		if e != nil {
			return coreconversation.ToolResult{}, coreconversation.NewToolExecutionError(coreconversation.ToolOutcomeRetryable, "GitHub MCP unavailable", 0, e)
		}
		return coreconversation.ToolResult{CallID: q.Call.ID, ToolName: q.Call.Name, Content: result.Content, IsError: result.IsError}.WithObservation(coreconversation.ToolOutcomeSuccess, "GitHub MCP completed", coreconversation.ToolMutationNone), nil
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
func githubMCPProvider(service *coregithub.Service, s coregithub.ResolvedConfig) (mcphttp.ToolProvider, error) {
	return mcphttp.New([]mcphttp.ServerConfig{{ID: "github", Endpoint: githubMCPEndpoint, SecretRef: githubMCPSecretRef, Headers: map[string]string{"X-MCP-Toolsets": "repos,pull_requests"}}}, githubMCPSecret{service: service, snapshot: s})
}
