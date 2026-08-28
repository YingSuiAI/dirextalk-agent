package main

import (
	"context"
	"github.com/YingSuiAI/dirextalk-agent/internal/coregithub"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/mcphttp"
	"testing"
	"time"
)

type githubResolverRepo struct{ v coregithub.ResolvedConfig }

func (r *githubResolverRepo) Get(context.Context, string, int64) (coregithub.Config, error) {
	return r.v.Config, nil
}
func (r *githubResolverRepo) Resolve(_ context.Context, o string, g int64) (coregithub.ResolvedConfig, error) {
	v := r.v
	v.OwnerID = o
	v.AccountGeneration = g
	return v, nil
}
func (r *githubResolverRepo) ResolveForDispatch(c context.Context, o string, g int64, _ coregithub.ResolvedConfig) (coregithub.ResolvedConfig, func() error, error) {
	v, e := r.Resolve(c, o, g)
	return v, func() error { return nil }, e
}
func (r *githubResolverRepo) Update(context.Context, coregithub.Mutation) (coregithub.Config, error) {
	return r.v.Config, nil
}
func (r *githubResolverRepo) MarkTested(context.Context, string, int64, int64, time.Time) (coregithub.Config, error) {
	return r.v.Config, nil
}

type githubResolverIdentity struct{}

func (githubResolverIdentity) Identity(context.Context, string) error { return nil }
func githubTool(name string, e mcphttp.ToolEffect) mcphttp.Tool {
	return mcphttp.Tool{Definition: coremodel.Tool{Name: name, Description: "x", InputSchema: map[string]any{"type": "object"}}, Effect: e, Run: func(context.Context, mcphttp.ToolInvocation) (mcphttp.ToolResult, error) {
		return mcphttp.ToolResult{Content: "ok"}, nil
	}}
}
func TestGitHubMCPFiltersToReadonlyCurrentAllowlist(t *testing.T) {
	repo := &githubResolverRepo{v: coregithub.ResolvedConfig{Config: coregithub.Config{Enabled: true, Provider: coregithub.ProviderGitHub, GitHubTokenConfigured: true, Revision: 1}, GitHubToken: "secret", CredentialVersion: 1}}
	svc, _ := coregithub.NewService(repo, githubResolverIdentity{})
	r := &githubMCPConversationResolver{service: svc, factory: func(context.Context, coregithub.ResolvedConfig) (mcphttp.ToolProvider, error) {
		return mcphttp.ToolProviderFunc(func(context.Context) ([]mcphttp.Tool, error) {
			return []mcphttp.Tool{githubTool("mcp__github__get_file_contents", mcphttp.ToolEffectReadOnly), githubTool("mcp__github__create_branch", mcphttp.ToolEffectUnsafeMutation)}, nil
		}), nil
	}}
	got, e := r.ResolveExtensions(webSearchResolverContext(), nil)
	if e != nil || len(got) != 1 || len(got[0].Tools) != 1 || got[0].Tools[0].Name != "mcp__github__get_file_contents" || !got[0].Snapshot.ReadOnly || got[0].Snapshot.RequiresConfirmation {
		t.Fatalf("%#v %v", got, e)
	}
}
