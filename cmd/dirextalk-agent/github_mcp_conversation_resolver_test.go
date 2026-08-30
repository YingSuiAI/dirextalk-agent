package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coregithub"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/mcphttp"
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
			return []mcphttp.Tool{githubTool("mcp__github__get_file_contents", mcphttp.ToolEffectUnsafeMutation), githubTool("mcp__github__create_branch", mcphttp.ToolEffectUnsafeMutation)}, nil
		}), nil
	}}
	got, e := r.ResolveExtensions(webSearchResolverContext(), nil)
	if e != nil || len(got) != 1 || len(got[0].Tools) != 1 || got[0].Tools[0].Name != "mcp__github__get_file_contents" || !got[0].Snapshot.ReadOnly || got[0].Snapshot.RequiresConfirmation {
		t.Fatalf("%#v %v", got, e)
	}
}

func TestGitHubMCPPreservesModelVisibleEmbeddedResourceContent(t *testing.T) {
	repo := &githubResolverRepo{v: coregithub.ResolvedConfig{Config: coregithub.Config{Enabled: true, Provider: coregithub.ProviderGitHub, GitHubTokenConfigured: true, Revision: 1}, GitHubToken: "secret", CredentialVersion: 1}}
	svc, err := coregithub.NewService(repo, githubResolverIdentity{})
	if err != nil {
		t.Fatalf("new GitHub service: %v", err)
	}
	want := `[MCP embedded text resource uri="repo://owner/repository/contents/main.go"]` + "\npackage main"
	r := &githubMCPConversationResolver{service: svc, factory: func(context.Context, coregithub.ResolvedConfig) (mcphttp.ToolProvider, error) {
		return mcphttp.ToolProviderFunc(func(context.Context) ([]mcphttp.Tool, error) {
			return []mcphttp.Tool{{
				Definition: coremodel.Tool{Name: "mcp__github__get_file_contents", Description: "Read a file.", InputSchema: map[string]any{"type": "object"}},
				Effect:     mcphttp.ToolEffectReadOnly,
				Run: func(context.Context, mcphttp.ToolInvocation) (mcphttp.ToolResult, error) {
					return mcphttp.ToolResult{Content: want}, nil
				},
			}}, nil
		}), nil
	}}
	resolved, err := r.ResolveExtensions(webSearchResolverContext(), nil)
	if err != nil || len(resolved) != 1 {
		t.Fatalf("resolved=%#v err=%v", resolved, err)
	}
	result, err := resolved[0].Execute(webSearchResolverContext(), coreconversation.ToolExecutionRequest{Call: coreconversation.ToolCall{ID: "call-1", Name: "mcp__github__get_file_contents", Arguments: `{}`}})
	if err != nil {
		t.Fatalf("execute GitHub MCP: %v", err)
	}
	if result.Content != want || !strings.Contains(result.Content, "package main") {
		t.Fatalf("embedded resource content was not preserved: %#v", result)
	}
}
