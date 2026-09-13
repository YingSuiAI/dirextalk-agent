package main

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coregithub"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/mcphttp"
)

type githubResolverRepo struct{ v coregithub.ResolvedConfig }

func (r *githubResolverRepo) Get(context.Context, coregithub.Scope) (coregithub.Config, error) {
	return r.v.Config, nil
}
func (r *githubResolverRepo) Resolve(_ context.Context, scope coregithub.Scope) (coregithub.ResolvedConfig, error) {
	v := r.v
	v.OwnerID = scope.OwnerID
	v.AccountGeneration = scope.AccountGeneration
	v.RoomID = scope.RoomID
	return v, nil
}
func (r *githubResolverRepo) ResolveForDispatch(c context.Context, scope coregithub.Scope, _ coregithub.ResolvedConfig) (coregithub.ResolvedConfig, func() error, error) {
	v, e := r.Resolve(c, scope)
	return v, func() error { return nil }, e
}
func (r *githubResolverRepo) Update(context.Context, coregithub.Mutation, func(string) error) (coregithub.Config, error) {
	return r.v.Config, nil
}
func (r *githubResolverRepo) MarkTested(context.Context, coregithub.Scope, int64, time.Time) (coregithub.Config, error) {
	return r.v.Config, nil
}

type githubResolverIdentity struct{}

func (githubResolverIdentity) Identity(context.Context, string) error { return nil }
func githubTool(name string, e mcphttp.ToolEffect) mcphttp.Tool {
	return mcphttp.Tool{Definition: coremodel.Tool{Name: name, Description: "x", InputSchema: map[string]any{"type": "object"}}, Effect: e, Run: func(context.Context, mcphttp.ToolInvocation) (mcphttp.ToolResult, error) {
		return mcphttp.ToolResult{Content: "ok"}, nil
	}}
}

func testedGitHubResolverConfig(enabled, configured bool) coregithub.ResolvedConfig {
	testedAt := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)
	value := coregithub.ResolvedConfig{Config: coregithub.Config{Enabled: enabled, Provider: coregithub.ProviderGitHub, GitHubTokenConfigured: configured, Revision: 1, TestedAt: &testedAt}, CredentialVersion: 1}
	if configured {
		value.GitHubToken = "secret"
	}
	return value
}

func TestGitHubMCPAdmitsReadsAndLightweightMutationsOnly(t *testing.T) {
	repo := &githubResolverRepo{v: testedGitHubResolverConfig(true, true)}
	svc, _ := coregithub.NewService(repo, githubResolverIdentity{})
	r := &githubMCPConversationResolver{service: svc, factory: func(_ context.Context, snapshot coregithub.ResolvedConfig) (mcphttp.ToolProvider, error) {
		if snapshot.GitHubToken != "" {
			t.Fatal("PAT entered the catalog snapshot")
		}
		return mcphttp.ToolProviderFunc(func(context.Context) ([]mcphttp.Tool, error) {
			read := githubTool("mcp__github__get_file_contents", mcphttp.ToolEffectUnsafeMutation)
			read.AdvertisedReadOnly = true
			unselectedRead := githubTool("mcp__github__get_discussion", mcphttp.ToolEffectUnsafeMutation)
			unselectedRead.AdvertisedReadOnly = true
			return []mcphttp.Tool{
				githubTool("mcp__github__push_files", mcphttp.ToolEffectUnsafeMutation),
				githubTool("mcp__github__merge_pull_request", mcphttp.ToolEffectUnsafeMutation),
				githubTool("mcp__github__issue_write", mcphttp.ToolEffectUnsafeMutation),
				githubTool("mcp__github__create_pull_request", mcphttp.ToolEffectUnsafeMutation),
				githubTool("mcp__github__create_branch", mcphttp.ToolEffectUnsafeMutation),
				githubTool("mcp__github__add_issue_comment", mcphttp.ToolEffectUnsafeMutation),
				read,
				unselectedRead,
			}, nil
		}), nil
	}}
	got, e := r.ResolveExtensions(webSearchResolverContext(), nil)
	wantNames := []string{"mcp__github__add_issue_comment", "mcp__github__get_file_contents", "mcp__github__issue_write", "mcp__github__merge_pull_request"}
	if e != nil || len(got) != 1 || len(got[0].Tools) != len(wantNames) || strings.Join(got[0].Snapshot.ToolNames, ",") != strings.Join(wantNames, ",") ||
		!got[0].Snapshot.ReadOnly || got[0].Snapshot.RequiresConfirmation {
		t.Fatalf("%#v %v", got, e)
	}
	read, err := got[0].Execute(webSearchResolverContext(), coreconversation.ToolExecutionRequest{Call: coreconversation.ToolCall{ID: "read", Name: "mcp__github__get_file_contents", Arguments: `{}`}})
	if err != nil || read.MutationState != coreconversation.ToolMutationNone || read.StateChanged {
		t.Fatalf("read=%+v err=%v", read, err)
	}
	write, err := got[0].Execute(webSearchResolverContext(), coreconversation.ToolExecutionRequest{Call: coreconversation.ToolCall{ID: "write", Name: "mcp__github__issue_write", Arguments: `{}`}})
	if err != nil || write.MutationState != coreconversation.ToolMutationChanged || !write.StateChanged {
		t.Fatalf("write=%+v err=%v", write, err)
	}
}

// TestGitHubMCPGroupTurnKeepsReadsAndDropsWrites pins the group GitHub
// boundary: a group turn keeps every read of the same catalog the personal
// Agent has, and drops every tool that could write, comment or merge with the
// owner's group credential. Those stay on the owner's private confirmation
// path, so one member cannot mutate the owner's repositories.
func TestGitHubMCPGroupTurnKeepsReadsAndDropsWrites(t *testing.T) {
	advertisedRead := githubTool("mcp__github__get_file_contents", mcphttp.ToolEffectUnsafeMutation)
	advertisedRead.AdvertisedReadOnly = true
	strictRead := githubTool("mcp__github__search_code", mcphttp.ToolEffectReadOnly)
	catalog := []mcphttp.Tool{
		advertisedRead,
		strictRead,
		githubTool("mcp__github__get_me", mcphttp.ToolEffectUnsafeMutation),
		githubTool("mcp__github__merge_pull_request", mcphttp.ToolEffectUnsafeMutation),
		githubTool("mcp__github__issue_write", mcphttp.ToolEffectUnsafeMutation),
		githubTool("mcp__github__add_issue_comment", mcphttp.ToolEffectUnsafeMutation),
		githubTool("mcp__github__push_files", mcphttp.ToolEffectUnsafeMutation),
		githubTool("mcp__github__create_pull_request", mcphttp.ToolEffectUnsafeMutation),
	}
	groupTools, ok := selectGitHubMCPTools(catalog, true)
	if !ok {
		t.Fatal("group catalog was rejected")
	}
	var groupNames []string
	for _, tool := range groupTools {
		groupNames = append(groupNames, tool.Definition.Name)
		if !githubMCPToolReadOnly(tool) {
			t.Fatalf("group turn was handed a writing tool: %s", tool.Definition.Name)
		}
	}
	sort.Strings(groupNames)
	if strings.Join(groupNames, ",") != "mcp__github__get_file_contents,mcp__github__search_code" {
		t.Fatalf("group read set changed: %v", groupNames)
	}
	// The owner's own turn keeps the lightweight mutations, so this boundary is
	// about who triggered the turn, not about losing the personal capability.
	personalTools, ok := selectGitHubMCPTools(catalog, false)
	if !ok {
		t.Fatal("personal catalog was rejected")
	}
	var personalNames []string
	for _, tool := range personalTools {
		personalNames = append(personalNames, tool.Definition.Name)
	}
	sort.Strings(personalNames)
	if strings.Join(personalNames, ",") != "mcp__github__add_issue_comment,mcp__github__get_file_contents,mcp__github__issue_write,mcp__github__merge_pull_request,mcp__github__search_code" {
		t.Fatalf("personal tool set changed: %v", personalNames)
	}
}

func TestGitHubMCPRequiresEnabledCredentialAndPreservesHistoricalConfig(t *testing.T) {
	for _, test := range []struct {
		name       string
		value      coregithub.ResolvedConfig
		wantTools  int
		wantCalled bool
	}{
		{name: "disabled", value: testedGitHubResolverConfig(false, true)},
		{name: "tokenless", value: testedGitHubResolverConfig(true, false)},
		{name: "historical configured row without tested timestamp", value: func() coregithub.ResolvedConfig {
			value := testedGitHubResolverConfig(true, true)
			value.TestedAt = nil
			return value
		}(), wantTools: 1, wantCalled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := &githubResolverRepo{v: test.value}
			svc, _ := coregithub.NewService(repo, githubResolverIdentity{})
			called := false
			resolver := &githubMCPConversationResolver{service: svc, factory: func(context.Context, coregithub.ResolvedConfig) (mcphttp.ToolProvider, error) {
				called = true
				return mcphttp.ToolProviderFunc(func(context.Context) ([]mcphttp.Tool, error) {
					return []mcphttp.Tool{githubTool("mcp__github__get_me", mcphttp.ToolEffectReadOnly)}, nil
				}), nil
			}}
			got, err := resolver.ResolveExtensions(webSearchResolverContext(), nil)
			if err != nil || len(got) != test.wantTools || called != test.wantCalled {
				t.Fatalf("resolved=%+v called=%v err=%v", got, called, err)
			}
		})
	}
}

func TestGitHubMCPUsesOfficialCuratedToolsEndpoint(t *testing.T) {
	config := githubMCPServerConfig()
	if config.Endpoint != "https://api.githubcopilot.com/mcp/" || config.ID != "github" || config.SecretRef != githubMCPSecretRef ||
		config.Headers["X-MCP-Tools"] != strings.Join(githubMCPDirectTools, ",") || len(config.Headers) != 1 {
		t.Fatalf("config=%+v", config)
	}
	for _, denied := range []string{"mcp__github__create_branch", "mcp__github__create_pull_request", "mcp__github__push_files"} {
		if githubMCPDirectTool(denied) {
			t.Fatalf("code mutation %q entered the direct GitHub tool set", denied)
		}
	}
}

func TestGitHubMCPAmbiguousMutationFailureIsNotReportedAsARead(t *testing.T) {
	repo := &githubResolverRepo{v: testedGitHubResolverConfig(true, true)}
	svc, _ := coregithub.NewService(repo, githubResolverIdentity{})
	resolver := &githubMCPConversationResolver{service: svc, factory: func(context.Context, coregithub.ResolvedConfig) (mcphttp.ToolProvider, error) {
		return mcphttp.ToolProviderFunc(func(context.Context) ([]mcphttp.Tool, error) {
			tool := githubTool("mcp__github__issue_write", mcphttp.ToolEffectUnsafeMutation)
			tool.Run = func(context.Context, mcphttp.ToolInvocation) (mcphttp.ToolResult, error) {
				return mcphttp.ToolResult{}, mcphttp.ErrProviderUnavailable
			}
			return []mcphttp.Tool{tool}, nil
		}), nil
	}}
	resolved, err := resolver.ResolveExtensions(webSearchResolverContext(), nil)
	if err != nil || len(resolved) != 1 {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	result, err := resolved[0].Execute(webSearchResolverContext(), coreconversation.ToolExecutionRequest{Call: coreconversation.ToolCall{ID: "write", Name: "mcp__github__issue_write", Arguments: `{}`}})
	if err != nil || result.Outcome != coreconversation.ToolOutcomeUnknownMutation || result.MutationState != coreconversation.ToolMutationUnknown || !result.IsError {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestGitHubMCPPreservesModelVisibleEmbeddedResourceContent(t *testing.T) {
	repo := &githubResolverRepo{v: testedGitHubResolverConfig(true, true)}
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
