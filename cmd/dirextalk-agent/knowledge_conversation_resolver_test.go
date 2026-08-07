package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

type conversationKnowledgeSearch struct {
	page  coreknowledge.SearchPage
	err   error
	query coreknowledge.SearchQuery
	calls int
}

type knowledgeBaseResolver func(context.Context, []coreconversation.ExtensionSelection) ([]coreconversation.ResolvedExtension, error)

func (f knowledgeBaseResolver) ResolveExtensions(ctx context.Context, selections []coreconversation.ExtensionSelection) ([]coreconversation.ResolvedExtension, error) {
	return f(ctx, selections)
}

func (s *conversationKnowledgeSearch) Search(_ context.Context, query coreknowledge.SearchQuery) (coreknowledge.SearchPage, error) {
	s.calls++
	s.query = query
	return s.page, s.err
}

func knowledgeResolverContext(owner string, generation int64) context.Context {
	return capabilityclient.WithCallContext(context.Background(), &capv1.CallContext{ChainId: "00000000-0000-4000-8000-000000000001", RootOperationId: "00000000-0000-4000-8000-000000000002"}, &capv1.PermissionContext{AuthenticatedOwnerId: owner, AccountGeneration: generation})
}

func TestKnowledgeConversationResolverPublishesAndExecutesBoundedReadOnlyTool(t *testing.T) {
	sourceID := "11111111-1111-4111-8111-111111111111"
	search := &conversationKnowledgeSearch{page: coreknowledge.SearchPage{
		Matches:          []coreknowledge.SearchMatch{{SourceID: sourceID, ChunkRef: "chunk-1", Snippet: strings.Repeat("界", coreknowledge.MaxSnippetBytes), Score: 0.9}},
		SearchProvenance: coreknowledge.SearchProvenance{EmbeddingProfileID: "22222222-2222-4222-8222-222222222222", EmbeddingProfileRevision: 7, EmbeddingModel: "embed-v1", EmbeddingGeneration: "generation-1", CollectionConfigDigest: strings.Repeat("a", 64)},
	}}
	resolver := &knowledgeConversationResolver{search: search}
	resolved, err := resolver.ResolveExtensions(knowledgeResolverContext("owner", 3), nil)
	if err != nil || len(resolved) != 1 || len(resolved[0].Tools) != 1 || resolved[0].Tools[0].Name != knowledgeConversationToolName {
		t.Fatalf("resolved=%#v err=%v", resolved, err)
	}
	if err := resolved[0].Snapshot.Validate(); err != nil || !resolved[0].Snapshot.ReadOnly || resolved[0].Snapshot.Source != knowledgeConversationToolSource {
		t.Fatalf("snapshot=%#v err=%v", resolved[0].Snapshot, err)
	}
	result, err := resolved[0].Execute(knowledgeResolverContext("owner", 3), coreconversation.ToolExecutionRequest{Call: coreconversation.ToolCall{ID: "call-1", Name: knowledgeConversationToolName, Arguments: `{"query":" release notes ","source_ids":["` + sourceID + `"],"limit":4}`}})
	if err != nil {
		t.Fatal(err)
	}
	if search.calls != 1 || search.query.Query != "release notes" || search.query.Limit != 4 || len(search.query.SourceIDs) != 1 || search.query.SourceIDs[0] != sourceID {
		t.Fatalf("calls=%d query=%+v", search.calls, search.query)
	}
	var body struct {
		Items                    []coreknowledge.SearchMatch `json:"items"`
		SearchMode               string                      `json:"search_mode"`
		EmbeddingProfileRevision int64                       `json:"embedding_profile_revision"`
	}
	if err := json.Unmarshal([]byte(result.Content), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Items) != 1 || len(body.Items[0].Snippet) > coreknowledge.MaxSnippetBytes || !json.Valid([]byte(result.Content)) || body.SearchMode != "semantic" || body.EmbeddingProfileRevision != 7 {
		t.Fatalf("result=%s", result.Content)
	}
	first := resolved[0].Snapshot
	again, err := resolver.ResolveExtensions(knowledgeResolverContext("owner", 3), nil)
	if err != nil || len(again) != 1 || again[0].Snapshot.ContentDigest != first.ContentDigest || again[0].Snapshot.ArtifactDigest != first.ArtifactDigest || again[0].Snapshot.ToolSchemaDigest != first.ToolSchemaDigest {
		t.Fatalf("unstable snapshot first=%#v again=%#v err=%v", first, again, err)
	}
}

func TestKnowledgeConversationResolverFencesPermissionAndToolConflicts(t *testing.T) {
	search := &conversationKnowledgeSearch{}
	resolver := &knowledgeConversationResolver{search: search}
	for name, ctx := range map[string]context.Context{
		"missing":     context.Background(),
		"empty_owner": knowledgeResolverContext("", 1),
		"generation":  knowledgeResolverContext("owner", 0),
	} {
		t.Run(name, func(t *testing.T) {
			resolved, err := resolver.ResolveExtensions(ctx, nil)
			if err != nil || len(resolved) != 0 {
				t.Fatalf("resolved=%#v err=%v", resolved, err)
			}
		})
	}
	resolved, err := resolver.ResolveExtensions(knowledgeResolverContext("owner", 1), nil)
	if err != nil || len(resolved) != 1 {
		t.Fatalf("resolved=%#v err=%v", resolved, err)
	}
	_, err = resolved[0].Execute(knowledgeResolverContext("replacement", 1), coreconversation.ToolExecutionRequest{Call: coreconversation.ToolCall{Name: knowledgeConversationToolName, Arguments: `{"query":"x"}`}})
	if !errors.Is(err, coreknowledge.ErrInvalid) || search.calls != 0 {
		t.Fatalf("owner fence err=%v calls=%d", err, search.calls)
	}
	base := knowledgeBaseResolver(func(context.Context, []coreconversation.ExtensionSelection) ([]coreconversation.ResolvedExtension, error) {
		selection := coreconversation.ExtensionSelection{Kind: coreconversation.ExtensionMCP, ID: "11111111-1111-4111-8111-111111111111", Version: "1", Digest: strings.Repeat("a", 64), AllowedTools: []string{knowledgeConversationToolName}}
		return []coreconversation.ResolvedExtension{{Selection: selection}}, nil
	})
	_, err = (&knowledgeConversationResolver{base: base, search: search}).ResolveExtensions(knowledgeResolverContext("owner", 1), nil)
	if !errors.Is(err, coreconversation.ErrConflict) {
		t.Fatalf("duplicate tool err=%v", err)
	}
}

func TestKnowledgeConversationResolverRejectsInvalidArgumentsBeforeSearch(t *testing.T) {
	search := &conversationKnowledgeSearch{}
	resolved, err := (&knowledgeConversationResolver{search: search}).ResolveExtensions(knowledgeResolverContext("owner", 1), nil)
	if err != nil || len(resolved) != 1 {
		t.Fatalf("resolved=%#v err=%v", resolved, err)
	}
	tests := map[string]string{
		"malformed":        `{"query":`,
		"unknown":          `{"query":"x","cursor":"secret"}`,
		"multiple_values":  `{"query":"x"}{"query":"y"}`,
		"empty":            `{"query":" "}`,
		"oversized":        `{"query":"` + strings.Repeat("x", knowledgeConversationMaxQueryBytes+1) + `"}`,
		"limit":            `{"query":"x","limit":11}`,
		"source":           `{"query":"x","source_ids":["not-a-uuid"]}`,
		"duplicate_source": `{"query":"x","source_ids":["11111111-1111-4111-8111-111111111111","11111111-1111-4111-8111-111111111111"]}`,
	}
	for name, arguments := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := resolved[0].Execute(knowledgeResolverContext("owner", 1), coreconversation.ToolExecutionRequest{Call: coreconversation.ToolCall{Name: knowledgeConversationToolName, Arguments: arguments}})
			if !errors.Is(err, coreknowledge.ErrInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	if search.calls != 0 {
		t.Fatalf("search calls=%d", search.calls)
	}
}

func TestKnowledgeConversationResolverRedactsSearchErrors(t *testing.T) {
	search := &conversationKnowledgeSearch{err: errors.New("postgres password=secret")}
	resolved, err := (&knowledgeConversationResolver{search: search}).ResolveExtensions(knowledgeResolverContext("owner", 1), nil)
	if err != nil || len(resolved) != 1 {
		t.Fatalf("resolved=%#v err=%v", resolved, err)
	}
	_, err = resolved[0].Execute(knowledgeResolverContext("owner", 1), coreconversation.ToolExecutionRequest{Call: coreconversation.ToolCall{Name: knowledgeConversationToolName, Arguments: `{"query":"x"}`}})
	if !errors.Is(err, coreknowledge.ErrConflict) || strings.Contains(err.Error(), "password") {
		t.Fatalf("unredacted err=%v", err)
	}
}
