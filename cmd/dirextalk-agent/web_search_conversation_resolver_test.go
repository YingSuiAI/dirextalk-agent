package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/corewebsearch"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

type resolverWebSearchRepository struct {
	resolved corewebsearch.ResolvedConfig
}

func (r *resolverWebSearchRepository) Get(context.Context, string, int64) (corewebsearch.Config, error) {
	return r.resolved.Config, nil
}
func (r *resolverWebSearchRepository) Resolve(_ context.Context, owner string, generation int64) (corewebsearch.ResolvedConfig, error) {
	r.resolved.OwnerID = owner
	r.resolved.AccountGeneration = generation
	return r.resolved, nil
}
func (r *resolverWebSearchRepository) ResolveForDispatch(ctx context.Context, owner string, generation int64, _ corewebsearch.ResolvedConfig) (corewebsearch.ResolvedConfig, func() error, error) {
	value, err := r.Resolve(ctx, owner, generation)
	return value, func() error { return nil }, err
}
func (r *resolverWebSearchRepository) Update(context.Context, corewebsearch.Mutation) (corewebsearch.Config, error) {
	return r.resolved.Config, nil
}
func (r *resolverWebSearchRepository) MarkTested(context.Context, string, int64, int64, time.Time) (corewebsearch.Config, error) {
	return r.resolved.Config, nil
}

type resolverWebSearcher struct {
	key   string
	calls int
}

func (s *resolverWebSearcher) Search(_ context.Context, key, query string, maxResults int) (corewebsearch.SearchResult, error) {
	s.key = key
	s.calls++
	return corewebsearch.SearchResult{Provider: corewebsearch.ProviderTavily, Query: query, Results: []corewebsearch.SearchItem{{Title: "Dirextalk", URL: "https://example.test", Content: "result", Score: 1}}}, nil
}

type racingWebSearchRepository struct {
	current      corewebsearch.ResolvedConfig
	resolveCall  int
	beforeSecond func(*corewebsearch.ResolvedConfig)
}

func (r *racingWebSearchRepository) Get(context.Context, string, int64) (corewebsearch.Config, error) {
	return r.current.Config, nil
}
func (r *racingWebSearchRepository) Resolve(_ context.Context, owner string, generation int64) (corewebsearch.ResolvedConfig, error) {
	r.resolveCall++
	if r.resolveCall == 2 && r.beforeSecond != nil {
		r.beforeSecond(&r.current)
	}
	value := r.current
	value.OwnerID = owner
	value.AccountGeneration = generation
	return value, nil
}
func (r *racingWebSearchRepository) ResolveForDispatch(ctx context.Context, owner string, generation int64, _ corewebsearch.ResolvedConfig) (corewebsearch.ResolvedConfig, func() error, error) {
	value, err := r.Resolve(ctx, owner, generation)
	return value, func() error { return nil }, err
}
func (r *racingWebSearchRepository) Update(context.Context, corewebsearch.Mutation) (corewebsearch.Config, error) {
	return r.current.Config, nil
}
func (r *racingWebSearchRepository) MarkTested(context.Context, string, int64, int64, time.Time) (corewebsearch.Config, error) {
	return r.current.Config, nil
}

func webSearchResolverContext() context.Context {
	return capabilityclient.WithCallContext(context.Background(), &capv1.CallContext{ChainId: "00000000-0000-4000-8000-000000000001", RootOperationId: "00000000-0000-4000-8000-000000000002"}, &capv1.PermissionContext{AuthenticatedOwnerId: "owner", AccountGeneration: 1})
}

func TestWebSearchConversationResolverInjectsStoredCredentialWithoutPersistingIt(t *testing.T) {
	repository := &resolverWebSearchRepository{resolved: corewebsearch.ResolvedConfig{
		Config: corewebsearch.Config{Enabled: true, Provider: corewebsearch.ProviderTavily, APIKeyConfigured: true, Revision: 7},
		APIKey: "tvly-persisted", CredentialVersion: 3,
	}}
	searcher := &resolverWebSearcher{}
	service, _ := corewebsearch.NewService(repository, searcher)
	resolver := &webSearchConversationResolver{service: service}
	resolved, err := resolver.ResolveExtensions(webSearchResolverContext(), nil)
	if err != nil || len(resolved) != 1 || len(resolved[0].Tools) != 1 || resolved[0].Tools[0].Name != "web_search" {
		t.Fatalf("resolved=%#v err=%v", resolved, err)
	}
	if !strings.Contains(resolved[0].Tools[0].Description, "do not repeat equivalent searches") ||
		!strings.Contains(resolved[0].Tools[0].Description, "concise natural-language Markdown") {
		t.Fatalf("web search completion guidance=%q", resolved[0].Tools[0].Description)
	}
	if err := resolved[0].Snapshot.Validate(); err != nil {
		t.Fatalf("snapshot invalid: %#v err=%v", resolved[0].Snapshot, err)
	}
	snapshotJSON, _ := json.Marshal(resolved[0].Snapshot)
	if strings.Contains(string(snapshotJSON), "tvly-persisted") || strings.Contains(resolved[0].Selection.Digest, "tvly") {
		t.Fatalf("snapshot/selection leaked key: %s %#v", snapshotJSON, resolved[0].Selection)
	}
	result, err := resolved[0].Execute(webSearchResolverContext(), coreconversation.ToolExecutionRequest{Call: coreconversation.ToolCall{ID: "call-1", Name: "web_search", Arguments: `{"query":"latest Dirextalk","max_results":3}`}})
	if err != nil || searcher.key != "tvly-persisted" || strings.Contains(result.Content, "tvly-persisted") {
		t.Fatalf("tool result=%#v key=%q err=%v", result, searcher.key, err)
	}
}

func TestWebSearchModelEvidenceNormalizesScreenshotLikeProviderMarkup(t *testing.T) {
	envelope, accepted := webSearchModelEvidence(corewebsearch.SearchResult{Answer: "<3级\n# 周边地区 北京时 2026-08-19 18:00更新\n/\n/\n|\n| --- | --- |\n", Results: []corewebsearch.SearchItem{{Title: "<b>北京天气</b>", URL: "https://weather.example.test/beijing", Content: "<div>晴</div>\n/\n\n|\n---\n体感良好"}}})
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, forbidden := range []string{"<b>", "<div>", "\n/\n", "| --- |"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("model evidence retained %q: %s", forbidden, text)
		}
	}
	if envelope.Summary != "<3级 周边地区 北京时 2026-08-19 18:00更新" || len(accepted) != 1 || envelope.Sources[0].URL != "https://weather.example.test/beijing" || envelope.Sources[0].Evidence != "晴 体感良好" {
		t.Fatalf("normalized envelope=%+v", envelope)
	}
}

func TestWebSearchModelEvidenceCanonicalizesDeduplicatesAndSkipsInvalidURLs(t *testing.T) {
	envelope, accepted := webSearchModelEvidence(corewebsearch.SearchResult{Results: []corewebsearch.SearchItem{
		{Title: "bad", URL: "ftp://example.test/a", Content: "bad"}, {Title: "credentials", URL: "https://user:pass@example.test/a", Content: "bad"},
		{Title: "first", URL: "HTTPS://Example.TEST/a#fragment", Content: "line&#10;one"}, {Title: "duplicate", URL: "https://example.test/a", Content: "two"},
	}})
	if len(envelope.Sources) != 1 || len(accepted) != 1 || accepted[0].URL != envelope.Sources[0].URL || accepted[0].Content != "line one" {
		t.Fatalf("envelope=%+v accepted=%+v", envelope, accepted)
	}
	references := webSearchEvidenceReferences(accepted)
	if len(references) != 1 || references[0].SourceID != envelope.Sources[0].URL || references[0].ContentDigest == "" ||
		references[0].Title != "first" || references[0].Preview != "" {
		t.Fatalf("references=%+v", references)
	}
}

func TestWebSearchPublicReferencesDoNotDuplicateFetchedPageContent(t *testing.T) {
	const rawPage = "北京天气预报,北京7天天气预报 热门城市 周边地区"
	references := webSearchEvidenceReferences([]corewebsearch.SearchItem{{
		Title: "北京天气", URL: "https://weather.example.test/beijing", Content: rawPage,
	}})
	if len(references) != 1 || references[0].Title != "北京天气" || references[0].Preview != "" ||
		references[0].SourceID == rawPage {
		t.Fatalf("public references retained fetched page content: %+v", references)
	}
}

func TestWebSearchToolGuidanceForbidsRawEvidenceDump(t *testing.T) {
	for _, required := range []string{"concise natural-language Markdown", "descriptive linked citations", "Never dump raw tool JSON", "meaningless separator"} {
		if !strings.Contains(webSearchToolDescription, required) {
			t.Fatalf("missing guidance %q", required)
		}
	}
}

func TestNormalizeWebSearchTextUnescapesEntitiesDropsControlsAndKeepsUTF8Boundary(t *testing.T) {
	got := normalizeWebSearchText("# &#x5317;&#x4EAC;\x00\n<strong>晴</strong>", 10)
	if got != "北京 晴" || !utf8.ValidString(got) {
		t.Fatalf("normalized=%q", got)
	}
	bounded := normalizeWebSearchText("天气🙂天气", 8)
	if !utf8.ValidString(bounded) || bounded != "天气" {
		t.Fatalf("utf8 boundary=%q", bounded)
	}
}

func TestWebSearchConversationResolverReloadsAfterServiceRestartAndFingerprintIsSecretFree(t *testing.T) {
	repository := &resolverWebSearchRepository{resolved: corewebsearch.ResolvedConfig{
		Config: corewebsearch.Config{Enabled: true, Provider: corewebsearch.ProviderTavily, APIKeyConfigured: true, Revision: 4},
		APIKey: "tvly-first", CredentialVersion: 1,
	}}
	firstService, _ := corewebsearch.NewService(repository, &resolverWebSearcher{})
	first, err := (&webSearchConversationResolver{service: firstService}).ResolveExtensions(webSearchResolverContext(), nil)
	if err != nil || len(first) != 1 {
		t.Fatalf("first resolve=%#v err=%v", first, err)
	}
	firstDigest := first[0].Selection.Digest
	legacySchema := sha256.Sum256([]byte(webSearchToolSchema))
	legacyPayload, _ := json.Marshal(map[string]any{"provider": corewebsearch.ProviderTavily, "revision": int64(4), "tool_schema_digest": hex.EncodeToString(legacySchema[:])})
	legacySum := sha256.Sum256(legacyPayload)
	legacyArtifact := sha256.Sum256([]byte("dirextalk-agent:builtin:web_search:tavily:v1"))
	if firstDigest == hex.EncodeToString(legacySum[:]) || first[0].Snapshot.ArtifactDigest == hex.EncodeToString(legacyArtifact[:]) {
		t.Fatal("legacy evidence identity remained executable")
	}
	// A fresh service/resolver reads the same durable repository. The executable
	// closure is rebuilt; no client request credential or in-memory cache is used.
	repository.resolved.APIKey = "tvly-second"
	secondService, _ := corewebsearch.NewService(repository, &resolverWebSearcher{})
	second, err := (&webSearchConversationResolver{service: secondService}).ResolveExtensions(webSearchResolverContext(), nil)
	if err != nil || len(second) != 1 || second[0].Selection.Digest != firstDigest {
		t.Fatalf("restart resolve=%#v err=%v", second, err)
	}
	repository.resolved.Enabled = false
	disabled, err := (&webSearchConversationResolver{service: secondService}).ResolveExtensions(webSearchResolverContext(), nil)
	if err != nil || len(disabled) != 0 {
		t.Fatalf("disabled resolve=%#v err=%v", disabled, err)
	}
	withoutPermission, err := (&webSearchConversationResolver{service: secondService}).ResolveExtensions(context.Background(), nil)
	if err != nil || len(withoutPermission) != 0 {
		t.Fatalf("unauthenticated resolve=%#v err=%v", withoutPermission, err)
	}
}

func TestWebSearchConversationResolverRejectsResolveToDispatchRacesBeforeProviderCall(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*corewebsearch.ResolvedConfig)
	}{
		{name: "rotation", mutate: func(value *corewebsearch.ResolvedConfig) {
			value.APIKey = "tvly-rotated"
			value.CredentialVersion++
			value.Revision++
		}},
		{name: "clear", mutate: func(value *corewebsearch.ResolvedConfig) {
			value.APIKey = ""
			value.APIKeyConfigured = false
			value.CredentialVersion++
			value.Revision++
		}},
		{name: "disable", mutate: func(value *corewebsearch.ResolvedConfig) {
			value.Enabled = false
			value.Revision++
		}},
		{name: "deprovision", mutate: func(value *corewebsearch.ResolvedConfig) {
			value.Config = corewebsearch.DefaultConfig()
			value.APIKey = ""
			value.CredentialVersion = 0
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &racingWebSearchRepository{current: corewebsearch.ResolvedConfig{
				Config: corewebsearch.Config{Enabled: true, Provider: corewebsearch.ProviderTavily, APIKeyConfigured: true, Revision: 7},
				APIKey: "tvly-initial", CredentialVersion: 3,
			}}
			searcher := &resolverWebSearcher{}
			service, err := corewebsearch.NewService(repository, searcher)
			if err != nil {
				t.Fatal(err)
			}
			resolved, err := (&webSearchConversationResolver{service: service}).ResolveExtensions(webSearchResolverContext(), nil)
			if err != nil || len(resolved) != 1 {
				t.Fatalf("resolve=%#v err=%v", resolved, err)
			}
			repository.beforeSecond = test.mutate
			_, err = resolved[0].Execute(webSearchResolverContext(), coreconversation.ToolExecutionRequest{Call: coreconversation.ToolCall{ID: "race-1", Name: "web_search", Arguments: `{"query":"race"}`}})
			if err == nil {
				t.Fatal("resolve-to-dispatch race unexpectedly dispatched")
			}
			if searcher.calls != 0 {
				t.Fatalf("provider calls=%d, want zero (err=%v)", searcher.calls, err)
			}
		})
	}
}
