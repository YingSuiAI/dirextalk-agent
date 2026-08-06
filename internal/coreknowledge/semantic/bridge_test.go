package semantic

import (
	"context"
	"errors"
	"strings"
	"testing"

	coreknowledge "github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

type bridgeProfileResolver struct {
	profile coremodel.Profile
	err     error
}

func (r bridgeProfileResolver) ResolveProfile(context.Context, string) (coremodel.Profile, error) {
	return r.profile, r.err
}

type bridgeBindingResolver struct {
	bindings []Binding
	err      error
}

func (r bridgeBindingResolver) ResolveBindings(context.Context, []string) ([]Binding, error) {
	return r.bindings, r.err
}

type bridgeEmbedder struct {
	vectors  [][]float32
	err      error
	calls    int
	profiles []string
}

func (e *bridgeEmbedder) Embed(_ context.Context, profile coremodel.Profile, _ []string) ([][]float32, error) {
	e.calls++
	e.profiles = append(e.profiles, profile.ID)
	return e.vectors, e.err
}

type bridgeConfigReader struct{ config coreknowledge.EmbeddingConfig }

func (r bridgeConfigReader) GetEmbeddingConfig(context.Context) (coreknowledge.EmbeddingConfig, error) {
	return r.config, nil
}

type bridgeRequestedProfileResolver struct{}

func (bridgeRequestedProfileResolver) ResolveProfile(_ context.Context, id string) (coremodel.Profile, error) {
	return coremodel.Profile{ID: id, Provider: coremodel.ProviderOpenAICompatible, Model: "m", APIKey: "k"}, nil
}

type bridgeVectorStore struct {
	matches []Match
	err     error
	upserts int
}

func (s *bridgeVectorStore) EnsureCollection(context.Context) error            { return nil }
func (s *bridgeVectorStore) DeleteSource(context.Context, string, int64) error { return nil }
func (s *bridgeVectorStore) Search(context.Context, []float32, []Binding, int) ([]Match, error) {
	return s.matches, s.err
}
func (s *bridgeVectorStore) Upsert(context.Context, string, int64, []Chunk) error {
	s.upserts++
	return nil
}

func TestSearchRejectsCrossSourceVectorResponse(t *testing.T) {
	e := &bridgeEmbedder{vectors: [][]float32{{1, 0}}}
	s := &bridgeVectorStore{matches: []Match{{SourceID: "other", Revision: 1, ChunkRef: "chunk-000000", Digest: strings.Repeat("a", 64), Snippet: "x", Score: .5, PointID: PointID("other", 1, "chunk-000000")}}}
	r, err := NewSearchResolver(SearchConfig{Embedder: e, VectorStore: s, BindingResolver: bridgeBindingResolver{bindings: []Binding{{SourceID: "source", Revision: 1}}}, ProfileResolver: bridgeProfileResolver{profile: coremodel.Profile{Provider: coremodel.ProviderOpenAICompatible, Model: "m", APIKey: "k"}}, EmbeddingProfileID: "p", Dimension: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Search(context.Background(), coreknowledge.SearchQuery{Query: "q"}); !errors.Is(err, ErrResponse) {
		t.Fatalf("err=%v", err)
	}
}

func TestSearchAcceptsMultilineKnowledgeSnippet(t *testing.T) {
	e := &bridgeEmbedder{vectors: [][]float32{{1, 0}}}
	binding := Binding{SourceID: "source", Revision: 1}
	s := &bridgeVectorStore{matches: []Match{{SourceID: binding.SourceID, Revision: binding.Revision, ChunkRef: "chunk-000000", Digest: strings.Repeat("a", 64), Snippet: "line one\nline two", Score: .5, PointID: PointID(binding.SourceID, binding.Revision, "chunk-000000")}}}
	r, err := NewSearchResolver(SearchConfig{Embedder: e, VectorStore: s, BindingResolver: bridgeBindingResolver{bindings: []Binding{binding}}, ProfileResolver: bridgeProfileResolver{profile: coremodel.Profile{Provider: coremodel.ProviderOpenAICompatible, Model: "m", APIKey: "k"}}, EmbeddingProfileID: "p", Dimension: 2})
	if err != nil {
		t.Fatal(err)
	}
	page, err := r.Search(context.Background(), coreknowledge.SearchQuery{Query: "q"})
	if err != nil || len(page.Matches) != 1 || page.Matches[0].Snippet != "line one\nline two" {
		t.Fatalf("page=%#v err=%v", page, err)
	}
}

func TestSearchReturnsPinnedEmbeddingProvenance(t *testing.T) {
	e := &bridgeEmbedder{vectors: [][]float32{{1, 0}}}
	binding := Binding{SourceID: "source", Revision: 1, Generation: "generation-1", EmbeddingProfileID: "profile", EmbeddingProfileRevision: 4, CollectionConfigDigest: strings.Repeat("a", 64)}
	s := &bridgeVectorStore{matches: []Match{{SourceID: binding.SourceID, Revision: binding.Revision, Generation: binding.Generation, ChunkRef: "chunk-000000", Digest: strings.Repeat("a", 64), Snippet: "x", Score: .5, PointID: GenerationPointID(binding.Generation, binding.SourceID, binding.Revision, "chunk-000000")}}}
	r, err := NewSearchResolver(SearchConfig{Embedder: e, VectorStore: s, BindingResolver: bridgeBindingResolver{bindings: []Binding{binding}}, ProfileResolver: bridgeProfileResolver{profile: coremodel.Profile{Revision: 4, Provider: coremodel.ProviderOpenAICompatible, Model: "embedding-model", APIKey: "k"}}, EmbeddingProfileID: binding.EmbeddingProfileID, CollectionConfigDigest: binding.CollectionConfigDigest, Dimension: 2})
	if err != nil {
		t.Fatal(err)
	}
	page, err := r.Search(context.Background(), coreknowledge.SearchQuery{Query: "q"})
	if err != nil {
		t.Fatal(err)
	}
	if page.EmbeddingProfileID != binding.EmbeddingProfileID || page.EmbeddingProfileRevision != 4 || page.EmbeddingModel != "embedding-model" || page.EmbeddingGeneration != binding.Generation || page.CollectionConfigDigest != binding.CollectionConfigDigest {
		t.Fatalf("provenance=%+v", page.SearchProvenance)
	}
}

func TestSearchRejectsAnthropicAndProviderErrors(t *testing.T) {
	e := &bridgeEmbedder{vectors: [][]float32{{1, 0}}, err: ErrProvider}
	r, err := NewSearchResolver(SearchConfig{Embedder: e, VectorStore: &bridgeVectorStore{}, BindingResolver: bridgeBindingResolver{bindings: []Binding{{SourceID: "source", Revision: 1}}}, ProfileResolver: bridgeProfileResolver{profile: coremodel.Profile{Provider: coremodel.ProviderAnthropic, Model: "m", APIKey: "k"}}, EmbeddingProfileID: "p", Dimension: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Search(context.Background(), coreknowledge.SearchQuery{Query: "q"}); !errors.Is(err, ErrProvider) {
		t.Fatalf("err=%v", err)
	}
}

func TestIndexEngineDeterministicReplayAndDimension(t *testing.T) {
	e := &bridgeEmbedder{vectors: [][]float32{{1, 0}}}
	s := &bridgeVectorStore{}
	r, err := NewIndexEngine(IndexConfig{Embedder: e, VectorStore: s, ProfileResolver: bridgeProfileResolver{profile: coremodel.Profile{Provider: coremodel.ProviderOpenAICompatible, Model: "m", APIKey: "k"}}, EmbeddingProfileID: "p", Dimension: 2, BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	doc := SourceDocument{ID: "source", Revision: 1, MediaType: "text/plain", Reader: strings.NewReader("hello"), MaxBytes: 100}
	if err := r.Index(context.Background(), doc); err != nil {
		t.Fatal(err)
	}
	if s.upserts != 1 {
		t.Fatalf("upserts=%d", s.upserts)
	}
}

func TestIndexEngineDocumentBindingOverridesRotatedConfig(t *testing.T) {
	embedder := &bridgeEmbedder{vectors: [][]float32{{1, 0}}}
	store := &bridgeVectorStore{}
	engine, err := NewIndexEngine(IndexConfig{
		Embedder: embedder, VectorStore: store, ProfileResolver: bridgeRequestedProfileResolver{},
		EmbeddingProfileID: "fallback-profile", Dimension: 3,
		ConfigReader: bridgeConfigReader{config: coreknowledge.EmbeddingConfig{EmbeddingProfileID: "rotated-profile", Dimension: 3}},
	})
	if err != nil {
		t.Fatal(err)
	}
	document := SourceDocument{
		ID: "source", Revision: 1, MediaType: "text/plain", Reader: strings.NewReader("pinned"), MaxBytes: 100,
		EmbeddingProfileID: "queued-profile", EmbeddingDimension: 2,
	}
	if err = engine.Index(context.Background(), document); err != nil {
		t.Fatal(err)
	}
	if len(embedder.profiles) != 1 || embedder.profiles[0] != "queued-profile" {
		t.Fatalf("embedded profiles=%v, want queued-profile", embedder.profiles)
	}
}
