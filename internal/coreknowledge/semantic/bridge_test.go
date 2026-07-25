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
	vectors [][]float32
	err     error
	calls   int
}

func (e *bridgeEmbedder) Embed(context.Context, coremodel.Profile, []string) ([][]float32, error) {
	e.calls++
	return e.vectors, e.err
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
