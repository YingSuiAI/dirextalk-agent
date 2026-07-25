package semantic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

func profile(provider coremodel.ModelProvider, base, key string) coremodel.Profile {
	return coremodel.Profile{Provider: provider, BaseURL: base, Model: "text-embedding-test", APIKey: key}
}

func TestOpenAIEmbedderPayloadHeadersAndOrdering(t *testing.T) {
	var gotHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/embeddings" || r.Method != http.MethodPost {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		gotHeader = r.Header.Get("Authorization")
		if r.Header.Get("x-goog-api-key") != "" {
			t.Error("OpenAI request leaked Gemini header")
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["model"] != "text-embedding-test" {
			t.Fatalf("payload model = %#v", payload["model"])
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":[{"index":1,"embedding":[0,1]},{"index":0,"embedding":[1,0]}]}`)
	}))
	defer server.Close()
	e, err := NewHTTPEmbedder(HTTPEmbedderConfig{Dimension: 2})
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Embed(context.Background(), profile(coremodel.ProviderOpenAICompatible, server.URL+"/v1", "secret-key"), []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if gotHeader != "Bearer secret-key" || len(got) != 2 || got[0][0] != 1 || got[1][1] != 1 {
		t.Fatalf("header/vectors = %q %#v", gotHeader, got)
	}
}

func TestGeminiEmbedderUsesPerInputEndpointAndHeader(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1beta/models/gemini-embedding:embedContent" || r.Header.Get("x-goog-api-key") != "gem-key" || r.Header.Get("Authorization") != "" {
			t.Errorf("path/headers = %s %q %q", r.URL.Path, r.Header.Get("x-goog-api-key"), r.Header.Get("Authorization"))
		}
		io.WriteString(w, `{"embedding":{"values":[0.25,0.75]}}`)
	}))
	defer server.Close()
	e, _ := NewHTTPEmbedder(HTTPEmbedderConfig{Dimension: 2})
	p := profile(coremodel.ProviderGemini, server.URL, "gem-key")
	p.Model = "gemini-embedding"
	got, err := e.Embed(context.Background(), p, []string{"a", "b"})
	if err != nil || calls != 2 || len(got) != 2 || got[0][0] != 0.25 {
		t.Fatalf("calls/vectors = %d %#v err=%v", calls, got, err)
	}
}

func TestEmbedderRejectsProviderDimensionMalformedAndOversize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"data":[{"embedding":[1]}]}`)
	}))
	defer server.Close()
	e, _ := NewHTTPEmbedder(HTTPEmbedderConfig{Dimension: 2})
	_, err := e.Embed(context.Background(), profile(coremodel.ProviderAnthropic, server.URL, "key"), []string{"x"})
	if !errors.Is(err, ErrProvider) {
		t.Fatalf("Anthropic error = %v", err)
	}
	_, err = e.Embed(context.Background(), profile(coremodel.ProviderOpenAICompatible, server.URL, "key"), []string{"x"})
	if !errors.Is(err, ErrResponse) {
		t.Fatalf("dimension error = %v", err)
	}
	oversize, _ := NewHTTPEmbedder(HTTPEmbedderConfig{Dimension: 2, MaxBodyBytes: 4})
	_, err = oversize.Embed(context.Background(), profile(coremodel.ProviderOpenAICompatible, server.URL, "key"), []string{"x"})
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("oversize error = %v", err)
	}
}

func TestEmbedderErrorDoesNotExposeKeyOrBody(t *testing.T) {
	secret := "super-secret-key"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, `{"error":"`+secret+`"}`)
	}))
	defer server.Close()
	e, _ := NewHTTPEmbedder(HTTPEmbedderConfig{Dimension: 2})
	_, err := e.Embed(context.Background(), profile(coremodel.ProviderOpenAICompatible, server.URL, secret), []string{"x"})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error exposed secret: %v", err)
	}
}

func TestMemoryStoreFenceIdempotencyAndDeterministicPointID(t *testing.T) {
	m, err := NewMemoryStore(2)
	if err != nil {
		t.Fatal(err)
	}
	chunk := Chunk{Ref: "0", Digest: strings.Repeat("a", 64), Snippet: "hello", Vector: []float32{1, 0}}
	if err := m.Upsert(context.Background(), "source-a", 1, []Chunk{chunk}); err != nil {
		t.Fatal(err)
	}
	if err := m.Upsert(context.Background(), "source-a", 1, []Chunk{chunk}); err != nil {
		t.Fatal(err)
	}
	if PointID("source-a", 1, "0") != PointID("source-a", 1, "0") || PointID("source-a", 1, "0") == PointID("source-a", 2, "0") {
		t.Fatal("point ID is not deterministic/fenced")
	}
	got, err := m.Search(context.Background(), []float32{1, 0}, []Binding{{SourceID: "source-a", Revision: 1}}, 10)
	if err != nil || len(got) != 1 || got[0].Score != 1 {
		t.Fatalf("search = %#v err=%v", got, err)
	}
	if _, err := m.Search(context.Background(), []float32{1, 0}, []Binding{{SourceID: "source-a", Revision: 2}}, 10); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteSource(context.Background(), "source-a", 1); err != nil {
		t.Fatal(err)
	}
	got, _ = m.Search(context.Background(), []float32{1, 0}, []Binding{{SourceID: "source-a", Revision: 1}}, 10)
	if len(got) != 0 {
		t.Fatalf("deleted points = %#v", got)
	}
}

func TestMemoryStoreConcurrentRaceBoundary(t *testing.T) {
	m, _ := NewMemoryStore(2)
	chunk := Chunk{Ref: "0", Digest: strings.Repeat("b", 64), Vector: []float32{1, 1}}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.Upsert(context.Background(), "source", 1, []Chunk{chunk})
			_, _ = m.Search(context.Background(), []float32{1, 1}, []Binding{{SourceID: "source", Revision: 1}}, 1)
		}()
	}
	wg.Wait()
}

func TestQdrantEnsureUpsertDeleteSearchAndExactBindings(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		if r.Header.Get("api-key") != "q-key" {
			t.Errorf("missing qdrant key")
		}
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/collections/knowledge"):
			io.WriteString(w, `{"result":{"config":{"params":{"vectors":{"size":2}}}}}`)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/points"):
			io.WriteString(w, `{"result":{"status":"completed"}}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/points/delete"):
			io.WriteString(w, `{"result":{"status":"completed"}}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/points/search"):
			io.WriteString(w, `{"result":[{"id":"`+PointID("s", 1, "0")+`","score":0.9,"payload":{"source_id":"s","revision":1,"chunk_ref":"0","digest":"`+strings.Repeat("c", 64)+`","snippet":"ok"}}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	q, err := NewQdrantStore(QdrantConfig{Endpoint: server.URL, Collection: "knowledge", Dimension: 2, APIKey: "q-key"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.EnsureCollection(context.Background()); err != nil {
		t.Fatal(err)
	}
	chunk := Chunk{Ref: "0", Digest: strings.Repeat("c", 64), Vector: []float32{1, 0}}
	if err := q.Upsert(context.Background(), "s", 1, []Chunk{chunk}); err != nil {
		t.Fatal(err)
	}
	got, err := q.Search(context.Background(), []float32{1, 0}, []Binding{{SourceID: "s", Revision: 1}}, 1)
	if err != nil || len(got) != 1 || got[0].SourceID != "s" {
		t.Fatalf("search = %#v err=%v", got, err)
	}
	if err := q.DeleteSource(context.Background(), "s", 1); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 4 {
		t.Fatalf("requests = %d", requests)
	}
}

func TestQdrantRejectsMalformedPayloadAndDimension(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/points/search") {
			io.WriteString(w, `{"result":[{"id":"not-a-uuid","score":1,"payload":{}}]}`)
			return
		}
		io.WriteString(w, `{"result":{"config":{"params":{"vectors":{"size":3}}}}}`)
	}))
	defer server.Close()
	q, _ := NewQdrantStore(QdrantConfig{Endpoint: server.URL, Collection: "knowledge", Dimension: 2})
	if err := q.EnsureCollection(context.Background()); !errors.Is(err, ErrResponse) {
		t.Fatalf("dimension error = %v", err)
	}
	_, err := q.Search(context.Background(), []float32{1, 0}, []Binding{{SourceID: "s", Revision: 1}}, 1)
	if !errors.Is(err, ErrResponse) {
		t.Fatalf("malformed error = %v", err)
	}
}

func TestQdrantPromoteGenerationPaginatesAndReplays(t *testing.T) {
	var scrollCalls, upserts int
	interrupted := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "__stage_gen/points/scroll") {
			scrollCalls++
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			if scrollCalls == 2 {
				if _, ok := req["offset"]; !ok {
					t.Errorf("missing scroll offset on page %d", scrollCalls)
				}
			}
			if scrollCalls == 2 && interrupted {
				interrupted = false
				http.Error(w, "retry", 500)
				return
			}
			start := 0
			if scrollCalls > 1 {
				start = 1000
			}
			points := make([]qdrantPoint, 0)
			for i := start; i < 1001; i++ {
				points = append(points, qdrantPoint{ID: GenerationPointID("gen", "s", 1, fmt.Sprintf("c%d", i)), Vector: []float32{1, 0}, Payload: qdrantPayload{SourceID: "s", Revision: 1, ChunkRef: fmt.Sprintf("c%d", i), Digest: strings.Repeat("a", 64), Generation: "gen"}})
			}
			next := any(nil)
			if start == 0 {
				next = "next"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"points": points, "next_page_offset": next}})
			return
		}
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/points") {
			upserts++
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	q, _ := NewQdrantStore(QdrantConfig{Endpoint: server.URL, Collection: "main", Dimension: 2})
	bindings := []Binding{{SourceID: "s", Revision: 1, Generation: "gen"}}
	if err := q.PromoteGeneration(context.Background(), "gen", bindings); err == nil {
		t.Fatal("expected interrupted page")
	}
	if err := q.PromoteGeneration(context.Background(), "gen", bindings); err != nil {
		t.Fatal(err)
	}
	if scrollCalls < 3 || upserts < 2 {
		t.Fatalf("scroll=%d upserts=%d", scrollCalls, upserts)
	}
}

func TestQdrantDeletePromotedGenerationUsesMainFilter(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/points/delete") {
			_ = json.NewDecoder(r.Body).Decode(&got)
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	q, _ := NewQdrantStore(QdrantConfig{Endpoint: server.URL, Collection: "main", Dimension: 2})
	if err := q.DeletePromotedGeneration(context.Background(), "gen", "src", 2); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fmt.Sprint(got), "generation") || !strings.Contains(fmt.Sprint(got), "src") {
		t.Fatalf("filter=%v", got)
	}
}

func TestSemanticTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		io.WriteString(w, `{"data":[]}`)
	}))
	defer server.Close()
	e, _ := NewHTTPEmbedder(HTTPEmbedderConfig{Dimension: 2, Timeout: time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := e.Embed(ctx, profile(coremodel.ProviderOpenAICompatible, server.URL, "k"), []string{"x"})
	if err == nil {
		t.Fatal("expected timeout")
	}
}
