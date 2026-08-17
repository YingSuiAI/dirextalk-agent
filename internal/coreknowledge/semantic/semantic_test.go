package semantic

import (
	"context"
	"encoding/json"
	"errors"
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
	var gotInputs []string
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
		for _, input := range payload["input"].([]any) {
			gotInputs = append(gotInputs, input.(string))
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":[{"index":1,"embedding":[0,1]},{"index":0,"embedding":[1,0]}]}`)
	}))
	defer server.Close()
	e, err := NewHTTPEmbedder(HTTPEmbedderConfig{Dimension: 2})
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Embed(context.Background(), profile(coremodel.ProviderOpenAICompatible, server.URL+"/v1", "secret-key"), []string{"line one\nline two", "a\tb"})
	if err != nil {
		t.Fatal(err)
	}
	if gotHeader != "Bearer secret-key" || len(got) != 2 || got[0][0] != 1 || got[1][1] != 1 || !strings.Contains(gotInputs[0], "\n") || !strings.Contains(gotInputs[1], "\t") {
		t.Fatalf("header/inputs/vectors = %q %#v %#v", gotHeader, gotInputs, got)
	}
}

func TestOpenAIEmbedderRejectsEmptyAndNULContent(t *testing.T) {
	e, err := NewHTTPEmbedder(HTTPEmbedderConfig{Dimension: 2})
	if err != nil {
		t.Fatal(err)
	}
	p := profile(coremodel.ProviderOpenAICompatible, "https://example.invalid/v1", "secret-key")
	for _, input := range []string{" \r\n\t", "contains\x00nul"} {
		if _, err := e.Embed(context.Background(), p, []string{input}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("input %q error = %v", input, err)
		}
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
	pointID := PointID("source-a", 1, "0")
	if pointID != PointID("source-a", 1, "0") || pointID == PointID("source-a", 2, "0") {
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
