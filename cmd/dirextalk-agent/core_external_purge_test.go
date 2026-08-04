package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/config"
)

func TestCoreExternalPurgeRegistryPurgesConfiguredRootsWhenKnowledgeDisabled(t *testing.T) {
	roots := map[string]string{
		"extension-staging":   t.TempDir(),
		"extension-workspace": t.TempDir(),
		"knowledge-content":   t.TempDir(),
		"knowledge-mount":     t.TempDir(),
	}
	for name, root := range roots {
		path := filepath.Join(root, name, "nested", "sentinel")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	registry, err := composeCoreExternalPurge(config.Config{
		CoreKnowledgeEnabled:       false,
		CoreExtensionStagingRoot:   roots["extension-staging"],
		CoreExtensionWorkspaceRoot: roots["extension-workspace"],
		CoreKnowledgeContentRoot:   roots["knowledge-content"],
		CoreKnowledgeMountRoot:     roots["knowledge-mount"],
	})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	if err := registry.Purge(context.Background()); err != nil {
		t.Fatal(err)
	}
	for name, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		if name == "knowledge-mount" {
			if len(entries) != 1 {
				t.Fatalf("read-only Knowledge mount was unexpectedly purged: %v", entries)
			}
			continue
		}
		if len(entries) != 0 {
			t.Fatalf("disabled Knowledge purge left %s entries: %v", name, entries)
		}
	}
}

func TestCoreExternalPurgeRejectsPartialQdrantConfiguration(t *testing.T) {
	_, err := composeCoreExternalPurge(config.Config{CoreKnowledgeQdrantEndpoint: "http://qdrant.invalid"})
	if err == nil {
		t.Fatal("partial Qdrant configuration unexpectedly accepted")
	}
}

func TestCoreExternalPurgeDeletesConfiguredQdrantWhenKnowledgeDisabled(t *testing.T) {
	var deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/collections" {
			_, _ = w.Write([]byte(`{"result":{"collections":[{"name":"knowledge"},{"name":"knowledge__stage_test"},{"name":"unrelated"}]}}`))
			return
		}
		if r.Method != http.MethodDelete || (r.URL.Path != "/collections/knowledge" && r.URL.Path != "/collections/knowledge__stage_test") {
			http.Error(w, "unexpected purge request", http.StatusBadRequest)
			return
		}
		deletes.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	root := t.TempDir()
	registry, err := composeCoreExternalPurge(config.Config{
		CoreKnowledgeEnabled:          false,
		CoreKnowledgeQdrantEndpoint:   server.URL,
		CoreKnowledgeQdrantCollection: "knowledge",
		CoreKnowledgeQdrantDimension:  2,
		CoreKnowledgeContentRoot:      root,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	if err := registry.Purge(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := deletes.Load(); got != 2 {
		t.Fatalf("Qdrant delete calls=%d, want 2 (base + stage)", got)
	}
}
