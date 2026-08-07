package main

import (
	"context"
	"os"
	"path/filepath"
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
	if err := os.Chmod(roots["extension-workspace"], 0o770); err != nil {
		t.Fatal(err)
	}
	registry, err := composeCoreExternalPurge(config.Config{
		CoreKnowledgeEnabled:       false,
		CoreExtensionStagingRoot:   roots["extension-staging"],
		CoreExtensionWorkspaceRoot: roots["extension-workspace"],
		CoreExtensionRunnerUID:     uint32(os.Geteuid()),
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
