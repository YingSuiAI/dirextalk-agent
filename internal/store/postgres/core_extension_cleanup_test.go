package postgres

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestRemoveStagedExtensionArtifactUsesBoundCleanup(t *testing.T) {
	root := t.TempDir()
	digest := strings.Repeat("c", 64)
	cleanupID := uuid.NewString()
	target := filepath.Join(root, digest)
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "manifest.json"), []byte("{}"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0500); err != nil {
		t.Fatal(err)
	}
	if err := removeStagedExtensionArtifact(root, digest, cleanupID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleaner wiring left staged artifact: %v", err)
	}
}

func TestExtensionArtifactCleanupIDIsStableForImmutableTuple(t *testing.T) {
	installationID := uuid.NewString()
	versionID := uuid.NewString()
	digest := strings.Repeat("a", 64)
	first := extensionArtifactCleanupID(installationID, versionID, digest)
	second := extensionArtifactCleanupID(installationID, versionID, digest)
	if first != second || uuid.Validate(first) != nil {
		t.Fatalf("unstable cleanup id: first=%q second=%q", first, second)
	}
	if other := extensionArtifactCleanupID(installationID, uuid.NewString(), digest); other == first {
		t.Fatalf("different immutable tuple reused cleanup id %q", first)
	}
}

func TestRemoveStagedExtensionArtifactCompletionRequiresSucceededDBState(t *testing.T) {
	root := t.TempDir()
	digest := strings.Repeat("d", 64)
	cleanupID := uuid.NewString()
	target := filepath.Join(root, digest)
	if err := os.Mkdir(target, 0500); err != nil {
		t.Fatal(err)
	}
	if err := removeStagedExtensionArtifact(root, digest, cleanupID); err != nil {
		t.Fatal(err)
	}
	completion := filepath.Join(root, ".removed-"+cleanupID)
	if _, err := os.Stat(completion); err != nil {
		t.Fatalf("completion marker missing before DB transition: %v", err)
	}
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(target, "replacement")
	if err := os.WriteFile(replacement, []byte("new generation"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeStagedExtensionArtifactCompletion(root, cleanupID, "running"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(completion); err != nil {
		t.Fatalf("non-succeeded DB state removed completion marker: %v", err)
	}
	if err := removeStagedExtensionArtifactCompletion(root, cleanupID, "succeeded"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(completion); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("succeeded DB state left completion marker: %v", err)
	}
	if got, err := os.ReadFile(replacement); err != nil || string(got) != "new generation" {
		t.Fatalf("completion GC crossed into replacement: %q err=%v", got, err)
	}
}
