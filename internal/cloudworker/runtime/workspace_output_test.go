package runtime

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestFilesystemOutputCollectorOmitsLargeUnchangedBaseline(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	large := deterministicNoise(MaxArtifactBytes - 64<<10)
	if err := os.WriteFile(filepath.Join(workspace, "large-input.bin"), large, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(large)
	if err := os.WriteFile(filepath.Join(workspace, "task.txt"), []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	collector := FilesystemOutputCollector{}
	baseline, err := collector.Snapshot(t.Context(), workspace, workspaceInputDigestForTest, MaxArtifactBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer baseline.Destroy()
	if err := os.WriteFile(filepath.Join(workspace, "task.txt"), []byte("after\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	artifacts, err := collector.Collect(t.Context(), workspace, baseline, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyArtifacts(artifacts)
	patch := artifactContentForTest(t, artifacts, "changes.patch")
	archive := artifactContentForTest(t, artifacts, WorkspaceDeltaArtifactName)
	if !bytes.Contains(patch, []byte("-before\n+after\n")) {
		t.Fatalf("patch = %q", patch)
	}
	entries := readDeltaArchiveForTest(t, archive)
	if _, exists := entries[workspaceDeltaFilesRoot+"/large-input.bin"]; exists {
		t.Fatal("unchanged large input was repackaged")
	}
	if got := string(entries[workspaceDeltaFilesRoot+"/task.txt"]); got != "after\n" {
		t.Fatalf("changed file = %q", got)
	}
	manifest := parseDeltaManifestForTest(t, entries[workspaceDeltaManifestPath])
	if len(manifest.Changes) != 1 || manifest.Changes[0].Change != "modified" ||
		manifest.Changes[0].Path != "task.txt" || len(manifest.Deletions) != 0 {
		t.Fatalf("manifest = %+v", manifest)
	}

	repeated, err := collector.Collect(t.Context(), workspace, baseline, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyArtifacts(repeated)
	if !equalArtifactBytesForTest(artifacts, repeated) {
		t.Fatal("identical delta was not deterministic")
	}
}

func TestFilesystemOutputCollectorRecordsAddsAndDeletions(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "delete.txt"), []byte("remove me\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "keep.txt"), []byte("keep me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	collector := FilesystemOutputCollector{}
	baseline, err := collector.Snapshot(t.Context(), workspace, workspaceInputDigestForTest, MaxArtifactBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer baseline.Destroy()
	if err := os.Remove(filepath.Join(workspace, "delete.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "new.bin"), []byte{0, 1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(workspace, "empty"), 0o750); err != nil {
		t.Fatal(err)
	}

	artifacts, err := collector.Collect(t.Context(), workspace, baseline, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyArtifacts(artifacts)
	entries := readDeltaArchiveForTest(t, artifactContentForTest(t, artifacts, WorkspaceDeltaArtifactName))
	if _, exists := entries[workspaceDeltaFilesRoot+"/keep.txt"]; exists {
		t.Fatal("unchanged file was repackaged")
	}
	if _, exists := entries[workspaceDeltaFilesRoot+"/delete.txt"]; exists {
		t.Fatal("deleted file content was repackaged")
	}
	if !bytes.Equal(entries[workspaceDeltaFilesRoot+"/new.bin"], []byte{0, 1, 2, 3}) {
		t.Fatalf("new binary = %v", entries[workspaceDeltaFilesRoot+"/new.bin"])
	}
	if _, exists := entries[workspaceDeltaFilesRoot+"/empty/"]; !exists {
		t.Fatal("new empty directory was not represented")
	}
	manifestRaw := entries[workspaceDeltaManifestPath]
	manifest := parseDeltaManifestForTest(t, manifestRaw)
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(canonical, manifestRaw) {
		t.Fatalf("manifest is not canonical: %q err=%v", manifestRaw, err)
	}
	if len(manifest.Changes) != 2 || manifest.Changes[0].Change != "added" ||
		manifest.Changes[0].Path != "empty" || manifest.Changes[1].Path != "new.bin" ||
		len(manifest.Deletions) != 1 || manifest.Deletions[0].Path != "delete.txt" ||
		manifest.Deletions[0].Type != workspaceEntryFile {
		t.Fatalf("manifest = %+v", manifest)
	}
	patch := artifactContentForTest(t, artifacts, "changes.patch")
	if !bytes.Contains(patch, []byte("deleted file mode 100640")) ||
		!bytes.Contains(patch, []byte("-remove me\n")) || bytes.Contains(patch, []byte("new.bin")) {
		t.Fatalf("patch = %q", patch)
	}
}

func TestFilesystemOutputCollectorRecordsModeOnlyChange(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	path := filepath.Join(workspace, "mode.txt")
	content := []byte("same content\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	collector := FilesystemOutputCollector{}
	baseline, err := collector.Snapshot(
		t.Context(), workspace, workspaceInputDigestForTest, MaxArtifactBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer baseline.Destroy()
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	artifacts, err := collector.Collect(t.Context(), workspace, baseline, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyArtifacts(artifacts)
	entries := readDeltaArchiveForTest(
		t, artifactContentForTest(t, artifacts, WorkspaceDeltaArtifactName),
	)
	manifest := parseDeltaManifestForTest(t, entries[workspaceDeltaManifestPath])
	if len(manifest.Changes) != 1 || manifest.Changes[0].Change != "modified" ||
		manifest.Changes[0].Path != "mode.txt" || manifest.Changes[0].Mode != "0640" ||
		!bytes.Equal(entries[workspaceDeltaFilesRoot+"/mode.txt"], content) {
		t.Fatalf("manifest=%+v entries=%v", manifest, sortedMapKeysForTest(entries))
	}
	patch := artifactContentForTest(t, artifacts, "changes.patch")
	if !bytes.Contains(patch, []byte("old mode 100600\nnew mode 100640\n")) ||
		bytes.Contains(patch, []byte("-same content")) {
		t.Fatalf("patch = %q", patch)
	}
}

func TestFilesystemOutputCollectorRecordsTypeReplacement(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	fileToDirectory := filepath.Join(workspace, "file-to-directory")
	directoryToFile := filepath.Join(workspace, "directory-to-file")
	if err := os.WriteFile(fileToDirectory, []byte("old file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directoryToFile, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(directoryToFile, "old.txt"), []byte("old child\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	collector := FilesystemOutputCollector{}
	baseline, err := collector.Snapshot(
		t.Context(), workspace, workspaceInputDigestForTest, MaxArtifactBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer baseline.Destroy()
	if err := os.Remove(fileToDirectory); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(fileToDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileToDirectory, "empty.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(directoryToFile); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(directoryToFile, []byte("replacement\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	artifacts, err := collector.Collect(t.Context(), workspace, baseline, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyArtifacts(artifacts)
	entries := readDeltaArchiveForTest(
		t, artifactContentForTest(t, artifacts, WorkspaceDeltaArtifactName),
	)
	manifest := parseDeltaManifestForTest(t, entries[workspaceDeltaManifestPath])
	if len(manifest.Changes) != 3 ||
		manifest.Changes[0].Path != "directory-to-file" || manifest.Changes[0].Change != "replaced" ||
		manifest.Changes[0].Type != workspaceEntryFile ||
		manifest.Changes[1].Path != "file-to-directory" || manifest.Changes[1].Change != "replaced" ||
		manifest.Changes[1].Type != workspaceEntryDirectory ||
		manifest.Changes[2].Path != "file-to-directory/empty.txt" || manifest.Changes[2].Change != "added" ||
		manifest.Changes[2].SizeBytes != 0 ||
		len(manifest.Deletions) != 1 || manifest.Deletions[0].Path != "directory-to-file/old.txt" {
		t.Fatalf("manifest = %+v", manifest)
	}
}

func TestFilesystemOutputCollectorReturnsDeterministicNoChangeDelta(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "unchanged.txt"), []byte("same\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	collector := FilesystemOutputCollector{}
	baseline, err := collector.Snapshot(t.Context(), workspace, workspaceInputDigestForTest, MaxArtifactBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer baseline.Destroy()
	artifacts, err := collector.Collect(t.Context(), workspace, baseline, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyArtifacts(artifacts)
	if got := string(artifactContentForTest(t, artifacts, "changes.patch")); got != "# dirextalk workspace delta: no changes\n" {
		t.Fatalf("patch = %q", got)
	}
	entries := readDeltaArchiveForTest(t, artifactContentForTest(t, artifacts, WorkspaceDeltaArtifactName))
	if len(entries) != 1 {
		t.Fatalf("archive entries = %v", sortedMapKeysForTest(entries))
	}
	manifest := parseDeltaManifestForTest(t, entries[workspaceDeltaManifestPath])
	if len(manifest.Changes) != 0 || len(manifest.Deletions) != 0 {
		t.Fatalf("manifest = %+v", manifest)
	}
}

func TestFilesystemOutputCollectorRejectsSymlinkAndRootReplacement(t *testing.T) {
	t.Parallel()
	collector := FilesystemOutputCollector{}
	t.Run("baseline_symlink", func(t *testing.T) {
		workspace := t.TempDir()
		target := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(workspace, "link")); err != nil {
			t.Fatal(err)
		}
		baseline, err := collector.Snapshot(t.Context(), workspace, workspaceInputDigestForTest, MaxArtifactBytes)
		baseline.Destroy()
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("snapshot error = %v", err)
		}
	})
	t.Run("workspace_ancestor_symlink", func(t *testing.T) {
		actualParent := t.TempDir()
		workspace := filepath.Join(actualParent, "workspace")
		if err := os.Mkdir(workspace, 0o700); err != nil {
			t.Fatal(err)
		}
		aliasParent := t.TempDir()
		alias := filepath.Join(aliasParent, "alias")
		if err := os.Symlink(actualParent, alias); err != nil {
			t.Fatal(err)
		}
		baseline, err := collector.Snapshot(
			t.Context(), filepath.Join(alias, "workspace"),
			workspaceInputDigestForTest, MaxArtifactBytes,
		)
		baseline.Destroy()
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("snapshot error = %v", err)
		}
	})
	t.Run("output_symlink", func(t *testing.T) {
		workspace := t.TempDir()
		baseline, err := collector.Snapshot(t.Context(), workspace, workspaceInputDigestForTest, MaxArtifactBytes)
		if err != nil {
			t.Fatal(err)
		}
		defer baseline.Destroy()
		target := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(workspace, "link")); err != nil {
			t.Fatal(err)
		}
		artifacts, err := collector.Collect(t.Context(), workspace, baseline, 4096)
		destroyArtifacts(artifacts)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("collect error = %v", err)
		}
	})
	t.Run("root_replacement", func(t *testing.T) {
		parent := t.TempDir()
		workspace := filepath.Join(parent, "workspace")
		if err := os.Mkdir(workspace, 0o700); err != nil {
			t.Fatal(err)
		}
		baseline, err := collector.Snapshot(t.Context(), workspace, workspaceInputDigestForTest, MaxArtifactBytes)
		if err != nil {
			t.Fatal(err)
		}
		defer baseline.Destroy()
		if err := os.Rename(workspace, workspace+"-old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(workspace, 0o700); err != nil {
			t.Fatal(err)
		}
		artifacts, err := collector.Collect(t.Context(), workspace, baseline, 4096)
		destroyArtifacts(artifacts)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("collect error = %v", err)
		}
	})
}

func TestFilesystemOutputCollectorRejectsHardlinks(t *testing.T) {
	t.Parallel()
	collector := FilesystemOutputCollector{}
	t.Run("baseline", func(t *testing.T) {
		workspace := t.TempDir()
		first := filepath.Join(workspace, "first.txt")
		if err := os.WriteFile(first, []byte("linked\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(first, filepath.Join(workspace, "second.txt")); err != nil {
			t.Fatal(err)
		}
		baseline, err := collector.Snapshot(
			t.Context(), workspace, workspaceInputDigestForTest, MaxArtifactBytes,
		)
		baseline.Destroy()
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("snapshot error = %v", err)
		}
	})
	t.Run("output", func(t *testing.T) {
		workspace := t.TempDir()
		baseline, err := collector.Snapshot(
			t.Context(), workspace, workspaceInputDigestForTest, MaxArtifactBytes,
		)
		if err != nil {
			t.Fatal(err)
		}
		defer baseline.Destroy()
		first := filepath.Join(workspace, "first.txt")
		if err := os.WriteFile(first, []byte("linked\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(first, filepath.Join(workspace, "second.txt")); err != nil {
			t.Fatal(err)
		}
		artifacts, err := collector.Collect(t.Context(), workspace, baseline, 4096)
		destroyArtifacts(artifacts)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("collect error = %v", err)
		}
	})
}

func TestReadStableWorkspaceFileRejectsTOCTOUReplacement(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "value.txt")
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(path, []byte("trusted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := openWorkspaceRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	digest, content, captured, err := readStableWorkspaceFile(
		t.Context(), root, "value.txt", before, 1024, func() {
			if renameErr := os.Rename(path, path+"-old"); renameErr != nil {
				t.Fatalf("rename: %v", renameErr)
			}
			if linkErr := os.Symlink(outside, path); linkErr != nil {
				t.Fatalf("symlink: %v", linkErr)
			}
		},
	)
	clear(content)
	if !errors.Is(err, ErrInvalid) || digest != "" || captured {
		t.Fatalf("digest=%q captured=%t err=%v", digest, captured, err)
	}
}

func TestReadStableWorkspaceFileRejectsAncestorSymlinkSwap(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	parent := filepath.Join(workspace, "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "value.txt")
	if err := os.WriteFile(path, []byte("trusted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "value.txt"), []byte("outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, _, err := openWorkspaceRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	digest, content, captured, err := readStableWorkspaceFile(
		t.Context(), root, "parent/value.txt", before, 1024, func() {
			if renameErr := os.Rename(parent, parent+"-old"); renameErr != nil {
				t.Fatalf("rename: %v", renameErr)
			}
			if linkErr := os.Symlink(outside, parent); linkErr != nil {
				t.Fatalf("symlink: %v", linkErr)
			}
		},
	)
	clear(content)
	if !errors.Is(err, ErrInvalid) || digest != "" || captured {
		t.Fatalf("digest=%q captured=%t err=%v", digest, captured, err)
	}
}

func TestFilesystemOutputCollectorRejectsDeltaOverLimit(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	collector := FilesystemOutputCollector{}
	baseline, err := collector.Snapshot(t.Context(), workspace, workspaceInputDigestForTest, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer baseline.Destroy()
	if err := os.WriteFile(filepath.Join(workspace, "too-large.bin"), deterministicNoise(2048), 0o600); err != nil {
		t.Fatal(err)
	}
	artifacts, err := collector.Collect(t.Context(), workspace, baseline, 1024)
	destroyArtifacts(artifacts)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("collect error = %v", err)
	}
}

func artifactContentForTest(t *testing.T, artifacts []Artifact, name string) []byte {
	t.Helper()
	for _, artifact := range artifacts {
		if artifact.Name == name {
			return artifact.Content
		}
	}
	t.Fatalf("artifact %q missing from %v", name, artifactNamesForTest(artifacts))
	return nil
}

func artifactNamesForTest(artifacts []Artifact) []string {
	names := make([]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		names = append(names, artifact.Name)
	}
	return names
}

func equalArtifactBytesForTest(left, right []Artifact) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Name != right[index].Name || left[index].MediaType != right[index].MediaType ||
			!bytes.Equal(left[index].Content, right[index].Content) {
			return false
		}
	}
	return true
}

func readDeltaArchiveForTest(t *testing.T, raw []byte) map[string][]byte {
	t.Helper()
	gzipReader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
	archive := tar.NewReader(gzipReader)
	entries := make(map[string][]byte)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, duplicate := entries[header.Name]; duplicate {
			t.Fatalf("duplicate archive path %q", header.Name)
		}
		content, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name] = content
	}
	return entries
}

func parseDeltaManifestForTest(t *testing.T, raw []byte) workspaceDeltaManifest {
	t.Helper()
	var manifest workspaceDeltaManifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func deterministicNoise(size int) []byte {
	result := make([]byte, size)
	state := uint32(0x9e3779b9)
	for index := range result {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		result[index] = byte(state)
	}
	return result
}

const workspaceInputDigestForTest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func sortedMapKeysForTest(values map[string][]byte) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func assertPatchDoesNotContainForTest(t *testing.T, patch []byte, values ...string) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(string(patch), value) {
			t.Fatalf("patch unexpectedly contains %q", value)
		}
	}
}
