package localartifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestSinkPersistsSSHOutputAndArtifactsAcrossRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "worker-artifacts")
	authority := Authority{OwnerID: "owner-1", AccountGeneration: 7}
	executionID := uuid.NewString()
	repository, err := NewRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	sink, err := repository.Bind(authority, executionID)
	if err != nil {
		t.Fatal(err)
	}
	if err = sink.StoreText(context.Background(), []byte("deployed\n"), []byte("warning\n"), 0); err != nil {
		t.Fatal(err)
	}
	html := []byte("<!doctype html><title>report</title>")
	if err = sink.StoreArtifact(context.Background(), "reports/index.html", bytes.NewReader(html), int64(len(html))); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	output, err := reopened.GetExecution(context.Background(), authority, executionID)
	if err != nil || output.ExitCode != 0 {
		t.Fatalf("GetExecution() = %#v, %v", output, err)
	}
	items, next, err := reopened.List(context.Background(), authority, executionID, "", 10)
	if err != nil || next != "" || len(items) != 3 {
		t.Fatalf("List() = %#v, %q, %v", items, next, err)
	}
	byKind := make(map[string]Artifact, len(items))
	for _, item := range items {
		byKind[item.Kind] = item
	}
	if byKind["stdout"].ArtifactID != output.StdoutArtifactID || byKind["stderr"].ArtifactID != output.StderrArtifactID {
		t.Fatalf("execution output not bound to text artifacts: %#v, %#v", output, byKind)
	}
	file := byKind["file"]
	if file.Name != "reports/index.html" || file.MediaType != "text/html; charset=utf-8" || file.SizeBytes != int64(len(html)) {
		t.Fatalf("file artifact = %#v", file)
	}
	digest := sha256.Sum256(html)
	if file.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("file digest = %s", file.SHA256)
	}
	chunk, err := reopened.Download(context.Background(), authority, file.ArtifactID, 5, 7)
	if err != nil || string(chunk.Data) != string(html[5:12]) || chunk.OffsetBytes != 5 || chunk.NextOffsetBytes != 12 || chunk.EOF {
		t.Fatalf("Download() = %#v, %v", chunk, err)
	}
	last, err := reopened.Download(context.Background(), authority, file.ArtifactID, chunk.NextOffsetBytes, MaxDownloadChunkBytes)
	if err != nil || !last.EOF || !bytes.Equal(append(chunk.Data, last.Data...), html[5:]) {
		t.Fatalf("last Download() = %#v, %v", last, err)
	}
}

func TestRepositoryPaginatesAndHidesForeignAuthority(t *testing.T) {
	repository, err := NewRepository(filepath.Join(t.TempDir(), "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	authority := Authority{OwnerID: "owner-1", AccountGeneration: 1}
	executionID := uuid.NewString()
	sink, _ := repository.Bind(authority, executionID)
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := sink.StoreArtifact(context.Background(), name, bytes.NewBufferString(name), int64(len(name))); err != nil {
			t.Fatal(err)
		}
	}
	first, token, err := repository.List(context.Background(), authority, executionID, "", 2)
	if err != nil || len(first) != 2 || token == "" {
		t.Fatalf("first page = %#v, %q, %v", first, token, err)
	}
	second, next, err := repository.List(context.Background(), authority, executionID, token, 2)
	if err != nil || len(second) != 1 || next != "" || second[0].ArtifactID <= first[1].ArtifactID {
		t.Fatalf("second page = %#v, %q, %v", second, next, err)
	}
	foreign := Authority{OwnerID: authority.OwnerID, AccountGeneration: 2}
	items, _, err := repository.List(context.Background(), foreign, executionID, "", 10)
	if err != nil || len(items) != 0 {
		t.Fatalf("foreign List() = %#v, %v", items, err)
	}
	if _, err = repository.Get(context.Background(), foreign, first[0].ArtifactID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign Get() error = %v", err)
	}
	if _, err = repository.Download(context.Background(), foreign, first[0].ArtifactID, 0, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign Download() error = %v", err)
	}
}

func TestSinkRejectsTraversalAndConflictingReplay(t *testing.T) {
	repository, err := NewRepository(filepath.Join(t.TempDir(), "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	authority := Authority{OwnerID: "owner-1", AccountGeneration: 1}
	sink, _ := repository.Bind(authority, uuid.NewString())
	if err := sink.StoreArtifact(context.Background(), "../escape", bytes.NewBufferString("x"), 1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("traversal error = %v", err)
	}
	if err := sink.StoreArtifact(context.Background(), "report.txt", bytes.NewBufferString("one"), 3); err != nil {
		t.Fatal(err)
	}
	if err := sink.StoreArtifact(context.Background(), "report.txt", bytes.NewBufferString("two"), 3); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting replay error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(repository.root), "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("escape path exists: %v", err)
	}
}

func TestRepositoryRejectsRelativeAndSymlinkRoots(t *testing.T) {
	if _, err := NewRepository("relative"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("relative root error = %v", err)
	}
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(link); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink root error = %v", err)
	}
}
