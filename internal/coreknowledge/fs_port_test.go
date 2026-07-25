package coreknowledge

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("/proc/self/fd unavailable")
	}
	return len(entries)
}

func TestRootManagedFileOpenerClosesIntermediateFDsOnError(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "a", "b"), 0o700); err != nil {
		t.Fatal(err)
	}
	opener, err := NewRootManagedFileOpener(root)
	if err != nil {
		t.Fatal(err)
	}
	defer opener.Close()
	before := openFDCount(t)
	for i := 0; i < 200; i++ {
		if _, err := opener.OpenManaged(context.Background(), "a/b/missing"); err == nil {
			t.Fatal("missing path unexpectedly opened")
		}
	}
	after := openFDCount(t)
	if after-before > 2 {
		t.Fatalf("intermediate descriptors leaked: before=%d after=%d", before, after)
	}
}

func TestRootManagedFileOpenerRejectsTraversalAndSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "safe"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "safe", "a.txt"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "safe", "a.txt"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	opener, err := NewRootManagedFileOpener(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opener.OpenManaged(context.Background(), "../safe/a.txt"); err == nil {
		t.Fatal("traversal accepted")
	}
	if _, err := opener.OpenManaged(context.Background(), "link"); err == nil {
		t.Fatal("symlink accepted")
	}
	f, err := opener.OpenManaged(context.Background(), "safe/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, _ := io.ReadAll(f)
	if string(b) != "ok" {
		t.Fatalf("content=%q", b)
	}
}

func TestRootContentPortFinalizeChecksumAndDelete(t *testing.T) {
	root := t.TempDir()
	port, err := NewRootContentPort(root, 16)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("hello"))
	hexDigest := fmt.Sprintf("%x", digest)
	meta := UploadMetadata{IdempotencyKey: "11111111-1111-4111-8111-111111111111", MediaType: "text/plain", DeclaredSize: 5, ContentSHA256: hexDigest}
	sink, err := port.Begin(context.Background(), meta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	ref, err := sink.Finalize(context.Background(), hexDigest, 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ref.Ref)); err != nil {
		t.Fatal(err)
	}
	if err := port.Delete(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ref.Ref)); !os.IsNotExist(err) {
		t.Fatalf("object remains: %v", err)
	}
}

func TestRootContentPortRestoresFinalizedQuotaAndReleasesOnlyVerifiedDelete(t *testing.T) {
	root := t.TempDir()
	digest := sha256.Sum256([]byte("hello"))
	hexDigest := fmt.Sprintf("%x", digest)
	meta := UploadMetadata{UploadID: "11111111-1111-4111-8111-111111111111", DeclaredSize: 5, ContentSHA256: hexDigest}
	port, err := NewRootContentPort(root, 5)
	if err != nil {
		t.Fatal(err)
	}
	sink, err := port.Begin(context.Background(), meta)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = sink.Write([]byte("hello"))
	ref, err := sink.Finalize(context.Background(), hexDigest, 5)
	if err != nil {
		t.Fatal(err)
	}
	_ = port.Close()
	port, err = NewRootContentPort(root, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer port.Close()
	if _, err := port.Begin(context.Background(), UploadMetadata{UploadID: "22222222-2222-4222-8222-222222222222", DeclaredSize: 1}); err != ErrLimitExceeded {
		t.Fatalf("restart forgot finalized quota: %v", err)
	}
	if err := port.Delete(context.Background(), ContentReference{Ref: ref.Ref, Digest: strings.Repeat("0", 64), SizeBytes: 5}); err != ErrChecksumMismatch {
		t.Fatalf("unverified delete err=%v", err)
	}
	if _, err := port.Begin(context.Background(), UploadMetadata{UploadID: "33333333-3333-4333-8333-333333333333", DeclaredSize: 1}); err != ErrLimitExceeded {
		t.Fatalf("bad delete released quota: %v", err)
	}
	if err := port.Delete(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if _, err := port.Begin(context.Background(), UploadMetadata{UploadID: "44444444-4444-4444-8444-444444444444", DeclaredSize: 1}); err != nil {
		t.Fatalf("verified delete did not release quota: %v", err)
	}
}

func TestRootPortsRetainDescriptorAcrossConfiguredPathSwap(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "old.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	opener, err := NewRootManagedFileOpener(root)
	if err != nil {
		t.Fatal(err)
	}
	defer opener.Close()
	if err := os.Rename(root, filepath.Join(parent, "old-root")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "old.txt"), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := opener.OpenManaged(context.Background(), "old.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, _ := io.ReadAll(f)
	if string(b) != "old" {
		t.Fatalf("path replacement redirected root: %q", b)
	}
	if err := os.Symlink(filepath.Join(parent, "old-root"), filepath.Join(parent, "symlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRootManagedFileOpener(filepath.Join(parent, "symlink")); err == nil {
		t.Fatal("symlink root accepted")
	}
}

func TestRootContentPortResumeDeterministicAndDistinct(t *testing.T) {
	root := t.TempDir()
	port, err := NewRootContentPort(root, 32)
	if err != nil {
		t.Fatal(err)
	}
	full := []byte("helloworld")
	h := sha256.Sum256(full)
	digest := fmt.Sprintf("%x", h)
	meta := UploadMetadata{UploadID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", MediaType: "text/plain", DeclaredSize: int64(len(full)), ContentSHA256: digest}
	if err := os.WriteFile(filepath.Join(root, ".upload-"+meta.UploadID), []byte("helloTAIL"), 0o600); err != nil {
		t.Fatal(err)
	}
	sink, err := port.Resume(context.Background(), meta, 5, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	ref, err := sink.Finalize(context.Background(), digest, int64(len(full)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ref.Ref, meta.UploadID) {
		t.Fatalf("final ref %q is not upload-bound", ref.Ref)
	}
	other := meta
	other.UploadID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	otherSink, err := port.Begin(context.Background(), other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherSink.Write(full); err != nil {
		t.Fatal(err)
	}
	otherRef, err := otherSink.Finalize(context.Background(), digest, int64(len(full)))
	if err != nil || otherRef.Ref == ref.Ref {
		t.Fatalf("same-digest refs collide: %q %q (err=%v)", ref.Ref, otherRef.Ref, err)
	}
	bad := meta
	bad.UploadID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	bad.DeclaredSize = 5
	badDigest := sha256.Sum256([]byte("hello"))
	bad.ContentSHA256 = fmt.Sprintf("%x", badDigest)
	if err := os.WriteFile(filepath.Join(root, ".upload-"+bad.UploadID), []byte("helxo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := port.Resume(context.Background(), bad, 5, 1); err != ErrChecksumMismatch {
		t.Fatalf("corrupt complete upload err=%v", err)
	}
	resumed, err := port.Resume(context.Background(), meta, int64(len(full)), 2)
	if err != nil {
		t.Fatal(err)
	}
	if replayRef, err := resumed.Finalize(context.Background(), digest, int64(len(full))); err != nil || replayRef.Ref != ref.Ref {
		t.Fatalf("finalized resume ref=%+v err=%v", replayRef, err)
	}
}

func TestRootContentPortResumeDistinguishesMissingObject(t *testing.T) {
	root := t.TempDir()
	port, err := NewRootContentPort(root, 32)
	if err != nil {
		t.Fatal(err)
	}
	meta := UploadMetadata{UploadID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", DeclaredSize: 4, ContentSHA256: strings.Repeat("0", 64)}
	if _, err := port.Resume(context.Background(), meta, 0, 0); err != ErrNotFound {
		t.Fatalf("missing staging error=%v, want ErrNotFound", err)
	}
}

func TestParseV1DeterministicAndBounded(t *testing.T) {
	chunks, err := ParseV1(context.Background(), "text/markdown", strings.NewReader(strings.Repeat("x", 5000)), 6000)
	if err != nil || len(chunks) != 2 || chunks[0].Ref != "chunk-000000" {
		t.Fatalf("chunks=%#v err=%v", chunks, err)
	}
	if _, err := ParseV1(context.Background(), "application/json", strings.NewReader("{"), 10); err == nil {
		t.Fatal("invalid json accepted")
	}
	if _, err := ParseV1(context.Background(), "text/plain", strings.NewReader(strings.Repeat("x", 10)), 5); err == nil {
		t.Fatal("limit ignored")
	}
}
