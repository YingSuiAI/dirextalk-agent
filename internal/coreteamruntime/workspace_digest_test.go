package coreteamruntime

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceDigestBindsMaterializedTreeContents(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "nested", "source.txt")
	if err := os.WriteFile(file, []byte("accepted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("nested/source.txt", filepath.Join(root, "source-link")); err != nil {
		t.Fatal(err)
	}

	digest, err := DigestWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWorkspaceDigest(root, digest); err != nil {
		t.Fatalf("verified materialized workspace: %v", err)
	}
	if err := os.WriteFile(file, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWorkspaceDigest(root, digest); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered workspace error=%v", err)
	}
}

func TestEmptyWorkspaceDigestIsCanonical(t *testing.T) {
	digest, err := DigestWorkspace("")
	if err != nil || digest != EmptyWorkspaceDigest {
		t.Fatalf("digest=%q err=%v", digest, err)
	}
	if err := VerifyWorkspaceDigest("", EmptyWorkspaceDigest); err != nil {
		t.Fatalf("empty workspace: %v", err)
	}
	if err := VerifyWorkspaceDigest("", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong empty digest error=%v", err)
	}
}
