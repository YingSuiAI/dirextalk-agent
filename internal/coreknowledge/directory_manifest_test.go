package coreknowledge

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestEnumerateManagedDirectoryDeterministicAndRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "docs", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "z.txt"), []byte("z"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "nested", "a.md"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "docs", "z.txt"), filepath.Join(root, "docs", "link")); err != nil {
		t.Fatal(err)
	}
	opener, err := NewRootManagedFileOpener(root)
	if err != nil {
		t.Fatal(err)
	}
	defer opener.Close()
	if _, err := opener.EnumerateManagedDirectory(context.Background(), "docs", DirectoryManifestLimits{}); err == nil {
		t.Fatal("symlink accepted")
	}
	_ = os.Remove(filepath.Join(root, "docs", "link"))
	first, err := opener.EnumerateManagedDirectory(context.Background(), "docs", DirectoryManifestLimits{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := opener.EnumerateManagedDirectory(context.Background(), "docs", DirectoryManifestLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest || len(first.Entries) != 2 || first.Entries[0].Path != "nested/a.md" {
		t.Fatalf("manifest not deterministic: %#v %#v", first, second)
	}
	if err := first.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestEnumerateManagedDirectoryBounds(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "x"), []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	opener, err := NewRootManagedFileOpener(root)
	if err != nil {
		t.Fatal(err)
	}
	defer opener.Close()
	_, err = opener.EnumerateManagedDirectory(context.Background(), "sub", DirectoryManifestLimits{MaxFileBytes: 3})
	if err == nil {
		t.Fatal("oversized file accepted")
	}
}

func TestVerifyManagedDirectoryManifestDetectsMutation(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, "docs", "a.txt")
	if err := os.WriteFile(name, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	opener, err := NewRootManagedFileOpener(root)
	if err != nil {
		t.Fatal(err)
	}
	defer opener.Close()
	manifest, err := opener.EnumerateManagedDirectory(context.Background(), "docs", DirectoryManifestLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := opener.VerifyManagedDirectoryManifest(context.Background(), manifest, DirectoryManifestLimits{}); err == nil {
		t.Fatal("mutation accepted")
	}
}
