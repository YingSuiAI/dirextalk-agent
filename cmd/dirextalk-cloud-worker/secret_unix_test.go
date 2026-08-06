//go:build darwin || linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConsumeCredentialUnlinksBeforeReturningBytes(t *testing.T) {
	root := credentialRoot(t)
	path := filepath.Join(root, modelCredentialFileName)
	want := []byte("sk-secret-consume-canary-1234567890")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := consumeModelCredential(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	if string(got) != string(want) {
		t.Fatal("credential bytes changed during secure consumption")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential path still exists after consumption: %v", err)
	}
}

func TestConsumeCredentialRejectsUnsafeFilesystemObjects(t *testing.T) {
	for name, prepare := range map[string]func(*testing.T, string){
		"symlink": func(t *testing.T, root string) {
			t.Helper()
			target := filepath.Join(root, "target")
			if err := os.WriteFile(target, []byte("scoped-test-credential-1234567890"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(root, modelCredentialFileName)); err != nil {
				t.Fatal(err)
			}
		},
		"wide mode": func(t *testing.T, root string) {
			t.Helper()
			path := filepath.Join(root, modelCredentialFileName)
			if err := os.WriteFile(path, []byte("scoped-test-credential-1234567890"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"hard link": func(t *testing.T, root string) {
			t.Helper()
			path := filepath.Join(root, modelCredentialFileName)
			if err := os.WriteFile(path, []byte("scoped-test-credential-1234567890"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(path, filepath.Join(root, "second-link")); err != nil {
				t.Fatal(err)
			}
		},
		"oversize": func(t *testing.T, root string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(root, modelCredentialFileName), []byte(strings.Repeat("x", maxCredentialBytes+1)), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := credentialRoot(t)
			prepare(t, root)
			credential, err := consumeModelCredential(root, uint32(os.Geteuid()))
			clear(credential)
			if err == nil || strings.Contains(err.Error(), "scoped-test-credential") || strings.Contains(err.Error(), "sk-") {
				t.Fatalf("unsafe credential err=%v", err)
			}
		})
	}
}

func TestConsumeCredentialRejectsWrongOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("owner mutation requires root in the qualification container")
	}
	root := credentialRoot(t)
	path := filepath.Join(root, modelCredentialFileName)
	if err := os.WriteFile(path, []byte("scoped-test-credential-1234567890"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 1, -1); err != nil {
		t.Fatal(err)
	}
	credential, err := consumeModelCredential(root, uint32(os.Geteuid()))
	clear(credential)
	if err == nil {
		t.Fatal("credential owned by another uid was accepted")
	}
}

func credentialRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}
