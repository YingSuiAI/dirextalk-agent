//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadControlPrivateKeyUsesSafeOwnedDescriptor(t *testing.T) {
	root := t.TempDir()
	key := filepath.Join(root, "key.pem")
	want := []byte("test-private-key-material")
	if err := os.WriteFile(key, want, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readControlPrivateKey(key, uint32(os.Geteuid()))
	if err != nil || string(got) != string(want) {
		t.Fatalf("key=%q err=%v", got, err)
	}
	clear(got)
}

func TestReadControlPrivateKeyRejectsUnsafeFilesystemObjects(t *testing.T) {
	for name, setup := range map[string]func(*testing.T) (string, uint32){
		"symlink": func(t *testing.T) (string, uint32) {
			root := t.TempDir()
			target := filepath.Join(root, "target")
			if err := os.WriteFile(target, []byte("test-private-key-material"), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(root, "key.pem")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return link, uint32(os.Geteuid())
		},
		"symlink parent": func(t *testing.T) (string, uint32) {
			root := t.TempDir()
			real := filepath.Join(root, "real")
			if err := os.Mkdir(real, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(real, "key.pem"), []byte("test-private-key-material"), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(root, "link")
			if err := os.Symlink(real, link); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(link, "key.pem"), uint32(os.Geteuid())
		},
		"hardlink": func(t *testing.T) (string, uint32) {
			root := t.TempDir()
			key := filepath.Join(root, "key.pem")
			if err := os.WriteFile(key, []byte("test-private-key-material"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(key, filepath.Join(root, "copy")); err != nil {
				t.Fatal(err)
			}
			return key, uint32(os.Geteuid())
		},
		"wide mode": func(t *testing.T) (string, uint32) {
			key := filepath.Join(t.TempDir(), "key.pem")
			if err := os.WriteFile(key, []byte("test-private-key-material"), 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(key, 0o640); err != nil {
				t.Fatal(err)
			}
			return key, uint32(os.Geteuid())
		},
		"wrong owner": func(t *testing.T) (string, uint32) {
			key := filepath.Join(t.TempDir(), "key.pem")
			if err := os.WriteFile(key, []byte("test-private-key-material"), 0o600); err != nil {
				t.Fatal(err)
			}
			return key, uint32(os.Geteuid() + 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			path, uid := setup(t)
			if key, err := readControlPrivateKey(path, uid); err == nil {
				clear(key)
				t.Fatal("unsafe control private key was accepted")
			}
		})
	}
}
