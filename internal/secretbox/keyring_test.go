package secretbox

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func testKey(fill byte) []byte {
	key := make([]byte, MasterKeySize)
	for i := range key {
		key[i] = fill
	}
	return key
}

func TestSealOpenBindsAADAndVersion(t *testing.T) {
	ring, err := New(7, testKey(0x41))
	if err != nil {
		t.Fatal(err)
	}
	aad, err := BindAAD("core_aws_credentials", "11111111-1111-4111-8111-111111111111", 3, "secret_access_key")
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := ring.Seal([]byte("canary-secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.KeyVersion != 7 || len(envelope.Nonce) != 12 || len(envelope.Ciphertext) <= len("canary-secret") {
		t.Fatalf("unexpected envelope: %#v", envelope)
	}
	opened, err := ring.Open(envelope, aad)
	if err != nil || string(opened) != "canary-secret" {
		t.Fatalf("opened=%q err=%v", opened, err)
	}
	wrongAAD, _ := BindAAD("core_aws_credentials", "11111111-1111-4111-8111-111111111111", 4, "secret_access_key")
	if _, err := ring.Open(envelope, wrongAAD); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("revision transplant err=%v", err)
	}
	wrongVersion, err := New(8, testKey(0x41))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongVersion.Open(envelope, aad); !errors.Is(err, ErrKeyVersionMismatch) {
		t.Fatalf("version mismatch err=%v", err)
	}
	wrongKey, err := New(7, testKey(0x42))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongKey.Open(envelope, aad); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong key err=%v", err)
	}
}

func TestLoadMountedFileRequiresRaw32BytesAnd0400(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "core-secret-master-key")
	if err := os.WriteFile(path, testKey(0x43), 0o400); err != nil {
		t.Fatal(err)
	}
	ring, err := LoadMountedFile(path, 1)
	if err != nil || ring.Version() != 1 {
		t.Fatalf("ring=%v err=%v", ring, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMountedFile(path, 1); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("insecure mode err=%v", err)
	}
	if err := os.WriteFile(path, append(testKey(0x43), '\n'), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMountedFile(path, 1); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("newline-padded key err=%v", err)
	}
}

func TestLoadMountedFileRejectsSymlinkAndIdentitySwap(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, testKey(0x44), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMountedFile(link, 1); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("symlink key err=%v", err)
	}
	if runtime.GOOS != "linux" {
		return
	}
	path := filepath.Join(dir, "swap")
	if err := os.WriteFile(path, testKey(0x45), 0o400); err != nil {
		t.Fatal(err)
	}
	called := false
	mountedKeyBeforeOpenHook = func(name string) {
		called = true
		replacement := name + ".replacement"
		if err := os.Rename(name, replacement); err != nil {
			t.Fatalf("swap original: %v", err)
		}
		if err := os.WriteFile(name, testKey(0x46), 0o400); err != nil {
			t.Fatalf("write replacement: %v", err)
		}
	}
	defer func() { mountedKeyBeforeOpenHook = nil }()
	if _, err := LoadMountedFile(path, 1); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("identity swap err=%v", err)
	}
	if !called {
		t.Fatal("identity swap hook was not invoked")
	}
}

func TestBindAADRejectsAmbiguousInputs(t *testing.T) {
	for _, tc := range []struct {
		domain, record, field string
		revision              int64
	}{
		{"", "record", "field", 1},
		{"domain", "", "field", 1},
		{"domain", "record", "", 1},
		{"domain", "record", "field", 0},
		{"domain\x00x", "record", "field", 1},
	} {
		if _, err := BindAAD(tc.domain, tc.record, tc.revision, tc.field); !errors.Is(err, ErrInvalidAAD) {
			t.Fatalf("inputs=%#v err=%v", tc, err)
		}
	}
}
