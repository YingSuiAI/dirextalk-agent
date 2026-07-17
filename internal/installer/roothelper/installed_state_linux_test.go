//go:build linux

package roothelper

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"syscall"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"golang.org/x/sys/unix"
)

func TestInstalledStateInspectorRequiresExactSecretVersionXattr(t *testing.T) {
	path := t.TempDir() + "/secret"
	if err := os.WriteFile(path, []byte("opaque-secret"), 0o400); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("opaque-secret"))
	if err := unix.Setxattr(path, secretVersionXattr, []byte("88888888-8888-4888-8888-888888888888"), 0); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOTSUP) {
			t.Skipf("trusted xattrs unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if err := unix.Setxattr(path, secretDigestXattr, digest[:], 0); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("file stat is unavailable")
	}
	secret := installer.SecretV1{
		VersionID: "88888888-8888-4888-8888-888888888888", TargetPath: path,
		FileMode: 0o400, OwnerUID: stat.Uid, OwnerGID: stat.Gid,
	}
	inspector := NewRootOwnedInstalledStateInspector(bootstrap.InstalledStateV1{})
	if err := inspector.VerifySecret(context.Background(), secret); err != nil {
		t.Fatalf("exact version rejected: %v", err)
	}
	secret.VersionID = "99999999-9999-4999-8999-999999999999"
	if err := inspector.VerifySecret(context.Background(), secret); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("different version error = %v", err)
	}
	secret.VersionID = "88888888-8888-4888-8888-888888888888"
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := inspector.VerifySecret(context.Background(), secret); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("tampered content error = %v", err)
	}
}

func TestInstalledStateInspectorRejectsSecretSymlink(t *testing.T) {
	target := t.TempDir() + "/target"
	link := t.TempDir() + "/secret"
	if err := os.WriteFile(target, []byte("opaque-secret"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	secret := installer.SecretV1{
		VersionID: "88888888-8888-4888-8888-888888888888", TargetPath: link,
		FileMode: 0o400, OwnerUID: uint32(os.Getuid()), OwnerGID: uint32(os.Getgid()),
	}
	if err := NewRootOwnedInstalledStateInspector(bootstrap.InstalledStateV1{}).VerifySecret(context.Background(), secret); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("symlink error = %v", err)
	}
}
