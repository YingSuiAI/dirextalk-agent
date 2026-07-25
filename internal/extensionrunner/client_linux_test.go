//go:build linux

package extensionrunner

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSocketIdentityAcceptsProduction0660AndRejectsUnsafePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runner.sock")
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	if _, err := socketIdentity(path, uid); err != nil {
		t.Fatalf("0660 socket rejected: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := socketIdentity(path, uid); err == nil {
		t.Fatal("world-writable socket accepted")
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := socketIdentity(path, uid); err == nil {
		t.Fatal("group-writable parent accepted")
	}
}
