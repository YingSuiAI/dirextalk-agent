//go:build linux

package runner

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestListenClearsOnlySameUIDStaleSocket(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "runner.sock")
	stale, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := Listen(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("same-UID stale socket rejected: %v", err)
	}
	defer listener.Close()
}

func TestListenDoesNotRemoveActiveSocket(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "runner.sock")
	active, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if _, err := Listen(path, uint32(os.Geteuid())); err == nil {
		t.Fatal("active listener replaced")
	}
	client, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatalf("active listener was disturbed: %v", err)
	}
	client.Close()
}

func TestListenDoesNotRemoveOrdinaryFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "runner.sock")
	if err := os.WriteFile(path, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path, uint32(os.Geteuid())); err == nil {
		t.Fatal("ordinary file accepted")
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != "owned" {
		t.Fatalf("ordinary file changed: body=%q err=%v", body, err)
	}
}

func TestListenDoesNotRemoveSocketWhenExpectedOwnerDiffers(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "runner.sock")
	stale, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	foreign := uint32(os.Geteuid()) + 1
	if err := clearStaleSocket(path, foreign); err == nil {
		t.Fatal("foreign-owned socket accepted")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("foreign socket removed: %v", err)
	}
}
