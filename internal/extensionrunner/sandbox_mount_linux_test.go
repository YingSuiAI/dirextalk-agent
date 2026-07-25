//go:build linux

package extensionrunner

import (
	"bytes"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenTreeEmptyPathOptIn(t *testing.T) {
	if os.Getenv("DIREXTALK_EXTENSION_RUNNER_MOUNT_API_TEST") != "1" {
		t.Skip("set DIREXTALK_EXTENSION_RUNNER_MOUNT_API_TEST=1 in a mount-api-capable namespace")
	}
	fd, err := unix.Open(t.TempDir(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	pathFD, err := unix.Openat(fd, ".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pathFD)
	treeFD, err := unix.OpenTree(pathFD, "", uint(unix.AT_EMPTY_PATH|unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(treeFD)
}

func TestSandboxMountBaseAttrsHardenDevicesAndSetID(t *testing.T) {
	want := uint64(unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOSUID)
	if sandboxMountBaseAttrs != want {
		t.Fatalf("sandbox mount attrs = %#x, want %#x", sandboxMountBaseAttrs, want)
	}
}

func TestCopySandboxSecretUsesDirectoryFD(t *testing.T) {
	source := []byte("approved secret")
	sourceFD, err := sealedMemfd("source", source)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sourceFD)
	dirFD, err := unix.Open(t.TempDir(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dirFD)
	if err := copySandboxSecret(sourceFD, dirFD, "approved", int64(len(source))); err != nil {
		t.Fatal(err)
	}
	outputFD, err := unix.Openat(dirFD, "approved", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(outputFD)
	output := make([]byte, len(source))
	if n, err := unix.Read(outputFD, output); err != nil || n != len(output) || !bytes.Equal(output, source) {
		t.Fatalf("copied secret n=%d err=%v", n, err)
	}
}
