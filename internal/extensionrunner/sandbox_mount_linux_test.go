//go:build linux

package extensionrunner

import (
	"bytes"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCloneSandboxTreeReopensCurrentNamespacePath(t *testing.T) {
	if os.Getenv("DIREXTALK_EXTENSION_RUNNER_MOUNT_API_TEST") != "1" {
		t.Skip("set DIREXTALK_EXTENSION_RUNNER_MOUNT_API_TEST=1 in a mount-api-capable namespace")
	}
	fd, err := unix.Open(t.TempDir(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	treeFD, err := cloneSandboxTree(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(treeFD)
}

func TestReopenSandboxTreeSourcePreservesDescriptorIdentity(t *testing.T) {
	fd, err := unix.Open(t.TempDir(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	reopened, err := reopenSandboxTreeSource(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(reopened)
	var inheritedStat, reopenedStat unix.Stat_t
	if unix.Fstat(fd, &inheritedStat) != nil || unix.Fstat(reopened, &reopenedStat) != nil {
		t.Fatal("fstat failed")
	}
	if inheritedStat.Dev != reopenedStat.Dev || inheritedStat.Ino != reopenedStat.Ino || inheritedStat.Mode != reopenedStat.Mode {
		t.Fatalf("reopened descriptor identity changed: inherited=%+v reopened=%+v", inheritedStat, reopenedStat)
	}
}

func TestCloneSandboxTreeRejectsNonDirectorySource(t *testing.T) {
	root := t.TempDir()
	file := root + "/entry"
	if err := os.WriteFile(file, []byte("manager"), 0o500); err != nil {
		t.Fatal(err)
	}
	fileFD, err := unix.Open(file, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fileFD)
	if tree, err := cloneSandboxTree(fileFD); err == nil {
		unix.Close(tree)
		t.Fatal("regular-file source unexpectedly cloned as a sandbox tree")
	}
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
