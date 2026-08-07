//go:build linux

package runner

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
	"golang.org/x/sys/unix"
)

func staticTestExecutable(t *testing.T) (string, []byte) {
	t.Helper()
	var machine uint16
	var code []byte
	switch runtime.GOARCH {
	case "amd64":
		machine = 62
		code = []byte{0x48, 0xc7, 0xc0, 0x3c, 0, 0, 0, 0x48, 0x31, 0xff, 0x0f, 0x05}
	case "arm64":
		machine = 183
		code = []byte{0xa8, 0x0b, 0x80, 0xd2, 0x00, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4}
	default:
		t.Skip("unsupported architecture")
	}
	const headerSize = 64
	const programHeaderSize = 56
	body := make([]byte, headerSize+programHeaderSize+len(code))
	copy(body[:16], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(body[16:], 2)
	binary.LittleEndian.PutUint16(body[18:], machine)
	binary.LittleEndian.PutUint32(body[20:], 1)
	binary.LittleEndian.PutUint64(body[24:], 0x400000+headerSize+programHeaderSize)
	binary.LittleEndian.PutUint64(body[32:], headerSize)
	binary.LittleEndian.PutUint16(body[52:], headerSize)
	binary.LittleEndian.PutUint16(body[54:], programHeaderSize)
	binary.LittleEndian.PutUint16(body[56:], 1)
	program := body[headerSize : headerSize+programHeaderSize]
	binary.LittleEndian.PutUint32(program[0:], 1)
	binary.LittleEndian.PutUint32(program[4:], 5)
	binary.LittleEndian.PutUint64(program[16:], 0x400000)
	binary.LittleEndian.PutUint64(program[32:], uint64(len(body)))
	binary.LittleEndian.PutUint64(program[40:], uint64(len(body)))
	binary.LittleEndian.PutUint64(program[48:], 0x1000)
	copy(body[headerSize+programHeaderSize:], code)
	path := filepath.Join(t.TempDir(), "static-shell")
	if err := os.WriteFile(path, body, 0o500); err != nil {
		t.Fatal(err)
	}
	return path, body
}

func TestPublishShellAndServiceAreImmutableBeforeAdmission(t *testing.T) {
	self, body := staticTestExecutable(t)
	root := t.TempDir()
	cleanupPublishedTestDirs(t, root)
	installRoot := filepath.Join(root, "install")
	if err := os.Mkdir(installRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	executor := LinuxExecutor{InstallRoot: installRoot, StaticShell: self}
	if err := executor.publishShell(); err != nil {
		t.Fatalf("publish shell: %v", err)
	}
	shellEntries := []extensionrunner.ManifestEntry{{Path: "entry", SHA256: extensionrunner.DigestBytes(body), Size: int64(len(body))}}
	assertImmutableInstall(t, installRoot, extensionrunner.ManifestDigest(shellEntries))

	digest, install, _, err := executor.publishService(body)
	if err != nil {
		t.Fatalf("publish service: %v", err)
	}
	if err := install.Close(); err != nil {
		t.Fatal(err)
	}
	assertImmutableInstall(t, installRoot, digest)
	// A restart/replay reuses only the already admitted immutable digest.
	if err := executor.publishShell(); err != nil {
		t.Fatalf("replay immutable shell: %v", err)
	}
}

func TestPublishShellPreservesPartialDigestOnRestart(t *testing.T) {
	self, body := staticTestExecutable(t)
	root := t.TempDir()
	cleanupPublishedTestDirs(t, root)
	installRoot := filepath.Join(root, "install")
	if err := os.Mkdir(installRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	entries := []extensionrunner.ManifestEntry{{Path: "entry", SHA256: extensionrunner.DigestBytes(body), Size: int64(len(body))}}
	target := filepath.Join(installRoot, extensionrunner.ManifestDigest(entries))
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(target, "unknown")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	executor := LinuxExecutor{InstallRoot: installRoot, StaticShell: self}
	if err := executor.publishShell(); err == nil {
		t.Fatal("partial digest was repaired or overwritten")
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "preserve" {
		t.Fatalf("partial digest changed: body=%q err=%v", got, err)
	}
}

func TestPublishTempCleanupNeverRemovesUnknownContent(t *testing.T) {
	root := t.TempDir()
	tmp, err := os.MkdirTemp(root, ".publish-")
	if err != nil {
		t.Fatal(err)
	}
	known := filepath.Join(tmp, "entry")
	unknown := filepath.Join(tmp, "unknown")
	if err := os.WriteFile(known, []byte("known"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unknown, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(tmp, &st); err != nil {
		t.Fatal(err)
	}
	removePublishTemp(tmp, uint64(st.Dev), st.Ino, st.Uid, []string{"entry"})
	if _, err := os.Stat(known); !os.IsNotExist(err) {
		t.Fatalf("known temp file not removed: %v", err)
	}
	if body, err := os.ReadFile(unknown); err != nil || string(body) != "preserve" {
		t.Fatalf("unknown temp content changed: body=%q err=%v", body, err)
	}
}

func cleanupPublishedTestDirs(t *testing.T, root string) {
	t.Helper()
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
}

func assertImmutableInstall(t *testing.T, root, digest string) {
	t.Helper()
	info, err := os.Stat(filepath.Join(root, digest))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o500 {
		t.Fatalf("published directory mode=%#o, want 0500", got)
	}
	install, err := (extensionrunner.DiskInstallResolver{Root: root}).ResolveInstall(digest)
	if err != nil {
		t.Fatalf("immutable install rejected: %v", err)
	}
	if err := install.Close(); err != nil {
		t.Fatal(err)
	}
}
