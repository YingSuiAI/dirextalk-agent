//go:build linux

package pisandbox

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

const landlockHelperEnvironment = "DIREXTALK_LANDLOCK_TEST_HELPER"

func TestLandlockAllowsOnlyDeclaredFilesystemView(t *testing.T) {
	allowed := filepath.Join(t.TempDir(), "allowed")
	denied := filepath.Join(t.TempDir(), "control")
	for _, directory := range []string{allowed, denied} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(allowed, "runtime"), []byte("qualified"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(denied, "mtls-key"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestLandlockHelper$", "--", allowed, denied)
	command.Env = append(os.Environ(), landlockHelperEnvironment+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		if errors.Is(err, ErrUnsupported) {
			t.Skip("host kernel does not expose the required Landlock ABI")
		}
		t.Fatalf("sandbox helper failed: %v output=%q", err, output)
	}
	if got, err := os.ReadFile(filepath.Join(allowed, "created")); err != nil || string(got) != "ok" {
		t.Fatalf("allowed write=%q err=%v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(denied, "mtls-key")); err != nil || string(got) != "private" {
		t.Fatalf("denied control file changed=%q err=%v", got, err)
	}
}

func TestLandlockHelper(t *testing.T) {
	if os.Getenv(landlockHelperEnvironment) != "1" {
		return
	}
	separator := 0
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator == 0 || len(os.Args) != separator+3 {
		os.Exit(90)
	}
	allowed, denied := os.Args[separator+1], os.Args[separator+2]
	rules := []PathRule{{Path: allowed, Access: ReadWriteExecute}}
	for _, path := range []string{"/usr/bin", "/usr/lib", "/usr/lib64", "/lib", "/lib64"} {
		if _, err := os.Stat(path); err == nil {
			rules = append(rules, PathRule{Path: path, Access: ReadExecute})
		}
	}
	for _, path := range []string{"/dev/null", "/dev/urandom"} {
		if _, err := os.Stat(path); err == nil {
			rules = append(rules, PathRule{Path: path, Access: ReadWrite})
		}
	}
	if _, err := os.Stat("/proc/self"); err == nil {
		rules = append(rules, PathRule{Path: "/proc/self", Access: ReadOnly})
	}
	runtime.LockOSThread()
	if err := Apply(Policy{MinimumABI: 2, Paths: rules}); err != nil {
		os.Exit(91)
	}
	if err := unix.Truncate(filepath.Join(denied, "mtls-key"), 0); !errors.Is(err, unix.EPERM) && !errors.Is(err, unix.EACCES) {
		os.Exit(93)
	}
	script := `set -eu
test "$(cat "$1/runtime")" = qualified
printf ok > "$1/created"
if IFS= read -r value < "$2/mtls-key"; then exit 20; fi
if IFS= read -r value < "/proc/$PPID/environ"; then exit 21; fi
`
	if err := unix.Exec("/bin/sh", []string{"sh", "-c", script, "sh", allowed, denied}, []string{"PATH=/usr/bin:/bin"}); err != nil {
		os.Exit(92)
	}
}
