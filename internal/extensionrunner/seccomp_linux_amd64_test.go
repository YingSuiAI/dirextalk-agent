//go:build linux && amd64

package extensionrunner

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestSeccompAllowsLegacyOpenForStaticShellWrites(t *testing.T) {
	if os.Getenv("DIREXTALK_SECCOMP_OPEN_HELPER") == "1" {
		path, err := unix.BytePtrFromString(os.Args[len(os.Args)-1])
		if err != nil || unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil || installSandboxSeccomp() != nil {
			os.Exit(20)
		}
		fd, _, errno := unix.Syscall6(
			unix.SYS_OPEN,
			uintptr(unsafe.Pointer(path)),
			uintptr(unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC),
			0o600,
			0,
			0,
			0,
		)
		if errno != 0 {
			os.Exit(21)
		}
		if _, err = unix.Write(int(fd), []byte("ready\n")); err != nil {
			os.Exit(22)
		}
		if err = unix.Close(int(fd)); err != nil {
			os.Exit(23)
		}
		os.Exit(0)
	}

	target := filepath.Join(t.TempDir(), "readiness-service")
	cmd := exec.Command(os.Args[0], "-test.run=^TestSeccompAllowsLegacyOpenForStaticShellWrites$", target)
	cmd.Env = append(os.Environ(), "DIREXTALK_SECCOMP_OPEN_HELPER=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("legacy open under seccomp failed: %v: %s", err, output)
	}
	body, err := os.ReadFile(target)
	if err != nil || string(body) != "ready\n" {
		t.Fatalf("legacy open result=%q err=%v", body, err)
	}
}
