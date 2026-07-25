//go:build linux

package extensionrunner

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSandboxChildFailureUsesOnlySafeStage(t *testing.T) {
	raw := errors.New("permission denied: /run/secrets/production-token")
	for _, stage := range []string{
		"bootstrap", "descriptors", "release", "mount-private", "null", "pivot", "stdin",
		"rlimits", "capabilities", "no-new-privs", "seccomp", "close-fds", "exec",
		"root-tmpfs", "layout", "app-clone", "app-bind", "app-remount", "work-clone", "work-bind", "work-remount",
		"hide-scratch", "hide-remount", "secrets-tmpfs", "secrets-copy", "secrets-remount",
	} {
		t.Run(stage, func(t *testing.T) {
			err := sandboxChildFailure(stage, raw)
			if got, want := err.Error(), stage+":other"; got != want {
				t.Fatalf("child diagnostic = %q, want safe stage and cause %q", got, want)
			}
			if !errors.Is(err, ErrDenied) {
				t.Fatalf("errors.Is(%v, ErrDenied) = false", err)
			}
			if strings.Contains(err.Error(), raw.Error()) {
				t.Fatalf("child diagnostic leaked raw error: %q", err)
			}
		})
	}
}

func TestSandboxChildFailurePreservesSafeNestedStage(t *testing.T) {
	raw := errors.New("operation failed: /run/secrets/production-token")
	err := sandboxChildFailure("mounts", sandboxChildFailure("app-bind", raw))
	if got, want := err.Error(), "app-bind:other"; got != want {
		t.Fatalf("nested child diagnostic = %q, want %q", got, want)
	}
	if !errors.Is(err, ErrDenied) || strings.Contains(err.Error(), raw.Error()) {
		t.Fatalf("nested child diagnostic is not safe: %q", err)
	}
}

func TestSandboxChildFailureUsesFixedCauseClasses(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		err        error
	}{
		{"denied", "denied", ErrDenied},
		{"permission", "permission", unix.EPERM},
		{"missing", "missing", unix.ENOENT},
		{"busy", "busy", unix.EBUSY},
		{"invalid", "invalid", unix.EINVAL},
		{"unsupported", "unsupported", unix.ENOSYS},
		{"other", "other", errors.New("raw /private/path errno 123")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := sandboxChildFailure("root-tmpfs", tc.err)
			if got, want := err.Error(), "root-tmpfs:"+tc.want; got != want {
				t.Fatalf("child diagnostic = %q, want %q", got, want)
			}
			if strings.Contains(err.Error(), tc.err.Error()) {
				t.Fatalf("child diagnostic leaked raw error: %q", err)
			}
		})
	}
}
