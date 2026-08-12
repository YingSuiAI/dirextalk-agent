//go:build linux

package extensionrunner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSandboxChildFailureUsesOnlySafeStage(t *testing.T) {
	raw := errors.New("permission denied: /run/secrets/production-token")
	for _, stage := range []string{
		"bootstrap", "descriptors", "release", "mount-ready", "mount-private", "null", "pivot", "stdin",
		"rlimits", "capabilities", "no-new-privs", "seccomp", "close-fds", "exec",
		"root-target", "root-tmpfs", "root-bind", "root-verify", "layout", "app-clone", "app-bind", "app-remount", "work-clone", "work-bind", "work-remount",
		"manager-clone", "manager-bind", "manager-remount", "manager-hide", "manager-release",
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

func TestSandboxFailureDiagnosticAllowsOnlyTypedSafeDiagnostics(t *testing.T) {
	safe := sandboxChildFailure("manager-hide", ErrDenied)
	if got, want := SandboxFailureDiagnostic(safe), "manager-hide:denied"; got != want {
		t.Fatalf("safe diagnostic = %q, want %q", got, want)
	}

	raw := errors.New("permission denied: /run/secrets/production-token")
	if got, want := SandboxFailureDiagnostic(raw), "bootstrap:denied"; got != want {
		t.Fatalf("raw diagnostic = %q, want %q", got, want)
	} else if strings.Contains(got, "/run/") || strings.Contains(got, "production-token") {
		t.Fatalf("raw diagnostic leaked runtime detail: %q", got)
	}

	unsafeTyped := sandboxChildStageError{stage: "raw-/private/path", cause: "other"}
	if got, want := SandboxFailureDiagnostic(unsafeTyped), "bootstrap:denied"; got != want {
		t.Fatalf("unsafe typed diagnostic = %q, want %q", got, want)
	}
}

func TestCompleteSandboxMountHandshakeBlocksUntilContinue(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	done := make(chan error, 1)
	go func() { done <- completeSandboxMountHandshake(fds[0]) }()
	if err := waitSandboxControl(context.Background(), fds[1], sandboxControlMounted); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("child passed mount barrier before continue: %v", err)
	default:
	}
	if _, err := unix.Write(fds[1], []byte{sandboxControlContinue}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("mount handshake failed: %v", err)
	}
}

func TestSandboxManagerBoundaryCompletesMountsBeforeReadyAndRelease(t *testing.T) {
	var events []string
	record := func(name string) func() error {
		return func() error {
			events = append(events, name)
			return nil
		}
	}
	err := applySandboxManagerBoundary(sandboxManagerBoundaryOps{
		hideManager:       record("hide"),
		verifyHidden:      record("verify-hidden"),
		mountReady:        record("mounted-continue"),
		clearCapabilities: record("clear-capabilities"),
		noNewPrivileges:   record("no-new-privileges"),
		releaseCommand:    record("release-command"),
		abortCommand:      func() { events = append(events, "abort-command") },
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"hide", "verify-hidden", "mounted-continue", "clear-capabilities", "no-new-privileges", "release-command"}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("manager boundary order = %v, want %v", events, want)
	}
}

func TestSandboxManagerBoundaryAbortsBlockedCommandBeforeRelease(t *testing.T) {
	for _, tc := range []struct {
		fail string
		want string
	}{
		{fail: "hide", want: "manager-hide:other"},
		{fail: "verify-hidden", want: "manager-hide:other"},
		{fail: "mounted-continue", want: "mount-ready:other"},
	} {
		t.Run(tc.fail, func(t *testing.T) {
			var events []string
			step := func(name string) func() error {
				return func() error {
					events = append(events, name)
					if name == tc.fail {
						return errors.New("raw /private/path")
					}
					return nil
				}
			}
			err := applySandboxManagerBoundary(sandboxManagerBoundaryOps{
				hideManager:       step("hide"),
				verifyHidden:      step("verify-hidden"),
				mountReady:        step("mounted-continue"),
				clearCapabilities: step("clear-capabilities"),
				noNewPrivileges:   step("no-new-privileges"),
				releaseCommand:    step("release-command"),
				abortCommand:      func() { events = append(events, "abort-command") },
			})
			if err == nil || err.Error() != tc.want || !errors.Is(err, ErrDenied) {
				t.Fatalf("boundary error = %v, want %q", err, tc.want)
			}
			if strings.Contains(strings.Join(events, ","), "release-command") {
				t.Fatalf("failed boundary released blocked command: %v", events)
			}
			if len(events) == 0 || events[len(events)-1] != "abort-command" {
				t.Fatalf("failed boundary did not abort blocked command: %v", events)
			}
		})
	}
}

func TestValidateSandboxRootMetadataRequiresFreshPrivateTmpfs(t *testing.T) {
	previous := unix.Stat_t{Dev: 10, Mode: unix.S_IFDIR | 0o700, Uid: 0, Gid: 0}
	root := unix.Stat_t{Dev: 11, Mode: unix.S_IFDIR | 0o700, Uid: 0, Gid: 0}
	filesystem := unix.Statfs_t{Type: unix.TMPFS_MAGIC, Flags: unix.ST_NODEV | unix.ST_NOSUID}
	if err := validateSandboxRootMetadata(previous, root, filesystem); err != nil {
		t.Fatalf("valid sandbox root rejected: %v", err)
	}
	for _, tc := range []struct {
		name       string
		root       unix.Stat_t
		filesystem unix.Statfs_t
	}{
		{name: "same filesystem", root: unix.Stat_t{Dev: 10, Mode: unix.S_IFDIR | 0o700}, filesystem: filesystem},
		{name: "wrong type", root: root, filesystem: unix.Statfs_t{Type: unix.EXT4_SUPER_MAGIC, Flags: unix.ST_NODEV | unix.ST_NOSUID}},
		{name: "missing nodev", root: root, filesystem: unix.Statfs_t{Type: unix.TMPFS_MAGIC, Flags: unix.ST_NOSUID}},
		{name: "missing nosuid", root: root, filesystem: unix.Statfs_t{Type: unix.TMPFS_MAGIC, Flags: unix.ST_NODEV}},
		{name: "writable mode bits", root: unix.Stat_t{Dev: 11, Mode: unix.S_IFDIR | 0o770}, filesystem: filesystem},
		{name: "wrong owner", root: unix.Stat_t{Dev: 11, Mode: unix.S_IFDIR | 0o700, Uid: 1}, filesystem: filesystem},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateSandboxRootMetadata(previous, tc.root, tc.filesystem); !errors.Is(err, ErrDenied) {
				t.Fatalf("invalid sandbox root error = %v, want ErrDenied", err)
			}
		})
	}
}

func TestSameSandboxRootIdentityRequiresExactDirectory(t *testing.T) {
	admitted := unix.Stat_t{Dev: 10, Ino: 20, Mode: unix.S_IFDIR | 0o700, Uid: 30, Gid: 40}
	if !sameSandboxRootIdentity(admitted, admitted) {
		t.Fatal("exact admitted root identity rejected")
	}
	for _, changed := range []unix.Stat_t{
		{Dev: 11, Ino: 20, Mode: unix.S_IFDIR | 0o700, Uid: 30, Gid: 40},
		{Dev: 10, Ino: 21, Mode: unix.S_IFDIR | 0o700, Uid: 30, Gid: 40},
		{Dev: 10, Ino: 20, Mode: unix.S_IFREG | 0o700, Uid: 30, Gid: 40},
		{Dev: 10, Ino: 20, Mode: unix.S_IFDIR | 0o755, Uid: 30, Gid: 40},
		{Dev: 10, Ino: 20, Mode: unix.S_IFDIR | 0o700, Uid: 31, Gid: 40},
		{Dev: 10, Ino: 20, Mode: unix.S_IFDIR | 0o700, Uid: 30, Gid: 41},
	} {
		if sameSandboxRootIdentity(admitted, changed) {
			t.Fatalf("changed root identity accepted: %+v", changed)
		}
	}
}

func TestSandboxRootTargetMetadataRequiresExactFreshDirectory(t *testing.T) {
	parent := unix.Stat_t{Dev: 10, Ino: 20, Mode: unix.S_IFDIR | 0o1777}
	target := unix.Stat_t{Dev: 10, Ino: 21, Mode: unix.S_IFDIR, Uid: 30, Gid: 40}
	if !validSandboxRootTarget(parent, target, 30, 40) {
		t.Fatal("valid fresh sandbox root target rejected")
	}
	for _, changed := range []unix.Stat_t{
		{Dev: 11, Ino: 21, Mode: unix.S_IFDIR, Uid: 30, Gid: 40},
		{Dev: 10, Ino: 20, Mode: unix.S_IFDIR, Uid: 30, Gid: 40},
		{Dev: 10, Ino: 21, Mode: unix.S_IFDIR | 0o700, Uid: 30, Gid: 40},
		{Dev: 10, Ino: 21, Mode: unix.S_IFDIR | unix.S_ISGID, Uid: 30, Gid: 40},
		{Dev: 10, Ino: 21, Mode: unix.S_IFREG, Uid: 30, Gid: 40},
		{Dev: 10, Ino: 21, Mode: unix.S_IFDIR, Uid: 31, Gid: 40},
		{Dev: 10, Ino: 21, Mode: unix.S_IFDIR, Uid: 30, Gid: 41},
	} {
		if validSandboxRootTarget(parent, changed, 30, 40) {
			t.Fatalf("changed sandbox root target accepted: %+v", changed)
		}
	}
}

func TestSandboxExecArgvPreservesArgv0AndPositionalArguments(t *testing.T) {
	if got := sandboxExecArgv(nil); len(got) != 1 || got[0] != "/app/entry" {
		t.Fatalf("empty argv = %#v, want default argv0", got)
	}
	input := []string{"sh", "-eu", "/app/service"}
	got := sandboxExecArgv(input)
	if len(got) != len(input) {
		t.Fatalf("argv length = %d, want %d", len(got), len(input))
	}
	for i := range input {
		if got[i] != input[i] {
			t.Fatalf("argv[%d] = %q, want %q", i, got[i], input[i])
		}
	}
	got[0] = "changed"
	if input[0] != "sh" {
		t.Fatal("argv helper aliased caller input")
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
