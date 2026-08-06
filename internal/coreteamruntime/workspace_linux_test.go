//go:build linux

package coreteamruntime

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/pisandbox"
)

func TestPiRunnerPreparesExistingWorkspaceTreeForPiIdentity(t *testing.T) {
	process := &fakeProcessRunner{stdout: validPiEventStream()}
	runner := newTestPiRunner(t, process)
	workspace := filepath.Join(runner.workspaceRoot, "repository")
	nested := filepath.Join(workspace, "nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(nested, "source.txt")
	executable := filepath.Join(workspace, "verify.sh")
	if err := os.WriteFile(regular, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0o500); err != nil {
		t.Fatal(err)
	}

	_, failure, err := runner.Run(t.Context(), validRuntimeAssignment(), Workspace{
		Directory: workspace, ContextJSON: []byte(`{}`), Credential: []byte("scoped-test-credential-1234567890"),
	})
	if err != nil || failure.Valid() {
		t.Fatalf("run error=%v failure=%+v", err, failure)
	}
	for path, mode := range map[string]os.FileMode{
		workspace: 0o770, nested: 0o770, regular: 0o660, executable: 0o770,
	} {
		state, statErr := os.Lstat(path)
		if statErr != nil {
			t.Fatal(statErr)
		}
		stat, ok := state.Sys().(*syscall.Stat_t)
		if !ok || stat.Gid != pisandbox.OfficialWorkerGID || state.Mode().Perm() != mode {
			t.Fatalf("path=%s mode=%#o stat=%+v", path, state.Mode().Perm(), stat)
		}
	}
}

func TestPiRunnerRejectsHardlinkedWorkspaceFiles(t *testing.T) {
	process := &fakeProcessRunner{stdout: validPiEventStream()}
	runner := newTestPiRunner(t, process)
	workspace := filepath.Join(runner.workspaceRoot, "repository")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(workspace, "source.txt")
	if err := os.WriteFile(original, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, filepath.Join(workspace, "alias.txt")); err != nil {
		t.Fatal(err)
	}

	_, _, err := runner.Run(t.Context(), validRuntimeAssignment(), Workspace{
		Directory: workspace, ContextJSON: []byte(`{}`), Credential: []byte("scoped-test-credential-1234567890"),
	})
	if !errors.Is(err, ErrInvalid) || process.calls != 0 {
		t.Fatalf("err=%v process calls=%d", err, process.calls)
	}
}

func TestPreparedWorkspaceSupportsGitAsPiIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("credential transition requires root or the production capability set")
	}
	if _, err := os.Stat("/usr/bin/git"); err != nil {
		t.Skip("git is not installed")
	}
	root, err := os.MkdirTemp("", "dirextalk-git-workspace-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	workspace := filepath.Join(root, "repository")
	if output, initErr := exec.Command("/usr/bin/git", "init", "--quiet", workspace).CombinedOutput(); initErr != nil {
		t.Fatalf("git init: %v output=%q", initErr, output)
	}
	if err := os.WriteFile(filepath.Join(workspace, "source.txt"), []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := preparePiWorkspace(root); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/bin/git", "-C", workspace, "status", "--porcelain")
	command.Env = []string{
		"PATH=/usr/bin:/bin", "HOME=" + root, "GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=safe.directory", "GIT_CONFIG_VALUE_0=" + workspace,
	}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: pisandbox.OfficialPiUID, Gid: pisandbox.OfficialPiGID, Groups: []uint32{},
	}}
	if output, statusErr := command.CombinedOutput(); statusErr != nil {
		t.Fatalf("git status as Pi: %v output=%q", statusErr, output)
	}
}

func TestRecoverPiWorkspaceNormalizesPrivatePiOwnedEntries(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Pi ownership transition requires root or the production capability set")
	}
	workspace, err := os.MkdirTemp("", "dirextalk-pi-workspace-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(workspace) })
	if err := preparePiWorkspace(workspace); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(workspace, "private")
	file := filepath.Join(private, "result.txt")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("result"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{file, private} {
		if err := os.Chown(path, pisandbox.OfficialPiUID, pisandbox.OfficialPiGID); err != nil {
			t.Fatal(err)
		}
	}
	if err := recoverPiWorkspace(workspace); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{private: 0o770, file: 0o660} {
		state, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		stat := state.Sys().(*syscall.Stat_t)
		if stat.Uid != pisandbox.OfficialPiUID || stat.Gid != pisandbox.OfficialPiGID || state.Mode().Perm() != mode {
			t.Fatalf("path=%s mode=%#o stat=%+v", path, state.Mode().Perm(), stat)
		}
	}
	if err := preparePiWorkspace(workspace); err != nil {
		t.Fatalf("normalized Pi workspace cannot be reused: %v", err)
	}
}

func TestCleanupPiJobRootRemovesPrivatePiOwnedEntries(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Pi ownership transition requires root or the production capability set")
	}
	stateRoot := t.TempDir()
	jobRoot := filepath.Join(stateRoot, "pi-role-test")
	private := filepath.Join(jobRoot, "private")
	if err := os.MkdirAll(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(private, "state"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(private, pisandbox.OfficialPiUID, pisandbox.OfficialPiGID); err != nil {
		t.Fatal(err)
	}
	if err := cleanupPiJobRoot(stateRoot, jobRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(jobRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("job root survived cleanup: %v", err)
	}
}

func TestWorkerFilesystemCapabilitiesRecoverAndCleanupPiOwnedFiles(t *testing.T) {
	root, err := os.MkdirTemp("", "dirextalk-worker-capability-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := preparePiDirectory(root); err != nil {
		t.Skipf("Worker filesystem capability unavailable: %v", err)
	}
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := preparePiWorkspace(workspace); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(workspace, "private")
	if err := withPiFilesystemIdentity(func() error {
		if err := os.Mkdir(private, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(private, "result.txt"), []byte("result"), 0o600)
	}); err != nil {
		t.Skipf("Worker filesystem capability unavailable: %v", err)
	}
	if err := recoverPiWorkspace(workspace); err != nil {
		t.Fatal(err)
	}
	state, err := os.Lstat(filepath.Join(private, "result.txt"))
	if err != nil {
		t.Fatal(err)
	}
	stat := state.Sys().(*syscall.Stat_t)
	if stat.Uid != pisandbox.OfficialPiUID || stat.Gid != pisandbox.OfficialPiGID || state.Mode().Perm() != piWorkspaceFileMode {
		t.Fatalf("mode=%#o stat=%+v", state.Mode().Perm(), stat)
	}
	jobRoot := filepath.Join(root, "pi-role-private")
	if err := withPiFilesystemIdentity(func() error {
		if err := os.Mkdir(jobRoot, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(jobRoot, "state"), []byte("private"), 0o600)
	}); err != nil {
		t.Fatal(err)
	}
	if err := cleanupPiJobRoot(root, jobRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(jobRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("job root survived cleanup: %v", err)
	}
}
