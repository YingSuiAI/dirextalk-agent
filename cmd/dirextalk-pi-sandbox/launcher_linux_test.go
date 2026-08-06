//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/pisandbox"
)

const launcherHelperEnvironment = "DIREXTALK_PI_SANDBOX_TEST_HELPER"

func TestLauncherAppliesPolicyClosesDescriptorsAndExecutesPi(t *testing.T) {
	runtimeDirectory := filepath.Dir(officialPiExecutable)
	if err := os.MkdirAll(runtimeDirectory, 0o755); err != nil {
		t.Skipf("official test path unavailable: %v", err)
	}
	for directory := runtimeDirectory; directory != "/opt"; directory = filepath.Dir(directory) {
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Skipf("official test path unavailable: %v", err)
		}
	}
	defer os.Remove(officialPiExecutable)
	script := `#!/bin/sh
set -eu
test "$(id -u)" = 65533
cap_eff=
while read -r name value; do
  if [ "$name" = CapEff: ]; then
    cap_eff=$value
    break
  fi
done < /proc/self/status
test "$cap_eff" = 0000000000000000
test "$(cat "$1/runtime")" = qualified
printf ok > "$1/result"
if IFS= read -r value < "$2/mtls-key"; then exit 20; fi
if IFS= read -r value < "/proc/$PPID/environ"; then exit 21; fi
if [ -e /proc/self/fd/3 ]; then exit 22; fi
if chmod 0644 "$2/mtls-key" 2>/dev/null; then exit 23; fi
`
	if err := os.WriteFile(officialPiExecutable, []byte(script), 0o555); err != nil {
		t.Skipf("official test executable unavailable: %v", err)
	}
	if err := os.Chmod(officialPiExecutable, 0o555); err != nil {
		t.Skipf("official test executable unavailable: %v", err)
	}
	workspaceParent, err := os.MkdirTemp("", "dirextalk-pi-sandbox-workspace-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(workspaceParent) })
	if err := os.Chown(workspaceParent, -1, pisandbox.OfficialPiGID); err != nil {
		t.Fatalf("prepare shared workspace parent: %v", err)
	}
	if err := os.Chmod(workspaceParent, 0o770); err != nil {
		t.Fatalf("prepare shared workspace parent: %v", err)
	}
	workspace := filepath.Join(workspaceParent, "workspace")
	control := filepath.Join(t.TempDir(), "control")
	for _, directory := range []string{workspace, control} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(workspace, "runtime"), []byte("qualified"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(workspace, -1, pisandbox.OfficialPiGID); err != nil {
		t.Fatalf("prepare shared workspace: %v", err)
	}
	if err := os.Chmod(workspace, 0o770); err != nil {
		t.Fatalf("prepare shared workspace: %v", err)
	}
	runtimePath := filepath.Join(workspace, "runtime")
	if err := os.Chown(runtimePath, -1, pisandbox.OfficialPiGID); err != nil {
		t.Fatalf("prepare shared runtime: %v", err)
	}
	if err := os.Chmod(runtimePath, 0o640); err != nil {
		t.Fatalf("prepare shared runtime: %v", err)
	}
	if err := os.WriteFile(filepath.Join(control, "mtls-key"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := []string{
		"--landlock-abi", "2",
		"--rx", filepath.Dir(filepath.Dir(officialPiExecutable)),
		"--rx", "/usr/bin",
	}
	for _, path := range []string{"/usr/lib", "/usr/lib64", "/lib", "/lib64"} {
		if _, err := os.Stat(path); err == nil {
			arguments = append(arguments, "--rx", path)
		}
	}
	arguments = append(arguments,
		"--rw", "/dev/null",
		"--ro", "/proc/self",
		"--rwx", workspace,
		"--", officialPiExecutable, workspace, control,
	)
	launcherRoot, err := os.MkdirTemp("", "dirextalk-pi-sandbox-launcher-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(launcherRoot) })
	if err := os.Chmod(launcherRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	launcherPath := filepath.Join(launcherRoot, "dirextalk-pi-sandbox.test")
	launcherContent, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcherPath, launcherContent, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(launcherPath, 0o555); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(launcherPath, append([]string{"-test.run=^TestLauncherHelper$", "--"}, arguments...)...)
	command.Env = append(os.Environ(), launcherHelperEnvironment+"=1")
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: pisandbox.OfficialPiUID, Gid: pisandbox.OfficialPiGID, Groups: []uint32{},
	}}
	extra, err := os.Open(filepath.Join(control, "mtls-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	command.ExtraFiles = []*os.File{extra}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("launcher failed: %v output=%q", err, output)
	}
	if result, err := os.ReadFile(filepath.Join(workspace, "result")); err != nil || string(result) != "ok" {
		t.Fatalf("result=%q err=%v", result, err)
	}
	state, err := os.Stat(filepath.Join(control, "mtls-key"))
	if err != nil {
		t.Fatal(err)
	}
	if state.Mode().Perm() != 0o600 {
		t.Fatalf("control key mode=%v", state.Mode().Perm())
	}
}

func TestLauncherHelper(t *testing.T) {
	if os.Getenv(launcherHelperEnvironment) != "1" {
		return
	}
	separator := 0
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator == 0 || separator+1 >= len(os.Args) {
		os.Exit(90)
	}
	policy, target, arguments, err := parseLaunch(os.Args[separator+1:])
	if err != nil {
		os.Exit(91)
	}
	switch launch(policy, target, arguments) {
	case nil:
		return
	case errLaunchControl:
		os.Exit(92)
	case errLaunchIdentity:
		os.Exit(93)
	case errLaunchPolicy:
		os.Exit(94)
	case errLaunchDescriptors:
		os.Exit(95)
	default:
		os.Exit(96)
	}
}
