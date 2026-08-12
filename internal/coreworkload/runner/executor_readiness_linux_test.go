//go:build linux

package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
	"golang.org/x/sys/unix"
)

func TestReadinessDiagnosticIsLowCardinality(t *testing.T) {
	err := unavailableAt("cgroup_root")
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("readiness error lost denied sentinel: %v", err)
	}
	stage, ok := ReadinessStage(err)
	if !ok || stage != "cgroup_root" {
		t.Fatalf("stage=%q ok=%v", stage, ok)
	}
	for _, forbidden := range []string{"/", "errno", "permission denied"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("diagnostic leaked forbidden detail %q: %q", forbidden, err)
		}
	}
}

func TestInstallReadinessDiagnosticIsFixedAndRedacted(t *testing.T) {
	err := installUnavailableAt("sandbox")
	stage, ok := installReadinessStage(err)
	if !ok || stage != "sandbox" || !errors.Is(err, ErrDenied) {
		t.Fatalf("stage=%q ok=%v err=%v", stage, ok, err)
	}
	if err.Error() != "core install unavailable" || strings.Contains(err.Error(), "/") || strings.Contains(err.Error(), "permission") {
		t.Fatalf("install diagnostic leaked detail: %q", err.Error())
	}
}

func TestInstallSandboxUnavailablePreservesOnlyTypedExtensionStage(t *testing.T) {
	source := (extensionrunner.LinuxBackend{}).Probe(context.Background())
	err := installSandboxUnavailable(source)
	stage, ok := installReadinessStage(err)
	if !ok || stage != "sandbox_cgroup_root" || !errors.Is(err, ErrDenied) {
		t.Fatalf("stage=%q ok=%v err=%v", stage, ok, err)
	}
	err = installSandboxUnavailable(errors.New("raw /private/path"))
	stage, ok = installReadinessStage(err)
	if !ok || stage != "sandbox" || strings.Contains(err.Error(), "private") {
		t.Fatalf("fallback stage=%q ok=%v err=%v", stage, ok, err)
	}
}

func TestSandboxReadinessStageUsesOnlyTypedExtensionStage(t *testing.T) {
	source := (extensionrunner.LinuxBackend{}).Probe(context.Background())
	if got := sandboxReadinessStage(source); got != "sandbox_cgroup_root" {
		t.Fatalf("typed stage=%q", got)
	}
	if got := sandboxReadinessStage(errors.New("raw /private/path")); got != "sandbox" {
		t.Fatalf("raw stage=%q", got)
	}
}

func TestCoreReadinessBudgetCoversRealSandboxStartup(t *testing.T) {
	if coreReadinessMemoryMB < 64 || coreReadinessProcesses < 16 || coreReadinessTimeoutS < 5 || coreReadinessDeadline < 30*time.Second {
		t.Fatalf("readiness budget too small: memory_mb=%d processes=%d timeout_s=%d deadline=%s", coreReadinessMemoryMB, coreReadinessProcesses, coreReadinessTimeoutS, coreReadinessDeadline)
	}
}

func TestCgroupRootAllowsReadExecuteButNeverGroupWorldWrite(t *testing.T) {
	owner := uint32(os.Geteuid())
	fs := unix.Statfs_t{Type: unix.CGROUP2_SUPER_MAGIC}
	base := unix.Stat_t{Mode: unix.S_IFDIR | 0o755, Uid: owner}
	if !safeCgroupStat(base, fs, owner) {
		t.Fatal("owner-controlled 0755 cgroup2 root rejected")
	}
	for _, mode := range []uint32{0o775, 0o757, 0o777} {
		st := base
		st.Mode = unix.S_IFDIR | mode
		if safeCgroupStat(st, fs, owner) {
			t.Fatalf("writable cgroup root %#o accepted", mode)
		}
	}
	foreign := base
	foreign.Uid++
	if safeCgroupStat(foreign, fs, owner) {
		t.Fatal("foreign-owned cgroup root accepted")
	}
	nonCgroup := fs
	nonCgroup.Type = 0
	if safeCgroupStat(base, nonCgroup, owner) {
		t.Fatal("non-cgroup2 filesystem accepted")
	}
}

func TestPrivateRootsStillRequire0700(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if absolutePrivateDir(root) {
		t.Fatal("0755 private root accepted")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if !absolutePrivateDir(root) {
		t.Fatal("0700 owner root rejected")
	}
	if absolutePrivateDir(filepath.Join(root, "missing")) {
		t.Fatal("missing private root accepted")
	}
}
