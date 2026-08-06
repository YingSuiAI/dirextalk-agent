//go:build linux

package runner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
