//go:build linux

package extensionrunner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestUnavailableAtUsesSafeStableStages(t *testing.T) {
	for _, stage := range []string{
		"validate/probe", "child_start", "release",
		"cgroup_create", "cgroup_memory", "cgroup_swap", "cgroup_oom", "cgroup_pids", "cgroup_cpu", "cgroup_attach",
	} {
		t.Run(stage, func(t *testing.T) {
			err := unavailableAt(stage)
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("errors.Is(%v, ErrUnavailable) = false", err)
			}
			want := "extension runner unavailable at " + stage + ": extension runner unavailable"
			if err.Error() != want {
				t.Fatalf("safe diagnostic = %q, want %q", err, want)
			}
		})
	}
}

func TestReadinessStagesContainNoRuntimeDetail(t *testing.T) {
	for _, stage := range []string{
		"probe_context", "cgroup_root", "cgroup_filesystem", "cgroup_controllers", "cgroup_delegation",
		"probe_identity", "probe_cgroup_create", "probe_cgroup_limits", "probe_executable", "probe_release_pipe",
		"probe_child_start", "probe_cgroup_attach", "probe_child_wait", "probe_cgroup_empty", "probe_cgroup_remove",
		"sandbox_root", "sandbox_install_root", "sandbox_workspace_root", "sandbox_executable", "sandbox_entry",
		"sandbox_publish", "sandbox_admit", "sandbox_workspace", "sandbox_identity", "sandbox_request", "sandbox_start", "sandbox_wait",
	} {
		err := unavailableAt(stage)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("stage %q lost unavailable sentinel", stage)
		}
		for _, forbidden := range []string{"/", "errno", "permission denied", "secret"} {
			if strings.Contains(err.Error(), forbidden) {
				t.Fatalf("stage %q leaked runtime detail %q: %q", stage, forbidden, err)
			}
		}
	}
}

func TestSetupCgroupReturnsSafeCreateStage(t *testing.T) {
	err := setupCgroup(filepath.Join(t.TempDir(), "missing", "child"), LimitsV2{}, 1)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("errors.Is(%v, ErrUnavailable) = false", err)
	}
	if got, want := err.Error(), "extension runner unavailable at cgroup_create: extension runner unavailable"; got != want {
		t.Fatalf("safe diagnostic = %q, want %q", got, want)
	}
}

func TestCgroupSettingsConstrainMemoryAndSwapBeforeRelease(t *testing.T) {
	settings := cgroupSettings(LimitsV2{MemoryBytes: 123, Processes: 4}, 99)
	if len(settings) < 2 || settings[0].n != "memory.max" || settings[0].v != "123" || settings[1].n != "memory.swap.max" || settings[1].v != "0" {
		t.Fatalf("memory limits are not first cgroup settings: %#v", settings)
	}
}

func TestSandboxChildDoesNotUsePdeathsigAcrossPIDNamespace(t *testing.T) {
	pidfd := -1
	attr := sandboxChildSysProcAttr(&pidfd)
	if attr.Pdeathsig != 0 {
		t.Fatalf("PID namespace child has Pdeathsig=%v", attr.Pdeathsig)
	}
	wantNamespaces := uintptr(unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWIPC | unix.CLONE_NEWNET)
	if attr.Cloneflags != wantNamespaces || attr.PidFD != &pidfd {
		t.Fatalf("sandbox child attributes = %+v", attr)
	}
}

func TestCoreCgroupLimitsIncludeTrustedManagerOverhead(t *testing.T) {
	base := LimitsV2{MemoryBytes: 16 << 20, Processes: 8}
	ordinary, err := effectiveCgroupLimits(SandboxInvocationV2{Request: RequestV2{Limits: base}})
	if err != nil || ordinary != base {
		t.Fatalf("ordinary limits = %+v, err=%v", ordinary, err)
	}
	core, err := effectiveCgroupLimits(SandboxInvocationV2{Request: RequestV2{Limits: base}, CoreTmpfsBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if core.MemoryBytes != base.MemoryBytes+coreManagerMemoryOverheadBytes || core.Processes != base.Processes+coreManagerProcessOverhead {
		t.Fatalf("core limits = %+v", core)
	}
}

func TestCoreCgroupLimitOverheadFailsClosedOnOverflow(t *testing.T) {
	maxInt64 := int64(^uint64(0) >> 1)
	for _, limits := range []LimitsV2{
		{MemoryBytes: maxInt64 - coreManagerMemoryOverheadBytes + 1, Processes: 1},
		{MemoryBytes: 1, Processes: maxInt64 - coreManagerProcessOverhead + 1},
	} {
		if _, err := effectiveCgroupLimits(SandboxInvocationV2{Request: RequestV2{Limits: limits}, CoreTmpfsBytes: 1}); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("overflow limits %+v err=%v", limits, err)
		}
	}
}

func TestCgroupCleanupFailsClosedOnPopulatedOrRemoveFailure(t *testing.T) {
	for _, test := range []struct {
		name   string
		events []string
		remove error
	}{
		{name: "populated", events: []string{"populated 1\n"}},
		{name: "remove", events: []string{"populated 0\n"}, remove: errors.New("remove")},
	} {
		t.Run(test.name, func(t *testing.T) {
			index := 0
			removed := false
			ops := cgroupOps{
				read: func(string) ([]byte, error) {
					value := test.events[min(index, len(test.events)-1)]
					index++
					return []byte(value), nil
				},
				remove: func(string) error { removed = true; return test.remove },
				sleep:  func(time.Duration) {},
			}
			err := cleanupCgroup(ops, "/safe-cgroup")
			if !errors.Is(err, errCgroupCleanup) {
				t.Fatalf("cleanup error=%v, want cleanup sentinel", err)
			}
			if test.name == "populated" && removed {
				t.Fatal("populated cgroup was removed")
			}
		})
	}
}

func TestKillGroupRequiresCgroupKillSuccess(t *testing.T) {
	writes := 0
	p := &reexecProcess{cgroup: "/safe-cgroup", cgroupOps: cgroupOps{
		write: func(path string, body []byte, mode os.FileMode) error {
			writes++
			if path != "/safe-cgroup/cgroup.kill" || string(body) != "1" || mode != 0 {
				t.Fatalf("kill write=%q %q %#o", path, body, mode)
			}
			return errors.New("write")
		},
	}}
	if err := p.KillGroup(); !errors.Is(err, errCgroupCleanup) || writes != 1 {
		t.Fatalf("KillGroup err=%v writes=%d", err, writes)
	}
}

func TestSetupCleanupPropagatesRemovalFailure(t *testing.T) {
	err := cleanupSetupCgroup(cgroupOps{
		read:   func(string) ([]byte, error) { return []byte("populated 0\n"), nil },
		remove: func(string) error { return errors.New("remove") },
		sleep:  func(time.Duration) {},
	}, "/safe-cgroup")
	if !errors.Is(err, errCgroupCleanup) {
		t.Fatalf("setup cleanup error=%v, want cleanup sentinel", err)
	}
}

func TestSandboxRlimitsLeaveProcessCountToCgroup(t *testing.T) {
	for _, setting := range sandboxRlimitSettings(LimitsV2{Processes: 1}) {
		if setting.resource == unix.RLIMIT_NPROC {
			t.Fatal("RLIMIT_NPROC duplicates cgroup pids.max and is per-UID rather than per-task")
		}
	}
	settings := cgroupSettings(LimitsV2{Processes: 1}, 9)
	if len(settings) < 4 || settings[3].n != "pids.max" || settings[3].v != "1" {
		t.Fatalf("per-task pids limit missing: %#v", settings)
	}
}

type stageErrorBackend struct{ err error }

func (b stageErrorBackend) Probe(context.Context) error { return nil }
func (b stageErrorBackend) StartV2(context.Context, SandboxInvocationV2) (Process, error) {
	return nil, b.err
}

type stageInstallResolver struct{}

func (stageInstallResolver) ResolveInstall(string) (*AdmittedInstall, error) {
	return &AdmittedInstall{}, nil
}

type stageWorkspaceResolver struct{ path string }

func (r stageWorkspaceResolver) ResolveWorkspace(string, string) (int, error) {
	return unix.Open(r.path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}

func TestRunnerPreservesStartV2StageError(t *testing.T) {
	startErr := unavailableAt("child_start")
	runner := Runner{
		InstallResolver:   stageInstallResolver{},
		WorkspaceResolver: stageWorkspaceResolver{path: t.TempDir()},
		V2Backend:         stageErrorBackend{err: startErr},
	}
	status, err := runner.RunV2(context.Background(), clientProtocolRequest(), nil, NewRunRegistry())
	if err != startErr {
		t.Fatalf("RunV2 error = %v, want original StartV2 error %v", err, startErr)
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("errors.Is(%v, ErrUnavailable) = false", err)
	}
	if status.Error != ErrorUnavailableBackend || status.Phase != PhaseFailed {
		t.Fatalf("status = %+v, want unavailable failed status", status)
	}
}

type cleanupFailureProcess struct{}

func (cleanupFailureProcess) Wait() ([]byte, []byte, string, error) {
	return nil, nil, "failed", errCgroupCleanup
}
func (cleanupFailureProcess) KillGroup() error { return errCgroupCleanup }
func (cleanupFailureProcess) WaitContext(ctx context.Context) ([]byte, []byte, string, error) {
	return nil, nil, "failed", errors.Join(ctx.Err(), errCgroupCleanup)
}

type cleanupFailureBackend struct{}

func (cleanupFailureBackend) Probe(context.Context) error { return nil }
func (cleanupFailureBackend) StartV2(context.Context, SandboxInvocationV2) (Process, error) {
	return cleanupFailureProcess{}, nil
}

func TestRunnerDoesNotReportCancellationWhenCgroupCleanupIsUnproven(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := Runner{
		InstallResolver:   stageInstallResolver{},
		WorkspaceResolver: stageWorkspaceResolver{path: t.TempDir()},
		V2Backend:         cleanupFailureBackend{},
	}
	status, err := runner.RunV2(ctx, clientProtocolRequest(), nil, NewRunRegistry())
	if err != nil || status.Error != ErrorCleanup {
		t.Fatalf("status=%+v err=%v, want cleanup failure", status, err)
	}
}
