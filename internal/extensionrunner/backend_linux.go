//go:build linux

package extensionrunner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// LinuxBackend uses Go's fork/exec implementation: raw clone in a Go process
// is unsafe.  Missing any kernel primitive is an availability failure.
type LinuxBackend struct {
	CgroupRoot string
	// ReexecPath is a trusted integration seam. Production leaves it empty and
	// always re-executes /proc/self/exe.
	ReexecPath string
}

// unavailableAt keeps Linux isolation diagnostics low-cardinality and safe to
// return to trusted local callers. It deliberately excludes paths, errno, and
// underlying OS error text.
func unavailableAt(stage string) error {
	return fmt.Errorf("extension runner unavailable at %s: %w", stage, ErrUnavailable)
}

func (b LinuxBackend) Probe(ctx context.Context) error {
	_ = ctx
	if b.CgroupRoot == "" || !filepath.IsAbs(b.CgroupRoot) {
		return unavailableAt("validate/probe")
	}
	var fs unix.Statfs_t
	if unix.Statfs(b.CgroupRoot, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return unavailableAt("validate/probe")
	}
	procs, e := os.OpenFile(filepath.Join(b.CgroupRoot, "cgroup.procs"), os.O_WRONLY, 0)
	if e != nil {
		return unavailableAt("validate/probe")
	}
	if e = procs.Close(); e != nil {
		return unavailableAt("validate/probe")
	}
	return nil
}

type bootstrapV1 struct {
	Request     RequestV2 `json:"request"`
	SecretCount int       `json:"secret_count"`
	HasStdin    bool      `json:"has_stdin"`
	RootDev     uint64    `json:"root_dev"`
	RootIno     uint64    `json:"root_ino"`
	EntryDev    uint64    `json:"entry_dev"`
	EntryIno    uint64    `json:"entry_ino"`
	EntryMode   uint32    `json:"entry_mode"`
	EntrySize   int64     `json:"entry_size"`
	EntrySHA256 string    `json:"entry_sha256"`
}

func (b LinuxBackend) StartV2(ctx context.Context, inv SandboxInvocationV2) (Process, error) {
	if b.Probe(ctx) != nil || inv.Install == nil || inv.WorkspaceFD < 0 {
		return nil, unavailableAt("validate/probe")
	}
	self := b.ReexecPath
	if self == "" {
		self = "/proc/self/exe"
	} else {
		var stat unix.Stat_t
		if !filepath.IsAbs(self) ||
			filepath.Clean(self) != self ||
			unix.Stat(self, &stat) != nil ||
			stat.Mode&unix.S_IFMT != unix.S_IFREG ||
			stat.Uid != uint32(os.Geteuid()) ||
			stat.Mode&0o022 != 0 ||
			stat.Mode&0o111 == 0 {
			return nil, unavailableAt("reexec")
		}
	}
	if err := unix.Access(self, unix.X_OK); err != nil {
		return nil, unavailableAt("reexec")
	}
	bs, err := json.Marshal(bootstrapV1{
		Request:     inv.Request,
		SecretCount: len(inv.SecretFDs),
		HasStdin:    inv.StdinFD >= 0,
		RootDev:     inv.Install.RootDev,
		RootIno:     inv.Install.RootIno,
		EntryDev:    inv.Install.EntryDev,
		EntryIno:    inv.Install.EntryIno,
		EntryMode:   inv.Install.EntryMode,
		EntrySize:   inv.Install.EntrySize,
		EntrySHA256: inv.Install.EntrySHA256,
	})
	if err != nil {
		return nil, unavailableAt("bootstrap")
	}
	boot, err := sealedMemfd("bootstrap", bs)
	if err != nil {
		return nil, unavailableAt("bootstrap")
	}
	defer unix.Close(boot)
	releaseR, releaseW, err := os.Pipe()
	if err != nil {
		return nil, unavailableAt("release_pipe")
	}
	defer releaseW.Close()
	root, err := inv.Install.DupRootFD()
	if err != nil {
		releaseR.Close()
		return nil, unavailableAt("install_fd")
	}
	defer unix.Close(root)
	entry, err := inv.Install.DupEntryFD()
	if err != nil {
		releaseR.Close()
		return nil, unavailableAt("install_fd")
	}
	defer unix.Close(entry)
	extra := func(fd int, name string) (*os.File, error) {
		dup, e := unix.Dup(fd)
		if e != nil {
			return nil, e
		}
		return os.NewFile(uintptr(dup), name), nil
	}
	files := make([]*os.File, 0, 5+len(inv.SecretFDs)+1)
	for _, item := range []struct {
		fd   int
		name string
	}{{boot, "bootstrap"}, {int(releaseR.Fd()), "release"}, {root, "install"}, {entry, "entry"}, {inv.WorkspaceFD, "workspace"}} {
		f, e := extra(item.fd, item.name)
		if e != nil {
			releaseR.Close()
			for _, x := range files {
				_ = x.Close()
			}
			return nil, unavailableAt("extra_files")
		}
		files = append(files, f)
	}
	if inv.StdinFD >= 0 {
		f, e := extra(inv.StdinFD, "stdin")
		if e != nil {
			releaseR.Close()
			for _, x := range files {
				_ = x.Close()
			}
			return nil, unavailableAt("extra_files")
		}
		files = append(files, f)
	}
	for _, fd := range inv.SecretFDs {
		f, e := extra(fd, "secret")
		if e != nil {
			releaseR.Close()
			for _, x := range files {
				_ = x.Close()
			}
			return nil, unavailableAt("extra_files")
		}
		files = append(files, f)
	}
	var pidfd int
	cmd := exec.Command(self, "__sandbox-child-v1")
	cmd.ExtraFiles = files
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWIPC | unix.CLONE_NEWNET, Unshareflags: 0, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}}, GidMappingsEnableSetgroups: false, Setpgid: true, Pdeathsig: syscall.SIGKILL, PidFD: &pidfd}
	var out, er boundedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &er
	if err = cmd.Start(); err != nil {
		releaseR.Close()
		return nil, unavailableAt("child_start")
	}
	releaseR.Close()
	cg := filepath.Join(b.CgroupRoot, inv.Request.RunID)
	if err = setupCgroup(cg, inv.Request.Limits, cmd.Process.Pid); err != nil {
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		_ = cmd.Wait()
		_ = unix.Close(pidfd)
		return nil, err
	}
	if _, err = releaseW.Write([]byte{1}); err != nil {
		ops := defaultCgroupOps()
		killErr := killCgroup(ops, cg)
		if killErr != nil {
			_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		}
		_ = cmd.Wait()
		_ = unix.Close(pidfd)
		return nil, errors.Join(unavailableAt("release"), killErr, cleanupSetupCgroup(ops, cg))
	}
	_ = releaseW.Close()
	process := &reexecProcess{
		cmd:           cmd,
		pidfd:         pidfd,
		cgroup:        cg,
		out:           &out,
		err:           &er,
		waitDone:      make(chan struct{}),
		cpuStop:       make(chan struct{}),
		cpuDone:       make(chan struct{}),
		cpuBudgetUsec: uint64(inv.Request.Limits.CPUSeconds) * 1_000_000,
		cgroupOps:     defaultCgroupOps(),
	}
	go process.monitorCPU()
	return process, nil
}
func sealedMemfd(n string, b []byte) (int, error) {
	fd, e := unix.MemfdCreate(n, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if e != nil {
		return -1, e
	}
	if _, e = unix.Write(fd, b); e != nil {
		unix.Close(fd)
		return -1, e
	}
	if _, e = unix.Seek(fd, 0, 0); e != nil {
		unix.Close(fd)
		return -1, e
	}
	_, e = unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE)
	if e != nil {
		unix.Close(fd)
		return -1, e
	}
	return fd, e
}
func setupCgroup(p string, l LimitsV2, pid int) (err error) {
	if e := os.Mkdir(p, 0750); e != nil {
		return unavailableAt("cgroup_create")
	}
	ok := false
	defer func() {
		if !ok {
			err = errors.Join(err, cleanupSetupCgroup(defaultCgroupOps(), p))
		}
	}()
	for _, x := range cgroupSettings(l, pid) {
		if e := os.WriteFile(filepath.Join(p, x.n), []byte(x.v), 0644); e != nil {
			return unavailableAt(x.stage)
		}
	}
	ok = true
	return nil
}

func cgroupSettings(l LimitsV2, pid int) []struct{ n, v, stage string } {
	return []struct{ n, v, stage string }{
		{"memory.max", itoa64(l.MemoryBytes), "cgroup_memory"},
		{"memory.swap.max", "0", "cgroup_swap"},
		{"memory.oom.group", "1", "cgroup_oom"},
		{"pids.max", itoa64(l.Processes), "cgroup_pids"},
		{"cpu.max", "100000 100000", "cgroup_cpu"},
		{"cgroup.procs", itoa64(int64(pid)), "cgroup_attach"},
	}
}
func itoa64(v int64) string { return strconv.FormatInt(v, 10) }

func cleanupSetupCgroup(ops cgroupOps, path string) error {
	return cleanupCgroup(ops, path)
}

type cgroupOps struct {
	write  func(string, []byte, os.FileMode) error
	read   func(string) ([]byte, error)
	remove func(string) error
	sleep  func(time.Duration)
}

func defaultCgroupOps() cgroupOps {
	return cgroupOps{write: os.WriteFile, read: os.ReadFile, remove: os.Remove, sleep: time.Sleep}
}

var errCgroupCleanup = errors.New("extension cgroup cleanup failed")

func cgroupCleanupFailure(stage string) error {
	return errors.Join(errCgroupCleanup, unavailableAt(stage))
}

func cleanupCgroup(ops cgroupOps, path string) error {
	if ops.read == nil || ops.remove == nil || ops.sleep == nil {
		ops = defaultCgroupOps()
	}
	if path == "" {
		return cgroupCleanupFailure("cgroup_remove")
	}
	for attempt := 0; attempt < 20; attempt++ {
		body, err := ops.read(filepath.Join(path, "cgroup.events"))
		if err != nil {
			return cgroupCleanupFailure("cgroup_empty")
		}
		empty := false
		fields := strings.Fields(string(body))
		for index := 0; index+1 < len(fields); index += 2 {
			if fields[index] == "populated" {
				empty = fields[index+1] == "0"
				break
			}
		}
		if empty {
			if ops.remove(path) != nil {
				return cgroupCleanupFailure("cgroup_remove")
			}
			return nil
		}
		ops.sleep(10 * time.Millisecond)
	}
	return cgroupCleanupFailure("cgroup_empty")
}

func killCgroup(ops cgroupOps, path string) error {
	if ops.write == nil || path == "" || ops.write(filepath.Join(path, "cgroup.kill"), []byte("1"), 0) != nil {
		return cgroupCleanupFailure("cgroup_kill")
	}
	return nil
}

type boundedBuffer struct{ b []byte }

var (
	errCPULimitExceeded = errors.New("extension CPU limit exceeded")
	errCPUAccounting    = errors.New("extension CPU accounting failed")
)

func (x *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if len(x.b) < MaxOutputBytes {
		k := MaxOutputBytes - len(x.b)
		if k > len(p) {
			k = len(p)
		}
		x.b = append(x.b, p[:k]...)
	}
	return n, nil
}

type reexecProcess struct {
	cmd           *exec.Cmd
	pidfd         int
	cgroup        string
	out, err      *boundedBuffer
	killOnce      sync.Once
	waitOnce      sync.Once
	waitDone      chan struct{}
	waitErr       error
	exitCode      int
	pidMu         sync.Mutex
	cpuStop       chan struct{}
	cpuDone       chan struct{}
	cpuStopOnce   sync.Once
	cpuBudgetUsec uint64
	cpuExceeded   atomic.Bool
	cpuMonitorBad atomic.Bool
	cgroupOps     cgroupOps
	killErr       error
}

// PersistentIdentity is the minimum durable evidence a higher-level
// supervisor may persist. It intentionally carries no host paths except the
// deployment-owned cgroup and never exposes credentials or output.
type PersistentIdentity struct {
	PID       int
	StartTime uint64
	Cgroup    string
}

// PersistentIdentity is available only while the process has not been reaped.
// StartTime comes from /proc/<pid>/stat and prevents PID-reuse acceptance.
func (p *reexecProcess) PersistentIdentity() (PersistentIdentity, error) {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return PersistentIdentity{}, ErrUnavailable
	}
	pid := p.cmd.Process.Pid
	start, err := processStartTime(pid)
	if err != nil {
		return PersistentIdentity{}, ErrUnavailable
	}
	return PersistentIdentity{PID: pid, StartTime: start, Cgroup: p.cgroup}, nil
}

func (p *reexecProcess) Wait() ([]byte, []byte, string, error) {
	p.beginWait()
	<-p.waitDone
	return p.waitResult(p.waitErr)
}
func (p *reexecProcess) WaitContext(ctx context.Context) ([]byte, []byte, string, error) {
	p.beginWait()
	select {
	case <-p.waitDone:
		return p.waitResult(p.waitErr)
	case <-ctx.Done():
		killErr := p.KillGroup()
		<-p.waitDone
		if errors.Is(errors.Join(killErr, p.waitErr), errCgroupCleanup) {
			return p.waitResult(errors.Join(killErr, p.waitErr))
		}
		return append([]byte(nil), p.out.b...), append([]byte(nil), p.err.b...), "failed", ctx.Err()
	}
}
func (p *reexecProcess) beginWait() {
	p.waitOnce.Do(func() {
		go func() {
			p.waitErr = p.cmd.Wait()
			p.exitCode = -1
			if p.cmd.ProcessState != nil {
				p.exitCode = p.cmd.ProcessState.ExitCode()
			}
			p.pidMu.Lock()
			pidfd := p.pidfd
			p.pidfd = -1
			p.pidMu.Unlock()
			if pidfd >= 0 {
				_ = unix.Close(pidfd)
			}
			p.finishCPUMonitor()
			p.waitErr = errors.Join(p.waitErr, cleanupCgroup(p.cgroupOps, p.cgroup))
			close(p.waitDone)
		}()
	})
}
func (p *reexecProcess) waitResult(err error) ([]byte, []byte, string, error) {
	stdout := append([]byte(nil), p.out.b...)
	stderr := append([]byte(nil), p.err.b...)
	if p.cpuExceeded.Load() {
		return stdout, stderr, "cpu_limit", errors.Join(err, errCPULimitExceeded)
	}
	if p.cpuMonitorBad.Load() {
		return stdout, stderr, "cpu_monitor_failed", errors.Join(err, errCPUAccounting)
	}
	if err != nil {
		return stdout, stderr, "failed", err
	}
	return stdout, stderr, "succeeded", nil
}

func (p *reexecProcess) stopCPUMonitor() {
	p.cpuStopOnce.Do(func() { close(p.cpuStop) })
}

// finishCPUMonitor joins the monitor and samples cpu.stat while the cgroup
// still exists, so a process that exits at the budget boundary is classified
// consistently with one killed by the periodic monitor.
func (p *reexecProcess) finishCPUMonitor() {
	p.stopCPUMonitor()
	<-p.cpuDone
	usage, err := readCgroupCPUUsage(filepath.Join(p.cgroup, "cpu.stat"))
	if err != nil {
		p.cpuMonitorBad.Store(true)
		return
	}
	if usage >= p.cpuBudgetUsec {
		p.cpuExceeded.Store(true)
	}
}

func (p *reexecProcess) monitorCPU() {
	defer close(p.cpuDone)
	if p.cpuBudgetUsec == 0 {
		p.cpuMonitorBad.Store(true)
		_ = p.KillGroup()
		return
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.cpuStop:
			return
		case <-ticker.C:
			usage, err := readCgroupCPUUsage(filepath.Join(p.cgroup, "cpu.stat"))
			if err != nil {
				p.cpuMonitorBad.Store(true)
				_ = p.KillGroup()
				return
			}
			if usage >= p.cpuBudgetUsec {
				p.cpuExceeded.Store(true)
				_ = p.KillGroup()
				return
			}
		}
	}
}

func readCgroupCPUUsage(path string) (uint64, error) {
	body, err := os.ReadFile(path)
	if err != nil || len(body) == 0 || len(body) > 4096 {
		return 0, ErrUnavailable
	}
	fields := strings.Fields(string(body))
	for index := 0; index+1 < len(fields); index += 2 {
		if fields[index] != "usage_usec" {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[index+1], 10, 64)
		if parseErr != nil {
			return 0, ErrUnavailable
		}
		return value, nil
	}
	return 0, ErrUnavailable
}
func (p *reexecProcess) ExitCode() *int {
	p.beginWait()
	<-p.waitDone
	code := p.exitCode
	return &code
}
func (p *reexecProcess) KillGroup() error {
	p.killOnce.Do(func() {
		ops := p.cgroupOps
		if ops.write == nil {
			ops = defaultCgroupOps()
		}
		p.killErr = killCgroup(ops, p.cgroup)
		p.pidMu.Lock()
		defer p.pidMu.Unlock()
		if p.killErr == nil || p.pidfd < 0 {
			return
		}
		fallbackErr := unix.PidfdSendSignal(p.pidfd, unix.SIGKILL, nil, 0)
		if fallbackErr != nil && !errors.Is(fallbackErr, unix.ESRCH) {
			p.killErr = errors.Join(p.killErr, cgroupCleanupFailure("pidfd_kill"))
		}
	})
	return p.killErr
}

// SandboxChildV1 is called only by the fixed internal command mode.
func SandboxChildV1() error {
	bootstrap, err := readSandboxBootstrap(3)
	if err != nil {
		return sandboxChildFailure("bootstrap", err)
	}
	return runSandboxChild(bootstrap)
}
