//go:build linux

package extensionrunner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	// ProbeRoot is a runner-owned executable filesystem used only for the
	// bounded readiness install. Production must set it explicitly rather than
	// inheriting a possibly noexec process temporary directory.
	ProbeRoot string
	// ManagerRoot stores one content-addressed immutable manager bundle per
	// executable digest. Core mode requires this runner-owned, exec-capable
	// filesystem because container overlayfs directories cannot be open_tree
	// cloned on every supported kernel.
	ManagerRoot string
	// NodeRuntimeRoot is the immutable, image-bundled Node/npm tree. It is
	// mounted read-only only for managed Node requests.
	NodeRuntimeRoot string
	// ReexecPath is a trusted integration seam. Production leaves it empty and
	// always re-executes /proc/self/exe.
	ReexecPath string
}

const (
	coreManagerMemoryOverheadBytes int64 = 32 << 20
	coreManagerProcessOverhead     int64 = 8
	sandboxMountHandshakeTimeout         = 5 * time.Second
	sandboxProbeMemoryBytes        int64 = 64 << 20
	sandboxProbeProcesses          int64 = 16
	sandboxProbeTimeoutMS          int64 = 5000
)

type availabilityError struct{ stage string }

func (e availabilityError) Error() string {
	return fmt.Sprintf("extension runner unavailable at %s: %s", e.stage, ErrUnavailable)
}
func (e availabilityError) Unwrap() error { return ErrUnavailable }

// unavailableAt keeps Linux isolation diagnostics low-cardinality and safe to
// return to trusted local callers. It deliberately excludes paths, errno, and
// underlying OS error text.
func unavailableAt(stage string) error {
	if !safeAvailabilityStage(stage) {
		stage = "unavailable"
	}
	return availabilityError{stage: stage}
}

// AvailabilityStage exposes only the redacted, low-cardinality stage carried
// by this package's typed availability errors. Callers must never recover a
// stage by parsing Error strings.
func AvailabilityStage(err error) (string, bool) {
	var target availabilityError
	if !errors.As(err, &target) || !safeAvailabilityStage(target.stage) {
		return "", false
	}
	return target.stage, true
}

func safeAvailabilityStage(stage string) bool {
	if stage == "" || len(stage) > 160 {
		return false
	}
	for _, r := range stage {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func waitSandboxControl(ctx context.Context, fd int, want byte) error {
	if ctx == nil || fd < 0 {
		return ErrUnavailable
	}
	deadline := time.Now().Add(sandboxMountHandshakeTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		timeout := 100 * time.Millisecond
		if remaining < timeout {
			timeout = remaining
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
		n, err := unix.Poll(poll, int((timeout+time.Millisecond-1)/time.Millisecond))
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		var message [1]byte
		read, err := unix.Read(fd, message[:])
		if err != nil {
			return err
		}
		if read != 1 || message[0] != want {
			return ErrUnavailable
		}
		return nil
	}
}

func (b LinuxBackend) validateCgroupPrerequisites(ctx context.Context) error {
	if ctx == nil {
		return unavailableAt("probe_context")
	}
	if err := ctx.Err(); err != nil {
		return unavailableAt("probe_context")
	}
	if b.CgroupRoot == "" || !filepath.IsAbs(b.CgroupRoot) {
		return unavailableAt("cgroup_root")
	}
	var fs unix.Statfs_t
	if unix.Statfs(b.CgroupRoot, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return unavailableAt("cgroup_filesystem")
	}
	controllers, e := os.ReadFile(filepath.Join(b.CgroupRoot, "cgroup.controllers"))
	if e != nil || !hasController(string(controllers), "cpu") || !hasController(string(controllers), "memory") || !hasController(string(controllers), "pids") {
		return unavailableAt("cgroup_controllers")
	}
	return ensureCgroupDelegation(filepath.Join(b.CgroupRoot, "cgroup.subtree_control"), os.ReadFile, writeCgroup)
}

func ensureCgroupDelegation(path string, readFile func(string) ([]byte, error), writeFile func(string, string) error) error {
	current, err := readFile(path)
	if err != nil {
		return unavailableAt("cgroup_delegation")
	}
	var commands []string
	for _, name := range []string{"cpu", "memory", "pids"} {
		if !hasController(string(current), name) {
			commands = append(commands, "+"+name)
		}
	}
	if len(commands) > 0 && writeFile(path, strings.Join(commands, " ")) != nil {
		return unavailableAt("cgroup_delegation")
	}
	current, err = readFile(path)
	if err != nil {
		return unavailableAt("cgroup_delegation")
	}
	for _, name := range []string{"cpu", "memory", "pids"} {
		if !hasController(string(current), name) {
			return unavailableAt("cgroup_delegation")
		}
	}
	return nil
}

func (b LinuxBackend) Probe(ctx context.Context) error {
	if err := b.validateCgroupPrerequisites(ctx); err != nil {
		return err
	}
	var e error
	nameBytes := make([]byte, 16)
	if _, e = rand.Read(nameBytes); e != nil {
		return unavailableAt("probe_identity")
	}
	child := filepath.Join(b.CgroupRoot, "dirextalk-probe-"+hex.EncodeToString(nameBytes))
	if e = os.Mkdir(child, 0o700); e != nil {
		return unavailableAt("probe_cgroup_create")
	}
	cleaned := false
	defer func() {
		if !cleaned {
			_ = os.Remove(child)
		}
	}()
	for file, value := range map[string]string{"memory.max": "16777216", "pids.max": "8", "cpu.max": "10000 100000"} {
		if e = writeCgroup(filepath.Join(child, file), value); e != nil {
			return unavailableAt("probe_cgroup_limits")
		}
	}
	self := b.ReexecPath
	if self == "" {
		self, e = os.Executable()
	}
	if e != nil || self == "" {
		return unavailableAt("probe_executable")
	}
	releaseR, releaseW, e := os.Pipe()
	if e != nil {
		return unavailableAt("probe_release_pipe")
	}
	command := exec.CommandContext(ctx, self, "__probe-child-v1")
	command.ExtraFiles = []*os.File{releaseR}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if e = command.Start(); e != nil {
		releaseR.Close()
		releaseW.Close()
		return unavailableAt("probe_child_start")
	}
	releaseR.Close()
	pid := strconv.Itoa(command.Process.Pid)
	if e = writeCgroup(filepath.Join(child, "cgroup.procs"), pid); e != nil {
		_ = command.Process.Kill()
		releaseW.Close()
		_ = command.Wait()
		return unavailableAt("probe_cgroup_attach")
	}
	_, _ = releaseW.Write([]byte{1})
	releaseW.Close()
	if e = command.Wait(); e != nil {
		return unavailableAt("probe_child_wait")
	}
	procs, e := os.ReadFile(filepath.Join(child, "cgroup.procs"))
	if e != nil || len(strings.TrimSpace(string(procs))) != 0 {
		return unavailableAt("probe_cgroup_empty")
	}
	if e = os.Remove(child); e != nil {
		return unavailableAt("probe_cgroup_remove")
	}
	cleaned = true
	return b.probeSandbox(ctx)
}

func (b LinuxBackend) probeSandbox(ctx context.Context) error {
	if !trustedProbeRoot(b.ProbeRoot) {
		return unavailableAt("sandbox_root")
	}
	root, err := os.MkdirTemp(b.ProbeRoot, "dirextalk-runner-probe-")
	if err != nil {
		return unavailableAt("sandbox_root")
	}
	defer removePublishedTree(root)
	installRoot := filepath.Join(root, "installs")
	workspaceRoot := filepath.Join(root, "workspace")
	if err := os.Mkdir(installRoot, 0o700); err != nil {
		return unavailableAt("sandbox_install_root")
	}
	if err := os.Mkdir(workspaceRoot, 0o700); err != nil {
		return unavailableAt("sandbox_workspace_root")
	}
	self := b.ReexecPath
	if self == "" {
		self, err = os.Executable()
		if err != nil {
			return unavailableAt("sandbox_executable")
		}
	}
	install, manifestDigest, err := materializeProbeInstall(installRoot, self)
	if err != nil {
		return err
	}
	defer install.Close()
	workspace, err := unix.Open(workspaceRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return unavailableAt("sandbox_workspace")
	}
	defer unix.Close(workspace)
	runID, taskID, fence, err := probeIDs()
	if err != nil {
		return unavailableAt("sandbox_identity")
	}
	request := RequestV2{RunID: runID, TaskID: taskID, TaskFence: fence, InstallDigest: manifestDigest, Entry: "entry", Argv: []string{"entry", "__sandbox-probe-v1"}, TimeoutMS: sandboxProbeTimeoutMS, Limits: LimitsV2{CPUSeconds: 2, MemoryBytes: sandboxProbeMemoryBytes, Processes: sandboxProbeProcesses, FileBytes: 16 << 20, OpenFiles: 64}}
	if err := ValidateRequestV2(request); err != nil {
		return unavailableAt("sandbox_request")
	}
	process, err := b.startV2(ctx, SandboxInvocationV2{Request: request, Install: install, WorkspaceFD: workspace, StdinFD: -1})
	if err != nil {
		return unavailableAt("sandbox_start")
	}
	waitCtx, cancelWait := context.WithTimeout(ctx, time.Duration(request.TimeoutMS)*time.Millisecond)
	defer cancelWait()
	var stderr []byte
	if waiter, ok := process.(interface {
		WaitContext(context.Context) ([]byte, []byte, string, error)
	}); ok {
		_, stderr, _, err = waiter.WaitContext(waitCtx)
	} else {
		_, stderr, _, err = process.Wait()
	}
	if err != nil {
		return unavailableAt(sandboxProbeWaitStage(stderr))
	}
	return nil
}

func sandboxProbeWaitStage(stderr []byte) string {
	const fallback = "sandbox_wait"
	value := strings.TrimSpace(string(stderr))
	if strings.Count(value, ":") != 1 {
		return fallback
	}
	stage, cause, ok := parseSandboxChildDiagnostic(value)
	if !ok {
		return fallback
	}
	return fallback + "_" + stage + "_" + cause
}

func sandboxFinalWaitStage(stderr []byte) string {
	const fallback = "sandbox_wait"
	lines := strings.Split(string(stderr), "\n")
	for index := len(lines) - 1; index >= 0; index-- {
		value := strings.TrimSpace(lines[index])
		if value == "" {
			continue
		}
		stage, cause, ok := parseSandboxChildDiagnostic(value)
		if !ok {
			return fallback
		}
		return fallback + "_" + stage + "_" + cause
	}
	return fallback
}

func parseSandboxChildDiagnostic(value string) (string, string, bool) {
	if strings.Count(value, ":") != 1 {
		return "", "", false
	}
	stage, cause, _ := strings.Cut(value, ":")
	switch stage {
	case "bootstrap", "descriptors", "release", "mount-ready", "null", "map-fs", "map-namespace", "mount-private", "map-root", "map-pwd", "map-verify",
		"mounts", "root-target", "root-tmpfs", "root-bind", "root-verify", "root-remount", "layout", "app-clone", "app-bind", "app-remount",
		"runtime-clone", "runtime-bind", "runtime-remount",
		"work-clone", "work-bind", "work-remount", "work-tmpfs", "manager-clone", "manager-bind", "manager-remount",
		"manager", "manager-hide", "manager-release", "hide-scratch", "hide-remount", "secrets-tmpfs", "secrets-copy", "secrets-remount",
		"root-switch", "stdin", "rlimits", "capabilities", "no-new-privs", "seccomp", "close-fds", "command", "exec", "result-export":
	default:
		return "", "", false
	}
	switch cause {
	case "denied", "permission", "missing", "busy", "invalid", "unsupported", "other":
		return stage, cause, true
	default:
		return "", "", false
	}
}

func trustedProbeRoot(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return false
	}
	var st unix.Stat_t
	return unix.Lstat(path, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Uid == uint32(os.Geteuid()) && st.Mode&0o022 == 0
}

func materializeProbeInstall(installRoot, self string) (*AdmittedInstall, string, error) {
	probe := filepath.Join(installRoot, "probe")
	if err := os.Mkdir(probe, 0o700); err != nil {
		return nil, "", unavailableAt("sandbox_install_root")
	}
	entry := filepath.Join(probe, "entry")
	source, err := os.ReadFile(self)
	if err != nil || writeFileSync(entry, source, 0o500) != nil {
		return nil, "", unavailableAt("sandbox_entry")
	}
	manifest := []ManifestEntry{{Path: "entry", SHA256: DigestBytes(source), Size: int64(len(source))}}
	manifestDigest := ManifestDigest(manifest)
	manifestBody, err := json.Marshal(DiskInstallManifestV1{SchemaVersion: installManifestSchemaV1, Entries: manifest})
	if err != nil || writeFileSync(filepath.Join(probe, installManifestName), append(manifestBody, '\n'), 0o400) != nil {
		return nil, "", unavailableAt("sandbox_entry")
	}
	if err := makePublishedTreeImmutable(probe); err != nil {
		return nil, "", unavailableAt("sandbox_publish")
	}
	target := filepath.Join(installRoot, manifestDigest)
	if err := unix.Renameat2(unix.AT_FDCWD, probe, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE); err != nil {
		return nil, "", unavailableAt("sandbox_publish")
	}
	if err := syncDirectory(installRoot); err != nil {
		return nil, "", unavailableAt("sandbox_publish")
	}
	install, err := OpenAdmittedInstall(target, manifestDigest, manifest)
	if err != nil {
		return nil, "", unavailableAt("sandbox_admit")
	}
	return install, manifestDigest, nil
}

func writeFileSync(path string, body []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	return err
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err == nil {
		err = closeErr
	}
	return err
}

func probeIDs() (string, string, string, error) {
	ids := make([]string, 3)
	for i := range ids {
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return "", "", "", err
		}
		raw[6] = (raw[6] & 0x0f) | 0x40
		raw[8] = (raw[8] & 0x3f) | 0x80
		ids[i] = fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
	}
	return ids[0], ids[1], ids[2], nil
}

func writeCgroup(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(value)
	return err
}

func hasController(value, want string) bool {
	for _, item := range strings.Fields(value) {
		if item == want || item == "+"+want {
			return true
		}
	}
	return false
}

type bootstrapV1 struct {
	Request        RequestV2 `json:"request"`
	SecretCount    int       `json:"secret_count"`
	HasStdin       bool      `json:"has_stdin"`
	RootDev        uint64    `json:"root_dev"`
	RootIno        uint64    `json:"root_ino"`
	EntryDev       uint64    `json:"entry_dev"`
	EntryIno       uint64    `json:"entry_ino"`
	EntryMode      uint32    `json:"entry_mode"`
	EntrySize      int64     `json:"entry_size"`
	EntrySHA256    string    `json:"entry_sha256"`
	RootTargetName string    `json:"root_target_name"`
	RootTargetDev  uint64    `json:"root_target_dev"`
	RootTargetIno  uint64    `json:"root_target_ino"`
	RootTargetMode uint32    `json:"root_target_mode"`
	TargetRootDev  uint64    `json:"target_root_dev"`
	TargetRootIno  uint64    `json:"target_root_ino"`
	RuntimeRootDev uint64    `json:"runtime_root_dev,omitempty"`
	RuntimeRootIno uint64    `json:"runtime_root_ino,omitempty"`
	ManagerBase    string    `json:"manager_base"`
	ManagerRootDev uint64    `json:"manager_root_dev"`
	ManagerRootIno uint64    `json:"manager_root_ino"`
	ManagerDev     uint64    `json:"manager_dev"`
	ManagerIno     uint64    `json:"manager_ino"`
	ManagerMode    uint32    `json:"manager_mode"`
	ManagerSize    int64     `json:"manager_size"`
	ManagerSHA256  string    `json:"manager_sha256"`
	CoreTmpfsBytes int64     `json:"core_tmpfs_bytes,omitempty"`
	CoreResultPath string    `json:"core_result_path,omitempty"`
}

func (b LinuxBackend) StartV2(ctx context.Context, inv SandboxInvocationV2) (Process, error) {
	// Active readiness is owned by the runner startup/operation boundary. Do not
	// launch a second disposable sandbox inside every real StartV2: the actual
	// cgroup creation, namespace handshake and mount construction below already
	// fail closed. Retain this idempotent cgroup-v2 prerequisite path so a
	// direct caller can never execute against an ordinary directory or without
	// the three required controllers delegated to child cgroups.
	if err := b.validateCgroupPrerequisites(ctx); err != nil {
		return nil, err
	}
	if inv.Install == nil || inv.WorkspaceFD < 0 {
		return nil, unavailableAt("validate_probe")
	}
	return b.startV2(ctx, inv)
}

func (b LinuxBackend) startV2(ctx context.Context, inv SandboxInvocationV2) (process Process, retErr error) {
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
	var managerRoot, managerFD int = -1, -1
	var runtimeRoot int = -1
	var runtimeStat unix.Stat_t
	if inv.Request.Runtime == "node" {
		var runtimeErr error
		runtimeRoot, runtimeStat, runtimeErr = openNodeRuntimeRoot(b.NodeRuntimeRoot)
		if runtimeErr != nil {
			return nil, unavailableAt("node_runtime")
		}
		defer unix.Close(runtimeRoot)
	}
	var managerBase, managerDigest string
	var managerRootStat, managerStat unix.Stat_t
	var managerErr error
	if inv.CoreTmpfsBytes > 0 {
		managerRoot, managerFD, managerBase, managerRootStat, managerStat, managerDigest, managerErr = materializeManagerSource(self, b.ManagerRoot)
		if managerErr != nil {
			return nil, unavailableAt("manager_fd")
		}
		defer unix.Close(managerRoot)
		defer unix.Close(managerFD)
	}
	sandboxTarget, err := createSandboxRootTarget(inv.Request.RunID)
	if err != nil {
		return nil, unavailableAt("root_target")
	}
	defer func() {
		if sandboxTarget != nil {
			retErr = errors.Join(retErr, sandboxTarget.cleanup())
			sandboxTarget.close()
		}
	}()
	bs, err := json.Marshal(bootstrapV1{
		Request:        inv.Request,
		SecretCount:    len(inv.SecretFDs),
		HasStdin:       inv.StdinFD >= 0,
		RootDev:        inv.Install.RootDev,
		RootIno:        inv.Install.RootIno,
		EntryDev:       inv.Install.EntryDev,
		EntryIno:       inv.Install.EntryIno,
		EntryMode:      inv.Install.EntryMode,
		EntrySize:      inv.Install.EntrySize,
		EntrySHA256:    inv.Install.EntrySHA256,
		RootTargetName: sandboxTarget.name,
		RootTargetDev:  uint64(sandboxTarget.target.Dev),
		RootTargetIno:  sandboxTarget.target.Ino,
		RootTargetMode: sandboxTarget.target.Mode,
		TargetRootDev:  uint64(sandboxTarget.parent.Dev),
		TargetRootIno:  sandboxTarget.parent.Ino,
		RuntimeRootDev: uint64(runtimeStat.Dev),
		RuntimeRootIno: runtimeStat.Ino,
		ManagerBase:    managerBase,
		ManagerRootDev: uint64(managerRootStat.Dev),
		ManagerRootIno: managerRootStat.Ino,
		ManagerDev:     uint64(managerStat.Dev),
		ManagerIno:     managerStat.Ino,
		ManagerMode:    managerStat.Mode,
		ManagerSize:    managerStat.Size,
		ManagerSHA256:  managerDigest,
		CoreTmpfsBytes: inv.CoreTmpfsBytes,
		CoreResultPath: inv.CoreResultPath,
	})
	if err != nil {
		return nil, unavailableAt("bootstrap")
	}
	boot, err := sealedMemfd("bootstrap", bs)
	if err != nil {
		return nil, unavailableAt("bootstrap")
	}
	defer unix.Close(boot)
	controlFDs, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, unavailableAt("release_pipe")
	}
	childControl := os.NewFile(uintptr(controlFDs[0]), "sandbox-control-child")
	parentControl := os.NewFile(uintptr(controlFDs[1]), "sandbox-control-parent")
	defer childControl.Close()
	defer parentControl.Close()
	root, err := inv.Install.DupRootFD()
	if err != nil {
		return nil, unavailableAt("install_fd")
	}
	defer unix.Close(root)
	entry, err := inv.Install.DupEntryFD()
	if err != nil {
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
	// Core mode is selected solely by a non-zero tmpfs size. CoreResultFD has
	// the normal Go zero value (also a valid descriptor), so it must not make
	// an ordinary extension invocation opt in accidentally.
	if inv.CoreTmpfsBytes < 0 || inv.CoreTmpfsBytes > 1<<40 || (inv.CoreTmpfsBytes == 0 && inv.CoreResultPath != "") || (inv.CoreTmpfsBytes > 0 && inv.CoreResultPath != "" && inv.CoreResultFD < 0) {
		return nil, unavailableAt("core_mode")
	}
	if inv.CoreTmpfsBytes > 0 && (inv.StdinFD >= 0 || len(inv.SecretFDs) != 0) {
		return nil, unavailableAt("core_mode")
	}
	cgroupLimits, err := effectiveCgroupLimits(inv)
	if err != nil {
		return nil, err
	}
	files := make([]*os.File, 0, 7+len(inv.SecretFDs))
	for _, item := range []struct {
		fd   int
		name string
	}{{boot, "bootstrap"}, {int(childControl.Fd()), "control"}, {root, "install"}, {entry, "entry"}, {inv.WorkspaceFD, "workspace"}} {
		f, e := extra(item.fd, item.name)
		if e != nil {
			for _, x := range files {
				_ = x.Close()
			}
			return nil, unavailableAt("extra_files")
		}
		files = append(files, f)
	}
	if inv.Request.Runtime == "node" {
		runtimeFile, e := extra(runtimeRoot, "node-runtime")
		if e != nil {
			return nil, unavailableAt("node_runtime")
		}
		files = append(files, runtimeFile)
	}
	if inv.CoreTmpfsBytes > 0 {
		manager, e := extra(managerRoot, "manager-root")
		if e != nil {
			return nil, unavailableAt("manager_fd")
		}
		files = append(files, manager)
		if inv.CoreResultPath != "" && inv.CoreResultFD < 0 {
			return nil, unavailableAt("result_fd")
		}
		if inv.CoreResultPath != "" {
			result, e := extra(inv.CoreResultFD, "core-result")
			if e != nil {
				return nil, unavailableAt("result_fd")
			}
			files = append(files, result)
		}
	}
	if inv.StdinFD >= 0 {
		f, e := extra(inv.StdinFD, "stdin")
		if e != nil {
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
	cmd.SysProcAttr = sandboxChildSysProcAttr(&pidfd)
	var out, er boundedBuffer
	if inv.PersistentOutputLimit > 0 {
		budget := &outputBudget{limit: inv.PersistentOutputLimit}
		// Persistent workloads never return their process output.  Do not
		// retain raw bytes in the runner merely to enforce the quota.
		out.budget, er.budget = budget, budget
	}
	cmd.Stdout = &out
	cmd.Stderr = &er
	if err = cmd.Start(); err != nil {
		return nil, unavailableAt("child_start")
	}
	_ = childControl.Close()
	cg := filepath.Join(b.CgroupRoot, inv.Request.RunID)
	if err = setupCgroup(cg, cgroupLimits, cmd.Process.Pid); err != nil {
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		_ = cmd.Wait()
		_ = unix.Close(pidfd)
		return nil, err
	}
	if _, err = parentControl.Write([]byte{sandboxControlRelease}); err != nil {
		ops := defaultCgroupOps()
		killErr := killCgroup(ops, cg)
		if killErr != nil {
			_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		}
		_ = cmd.Wait()
		_ = unix.Close(pidfd)
		return nil, errors.Join(unavailableAt("release"), killErr, cleanupSetupCgroup(ops, cg))
	}
	if err = waitSandboxControl(ctx, int(parentControl.Fd()), sandboxControlMounted); err != nil {
		ops := defaultCgroupOps()
		killErr := killCgroup(ops, cg)
		if killErr != nil {
			_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		}
		_ = cmd.Wait()
		_ = unix.Close(pidfd)
		return nil, errors.Join(unavailableAt(sandboxProbeWaitStage(er.Snapshot())), killErr, cleanupSetupCgroup(ops, cg))
	}
	if err = sandboxTarget.cleanup(); err != nil {
		ops := defaultCgroupOps()
		killErr := killCgroup(ops, cg)
		if killErr != nil {
			_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		}
		_ = cmd.Wait()
		_ = unix.Close(pidfd)
		retryErr := sandboxTarget.cleanup()
		return nil, errors.Join(unavailableAt("root_target_cleanup"), err, retryErr, killErr, cleanupSetupCgroup(ops, cg))
	}
	sandboxTarget.close()
	sandboxTarget = nil
	if _, err = parentControl.Write([]byte{sandboxControlContinue}); err != nil {
		ops := defaultCgroupOps()
		killErr := killCgroup(ops, cg)
		if killErr != nil {
			_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		}
		_ = cmd.Wait()
		_ = unix.Close(pidfd)
		return nil, errors.Join(unavailableAt("release"), killErr, cleanupSetupCgroup(ops, cg))
	}
	_ = parentControl.Close()
	reexec := &reexecProcess{
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
	process = reexec
	go reexec.monitorCPU()
	return process, nil
}

func effectiveCgroupLimits(inv SandboxInvocationV2) (LimitsV2, error) {
	limits := inv.Request.Limits
	if inv.CoreTmpfsBytes == 0 {
		return limits, nil
	}
	// Core keeps one trusted Go manager outside the untrusted command. Its
	// runtime threads and resident memory are implementation overhead, not the
	// workload budget carried by the public request.
	if limits.MemoryBytes > int64(^uint64(0)>>1)-coreManagerMemoryOverheadBytes || limits.Processes > int64(^uint64(0)>>1)-coreManagerProcessOverhead {
		return LimitsV2{}, unavailableAt("core_limits")
	}
	limits.MemoryBytes += coreManagerMemoryOverheadBytes
	limits.Processes += coreManagerProcessOverhead
	return limits, nil
}

func sandboxChildSysProcAttr(pidfd *int) *syscall.SysProcAttr {
	// Do not combine Pdeathsig with CLONE_NEWPID. Go records the parent PID
	// before clone and checks it again in the child; the namespace init cannot
	// see its outer parent, so that check self-signals SIGKILL. The runner owns
	// this child through its pidfd and exact cgroup kill/reap path instead.
	return &syscall.SysProcAttr{
		Cloneflags:                 unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWIPC | unix.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		Setpgid:                    true,
		PidFD:                      pidfd,
	}
}

const managerBundlePrefix = ".dirextalk-manager-v1-"
const managerBundleEntry = "manager"
const maxManagerBytes = 128 << 20

func materializeManagerSource(self, managerRoot string) (int, int, string, unix.Stat_t, unix.Stat_t, string, error) {
	var empty unix.Stat_t
	if !trustedProbeRoot(managerRoot) {
		return -1, -1, "", empty, empty, "", ErrDenied
	}
	path := self
	if self == "/proc/self/exe" {
		var err error
		path, err = os.Executable()
		if err != nil {
			return -1, -1, "", empty, empty, "", err
		}
	}
	path, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, -1, "", empty, empty, "", ErrDenied
	}
	base := filepath.Base(path)
	if !safeName(base) {
		return -1, -1, "", empty, empty, "", ErrDenied
	}
	sourceRoot, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, -1, "", empty, empty, "", err
	}
	defer unix.Close(sourceRoot)
	var sourceRootStat unix.Stat_t
	if unix.Fstat(sourceRoot, &sourceRootStat) != nil || sourceRootStat.Mode&unix.S_IFMT != unix.S_IFDIR || !trustedExecutableOwner(sourceRootStat.Uid) || sourceRootStat.Mode&0o022 != 0 {
		return -1, -1, "", empty, empty, "", ErrDenied
	}
	sourceFD, err := unix.Openat(sourceRoot, base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, -1, "", empty, empty, "", err
	}
	defer unix.Close(sourceFD)
	var st, selfStat unix.Stat_t
	if unix.Fstat(sourceFD, &st) != nil || unix.Stat(self, &selfStat) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || !trustedExecutableOwner(st.Uid) || st.Mode&0o111 == 0 || st.Mode&0o022 != 0 || st.Dev != selfStat.Dev || st.Ino != selfStat.Ino || st.Size <= 0 || st.Size > maxManagerBytes {
		return -1, -1, "", empty, empty, "", ErrDenied
	}
	digest, err := digestDescriptor(sourceFD, st.Size)
	if err != nil {
		return -1, -1, "", empty, empty, "", err
	}
	target := filepath.Join(managerRoot, managerBundlePrefix+digest)
	if _, err := os.Lstat(target); os.IsNotExist(err) {
		if err := publishManagerBundle(managerRoot, target, sourceFD, st.Size, digest); err != nil {
			return -1, -1, "", empty, empty, "", err
		}
	} else if err != nil {
		return -1, -1, "", empty, empty, "", err
	}
	root, fd, rootStat, managerStat, err := openManagerBundle(target, digest, st.Size)
	if err != nil {
		return -1, -1, "", empty, empty, "", err
	}
	return root, fd, managerBundleEntry, rootStat, managerStat, digest, nil
}

func publishManagerBundle(managerRoot, target string, sourceFD int, size int64, digest string) error {
	tmp, err := os.MkdirTemp(managerRoot, ".manager-publish-")
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			_ = removePublishedTree(tmp)
		}
	}()
	fd, err := unix.Open(filepath.Join(tmp, managerBundleEntry), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if err = copyDescriptor(sourceFD, fd, size); err == nil {
		err = unix.Fsync(fd)
	}
	if err == nil {
		err = unix.Fchmod(fd, 0o500)
	}
	closeErr := unix.Close(fd)
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = makePublishedTreeImmutable(tmp); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			existingRoot, existing, _, _, validateErr := openManagerBundle(target, digest, size)
			if existingRoot >= 0 {
				unix.Close(existingRoot)
			}
			if existing >= 0 {
				unix.Close(existing)
			}
			return validateErr
		}
		return err
	}
	published = true
	return syncDirectory(managerRoot)
}

func copyDescriptor(sourceFD, targetFD int, size int64) error {
	buf := make([]byte, 64<<10)
	for offset := int64(0); offset < size; {
		want := int64(len(buf))
		if size-offset < want {
			want = size - offset
		}
		n, err := unix.Pread(sourceFD, buf[:want], offset)
		if err != nil || n <= 0 {
			return ErrDenied
		}
		for written := 0; written < n; {
			count, writeErr := unix.Write(targetFD, buf[written:n])
			if writeErr != nil || count <= 0 {
				return ErrDenied
			}
			written += count
		}
		offset += int64(n)
	}
	return nil
}

func openManagerBundle(target, digest string, size int64) (int, int, unix.Stat_t, unix.Stat_t, error) {
	var empty unix.Stat_t
	if filepath.Base(target) != managerBundlePrefix+digest || !digestRE.MatchString(digest) {
		return -1, -1, empty, empty, ErrDenied
	}
	root, err := unix.Open(target, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, -1, empty, empty, err
	}
	var rootStat unix.Stat_t
	if unix.Fstat(root, &rootStat) != nil || rootStat.Mode&unix.S_IFMT != unix.S_IFDIR || rootStat.Uid != uint32(os.Geteuid()) || rootStat.Mode&0o777 != 0o500 {
		unix.Close(root)
		return -1, -1, empty, empty, ErrDenied
	}
	dup, err := unix.Dup(root)
	if err != nil {
		unix.Close(root)
		return -1, -1, empty, empty, err
	}
	dir := os.NewFile(uintptr(dup), "manager-bundle")
	entries, err := dir.ReadDir(-1)
	closeErr := dir.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil || len(entries) != 1 || entries[0].Name() != managerBundleEntry || !entries[0].Type().IsRegular() {
		unix.Close(root)
		return -1, -1, empty, empty, ErrDenied
	}
	fd, err := unix.Openat(root, managerBundleEntry, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		unix.Close(root)
		return -1, -1, empty, empty, err
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0o777 != 0o500 || st.Nlink != 1 || st.Size != size {
		unix.Close(fd)
		unix.Close(root)
		return -1, -1, empty, empty, ErrDenied
	}
	got, err := digestDescriptor(fd, st.Size)
	if err != nil || got != digest {
		unix.Close(fd)
		unix.Close(root)
		return -1, -1, empty, empty, ErrDenied
	}
	return root, fd, rootStat, st, nil
}

func trustedExecutableOwner(uid uint32) bool {
	return uid == 0 || uid == uint32(os.Geteuid())
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

type boundedBuffer struct {
	mu       sync.RWMutex
	b        []byte
	limit    int
	exceeded bool
	budget   *outputBudget
}

// outputBudget serializes the two pipe readers.  A single reservation is the
// only authority for persistent stdout+stderr, so simultaneous writes cannot
// each consume the full quota.
type outputBudget struct {
	mu       sync.Mutex
	limit    int64
	used     int64
	exceeded bool
}

func (b *outputBudget) reserve(n int) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || b.used > b.limit-int64(n) {
		b.exceeded = true
		return false
	}
	b.used += int64(n)
	return true
}

func (b *outputBudget) snapshot() (int64, bool) {
	if b == nil {
		return 0, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used, b.exceeded
}

var (
	errCPULimitExceeded = errors.New("extension CPU limit exceeded")
	errCPUAccounting    = errors.New("extension CPU accounting failed")
)

func (x *boundedBuffer) Write(p []byte) (int, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.budget != nil {
		if !x.budget.reserve(len(p)) {
			x.exceeded = true
		}
		// Persistent output is intentionally not an exported artifact.
		return len(p), nil
	}
	limit := x.limit
	if limit <= 0 {
		limit = MaxOutputBytes
	}
	if len(x.b)+len(p) > limit {
		x.exceeded = true
	}
	n := len(p)
	if len(x.b) < limit {
		k := limit - len(x.b)
		if k > len(p) {
			k = len(p)
		}
		x.b = append(x.b, p[:k]...)
	}
	return n, nil
}

func (x *boundedBuffer) SetLimit(limit int) {
	if limit <= 0 {
		limit = MaxOutputBytes
	}
	x.mu.Lock()
	x.limit = limit
	if len(x.b) > limit {
		x.b = x.b[:limit]
		x.exceeded = true
	}
	x.mu.Unlock()
}

func (x *boundedBuffer) Snapshot() []byte {
	if x == nil {
		return nil
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	return append([]byte(nil), x.b...)
}
func (x *boundedBuffer) Exceeded() bool {
	x.mu.RLock()
	defer x.mu.RUnlock()
	exceeded := x.exceeded
	if x.budget != nil {
		_, budgetExceeded := x.budget.snapshot()
		exceeded = exceeded || budgetExceeded
	}
	return exceeded
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
		joined := errors.Join(killErr, p.waitErr)
		if errors.Is(joined, errCgroupCleanup) {
			return p.waitResult(joined)
		}
		return p.out.Snapshot(), p.err.Snapshot(), "failed", ctx.Err()
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
	stdout := p.out.Snapshot()
	stderr := p.err.Snapshot()
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

// OutputBytes reports the retained stdout+stderr bytes for a persistent
// service. The underlying buffers are bounded by MaxOutputBytes per stream.
func (p *reexecProcess) OutputBytes() int64 {
	if p == nil {
		return 0
	}
	if p.out != nil && p.out.budget != nil {
		used, _ := p.out.budget.snapshot()
		return used
	}
	return int64(len(p.out.Snapshot()) + len(p.err.Snapshot()))
}
func (p *reexecProcess) OutputExceeded() bool {
	return p != nil && (p.out.Exceeded() || p.err.Exceeded())
}
func (p *reexecProcess) SetOutputLimit(limit int64) {
	if p == nil || limit <= 0 || limit > 1<<40 {
		return
	}
	// Retained for compatibility with existing callers.  It cannot make a
	// running persistent process safe; StartPersistentServiceV1 supplies the
	// shared budget before StartV2 instead.
	p.out.SetLimit(int(limit))
	p.err.SetLimit(int(limit))
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

// SandboxCommandV1 is reachable only from the manager's immutable reexec
// descriptor. It receives only the sealed bootstrap and applies the untrusted
// command restrictions immediately before exec.
func SandboxCommandV1() error {
	bootstrap, err := readSandboxBootstrap(sandboxBootstrapFD)
	if err != nil {
		return sandboxChildFailure("bootstrap", err)
	}
	return runSandboxCommand(bootstrap)
}
