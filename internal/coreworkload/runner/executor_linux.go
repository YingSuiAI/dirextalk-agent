//go:build linux

package runner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
	"golang.org/x/sys/unix"
)

// Executor is retained for the small in-memory supervisor used by unit tests.
type Executor interface {
	Execute(context.Context, Request) (string, error)
}

// persistentExecutor is deliberately private: only the Linux production
// executor is allowed to turn a ready receipt into a running service.
type persistentExecutor interface {
	ApplyPersistent(context.Context, Request) (Receipt, error)
	ReadPersistent(context.Context, Request, Receipt) (Receipt, error)
	DestroyPersistent(context.Context, Request, Receipt) (Receipt, error)
}

type LinuxExecutor struct{ InstallRoot, WorkspaceRoot, CgroupRoot, StaticShell string }

const maxServiceBytes = 16 << 20

func (e LinuxExecutor) Execute(ctx context.Context, q Request) (string, error) {
	r, err := e.ApplyPersistent(ctx, q)
	return r.State, err
}

func (e LinuxExecutor) ApplyPersistent(ctx context.Context, q Request) (Receipt, error) {
	if q.Action != "apply" || len(q.NetworkGrants) != 0 || len(q.SecretDescriptors) != 0 || !e.validLimits(q) {
		return Receipt{}, ErrDenied
	}
	if err := e.runInstall(ctx, q); err != nil {
		return Receipt{}, err
	}
	staged := true
	defer func() {
		if staged {
			_ = e.removeWorkspace(q)
		}
	}()
	service, err := e.readWorkspaceService(q)
	if err != nil {
		return Receipt{}, ErrDenied
	}
	digest, install, argv, err := e.publishService(service)
	if err != nil {
		return Receipt{}, ErrDenied
	}
	published := true
	defer func() {
		if published {
			_ = e.removeBundle(digest)
		}
	}()
	defer install.Close()
	workspace, err := (extensionrunner.DiskWorkspaceResolver{Root: e.WorkspaceRoot}).ResolveWorkspace(q.OperationID, q.DispatchClaim)
	if err != nil {
		return Receipt{}, ErrDenied
	}
	defer unix.Close(workspace)
	r := e.request(q, digest, argv)
	p, err := extensionrunner.StartPersistentServiceV1(ctx, extensionrunner.LinuxBackend{CgroupRoot: e.CgroupRoot}, extensionrunner.SandboxInvocationV2{Request: r, Install: install, WorkspaceFD: workspace, StdinFD: -1, CoreTmpfsBytes: q.Limits.DiskMB * 1024 * 1024}, time.Millisecond, q.Limits.OutputMB*1024*1024)
	if err != nil {
		return Receipt{}, ErrDenied
	}
	id := p.Identity()
	if !e.identityOwned(id) {
		_ = p.Destroy(context.Background())
		return Receipt{}, ErrDenied
	}
	// The child now holds the immutable mount. Unlink bundle first, then the
	// exact staging workspace; a crash in either window is intent-recoverable.
	if err := e.removeBundle(digest); err != nil {
		_ = p.Destroy(context.Background())
		return Receipt{}, ErrDenied
	}
	published = false
	if err := e.removeWorkspace(q); err != nil {
		_ = p.Destroy(context.Background())
		return Receipt{}, ErrDenied
	}
	staged = false
	// The rlimit only covers the writable sandbox view. Keep a separate
	// aggregate accounting guard over the runner-owned workspace and bundle so
	// a long-lived service cannot grow either side after admission.
	// The manager owns the persistent lifetime, not the request connection.
	go e.monitorPersistent(context.Background(), q, digest, p)
	return Receipt{State: "ready", ServiceDigest: digest, PID: id.PID, StartTime: id.StartTime, Cgroup: id.Cgroup}, nil
}

// ReapIntent closes the pre-receipt crash window. RunID is the validated
// operation UUID and therefore maps to exactly one child cgroup.
func (e LinuxExecutor) ReapIntent(_ context.Context, q Request) error {
	if q.Validate() != nil || !coreworkload.ValidUUID(q.OperationID) {
		return ErrDenied
	}
	path := filepath.Join(e.CgroupRoot, q.OperationID)
	if filepath.Dir(path) != e.CgroupRoot {
		return ErrDenied
	}
	if err := extensionrunner.DestroyPersistentCgroup(context.Background(), path); err != nil {
		return err
	}
	stage := filepath.Join(e.WorkspaceRoot, q.OperationID, q.DispatchClaim)
	if _, err := os.Stat(stage); err == nil {
		service, err := e.readWorkspaceService(q)
		// Result validation precedes publication. A missing, partial, or
		// invalid service therefore cannot name a bundle; clear only staging.
		if err == nil {
			digest, digestErr := e.serviceDigest(service)
			if digestErr == nil {
				if err := e.removeBundle(digest); err != nil {
					return ErrDenied
				}
			}
		}
	} else if !os.IsNotExist(err) {
		return ErrDenied
	}
	if err := e.removeWorkspace(q); err != nil {
		return ErrDenied
	}
	return nil
}

func (e LinuxExecutor) serviceDigest(service []byte) (string, error) {
	shell, err := os.ReadFile(e.StaticShell)
	if err != nil {
		return "", ErrDenied
	}
	if isELF(service) {
		return extensionrunner.ManifestDigest([]extensionrunner.ManifestEntry{{Path: "entry", SHA256: extensionrunner.DigestBytes(service), Size: int64(len(service))}}), nil
	}
	if !bytes.HasPrefix(service, []byte("#!")) {
		return "", ErrDenied
	}
	return extensionrunner.ManifestDigest([]extensionrunner.ManifestEntry{{Path: "entry", SHA256: extensionrunner.DigestBytes(shell), Size: int64(len(shell))}, {Path: "service", SHA256: extensionrunner.DigestBytes(service), Size: int64(len(service))}}), nil
}

func (e LinuxExecutor) ReadPersistent(_ context.Context, q Request, prior Receipt) (Receipt, error) {
	if prior.Destroyed || prior.State != "ready" || prior.ServiceDigest == "" || !e.identityOwned(extensionrunner.PersistentIdentity{PID: prior.PID, StartTime: prior.StartTime, Cgroup: prior.Cgroup}) {
		return Receipt{State: "unknown"}, nil
	}
	if err := extensionrunner.ValidatePersistentIdentity(extensionrunner.PersistentIdentity{PID: prior.PID, StartTime: prior.StartTime, Cgroup: prior.Cgroup}); err != nil {
		return Receipt{State: "unknown"}, nil
	}
	return Receipt{State: "ready", ServiceDigest: prior.ServiceDigest, PID: prior.PID, StartTime: prior.StartTime, Cgroup: prior.Cgroup}, nil
}

func (e LinuxExecutor) DestroyPersistent(ctx context.Context, q Request, prior Receipt) (Receipt, error) {
	if prior.Destroyed {
		return Receipt{State: "destroyed", ServiceDigest: prior.ServiceDigest, PID: prior.PID, StartTime: prior.StartTime, Cgroup: prior.Cgroup}, nil
	}
	id := extensionrunner.PersistentIdentity{PID: prior.PID, StartTime: prior.StartTime, Cgroup: prior.Cgroup}
	if prior.State != "ready" || !e.identityOwned(id) {
		return Receipt{}, ErrDenied
	}
	if err := extensionrunner.DestroyPersistentIdentity(ctx, id); err != nil {
		return Receipt{}, ErrDenied
	}
	if err := e.removeBundle(prior.ServiceDigest); err != nil {
		return Receipt{}, ErrDenied
	}
	return Receipt{State: "destroyed", ServiceDigest: prior.ServiceDigest, PID: prior.PID, StartTime: prior.StartTime, Cgroup: prior.Cgroup}, nil
}

// ReapPersistent is used only during supervisor restart reconciliation.  It
// checks the exact PID/start-time/cgroup identity before asking the sandbox to
// kill descendants, wait populated=0 and remove the cgroup.
func (e LinuxExecutor) ReapPersistent(_ context.Context, prior Receipt) error {
	id := extensionrunner.PersistentIdentity{PID: prior.PID, StartTime: prior.StartTime, Cgroup: prior.Cgroup}
	if (prior.State != "ready" && prior.State != "cleanup_required") || prior.Destroyed || !e.identityOwned(id) {
		return ErrDenied
	}
	if err := extensionrunner.DestroyPersistentIdentity(context.Background(), id); err != nil {
		return ErrDenied
	}
	if err := e.removeBundle(prior.ServiceDigest); err != nil {
		return ErrDenied
	}
	return nil
}

// Probe validates all static roots before the socket advertises readiness.
// The dynamic tmpfs/cgroup proof remains inside RunCoreResultV1 during Apply;
// callers keep capability disabled if that full proof cannot run.
func (e LinuxExecutor) Probe() error {
	if !absolutePrivateDir(e.InstallRoot) {
		return unavailableAt("install_root")
	}
	if !absolutePrivateDir(e.WorkspaceRoot) {
		return unavailableAt("workspace_root")
	}
	if !absoluteCgroupDir(e.CgroupRoot) {
		return unavailableAt("cgroup_root")
	}
	if e.publishShell() != nil {
		return unavailableAt("static_shell")
	}
	// Exercise the exact ephemeral Core result path before advertising a
	// runner: user namespace mounts, seccomp, cgroup attach/cleanup and sealed
	// result extraction all happen below. Nothing is retained after this call.
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return unavailableAt("identity")
	}
	id := hex.EncodeToString(token[:])
	q := Request{Action: "apply", WorkloadID: id[:8] + "-" + id[8:12] + "-4" + id[13:16] + "-8" + id[17:20] + "-" + id[20:], OperationID: id[:8] + "-" + id[8:12] + "-4" + id[13:16] + "-8" + id[17:20] + "-" + id[20:], PlanDigest: strings.Repeat("0", 64), PlanRevision: 1, DispatchClaim: id[:8] + "-" + id[8:12] + "-4" + id[13:16] + "-8" + id[17:20] + "-" + id[20:], DispatchEpoch: 1, CommandSteps: []string{"printf '#!/bin/sh\\nexit 0\\n' > readiness-service"}, Service: "readiness-service", Limits: coreworkload.ResourceLimits{CPU: 1, MemoryMB: 16, Processes: 8, DiskMB: 16, TimeoutS: 1, OutputMB: 1}}
	if q.Validate() != nil {
		return unavailableAt("request")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.runInstall(ctx, q); err != nil {
		return unavailableAt("install")
	}
	defer e.removeWorkspace(q)
	service, err := e.readWorkspaceService(q)
	if err != nil {
		return unavailableAt("result")
	}
	digest, install, argv, err := e.publishService(service)
	if err != nil {
		return unavailableAt("publish")
	}
	defer install.Close()
	defer e.removeBundle(digest)
	workspace, err := (extensionrunner.DiskWorkspaceResolver{Root: e.WorkspaceRoot}).ResolveWorkspace(q.OperationID, q.DispatchClaim)
	if err != nil {
		return unavailableAt("workspace")
	}
	defer unix.Close(workspace)
	p, err := extensionrunner.StartPersistentServiceV1(ctx, extensionrunner.LinuxBackend{CgroupRoot: e.CgroupRoot}, extensionrunner.SandboxInvocationV2{Request: e.request(q, digest, argv), Install: install, WorkspaceFD: workspace, StdinFD: -1, CoreTmpfsBytes: q.Limits.DiskMB * 1024 * 1024}, time.Millisecond, q.Limits.OutputMB*1024*1024)
	if err != nil || p == nil || !e.identityOwned(p.Identity()) {
		return unavailableAt("sandbox")
	}
	if p.Destroy(context.Background()) != nil {
		return unavailableAt("cleanup")
	}
	return nil
}

type readinessError struct{ stage string }

func (e readinessError) Error() string { return "core runner unavailable at " + e.stage }
func (e readinessError) Unwrap() error { return ErrDenied }

func unavailableAt(stage string) error { return readinessError{stage: stage} }

// ReadinessStage exposes only the fixed, low-cardinality startup stage. It
// deliberately never returns paths, errno values, or wrapped OS error text.
func ReadinessStage(err error) (string, bool) {
	var target readinessError
	if !errors.As(err, &target) {
		return "", false
	}
	return target.stage, true
}

func absolutePrivateDir(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	st, err := os.Stat(path)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0o077 != 0 {
		return false
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	return ok && uint32(owner.Uid) == uint32(os.Geteuid())
}

func absoluteCgroupDir(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return false
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Stat(path, &st) != nil || unix.Statfs(path, &fs) != nil {
		return false
	}
	return safeCgroupStat(st, fs, uint32(os.Geteuid()))
}

func safeCgroupStat(st unix.Stat_t, fs unix.Statfs_t, owner uint32) bool {
	return fs.Type == unix.CGROUP2_SUPER_MAGIC && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Uid == owner && st.Mode&0o022 == 0
}

func (e LinuxExecutor) validLimits(q Request) bool {
	return q.Limits.CPU > 0 && q.Limits.MemoryMB > 0 && q.Limits.Processes > 0 && q.Limits.DiskMB > 0 && q.Limits.TimeoutS > 0 && q.Limits.OutputMB > 0
}
func (e LinuxExecutor) request(q Request, digest string, argv []string) extensionrunner.RequestV2 {
	return extensionrunner.RequestV2{RunID: q.OperationID, TaskID: q.OperationID, TaskFence: q.DispatchClaim, InstallDigest: digest, Entry: "entry", Argv: argv, TimeoutMS: q.Limits.TimeoutS * 1000, Limits: extensionrunner.LimitsV2{CPUSeconds: q.Limits.CPU, MemoryBytes: q.Limits.MemoryMB * 1024 * 1024, Processes: q.Limits.Processes, FileBytes: q.Limits.DiskMB * 1024 * 1024, OpenFiles: 1024}}
}

func (e LinuxExecutor) runInstall(ctx context.Context, q Request) error {
	if err := e.publishShell(); err != nil {
		return ErrDenied
	}
	b, err := os.ReadFile(e.StaticShell)
	if err != nil {
		return ErrDenied
	}
	m := []extensionrunner.ManifestEntry{{Path: "entry", SHA256: extensionrunner.DigestBytes(b), Size: int64(len(b))}}
	d := extensionrunner.ManifestDigest(m)
	r := e.request(q, d, []string{"sh", "-eu", "-c", "set -eu\n" + strings.Join(q.CommandSteps, "\n") + "\n"})
	r.ResultFiles = []string{q.Service}
	install, err := (extensionrunner.DiskInstallResolver{Root: e.InstallRoot}).ResolveInstall(d)
	if err != nil {
		return ErrDenied
	}
	defer install.Close()
	workspace, err := (extensionrunner.DiskWorkspaceResolver{Root: e.WorkspaceRoot}).ResolveWorkspace(q.OperationID, q.DispatchClaim)
	if err != nil {
		return ErrDenied
	}
	defer unix.Close(workspace)
	service, err := extensionrunner.RunCoreResultV1(ctx, extensionrunner.LinuxBackend{CgroupRoot: e.CgroupRoot}, extensionrunner.SandboxInvocationV2{Request: r, Install: install, WorkspaceFD: workspace, StdinFD: -1}, q.Limits.DiskMB*1024*1024, q.Service)
	if err != nil || len(service) == 0 {
		return ErrDenied
	}
	// The private tmpfs was destroyed with the manager. Publish only the
	// validated sealed export into the runner-owned staging workspace.
	path := filepath.Join(e.WorkspaceRoot, q.OperationID, q.DispatchClaim, q.Service)
	if err := os.WriteFile(path, service, 0600); err != nil {
		return ErrDenied
	}
	return nil
}

func (e LinuxExecutor) readWorkspaceService(q Request) ([]byte, error) {
	fd, err := (extensionrunner.DiskWorkspaceResolver{Root: e.WorkspaceRoot}).ResolveWorkspace(q.OperationID, q.DispatchClaim)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	how := &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS}
	f, err := unix.Openat2(fd, q.Service, how)
	if err != nil {
		return nil, err
	}
	defer unix.Close(f)
	var st unix.Stat_t
	if unix.Fstat(f, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size <= 0 || st.Size > maxServiceBytes {
		return nil, ErrDenied
	}
	file := os.NewFile(uintptr(f), "service")
	b, err := io.ReadAll(io.LimitReader(file, maxServiceBytes+1))
	_ = file.Close()
	f = -1
	if err != nil || int64(len(b)) != st.Size {
		return nil, ErrDenied
	}
	return b, nil
}

func (e LinuxExecutor) publishService(service []byte) (string, *extensionrunner.AdmittedInstall, []string, error) {
	if !filepath.IsAbs(e.InstallRoot) || !filepath.IsAbs(e.StaticShell) {
		return "", nil, nil, ErrDenied
	}
	shell, err := os.ReadFile(e.StaticShell)
	if err != nil || len(shell) == 0 {
		return "", nil, nil, ErrDenied
	}
	entries := []extensionrunner.ManifestEntry{}
	files := map[string][]byte{}
	argv := []string{}
	if isELF(service) {
		files["entry"] = service
		entries = append(entries, extensionrunner.ManifestEntry{Path: "entry", SHA256: extensionrunner.DigestBytes(service), Size: int64(len(service))})
	} else if bytes.HasPrefix(service, []byte("#!")) && len(service) <= maxServiceBytes {
		files["entry"], files["service"] = shell, service
		entries = []extensionrunner.ManifestEntry{{Path: "entry", SHA256: extensionrunner.DigestBytes(shell), Size: int64(len(shell))}, {Path: "service", SHA256: extensionrunner.DigestBytes(service), Size: int64(len(service))}}
		argv = []string{"sh", "-eu", "/app/service"}
	} else {
		return "", nil, nil, ErrDenied
	}
	d := extensionrunner.ManifestDigest(entries)
	target := filepath.Join(e.InstallRoot, d)
	if err := os.Mkdir(target, 0700); err != nil && !os.IsExist(err) {
		return "", nil, nil, err
	}
	for n, b := range files {
		if err := writeSync(filepath.Join(target, n), b, 0500); err != nil {
			return "", nil, nil, err
		}
	}
	manifest, err := json.Marshal(extensionrunner.DiskInstallManifestV1{SchemaVersion: "dirextalk.extension.install-manifest/v1", Entries: entries})
	if err != nil {
		return "", nil, nil, err
	}
	if err = writeSync(filepath.Join(target, ".dirextalk-install-v1.json"), append(manifest, '\n'), 0400); err != nil {
		return "", nil, nil, err
	}
	if dfd, e := os.Open(target); e == nil {
		e = dfd.Sync()
		_ = dfd.Close()
		if e != nil {
			return "", nil, nil, e
		}
	}
	install, err := (extensionrunner.DiskInstallResolver{Root: e.InstallRoot}).ResolveInstall(d)
	if err != nil {
		return "", nil, nil, err
	}
	return d, install, argv, nil
}
func writeSync(path string, b []byte, mode os.FileMode) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	c := f.Close()
	if e == nil {
		e = c
	}
	return e
}
func isELF(b []byte) bool {
	x, e := elf.NewFile(bytes.NewReader(b))
	if e != nil {
		return false
	}
	defer x.Close()
	for _, p := range x.Progs {
		if p.Type == elf.PT_INTERP {
			return false
		}
	}
	n, e := x.DynString(elf.DT_NEEDED)
	return e != nil || len(n) == 0
}
func (e LinuxExecutor) admittedDigest(d string) bool {
	a, err := (extensionrunner.DiskInstallResolver{Root: e.InstallRoot}).ResolveInstall(d)
	if err != nil {
		return false
	}
	return a.Close() == nil
}
func (e LinuxExecutor) identityOwned(id extensionrunner.PersistentIdentity) bool {
	return id.PID > 0 && id.StartTime > 0 && filepath.Dir(id.Cgroup) == e.CgroupRoot && filepath.Base(id.Cgroup) != ""
}
func (e LinuxExecutor) monitorPersistent(_ context.Context, q Request, digest string, p *extensionrunner.PersistentServiceV1) {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(time.Duration(q.Limits.TimeoutS) * time.Second)
	defer deadline.Stop()
	for {
		select {
		case <-deadline.C:
			_ = p.Destroy(context.Background())
			return
		case <-tick.C:
		}
		if p.OutputExceeded() || p.OutputBytes() > q.Limits.OutputMB*1024*1024 {
			_ = p.Destroy(context.Background())
			return
		}
		// A vanished service needs no monitor. Destroy is deliberately not
		// called here: only an explicit fenced destroy writes a tombstone.
		id := p.Identity()
		if extensionrunner.ValidatePersistentIdentity(id) != nil {
			return
		}
	}
}
func (e LinuxExecutor) removeWorkspace(q Request) error {
	return os.RemoveAll(filepath.Join(e.WorkspaceRoot, q.OperationID, q.DispatchClaim))
}
func (e LinuxExecutor) removeBundle(d string) error {
	return os.RemoveAll(filepath.Join(e.InstallRoot, d))
}

func (e LinuxExecutor) publishShell() error {
	if !filepath.IsAbs(e.InstallRoot) || !filepath.IsAbs(e.StaticShell) {
		return ErrDenied
	}
	info, err := os.Stat(e.StaticShell)
	if err != nil {
		return ErrDenied
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(st.Uid) != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return ErrDenied
	}
	b, err := os.ReadFile(e.StaticShell)
	if err != nil || len(b) == 0 {
		return ErrDenied
	}
	m := []extensionrunner.ManifestEntry{{Path: "entry", SHA256: extensionrunner.DigestBytes(b), Size: int64(len(b))}}
	d := extensionrunner.ManifestDigest(m)
	target := filepath.Join(e.InstallRoot, d)
	if _, err = os.Stat(target); err == nil {
		return nil
	}
	if err = os.Mkdir(target, 0700); err != nil {
		return err
	}
	if err = writeSync(filepath.Join(target, "entry"), b, 0500); err != nil {
		return err
	}
	manifest, err := json.Marshal(extensionrunner.DiskInstallManifestV1{SchemaVersion: "dirextalk.extension.install-manifest/v1", Entries: m})
	if err != nil {
		return err
	}
	return writeSync(filepath.Join(target, ".dirextalk-install-v1.json"), append(manifest, '\n'), 0400)
}

var _ = sha256.Size
var _ = hex.EncodeToString
