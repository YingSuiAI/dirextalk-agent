//go:build linux

package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

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
	service, err := e.readWorkspaceService(q)
	if err != nil {
		return Receipt{}, ErrDenied
	}
	digest, install, argv, err := e.publishService(service)
	if err != nil {
		return Receipt{}, ErrDenied
	}
	defer install.Close()
	workspace, err := (extensionrunner.DiskWorkspaceResolver{Root: e.WorkspaceRoot}).ResolveWorkspace(q.OperationID, q.DispatchClaim)
	if err != nil {
		return Receipt{}, ErrDenied
	}
	defer unix.Close(workspace)
	r := e.request(q, digest, argv)
	p, err := extensionrunner.StartPersistentServiceV1(ctx, extensionrunner.LinuxBackend{CgroupRoot: e.CgroupRoot}, extensionrunner.SandboxInvocationV2{Request: r, Install: install, WorkspaceFD: workspace, StdinFD: -1}, time.Millisecond)
	if err != nil {
		return Receipt{}, ErrDenied
	}
	id := p.Identity()
	if !e.identityOwned(id) || e.exceedsDisk(q) {
		_ = p.Destroy(context.Background())
		return Receipt{}, ErrDenied
	}
	// The rlimit only covers the writable sandbox view. Keep a separate
	// aggregate accounting guard over the runner-owned workspace and bundle so
	// a long-lived service cannot grow either side after admission.
	go e.monitorDisk(q, p)
	return Receipt{State: "ready", ServiceDigest: digest, PID: id.PID, StartTime: id.StartTime, Cgroup: id.Cgroup}, nil
}

func (e LinuxExecutor) ReadPersistent(_ context.Context, q Request, prior Receipt) (Receipt, error) {
	if prior.Destroyed || prior.State != "ready" || prior.ServiceDigest == "" || !e.identityOwned(extensionrunner.PersistentIdentity{PID: prior.PID, StartTime: prior.StartTime, Cgroup: prior.Cgroup}) {
		return Receipt{State: "unknown"}, nil
	}
	if err := extensionrunner.ValidatePersistentIdentity(extensionrunner.PersistentIdentity{PID: prior.PID, StartTime: prior.StartTime, Cgroup: prior.Cgroup}); err != nil || e.exceedsDisk(q) || !e.admittedDigest(prior.ServiceDigest) {
		return Receipt{State: "unknown"}, nil
	}
	return Receipt{State: "ready", ServiceDigest: prior.ServiceDigest, PID: prior.PID, StartTime: prior.StartTime, Cgroup: prior.Cgroup}, nil
}

func (e LinuxExecutor) DestroyPersistent(ctx context.Context, q Request, prior Receipt) (Receipt, error) {
	if prior.Destroyed {
		return Receipt{State: "destroyed", ServiceDigest: prior.ServiceDigest, PID: prior.PID, StartTime: prior.StartTime, Cgroup: prior.Cgroup}, nil
	}
	id := extensionrunner.PersistentIdentity{PID: prior.PID, StartTime: prior.StartTime, Cgroup: prior.Cgroup}
	if prior.State != "ready" || !e.identityOwned(id) || !e.admittedDigest(prior.ServiceDigest) {
		return Receipt{}, ErrDenied
	}
	if err := extensionrunner.DestroyPersistentIdentity(ctx, id); err != nil {
		return Receipt{}, ErrDenied
	}
	if err := e.removeWorkspace(q); err != nil {
		return Receipt{}, ErrDenied
	}
	if err := e.removeBundle(prior.ServiceDigest); err != nil {
		return Receipt{}, ErrDenied
	}
	return Receipt{State: "destroyed", ServiceDigest: prior.ServiceDigest, PID: prior.PID, StartTime: prior.StartTime, Cgroup: prior.Cgroup}, nil
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
	status, err := (extensionrunner.Runner{InstallResolver: extensionrunner.DiskInstallResolver{Root: e.InstallRoot}, WorkspaceResolver: extensionrunner.DiskWorkspaceResolver{Root: e.WorkspaceRoot}, V2Backend: extensionrunner.LinuxBackend{CgroupRoot: e.CgroupRoot}}).RunV2(ctx, r, nil, extensionrunner.NewRunRegistry())
	if err != nil || status.Error != extensionrunner.ErrorNone || status.ExitCode == nil || *status.ExitCode != 0 || int64(len(status.Stdout)+len(status.Stderr)) > q.Limits.OutputMB*1024*1024 || e.exceedsDisk(q) {
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
func (e LinuxExecutor) exceedsDisk(q Request) bool {
	n, err := treeBytes(e.WorkspaceRoot)
	if err != nil {
		return true
	}
	m, err := treeBytes(e.InstallRoot)
	return err != nil || n+m > q.Limits.DiskMB*1024*1024
}
func (e LinuxExecutor) monitorDisk(q Request, p *extensionrunner.PersistentServiceV1) {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for range tick.C {
		if e.exceedsDisk(q) {
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
func treeBytes(root string) (int64, error) {
	var n int64
	err := filepath.Walk(root, func(_ string, i os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if i.Mode().IsRegular() {
			n += i.Size()
		}
		return nil
	})
	return n, err
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
