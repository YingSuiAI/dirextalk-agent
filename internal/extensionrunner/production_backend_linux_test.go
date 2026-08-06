//go:build linux

package extensionrunner

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPeerDisconnectCancelsRunContext(t *testing.T) {
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	serverFile := os.NewFile(uintptr(sockets[0]), "server")
	connection, err := net.FileConn(serverFile)
	_ = serverFile.Close()
	if err != nil {
		_ = unix.Close(sockets[1])
		t.Fatal(err)
	}
	server := connection.(*net.UnixConn)
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go monitorPeerDisconnect(server, done, cancel)
	if err := unix.Close(sockets[1]); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		close(done)
		t.Fatal("peer disconnect did not cancel run")
	}
	close(done)
}

func TestSandboxBootstrapMustBeCanonicalAndSealed(t *testing.T) {
	request := sandboxRequest()
	value := bootstrapV1{
		Request:     request,
		SecretCount: 0,
		HasStdin:    false,
		RootDev:     1,
		RootIno:     2,
		EntryDev:    3,
		EntryIno:    4,
		EntryMode:   unix.S_IFREG | 0o555,
		EntrySize:   12,
		EntrySHA256: DigestBytes([]byte("entry")),
	}
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := sealedMemfd("bootstrap-test", body)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	got, err := readSandboxBootstrap(fd)
	if err != nil || got.EntrySHA256 != value.EntrySHA256 {
		t.Fatalf("got=%+v err=%v", got, err)
	}

	unsealed, err := unix.MemfdCreate("unsealed", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(unsealed)
	if _, err = unix.Write(unsealed, body); err != nil {
		t.Fatal(err)
	}
	if _, err = readSandboxBootstrap(unsealed); err == nil {
		t.Fatal("unsealed bootstrap accepted")
	}

	noncanonical, err := sealedMemfd("noncanonical", append(body, '\n'))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(noncanonical)
	if _, err = readSandboxBootstrap(noncanonical); err == nil {
		t.Fatal("noncanonical bootstrap accepted")
	}
}

func TestCoreSandboxBootstrapBindsManagerIdentity(t *testing.T) {
	request := sandboxRequest()
	value := bootstrapV1{
		Request: request, RootDev: 1, RootIno: 2, EntryDev: 3, EntryIno: 4,
		EntryMode: unix.S_IFREG | 0o555, EntrySize: 12, EntrySHA256: DigestBytes([]byte("entry")),
		ManagerBase: "dirextalk-core-runner", ManagerRootDev: 5, ManagerRootIno: 6,
		ManagerDev: 7, ManagerIno: 8, ManagerMode: unix.S_IFREG | 0o555,
		ManagerSize: 13, ManagerSHA256: DigestBytes([]byte("manager")), CoreTmpfsBytes: 1 << 20,
	}
	seal := func(v bootstrapV1) int {
		body, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		fd, err := sealedMemfd("core-bootstrap-test", body)
		if err != nil {
			t.Fatal(err)
		}
		return fd
	}
	fd := seal(value)
	if _, err := readSandboxBootstrap(fd); err != nil {
		unix.Close(fd)
		t.Fatalf("valid manager binding rejected: %v", err)
	}
	unix.Close(fd)
	for _, mutate := range []func(*bootstrapV1){
		func(v *bootstrapV1) { v.ManagerBase = "../escape" },
		func(v *bootstrapV1) { v.ManagerIno = 0 },
		func(v *bootstrapV1) { v.ManagerMode |= 0o020 },
		func(v *bootstrapV1) { v.ManagerSHA256 = strings.Repeat("0", 63) },
	} {
		tampered := value
		mutate(&tampered)
		fd = seal(tampered)
		if _, err := readSandboxBootstrap(fd); err == nil {
			unix.Close(fd)
			t.Fatal("tampered manager binding accepted")
		}
		unix.Close(fd)
	}
}

func TestManagerSourceBindsCurrentExecutableParent(t *testing.T) {
	root, fd, base, rootStat, st, digest, err := openManagerSource("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(root)
	defer unix.Close(fd)
	if !safeName(base) || rootStat.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&unix.S_IFMT != unix.S_IFREG || digest == "" {
		t.Fatalf("manager source base=%q root=%#o file=%#o digest=%q", base, rootStat.Mode, st.Mode, digest)
	}
	opened, err := unix.Openat(root, base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(opened)
	var got unix.Stat_t
	if unix.Fstat(opened, &got) != nil || got.Dev != st.Dev || got.Ino != st.Ino {
		t.Fatal("manager basename did not resolve to the bound executable")
	}
}

func TestResultFilesStayBeneathWorkspaceFD(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("registered result")
	if err := os.WriteFile(filepath.Join(root, "nested", "result.txt"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	files, err := VerifyResultFilesFD(fd, []string{"nested/result.txt"})
	if err != nil || len(files) != 1 {
		t.Fatalf("files=%+v err=%v", files, err)
	}
	sum := sha256.Sum256(content)
	if files[0].SHA256 != hex.EncodeToString(sum[:]) || files[0].Size != int64(len(content)) {
		t.Fatalf("file=%+v", files[0])
	}
	if _, err = VerifyResultFilesFD(fd, []string{"escape"}); err == nil {
		t.Fatal("symlink escape accepted")
	}
}

func TestResultFilesRejectNonRegularWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	if err := unix.Mkfifo(filepath.Join(root, "result.fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(root, "result.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	for _, path := range []string{"result.fifo", "result.sock"} {
		done := make(chan error, 1)
		go func() { _, err := VerifyResultFilesFD(fd, []string{path}); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("%s accepted", path)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s blocked result collection", path)
		}
	}
}

func TestCPUFinalSampleClassifiesExitedProcessAtLimit(t *testing.T) {
	cgroup := t.TempDir()
	if err := os.WriteFile(filepath.Join(cgroup, "cpu.stat"), []byte("usage_usec 100\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &reexecProcess{
		cgroup:        cgroup,
		out:           &boundedBuffer{},
		err:           &boundedBuffer{},
		cpuStop:       make(chan struct{}),
		cpuDone:       make(chan struct{}),
		cpuBudgetUsec: 100,
	}
	close(p.cpuDone) // The periodic monitor has already exited before Wait joins it.
	p.finishCPUMonitor()
	_, _, status, err := p.waitResult(nil)
	if status != "cpu_limit" || !errors.Is(err, errCPULimitExceeded) {
		t.Fatalf("status=%q err=%v", status, err)
	}
}

func TestCPUAccountingFailureCannotSucceed(t *testing.T) {
	p := &reexecProcess{
		cgroup:  t.TempDir(),
		out:     &boundedBuffer{},
		err:     &boundedBuffer{},
		cpuStop: make(chan struct{}),
		cpuDone: make(chan struct{}),
	}
	close(p.cpuDone) // The monitor has stopped; the final accounting sample fails.
	p.finishCPUMonitor()
	_, _, status, err := p.waitResult(nil)
	if status != "cpu_monitor_failed" || !errors.Is(err, errCPUAccounting) {
		t.Fatalf("status=%q err=%v", status, err)
	}
}

func TestPersistentOutputBudgetIsSharedAndDoesNotRetainRawBytes(t *testing.T) {
	budget := &outputBudget{limit: 8}
	stdout := &boundedBuffer{budget: budget}
	stderr := &boundedBuffer{budget: budget}
	if n, err := stdout.Write([]byte("1234")); err != nil || n != 4 {
		t.Fatalf("stdout write n=%d err=%v", n, err)
	}
	if n, err := stderr.Write([]byte("5678")); err != nil || n != 4 {
		t.Fatalf("stderr write n=%d err=%v", n, err)
	}
	if stdout.Exceeded() || stderr.Exceeded() {
		t.Fatal("exact combined budget was marked exceeded")
	}
	if got := len(stdout.Snapshot()) + len(stderr.Snapshot()); got != 0 {
		t.Fatalf("persistent raw output retained %d bytes", got)
	}
	if n, err := stdout.Write([]byte("x")); err != nil || n != 1 {
		t.Fatalf("first excess write n=%d err=%v", n, err)
	}
	if !stdout.Exceeded() || !stderr.Exceeded() {
		t.Fatal("first byte over shared budget was not signalled")
	}
	if used, _ := budget.snapshot(); used != 8 {
		t.Fatalf("budget used=%d want 8", used)
	}
}

func TestReexecWaitContextReturnsCleanupFailureInsteadOfCancellation(t *testing.T) {
	cgroup := t.TempDir()
	if err := os.WriteFile(filepath.Join(cgroup, "cpu.stat"), []byte("usage_usec 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", "sleep 0.05")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &reexecProcess{
		cmd:           cmd,
		pidfd:         -1,
		cgroup:        cgroup,
		out:           &boundedBuffer{},
		err:           &boundedBuffer{},
		waitDone:      make(chan struct{}),
		cpuStop:       make(chan struct{}),
		cpuDone:       make(chan struct{}),
		cpuBudgetUsec: 1,
		cgroupOps: cgroupOps{
			write:  func(string, []byte, os.FileMode) error { return nil },
			read:   func(string) ([]byte, error) { return []byte("populated 0\n"), nil },
			remove: func(string) error { return errors.New("remove") },
			sleep:  func(time.Duration) {},
		},
	}
	close(p.cpuDone)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err := p.WaitContext(ctx)
	if !errors.Is(err, errCgroupCleanup) || errors.Is(err, context.Canceled) {
		t.Fatalf("WaitContext error=%v, want cleanup failure", err)
	}
}

func TestAvailableResultsContinuePastInvalidAndPreserveLaterFiles(t *testing.T) {
	root := t.TempDir()
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	baseline, err := SnapshotWorkspaceFD(fd)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"first.txt", "last.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mkfifo(filepath.Join(root, "invalid.fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := CollectAvailableResultFilesFD(fd, []string{"first.txt", "invalid.fifo", "last.txt"})
	if !errors.Is(err, ErrInvalid) || len(files) != 2 || files[0].Path != "first.txt" || files[1].Path != "last.txt" {
		t.Fatalf("files=%+v err=%v", files, err)
	}
	if err := CleanupWorkspaceFD(fd, baseline, resultFilePaths(files)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"first.txt", "last.txt"} {
		if _, err := os.Lstat(filepath.Join(root, name)); err != nil {
			t.Fatalf("valid result %s removed: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "invalid.fifo")); !os.IsNotExist(err) {
		t.Fatalf("invalid result remained: %v", err)
	}
}

func TestWorkspaceCleanupPreservesBaselineAndRegisteredResults(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "input.txt"), []byte("input"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	baseline, err := SnapshotWorkspaceFD(fd)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "output"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "output", "keep.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "discard.txt"), []byte("discard"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "discard-link")); err != nil {
		t.Fatal(err)
	}
	if err := CleanupWorkspaceFD(fd, baseline, []string{"output/keep.txt"}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"input.txt", "output/keep.txt"} {
		if _, err := os.Lstat(filepath.Join(root, path)); err != nil {
			t.Fatalf("%s removed: %v", path, err)
		}
	}
	for _, path := range []string{"discard.txt", "discard-link"} {
		if _, err := os.Lstat(filepath.Join(root, path)); !os.IsNotExist(err) {
			t.Fatalf("%s remained: %v", path, err)
		}
	}
}

func TestWorkspaceCleanupRemovesReplacedBaselineIdentity(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "parent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "parent", "baseline"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	baseline, err := SnapshotWorkspaceFD(fd)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "parent", "baseline")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "parent", "baseline"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "parent", "baseline", "replacement.txt"), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CleanupWorkspaceFD(fd, baseline, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "parent")); err != nil {
		t.Fatalf("unchanged baseline parent removed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "parent", "baseline")); !os.IsNotExist(err) {
		t.Fatalf("replaced baseline remained: %v", err)
	}
}

func TestWorkspaceCleanupPreservesRegisteredBaselineReplacement(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "result.txt"), []byte("baseline"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	baseline, err := SnapshotWorkspaceFD(fd)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "result.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "result.txt"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CleanupWorkspaceFD(fd, baseline, []string{"result.txt"}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(filepath.Join(root, "result.txt")); err != nil || !info.IsDir() {
		t.Fatalf("registered replacement not preserved: info=%v err=%v", info, err)
	}
}

func TestWorkspaceCleanupPreservesNestedKeepUnderReplacedBaselineAncestor(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "output"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "output", "baseline.txt"), []byte("baseline"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	baseline, err := SnapshotWorkspaceFD(fd)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, "output")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "output"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "output", "result.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "output", "discard.txt"), []byte("discard"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CleanupWorkspaceFD(fd, baseline, []string{"output/result.json"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "output", "result.json")); err != nil {
		t.Fatalf("nested registered result removed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "output", "discard.txt")); !os.IsNotExist(err) {
		t.Fatalf("unregistered sibling remained: %v", err)
	}
}

func TestSeccompAllowlistOmitsHostEscapeSyscalls(t *testing.T) {
	allowed := map[uint32]bool{}
	for _, number := range sandboxAllowedSyscalls() {
		allowed[number] = true
	}
	for name, number := range map[string]uint32{
		"socket":          uint32(unix.SYS_SOCKET),
		"connect":         uint32(unix.SYS_CONNECT),
		"mount":           uint32(unix.SYS_MOUNT),
		"umount2":         uint32(unix.SYS_UMOUNT2),
		"pivot_root":      uint32(unix.SYS_PIVOT_ROOT),
		"unshare":         uint32(unix.SYS_UNSHARE),
		"setns":           uint32(unix.SYS_SETNS),
		"ptrace":          uint32(unix.SYS_PTRACE),
		"bpf":             uint32(unix.SYS_BPF),
		"keyctl":          uint32(unix.SYS_KEYCTL),
		"perf_event_open": uint32(unix.SYS_PERF_EVENT_OPEN),
		"clone3":          uint32(unix.SYS_CLONE3),
		"io_uring_setup":  uint32(unix.SYS_IO_URING_SETUP),
	} {
		if allowed[number] {
			t.Fatalf("%s unexpectedly allowed", name)
		}
	}
	if !allowed[uint32(unix.SYS_EXECVE)] || !allowed[uint32(unix.SYS_EXIT_GROUP)] {
		t.Fatal("basic static process syscalls missing")
	}
	filters := sandboxSeccompFilters()
	if len(filters) < 10 || filters[len(filters)-1].K != uint32(unix.SECCOMP_RET_ERRNO)|uint32(unix.EPERM) {
		t.Fatal("seccomp does not fail closed")
	}
	clone3Fallback := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.ENOSYS)
	clone3FallbackFound := false
	for _, filter := range filters {
		clone3FallbackFound = clone3FallbackFound || filter.K == clone3Fallback
	}
	if !clone3FallbackFound {
		t.Fatal("clone3 must fail with ENOSYS so process creation falls back to filtered clone")
	}
}

func TestCgroupCPUUsageParsing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cpu.stat")
	if err := os.WriteFile(path, []byte("usage_usec 12345\nuser_usec 12000\nsystem_usec 345\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	usage, err := readCgroupCPUUsage(path)
	if err != nil || usage != 12345 {
		t.Fatalf("usage=%d err=%v", usage, err)
	}
	if err := os.WriteFile(path, []byte("user_usec 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCgroupCPUUsage(path); err == nil {
		t.Fatal("missing usage accepted")
	}
}

func TestDiskInstallResolverRequiresExactImmutableTree(t *testing.T) {
	root := t.TempDir()
	entry := minimalStaticELF(t)
	resource := []byte("resource")
	entries := []ManifestEntry{
		{Path: "entry", SHA256: DigestBytes(entry), Size: int64(len(entry))},
		{Path: "resources/value.txt", SHA256: DigestBytes(resource), Size: int64(len(resource))},
	}
	digest := ManifestDigest(entries)
	install := filepath.Join(root, digest)
	t.Cleanup(func() {
		_ = os.Chmod(install, 0o700)
		_ = os.Chmod(filepath.Join(install, "resources"), 0o700)
	})
	if err := os.MkdirAll(filepath.Join(install, "resources"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(install, "entry"), entry, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(install, "resources", "value.txt"), resource, 0o400); err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(DiskInstallManifestV1{SchemaVersion: installManifestSchemaV1, Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(install, installManifestName), append(manifest, '\n'), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(install, "resources"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(install, 0o500); err != nil {
		t.Fatal(err)
	}
	admitted, err := (DiskInstallResolver{Root: root}).ResolveInstall(digest)
	if err != nil {
		t.Fatalf("valid immutable install rejected: %v", err)
	}
	if err := admitted.Close(); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(install, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(install, "unexpected"), []byte("extra"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(install, 0o500); err != nil {
		t.Fatal(err)
	}
	if admitted, err = (DiskInstallResolver{Root: root}).ResolveInstall(digest); err == nil {
		_ = admitted.Close()
		t.Fatal("unmanifested file accepted")
	}
}

func minimalStaticELF(t *testing.T) []byte {
	t.Helper()
	var machine uint16
	var code []byte
	switch runtime.GOARCH {
	case "amd64":
		machine = uint16(62)
		code = []byte{0x48, 0xc7, 0xc0, 0x3c, 0, 0, 0, 0x48, 0x31, 0xff, 0x0f, 0x05}
	case "arm64":
		machine = uint16(183)
		code = []byte{0xa8, 0x0b, 0x80, 0xd2, 0x00, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4}
	default:
		t.Skip("unsupported architecture")
	}
	const headerSize = 64
	const programHeaderSize = 56
	size := headerSize + programHeaderSize + len(code)
	body := make([]byte, size)
	copy(body[:16], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(body[16:], 2)
	binary.LittleEndian.PutUint16(body[18:], machine)
	binary.LittleEndian.PutUint32(body[20:], 1)
	binary.LittleEndian.PutUint64(body[24:], 0x400000+headerSize+programHeaderSize)
	binary.LittleEndian.PutUint64(body[32:], headerSize)
	binary.LittleEndian.PutUint16(body[52:], headerSize)
	binary.LittleEndian.PutUint16(body[54:], programHeaderSize)
	binary.LittleEndian.PutUint16(body[56:], 1)
	program := body[headerSize : headerSize+programHeaderSize]
	binary.LittleEndian.PutUint32(program[0:], 1)
	binary.LittleEndian.PutUint32(program[4:], 5)
	binary.LittleEndian.PutUint64(program[16:], 0x400000)
	binary.LittleEndian.PutUint64(program[24:], 0x400000)
	binary.LittleEndian.PutUint64(program[32:], uint64(size))
	binary.LittleEndian.PutUint64(program[40:], uint64(size))
	binary.LittleEndian.PutUint64(program[48:], 0x1000)
	copy(body[headerSize+programHeaderSize:], code)
	return body
}
