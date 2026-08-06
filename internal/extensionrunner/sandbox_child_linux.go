//go:build linux

package extensionrunner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

const coreResultMaxBytes = 16 << 20

var coreResultPathRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$`)

const (
	sandboxBootstrapFD = 3
	sandboxReleaseFD   = 4
	sandboxInstallFD   = 5
	sandboxEntryFD     = 6
	sandboxWorkspaceFD = 7
	sandboxStdinFD     = 8
	// Core mode forbids stdin and secret descriptors, so its two manager-only
	// descriptors occupy the otherwise-unused fd 8 and 9 slots.
	sandboxManagerFD = 8
	sandboxResultFD  = 9
)

// sandboxChildStageError intentionally discards the underlying error. The
// fixed child command may write only its low-cardinality stage and cause class
// to stderr.
type sandboxChildStageError struct{ stage, cause string }

func (e sandboxChildStageError) Error() string { return e.stage + ":" + e.cause }
func (e sandboxChildStageError) Unwrap() error { return ErrDenied }

func sandboxChildFailure(stage string, err error) error {
	var safe sandboxChildStageError
	if errors.As(err, &safe) {
		return err
	}
	return sandboxChildStageError{stage: stage, cause: sandboxChildCause(err)}
}

func sandboxChildCause(err error) string {
	switch {
	case errors.Is(err, ErrDenied):
		return "denied"
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return "permission"
	case errors.Is(err, unix.ENOENT):
		return "missing"
	case errors.Is(err, unix.EBUSY):
		return "busy"
	case errors.Is(err, unix.EINVAL):
		return "invalid"
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EOPNOTSUPP):
		return "unsupported"
	default:
		return "other"
	}
}

func readSandboxBootstrap(fd int) (bootstrapV1, error) {
	var empty bootstrapV1
	seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	required := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if err != nil || seals&required != required {
		return empty, ErrDenied
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size <= 0 || st.Size > MaxMessageBytes {
		return empty, ErrDenied
	}
	body := make([]byte, int(st.Size))
	n, err := unix.Pread(fd, body, 0)
	if err != nil || n != len(body) {
		return empty, ErrDenied
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var value bootstrapV1
	if err := decoder.Decode(&value); err != nil {
		return empty, ErrDenied
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return empty, ErrDenied
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, body) {
		return empty, ErrDenied
	}
	if ValidateRequestV2(value.Request) != nil ||
		value.SecretCount != len(value.Request.Secrets) ||
		value.HasStdin != (value.Request.Stdin != nil) ||
		value.EntrySize < 0 ||
		!digestRE.MatchString(value.EntrySHA256) {
		return empty, ErrDenied
	}
	if value.CoreTmpfsBytes > 0 {
		if !safeName(value.ManagerBase) || value.ManagerRootIno == 0 || value.ManagerIno == 0 || value.ManagerSize <= 0 || value.ManagerMode&unix.S_IFMT != unix.S_IFREG || value.ManagerMode&0o111 == 0 || value.ManagerMode&0o022 != 0 || !digestRE.MatchString(value.ManagerSHA256) {
			return empty, ErrDenied
		}
	} else if value.ManagerBase != "" || value.ManagerRootDev != 0 || value.ManagerRootIno != 0 || value.ManagerDev != 0 || value.ManagerIno != 0 || value.ManagerMode != 0 || value.ManagerSize != 0 || value.ManagerSHA256 != "" {
		return empty, ErrDenied
	}
	return value, nil
}

func runSandboxChild(bootstrap bootstrapV1) error {
	runtime.LockOSThread()

	if err := verifySandboxDescriptors(bootstrap); err != nil {
		return sandboxChildFailure("descriptors", err)
	}
	nullFD := -1
	if !bootstrap.HasStdin {
		var err error
		nullFD, err = unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return sandboxChildFailure("null", err)
		}
		defer unix.Close(nullFD)
	}
	var release [1]byte
	if n, err := unix.Read(sandboxReleaseFD, release[:]); err != nil {
		return sandboxChildFailure("release", err)
	} else if n != 1 || release[0] != 1 {
		return sandboxChildFailure("release", ErrDenied)
	}
	if err := unix.Unshare(unix.CLONE_FS); err != nil {
		return sandboxChildFailure("map-fs", err)
	}
	// Create the sandbox-owned mount namespace while every admitted source is
	// still reachable.  The manager bundle lives beside the admitted install,
	// outside the temporary workspace root; cloning it after the first chroot
	// is rejected by some kernels even though the inherited directory FD still
	// identifies the correct inode.
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return sandboxChildFailure("map-namespace", err)
	}
	installMountFD, err := cloneSandboxTree(sandboxInstallFD)
	if err != nil {
		return sandboxChildFailure("app-clone", err)
	}
	workspaceMountFD, managerMountFD := -1, -1
	defer func() {
		if installMountFD >= 0 {
			_ = unix.Close(installMountFD)
		}
		if workspaceMountFD >= 0 {
			_ = unix.Close(workspaceMountFD)
		}
		if managerMountFD >= 0 {
			_ = unix.Close(managerMountFD)
		}
	}()
	if bootstrap.CoreTmpfsBytes > 0 {
		managerMountFD, err = cloneSandboxTree(sandboxManagerFD)
		if err != nil {
			return sandboxChildFailure("manager-clone", err)
		}
	} else {
		workspaceMountFD, err = cloneSandboxTree(sandboxWorkspaceFD)
		if err != nil {
			return sandboxChildFailure("work-clone", err)
		}
	}
	if err := unix.Fchdir(sandboxWorkspaceFD); err != nil {
		return sandboxChildFailure("map-root", err)
	}
	if err := unix.Chroot("."); err != nil {
		return sandboxChildFailure("map-root", err)
	}
	if err := unix.Fchdir(sandboxInstallFD); err != nil {
		return sandboxChildFailure("map-pwd", err)
	}
	mappedWorkspaceFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return sandboxChildFailure("map-verify", err)
	}
	defer func() {
		if mappedWorkspaceFD >= 0 {
			_ = unix.Close(mappedWorkspaceFD)
		}
	}()
	mappedInstallFD, err := unix.Open(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return sandboxChildFailure("map-verify", err)
	}
	defer func() {
		if mappedInstallFD >= 0 {
			_ = unix.Close(mappedInstallFD)
		}
	}()
	if err := verifyMappedSandboxDirs(mappedInstallFD, mappedWorkspaceFD); err != nil {
		return sandboxChildFailure("map-verify", err)
	}
	rootFD, err := prepareSandboxMounts(bootstrap, installMountFD, workspaceMountFD, managerMountFD)
	if err != nil {
		return sandboxChildFailure("mounts", err)
	}
	defer func() {
		if rootFD >= 0 {
			_ = unix.Close(rootFD)
		}
	}()
	for _, fd := range []*int{&installMountFD, &workspaceMountFD, &managerMountFD} {
		if *fd >= 0 {
			_ = unix.Close(*fd)
			*fd = -1
		}
	}
	if bootstrap.CoreTmpfsBytes > 0 {
		_ = unix.Close(sandboxManagerFD)
	}
	if err := unix.Fchdir(rootFD); err != nil {
		return sandboxChildFailure("root-switch", err)
	}
	if err := unix.Chroot("."); err != nil {
		return sandboxChildFailure("root-switch", err)
	}
	if err := unix.Chdir("/work"); err != nil {
		return sandboxChildFailure("root-switch", err)
	}
	closeAfterRoot := []int{sandboxBootstrapFD, sandboxReleaseFD, sandboxInstallFD, sandboxEntryFD, sandboxWorkspaceFD, mappedInstallFD, mappedWorkspaceFD, rootFD}
	if bootstrap.CoreTmpfsBytes > 0 {
		// The manager retains only bootstrap/result descriptors. The old host
		// workspace, manager source and all mount handles are closed before it
		// starts the command.
		closeAfterRoot = []int{sandboxReleaseFD, sandboxInstallFD, sandboxEntryFD, sandboxWorkspaceFD, mappedInstallFD, mappedWorkspaceFD, rootFD}
	}
	for _, fd := range closeAfterRoot {
		_ = unix.Close(fd)
	}
	mappedInstallFD, mappedWorkspaceFD, rootFD = -1, -1, -1
	if bootstrap.HasStdin {
		if err := unix.Dup2(sandboxStdinFD, 0); err != nil {
			return sandboxChildFailure("stdin", err)
		}
	} else if err := unix.Dup2(nullFD, 0); err != nil {
		return sandboxChildFailure("stdin", err)
	}
	if bootstrap.HasStdin {
		_ = unix.Close(sandboxStdinFD)
	}
	for i := 0; i < bootstrap.SecretCount; i++ {
		_ = unix.Close(sandboxStdinFD + btoi(bootstrap.HasStdin) + i)
	}
	if bootstrap.CoreTmpfsBytes > 0 {
		return runSandboxManager(bootstrap)
	}
	if err := verifySandboxStandardFDs(); err != nil {
		return sandboxChildFailure("close-fds", err)
	}
	if err := applySandboxRlimits(bootstrap.Request.Limits); err != nil {
		return sandboxChildFailure("rlimits", err)
	}
	unix.Umask(0o077)
	if err := clearSandboxCapabilities(); err != nil {
		return sandboxChildFailure("capabilities", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return sandboxChildFailure("no-new-privs", err)
	}
	if err := installSandboxSeccomp(); err != nil {
		return sandboxChildFailure("seccomp", err)
	}
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_UNSHARE); err != nil {
		return sandboxChildFailure("close-fds", err)
	}
	// /app/entry may be a BusyBox multi-call binary.  Exec selects its applet
	// from argv[0], so the first admitted argument is the executable name, not
	// a positional argument passed after the binary path.
	argv := sandboxExecArgv(bootstrap.Request.Argv)
	if err := unix.Exec("/app/entry", argv, []string{}); err != nil {
		return sandboxChildFailure("exec", err)
	}
	return nil
}

func runSandboxManager(bootstrap bootstrapV1) error {
	// The manager deliberately retains only its sealed bootstrap and optional
	// result memfd. The immutable reexec image is reachable only through the
	// temporary /run/manager mount; the command receives only bootstrap fd 3.
	if bootstrap.CoreTmpfsBytes <= 0 {
		return sandboxChildFailure("manager", ErrDenied)
	}
	boot, err := unix.Dup(sandboxBootstrapFD)
	if err != nil {
		return sandboxChildFailure("manager", err)
	}
	bootFile := os.NewFile(uintptr(boot), "sandbox-bootstrap")
	releaseR, releaseW, err := os.Pipe()
	if err != nil {
		_ = bootFile.Close()
		return sandboxChildFailure("manager-release", err)
	}
	managerPath := filepath.Join("/run/manager", bootstrap.ManagerBase)
	cmd := exec.Command(managerPath, "__sandbox-command-v1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	// Start waits for the kernel's exec result. The child then blocks on fd 4,
	// allowing the trusted manager directory to be detached before any
	// untrusted entry is executed.
	cmd.ExtraFiles = []*os.File{bootFile, releaseR}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if cmd.Start() != nil {
		_ = releaseR.Close()
		_ = releaseW.Close()
		_ = bootFile.Close()
		return sandboxChildFailure("command", ErrDenied)
	}
	_ = releaseR.Close()
	_ = bootFile.Close()
	abort := func() {
		_ = releaseW.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	if err := unix.Unmount("/run/manager", unix.MNT_DETACH); err != nil {
		abort()
		return sandboxChildFailure("manager-hide", err)
	}
	if _, err := os.Lstat(managerPath); !errors.Is(err, os.ErrNotExist) {
		abort()
		return sandboxChildFailure("manager-hide", ErrDenied)
	}
	if err := clearSandboxCapabilities(); err != nil {
		abort()
		return sandboxChildFailure("capabilities", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		abort()
		return sandboxChildFailure("no-new-privs", err)
	}
	if n, err := releaseW.Write([]byte{1}); err != nil || n != 1 {
		abort()
		return sandboxChildFailure("manager-release", ErrDenied)
	}
	_ = releaseW.Close()
	if cmd.Wait() != nil {
		return sandboxChildFailure("command", ErrDenied)
	}
	if bootstrap.CoreResultPath != "" {
		if err := exportSandboxResult(sandboxResultFD, bootstrap.CoreResultPath); err != nil {
			return sandboxChildFailure("result-export", err)
		}
	}
	return nil
}

func runSandboxCommand(bootstrap bootstrapV1) error {
	var release [1]byte
	if n, err := unix.Read(4, release[:]); err != nil || n != 1 || release[0] != 1 {
		return sandboxChildFailure("manager-release", ErrDenied)
	}
	_ = unix.Close(4)
	_ = unix.Close(sandboxBootstrapFD)
	if err := applySandboxRlimits(bootstrap.Request.Limits); err != nil {
		return sandboxChildFailure("rlimits", err)
	}
	if err := clearSandboxCapabilities(); err != nil {
		return sandboxChildFailure("capabilities", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return sandboxChildFailure("no-new-privs", err)
	}
	if err := installSandboxSeccomp(); err != nil {
		return sandboxChildFailure("seccomp", err)
	}
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_UNSHARE); err != nil {
		return sandboxChildFailure("close-fds", err)
	}
	return unix.Exec("/app/entry", sandboxExecArgv(bootstrap.Request.Argv), []string{})
}

func sandboxExecArgv(args []string) []string {
	if len(args) == 0 {
		return []string{"/app/entry"}
	}
	return append([]string(nil), args...)
}

func exportSandboxResult(resultFD int, name string) error {
	if resultFD < 0 || !coreResultPathRE.MatchString(name) || filepath.IsAbs(name) || name == "." || name == ".." {
		return ErrDenied
	}
	root, err := unix.Open("/work", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(root)
	fd, err := unix.Openat2(root, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size <= 0 || st.Size > coreResultMaxBytes {
		return ErrDenied
	}
	if err = unix.Ftruncate(resultFD, 0); err != nil {
		return err
	}
	buf := make([]byte, 64<<10)
	var off int64
	for off < st.Size {
		n, er := unix.Pread(fd, buf, off)
		if er != nil || n <= 0 {
			return ErrDenied
		}
		if written, ew := unix.Pwrite(resultFD, buf[:n], off); ew != nil || written != n {
			return ErrDenied
		}
		off += int64(n)
	}
	if err = unix.Ftruncate(resultFD, st.Size); err != nil || unix.Fsync(resultFD) != nil {
		return ErrDenied
	}
	_, err = unix.FcntlInt(uintptr(resultFD), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE)
	return err
}

func btoi(v bool) int {
	if v {
		return 1
	}
	return 0
}

func verifySandboxStandardFDs() error {
	for _, fd := range []int{0, 1, 2} {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT == unix.S_IFDIR {
			return ErrDenied
		}
	}
	return nil
}

func verifySandboxDescriptors(bootstrap bootstrapV1) error {
	for _, expected := range []struct {
		fd       int
		dev, ino uint64
		mode     uint32
		size     int64
	}{
		{sandboxInstallFD, bootstrap.RootDev, bootstrap.RootIno, unix.S_IFDIR, 0},
		{sandboxEntryFD, bootstrap.EntryDev, bootstrap.EntryIno, unix.S_IFREG, bootstrap.EntrySize},
	} {
		var st unix.Stat_t
		if err := unix.Fstat(expected.fd, &st); err != nil ||
			uint64(st.Dev) != expected.dev ||
			st.Ino != expected.ino ||
			st.Mode&unix.S_IFMT != expected.mode ||
			(expected.mode == unix.S_IFREG && st.Size != expected.size) {
			return ErrDenied
		}
	}
	var entryStat unix.Stat_t
	if err := unix.Fstat(sandboxEntryFD, &entryStat); err != nil ||
		entryStat.Mode != bootstrap.EntryMode ||
		entryStat.Mode&0o111 == 0 ||
		entryStat.Mode&0o222 != 0 {
		return ErrDenied
	}
	sum, err := digestDescriptor(sandboxEntryFD, bootstrap.EntrySize)
	if err != nil || sum != bootstrap.EntrySHA256 {
		return ErrDenied
	}
	var workspace unix.Stat_t
	if err := unix.Fstat(sandboxWorkspaceFD, &workspace); err != nil ||
		workspace.Mode&unix.S_IFMT != unix.S_IFDIR ||
		workspace.Mode&0o077 != 0 ||
		workspace.Uid != 0 {
		return ErrDenied
	}
	nextFD := sandboxStdinFD
	if bootstrap.HasStdin {
		if err := VerifySealedFD(nextFD, bootstrap.Request.Stdin.Size, bootstrap.Request.Stdin.SHA256); err != nil {
			return ErrDenied
		}
		nextFD++
	}
	for i, secret := range bootstrap.Request.Secrets {
		if err := VerifySealedFD(nextFD+i, secret.Size, secret.SHA256); err != nil {
			return ErrDenied
		}
	}
	if bootstrap.CoreTmpfsBytes > 0 {
		var rootStat unix.Stat_t
		if err := unix.Fstat(sandboxManagerFD, &rootStat); err != nil || rootStat.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(rootStat.Dev) != bootstrap.ManagerRootDev || rootStat.Ino != bootstrap.ManagerRootIno {
			return ErrDenied
		}
		fd, err := unix.Openat(sandboxManagerFD, bootstrap.ManagerBase, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return ErrDenied
		}
		defer unix.Close(fd)
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || uint64(st.Dev) != bootstrap.ManagerDev || st.Ino != bootstrap.ManagerIno || st.Mode != bootstrap.ManagerMode || st.Size != bootstrap.ManagerSize {
			return ErrDenied
		}
		digest, err := digestDescriptor(fd, st.Size)
		if err != nil || digest != bootstrap.ManagerSHA256 {
			return ErrDenied
		}
	}
	return nil
}

func verifyMappedSandboxDirs(installFD, workspaceFD int) error {
	for _, pair := range []struct{ inherited, mapped int }{{sandboxInstallFD, installFD}, {sandboxWorkspaceFD, workspaceFD}} {
		var inheritedStat, mappedStat unix.Stat_t
		if unix.Fstat(pair.inherited, &inheritedStat) != nil || unix.Fstat(pair.mapped, &mappedStat) != nil ||
			mappedStat.Mode != inheritedStat.Mode || mappedStat.Mode&unix.S_IFMT != unix.S_IFDIR || inheritedStat.Dev != mappedStat.Dev || inheritedStat.Ino != mappedStat.Ino {
			return ErrDenied
		}
	}
	return nil
}

func digestDescriptor(fd int, size int64) (string, error) {
	if size < 0 {
		return "", ErrDenied
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	var offset int64
	for offset < size {
		want := int64(len(buffer))
		if remaining := size - offset; remaining < want {
			want = remaining
		}
		n, err := unix.Pread(fd, buffer[:want], offset)
		if err != nil || n <= 0 {
			return "", ErrDenied
		}
		_, _ = hash.Write(buffer[:n])
		offset += int64(n)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func applySandboxRlimits(limits LimitsV2) error {
	for _, item := range sandboxRlimitSettings(limits) {
		limit := &unix.Rlimit{Cur: item.value, Max: item.value}
		if err := unix.Setrlimit(item.resource, limit); err != nil {
			return err
		}
	}
	return nil
}

type sandboxRlimitSetting struct {
	resource int
	value    uint64
}

func sandboxRlimitSettings(limits LimitsV2) []sandboxRlimitSetting {
	return []sandboxRlimitSetting{
		{unix.RLIMIT_CPU, uint64(limits.CPUSeconds)},
		{unix.RLIMIT_FSIZE, uint64(limits.FileBytes)},
		{unix.RLIMIT_NOFILE, uint64(limits.OpenFiles)},
		{unix.RLIMIT_CORE, 0},
	}
}

func clearSandboxCapabilities() error {
	for capability := 0; capability < 64; capability++ {
		err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capability), 0, 0, 0)
		if err != nil && err != unix.EINVAL {
			return err
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil && err != unix.EINVAL {
		return err
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	return unix.Capset(&header, &data[0])
}
