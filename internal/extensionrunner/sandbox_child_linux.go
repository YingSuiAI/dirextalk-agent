//go:build linux

package extensionrunner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"runtime"

	"golang.org/x/sys/unix"
)

const (
	sandboxBootstrapFD = 3
	sandboxReleaseFD   = 4
	sandboxInstallFD   = 5
	sandboxEntryFD     = 6
	sandboxWorkspaceFD = 7
	sandboxStdinFD     = 8
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
	if err := unix.Fchdir(sandboxWorkspaceFD); err != nil {
		return sandboxChildFailure("map-root", err)
	}
	if err := unix.Chroot("."); err != nil {
		return sandboxChildFailure("map-root", err)
	}
	if err := unix.Fchdir(sandboxInstallFD); err != nil {
		return sandboxChildFailure("map-pwd", err)
	}
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return sandboxChildFailure("map-namespace", err)
	}
	mappedWorkspaceFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return sandboxChildFailure("map-verify", err)
	}
	defer unix.Close(mappedWorkspaceFD)
	mappedInstallFD, err := unix.Open(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return sandboxChildFailure("map-verify", err)
	}
	defer unix.Close(mappedInstallFD)
	if err := verifyMappedSandboxDirs(mappedInstallFD, mappedWorkspaceFD); err != nil {
		return sandboxChildFailure("map-verify", err)
	}
	rootFD, err := prepareSandboxMounts(bootstrap, mappedInstallFD, mappedWorkspaceFD)
	if err != nil {
		return sandboxChildFailure("mounts", err)
	}
	defer unix.Close(rootFD)
	if err := unix.Fchdir(rootFD); err != nil {
		return sandboxChildFailure("root-switch", err)
	}
	if err := unix.Chroot("."); err != nil {
		return sandboxChildFailure("root-switch", err)
	}
	if err := unix.Chdir("/work"); err != nil {
		return sandboxChildFailure("root-switch", err)
	}
	for _, fd := range []int{sandboxBootstrapFD, sandboxReleaseFD, sandboxInstallFD, sandboxEntryFD, sandboxWorkspaceFD, mappedInstallFD, mappedWorkspaceFD, rootFD} {
		_ = unix.Close(fd)
	}
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
	argv0 := "/app/entry"
	args := bootstrap.Request.Argv
	if len(args) > 0 {
		argv0, args = args[0], args[1:]
	}
	argv := make([]string, 1, 1+len(args))
	argv[0] = argv0
	argv = append(argv, args...)
	if err := unix.Exec("/app/entry", argv, []string{}); err != nil {
		return sandboxChildFailure("exec", err)
	}
	return nil
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
