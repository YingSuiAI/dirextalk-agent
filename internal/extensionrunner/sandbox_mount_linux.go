//go:build linux

package extensionrunner

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const sandboxMountBaseAttrs = unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOSUID

const (
	sandboxRootTargetRoot = "/tmp"
)

var errSandboxRootCleanup = errors.New("sandbox root target cleanup failed")

type sandboxRootTarget struct {
	parentFD int
	targetFD int
	name     string
	parent   unix.Stat_t
	target   unix.Stat_t
}

func prepareSandboxMounts(bootstrap bootstrapV1, previousRootFD, targetParentFD, targetFD, installMountFD, workspaceMountFD, managerMountFD, runtimeMountFD int) (int, error) {
	rootBytes := bootstrap.Request.Limits.MemoryBytes / 4
	if rootBytes < 1<<20 {
		rootBytes = 1 << 20
	}
	if rootBytes > 64<<20 {
		rootBytes = 64 << 20
	}
	rootFD, err := mountSandboxRoot(rootBytes, previousRootFD, targetParentFD, targetFD, bootstrap)
	if err != nil {
		return -1, err
	}
	if err := createSandboxLayout(rootFD); err != nil {
		unix.Close(rootFD)
		return -1, sandboxChildFailure("layout", err)
	}
	if bootstrap.CoreTmpfsBytes > 0 {
		if managerMountFD < 0 {
			unix.Close(rootFD)
			return -1, sandboxChildFailure("manager-clone", ErrDenied)
		}
		if err := mountDetachedSandboxTree(managerMountFD, rootFD, "run/manager", sandboxMountBaseAttrs|unix.MOUNT_ATTR_RDONLY, "manager-remount", "manager-bind"); err != nil {
			unix.Close(rootFD)
			return -1, err
		}
	}
	if installMountFD < 0 {
		unix.Close(rootFD)
		return -1, sandboxChildFailure("app-clone", ErrDenied)
	}
	if err := mountDetachedSandboxTree(installMountFD, rootFD, "app", sandboxMountBaseAttrs|unix.MOUNT_ATTR_RDONLY, "app-remount", "app-bind"); err != nil {
		unix.Close(rootFD)
		return -1, err
	}
	if bootstrap.Request.Runtime == "node" {
		if runtimeMountFD < 0 {
			unix.Close(rootFD)
			return -1, sandboxChildFailure("runtime-clone", ErrDenied)
		}
		if err := mountDetachedSandboxTree(runtimeMountFD, rootFD, "runtime", sandboxMountBaseAttrs|unix.MOUNT_ATTR_RDONLY, "runtime-remount", "runtime-bind"); err != nil {
			unix.Close(rootFD)
			return -1, err
		}
	}
	if bootstrap.CoreTmpfsBytes > 0 {
		work, e := newSandboxTmpfs(bootstrap.CoreTmpfsBytes, 0o700, sandboxMountBaseAttrs|unix.MOUNT_ATTR_NOEXEC)
		if e != nil {
			unix.Close(rootFD)
			return -1, sandboxChildFailure("work-tmpfs", e)
		}
		workTarget, openErr := openSandboxDirAt(rootFD, "work")
		if openErr == nil {
			e = moveSandboxMount(work, workTarget)
			unix.Close(workTarget)
		}
		if openErr != nil || e != nil {
			unix.Close(work)
			unix.Close(rootFD)
			return -1, sandboxChildFailure("work-tmpfs", e)
		}
		unix.Close(work)
	} else {
		if workspaceMountFD < 0 {
			unix.Close(rootFD)
			return -1, sandboxChildFailure("work-clone", ErrDenied)
		}
		if err := mountDetachedSandboxTree(workspaceMountFD, rootFD, "work", sandboxMountBaseAttrs|unix.MOUNT_ATTR_NOEXEC, "work-remount", "work-bind"); err != nil {
			unix.Close(rootFD)
			return -1, err
		}
	}
	if err := mountSandboxSecrets(rootFD, bootstrap); err != nil {
		unix.Close(rootFD)
		return -1, err
	}
	if bootstrap.CoreTmpfsBytes > 0 {
		// Make only the root tmpfs mount read-only. /work is a distinct tmpfs
		// mount, so it remains the sole writable location.
		if err := unix.MountSetattr(rootFD, "", unix.AT_EMPTY_PATH, &unix.MountAttr{Attr_set: sandboxMountBaseAttrs | unix.MOUNT_ATTR_RDONLY}); err != nil {
			unix.Close(rootFD)
			return -1, sandboxChildFailure("root-remount", err)
		}
	}
	return rootFD, nil
}

func mountSandboxRoot(size int64, previousRootFD, targetParentFD, targetFD int, bootstrap bootstrapV1) (int, error) {
	if size <= 0 || previousRootFD < 0 || targetParentFD < 0 || targetFD < 0 {
		return -1, sandboxChildFailure("root-tmpfs", ErrDenied)
	}
	var previous unix.Stat_t
	if err := unix.Fstat(previousRootFD, &previous); err != nil || previous.Mode&unix.S_IFMT != unix.S_IFDIR {
		return -1, sandboxChildFailure("root-verify", ErrDenied)
	}
	currentRootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, sandboxChildFailure("root-verify", err)
	}
	var current unix.Stat_t
	if err := unix.Fstat(currentRootFD, &current); err != nil {
		unix.Close(currentRootFD)
		return -1, sandboxChildFailure("root-verify", err)
	}
	unix.Close(currentRootFD)
	if !sameSandboxRootIdentity(previous, current) {
		return -1, sandboxChildFailure("root-verify", ErrDenied)
	}
	rootFD, err := newSandboxTmpfs(size, 0o700, sandboxMountBaseAttrs)
	if err != nil {
		return -1, sandboxChildFailure("root-tmpfs", err)
	}
	// Revalidate the strongest sealed identities immediately before the mount
	// mutation. The descriptors already prevent path redirection; this second
	// check also rejects metadata or namespace drift during source cloning.
	if err := verifySandboxRootTargetForMount(targetParentFD, targetFD, bootstrap); err != nil {
		unix.Close(rootFD)
		return -1, sandboxChildFailure("root-target", err)
	}
	if err := moveSandboxMount(rootFD, targetFD); err != nil {
		unix.Close(rootFD)
		return -1, sandboxChildFailure("root-bind", err)
	}
	attachedFD, err := openSandboxRootTargetAt(targetParentFD, bootstrap.RootTargetName)
	if err != nil {
		unix.Close(rootFD)
		return -1, sandboxChildFailure("root-verify", err)
	}
	var root, attached unix.Stat_t
	var filesystem unix.Statfs_t
	if err := unix.Fstat(rootFD, &root); err != nil || unix.Fstat(attachedFD, &attached) != nil {
		unix.Close(attachedFD)
		unix.Close(rootFD)
		return -1, sandboxChildFailure("root-verify", ErrDenied)
	}
	if err := unix.Fstatfs(attachedFD, &filesystem); err != nil {
		unix.Close(attachedFD)
		unix.Close(rootFD)
		return -1, sandboxChildFailure("root-verify", err)
	}
	if !sameSandboxRootIdentity(root, attached) {
		unix.Close(attachedFD)
		unix.Close(rootFD)
		return -1, sandboxChildFailure("root-verify", ErrDenied)
	}
	if err := validateSandboxRootMetadata(previous, attached, filesystem); err != nil {
		unix.Close(attachedFD)
		unix.Close(rootFD)
		return -1, sandboxChildFailure("root-verify", err)
	}
	unix.Close(rootFD)
	return attachedFD, nil
}

func sandboxRootTargetName(runID string) string { return sandboxRootAnchorPrefix + runID }

func openSandboxRootTargetAt(parentFD int, name string) (int, error) {
	runID := strings.TrimPrefix(name, sandboxRootAnchorPrefix)
	if parentFD < 0 || runID == name {
		return -1, ErrDenied
	}
	canonical, err := idPathPart(runID)
	if err != nil || canonical != runID || name != sandboxRootTargetName(runID) {
		return -1, ErrDenied
	}
	return unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
}

func createSandboxRootTarget(runID string) (*sandboxRootTarget, error) {
	if _, err := idPathPart(runID); err != nil {
		return nil, ErrDenied
	}
	name := sandboxRootTargetName(runID)
	parentFD, parent, err := openSandboxRootTargetParent(false)
	if err != nil {
		return nil, err
	}
	if err = unix.Mkdirat(parentFD, name, 0); err != nil {
		unix.Close(parentFD)
		return nil, err
	}
	created := true
	defer func() {
		if created {
			_ = unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
			_ = unix.Close(parentFD)
		}
	}()
	targetFD, err := openSandboxRootTargetAt(parentFD, name)
	if err != nil {
		return nil, err
	}
	var target unix.Stat_t
	statErr := unix.Fstat(targetFD, &target)
	if statErr != nil || !validSandboxRootTarget(parent, target, uint32(os.Geteuid()), uint32(os.Getegid())) {
		unix.Close(targetFD)
		return nil, ErrDenied
	}
	created = false
	return &sandboxRootTarget{parentFD: parentFD, targetFD: targetFD, name: name, parent: parent, target: target}, nil
}

func (t *sandboxRootTarget) cleanup() error {
	if t == nil {
		return nil
	}
	if t.parentFD < 0 && t.targetFD < 0 {
		return nil
	}
	var parent, retained unix.Stat_t
	var filesystem unix.Statfs_t
	if unix.Fstat(t.parentFD, &parent) != nil || unix.Fstatfs(t.parentFD, &filesystem) != nil ||
		!sameSandboxRootIdentity(t.parent, parent) || !validSandboxRootTargetParent(parent, filesystem, false) ||
		unix.Fstat(t.targetFD, &retained) != nil || !sameSandboxRootIdentity(t.target, retained) {
		return errors.Join(errSandboxRootCleanup, ErrDenied)
	}
	fd, err := openSandboxRootTargetAt(t.parentFD, t.name)
	if err == unix.ENOENT {
		if retained.Nlink == 0 {
			return nil
		}
		return errors.Join(errSandboxRootCleanup, ErrDenied)
	}
	if err != nil {
		return errors.Join(errSandboxRootCleanup, err)
	}
	var current unix.Stat_t
	statErr := unix.Fstat(fd, &current)
	unix.Close(fd)
	if statErr != nil || !sameSandboxRootIdentity(t.target, current) {
		return errors.Join(errSandboxRootCleanup, ErrDenied)
	}
	if err := unix.Unlinkat(t.parentFD, t.name, unix.AT_REMOVEDIR); err != nil {
		return errors.Join(errSandboxRootCleanup, err)
	}
	var linked unix.Stat_t
	if err := unix.Fstatat(t.parentFD, t.name, &linked, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
		return errors.Join(errSandboxRootCleanup, ErrDenied)
	}
	if unix.Fstat(t.targetFD, &retained) != nil || retained.Nlink != 0 || !sameSandboxRootIdentity(t.target, retained) {
		return errors.Join(errSandboxRootCleanup, ErrDenied)
	}
	return nil
}

func (t *sandboxRootTarget) close() {
	if t == nil {
		return
	}
	if t.targetFD >= 0 {
		_ = unix.Close(t.targetFD)
		t.targetFD = -1
	}
	if t.parentFD >= 0 {
		_ = unix.Close(t.parentFD)
		t.parentFD = -1
	}
}

func openSandboxRootTargetParent(child bool) (int, unix.Stat_t, error) {
	var empty unix.Stat_t
	fd, err := unix.Open(sandboxRootTargetRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, empty, err
	}
	var stat unix.Stat_t
	var filesystem unix.Statfs_t
	if unix.Fstat(fd, &stat) != nil || unix.Fstatfs(fd, &filesystem) != nil || !validSandboxRootTargetParent(stat, filesystem, child) {
		unix.Close(fd)
		return -1, empty, ErrDenied
	}
	return fd, stat, nil
}

func openSandboxRootTarget(bootstrap bootstrapV1) (int, int, error) {
	parentFD, parent, err := openSandboxRootTargetParent(true)
	if err != nil {
		return -1, -1, err
	}
	if uint64(parent.Dev) != bootstrap.TargetRootDev || parent.Ino != bootstrap.TargetRootIno {
		unix.Close(parentFD)
		return -1, -1, ErrDenied
	}
	targetFD, err := openSandboxRootTargetAt(parentFD, bootstrap.RootTargetName)
	if err != nil {
		unix.Close(parentFD)
		return -1, -1, err
	}
	var target unix.Stat_t
	if unix.Fstat(targetFD, &target) != nil || uint64(target.Dev) != bootstrap.RootTargetDev || target.Ino != bootstrap.RootTargetIno ||
		target.Mode != bootstrap.RootTargetMode || target.Uid != 0 || target.Gid != 0 {
		unix.Close(targetFD)
		unix.Close(parentFD)
		return -1, -1, ErrDenied
	}
	return parentFD, targetFD, nil
}

func validSandboxRootTarget(parent, target unix.Stat_t, uid, gid uint32) bool {
	return target.Mode == unix.S_IFDIR && target.Uid == uid && target.Gid == gid &&
		target.Dev == parent.Dev && target.Ino != parent.Ino
}

func validSandboxRootTargetParent(stat unix.Stat_t, filesystem unix.Statfs_t, child bool) bool {
	const requiredFlags = unix.ST_NODEV | unix.ST_NOSUID | unix.ST_NOEXEC
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != 0o1777 || filesystem.Type != unix.TMPFS_MAGIC || filesystem.Flags&requiredFlags != requiredFlags {
		return false
	}
	return child || stat.Uid == 0 && stat.Gid == 0
}

func verifySandboxRootTargetForMount(parentFD, targetFD int, bootstrap bootstrapV1) error {
	var parent, target unix.Stat_t
	var filesystem unix.Statfs_t
	if unix.Fstat(parentFD, &parent) != nil || unix.Fstatfs(parentFD, &filesystem) != nil ||
		!validSandboxRootTargetParent(parent, filesystem, true) || uint64(parent.Dev) != bootstrap.TargetRootDev || parent.Ino != bootstrap.TargetRootIno ||
		unix.Fstat(targetFD, &target) != nil || uint64(target.Dev) != bootstrap.RootTargetDev || target.Ino != bootstrap.RootTargetIno ||
		target.Mode != bootstrap.RootTargetMode || target.Uid != 0 || target.Gid != 0 {
		return ErrDenied
	}
	return nil
}

func sameSandboxRootIdentity(admitted, current unix.Stat_t) bool {
	return admitted.Dev == current.Dev && admitted.Ino == current.Ino && admitted.Mode == current.Mode &&
		admitted.Uid == current.Uid && admitted.Gid == current.Gid && current.Mode&unix.S_IFMT == unix.S_IFDIR
}

func validateSandboxRootMetadata(previous, root unix.Stat_t, filesystem unix.Statfs_t) error {
	const requiredFlags = unix.ST_NODEV | unix.ST_NOSUID
	if root.Mode&unix.S_IFMT != unix.S_IFDIR || root.Mode&0o777 != 0o700 || root.Uid != 0 || root.Gid != 0 ||
		root.Dev == previous.Dev || filesystem.Type != unix.TMPFS_MAGIC || filesystem.Flags&requiredFlags != requiredFlags {
		return ErrDenied
	}
	return nil
}

func createSandboxLayout(rootFD int) error {
	for _, name := range []string{"app", "work", "run", "dev", "runtime"} {
		if err := unix.Mkdirat(rootFD, name, 0o700); err != nil {
			return err
		}
	}
	devFD, err := openSandboxDirAt(rootFD, "dev")
	if err != nil {
		return err
	}
	nullFD, err := unix.Openat(devFD, "null", unix.O_RDONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err == nil {
		err = unix.Close(nullFD)
	}
	closeErr := unix.Close(devFD)
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	runFD, err := openSandboxDirAt(rootFD, "run")
	if err != nil {
		return err
	}
	defer unix.Close(runFD)
	if err := unix.Mkdirat(runFD, "secrets", 0o700); err != nil {
		return err
	}
	return unix.Mkdirat(runFD, "manager", 0o700)
}

func openSandboxDirAt(parentFD int, name string) (int, error) {
	return unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
}

func newSandboxTmpfs(size int64, mode uint32, attrs uint64) (int, error) {
	fsFD, err := unix.Fsopen("tmpfs", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return -1, err
	}
	defer unix.Close(fsFD)
	if err = unix.FsconfigSetString(fsFD, "mode", strconv.FormatUint(uint64(mode), 8)); err != nil {
		return -1, err
	}
	if err = unix.FsconfigSetString(fsFD, "size", strconv.FormatInt(size, 10)); err != nil {
		return -1, err
	}
	if err = unix.FsconfigCreate(fsFD); err != nil {
		return -1, err
	}
	mountFD, err := unix.Fsmount(fsFD, unix.FSMOUNT_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err = setSandboxMountAttrs(mountFD, attrs); err != nil {
		unix.Close(mountFD)
		return -1, err
	}
	return mountFD, nil
}

func moveSandboxMount(mountFD, targetFD int) error {
	return unix.MoveMount(mountFD, "", targetFD, "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH)
}

func hideSandboxManagerMount(rootFD int) error {
	// The sandbox root is attached only inside this private mount namespace.
	// Cover the trusted manager with an empty immutable mount before
	// capabilities are cleared instead of relying on pathname unmount behavior.
	coverFD, err := newSandboxTmpfs(1<<20, 0o700, sandboxMountBaseAttrs|unix.MOUNT_ATTR_RDONLY|unix.MOUNT_ATTR_NOEXEC)
	if err != nil {
		return sandboxChildFailure("manager-hide", err)
	}
	defer unix.Close(coverFD)
	targetFD, err := unix.Openat2(rootFD, "run/manager", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return sandboxChildFailure("manager-hide", err)
	}
	defer unix.Close(targetFD)
	if err := moveSandboxMount(coverFD, targetFD); err != nil {
		return sandboxChildFailure("manager-hide", err)
	}
	return nil
}

func cloneSandboxTree(sourceFD int) (int, error) {
	// The source descriptors were opened by the parent before this process
	// unshared its mount namespace. An open_tree call made directly against
	// one of those descriptors is rejected because the referenced mount still
	// belongs to the old namespace. Reopen the same absolute directory through
	// the current namespace, then prove that it is still the admitted inode
	// before creating the detached bind mount.
	sourcePathFD, err := reopenSandboxTreeSource(sourceFD)
	if err != nil {
		return -1, err
	}
	defer unix.Close(sourcePathFD)
	return unix.OpenTree(sourcePathFD, ".", uint(unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC))
}

func reopenSandboxTreeSource(sourceFD int) (int, error) {
	path, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(sourceFD))
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return -1, ErrDenied
	}
	reopened, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return -1, err
	}
	var inheritedStat, reopenedStat unix.Stat_t
	if unix.Fstat(sourceFD, &inheritedStat) != nil || unix.Fstat(reopened, &reopenedStat) != nil ||
		inheritedStat.Dev != reopenedStat.Dev || inheritedStat.Ino != reopenedStat.Ino ||
		inheritedStat.Mode != reopenedStat.Mode || reopenedStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		unix.Close(reopened)
		return -1, ErrDenied
	}
	return reopened, nil
}

func mountDetachedSandboxTree(treeFD, rootFD int, target string, attrs uint64, attrStage, moveStage string) error {
	targetFD, err := openSandboxDirAt(rootFD, target)
	if err != nil {
		return sandboxChildFailure(moveStage, err)
	}
	defer unix.Close(targetFD)
	if err = unix.MountSetattr(treeFD, "", uint(unix.AT_EMPTY_PATH|unix.AT_RECURSIVE), &unix.MountAttr{Attr_set: attrs}); err != nil {
		return sandboxChildFailure(attrStage, err)
	}
	if err = unix.MoveMount(treeFD, "", targetFD, "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH); err != nil {
		return sandboxChildFailure(moveStage, err)
	}
	return nil
}

func setSandboxMountAttrs(mountFD int, attrs uint64) error {
	return unix.MountSetattr(mountFD, "", uint(unix.AT_EMPTY_PATH|unix.AT_RECURSIVE), &unix.MountAttr{Attr_set: attrs})
}

func mountSandboxSecrets(rootFD int, bootstrap bootstrapV1) error {
	runFD, err := openSandboxDirAt(rootFD, "run")
	if err != nil {
		return sandboxChildFailure("secrets-tmpfs", err)
	}
	defer unix.Close(runFD)
	var total int64 = 4096
	for _, secret := range bootstrap.Request.Secrets {
		total += secret.Size + 4096
	}
	secretsMountFD, err := newSandboxTmpfs(total, 0o700, sandboxMountBaseAttrs|unix.MOUNT_ATTR_NOEXEC)
	if err != nil {
		return sandboxChildFailure("secrets-tmpfs", err)
	}
	defer unix.Close(secretsMountFD)
	if err = verifySandboxDirectoryFD(secretsMountFD); err != nil {
		return sandboxChildFailure("secrets-copy", err)
	}
	fd := sandboxInputStartFD(bootstrap)
	if bootstrap.HasStdin {
		fd++
	}
	for i, secret := range bootstrap.Request.Secrets {
		if err = copySandboxSecret(fd+i, secretsMountFD, secret.Name, secret.Size); err != nil {
			return sandboxChildFailure("secrets-copy", err)
		}
	}
	if err = setSandboxMountAttrs(secretsMountFD, sandboxMountBaseAttrs|unix.MOUNT_ATTR_NOEXEC|unix.MOUNT_ATTR_RDONLY); err != nil {
		return sandboxChildFailure("secrets-remount", err)
	}
	targetFD, err := openSandboxDirAt(runFD, "secrets")
	if err != nil {
		return sandboxChildFailure("secrets-tmpfs", err)
	}
	err = moveSandboxMount(secretsMountFD, targetFD)
	unix.Close(targetFD)
	if err != nil {
		return sandboxChildFailure("secrets-tmpfs", err)
	}
	return nil
}

func verifySandboxDirectoryFD(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0o077 != 0 || st.Uid != 0 {
		return ErrDenied
	}
	return nil
}

func copySandboxSecret(sourceFD, targetDirFD int, name string, size int64) error {
	targetFD, err := unix.Openat(targetDirFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o400)
	if err != nil {
		return err
	}
	defer unix.Close(targetFD)
	buffer := make([]byte, 64<<10)
	var offset int64
	for offset < size {
		want := int64(len(buffer))
		if remaining := size - offset; remaining < want {
			want = remaining
		}
		n, err := unix.Pread(sourceFD, buffer[:want], offset)
		if err != nil || n <= 0 {
			return ErrDenied
		}
		written := 0
		for written < n {
			count, writeErr := unix.Write(targetFD, buffer[written:n])
			if writeErr != nil || count <= 0 {
				return ErrDenied
			}
			written += count
		}
		offset += int64(n)
	}
	return unix.Fsync(targetFD)
}
