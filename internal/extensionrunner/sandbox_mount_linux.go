//go:build linux

package extensionrunner

import (
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

const sandboxMountBaseAttrs = unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOSUID

func prepareSandboxMounts(bootstrap bootstrapV1, installMountFD, workspaceMountFD, managerMountFD int) (int, error) {
	rootBytes := bootstrap.Request.Limits.MemoryBytes / 4
	if rootBytes < 1<<20 {
		rootBytes = 1 << 20
	}
	if rootBytes > 64<<20 {
		rootBytes = 64 << 20
	}
	rootFD, err := newSandboxTmpfs(rootBytes, 0o700, sandboxMountBaseAttrs)
	if err != nil {
		return -1, sandboxChildFailure("root-tmpfs", err)
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

func createSandboxLayout(rootFD int) error {
	for _, name := range []string{"app", "work", "run", "dev"} {
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

func hideSandboxManagerMount() error {
	// The sandbox root remains a detached mount tree, so umount2 by pathname
	// returns EINVAL even though the manager is a mount within that tree. Cover
	// it with an empty immutable mount before capabilities are cleared instead.
	coverFD, err := newSandboxTmpfs(1<<20, 0o700, sandboxMountBaseAttrs|unix.MOUNT_ATTR_RDONLY|unix.MOUNT_ATTR_NOEXEC)
	if err != nil {
		return sandboxChildFailure("manager-hide", err)
	}
	defer unix.Close(coverFD)
	targetFD, err := unix.Open("/run/manager", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
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
	fd := sandboxStdinFD
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
