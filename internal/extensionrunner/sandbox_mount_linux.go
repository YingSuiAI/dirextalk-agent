//go:build linux

package extensionrunner

import (
	"strconv"

	"golang.org/x/sys/unix"
)

const sandboxMountBaseAttrs = unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOSUID

func prepareSandboxMounts(bootstrap bootstrapV1, installFD, workspaceFD int) (int, error) {
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
	if err := mountSandboxTree(installFD, rootFD, "app", sandboxMountBaseAttrs|unix.MOUNT_ATTR_RDONLY, "app-clone", "app-remount", "app-bind"); err != nil {
		unix.Close(rootFD)
		return -1, err
	}
	if err := mountSandboxTree(workspaceFD, rootFD, "work", sandboxMountBaseAttrs|unix.MOUNT_ATTR_NOEXEC, "work-clone", "work-remount", "work-bind"); err != nil {
		unix.Close(rootFD)
		return -1, err
	}
	if err := mountSandboxSecrets(rootFD, bootstrap); err != nil {
		unix.Close(rootFD)
		return -1, err
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
	return unix.Mkdirat(runFD, "secrets", 0o700)
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

func mountSandboxTree(sourceFD, rootFD int, target string, attrs uint64, cloneStage, attrStage, moveStage string) error {
	targetFD, err := openSandboxDirAt(rootFD, target)
	if err != nil {
		return sandboxChildFailure(moveStage, err)
	}
	defer unix.Close(targetFD)
	sourcePathFD, err := unix.Openat(sourceFD, ".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return sandboxChildFailure(cloneStage, err)
	}
	defer unix.Close(sourcePathFD)
	treeFD, err := unix.OpenTree(sourcePathFD, "", uint(unix.AT_EMPTY_PATH|unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC))
	if err != nil {
		return sandboxChildFailure(cloneStage, err)
	}
	defer unix.Close(treeFD)
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
