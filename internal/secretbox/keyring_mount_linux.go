//go:build linux

package secretbox

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type mountedIdentity struct {
	dev   uint64
	ino   uint64
	mode  uint32
	uid   uint32
	nlink uint64
}

func mountedIdentityFromStat(stat *unix.Stat_t) mountedIdentity {
	return mountedIdentity{dev: uint64(stat.Dev), ino: uint64(stat.Ino), mode: stat.Mode, uid: stat.Uid, nlink: uint64(stat.Nlink)}
}

func validMountedStat(stat *unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Mode&0o777 == 0o400 && stat.Nlink == 1 && stat.Uid == uint32(os.Getuid())
}

func openMountedKey(path string) (*os.File, mountedIdentity, error) {
	path = filepath.Clean(path)
	var before unix.Stat_t
	if err := unix.Lstat(path, &before); err != nil || !validMountedStat(&before) {
		return nil, mountedIdentity{}, ErrInvalidKey
	}
	if mountedKeyBeforeOpenHook != nil {
		mountedKeyBeforeOpenHook(path)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, mountedIdentity{}, ErrInvalidKey
	}
	f := os.NewFile(uintptr(fd), path)
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || !validMountedStat(&opened) || mountedIdentityFromStat(&before) != mountedIdentityFromStat(&opened) {
		_ = f.Close()
		return nil, mountedIdentity{}, ErrInvalidKey
	}
	return f, mountedIdentityFromStat(&opened), nil
}

func verifyMountedKey(file *os.File, expected mountedIdentity) error {
	if file == nil {
		return ErrInvalidKey
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &after); err != nil || !validMountedStat(&after) || mountedIdentityFromStat(&after) != expected {
		return ErrInvalidKey
	}
	return nil
}
