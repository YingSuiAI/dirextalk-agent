//go:build !windows

package releaseecr

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func openExistingSessionLock(name string) (*os.File, error) {
	fd, err := unix.Open(name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || int(stat.Uid) != os.Geteuid() {
		_ = file.Close()
		return nil, ErrSession
	}
	return file, nil
}

func tryLockSessionFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

func unlockSessionFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
