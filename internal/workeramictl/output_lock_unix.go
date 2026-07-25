//go:build !windows

package workeramictl

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func openBuildOutputLock(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	stat, ok := info.Sys().(*syscall.Stat_t)
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		int(stat.Uid) != os.Geteuid() || !os.SameFile(info, pathInfo) {
		_ = file.Close()
		return nil, errOutput
	}
	return file, nil
}

func tryLockBuildOutput(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

func unlockBuildOutput(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
