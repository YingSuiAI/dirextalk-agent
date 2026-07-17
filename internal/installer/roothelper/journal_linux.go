//go:build linux

package roothelper

import (
	"os"
	"syscall"
)

func validateRootOwnedRestartJournalParent(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || !rootOwnedDirectory(info) {
		return ErrUnavailable
	}
	return nil
}

func validateRootOwnedRestartJournalFile(path string) error {
	info, err := os.Lstat(path)
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		stat.Uid != 0 || stat.Gid != 0 {
		return ErrUnavailable
	}
	return nil
}

func infoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}
