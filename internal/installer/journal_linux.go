//go:build linux

package installer

import (
	"os"
	"path/filepath"
	"syscall"
)

func validateRootOwnedJournalParent(name string) error {
	if err := verifyRootOwnedPath(filepath.ToSlash(name), false); err != nil {
		return err
	}
	info, err := os.Lstat(name)
	if err != nil || !info.IsDir() || !rootOwnedAndImmutable(info) {
		return errorf(CodeJournalUnavailable, "journal parent metadata is invalid")
	}
	return nil
}

func validateRootOwnedJournalFile(name string) error {
	if err := verifyRootOwnedPath(filepath.ToSlash(name), true); err != nil {
		return err
	}
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errorf(CodeJournalUnavailable, "journal file metadata is invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errorf(CodeJournalUnavailable, "journal file owner is invalid")
	}
	return nil
}
