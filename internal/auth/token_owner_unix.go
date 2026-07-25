//go:build !windows

package auth

import (
	"errors"
	"os"
	"syscall"
)

func validateServiceTokenFileInfo(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return errors.New("service token file must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("service token file must not be group/world accessible")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(stat.Uid) != uint32(os.Geteuid()) {
		return errors.New("service token file must be owned by the agent user")
	}
	return nil
}
