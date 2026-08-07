//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/worker"
)

func currentEffectiveUID() uint32 { return uint32(os.Geteuid()) }

func validatePrivateDirectory(path string, expectedUID, expectedGID uint32) error {
	if path == "" || path == "/" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return worker.ErrInvalid
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o007 != 0 {
		return worker.ErrInvalid
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID || stat.Gid != expectedGID {
		return worker.ErrInvalid
	}
	return nil
}
