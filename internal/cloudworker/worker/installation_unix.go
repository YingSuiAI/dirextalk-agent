//go:build unix

package worker

import (
	"os"
	"path/filepath"
	"syscall"
)

func verifyOwnedPath(
	path string,
	trustedRoot string,
	expectedOwner uint32,
	executable bool,
) error {
	if !pathWithinTrustedRoot(path, trustedRoot) {
		return ErrInvalid
	}
	current := path
	for {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return ErrInvalid
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != expectedOwner {
			return ErrInvalid
		}
		if current == path {
			if !info.Mode().IsRegular() ||
				(executable && info.Mode().Perm()&0o111 == 0) ||
				(!executable && info.Mode().Perm()&0o111 != 0) {
				return ErrInvalid
			}
		} else if !info.IsDir() {
			return ErrInvalid
		}
		if current == trustedRoot {
			return nil
		}
		parent := filepath.Dir(current)
		if parent == current || !pathWithinOrEqualTrustedRoot(parent, trustedRoot) {
			return ErrInvalid
		}
		current = parent
	}
}

func pathWithinOrEqualTrustedRoot(path, root string) bool {
	if path == root {
		return true
	}
	return pathWithinTrustedRoot(path, root)
}
