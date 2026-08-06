//go:build !linux

package coreteamruntime

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	piDirectoryMode  = os.FileMode(0o700)
	piConfigFileMode = os.FileMode(0o600)
)

func preparePiDirectory(path string) error { return os.Chmod(path, piDirectoryMode) }

func preparePiFile(path string) error { return os.Chmod(path, piConfigFileMode) }

func preparePiWorkspace(path string) error {
	return filepath.WalkDir(path, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		state, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if state.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if entry.IsDir() {
			return os.Chmod(current, piDirectoryMode)
		}
		if !state.Mode().IsRegular() {
			return ErrInvalid
		}
		return os.Chmod(current, piConfigFileMode)
	})
}

func recoverPiWorkspace(path string) error { return preparePiWorkspace(path) }

func cleanupPiJobRoot(stateRoot, jobRoot string) error {
	relative, err := filepath.Rel(stateRoot, jobRoot)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return ErrInvalid
	}
	if err := os.RemoveAll(jobRoot); err != nil {
		return ErrUnavailable
	}
	return nil
}
