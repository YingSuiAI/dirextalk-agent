//go:build linux

package coreteamruntime

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/YingSuiAI/dirextalk-agent/internal/pisandbox"
	"golang.org/x/sys/unix"
)

const (
	piDirectoryMode           = os.FileMode(0o770)
	piConfigFileMode          = os.FileMode(0o640)
	piWorkspaceFileMode       = os.FileMode(0o660)
	piWorkspaceExecutableMode = os.FileMode(0o770)
)

func preparePiDirectory(path string) error {
	if err := os.Chown(path, -1, pisandbox.OfficialPiGID); err != nil {
		return err
	}
	return os.Chmod(path, piDirectoryMode)
}

func preparePiFile(path string) error {
	if err := os.Chown(path, -1, pisandbox.OfficialPiGID); err != nil {
		return err
	}
	return os.Chmod(path, piConfigFileMode)
}

func preparePiWorkspace(path string) error {
	workerUID := uint32(os.Geteuid())
	return filepath.WalkDir(path, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		state, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := state.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != workerUID && stat.Uid != pisandbox.OfficialPiUID) {
			return ErrInvalid
		}
		if state.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if stat.Uid == pisandbox.OfficialPiUID {
			if stat.Gid != pisandbox.OfficialPiGID {
				return ErrInvalid
			}
			if entry.IsDir() && state.Mode().Perm() != piDirectoryMode {
				return ErrInvalid
			}
			if state.Mode().IsRegular() {
				mode := piWorkspaceFileMode
				if state.Mode().Perm()&0o111 != 0 {
					mode = piWorkspaceExecutableMode
				}
				if stat.Nlink != 1 || state.Mode().Perm() != mode {
					return ErrInvalid
				}
			}
			return nil
		}
		if entry.IsDir() {
			return preparePiDirectory(current)
		}
		if !state.Mode().IsRegular() || stat.Nlink != 1 {
			return ErrInvalid
		}
		mode := piWorkspaceFileMode
		if state.Mode().Perm()&0o111 != 0 {
			mode = piWorkspaceExecutableMode
		}
		if err := os.Chown(current, -1, pisandbox.OfficialPiGID); err != nil {
			return err
		}
		return os.Chmod(current, mode)
	})
}

func recoverPiWorkspace(path string) error {
	workerUID := uint32(os.Geteuid())
	return withPiFilesystemIdentity(func() error {
		return filepath.WalkDir(path, func(current string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			state, err := os.Lstat(current)
			if err != nil {
				return err
			}
			stat, ok := state.Sys().(*syscall.Stat_t)
			if !ok || (stat.Uid != workerUID && stat.Uid != pisandbox.OfficialPiUID) {
				return ErrInvalid
			}
			if state.Mode()&os.ModeSymlink != 0 {
				if stat.Uid == pisandbox.OfficialPiUID && os.Lchown(current, -1, pisandbox.OfficialPiGID) != nil {
					return ErrUnavailable
				}
				return nil
			}
			if entry.IsDir() {
				if stat.Uid == pisandbox.OfficialPiUID {
					if os.Chown(current, -1, pisandbox.OfficialPiGID) != nil || os.Chmod(current, piDirectoryMode) != nil {
						return ErrUnavailable
					}
				} else if stat.Gid != pisandbox.OfficialPiGID || state.Mode().Perm() != piDirectoryMode {
					return ErrInvalid
				}
				return nil
			}
			if !state.Mode().IsRegular() || stat.Nlink != 1 {
				return ErrInvalid
			}
			mode := piWorkspaceFileMode
			if state.Mode().Perm()&0o111 != 0 {
				mode = piWorkspaceExecutableMode
			}
			if stat.Uid == pisandbox.OfficialPiUID {
				if os.Chown(current, -1, pisandbox.OfficialPiGID) != nil || os.Chmod(current, mode) != nil {
					return ErrUnavailable
				}
			} else if stat.Gid != pisandbox.OfficialPiGID || state.Mode().Perm() != mode {
				return ErrInvalid
			}
			return nil
		})
	})
}

func cleanupPiJobRoot(stateRoot, jobRoot string) error {
	relative, err := filepath.Rel(stateRoot, jobRoot)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return ErrInvalid
	}
	if err := os.RemoveAll(jobRoot); err == nil {
		if _, statErr := os.Lstat(jobRoot); errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
	}
	return withPiFilesystemIdentity(func() error {
		if err := os.RemoveAll(jobRoot); err != nil {
			return ErrUnavailable
		}
		if _, err := os.Lstat(jobRoot); !errors.Is(err, os.ErrNotExist) {
			return ErrUnavailable
		}
		return nil
	})
}

func withPiFilesystemIdentity(operation func() error) (result error) {
	if operation == nil {
		return ErrInvalid
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	previousGID, err := unix.SetfsgidRetGid(int(pisandbox.OfficialPiGID))
	if err != nil {
		return ErrUnavailable
	}
	defer func() {
		if _, err := unix.SetfsgidRetGid(previousGID); err != nil && result == nil {
			result = ErrUnavailable
		}
	}()
	previousUID, err := unix.SetfsuidRetUid(int(pisandbox.OfficialPiUID))
	if err != nil {
		return ErrUnavailable
	}
	defer func() {
		if _, err := unix.SetfsuidRetUid(previousUID); err != nil && result == nil {
			result = ErrUnavailable
		}
	}()
	return operation()
}
