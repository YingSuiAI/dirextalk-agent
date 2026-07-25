//go:build linux

package extensionrunner

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const maxWorkspaceSnapshotEntries = 8192

type workspaceIdentity struct {
	Device uint64
	Inode  uint64
	Mode   uint32
}

type workspaceSnapshot map[string]workspaceIdentity

func SnapshotWorkspaceFD(rootFD int) (workspaceSnapshot, error) {
	if rootFD < 0 {
		return nil, ErrInvalid
	}
	snapshot := workspaceSnapshot{}
	fd, err := unix.Openat(rootFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	if err := walkWorkspace(fd, "", func(path string, stat unix.Stat_t) error {
		if len(snapshot) >= maxWorkspaceSnapshotEntries {
			return ErrInvalid
		}
		snapshot[path] = workspaceIdentity{Device: uint64(stat.Dev), Inode: stat.Ino, Mode: stat.Mode}
		return nil
	}); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func CleanupWorkspaceFD(rootFD int, baseline workspaceSnapshot, keep []string) error {
	if rootFD < 0 || baseline == nil {
		return ErrInvalid
	}
	protected := make(map[string]bool, len(baseline)+len(keep))
	keepAncestors := make(map[string]bool, len(keep))
	protectParents := func(path string) {
		for {
			protected[path] = true
			index := strings.LastIndexByte(path, '/')
			if index < 0 {
				return
			}
			path = path[:index]
		}
	}
	for path := range baseline {
		protectParents(path)
	}
	for _, path := range keep {
		if !safeRelativeSlash(path) {
			return ErrInvalid
		}
		protectParents(path)
		for index := strings.LastIndexByte(path, '/'); index >= 0; index = strings.LastIndexByte(path, '/') {
			path = path[:index]
			keepAncestors[path] = true
		}
	}
	keepExact := make(map[string]bool, len(keep))
	for _, path := range keep {
		keepExact[path] = true
	}
	fd, err := unix.Openat(rootFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrInvalid
	}
	return cleanupWorkspaceDirectory(fd, "", baseline, protected, keepAncestors, keepExact)
}

func walkWorkspace(dirFD int, prefix string, visit func(string, unix.Stat_t) error) error {
	file := os.NewFile(uintptr(dirFD), prefix)
	defer file.Close()
	entries, err := file.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := entry.Name()
		if prefix != "" {
			path = prefix + "/" + path
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(dirFD, entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if err := visit(path, stat); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			child, err := unix.Openat(dirFD, entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			if err := walkWorkspace(child, path, visit); err != nil {
				return err
			}
		}
	}
	return nil
}

func cleanupWorkspaceDirectory(dirFD int, prefix string, baseline workspaceSnapshot, protected, keepAncestors, keepExact map[string]bool) error {
	file := os.NewFile(uintptr(dirFD), prefix)
	defer file.Close()
	entries, err := file.ReadDir(-1)
	if err != nil {
		return err
	}
	var result error
	for _, entry := range entries {
		name := entry.Name()
		path := name
		if prefix != "" {
			path = prefix + "/" + name
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(dirFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			result = errors.Join(result, err)
			continue
		}
		identity, existed := baseline[path]
		same := existed &&
			identity.Device == uint64(stat.Dev) &&
			identity.Inode == stat.Ino &&
			identity.Mode&unix.S_IFMT == stat.Mode&unix.S_IFMT
			// A registered result is retained even when it replaced a baseline
			// object. Other replacements are task output and must be removed,
			// including below an unchanged baseline parent.
		if existed && !same && !keepExact[path] && !keepAncestors[path] {
			result = errors.Join(result, removeWorkspaceTreeAt(dirFD, name))
			continue
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			if !protected[path] && !same {
				result = errors.Join(result, removeWorkspaceTreeAt(dirFD, name))
				continue
			}
			child, openErr := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if openErr != nil {
				result = errors.Join(result, openErr)
				continue
			}
			result = errors.Join(result, cleanupWorkspaceDirectory(child, path, baseline, protected, keepAncestors, keepExact))
			if !same && !protected[path] {
				result = errors.Join(result, unix.Unlinkat(dirFD, name, unix.AT_REMOVEDIR))
			}
			continue
		}
		if same || keepExact[path] {
			continue
		}
		result = errors.Join(result, unix.Unlinkat(dirFD, name, 0))
	}
	return result
}

func removeWorkspaceTreeAt(parentFD int, name string) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if err == unix.ENOENT {
			return nil
		}
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return unix.Unlinkat(parentFD, name, 0)
	}
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	entries, readErr := file.ReadDir(-1)
	if readErr != nil {
		_ = file.Close()
		return readErr
	}
	var result error
	for _, entry := range entries {
		result = errors.Join(result, removeWorkspaceTreeAt(fd, entry.Name()))
	}
	result = errors.Join(result, file.Close())
	if result != nil {
		return result
	}
	return unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
}
