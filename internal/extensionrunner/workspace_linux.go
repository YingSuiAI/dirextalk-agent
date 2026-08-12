//go:build linux

package extensionrunner

import (
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maxWorkspaceSnapshotEntries = 8192
	workspaceReadBatchSize      = 128
)

var errWorkspaceTraversalLimit = errors.New("extension workspace traversal limit exceeded")

type workspaceIdentity struct {
	Device uint64
	Inode  uint64
	Mode   uint32
}

type workspaceSnapshot map[string]workspaceIdentity

type workspaceTraversalBudget struct {
	entries  int
	bytes    int64
	maxBytes int64
	strict   bool
	exceeded bool
}

func (b *workspaceTraversalBudget) observe(stat unix.Stat_t) error {
	b.entries++
	violated := b.entries > maxWorkspaceSnapshotEntries || stat.Size < 0
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR && !violated {
		violated = b.bytes > b.maxBytes-stat.Size
		if !violated {
			b.bytes += stat.Size
		}
	}
	if violated {
		b.exceeded = true
		if b.strict {
			return errWorkspaceTraversalLimit
		}
	}
	return nil
}

func SnapshotWorkspaceFD(rootFD int, maxBytes int64) (workspaceSnapshot, error) {
	if rootFD < 0 || maxBytes <= 0 {
		return nil, ErrInvalid
	}
	snapshot := workspaceSnapshot{}
	budget := &workspaceTraversalBudget{maxBytes: maxBytes, strict: true}
	fd, err := unix.Openat(rootFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	if err := walkWorkspace(fd, "", func(path string, stat unix.Stat_t) error {
		if err := budget.observe(stat); err != nil {
			return err
		}
		snapshot[path] = workspaceIdentity{Device: uint64(stat.Dev), Inode: stat.Ino, Mode: stat.Mode}
		return nil
	}); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func CleanupWorkspaceFD(rootFD int, baseline workspaceSnapshot, keep []string, maxBytes int64) error {
	if rootFD < 0 || baseline == nil || maxBytes <= 0 {
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
		if !safeRelativeSlash(path) || sandboxReservedResultPath(path) {
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
	budget := &workspaceTraversalBudget{maxBytes: maxBytes}
	err = cleanupWorkspaceDirectory(fd, "", baseline, protected, keepAncestors, keepExact, budget)
	if budget.exceeded {
		err = errors.Join(err, errWorkspaceTraversalLimit)
	}
	return err
}

func walkWorkspace(dirFD int, prefix string, visit func(string, unix.Stat_t) error) error {
	file := os.NewFile(uintptr(dirFD), prefix)
	defer file.Close()
	return readDirectoryBatches(file, func(entry os.DirEntry) error {
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
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			return nil
		}
		child, err := unix.Openat(dirFD, entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		return walkWorkspace(child, path, visit)
	})
}

func cleanupWorkspaceDirectory(dirFD int, prefix string, baseline workspaceSnapshot, protected, keepAncestors, keepExact map[string]bool, budget *workspaceTraversalBudget) error {
	file := os.NewFile(uintptr(dirFD), prefix)
	defer file.Close()
	var result error
	err := readDirectoryBatches(file, func(entry os.DirEntry) error {
		name := entry.Name()
		path := name
		if prefix != "" {
			path = prefix + "/" + name
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(dirFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			result = errors.Join(result, err)
			return nil
		}
		if err := budget.observe(stat); err != nil {
			return err
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
			removeErr := removeWorkspaceTreeAt(dirFD, name, budget, true)
			if errors.Is(removeErr, errWorkspaceTraversalLimit) {
				return removeErr
			}
			result = errors.Join(result, removeErr)
			return nil
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			if !protected[path] && !same {
				removeErr := removeWorkspaceTreeAt(dirFD, name, budget, true)
				if errors.Is(removeErr, errWorkspaceTraversalLimit) {
					return removeErr
				}
				result = errors.Join(result, removeErr)
				return nil
			}
			child, openErr := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if openErr != nil {
				result = errors.Join(result, openErr)
				return nil
			}
			cleanupErr := cleanupWorkspaceDirectory(child, path, baseline, protected, keepAncestors, keepExact, budget)
			if errors.Is(cleanupErr, errWorkspaceTraversalLimit) {
				return cleanupErr
			}
			result = errors.Join(result, cleanupErr)
			if !same && !protected[path] {
				result = errors.Join(result, unix.Unlinkat(dirFD, name, unix.AT_REMOVEDIR))
			}
			return nil
		}
		if same || keepExact[path] {
			return nil
		}
		result = errors.Join(result, unix.Unlinkat(dirFD, name, 0))
		return nil
	})
	if err != nil {
		return errors.Join(result, err)
	}
	return result
}

func removeWorkspaceTreeAt(parentFD int, name string, budget *workspaceTraversalBudget, rootObserved bool) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if err == unix.ENOENT {
			return nil
		}
		return err
	}
	if !rootObserved {
		if err := budget.observe(stat); err != nil {
			return err
		}
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return unix.Unlinkat(parentFD, name, 0)
	}
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	var result error
	readErr := readDirectoryBatches(file, func(entry os.DirEntry) error {
		removeErr := removeWorkspaceTreeAt(fd, entry.Name(), budget, false)
		if errors.Is(removeErr, errWorkspaceTraversalLimit) {
			return removeErr
		}
		result = errors.Join(result, removeErr)
		return nil
	})
	if readErr != nil {
		result = errors.Join(result, readErr)
	}
	result = errors.Join(result, file.Close())
	if result != nil {
		return result
	}
	return unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
}

func readDirectoryBatches(file *os.File, visit func(os.DirEntry) error) error {
	for {
		entries, err := file.ReadDir(workspaceReadBatchSize)
		for _, entry := range entries {
			if visitErr := visit(entry); visitErr != nil {
				return visitErr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
