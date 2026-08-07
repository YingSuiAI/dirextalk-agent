//go:build linux

package runtime

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const workspaceResolveFlags = unix.RESOLVE_BENEATH |
	unix.RESOLVE_NO_SYMLINKS |
	unix.RESOLVE_NO_MAGICLINKS |
	unix.RESOLVE_NO_XDEV

func openWorkspaceRoot(path string) (*os.File, os.FileInfo, error) {
	if !cleanAbsolute(path) {
		return nil, nil, ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, nil, ErrInvalid
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, nil, ErrInvalid
	}
	root := os.NewFile(uintptr(fd), path)
	if root == nil {
		_ = unix.Close(fd)
		return nil, nil, ErrInvalid
	}
	opened, statErr := root.Stat()
	after, lstatErr := os.Lstat(path)
	if statErr != nil || lstatErr != nil || !opened.IsDir() ||
		!os.SameFile(before, opened) || !os.SameFile(before, after) ||
		before.Mode() != opened.Mode() || before.Mode() != after.Mode() {
		_ = root.Close()
		return nil, nil, ErrInvalid
	}
	return root, opened, nil
}

func openWorkspaceEntry(
	root *os.File,
	canonicalPath string,
	readContent bool,
) (*os.File, os.FileInfo, error) {
	if root == nil || !validWorkspaceDeltaPath(canonicalPath) {
		return nil, nil, ErrInvalid
	}
	flags := unix.O_PATH | unix.O_CLOEXEC
	if readContent {
		flags = unix.O_RDONLY | unix.O_CLOEXEC
	}
	fd, err := unix.Openat2(int(root.Fd()), canonicalPath, &unix.OpenHow{
		Flags: uint64(flags), Resolve: workspaceResolveFlags,
	})
	if err != nil {
		return nil, nil, ErrInvalid
	}
	file := os.NewFile(uintptr(fd), canonicalPath)
	if file == nil {
		_ = unix.Close(fd)
		return nil, nil, ErrInvalid
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, ErrInvalid
	}
	return file, info, nil
}

func openWorkspaceDirectory(
	root *os.File,
	canonicalPath string,
) (*os.File, os.FileInfo, error) {
	if root == nil || (canonicalPath != "" && !validWorkspaceDeltaPath(canonicalPath)) {
		return nil, nil, ErrInvalid
	}
	path := canonicalPath
	if path == "" {
		path = "."
	}
	fd, err := unix.Openat2(int(root.Fd()), path, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: workspaceResolveFlags,
	})
	if err != nil {
		return nil, nil, ErrInvalid
	}
	directory := os.NewFile(uintptr(fd), canonicalPath)
	if directory == nil {
		_ = unix.Close(fd)
		return nil, nil, ErrInvalid
	}
	info, err := directory.Stat()
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		_ = directory.Close()
		return nil, nil, ErrInvalid
	}
	return directory, info, nil
}

func validWorkspaceRegularFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

func stableWorkspaceSystemInfo(expected, actual os.FileInfo) bool {
	left, leftOK := expected.Sys().(*syscall.Stat_t)
	right, rightOK := actual.Sys().(*syscall.Stat_t)
	return leftOK && rightOK && left.Dev == right.Dev && left.Ino == right.Ino &&
		left.Nlink == right.Nlink && left.Ctim.Sec == right.Ctim.Sec &&
		left.Ctim.Nsec == right.Ctim.Nsec
}
