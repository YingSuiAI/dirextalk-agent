//go:build linux

package main

import (
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func readControlPrivateKey(path string, uid uint32) ([]byte, error) {
	if !cleanAbsolute(path) {
		return nil, errControl
	}
	rootFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errControl
	}
	defer unix.Close(rootFD)
	fd, err := unix.Openat2(rootFD, strings.TrimPrefix(path, "/"), &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, errControl
	}
	var state unix.Stat_t
	mode := uint32(0)
	if unix.Fstat(fd, &state) == nil {
		mode = state.Mode & 0o777
	}
	if state.Mode&unix.S_IFMT != unix.S_IFREG || state.Uid != uid || state.Nlink != 1 ||
		(mode != 0o400 && mode != 0o600) || state.Size < 1 || state.Size > 1<<20 {
		_ = unix.Close(fd)
		return nil, errControl
	}
	file := os.NewFile(uintptr(fd), "worker-control-private-key")
	content, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || int64(len(content)) != state.Size {
		clear(content)
		return nil, errControl
	}
	return content, nil
}
