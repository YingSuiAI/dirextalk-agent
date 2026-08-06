//go:build linux

package runner

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// Listen creates only a Unix SOCK_SEQPACKET endpoint in a pre-existing,
// protected directory. A same-UID stale socket may be removed only after its
// inode is stable across a refused connection probe. Ordinary files, foreign
// sockets, and active listeners are never removed.
func Listen(path string, owner uint32) (*net.UnixListener, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || owner == 0 {
		return nil, ErrDenied
	}
	d := filepath.Dir(path)
	info, e := os.Lstat(d)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o002 != 0 || (info.Mode().Perm()&0o020 != 0 && info.Mode()&(os.ModeSetgid|os.ModeSticky) != (os.ModeSetgid|os.ModeSticky)) {
		return nil, ErrDenied
	}
	dirStat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(dirStat.Uid) != owner {
		return nil, ErrDenied
	}
	if e = clearStaleSocket(path, owner); e != nil {
		return nil, ErrDenied
	}
	l, e := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if e != nil {
		return nil, e
	}
	if e = os.Chmod(path, 0o660); e != nil {
		_ = l.Close()
		return nil, e
	}
	st, e := os.Lstat(path)
	if e != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm()&0o002 != 0 {
		_ = l.Close()
		return nil, ErrDenied
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || uint32(sys.Uid) != owner {
		_ = l.Close()
		return nil, ErrDenied
	}
	return l, nil
}

type socketIdentity struct {
	dev, ino uint64
	uid      uint32
}

func clearStaleSocket(path string, owner uint32) error {
	var before unix.Stat_t
	err := unix.Lstat(path, &before)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil || before.Mode&unix.S_IFMT != unix.S_IFSOCK || before.Uid != owner {
		return ErrDenied
	}
	want := socketIdentity{dev: uint64(before.Dev), ino: before.Ino, uid: before.Uid}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	err = unix.Connect(fd, &unix.SockaddrUnix{Name: path})
	_ = unix.Close(fd)
	if err == nil {
		return ErrDenied
	}
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if !errors.Is(err, unix.ECONNREFUSED) {
		return ErrDenied
	}
	var after unix.Stat_t
	if err = unix.Lstat(path, &after); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	got := socketIdentity{dev: uint64(after.Dev), ino: after.Ino, uid: after.Uid}
	if after.Mode&unix.S_IFMT != unix.S_IFSOCK || got != want {
		return ErrDenied
	}
	return unix.Unlink(path)
}
