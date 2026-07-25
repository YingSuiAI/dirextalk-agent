//go:build linux

package runner

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// Listen creates only a Unix SOCK_SEQPACKET endpoint in a pre-existing,
// protected directory. It never unlinks a path it did not create.
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
	if _, e = os.Lstat(path); e == nil || !os.IsNotExist(e) {
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
