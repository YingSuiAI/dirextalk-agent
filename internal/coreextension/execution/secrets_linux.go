//go:build linux

package execution

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func sealSecret(data []byte) (*os.File, error) {
	if len(data) == 0 || len(data) > 1<<20 {
		return nil, errors.New("invalid secret")
	}
	fd, err := unix.MemfdCreate("dirextalk-secret", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "secret")
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err = unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE); err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err = f.Seek(0, 0); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

var _ = syscall.CloseOnExec
