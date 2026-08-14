//go:build unix

package runtime

import (
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

var processStartLock sync.Mutex

func configureProcessCancellation(command *exec.Cmd, uid, gid uint32) error {
	if command == nil || (uid == 0) != (gid == 0) {
		return ErrInvalid
	}
	attributes := &syscall.SysProcAttr{
		Setpgid: true, Pdeathsig: syscall.SIGKILL, AmbientCaps: []uintptr{},
	}
	if uid != 0 {
		attributes.Credential = &syscall.Credential{
			Uid: uid, Gid: gid, Groups: []uint32{}, NoSetGroups: false,
		}
	}
	command.SysProcAttr = attributes
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	return nil
}

func validateProcessIdentity(uid, gid uint32) error {
	if (uid == 0) != (gid == 0) {
		return ErrInvalid
	}
	if uid != 0 && uid == uint32(os.Geteuid()) {
		return ErrInvalid
	}
	return nil
}

func startIsolatedProcess(command *exec.Cmd, dropIdentity bool) error {
	if command == nil {
		return ErrInvalid
	}
	processStartLock.Lock()
	defer processStartLock.Unlock()
	if !dropIdentity {
		return command.Start()
	}
	// The service receives only CAP_SETUID/CAP_SETGID. Clear its ambient set
	// before fork so Pi cannot retain either capability after the credential
	// transition. The parent's effective capabilities remain available for
	// this one setuid/setgid operation.
	if err := unix.Prctl(
		unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0,
	); err != nil {
		return ErrExecution
	}
	previousMask := syscall.Umask(0o007)
	err := command.Start()
	syscall.Umask(previousMask)
	return err
}
