//go:build !unix

package runtime

import "os/exec"

func configureProcessCancellation(command *exec.Cmd, uid, gid uint32) error {
	if command == nil || uid != 0 || gid != 0 {
		return ErrInvalid
	}
	command.WaitDelay = processWaitDelay()
	return nil
}

func validateProcessIdentity(uid, gid uint32) error {
	if uid != 0 || gid != 0 {
		return ErrInvalid
	}
	return nil
}

func startIsolatedProcess(command *exec.Cmd, _ bool) error {
	if command == nil {
		return ErrInvalid
	}
	return command.Start()
}
