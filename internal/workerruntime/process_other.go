//go:build !unix

package workerruntime

import "os/exec"

func configureProcessCancellation(command *exec.Cmd) {
	command.WaitDelay = processWaitDelay()
}
