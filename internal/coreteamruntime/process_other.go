//go:build !unix

package coreteamruntime

import (
	"os/exec"
	"time"
)

func configureProcessCancellation(command *exec.Cmd) { command.WaitDelay = 2 * time.Second }
