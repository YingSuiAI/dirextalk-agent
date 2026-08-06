//go:build linux

package coreteamruntime

import (
	"os/exec"
	"syscall"

	"github.com/YingSuiAI/dirextalk-agent/internal/pisandbox"
)

func configureSandboxIdentity(command *exec.Cmd, sandboxed bool) {
	if !sandboxed {
		return
	}
	command.SysProcAttr.Credential = &syscall.Credential{
		Uid:    pisandbox.OfficialPiUID,
		Gid:    pisandbox.OfficialPiGID,
		Groups: []uint32{},
	}
}
