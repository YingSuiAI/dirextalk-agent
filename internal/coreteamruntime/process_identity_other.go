//go:build !linux

package coreteamruntime

import "os/exec"

func configureSandboxIdentity(_ *exec.Cmd, _ bool) {}
