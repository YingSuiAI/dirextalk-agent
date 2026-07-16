//go:build !linux

package installer

import "os/exec"

func configureCommandCancellation(*exec.Cmd) {}
