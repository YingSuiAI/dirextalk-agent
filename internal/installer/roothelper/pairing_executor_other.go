//go:build !linux

package roothelper

import "os/exec"

func configurePairingCommandCancellation(*exec.Cmd) {}
