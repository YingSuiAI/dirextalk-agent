//go:build linux

package main

import (
	"errors"
	"os"
	"runtime"

	"github.com/YingSuiAI/dirextalk-agent/internal/pisandbox"
	"golang.org/x/sys/unix"
)

var (
	errLaunchControl     = errors.New("Pi sandbox control-process protection failed")
	errLaunchIdentity    = errors.New("Pi sandbox identity verification failed")
	errLaunchPolicy      = errors.New("Pi sandbox policy application failed")
	errLaunchDescriptors = errors.New("Pi sandbox descriptor closure failed")
	errLaunchExec        = errors.New("Pi sandbox exec failed")
)

func launch(policy pisandbox.Policy, target string, arguments []string) error {
	runtime.LockOSThread()
	if unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) != nil {
		return errLaunchControl
	}
	if verifyPiIdentity() != nil {
		return errLaunchIdentity
	}
	if err := pisandbox.Apply(policy); err != nil {
		return errLaunchPolicy
	}
	if err := unix.CloseRange(3, ^uint(0), 0); err != nil {
		return errLaunchDescriptors
	}
	argv := append([]string{target}, arguments...)
	if unix.Exec(target, argv, os.Environ()) != nil {
		return errLaunchExec
	}
	return nil
}

func verifyPiIdentity() error {
	ruid, euid, suid := unix.Getresuid()
	rgid, egid, sgid := unix.Getresgid()
	groups, err := unix.Getgroups()
	if ruid != pisandbox.OfficialPiUID || euid != pisandbox.OfficialPiUID || suid != pisandbox.OfficialPiUID ||
		rgid != pisandbox.OfficialPiGID || egid != pisandbox.OfficialPiGID || sgid != pisandbox.OfficialPiGID ||
		err != nil || len(groups) != 0 {
		return errLaunch
	}
	if unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != nil {
		return errLaunch
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if unix.Capset(&header, &data[0]) != nil || unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) != nil {
		return errLaunch
	}
	unix.Umask(0o007)
	return nil
}
