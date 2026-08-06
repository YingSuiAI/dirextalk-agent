//go:build linux

package main

import "golang.org/x/sys/unix"

func protectControlProcess() error {
	if unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) != nil {
		return errConfig
	}
	return nil
}
