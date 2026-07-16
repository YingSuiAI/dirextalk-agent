//go:build linux

package main

import "os"

func currentRuntimeIdentity() runtimeIdentity {
	return runtimeIdentity{uid: os.Geteuid(), gid: os.Getegid(), verified: true}
}
