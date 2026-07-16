//go:build !linux

package main

func currentRuntimeIdentity() runtimeIdentity {
	return runtimeIdentity{verified: false}
}
