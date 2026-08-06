//go:build linux

package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestProtectControlProcessDisablesDumping(t *testing.T) {
	original, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Prctl(unix.PR_SET_DUMPABLE, uintptr(original), 0, 0, 0)
	if err := protectControlProcess(); err != nil {
		t.Fatal(err)
	}
	got, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil || got != 0 {
		t.Fatalf("dumpable=%d err=%v", got, err)
	}
}
