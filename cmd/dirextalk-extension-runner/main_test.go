//go:build linux

package main

import (
	"os"
	"testing"
)

func TestValidateWorkspaceDirRequiresExactSharedOwnershipAndMode(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := validateWorkspaceDir(root, uint32(os.Getegid())); err != nil {
		t.Fatalf("valid shared workspace rejected: %v", err)
	}
	for _, mode := range []os.FileMode{0o700, 0o750, 0o777} {
		if err := os.Chmod(root, mode); err != nil {
			t.Fatal(err)
		}
		if err := validateWorkspaceDir(root, uint32(os.Getegid())); err == nil {
			t.Fatalf("workspace mode %#o accepted", mode)
		}
	}
	if err := os.Chmod(root, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := validateWorkspaceDir(root, uint32(os.Getegid())+1); err == nil {
		t.Fatal("workspace with wrong shared group accepted")
	}
}
