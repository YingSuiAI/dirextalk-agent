//go:build darwin || linux

package main

import (
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const modelCredentialFileName = "model-credential"

func consumeModelCredential(root string, uid uint32) ([]byte, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errInput
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errInput
	}
	defer unix.Close(rootFD)
	var rootState unix.Stat_t
	if unix.Fstat(rootFD, &rootState) != nil || rootState.Mode&unix.S_IFMT != unix.S_IFDIR ||
		rootState.Uid != uid || rootState.Mode&0o777 != 0o700 {
		return nil, errInput
	}
	credentialFD, err := unix.Openat(rootFD, modelCredentialFileName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errInput
	}
	var state unix.Stat_t
	if unix.Fstat(credentialFD, &state) != nil || state.Mode&unix.S_IFMT != unix.S_IFREG || state.Uid != uid ||
		state.Mode&0o777 != 0o600 || state.Nlink != 1 || state.Size < 16 || state.Size > maxCredentialBytes {
		_ = unix.Close(credentialFD)
		return nil, errInput
	}
	if err = unix.Unlinkat(rootFD, modelCredentialFileName, 0); err != nil {
		_ = unix.Close(credentialFD)
		return nil, errInput
	}
	if err = unix.Fsync(rootFD); err != nil {
		_ = unix.Close(credentialFD)
		return nil, errInput
	}
	file := os.NewFile(uintptr(credentialFD), "model-credential")
	credential, err := io.ReadAll(io.LimitReader(file, maxCredentialBytes+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || int64(len(credential)) != state.Size {
		clear(credential)
		return nil, errInput
	}
	return credential, nil
}
