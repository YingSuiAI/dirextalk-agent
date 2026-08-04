//go:build !linux

package secretbox

import "os"

type mountedIdentity struct{}

func openMountedKey(path string) (*os.File, mountedIdentity, error) {
	if err := ValidateMountedFile(path); err != nil {
		return nil, mountedIdentity{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, mountedIdentity{}, ErrInvalidKey
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 {
		_ = f.Close()
		return nil, mountedIdentity{}, ErrInvalidKey
	}
	return f, mountedIdentity{}, nil
}

func verifyMountedKey(file *os.File, _ mountedIdentity) error {
	if file == nil {
		return ErrInvalidKey
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 {
		return ErrInvalidKey
	}
	return nil
}
