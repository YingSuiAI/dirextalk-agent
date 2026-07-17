//go:build linux

package roothelper

import "os"

func configureDeliveryFenceTemporary(file *os.File, requireRootOwnership bool) error {
	if file == nil {
		return ErrUnavailable
	}
	if requireRootOwnership && (os.Geteuid() != 0 || file.Chown(0, 0) != nil) {
		return ErrUnavailable
	}
	if file.Chmod(0o600) != nil {
		return ErrUnavailable
	}
	return nil
}
