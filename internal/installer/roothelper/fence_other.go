//go:build !linux

package roothelper

import "os"

func configureDeliveryFenceTemporary(file *os.File, requireRootOwnership bool) error {
	if file == nil || requireRootOwnership || file.Chmod(0o600) != nil {
		return ErrUnavailable
	}
	return nil
}
