//go:build windows

package auth

import (
	"errors"
	"os"
)

func validateServiceTokenFileInfo(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return errors.New("service token file must be a regular file")
	}
	return nil
}
