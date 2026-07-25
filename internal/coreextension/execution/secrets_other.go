//go:build !linux

package execution

import (
	"errors"
	"os"
)

func sealSecret([]byte) (*os.File, error) {
	return nil, errors.New("sealed secret descriptors unavailable")
}
