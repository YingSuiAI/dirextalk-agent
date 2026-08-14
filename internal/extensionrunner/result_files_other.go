//go:build !linux

package extensionrunner

import "os"

func VerifyResultFilesFD(int, []string, int64) ([]ResultFile, error) {
	return nil, ErrUnavailable
}
func CollectAvailableResultFilesFD(int, []string, int64) ([]ResultFile, error) {
	return nil, ErrUnavailable
}

func OpenVerifiedResultFilesFD(int, []ResultFile) ([]*os.File, error) {
	return nil, ErrUnavailable
}
