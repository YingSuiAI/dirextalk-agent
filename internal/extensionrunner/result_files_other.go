//go:build !linux

package extensionrunner

func VerifyResultFilesFD(int, []string, int64) ([]ResultFile, error) {
	return nil, ErrUnavailable
}
func CollectAvailableResultFilesFD(int, []string, int64) ([]ResultFile, error) {
	return nil, ErrUnavailable
}
