//go:build !linux

package extensionrunner

func VerifyResultFilesFD(int, []string) ([]ResultFile, error) {
	return nil, ErrUnavailable
}
func CollectAvailableResultFilesFD(int, []string) ([]ResultFile, error) {
	return nil, ErrUnavailable
}
