//go:build !linux

package extensionrunner

func VerifySealedFD(int, int64, string) error { return ErrUnavailable }
func ValidateSealedFD(fd int, size int64, digest string) error {
	return VerifySealedFD(fd, size, digest)
}
