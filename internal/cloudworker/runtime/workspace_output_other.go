//go:build !linux

package runtime

import "os"

// Cloud Worker images are Linux-only. Fail closed where openat2 and link-count
// identity cannot be proven.
func openWorkspaceRoot(string) (*os.File, os.FileInfo, error) {
	return nil, nil, ErrUnsupported
}

func openWorkspaceEntry(*os.File, string, bool) (*os.File, os.FileInfo, error) {
	return nil, nil, ErrUnsupported
}

func openWorkspaceDirectory(*os.File, string) (*os.File, os.FileInfo, error) {
	return nil, nil, ErrUnsupported
}

func validWorkspaceRegularFile(os.FileInfo) bool { return false }

func stableWorkspaceSystemInfo(os.FileInfo, os.FileInfo) bool { return false }
