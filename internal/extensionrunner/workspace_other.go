//go:build !linux

package extensionrunner

type workspaceSnapshot map[string]struct{}

func SnapshotWorkspaceFD(int, int64) (workspaceSnapshot, error) {
	return nil, ErrUnavailable
}
func CleanupWorkspaceFD(int, workspaceSnapshot, []string, int64) error {
	return ErrUnavailable
}
