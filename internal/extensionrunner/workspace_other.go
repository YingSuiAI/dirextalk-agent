//go:build !linux

package extensionrunner

type workspaceSnapshot map[string]struct{}

func SnapshotWorkspaceFD(int) (workspaceSnapshot, error) {
	return nil, ErrUnavailable
}
func CleanupWorkspaceFD(int, workspaceSnapshot, []string) error {
	return ErrUnavailable
}
