//go:build !linux

package execgate

func newPermissionMonitor(string) (permissionMonitor, error) { return nil, ErrUnavailable }
