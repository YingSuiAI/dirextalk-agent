//go:build !linux

package execgate

import "context"

func QualifyFanotifyExecPermission(context.Context, string) error {
	return ErrUnavailable
}
