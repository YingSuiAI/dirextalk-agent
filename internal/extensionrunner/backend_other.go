//go:build !linux

package extensionrunner

import "context"

type LinuxBackend struct{}

func (LinuxBackend) Probe(context.Context) error { return ErrUnavailable }
func (LinuxBackend) StartV2(context.Context, SandboxInvocationV2) (Process, error) {
	return nil, ErrUnavailable
}
