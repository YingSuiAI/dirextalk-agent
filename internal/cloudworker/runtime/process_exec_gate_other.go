//go:build !linux

package runtime

func newProductionProcessExecGate() (processExecGate, error) { return nil, ErrUnsupported }
