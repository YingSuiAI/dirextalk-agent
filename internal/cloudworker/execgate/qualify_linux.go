//go:build linux

package execgate

import (
	"context"
	"errors"
	"os/exec"
)

// QualifyFanotifyExecPermission exercises the production fanotify permission
// monitor through one real executable open. The immutable AMI runs this exact
// path before starting the long-running execution Gate.
func QualifyFanotifyExecPermission(ctx context.Context, executable string) error {
	if ctx == nil || executable == "" {
		return ErrInvalid
	}
	monitor, err := newPermissionMonitor(executable)
	if err != nil {
		return err
	}
	defer monitor.Close()

	command := exec.CommandContext(ctx, executable)
	done := make(chan error, 1)
	go func() { done <- command.Run() }()

	select {
	case event, ok := <-monitor.Events():
		if !ok || event.PID < 1 || event.File == nil {
			return ErrUnavailable
		}
		if err := event.respond(true); err != nil {
			_ = event.File.Close()
			return err
		}
		_ = event.File.Close()
	case err := <-monitor.Errors():
		if err == nil {
			return ErrUnavailable
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}

	if err := <-done; err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
			return ctx.Err()
		}
		return err
	}
	return nil
}
