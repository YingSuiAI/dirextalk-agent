//go:build linux

package execgate

import (
	"context"
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
	if err := command.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	return qualifyPermissionEvents(ctx, monitor.Events(), monitor.Errors(), done)
}

func qualifyPermissionEvents(
	ctx context.Context,
	events <-chan permissionEvent,
	monitorErrors <-chan error,
	commandDone <-chan error,
) error {
	observed := uint64(0)
	if ctx == nil || events == nil || monitorErrors == nil || commandDone == nil {
		return ErrInvalid
	}
	for {
		select {
		case event, ok := <-events:
			if !ok || event.PID < 1 || event.File == nil {
				return ErrUnavailable
			}
			if err := event.respond(true); err != nil {
				_ = event.File.Close()
				return err
			}
			_ = event.File.Close()
			observed++
		case err, ok := <-monitorErrors:
			if !ok || err == nil {
				return ErrUnavailable
			}
			return err
		case err, ok := <-commandDone:
			if !ok {
				return ErrUnavailable
			}
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return err
			}
			if observed == 0 {
				return ErrUnavailable
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
