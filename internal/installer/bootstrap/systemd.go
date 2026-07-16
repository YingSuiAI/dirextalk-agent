package bootstrap

import (
	"context"
	"errors"
	"os/exec"
)

const installerSocketUnit = "dirextalk-worker-installer.socket"

type fixedCommandRunner interface {
	Run(context.Context, string, ...string) error
}

type SystemdSocketController struct{ runner fixedCommandRunner }

func NewSystemdSocketController() *SystemdSocketController {
	return &SystemdSocketController{runner: systemCommandRunner{}}
}

func newSystemdSocketController(runner fixedCommandRunner) (*SystemdSocketController, error) {
	if runner == nil {
		return nil, ErrInvalidInput
	}
	return &SystemdSocketController{runner: runner}, nil
}

func (controller *SystemdSocketController) Disable(ctx context.Context) error {
	if controller == nil || controller.runner == nil || ctx == nil {
		return ErrSocketActivation
	}
	if err := controller.runner.Run(ctx, "/usr/bin/systemctl", "disable", "--now", installerSocketUnit); err != nil {
		return ErrSocketActivation
	}
	return nil
}

func (controller *SystemdSocketController) Enable(ctx context.Context) error {
	if controller == nil || controller.runner == nil || ctx == nil {
		return ErrSocketActivation
	}
	if err := controller.runner.Run(ctx, "/usr/bin/systemctl", "enable", installerSocketUnit); err != nil {
		return errors.Join(ErrSocketActivation, controller.forceDisabled(ctx))
	}
	if err := controller.runner.Run(ctx, "/usr/bin/systemctl", "start", installerSocketUnit); err != nil {
		return errors.Join(ErrSocketActivation, controller.forceDisabled(ctx))
	}
	return nil
}

func (controller *SystemdSocketController) forceDisabled(ctx context.Context) error {
	return controller.runner.Run(ctx, "/usr/bin/systemctl", "disable", "--now", installerSocketUnit)
}

type systemCommandRunner struct{}

func (systemCommandRunner) Run(ctx context.Context, name string, arguments ...string) error {
	if ctx == nil || name != "/usr/bin/systemctl" {
		return ErrSocketActivation
	}
	command := exec.CommandContext(ctx, name, arguments...)
	command.Stdout = nil
	command.Stderr = nil
	command.Stdin = nil
	return command.Run()
}
