package runtime

import (
	"context"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
)

type processExecGate interface {
	Register(context.Context, execgate.Registration) (processExecGateRun, error)
}

type processExecGateRun interface {
	Activate(context.Context, int) (execgate.Proof, error)
	Terminal(context.Context) (execgate.Proof, error)
	Cancel(context.Context) error
}

type productionProcessExecGate struct{ client *execgate.Client }

func (gate productionProcessExecGate) Register(ctx context.Context, value execgate.Registration) (processExecGateRun, error) {
	return gate.client.Register(ctx, value)
}
