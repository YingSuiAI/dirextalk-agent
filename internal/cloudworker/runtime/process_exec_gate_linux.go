//go:build linux

package runtime

import (
	"context"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
)

func newProductionProcessExecGate() (processExecGate, error) {
	client, err := execgate.NewClient(execgate.DefaultSocketPath)
	if err != nil {
		return nil, ErrExecution
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err = client.Ping(ctx); err != nil {
		return nil, ErrExecution
	}
	return productionProcessExecGate{client: client}, nil
}
