package workerrunner

import (
	"context"
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
)

const RuntimeExecuteActionKind = "worker.runtime.execute"

type RuntimeExecuteAction struct {
	runtimes *workerruntime.Registry
}

func NewRuntimeExecuteAction(
	runtimes *workerruntime.Registry,
) (*RuntimeExecuteAction, error) {
	if runtimes == nil {
		return nil, ErrInvalidBundle
	}
	return &RuntimeExecuteAction{runtimes: runtimes}, nil
}

func (*RuntimeExecuteAction) Kind() string { return RuntimeExecuteActionKind }

func (handler *RuntimeExecuteAction) Validate(action ActionV1) error {
	if handler == nil || handler.runtimes == nil ||
		action.Kind != RuntimeExecuteActionKind ||
		action.Runtime == nil || action.Noop != nil ||
		action.Installer != nil {
		return ErrInvalidBundle
	}
	if err := handler.runtimes.ValidateTask(action.Runtime.Task); err != nil {
		return errors.Join(ErrInvalidBundle, err)
	}
	return nil
}

func (handler *RuntimeExecuteAction) Execute(
	ctx context.Context,
	action ActionV1,
) (ActionResult, error) {
	if err := handler.Validate(action); err != nil {
		return ActionResult{}, err
	}
	result, err := handler.runtimes.Execute(ctx, action.Runtime.Task)
	if err != nil {
		return ActionResult{}, errors.Join(workerruntime.ErrExecution, err)
	}
	return ActionResult{Status: "succeeded", Runtime: &result}, nil
}
