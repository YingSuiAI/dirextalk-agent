package workerruntime

import (
	"context"
	"fmt"
)

// Registry is a closed set of qualified runtime adapters installed in the
// Worker image. A task can select an adapter identity, never an executable.
type Registry struct {
	executors map[Adapter]Executor
}

func NewRegistry(executors ...Executor) (*Registry, error) {
	registry := &Registry{executors: make(map[Adapter]Executor, len(executors))}
	for _, executor := range executors {
		if executor == nil || !validAdapter(executor.Adapter()) {
			return nil, fmt.Errorf("%w: invalid runtime executor", ErrInvalid)
		}
		if _, duplicate := registry.executors[executor.Adapter()]; duplicate {
			return nil, fmt.Errorf("%w: duplicate runtime executor", ErrInvalid)
		}
		registry.executors[executor.Adapter()] = executor
	}
	if len(registry.executors) == 0 {
		return nil, fmt.Errorf("%w: runtime registry is empty", ErrInvalid)
	}
	return registry, nil
}

func (registry *Registry) ValidateTask(task TaskV1) error {
	if registry == nil {
		return ErrUnsupported
	}
	executor, ok := registry.executors[task.Adapter]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnsupported, task.Adapter)
	}
	if err := task.Validate(); err != nil {
		return err
	}
	if err := executor.ValidateTask(task); err != nil {
		return err
	}
	return nil
}

func (registry *Registry) Execute(
	ctx context.Context,
	task TaskV1,
) (Result, error) {
	if ctx == nil {
		return Result{}, ErrInvalid
	}
	if err := registry.ValidateTask(task); err != nil {
		return Result{}, err
	}
	result, err := registry.executors[task.Adapter].Execute(ctx, task)
	if err != nil {
		return Result{}, err
	}
	if err := result.Validate(); err != nil {
		return Result{}, fmt.Errorf("%w: adapter returned an invalid result", ErrExecution)
	}
	return result, nil
}
