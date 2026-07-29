package workerruntime

import (
	"context"
	"errors"
	"testing"
)

func TestRegistryKeepsRuntimeAdaptersClosed(t *testing.T) {
	t.Parallel()
	executor := &fakeExecutor{adapter: AdapterCodexV1}
	registry, err := NewRegistry(executor)
	if err != nil {
		t.Fatal(err)
	}
	task := validTask()
	if err := registry.ValidateTask(task); err != nil {
		t.Fatal(err)
	}
	task.Adapter = AdapterHermesV1
	if !errors.Is(registry.ValidateTask(task), ErrUnsupported) {
		t.Fatal("uninstalled runtime adapter was accepted")
	}
	if _, err := NewRegistry(executor, executor); !errors.Is(err, ErrInvalid) {
		t.Fatal("duplicate runtime adapter was accepted")
	}
}

func TestRegistryRejectsInvalidExecutorResult(t *testing.T) {
	t.Parallel()
	executor := &fakeExecutor{
		adapter: AdapterCodexV1,
		result: Result{Artifacts: []Artifact{{
			Name: "final.txt", MediaType: "text/plain; charset=utf-8",
			Content: []byte("sk-abcdefghijklmnopqrstuvwxyz"),
		}}},
	}
	registry, err := NewRegistry(executor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Execute(context.Background(), validTask()); !errors.Is(err, ErrExecution) {
		t.Fatalf("invalid adapter output error = %v", err)
	}
	if _, err := registry.Execute(nil, validTask()); !errors.Is(
		err, ErrInvalid,
	) {
		t.Fatalf("nil context error = %v", err)
	}
}

type fakeExecutor struct {
	adapter Adapter
	result  Result
	err     error
}

func (executor *fakeExecutor) Adapter() Adapter { return executor.adapter }

func (executor *fakeExecutor) ValidateTask(task TaskV1) error {
	if task.Adapter != executor.adapter {
		return ErrUnsupported
	}
	return nil
}

func (executor *fakeExecutor) Execute(
	context.Context,
	TaskV1,
) (Result, error) {
	return executor.result, executor.err
}
