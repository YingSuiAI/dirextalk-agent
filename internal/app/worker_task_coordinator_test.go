package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
)

func TestWorkerTaskCoordinatorMapsLifecycleAndUsesStableScope(t *testing.T) {
	fixture := newWorkerTaskFixture(t)
	coordinator := fixture.coordinator(t)
	ctx := context.Background()

	if err := coordinator.Claim(ctx, fixture.claim); err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if len(fixture.store.acquireCommands) != 1 || fixture.store.acquireCommands[0].StepID != fixture.claim.StepID {
		t.Fatalf("Claim() acquired command = %#v, want exact deployment step %s", fixture.store.acquireCommands, fixture.claim.StepID)
	}
	heartbeat := worker.TaskExecutionHeartbeat{
		IdempotencyKey: uuid.NewString(), DeploymentID: fixture.claim.DeploymentID, OwnerID: fixture.claim.OwnerID,
		TaskID: fixture.claim.TaskID, StepID: fixture.claim.StepID, WorkerID: fixture.claim.WorkerID,
		Attempt: fixture.claim.Attempt, LeaseEpoch: fixture.claim.LeaseEpoch, LeaseDuration: 2 * time.Minute,
	}
	if err := coordinator.Heartbeat(ctx, heartbeat); err != nil {
		t.Fatalf("Heartbeat() error = %v", err)
	}
	checkpoint := worker.TaskExecutionCheckpoint{
		IdempotencyKey: uuid.NewString(), DeploymentID: fixture.claim.DeploymentID, OwnerID: fixture.claim.OwnerID,
		TaskID: fixture.claim.TaskID, StepID: fixture.claim.StepID, WorkerID: fixture.claim.WorkerID,
		Attempt: fixture.claim.Attempt, LeaseEpoch: fixture.claim.LeaseEpoch, CheckpointRef: "s3://worker/checkpoints/one.json",
	}
	if err := coordinator.Checkpoint(ctx, checkpoint); err != nil {
		t.Fatalf("Checkpoint() error = %v", err)
	}
	completion := worker.TaskExecutionCompletion{
		IdempotencyKey: uuid.NewString(), DeploymentID: fixture.claim.DeploymentID, OwnerID: fixture.claim.OwnerID,
		TaskID: fixture.claim.TaskID, StepID: fixture.claim.StepID, WorkerID: fixture.claim.WorkerID,
		Attempt: fixture.claim.Attempt, LeaseEpoch: fixture.claim.LeaseEpoch,
		Outcome: worker.OutcomeSucceeded, ResultRef: "s3://worker/results/one.tar",
	}
	if err := coordinator.Complete(ctx, completion); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if fixture.store.task.ExecutionStatus != task.ExecutionFinished || fixture.store.task.OutcomeStatus != task.OutcomeSucceeded {
		t.Fatalf("Task after completion = %#v", fixture.store.task)
	}
	if len(fixture.store.scopes) != 4 {
		t.Fatalf("mutation scopes = %d, want 4", len(fixture.store.scopes))
	}
	for _, scope := range fixture.store.scopes {
		if scope != fixture.store.scopes[0] || scope.Validate() != nil {
			t.Fatalf("unstable internal mutation scope = %#v", fixture.store.scopes)
		}
	}
}

func TestWorkerTaskCoordinatorRejectsLeaseEpochMismatch(t *testing.T) {
	fixture := newWorkerTaskFixture(t)
	fixture.store.attempt.LeaseEpoch++

	err := fixture.coordinator(t).Claim(context.Background(), fixture.claim)
	if !errors.Is(err, ErrWorkerTaskFactsMismatch) {
		t.Fatalf("Claim() error = %v, want ErrWorkerTaskFactsMismatch", err)
	}
}

func TestWorkerTaskCoordinatorAcceptsCanceledOnlyAfterTaskTerminalFence(t *testing.T) {
	fixture := newWorkerTaskFixture(t)
	coordinator := fixture.coordinator(t)
	completion := worker.TaskExecutionCompletion{
		IdempotencyKey: uuid.NewString(), DeploymentID: fixture.claim.DeploymentID, OwnerID: fixture.claim.OwnerID,
		TaskID: fixture.claim.TaskID, StepID: fixture.claim.StepID, WorkerID: fixture.claim.WorkerID,
		Attempt: fixture.claim.Attempt, LeaseEpoch: fixture.claim.LeaseEpoch, Outcome: worker.OutcomeCanceled,
	}

	if err := coordinator.Complete(context.Background(), completion); !errors.Is(err, ErrWorkerTaskFactsMismatch) {
		t.Fatalf("running Task canceled completion error = %v", err)
	}
	if fixture.store.completeCalls != 0 {
		t.Fatal("canceled Worker completion must not call CompleteStep")
	}
	fixture.store.task.ExecutionStatus = task.ExecutionFinished
	fixture.store.task.OutcomeStatus = task.OutcomeCanceled
	fixture.store.steps[0].ExecutionStatus = task.ExecutionFinished
	fixture.store.steps[0].OutcomeStatus = task.OutcomeCanceled
	fixture.store.steps[0].LeaseEpoch = completion.LeaseEpoch + 1
	if err := coordinator.Complete(context.Background(), completion); err != nil {
		t.Fatalf("terminal canceled Task rejected: %v", err)
	}
}

type workerTaskFixture struct {
	agentID string
	claim   worker.TaskExecutionClaim
	store   *fakeWorkerTaskStore
}

func newWorkerTaskFixture(t *testing.T) workerTaskFixture {
	t.Helper()
	taskID, stepID, workerID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	claim := worker.TaskExecutionClaim{
		IdempotencyKey: uuid.NewString(), DeploymentID: uuid.NewString(), OwnerID: "owner-1",
		TaskID: taskID, StepID: stepID, WorkerID: workerID, Attempt: 1, LeaseEpoch: 1, LeaseDuration: time.Minute,
	}
	attempt := task.Attempt{
		TaskID: taskID, StepID: stepID, WorkerID: workerID, Attempt: 1, LeaseEpoch: 1,
		ExecutionStatus: task.ExecutionRunning, OutcomeStatus: task.OutcomePending,
	}
	return workerTaskFixture{
		agentID: uuid.NewString(), claim: claim,
		store: &fakeWorkerTaskStore{
			task:    task.Task{TaskID: taskID, OwnerID: claim.OwnerID, ExecutionStatus: task.ExecutionQueued, OutcomeStatus: task.OutcomePending},
			attempt: attempt,
			steps:   []task.Step{{TaskID: taskID, StepID: stepID, Attempt: 1, LeaseEpoch: 1, ExecutionStatus: task.ExecutionRunning, OutcomeStatus: task.OutcomePending}},
		},
	}
}

func (fixture workerTaskFixture) coordinator(t *testing.T) *WorkerTaskCoordinator {
	t.Helper()
	coordinator, err := NewWorkerTaskCoordinator(fixture.agentID, fixture.store)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

type fakeWorkerTaskStore struct {
	task            task.Task
	attempt         task.Attempt
	steps           []task.Step
	scopes          []task.MutationScope
	acquireCommands []task.AcquireReadyStepCommand
	completeCalls   int
}

func (store *fakeWorkerTaskStore) Get(context.Context, string) (task.Task, error) {
	return store.task, nil
}

func (store *fakeWorkerTaskStore) ListSteps(context.Context, string) ([]task.Step, error) {
	return append([]task.Step(nil), store.steps...), nil
}

func (store *fakeWorkerTaskStore) AcquireReadyStep(_ context.Context, scope task.MutationScope, command task.AcquireReadyStepCommand) (task.Attempt, bool, error) {
	store.scopes = append(store.scopes, scope)
	store.acquireCommands = append(store.acquireCommands, command)
	return store.attempt, true, nil
}

func (store *fakeWorkerTaskStore) RenewStepLease(_ context.Context, scope task.MutationScope, _ task.RenewStepLeaseCommand) (task.Attempt, error) {
	store.scopes = append(store.scopes, scope)
	return store.attempt, nil
}

func (store *fakeWorkerTaskStore) CheckpointStep(_ context.Context, scope task.MutationScope, command task.CheckpointStepCommand) (task.Attempt, error) {
	store.scopes = append(store.scopes, scope)
	store.attempt.CheckpointRef = command.CheckpointRef
	return store.attempt, nil
}

func (store *fakeWorkerTaskStore) CompleteStep(_ context.Context, scope task.MutationScope, command task.CompleteStepCommand) (task.Attempt, error) {
	store.scopes = append(store.scopes, scope)
	store.completeCalls++
	store.attempt.ExecutionStatus = task.ExecutionFinished
	store.attempt.OutcomeStatus = command.Outcome
	store.attempt.ResultRef = command.ResultRef
	store.task.ExecutionStatus = task.ExecutionFinished
	store.task.OutcomeStatus = command.Outcome
	return store.attempt, nil
}
