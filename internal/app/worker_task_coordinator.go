package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
)

var ErrWorkerTaskFactsMismatch = errors.New("Worker and Task execution facts do not match")

type workerTaskExecutionStore interface {
	Get(context.Context, string) (task.Task, error)
	ListSteps(context.Context, string) ([]task.Step, error)
	AcquireReadyStep(context.Context, task.MutationScope, task.AcquireReadyStepCommand) (task.Attempt, bool, error)
	RenewStepLease(context.Context, task.MutationScope, task.RenewStepLeaseCommand) (task.Attempt, error)
	CheckpointStep(context.Context, task.MutationScope, task.CheckpointStepCommand) (task.Attempt, error)
	CompleteStep(context.Context, task.MutationScope, task.CompleteStepCommand) (task.Attempt, error)
}

// WorkerTaskCoordinator maps credential-free Worker lifecycle facts to the
// durable Task/Step state machine. Its internal MutationScope is stable across
// restarts so the Worker's idempotency key also replays the Task mutation.
type WorkerTaskCoordinator struct {
	store workerTaskExecutionStore
	scope task.MutationScope
}

var _ worker.TaskExecutionCoordinator = (*WorkerTaskCoordinator)(nil)

func NewWorkerTaskCoordinator(agentInstanceID string, store workerTaskExecutionStore) (*WorkerTaskCoordinator, error) {
	agentID, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || agentID == uuid.Nil || store == nil {
		return nil, fmt.Errorf("%w: Worker Task coordinator dependencies are invalid", ErrWorkerTaskFactsMismatch)
	}
	scope := task.MutationScope{
		ClientID:     "dirextalk-agent-worker-task",
		CredentialID: uuid.NewSHA1(agentID, []byte("worker-task-coordinator/v1")).String(),
	}
	if err := scope.Validate(); err != nil {
		return nil, fmt.Errorf("%w: stable mutation scope is invalid", ErrWorkerTaskFactsMismatch)
	}
	return &WorkerTaskCoordinator{store: store, scope: scope}, nil
}

func (coordinator *WorkerTaskCoordinator) Claim(ctx context.Context, event worker.TaskExecutionClaim) error {
	if err := coordinator.validateOwner(ctx, event.TaskID, event.OwnerID); err != nil {
		return err
	}
	if err := validateWorkerExecutionIDs(event.IdempotencyKey, event.DeploymentID, event.TaskID, event.StepID, event.WorkerID); err != nil {
		return err
	}
	command := task.AcquireReadyStepCommand{
		IdempotencyKey: event.IdempotencyKey, TaskID: event.TaskID, StepID: event.StepID, WorkerID: event.WorkerID,
		ExecutorKind: task.ExecutorCloudWorker, LeaseDuration: event.LeaseDuration,
	}
	attempt, found, err := coordinator.store.AcquireReadyStep(ctx, coordinator.scope, command)
	if err != nil {
		return err
	}
	if !found || !attemptMatches(attempt, event.TaskID, event.StepID, event.WorkerID, event.Attempt, event.LeaseEpoch) ||
		attempt.ExecutionStatus != task.ExecutionRunning || attempt.OutcomeStatus != task.OutcomePending {
		return ErrWorkerTaskFactsMismatch
	}
	return nil
}

func (coordinator *WorkerTaskCoordinator) Heartbeat(ctx context.Context, event worker.TaskExecutionHeartbeat) error {
	if err := coordinator.validateOwner(ctx, event.TaskID, event.OwnerID); err != nil {
		return err
	}
	if err := validateWorkerExecutionIDs(event.IdempotencyKey, event.DeploymentID, event.TaskID, event.StepID, event.WorkerID); err != nil {
		return err
	}
	command := task.RenewStepLeaseCommand{
		IdempotencyKey: event.IdempotencyKey, TaskID: event.TaskID, StepID: event.StepID,
		Attempt: event.Attempt, LeaseEpoch: event.LeaseEpoch, WorkerID: event.WorkerID, LeaseDuration: event.LeaseDuration,
	}
	attempt, err := coordinator.store.RenewStepLease(ctx, coordinator.scope, command)
	if err != nil {
		return err
	}
	if !attemptMatches(attempt, event.TaskID, event.StepID, event.WorkerID, event.Attempt, event.LeaseEpoch) ||
		attempt.ExecutionStatus != task.ExecutionRunning || attempt.OutcomeStatus != task.OutcomePending {
		return ErrWorkerTaskFactsMismatch
	}
	return nil
}

func (coordinator *WorkerTaskCoordinator) Checkpoint(ctx context.Context, event worker.TaskExecutionCheckpoint) error {
	if err := coordinator.validateOwner(ctx, event.TaskID, event.OwnerID); err != nil {
		return err
	}
	if err := validateWorkerExecutionIDs(event.IdempotencyKey, event.DeploymentID, event.TaskID, event.StepID, event.WorkerID); err != nil {
		return err
	}
	command := task.CheckpointStepCommand{
		IdempotencyKey: event.IdempotencyKey, TaskID: event.TaskID, StepID: event.StepID,
		Attempt: event.Attempt, LeaseEpoch: event.LeaseEpoch, WorkerID: event.WorkerID, CheckpointRef: event.CheckpointRef,
	}
	attempt, err := coordinator.store.CheckpointStep(ctx, coordinator.scope, command)
	if err != nil {
		return err
	}
	if !attemptMatches(attempt, event.TaskID, event.StepID, event.WorkerID, event.Attempt, event.LeaseEpoch) ||
		attempt.ExecutionStatus != task.ExecutionRunning || attempt.OutcomeStatus != task.OutcomePending || attempt.CheckpointRef != strings.TrimSpace(event.CheckpointRef) {
		return ErrWorkerTaskFactsMismatch
	}
	return nil
}

func (coordinator *WorkerTaskCoordinator) Complete(ctx context.Context, event worker.TaskExecutionCompletion) error {
	current, err := coordinator.loadOwnedTask(ctx, event.TaskID, event.OwnerID)
	if err != nil {
		return err
	}
	if err := validateWorkerExecutionIDs(event.IdempotencyKey, event.DeploymentID, event.TaskID, event.StepID, event.WorkerID); err != nil {
		return err
	}
	if event.Outcome == worker.OutcomeCanceled {
		return coordinator.acceptCanceled(ctx, current, event)
	}
	outcome, ok := taskOutcome(event.Outcome)
	if !ok {
		return ErrWorkerTaskFactsMismatch
	}
	command := task.CompleteStepCommand{
		IdempotencyKey: event.IdempotencyKey, TaskID: event.TaskID, StepID: event.StepID,
		Attempt: event.Attempt, LeaseEpoch: event.LeaseEpoch, WorkerID: event.WorkerID,
		Outcome: outcome, ResultRef: event.ResultRef,
	}
	attempt, err := coordinator.store.CompleteStep(ctx, coordinator.scope, command)
	if err != nil {
		return err
	}
	if !attemptMatches(attempt, event.TaskID, event.StepID, event.WorkerID, event.Attempt, event.LeaseEpoch) ||
		attempt.ExecutionStatus != task.ExecutionFinished || attempt.OutcomeStatus != outcome || attempt.ResultRef != strings.TrimSpace(event.ResultRef) {
		return ErrWorkerTaskFactsMismatch
	}
	updated, err := coordinator.loadOwnedTask(ctx, event.TaskID, event.OwnerID)
	if err != nil {
		return err
	}
	if outcome == task.OutcomeSucceeded {
		if updated.ExecutionStatus == task.ExecutionFinished && updated.OutcomeStatus == task.OutcomeSucceeded {
			return nil
		}
		if updated.ExecutionStatus == task.ExecutionQueued && updated.OutcomeStatus == task.OutcomePending {
			return nil
		}
		return ErrWorkerTaskFactsMismatch
	}
	if updated.ExecutionStatus != task.ExecutionFinished || updated.OutcomeStatus != outcome {
		return ErrWorkerTaskFactsMismatch
	}
	return nil
}

func (coordinator *WorkerTaskCoordinator) acceptCanceled(ctx context.Context, current task.Task, event worker.TaskExecutionCompletion) error {
	if current.ExecutionStatus != task.ExecutionFinished || current.OutcomeStatus != task.OutcomeCanceled {
		return ErrWorkerTaskFactsMismatch
	}
	steps, err := coordinator.store.ListSteps(ctx, event.TaskID)
	if err != nil {
		return err
	}
	for _, step := range steps {
		if step.TaskID == event.TaskID && step.StepID == event.StepID && step.Attempt == event.Attempt && step.LeaseEpoch == event.LeaseEpoch+1 &&
			step.ExecutionStatus == task.ExecutionFinished && step.OutcomeStatus == task.OutcomeCanceled {
			return nil
		}
	}
	return ErrWorkerTaskFactsMismatch
}

func (coordinator *WorkerTaskCoordinator) validateOwner(ctx context.Context, taskID, ownerID string) error {
	_, err := coordinator.loadOwnedTask(ctx, taskID, ownerID)
	return err
}

func (coordinator *WorkerTaskCoordinator) loadOwnedTask(ctx context.Context, taskID, ownerID string) (task.Task, error) {
	if coordinator == nil || coordinator.store == nil || ctx == nil || strings.TrimSpace(ownerID) == "" {
		return task.Task{}, ErrWorkerTaskFactsMismatch
	}
	current, err := coordinator.store.Get(ctx, taskID)
	if err != nil {
		return task.Task{}, err
	}
	if current.TaskID != taskID || current.OwnerID != ownerID {
		return task.Task{}, ErrWorkerTaskFactsMismatch
	}
	return current, nil
}

func validateWorkerExecutionIDs(values ...string) error {
	for _, value := range values {
		parsed, err := uuid.Parse(strings.TrimSpace(value))
		if err != nil || parsed == uuid.Nil {
			return ErrWorkerTaskFactsMismatch
		}
	}
	return nil
}

func attemptMatches(attempt task.Attempt, taskID, stepID, workerID string, attemptNumber int32, leaseEpoch int64) bool {
	return attempt.TaskID == taskID && attempt.StepID == stepID && attempt.WorkerID == workerID &&
		attempt.Attempt == attemptNumber && attempt.LeaseEpoch == leaseEpoch
}

func taskOutcome(outcome worker.Outcome) (task.OutcomeStatus, bool) {
	switch outcome {
	case worker.OutcomeSucceeded:
		return task.OutcomeSucceeded, true
	case worker.OutcomeFailed:
		return task.OutcomeFailed, true
	case worker.OutcomeTimedOut:
		return task.OutcomeTimedOut, true
	case worker.OutcomeInterrupted:
		return task.OutcomeInterrupted, true
	default:
		return "", false
	}
}
