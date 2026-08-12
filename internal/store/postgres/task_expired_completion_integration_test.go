package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestTimedOutCompletionClosesExactExpiredLease(t *testing.T) {
	pool, store, _ := newPlanningTestStore(t)
	ctx := context.Background()
	scope := task.MutationScope{
		ClientID:     "expired-completion-integration",
		CredentialID: uuid.NewString(),
	}
	stepID := uuid.NewString()
	created, err := store.Create(ctx, scope, task.CreateCommand{
		IdempotencyKey: uuid.NewString(),
		OwnerID:        "owner-expired-completion",
		Goal:           "Exercise the expired Worker completion fence.",
		Retention:      task.RetentionEphemeralAutoDestroy,
		Steps: []task.StepDefinition{{
			StepID:       stepID,
			Name:         "expired-worker",
			ExecutorKind: task.ExecutorCloudWorker,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	steps, err := store.ListSteps(ctx, created.TaskID)
	if err != nil || len(steps) != 1 {
		t.Fatalf("ListSteps() = %#v, %v", steps, err)
	}
	workerID := uuid.NewString()
	attempt, found, err := store.AcquireReadyStep(ctx, scope, task.AcquireReadyStepCommand{
		IdempotencyKey: uuid.NewString(),
		TaskID:         created.TaskID,
		StepID:         steps[0].StepID,
		WorkerID:       workerID,
		ExecutorKind:   task.ExecutorCloudWorker,
		LeaseDuration:  time.Minute,
	})
	if err != nil || !found {
		t.Fatalf("AcquireReadyStep() = %#v, %t, %v", attempt, found, err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE task_attempts
		SET lease_expires_at=clock_timestamp() - interval '1 second'
		WHERE task_id=$1 AND step_id=$2 AND attempt=$3`,
		attempt.TaskID, attempt.StepID, attempt.Attempt,
	); err != nil {
		t.Fatal(err)
	}
	failed := task.CompleteStepCommand{
		IdempotencyKey: uuid.NewString(),
		TaskID:         attempt.TaskID,
		StepID:         attempt.StepID,
		Attempt:        attempt.Attempt,
		LeaseEpoch:     attempt.LeaseEpoch,
		WorkerID:       attempt.WorkerID,
		Outcome:        task.OutcomeFailed,
	}
	if _, err := store.CompleteStep(ctx, scope, failed); !errors.Is(err, task.ErrLeaseExpired) {
		t.Fatalf("failed completion error = %v, want task.ErrLeaseExpired", err)
	}
	timedOut := failed
	timedOut.IdempotencyKey = uuid.NewString()
	timedOut.Outcome = task.OutcomeTimedOut
	completed, err := store.CompleteStep(ctx, scope, timedOut)
	if err != nil || completed.ExecutionStatus != task.ExecutionFinished ||
		completed.OutcomeStatus != task.OutcomeTimedOut {
		t.Fatalf("timed-out completion = %#v, %v", completed, err)
	}
	persisted, err := store.Get(ctx, created.TaskID)
	if err != nil || persisted.ExecutionStatus != task.ExecutionFinished ||
		persisted.OutcomeStatus != task.OutcomeTimedOut {
		t.Fatalf("persisted Task = %#v, %v", persisted, err)
	}
}
