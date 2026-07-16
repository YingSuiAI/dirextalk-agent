package p0_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestTaskStoreConcurrentCreateIsCallerScopedAndAtomic(t *testing.T) {
	database := newMigratedDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	firstStepID, secondStepID := uuid.NewString(), uuid.NewString()
	command := task.CreateCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: "owner-1", Goal: "compile and verify",
		Retention: task.RetentionEphemeralAutoDestroy,
		Steps: []task.StepDefinition{
			{StepID: firstStepID, Name: "compile", ExecutorKind: task.ExecutorCloudWorker},
			{StepID: secondStepID, Name: "verify", ExecutorKind: task.ExecutorCloudWorker, DependsOnStepIDs: []string{firstStepID}},
		},
	}
	firstCaller := task.MutationScope{ClientID: "message-server-a", CredentialID: uuid.NewString()}

	const goroutines = 12
	type createResult struct {
		item task.Task
		err  error
	}
	results := make(chan createResult, goroutines)
	var wait sync.WaitGroup
	for range goroutines {
		wait.Add(1)
		go func() {
			defer wait.Done()
			item, err := database.store.Create(ctx, firstCaller, command)
			results <- createResult{item: item, err: err}
		}()
	}
	wait.Wait()
	close(results)

	var firstSnapshot []byte
	var firstTask task.Task
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent Create() error = %v", result.err)
		}
		encoded, err := json.Marshal(result.item)
		if err != nil {
			t.Fatalf("encode task snapshot: %v", err)
		}
		if firstSnapshot == nil {
			firstSnapshot = encoded
			firstTask = result.item
		} else if !bytes.Equal(encoded, firstSnapshot) {
			t.Fatalf("idempotent Create() returned a different snapshot:\nfirst=%s\nnext=%s", firstSnapshot, encoded)
		}
	}

	secondCaller := task.MutationScope{ClientID: "message-server-b", CredentialID: uuid.NewString()}
	secondTask, err := database.store.Create(ctx, secondCaller, command)
	if err != nil {
		t.Fatalf("same idempotency UUID in another caller scope failed: %v", err)
	}
	if secondTask.TaskID == firstTask.TaskID {
		t.Fatal("different caller scopes shared a task")
	}

	assertTableCount(t, ctx, database, "tasks", 2)
	assertTableCount(t, ctx, database, "task_steps", 4)
	assertTableCount(t, ctx, database, "task_step_dependencies", 2)
	assertTableCount(t, ctx, database, "task_events", 2)
	assertTableCount(t, ctx, database, "outbox_events", 2)
	var ledgerCount int
	if err := database.pool.QueryRow(ctx, `
		SELECT count(*) FROM idempotency_records
		WHERE operation='task.create' AND idempotency_key=$1`, command.IdempotencyKey).Scan(&ledgerCount); err != nil {
		t.Fatalf("count scoped idempotency records: %v", err)
	}
	if ledgerCount != 2 {
		t.Fatalf("scoped idempotency records = %d, want 2", ledgerCount)
	}
}

func TestTaskStoreRollsBackTaskWhenDAGInsertFails(t *testing.T) {
	database := newMigratedDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	scope := task.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()}
	if _, err := database.pool.Exec(ctx, `
		CREATE FUNCTION reject_test_task_step() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'injected task step failure'; END;
		$$;
		CREATE TRIGGER reject_test_task_step BEFORE INSERT ON task_steps
		FOR EACH ROW EXECUTE FUNCTION reject_test_task_step()`); err != nil {
		t.Fatalf("install task step failure injection: %v", err)
	}
	command := task.CreateCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: "owner-1", Goal: "atomic create",
		Retention: task.RetentionEphemeralAutoDestroy,
		Steps:     []task.StepDefinition{{StepID: uuid.NewString(), Name: "first", ExecutorKind: task.ExecutorCloudWorker}},
	}
	if _, err := database.store.Create(ctx, scope, command); err == nil {
		t.Fatal("injected task step failure unexpectedly succeeded")
	}
	assertTableCount(t, ctx, database, "tasks", 0)
	assertTableCount(t, ctx, database, "task_steps", 0)
	assertTableCount(t, ctx, database, "task_events", 0)
	assertTableCount(t, ctx, database, "outbox_events", 0)
	var rolledBackLedger int
	if err := database.pool.QueryRow(ctx, `SELECT count(*) FROM idempotency_records WHERE idempotency_key=$1`, command.IdempotencyKey).Scan(&rolledBackLedger); err != nil {
		t.Fatalf("count rolled-back idempotency record: %v", err)
	}
	if rolledBackLedger != 0 {
		t.Fatalf("rolled-back idempotency records = %d, want 0", rolledBackLedger)
	}
}

func TestAcquireReadyStepLeasesOnlyTheRequestedReadyStep(t *testing.T) {
	database := newMigratedDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	scope := task.MutationScope{ClientID: "worker-coordinator", CredentialID: uuid.NewString()}
	created, err := database.store.Create(ctx, scope, task.CreateCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: "owner-1", Goal: "run two independent Worker deployments",
		Retention: task.RetentionEphemeralAutoDestroy,
		Steps: []task.StepDefinition{
			{StepID: uuid.NewString(), Name: "older-ready-step", ExecutorKind: task.ExecutorCloudWorker},
			{StepID: uuid.NewString(), Name: "deployment-target-step", ExecutorKind: task.ExecutorCloudWorker},
		},
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	steps, err := database.store.ListSteps(ctx, created.TaskID)
	if err != nil {
		t.Fatalf("list task steps: %v", err)
	}
	olderStepID := stepIDByName(t, steps, "older-ready-step")
	targetStepID := stepIDByName(t, steps, "deployment-target-step")

	attempt, found, err := database.store.AcquireReadyStep(ctx, scope, task.AcquireReadyStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: created.TaskID, StepID: targetStepID, WorkerID: uuid.NewString(),
		ExecutorKind: task.ExecutorCloudWorker, LeaseDuration: time.Minute,
	})
	if err != nil || !found {
		t.Fatalf("acquire requested step: attempt=%#v found=%v err=%v", attempt, found, err)
	}
	if attempt.StepID != targetStepID {
		t.Fatalf("leased step=%s, want deployment target=%s (older ready step=%s)", attempt.StepID, targetStepID, olderStepID)
	}
	steps, err = database.store.ListSteps(ctx, created.TaskID)
	if err != nil {
		t.Fatalf("list steps after acquire: %v", err)
	}
	for _, step := range steps {
		if step.StepID == olderStepID && (step.ExecutionStatus != task.ExecutionQueued || step.Attempt != 0 || step.LeaseEpoch != 0) {
			t.Fatalf("unrequested ready step was mutated: %#v", step)
		}
	}
}

func TestTaskStoreLeaseFencingCheckpointCompleteAndCancel(t *testing.T) {
	database := newMigratedDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	scope := task.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()}
	workerID := uuid.NewString()
	firstStepID, secondStepID := uuid.NewString(), uuid.NewString()
	created, err := database.store.Create(ctx, scope, task.CreateCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: "owner-1", Goal: "build in two steps",
		Retention: task.RetentionEphemeralAutoDestroy,
		Steps: []task.StepDefinition{
			{StepID: firstStepID, Name: "compile", ExecutorKind: task.ExecutorCloudWorker},
			{StepID: secondStepID, Name: "verify", ExecutorKind: task.ExecutorCloudWorker, DependsOnStepIDs: []string{firstStepID}},
		},
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	steps, err := database.store.ListSteps(ctx, created.TaskID)
	if err != nil {
		t.Fatalf("list created steps: %v", err)
	}
	firstStepID, secondStepID = stepIDByName(t, steps, "compile"), stepIDByName(t, steps, "verify")

	firstAttempt, found, err := database.store.AcquireReadyStep(ctx, scope, task.AcquireReadyStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: created.TaskID, StepID: firstStepID, WorkerID: workerID,
		ExecutorKind: task.ExecutorCloudWorker, LeaseDuration: time.Minute,
	})
	if err != nil || !found {
		t.Fatalf("acquire first step: found=%v err=%v", found, err)
	}
	if firstAttempt.StepID != firstStepID || firstAttempt.Attempt != 1 || firstAttempt.LeaseEpoch != 1 {
		t.Fatalf("first attempt = %#v", firstAttempt)
	}

	if _, found, err := database.store.AcquireReadyStep(ctx, scope, task.AcquireReadyStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: created.TaskID, StepID: secondStepID, WorkerID: workerID,
		ExecutorKind: task.ExecutorCloudWorker, LeaseDuration: time.Minute,
	}); err != nil || found {
		t.Fatalf("dependency-blocked acquire: found=%v err=%v", found, err)
	}

	checkpoint, err := database.store.CheckpointStep(ctx, scope, task.CheckpointStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: created.TaskID, StepID: firstStepID,
		Attempt: 1, LeaseEpoch: 1, WorkerID: workerID, CheckpointRef: "s3://artifacts/checkpoints/compile",
	})
	if err != nil || checkpoint.CheckpointRef == "" {
		t.Fatalf("checkpoint first step: attempt=%#v err=%v", checkpoint, err)
	}
	renewed, err := database.store.RenewStepLease(ctx, scope, task.RenewStepLeaseCommand{
		IdempotencyKey: uuid.NewString(), TaskID: created.TaskID, StepID: firstStepID,
		Attempt: 1, LeaseEpoch: 1, WorkerID: workerID, LeaseDuration: 2 * time.Minute,
	})
	if err != nil || !renewed.LeaseExpiresAt.After(firstAttempt.LeaseExpiresAt) {
		t.Fatalf("renew first step: attempt=%#v err=%v", renewed, err)
	}
	if _, err := database.store.CompleteStep(ctx, scope, task.CompleteStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: created.TaskID, StepID: firstStepID,
		Attempt: 1, LeaseEpoch: 1, WorkerID: workerID, Outcome: task.OutcomeSucceeded,
		ResultRef: "s3://artifacts/results/compile",
	}); err != nil {
		t.Fatalf("complete first step: %v", err)
	}
	if _, err := database.store.CheckpointStep(ctx, scope, task.CheckpointStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: created.TaskID, StepID: firstStepID,
		Attempt: 1, LeaseEpoch: 1, WorkerID: workerID, CheckpointRef: "s3://artifacts/checkpoints/late",
	}); !errors.Is(err, task.ErrStaleLease) {
		t.Fatalf("completed attempt late checkpoint error = %v, want ErrStaleLease", err)
	}

	secondAttempt, found, err := database.store.AcquireReadyStep(ctx, scope, task.AcquireReadyStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: created.TaskID, StepID: secondStepID, WorkerID: workerID,
		ExecutorKind: task.ExecutorCloudWorker, LeaseDuration: time.Minute,
	})
	if err != nil || !found || secondAttempt.StepID != secondStepID {
		t.Fatalf("acquire dependent step: attempt=%#v found=%v err=%v", secondAttempt, found, err)
	}
	current, err := database.store.Get(ctx, created.TaskID)
	if err != nil {
		t.Fatalf("get task before cancel: %v", err)
	}
	canceled, err := database.store.Cancel(ctx, scope, task.CancelCommand{
		IdempotencyKey: uuid.NewString(), TaskID: created.TaskID, ExpectedRevision: current.Revision,
		Reason: "operator requested password=super-secret",
	})
	if err != nil {
		t.Fatalf("cancel task: %v", err)
	}
	if canceled.ExecutionStatus != task.ExecutionFinished || canceled.OutcomeStatus != task.OutcomeCanceled {
		t.Fatalf("canceled task = %#v", canceled)
	}
	if _, err := database.store.CheckpointStep(ctx, scope, task.CheckpointStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: created.TaskID, StepID: secondStepID,
		Attempt: secondAttempt.Attempt, LeaseEpoch: secondAttempt.LeaseEpoch, WorkerID: workerID,
		CheckpointRef: "s3://artifacts/checkpoints/late",
	}); !errors.Is(err, task.ErrStaleLease) {
		t.Fatalf("canceled attempt late checkpoint error = %v, want ErrStaleLease", err)
	}

	var summary []byte
	if err := database.pool.QueryRow(ctx, `
		SELECT summary_json FROM task_events
		WHERE aggregate_id=$1 AND event_type='agent.task.canceled'`, created.TaskID).Scan(&summary); err != nil {
		t.Fatalf("read cancel event summary: %v", err)
	}
	text := string(summary)
	for _, required := range []string{
		`"task_id"`, `"owner_id"`, `"execution_status"`, `"outcome_status"`, `"retention_policy"`,
		`"current_step_id"`, `"approved_plan_id"`, `"revision"`, `"created_at"`, `"updated_at"`,
		`"actor_client_id"`, `"actor_credential_id"`, `"reason"`, `[redacted]`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("cancel summary missing %q: %s", required, text)
		}
	}
	if strings.Contains(text, "super-secret") {
		t.Fatalf("cancel summary leaked reason secret: %s", text)
	}
	var samePayload bool
	if err := database.pool.QueryRow(ctx, `
		SELECT e.summary_json=o.payload_json
		FROM task_events e JOIN outbox_events o ON o.event_seq=e.seq
		WHERE e.aggregate_id=$1 AND e.event_type='agent.task.canceled'`, created.TaskID).Scan(&samePayload); err != nil {
		t.Fatalf("compare cancel event and outbox payload: %v", err)
	}
	if !samePayload {
		t.Fatal("cancel event and outbox payload diverged")
	}
	var canceledStepSummary []byte
	if err := database.pool.QueryRow(ctx, `
		SELECT summary_json FROM task_events
		WHERE aggregate_type='step' AND event_type='agent.step.canceled'`).Scan(&canceledStepSummary); err != nil {
		t.Fatalf("read canceled step event: %v", err)
	}
	stepText := string(canceledStepSummary)
	for _, required := range []string{`"schema_version": 1`, `"task_id"`, `"step_id"`, `"execution_status"`, `"outcome_status"`, `"lease_epoch"`, `"actor_client_id"`, `"actor_credential_id"`} {
		if !strings.Contains(stepText, required) {
			t.Fatalf("canceled step summary missing %q: %s", required, stepText)
		}
	}
	for _, forbidden := range []string{"checkpoint_ref", "result_ref", "s3://"} {
		if strings.Contains(stepText, forbidden) {
			t.Fatalf("canceled step summary leaked %q: %s", forbidden, stepText)
		}
	}
}

func TestFailedStepCancelsAndFencesRunningSiblings(t *testing.T) {
	database := newMigratedDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	scope := task.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()}
	workerID := uuid.NewString()
	created, err := database.store.Create(ctx, scope, task.CreateCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: "owner-1", Goal: "parallel work",
		Retention: task.RetentionEphemeralAutoDestroy,
		Steps: []task.StepDefinition{
			{StepID: uuid.NewString(), Name: "first", ExecutorKind: task.ExecutorCloudWorker},
			{StepID: uuid.NewString(), Name: "sibling", ExecutorKind: task.ExecutorCloudWorker},
		},
	})
	if err != nil {
		t.Fatalf("create parallel task: %v", err)
	}
	steps, err := database.store.ListSteps(ctx, created.TaskID)
	if err != nil {
		t.Fatalf("list parallel steps: %v", err)
	}
	firstStepID := stepIDByName(t, steps, "first")
	siblingStepID := stepIDByName(t, steps, "sibling")
	first, found, err := database.store.AcquireReadyStep(ctx, scope, task.AcquireReadyStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: created.TaskID, StepID: firstStepID, WorkerID: workerID,
		ExecutorKind: task.ExecutorCloudWorker, LeaseDuration: time.Minute,
	})
	if err != nil || !found {
		t.Fatalf("acquire first parallel step: found=%v err=%v", found, err)
	}
	sibling, found, err := database.store.AcquireReadyStep(ctx, scope, task.AcquireReadyStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: created.TaskID, StepID: siblingStepID, WorkerID: workerID,
		ExecutorKind: task.ExecutorCloudWorker, LeaseDuration: time.Minute,
	})
	if err != nil || !found {
		t.Fatalf("acquire sibling step: found=%v err=%v", found, err)
	}
	if _, err := database.store.CompleteStep(ctx, scope, task.CompleteStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: created.TaskID, StepID: first.StepID,
		Attempt: first.Attempt, LeaseEpoch: first.LeaseEpoch, WorkerID: workerID,
		Outcome: task.OutcomeFailed,
	}); err != nil {
		t.Fatalf("fail first step: %v", err)
	}
	current, err := database.store.Get(ctx, created.TaskID)
	if err != nil {
		t.Fatalf("get failed task: %v", err)
	}
	if current.ExecutionStatus != task.ExecutionFinished || current.OutcomeStatus != task.OutcomeFailed {
		t.Fatalf("failed task = %#v", current)
	}
	if _, err := database.store.CheckpointStep(ctx, scope, task.CheckpointStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: created.TaskID, StepID: sibling.StepID,
		Attempt: sibling.Attempt, LeaseEpoch: sibling.LeaseEpoch, WorkerID: workerID,
		CheckpointRef: "s3://artifacts/checkpoints/stale-sibling",
	}); !errors.Is(err, task.ErrStaleLease) {
		t.Fatalf("failed-task sibling error = %v, want ErrStaleLease", err)
	}
	var canceledEvents int
	if err := database.pool.QueryRow(ctx, `
		SELECT count(*) FROM task_events
		WHERE aggregate_type='step' AND event_type='agent.step.canceled'`).Scan(&canceledEvents); err != nil {
		t.Fatalf("count sibling cancellation events: %v", err)
	}
	if canceledEvents != 1 {
		t.Fatalf("sibling cancellation events = %d, want 1", canceledEvents)
	}
}

func TestExpiredLeaseReacquiresWithNewEpochAndFencesOldWorker(t *testing.T) {
	database := newMigratedDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	scope := task.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()}
	workerID := uuid.NewString()
	stepID := uuid.NewString()
	created, err := database.store.Create(ctx, scope, task.CreateCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: "owner-1", Goal: "recover expired work",
		Retention: task.RetentionEphemeralAutoDestroy,
		Steps:     []task.StepDefinition{{StepID: stepID, Name: "compile", ExecutorKind: task.ExecutorCloudWorker}},
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	steps, err := database.store.ListSteps(ctx, created.TaskID)
	if err != nil {
		t.Fatalf("list created steps: %v", err)
	}
	stepID = stepIDByName(t, steps, "compile")
	first, found, err := database.store.AcquireReadyStep(ctx, scope, task.AcquireReadyStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: created.TaskID, StepID: stepID, WorkerID: workerID,
		ExecutorKind: task.ExecutorCloudWorker, LeaseDuration: time.Minute,
	})
	if err != nil || !found {
		t.Fatalf("acquire initial attempt: found=%v err=%v", found, err)
	}
	if _, err := database.pool.Exec(ctx, `
		UPDATE task_attempts SET lease_expires_at=clock_timestamp()-interval '1 second'
		WHERE task_id=$1 AND step_id=$2 AND attempt=$3`, created.TaskID, stepID, first.Attempt); err != nil {
		t.Fatalf("expire fixture lease: %v", err)
	}
	second, found, err := database.store.AcquireReadyStep(ctx, scope, task.AcquireReadyStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: created.TaskID, StepID: stepID, WorkerID: workerID,
		ExecutorKind: task.ExecutorCloudWorker, LeaseDuration: time.Minute,
	})
	if err != nil || !found {
		t.Fatalf("reacquire expired step: found=%v err=%v", found, err)
	}
	if second.Attempt != first.Attempt+1 || second.LeaseEpoch != first.LeaseEpoch+1 {
		t.Fatalf("reacquired attempt = %#v, first = %#v", second, first)
	}
	if _, err := database.store.CheckpointStep(ctx, scope, task.CheckpointStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: created.TaskID, StepID: stepID,
		Attempt: first.Attempt, LeaseEpoch: first.LeaseEpoch, WorkerID: workerID,
		CheckpointRef: "s3://artifacts/checkpoints/stale",
	}); !errors.Is(err, task.ErrStaleLease) {
		t.Fatalf("old epoch error = %v, want ErrStaleLease", err)
	}
}

func assertTableCount(t *testing.T, ctx context.Context, database testDatabase, table string, want int) {
	t.Helper()
	allowed := map[string]bool{
		"tasks": true, "task_steps": true, "task_step_dependencies": true,
		"task_events": true, "outbox_events": true,
	}
	if !allowed[table] {
		t.Fatalf("test table %q is not allowed", table)
	}
	var got int
	if err := database.pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&got); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	if got != want {
		t.Fatalf("%s rows = %d, want %d", table, got, want)
	}
}

func stepIDByName(t *testing.T, steps []task.Step, name string) string {
	t.Helper()
	for _, step := range steps {
		if step.Name == name {
			return step.StepID
		}
	}
	t.Fatalf("step %q not found in %#v", name, steps)
	return ""
}
