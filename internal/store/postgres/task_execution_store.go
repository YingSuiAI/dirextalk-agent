package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	acquireStepOperation    = "task.step.acquire"
	renewStepOperation      = "task.step.renew"
	checkpointStepOperation = "task.step.checkpoint"
	completeStepOperation   = "task.step.complete"
)

func (store *Store) AcquireReadyStep(ctx context.Context, scope task.MutationScope, command task.AcquireReadyStepCommand) (task.Attempt, bool, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return task.Attempt{}, false, err
	}
	if err := command.Validate(); err != nil {
		return task.Attempt{}, false, err
	}
	taskID, _ := uuid.Parse(command.TaskID)
	requestedStepID, _ := uuid.Parse(command.StepID)
	workerID, _ := uuid.Parse(command.WorkerID)
	digest := command.Digest()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return task.Attempt{}, false, fmt.Errorf("begin acquire ready step: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, _, response, err := claimScopedIdempotency(ctx, tx, caller, acquireStepOperation, command.IdempotencyKey, digest[:], taskID)
	if err != nil {
		return task.Attempt{}, false, err
	}
	if existing {
		attempt, found, err := decodeAcquireStepSnapshot(response)
		if err != nil {
			return task.Attempt{}, false, fmt.Errorf("decode idempotent acquire response: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return task.Attempt{}, false, fmt.Errorf("commit idempotent acquire step: %w", err)
		}
		return attempt, found, nil
	}

	currentTask, err := loadTask(ctx, tx, taskID, true)
	if err != nil {
		return task.Attempt{}, false, err
	}
	if currentTask.ExecutionStatus == task.ExecutionFinished || currentTask.OutcomeStatus != task.OutcomePending {
		return task.Attempt{}, false, task.ErrTerminal
	}

	var step task.Step
	var expiredLease bool
	err = tx.QueryRow(ctx, `
		SELECT s.step_id, s.task_id, s.name, s.executor_kind, s.execution_status, s.outcome_status,
		       s.attempt, s.lease_epoch, s.checkpoint_ref, s.result_ref, s.revision, s.created_at, s.updated_at,
		       (s.execution_status=$4) AS expired_lease
		FROM task_steps s
		LEFT JOIN task_attempts a
		  ON a.task_id=s.task_id AND a.step_id=s.step_id AND a.attempt=s.attempt
		WHERE s.task_id=$1 AND s.executor_kind=$2 AND s.outcome_status=$3 AND s.step_id=$8
		  AND NOT EXISTS (
		      SELECT 1
		      FROM task_step_dependencies d
		      JOIN task_steps dependency
		        ON dependency.task_id=d.task_id AND dependency.step_id=d.depends_on_step_id
		      WHERE d.task_id=s.task_id AND d.step_id=s.step_id
		        AND NOT (dependency.execution_status=$5 AND dependency.outcome_status=$6)
		  )
		  AND (
		      s.execution_status=$7
		      OR (
		          s.execution_status=$4 AND a.execution_status=$4 AND a.outcome_status=$3
		          AND a.lease_expires_at<=clock_timestamp()
		      )
		  )
		ORDER BY s.created_at, s.step_id
		FOR UPDATE OF s SKIP LOCKED
		LIMIT 1`,
		taskID, command.ExecutorKind, task.OutcomePending, task.ExecutionRunning,
		task.ExecutionFinished, task.OutcomeSucceeded, task.ExecutionQueued, requestedStepID,
	).Scan(
		&step.StepID, &step.TaskID, &step.Name, &step.ExecutorKind, &step.ExecutionStatus, &step.OutcomeStatus,
		&step.Attempt, &step.LeaseEpoch, &step.CheckpointRef, &step.ResultRef, &step.Revision, &step.CreatedAt, &step.UpdatedAt,
		&expiredLease,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		snapshot := newAcquireStepSnapshot(false, task.Attempt{})
		if err := setScopedIdempotencyResponse(ctx, tx, caller, acquireStepOperation, command.IdempotencyKey, snapshot); err != nil {
			return task.Attempt{}, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return task.Attempt{}, false, fmt.Errorf("commit empty acquire step: %w", err)
		}
		return task.Attempt{}, false, nil
	}
	if err != nil {
		return task.Attempt{}, false, fmt.Errorf("select ready task step: %w", err)
	}
	step = normalizeStepTimes(step)
	stepID := requestedStepID
	if expiredLease {
		result, err := tx.Exec(ctx, `
			UPDATE task_attempts
			SET execution_status=$5, outcome_status=$6, lease_expires_at=clock_timestamp(),
			    revision=revision+1, updated_at=clock_timestamp()
			WHERE task_id=$1 AND step_id=$2 AND attempt=$3 AND lease_epoch=$4
			  AND execution_status=$7 AND outcome_status=$8 AND lease_expires_at<=clock_timestamp()`,
			taskID, stepID, step.Attempt, step.LeaseEpoch,
			task.ExecutionFinished, task.OutcomeInterrupted, task.ExecutionRunning, task.OutcomePending,
		)
		if err != nil {
			return task.Attempt{}, false, fmt.Errorf("interrupt expired task attempt: %w", err)
		}
		if result.RowsAffected() != 1 {
			return task.Attempt{}, false, task.ErrStaleLease
		}
	}

	newAttempt := step.Attempt + 1
	newEpoch := step.LeaseEpoch + 1
	err = tx.QueryRow(ctx, `
		UPDATE task_steps
		SET execution_status=$4, outcome_status=$5, attempt=$6, lease_epoch=$7,
		    revision=revision+1, updated_at=clock_timestamp()
		WHERE task_id=$1 AND step_id=$2 AND lease_epoch=$3
		RETURNING execution_status, outcome_status, attempt, lease_epoch, revision, updated_at`,
		taskID, stepID, step.LeaseEpoch, task.ExecutionRunning, task.OutcomePending, newAttempt, newEpoch,
	).Scan(&step.ExecutionStatus, &step.OutcomeStatus, &step.Attempt, &step.LeaseEpoch, &step.Revision, &step.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return task.Attempt{}, false, task.ErrStaleLease
	}
	if err != nil {
		return task.Attempt{}, false, fmt.Errorf("lease ready task step: %w", err)
	}
	step = normalizeStepTimes(step)

	leased, err := insertAttempt(ctx, tx, taskID, stepID, workerID, newAttempt, newEpoch, command.LeaseDuration)
	if err != nil {
		return task.Attempt{}, false, err
	}
	if err := tx.QueryRow(ctx, `
		UPDATE tasks
		SET execution_status=$2, outcome_status=$3, current_step_id=$4,
		    revision=revision+1, updated_at=clock_timestamp()
		WHERE task_id=$1 AND outcome_status=$3
		RETURNING revision, updated_at`,
		taskID, task.ExecutionRunning, task.OutcomePending, stepID,
	).Scan(&currentTask.Revision, &currentTask.UpdatedAt); err != nil {
		return task.Attempt{}, false, fmt.Errorf("mark task step running: %w", err)
	}
	currentTask.ExecutionStatus = task.ExecutionRunning
	currentTask.CurrentStepID = step.StepID
	currentTask = normalizeTaskTimes(currentTask)
	if _, err := appendStepEvent(ctx, tx, step, caller, "agent.step.leased"); err != nil {
		return task.Attempt{}, false, err
	}
	if _, err := appendTaskEvent(ctx, tx, currentTask, caller, "agent.task.running", ""); err != nil {
		return task.Attempt{}, false, err
	}
	snapshot := newAcquireStepSnapshot(true, leased)
	if err := setScopedIdempotencyResponse(ctx, tx, caller, acquireStepOperation, command.IdempotencyKey, snapshot); err != nil {
		return task.Attempt{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return task.Attempt{}, false, fmt.Errorf("commit acquire ready step: %w", err)
	}
	return leased, true, nil
}

func (store *Store) RenewStepLease(ctx context.Context, scope task.MutationScope, command task.RenewStepLeaseCommand) (task.Attempt, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return task.Attempt{}, err
	}
	if err := command.Validate(); err != nil {
		return task.Attempt{}, err
	}
	return store.mutateAttempt(ctx, caller, renewStepOperation, command.IdempotencyKey, command.Digest(), command.TaskID, func(ctx context.Context, tx pgx.Tx) (task.Attempt, error) {
		attempt, err := lockActiveAttempt(ctx, tx, command.TaskID, command.StepID, command.Attempt, command.LeaseEpoch, command.WorkerID)
		if err != nil {
			return task.Attempt{}, err
		}
		leaseMicros := command.LeaseDuration.Microseconds()
		if err := tx.QueryRow(ctx, `
			UPDATE task_attempts
			SET lease_expires_at=clock_timestamp() + ($7::bigint * interval '1 microsecond'),
			    revision=revision+1, updated_at=clock_timestamp()
			WHERE task_id=$1 AND step_id=$2 AND attempt=$3 AND lease_epoch=$4 AND worker_id=$5
			  AND execution_status=$6
			RETURNING lease_expires_at, revision, updated_at`,
			attempt.TaskID, attempt.StepID, attempt.Attempt, attempt.LeaseEpoch, attempt.WorkerID,
			task.ExecutionRunning, leaseMicros,
		).Scan(&attempt.LeaseExpiresAt, &attempt.Revision, &attempt.UpdatedAt); err != nil {
			return task.Attempt{}, fmt.Errorf("renew task step lease: %w", err)
		}
		return normalizeAttemptTimes(attempt), nil
	})
}

func (store *Store) CheckpointStep(ctx context.Context, scope task.MutationScope, command task.CheckpointStepCommand) (task.Attempt, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return task.Attempt{}, err
	}
	if err := command.Validate(); err != nil {
		return task.Attempt{}, err
	}
	return store.mutateAttempt(ctx, caller, checkpointStepOperation, command.IdempotencyKey, command.Digest(), command.TaskID, func(ctx context.Context, tx pgx.Tx) (task.Attempt, error) {
		attempt, err := lockActiveAttempt(ctx, tx, command.TaskID, command.StepID, command.Attempt, command.LeaseEpoch, command.WorkerID)
		if err != nil {
			return task.Attempt{}, err
		}
		if err := tx.QueryRow(ctx, `
			UPDATE task_attempts
			SET checkpoint_ref=$6, revision=revision+1, updated_at=clock_timestamp()
			WHERE task_id=$1 AND step_id=$2 AND attempt=$3 AND lease_epoch=$4 AND worker_id=$5
			RETURNING checkpoint_ref, revision, updated_at`,
			attempt.TaskID, attempt.StepID, attempt.Attempt, attempt.LeaseEpoch, attempt.WorkerID, command.CheckpointRef,
		).Scan(&attempt.CheckpointRef, &attempt.Revision, &attempt.UpdatedAt); err != nil {
			return task.Attempt{}, fmt.Errorf("checkpoint task attempt: %w", err)
		}
		attempt = normalizeAttemptTimes(attempt)
		step, err := updateStepCheckpoint(ctx, tx, attempt, command.CheckpointRef)
		if err != nil {
			return task.Attempt{}, err
		}
		if _, err := appendStepEvent(ctx, tx, step, caller, "agent.step.checkpointed"); err != nil {
			return task.Attempt{}, err
		}
		return attempt, nil
	})
}

func (store *Store) CompleteStep(ctx context.Context, scope task.MutationScope, command task.CompleteStepCommand) (task.Attempt, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return task.Attempt{}, err
	}
	if err := command.Validate(); err != nil {
		return task.Attempt{}, err
	}
	return store.mutateAttempt(ctx, caller, completeStepOperation, command.IdempotencyKey, command.Digest(), command.TaskID, func(ctx context.Context, tx pgx.Tx) (task.Attempt, error) {
		attempt, err := lockActiveAttempt(ctx, tx, command.TaskID, command.StepID, command.Attempt, command.LeaseEpoch, command.WorkerID)
		if err != nil {
			return task.Attempt{}, err
		}
		if err := tx.QueryRow(ctx, `
			UPDATE task_attempts
			SET execution_status=$6, outcome_status=$7, result_ref=$8, lease_expires_at=NULL,
			    revision=revision+1, updated_at=clock_timestamp()
			WHERE task_id=$1 AND step_id=$2 AND attempt=$3 AND lease_epoch=$4 AND worker_id=$5
			RETURNING execution_status, outcome_status, result_ref,
			          COALESCE(lease_expires_at, 'epoch'::timestamptz), revision, updated_at`,
			attempt.TaskID, attempt.StepID, attempt.Attempt, attempt.LeaseEpoch, attempt.WorkerID,
			task.ExecutionFinished, command.Outcome, command.ResultRef,
		).Scan(&attempt.ExecutionStatus, &attempt.OutcomeStatus, &attempt.ResultRef, &attempt.LeaseExpiresAt, &attempt.Revision, &attempt.UpdatedAt); err != nil {
			return task.Attempt{}, fmt.Errorf("complete task attempt: %w", err)
		}
		attempt.LeaseExpiresAt = time.Time{}
		attempt = normalizeAttemptTimes(attempt)
		step, err := completeStepProjection(ctx, tx, attempt, command.Outcome, command.ResultRef)
		if err != nil {
			return task.Attempt{}, err
		}
		currentTask, err := finishOrQueueTask(ctx, tx, attempt.TaskID, command.Outcome, caller)
		if err != nil {
			return task.Attempt{}, err
		}
		if _, err := appendStepEvent(ctx, tx, step, caller, "agent.step.completed"); err != nil {
			return task.Attempt{}, err
		}
		if _, err := appendTaskEvent(ctx, tx, currentTask, caller, "agent.task.changed", ""); err != nil {
			return task.Attempt{}, err
		}
		return attempt, nil
	})
}

func (store *Store) mutateAttempt(
	ctx context.Context,
	caller idempotencyCaller,
	operation, key string,
	digest [32]byte,
	rawTaskID string,
	mutation func(context.Context, pgx.Tx) (task.Attempt, error),
) (task.Attempt, error) {
	taskID, _ := uuid.Parse(rawTaskID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return task.Attempt{}, fmt.Errorf("begin %s: %w", operation, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, response, err := claimScopedIdempotency(ctx, tx, caller, operation, key, digest[:], taskID)
	if err != nil {
		return task.Attempt{}, err
	}
	if existing {
		attempt, err := decodeAttemptSnapshot(response)
		if err != nil {
			return task.Attempt{}, fmt.Errorf("decode idempotent %s response: %w", operation, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return task.Attempt{}, fmt.Errorf("commit idempotent %s: %w", operation, err)
		}
		return attempt, nil
	}
	if _, err := loadTask(ctx, tx, taskID, true); err != nil {
		return task.Attempt{}, err
	}
	attempt, err := mutation(ctx, tx)
	if err != nil {
		return task.Attempt{}, err
	}
	if err := setScopedIdempotencyResponse(ctx, tx, caller, operation, key, newAttemptSnapshot(attempt)); err != nil {
		return task.Attempt{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return task.Attempt{}, fmt.Errorf("commit %s: %w", operation, err)
	}
	return attempt, nil
}

func insertAttempt(ctx context.Context, tx pgx.Tx, taskID, stepID, workerID uuid.UUID, attemptNumber int32, leaseEpoch int64, leaseDuration time.Duration) (task.Attempt, error) {
	var attempt task.Attempt
	if err := tx.QueryRow(ctx, `
		INSERT INTO task_attempts
		    (task_id, step_id, attempt, lease_epoch, worker_id, lease_expires_at, execution_status, outcome_status)
		VALUES ($1,$2,$3,$4,$5,clock_timestamp() + ($6::bigint * interval '1 microsecond'),$7,$8)
		RETURNING task_id, step_id, attempt, lease_epoch, worker_id,
		          lease_expires_at, execution_status, outcome_status,
		          checkpoint_ref, result_ref, revision, created_at, updated_at`,
		taskID, stepID, attemptNumber, leaseEpoch, workerID, leaseDuration.Microseconds(),
		task.ExecutionRunning, task.OutcomePending,
	).Scan(
		&attempt.TaskID, &attempt.StepID, &attempt.Attempt, &attempt.LeaseEpoch, &attempt.WorkerID,
		&attempt.LeaseExpiresAt, &attempt.ExecutionStatus, &attempt.OutcomeStatus,
		&attempt.CheckpointRef, &attempt.ResultRef, &attempt.Revision, &attempt.CreatedAt, &attempt.UpdatedAt,
	); err != nil {
		return task.Attempt{}, fmt.Errorf("insert task attempt: %w", err)
	}
	return normalizeAttemptTimes(attempt), nil
}

func lockActiveAttempt(ctx context.Context, tx pgx.Tx, taskID, stepID string, attemptNumber int32, leaseEpoch int64, workerID string) (task.Attempt, error) {
	var attempt task.Attempt
	var active bool
	err := tx.QueryRow(ctx, `
		SELECT task_id, step_id, attempt, lease_epoch, COALESCE(worker_id::text,''),
		       COALESCE(lease_expires_at, 'epoch'::timestamptz), execution_status, outcome_status,
		       checkpoint_ref, result_ref, revision, created_at, updated_at,
		       COALESCE(lease_expires_at>clock_timestamp(), false)
		FROM task_attempts
		WHERE task_id=$1 AND step_id=$2 AND attempt=$3
		FOR UPDATE`, taskID, stepID, attemptNumber).Scan(
		&attempt.TaskID, &attempt.StepID, &attempt.Attempt, &attempt.LeaseEpoch, &attempt.WorkerID,
		&attempt.LeaseExpiresAt, &attempt.ExecutionStatus, &attempt.OutcomeStatus,
		&attempt.CheckpointRef, &attempt.ResultRef, &attempt.Revision, &attempt.CreatedAt, &attempt.UpdatedAt,
		&active,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return task.Attempt{}, task.ErrAttemptNotFound
	}
	if err != nil {
		return task.Attempt{}, fmt.Errorf("lock task attempt: %w", err)
	}
	if attempt.LeaseEpoch != leaseEpoch || attempt.WorkerID != normalizedUUIDString(workerID) || attempt.ExecutionStatus != task.ExecutionRunning || attempt.OutcomeStatus != task.OutcomePending {
		return task.Attempt{}, task.ErrStaleLease
	}
	if !active {
		return task.Attempt{}, task.ErrLeaseExpired
	}
	return normalizeAttemptTimes(attempt), nil
}

func updateStepCheckpoint(ctx context.Context, tx pgx.Tx, attempt task.Attempt, checkpointRef string) (task.Step, error) {
	return updateStepProjection(ctx, tx, attempt, `
		UPDATE task_steps
		SET checkpoint_ref=$6, revision=revision+1, updated_at=clock_timestamp()
		WHERE task_id=$1 AND step_id=$2 AND attempt=$3 AND lease_epoch=$4 AND execution_status=$5
		RETURNING step_id, task_id, name, executor_kind, execution_status, outcome_status,
		          attempt, lease_epoch, checkpoint_ref, result_ref, revision, created_at, updated_at`,
		task.ExecutionRunning, checkpointRef)
}

func completeStepProjection(ctx context.Context, tx pgx.Tx, attempt task.Attempt, outcome task.OutcomeStatus, resultRef string) (task.Step, error) {
	return updateStepProjection(ctx, tx, attempt, `
		UPDATE task_steps
		SET execution_status=$6, outcome_status=$7, result_ref=$8,
		    revision=revision+1, updated_at=clock_timestamp()
		WHERE task_id=$1 AND step_id=$2 AND attempt=$3 AND lease_epoch=$4 AND execution_status=$5
		RETURNING step_id, task_id, name, executor_kind, execution_status, outcome_status,
		          attempt, lease_epoch, checkpoint_ref, result_ref, revision, created_at, updated_at`,
		task.ExecutionRunning, task.ExecutionFinished, outcome, resultRef)
}

func updateStepProjection(ctx context.Context, tx pgx.Tx, attempt task.Attempt, statement string, arguments ...any) (task.Step, error) {
	base := []any{attempt.TaskID, attempt.StepID, attempt.Attempt, attempt.LeaseEpoch}
	base = append(base, arguments...)
	var step task.Step
	err := tx.QueryRow(ctx, statement, base...).Scan(
		&step.StepID, &step.TaskID, &step.Name, &step.ExecutorKind, &step.ExecutionStatus, &step.OutcomeStatus,
		&step.Attempt, &step.LeaseEpoch, &step.CheckpointRef, &step.ResultRef, &step.Revision, &step.CreatedAt, &step.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return task.Step{}, task.ErrStaleLease
	}
	if err != nil {
		return task.Step{}, fmt.Errorf("update task step projection: %w", err)
	}
	return normalizeStepTimes(step), nil
}

func finishOrQueueTask(ctx context.Context, tx pgx.Tx, rawTaskID string, stepOutcome task.OutcomeStatus, caller idempotencyCaller) (task.Task, error) {
	taskID, _ := uuid.Parse(rawTaskID)
	current, err := loadTask(ctx, tx, taskID, true)
	if err != nil {
		return task.Task{}, err
	}
	nextExecution := task.ExecutionFinished
	nextOutcome := stepOutcome
	if stepOutcome == task.OutcomeSucceeded {
		var unfinished bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM task_steps
				WHERE task_id=$1 AND NOT (execution_status=$2 AND outcome_status=$3)
			)`, taskID, task.ExecutionFinished, task.OutcomeSucceeded).Scan(&unfinished); err != nil {
			return task.Task{}, fmt.Errorf("check remaining task steps: %w", err)
		}
		if unfinished {
			nextExecution = task.ExecutionQueued
			nextOutcome = task.OutcomePending
		}
	} else {
		if err := cancelOutstandingSteps(ctx, tx, taskID, caller); err != nil {
			return task.Task{}, err
		}
	}
	if err := tx.QueryRow(ctx, `
		UPDATE tasks
		SET execution_status=$2, outcome_status=$3, current_step_id=NULL,
		    revision=revision+1, updated_at=clock_timestamp()
		WHERE task_id=$1 AND outcome_status=$4
		RETURNING revision, updated_at`,
		taskID, nextExecution, nextOutcome, task.OutcomePending,
	).Scan(&current.Revision, &current.UpdatedAt); errors.Is(err, pgx.ErrNoRows) {
		return task.Task{}, task.ErrTerminal
	} else if err != nil {
		return task.Task{}, fmt.Errorf("advance task after step completion: %w", err)
	}
	current.ExecutionStatus = nextExecution
	current.OutcomeStatus = nextOutcome
	current.CurrentStepID = ""
	return normalizeTaskTimes(current), nil
}

func cancelOutstandingSteps(ctx context.Context, tx pgx.Tx, taskID uuid.UUID, caller idempotencyCaller) error {
	if _, err := tx.Exec(ctx, `
		UPDATE task_attempts
		SET execution_status=$2, outcome_status=$3, lease_epoch=lease_epoch+1,
		    lease_expires_at=clock_timestamp(), revision=revision+1, updated_at=clock_timestamp()
		WHERE task_id=$1 AND execution_status<>$2`,
		taskID, task.ExecutionFinished, task.OutcomeCanceled,
	); err != nil {
		return fmt.Errorf("cancel outstanding task attempts: %w", err)
	}
	rows, err := tx.Query(ctx, `
		UPDATE task_steps
		SET execution_status=$2, outcome_status=$3, lease_epoch=lease_epoch+1,
		    revision=revision+1, updated_at=clock_timestamp()
		WHERE task_id=$1 AND execution_status<>$2
		RETURNING step_id, task_id, name, executor_kind, execution_status, outcome_status,
		          attempt, lease_epoch, checkpoint_ref, result_ref, revision, created_at, updated_at`,
		taskID, task.ExecutionFinished, task.OutcomeCanceled,
	)
	if err != nil {
		return fmt.Errorf("cancel outstanding task steps: %w", err)
	}
	changed := make([]task.Step, 0)
	for rows.Next() {
		var step task.Step
		if err := rows.Scan(
			&step.StepID, &step.TaskID, &step.Name, &step.ExecutorKind, &step.ExecutionStatus, &step.OutcomeStatus,
			&step.Attempt, &step.LeaseEpoch, &step.CheckpointRef, &step.ResultRef, &step.Revision, &step.CreatedAt, &step.UpdatedAt,
		); err != nil {
			rows.Close()
			return fmt.Errorf("scan canceled task step: %w", err)
		}
		changed = append(changed, normalizeStepTimes(step))
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate canceled task steps: %w", err)
	}
	rows.Close()
	for _, step := range changed {
		if _, err := appendStepEvent(ctx, tx, step, caller, "agent.step.canceled"); err != nil {
			return err
		}
	}
	return nil
}

func appendStepEvent(ctx context.Context, tx pgx.Tx, step task.Step, caller idempotencyCaller, eventType string) (task.Event, error) {
	summary, err := json.Marshal(struct {
		SchemaVersion   int                  `json:"schema_version"`
		TaskID          string               `json:"task_id"`
		StepID          string               `json:"step_id"`
		ExecutionStatus task.ExecutionStatus `json:"execution_status"`
		OutcomeStatus   task.OutcomeStatus   `json:"outcome_status"`
		Attempt         int32                `json:"attempt"`
		LeaseEpoch      int64                `json:"lease_epoch"`
		Revision        int64                `json:"revision"`
		UpdatedAt       time.Time            `json:"updated_at"`
		ActorClientID   string               `json:"actor_client_id"`
		ActorCredential string               `json:"actor_credential_id"`
	}{
		snapshotSchemaV1, step.TaskID, step.StepID, step.ExecutionStatus, step.OutcomeStatus,
		step.Attempt, step.LeaseEpoch, step.Revision, step.UpdatedAt.UTC(),
		caller.ClientID, caller.CredentialID.String(),
	})
	if err != nil {
		return task.Event{}, fmt.Errorf("encode step event: %w", err)
	}
	eventID, err := uuid.NewV7()
	if err != nil {
		return task.Event{}, fmt.Errorf("generate step event id: %w", err)
	}
	var event task.Event
	if err := tx.QueryRow(ctx, `
		INSERT INTO task_events (event_id, event_type, aggregate_type, aggregate_id, revision, summary_json)
		VALUES ($1,$2,'step',$3,$4,$5)
		RETURNING seq, event_id, event_type, aggregate_type, aggregate_id, revision, summary_json, occurred_at`,
		eventID, eventType, step.StepID, step.Revision, summary,
	).Scan(&event.Seq, &event.EventID, &event.EventType, &event.AggregateType, &event.AggregateID, &event.Revision, &event.SummaryJSON, &event.OccurredAt); err != nil {
		return task.Event{}, fmt.Errorf("insert step event: %w", err)
	}
	outboxID, err := uuid.NewV7()
	if err != nil {
		return task.Event{}, fmt.Errorf("generate step outbox id: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO outbox_events (outbox_id, event_seq, topic, payload_json)
		VALUES ($1,$2,$3,$4)`, outboxID, event.Seq, eventType, summary); err != nil {
		return task.Event{}, fmt.Errorf("insert step outbox event: %w", err)
	}
	return event, nil
}

func normalizedUUIDString(value string) string {
	parsed, err := uuid.Parse(value)
	if err != nil {
		return value
	}
	return parsed.String()
}
