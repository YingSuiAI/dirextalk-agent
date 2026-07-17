package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const suspendStepForSecretsOperation = "task.step.wait_for_service_secrets"

// SuspendStepForSecrets is the durable boundary for a Cloud Goal that needs a
// user secret upload. The current attempt is closed as interrupted (not
// failed), its lease is released, and Task/Step become waiting_user in one
// transaction. The only event reason is the fixed non-sensitive code.
func (store *Store) SuspendStepForSecrets(ctx context.Context, scope task.MutationScope, command task.SuspendStepForSecretsCommand) (task.Attempt, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return task.Attempt{}, err
	}
	if err := command.Validate(); err != nil {
		return task.Attempt{}, err
	}
	if command.AgentInstanceID != store.instanceID.String() {
		return task.Attempt{}, task.ErrInvalid
	}
	taskUUID, err := uuid.Parse(command.TaskID)
	if err != nil {
		return task.Attempt{}, task.ErrInvalid
	}
	return store.mutateAttempt(ctx, caller, suspendStepForSecretsOperation, command.IdempotencyKey, command.Digest(), command.TaskID, func(ctx context.Context, tx pgx.Tx) (task.Attempt, error) {
		currentTask, err := loadTask(ctx, tx, taskUUID, true)
		if err != nil {
			return task.Attempt{}, err
		}
		if currentTask.Revision != command.ExpectedTaskRevision || currentTask.ExecutionStatus != task.ExecutionRunning ||
			currentTask.OutcomeStatus != task.OutcomePending || currentTask.CurrentStepID != command.StepID {
			return task.Attempt{}, task.ErrStaleLease
		}

		attempt, err := lockActiveAttempt(ctx, tx, command.TaskID, command.StepID, command.Attempt, command.LeaseEpoch, command.WorkerID)
		if err != nil {
			return task.Attempt{}, err
		}
		if attempt.Revision != command.ExpectedAttemptRevision {
			return task.Attempt{}, task.ErrStaleLease
		}
		step, err := loadTaskStepForUpdate(ctx, tx, command.TaskID, command.StepID)
		if err != nil {
			return task.Attempt{}, err
		}
		if step.Revision != command.ExpectedStepRevision || step.ExecutionStatus != task.ExecutionRunning ||
			step.OutcomeStatus != task.OutcomePending || step.Attempt != command.Attempt || step.LeaseEpoch != command.LeaseEpoch {
			return task.Attempt{}, task.ErrStaleLease
		}
		if err := validateCloudGoalSecretRequirements(ctx, tx, caller, currentTask, command.Requirements); err != nil {
			return task.Attempt{}, err
		}

		var leaseExpiresAt *time.Time
		if err := tx.QueryRow(ctx, `
			UPDATE task_attempts
			SET execution_status=$6, outcome_status=$7, lease_expires_at=NULL,
			    revision=revision+1, updated_at=clock_timestamp()
			WHERE task_id=$1 AND step_id=$2 AND attempt=$3 AND lease_epoch=$4 AND worker_id=$5
			  AND execution_status=$8 AND outcome_status=$9 AND revision=$10
			RETURNING execution_status, outcome_status, lease_expires_at, revision, updated_at`,
			attempt.TaskID, attempt.StepID, attempt.Attempt, attempt.LeaseEpoch, attempt.WorkerID,
			task.ExecutionFinished, task.OutcomeInterrupted, task.ExecutionRunning, task.OutcomePending, command.ExpectedAttemptRevision,
		).Scan(&attempt.ExecutionStatus, &attempt.OutcomeStatus, &leaseExpiresAt, &attempt.Revision, &attempt.UpdatedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return task.Attempt{}, task.ErrStaleLease
			}
			return task.Attempt{}, fmt.Errorf("release task attempt for user secret wait: %w", err)
		}
		if leaseExpiresAt == nil {
			attempt.LeaseExpiresAt = time.Time{}
		} else {
			attempt.LeaseExpiresAt = leaseExpiresAt.UTC()
		}

		// Register first and then re-read the upload state. If an upload commits
		// between the materializer's lookup and this transition, the Task is
		// immediately re-queued instead of being stranded waiting forever.
		if err := insertCloudGoalSecretWaits(ctx, tx, store.instanceID, caller, currentTask, step, command.Requirements); err != nil {
			return task.Attempt{}, err
		}
		ready, err := allCloudGoalSecretWaitsUploaded(ctx, tx, command.TaskID, command.StepID, command.Attempt, command.LeaseEpoch)
		if err != nil {
			return task.Attempt{}, err
		}
		nextStepStatus, nextTaskStatus := task.ExecutionWaitingUser, task.ExecutionWaitingUser
		if ready {
			nextStepStatus, nextTaskStatus = task.ExecutionQueued, task.ExecutionQueued
			if err := deleteCloudGoalSecretWaits(ctx, tx, command.TaskID, command.StepID, command.Attempt, command.LeaseEpoch); err != nil {
				return task.Attempt{}, err
			}
		}
		if err := tx.QueryRow(ctx, `
			UPDATE task_steps
			SET execution_status=$6, revision=revision+1, updated_at=clock_timestamp()
			WHERE task_id=$1 AND step_id=$2 AND attempt=$3 AND lease_epoch=$4
			  AND execution_status=$5 AND outcome_status=$7 AND revision=$8
			RETURNING execution_status, outcome_status, revision, updated_at`,
			step.TaskID, step.StepID, step.Attempt, step.LeaseEpoch, task.ExecutionRunning, nextStepStatus,
			task.OutcomePending, command.ExpectedStepRevision,
		).Scan(&step.ExecutionStatus, &step.OutcomeStatus, &step.Revision, &step.UpdatedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return task.Attempt{}, task.ErrStaleLease
			}
			return task.Attempt{}, fmt.Errorf("mark task step waiting for user secret: %w", err)
		}
		currentStepID := command.StepID
		if ready {
			currentStepID = ""
		}
		if err := tx.QueryRow(ctx, `
			UPDATE tasks
			SET execution_status=$3, current_step_id=NULLIF($4::text,'')::uuid, revision=revision+1, updated_at=clock_timestamp()
			WHERE task_id=$1 AND revision=$2 AND execution_status=$5 AND outcome_status=$6 AND current_step_id=$7
			RETURNING revision, updated_at`,
			command.TaskID, command.ExpectedTaskRevision, nextTaskStatus, currentStepID,
			task.ExecutionRunning, task.OutcomePending, command.StepID,
		).Scan(&currentTask.Revision, &currentTask.UpdatedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return task.Attempt{}, task.ErrStaleLease
			}
			return task.Attempt{}, fmt.Errorf("mark task waiting for user secret: %w", err)
		}
		currentTask.ExecutionStatus = nextTaskStatus
		currentTask.CurrentStepID = currentStepID
		currentTask = normalizeTaskTimes(currentTask)
		step = normalizeStepTimes(step)
		attempt = normalizeAttemptTimes(attempt)
		attempt.TaskRevision, attempt.StepRevision = currentTask.Revision, step.Revision
		if ready {
			if _, err := appendStepEvent(ctx, tx, step, caller, "agent.step.queued"); err != nil {
				return task.Attempt{}, err
			}
			if _, err := appendTaskEvent(ctx, tx, currentTask, caller, "agent.task.queued", ""); err != nil {
				return task.Attempt{}, err
			}
		} else {
			if _, err := appendStepEvent(ctx, tx, step, caller, "agent.step.waiting_user"); err != nil {
				return task.Attempt{}, err
			}
			if _, err := appendTaskEvent(ctx, tx, currentTask, caller, "agent.task.waiting_user", task.WaitingReasonServiceSecretsNotReady); err != nil {
				return task.Attempt{}, err
			}
		}
		return attempt, nil
	})
}

func loadTaskStepForUpdate(ctx context.Context, tx pgx.Tx, taskID, stepID string) (task.Step, error) {
	var step task.Step
	err := tx.QueryRow(ctx, `
		SELECT step_id, task_id, name, executor_kind, execution_status, outcome_status,
		       attempt, lease_epoch, checkpoint_ref, result_ref, revision, created_at, updated_at
		FROM task_steps WHERE task_id=$1 AND step_id=$2 FOR UPDATE`, taskID, stepID).Scan(
		&step.StepID, &step.TaskID, &step.Name, &step.ExecutorKind, &step.ExecutionStatus, &step.OutcomeStatus,
		&step.Attempt, &step.LeaseEpoch, &step.CheckpointRef, &step.ResultRef, &step.Revision, &step.CreatedAt, &step.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return task.Step{}, task.ErrStepNotFound
	}
	if err != nil {
		return task.Step{}, fmt.Errorf("lock task step: %w", err)
	}
	return normalizeStepTimes(step), nil
}

func validateCloudGoalSecretRequirements(ctx context.Context, tx pgx.Tx, caller idempotencyCaller, currentTask task.Task, requirements []task.SecretWaitRequirement) error {
	var storedClient string
	var storedCredential uuid.UUID
	var ownerID, digest string
	var recipeJSON []byte
	err := tx.QueryRow(ctx, `
		SELECT session.caller_client_id, session.caller_credential_id, session.owner_id, draft.digest, draft.recipe_json
		FROM planning_sessions session
		JOIN planning_recipe_drafts draft ON draft.session_id=session.session_id
		WHERE session.task_id=$1
		FOR UPDATE OF session, draft`, currentTask.TaskID).Scan(&storedClient, &storedCredential, &ownerID, &digest, &recipeJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return task.ErrStaleLease
	}
	if err != nil {
		return fmt.Errorf("lock Cloud Goal secret wait metadata: %w", err)
	}
	if storedClient != caller.ClientID || storedCredential != caller.CredentialID || ownerID != currentTask.OwnerID || currentTask.OwnerID == "" {
		return task.ErrStaleLease
	}
	var persisted recipe.RecipeV1
	if err := json.Unmarshal(recipeJSON, &persisted); err != nil || persisted.Validate() != nil {
		return task.ErrStaleLease
	}
	persistedDigest, err := persisted.Digest()
	if err != nil || persistedDigest != digest {
		return task.ErrStaleLease
	}
	want := make(map[string]string, len(persisted.SecretSlots))
	for _, slot := range persisted.SecretSlots {
		want[slot.Purpose] = digest
	}
	if len(want) == 0 || len(want) != len(requirements) {
		return task.ErrStaleLease
	}
	for _, requirement := range requirements {
		if want[requirement.Purpose] != requirement.RecipeDigest || requirement.RecipeDigest != digest {
			return task.ErrStaleLease
		}
	}
	return nil
}

func insertCloudGoalSecretWaits(ctx context.Context, tx pgx.Tx, instanceID uuid.UUID, caller idempotencyCaller, currentTask task.Task, step task.Step, requirements []task.SecretWaitRequirement) error {
	requirements = append([]task.SecretWaitRequirement(nil), requirements...)
	sort.Slice(requirements, func(i, j int) bool { return requirements[i].Purpose < requirements[j].Purpose })
	for _, requirement := range requirements {
		if _, err := tx.Exec(ctx, `
			INSERT INTO cloud_goal_secret_waits
			    (agent_instance_id, task_id, step_id, attempt, lease_epoch, caller_client_id, caller_credential_id, owner_id, purpose, recipe_digest)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			instanceID, currentTask.TaskID, step.StepID, step.Attempt, step.LeaseEpoch,
			caller.ClientID, caller.CredentialID, currentTask.OwnerID, requirement.Purpose, requirement.RecipeDigest,
		); err != nil {
			return fmt.Errorf("insert Cloud Goal secret wait: %w", err)
		}
	}
	return nil
}

func deleteCloudGoalSecretWaits(ctx context.Context, tx pgx.Tx, taskID, stepID string, attempt int32, leaseEpoch int64) error {
	if _, err := tx.Exec(ctx, `DELETE FROM cloud_goal_secret_waits
		WHERE task_id=$1 AND step_id=$2 AND attempt=$3 AND lease_epoch=$4`, taskID, stepID, attempt, leaseEpoch); err != nil {
		return fmt.Errorf("delete Cloud Goal secret waits: %w", err)
	}
	return nil
}

func allCloudGoalSecretWaitsUploaded(ctx context.Context, tx pgx.Tx, taskID, stepID string, attempt int32, leaseEpoch int64) (bool, error) {
	var missing bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM cloud_goal_secret_waits wait
			WHERE wait.task_id=$1 AND wait.step_id=$2 AND wait.attempt=$3 AND wait.lease_epoch=$4
			  AND (
			      SELECT count(*)
			      FROM secret_bootstrap_sessions session
			      WHERE session.creator_client_id=wait.caller_client_id
			        AND session.agent_instance_id=wait.agent_instance_id
			        AND session.owner_id=wait.owner_id
			        AND session.purpose=wait.purpose
			        AND session.target_id=wait.recipe_digest
			        AND session.status='uploaded'
			        AND session.expires_at>clock_timestamp()
			  ) <> 1
		)`, taskID, stepID, attempt, leaseEpoch).Scan(&missing)
	if err != nil {
		return false, fmt.Errorf("check Cloud Goal secret wait uploads: %w", err)
	}
	return !missing, nil
}

// wakeCloudGoalSecretWaits runs inside SecretBootstrapStore's upload
// transaction. Matching is metadata-only and exact; an unrelated owner,
// caller, recipe digest, purpose, or Agent instance can never resume work.
func wakeCloudGoalSecretWaits(ctx context.Context, tx pgx.Tx, uploaded secretbootstrap.Record, caller idempotencyCaller) error {
	if uploaded.Session.Status != secretbootstrap.StatusUploaded || uploaded.CreatorClientID != caller.ClientID {
		return task.ErrStaleLease
	}
	rows, err := tx.Query(ctx, `
		SELECT task_id::text, step_id::text, attempt, lease_epoch
		FROM cloud_goal_secret_waits
		WHERE agent_instance_id=$1 AND caller_client_id=$2 AND owner_id=$3 AND purpose=$4 AND recipe_digest=$5
		FOR UPDATE`,
		uploaded.Session.AgentInstanceID, uploaded.CreatorClientID, uploaded.Session.OwnerID, uploaded.Session.Purpose, uploaded.Session.TargetID,
	)
	if err != nil {
		return fmt.Errorf("lock matching Cloud Goal secret waits: %w", err)
	}
	type waitKey struct {
		taskID, stepID string
		attempt        int32
		leaseEpoch     int64
	}
	keys := make(map[waitKey]struct{})
	for rows.Next() {
		var key waitKey
		if err := rows.Scan(&key.taskID, &key.stepID, &key.attempt, &key.leaseEpoch); err != nil {
			rows.Close()
			return fmt.Errorf("scan Cloud Goal secret wait: %w", err)
		}
		keys[key] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate Cloud Goal secret waits: %w", err)
	}
	rows.Close()
	ordered := make([]waitKey, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].taskID == ordered[j].taskID {
			return ordered[i].stepID < ordered[j].stepID
		}
		return ordered[i].taskID < ordered[j].taskID
	})
	for _, key := range ordered {
		if err := wakeOneCloudGoalSecretWait(ctx, tx, uploaded, caller, key.taskID, key.stepID, key.attempt, key.leaseEpoch); err != nil {
			return err
		}
	}
	return nil
}

func wakeOneCloudGoalSecretWait(ctx context.Context, tx pgx.Tx, uploaded secretbootstrap.Record, caller idempotencyCaller, taskID, stepID string, attemptNumber int32, leaseEpoch int64) error {
	parsedTask, err := uuid.Parse(taskID)
	if err != nil {
		return task.ErrStaleLease
	}
	current, err := loadTask(ctx, tx, parsedTask, true)
	if err != nil {
		return err
	}
	if current.ExecutionStatus != task.ExecutionWaitingUser || current.OutcomeStatus != task.OutcomePending || current.CurrentStepID != stepID {
		return deleteCloudGoalSecretWaits(ctx, tx, taskID, stepID, attemptNumber, leaseEpoch)
	}
	step, err := loadTaskStepForUpdate(ctx, tx, taskID, stepID)
	if err != nil {
		return err
	}
	if step.ExecutionStatus != task.ExecutionWaitingUser || step.OutcomeStatus != task.OutcomePending || step.Attempt != attemptNumber || step.LeaseEpoch != leaseEpoch {
		return deleteCloudGoalSecretWaits(ctx, tx, taskID, stepID, attemptNumber, leaseEpoch)
	}
	ready, err := allCloudGoalSecretWaitsUploaded(ctx, tx, taskID, stepID, attemptNumber, leaseEpoch)
	if err != nil || !ready {
		return err
	}
	if err := tx.QueryRow(ctx, `
		UPDATE task_steps
		SET execution_status=$5, revision=revision+1, updated_at=clock_timestamp()
		WHERE task_id=$1 AND step_id=$2 AND attempt=$3 AND lease_epoch=$4
		  AND execution_status=$6 AND outcome_status=$7 AND revision=$8
		RETURNING execution_status, outcome_status, revision, updated_at`,
		taskID, stepID, attemptNumber, leaseEpoch, task.ExecutionQueued,
		task.ExecutionWaitingUser, task.OutcomePending, step.Revision,
	).Scan(&step.ExecutionStatus, &step.OutcomeStatus, &step.Revision, &step.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return task.ErrStaleLease
		}
		return fmt.Errorf("queue secret-ready task step: %w", err)
	}
	if err := tx.QueryRow(ctx, `
		UPDATE tasks
		SET execution_status=$3, current_step_id=NULL, revision=revision+1, updated_at=clock_timestamp()
		WHERE task_id=$1 AND revision=$2 AND execution_status=$4 AND outcome_status=$5 AND current_step_id=$6
		RETURNING revision, updated_at`,
		taskID, current.Revision, task.ExecutionQueued, task.ExecutionWaitingUser, task.OutcomePending, stepID,
	).Scan(&current.Revision, &current.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return task.ErrStaleLease
		}
		return fmt.Errorf("queue secret-ready task: %w", err)
	}
	current.ExecutionStatus, current.CurrentStepID = task.ExecutionQueued, ""
	current = normalizeTaskTimes(current)
	step = normalizeStepTimes(step)
	if err := deleteCloudGoalSecretWaits(ctx, tx, taskID, stepID, attemptNumber, leaseEpoch); err != nil {
		return err
	}
	if _, err := appendStepEvent(ctx, tx, step, caller, "agent.step.queued"); err != nil {
		return err
	}
	if _, err := appendTaskEvent(ctx, tx, current, caller, "agent.task.queued", ""); err != nil {
		return err
	}
	return nil
}
