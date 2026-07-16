package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	cloudGoalStageOutputOperation = "planning.cloud_goal.stage_output"
	cloudGoalStageSnapshotV1      = 1
)

type cloudGoalStageOutputSnapshot struct {
	SchemaVersion int                             `json:"schema_version"`
	Identity      planning.CloudGoalStageIdentity `json:"identity"`
	Output        planning.CloudGoalStageOutput   `json:"output"`
}

var (
	_ planning.CloudGoalStageOutputRepository = (*Store)(nil)
	_ planning.CloudGoalMaterializedFacts     = (*Store)(nil)
)

func (store *Store) GetCloudGoalStageOutput(
	ctx context.Context,
	scope task.MutationScope,
	identity planning.CloudGoalStageIdentity,
	attempt task.Attempt,
) (planning.CloudGoalStageOutput, bool, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return planning.CloudGoalStageOutput{}, false, err
	}
	if identity.Validate() != nil {
		return planning.CloudGoalStageOutput{}, false, planning.ErrCloudGoalOutputInvalid
	}
	if err := validatePersistedCloudGoalAttempt(ctx, store.pool, caller, identity, attempt, false); err != nil {
		return planning.CloudGoalStageOutput{}, false, err
	}
	var requestHash, response []byte
	var aggregateID uuid.UUID
	err = store.pool.QueryRow(ctx, `
		SELECT request_hash, aggregate_id, response_json
		FROM idempotency_records
		WHERE operation=$1 AND caller_client_id=$2 AND caller_credential_id=$3 AND idempotency_key=$4`,
		cloudGoalStageOutputOperation, caller.ClientID, caller.CredentialID, identity.OutputIdempotencyKey,
	).Scan(&requestHash, &aggregateID, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return planning.CloudGoalStageOutput{}, false, nil
	}
	if err != nil {
		return planning.CloudGoalStageOutput{}, false, planning.ErrPersistence
	}
	snapshot, err := decodeCloudGoalStageOutputSnapshot(response)
	if err != nil || snapshot.Identity != identity || aggregateID.String() != identity.StepID {
		return planning.CloudGoalStageOutput{}, false, planning.ErrIdempotencyConflict
	}
	digest := (planning.SaveCloudGoalStageOutputCommand{Identity: snapshot.Identity, Output: snapshot.Output}).Digest()
	if !bytes.Equal(requestHash, digest[:]) {
		return planning.CloudGoalStageOutput{}, false, planning.ErrPersistence
	}
	return snapshot.Output, true, nil
}

func (store *Store) SaveCloudGoalStageOutput(
	ctx context.Context,
	scope task.MutationScope,
	command planning.SaveCloudGoalStageOutputCommand,
) (planning.CloudGoalStageOutput, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return planning.CloudGoalStageOutput{}, err
	}
	if command.Validate() != nil {
		return planning.CloudGoalStageOutput{}, planning.ErrCloudGoalOutputInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return planning.CloudGoalStageOutput{}, planning.ErrPersistence
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := validatePersistedCloudGoalAttempt(ctx, tx, caller, command.Identity, command.Attempt, true); err != nil {
		return planning.CloudGoalStageOutput{}, err
	}

	stepID, _ := uuid.Parse(command.Identity.StepID)
	digest := command.Digest()
	existing, _, response, err := claimScopedIdempotency(
		ctx, tx, caller, cloudGoalStageOutputOperation, command.Identity.OutputIdempotencyKey, digest[:], stepID,
	)
	if err != nil {
		return planning.CloudGoalStageOutput{}, err
	}
	if existing {
		snapshot, err := decodeCloudGoalStageOutputSnapshot(response)
		if err != nil || snapshot.Identity != command.Identity || snapshot.Output != command.Output {
			return planning.CloudGoalStageOutput{}, planning.ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return planning.CloudGoalStageOutput{}, planning.ErrPersistence
		}
		return snapshot.Output, nil
	}
	snapshot := cloudGoalStageOutputSnapshot{SchemaVersion: cloudGoalStageSnapshotV1, Identity: command.Identity, Output: command.Output}
	if err := setScopedIdempotencyResponse(ctx, tx, caller, cloudGoalStageOutputOperation, command.Identity.OutputIdempotencyKey, snapshot); err != nil {
		return planning.CloudGoalStageOutput{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return planning.CloudGoalStageOutput{}, planning.ErrPersistence
	}
	return command.Output, nil
}

func validatePersistedCloudGoalAttempt(
	ctx context.Context,
	query planningQuerier,
	caller idempotencyCaller,
	identity planning.CloudGoalStageIdentity,
	attempt task.Attempt,
	lock bool,
) error {
	if identity.Validate() != nil || identity.ValidateAttempt(attempt) != nil {
		return planning.ErrCloudGoalOutputInvalid
	}
	session, storedCaller, _, err := readResearchByBinding(ctx, query, identity.Binding, lock)
	if err != nil {
		return err
	}
	if storedCaller != caller {
		return planning.ErrScopeMismatch
	}
	if session.Binding != identity.Binding || session.TaskID != identity.TaskID {
		return planning.ErrIdempotencyConflict
	}
	taskID, _ := uuid.Parse(identity.TaskID)
	item, err := loadTask(ctx, query, taskID, lock)
	if err != nil {
		return err
	}
	goalDigest := sha256.Sum256([]byte(strings.TrimSpace(item.Goal)))
	if item.OwnerID != identity.Binding.OwnerID || fmt.Sprintf("%x", goalDigest[:]) != identity.GoalDigest {
		return planning.ErrIdempotencyConflict
	}
	var active bool
	err = query.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1
		    FROM task_steps step
		    JOIN task_attempts attempt
		      ON attempt.task_id=step.task_id AND attempt.step_id=step.step_id
		     AND attempt.attempt=$3 AND attempt.lease_epoch=$4
		    WHERE step.task_id=$1 AND step.step_id=$2 AND step.name=$5
		      AND step.executor_kind=$6 AND step.attempt=$3 AND step.lease_epoch=$4
		      AND step.execution_status=$7 AND step.outcome_status=$8
		      AND attempt.worker_id=$9 AND attempt.execution_status=$7 AND attempt.outcome_status=$8
		      AND attempt.lease_expires_at>clock_timestamp()
		)`, identity.TaskID, identity.StepID, attempt.Attempt, attempt.LeaseEpoch,
		identity.StepName, task.ExecutorControlPlane, task.ExecutionRunning, task.OutcomePending, attempt.WorkerID,
	).Scan(&active)
	if err != nil {
		return planning.ErrPersistence
	}
	if !active {
		return task.ErrStaleLease
	}
	return nil
}

func (store *Store) FindCloudGoalQuote(ctx context.Context, ownerID, quoteID string) (cloudquote.QuoteV1, bool, error) {
	value, err := store.GetQuote(ctx, ownerID, quoteID)
	if errors.Is(err, ErrCloudFactNotFound) {
		return cloudquote.QuoteV1{}, false, nil
	}
	return value, err == nil, err
}

func (store *Store) FindCloudGoalPlan(ctx context.Context, ownerID, planID string) (cloudapproval.PlanV1, bool, error) {
	value, err := store.GetPlan(ctx, ownerID, planID)
	if errors.Is(err, ErrCloudFactNotFound) {
		return cloudapproval.PlanV1{}, false, nil
	}
	return value, err == nil, err
}

func decodeCloudGoalStageOutputSnapshot(encoded []byte) (cloudGoalStageOutputSnapshot, error) {
	var snapshot cloudGoalStageOutputSnapshot
	if err := json.Unmarshal(encoded, &snapshot); err != nil || snapshot.SchemaVersion != cloudGoalStageSnapshotV1 ||
		snapshot.Identity.Validate() != nil || snapshot.Output.ValidateForStage(snapshot.Identity.StepName) != nil {
		return cloudGoalStageOutputSnapshot{}, planning.ErrPersistence
	}
	return snapshot, nil
}
