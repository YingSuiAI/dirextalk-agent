package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	executionV2RunConfirmationDomain = "execution_v2.run"
	executionV2RunCreateOperation    = "execution_v2_run_create"
	executionV2RunRetryOperation     = "execution_v2_run_retry"
	executionV2RunCancelOperation    = "execution_v2_run_cancel"
)

// CoreExecutionV2RunStore is the PostgreSQL transaction owner for generic
// (non Cloud Worker) Execution V2 runs. The ordinary Execution V2 record
// repository cannot compose a real CoreTask and CoreConfirmation atomically;
// this narrow store joins those authorities without creating a shadow
// confirmation record.
type CoreExecutionV2RunStore struct{ store *Store }

func NewCoreExecutionV2RunStore(store *Store) *CoreExecutionV2RunStore {
	return &CoreExecutionV2RunStore{store: store}
}

var (
	_ coreexecutionv2.GenericRunLifecycle          = (*CoreExecutionV2RunStore)(nil)
	_ coreexecutionv2.GenericRunConfirmationReader = (*CoreExecutionV2RunStore)(nil)
)

func (s *CoreExecutionV2RunStore) CreateGenericRun(
	ctx context.Context,
	command coreexecutionv2.GenericRunCreateCommand,
) (coreexecutionv2.GenericRunEnvelope, error) {
	command, err := normalizeGenericRunCreate(command)
	if s == nil || s.store == nil || s.store.pool == nil || ctx == nil || err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "execution-v2-run:create:"+command.Run.ID); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	replayOperation := genericRunCreateReplayOperation(command)
	replayDigest := genericRunCreateDigest(command)
	var storedReplayDigest string
	var storedReplayRaw []byte
	err = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_task_replays
		WHERE operation=$1 AND idempotency_key=$2 FOR UPDATE`, replayOperation, command.Task.Spec.IdempotencyKey).
		Scan(&storedReplayDigest, &storedReplayRaw)
	if err == nil {
		var replay coreexecutionv2.GenericRunEnvelope
		if storedReplayDigest != replayDigest || json.Unmarshal(storedReplayRaw, &replay) != nil ||
			genericRunEnvelopeCreateDigest(replay) != replayDigest {
			return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return coreexecutionv2.GenericRunEnvelope{}, err
		}
		return replay, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}

	var existingOwner string
	err = tx.QueryRow(ctx, `SELECT owner_id FROM core_execution_v2_records WHERE resource_type='run' AND resource_id=$1`, command.Run.ID).Scan(&existingOwner)
	if err == nil {
		_ = existingOwner
		// A valid create commits its stable response replay in this same
		// transaction. A record without that replay is an integrity conflict,
		// never permission to reconstruct a response from mutable current rows.
		return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}

	if err = insertExecutionV2RecordTx(ctx, tx, command.Run, "run_created"); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, mapExecutionV2RunPGError(err)
	}
	if err = insertExecutionV2RecordTx(ctx, tx, command.Stage, "stage_created"); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, mapExecutionV2RunPGError(err)
	}
	if err = insertGenericRunTaskTx(ctx, tx, command.Task); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, mapExecutionV2RunPGError(err)
	}
	binding, _ := command.Confirmation.Binding.Normalize()
	bindingRaw, _ := json.Marshal(binding)
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmations(
		confirmation_id,operation_domain,target_id,target_revision,binding_json,task_id,state,
		consumed_released,revision,created_at,updated_at,expires_at,terminal_code,terminal_note,terminal_reason)
		VALUES($1,$2,$3,$4,$5,$6,'pending',false,1,$7,$7,$8,'','','')`,
		command.Confirmation.ConfirmationID, binding.OperationDomain, binding.TargetID,
		binding.TargetRevision, bindingRaw, command.Task.ID, command.Confirmation.CreatedAt,
		command.Confirmation.ExpiresAt); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, mapExecutionV2RunPGError(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_target_bindings(confirmation_id,binding_json,updated_at) VALUES($1,$2,$3)`,
		command.Confirmation.ConfirmationID, bindingRaw, command.Confirmation.CreatedAt); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, mapExecutionV2RunPGError(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_current_bindings(operation_domain,target_id,target_revision,binding_json,updated_at) VALUES($1,$2,$3,$4,$5)`,
		binding.OperationDomain, binding.TargetID, binding.TargetRevision, bindingRaw, command.Confirmation.CreatedAt); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, mapExecutionV2RunPGError(err)
	}

	envelope, err := s.loadGenericRunEnvelopeTx(ctx, tx, command.Run.OwnerID, command.Run.ID, command.Task.ID, command.Confirmation.ConfirmationID, command.Stage.ID, false)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	replayRaw, err := json.Marshal(envelope)
	if err != nil || len(replayRaw) > coretask.MaxResultBytes {
		return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrInvalid
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_replays(operation,idempotency_key,request_hash,response_json,created_at)
		VALUES($1,$2,$3,$4,$5)`, replayOperation, command.Task.Spec.IdempotencyKey, replayDigest, replayRaw, command.At); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, mapExecutionV2RunPGError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	return envelope, nil
}

func (s *CoreExecutionV2RunStore) BeginGenericRun(ctx context.Context, supplied coretask.Task) (coreexecutionv2.GenericRunEnvelope, error) {
	if s == nil || s.store == nil || s.store.pool == nil || ctx == nil || validateSuppliedGenericRunTask(supplied) != nil {
		return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrInvalid
	}
	payload := supplied.Spec.Payload.ExecutionV2Run
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	defer tx.Rollback(ctx)
	now, err := postgresClockTx(ctx, tx)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	currentTask, err := NewCoreTaskStore(s.store).taskTxLocked(ctx, tx, supplied.ID, false)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, mapGenericRunTaskError(err)
	}
	confirmation, released, err := genericRunConfirmationTx(ctx, tx, payload.ConfirmationID, true)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, mapGenericRunConfirmationError(err)
	}
	run, err := executionV2RecordTx(ctx, tx, payload.OwnerID, "run", payload.RunID, true)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	stage, err := executionV2RecordTx(ctx, tx, payload.OwnerID, "stage", payload.StageID, true)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	if err = validateGenericRunAuthorityTx(ctx, tx, currentTask, confirmation, released, run, stage); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	if genericRunTerminal(run.Status) || genericRunTerminal(stage.Status) || genericRunTaskTerminal(currentTask.Status) {
		if run.Status != stage.Status || !genericRunTerminal(run.Status) || !genericRunTaskTerminal(currentTask.Status) ||
			currentTask.Attempt != supplied.Attempt || currentTask.LeaseEpoch != supplied.LeaseEpoch ||
			!sameGenericRunTaskSpec(currentTask.Spec, supplied.Spec) {
			return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return coreexecutionv2.GenericRunEnvelope{}, err
		}
		return coreexecutionv2.GenericRunEnvelope{Run: run, Stage: stage, Task: currentTask, Confirmation: confirmation}, nil
	}
	if !sameActiveGenericRunFence(currentTask, supplied, now) {
		return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
	}

	switch confirmation.State {
	case coreconfirmation.StateConfirmed:
		if released {
			return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
		}
		if !confirmation.ExpiresAt.After(now) {
			confirmation, err = terminalizeExpiredTx(ctx, tx, s.store.instanceID, confirmation, now, coreconfirmation.ReasonExpired)
			if err != nil {
				return coreexecutionv2.GenericRunEnvelope{}, mapGenericRunConfirmationError(err)
			}
			run, err = executionV2RecordTx(ctx, tx, payload.OwnerID, "run", payload.RunID, false)
			if err != nil {
				return coreexecutionv2.GenericRunEnvelope{}, err
			}
			stage, err = executionV2RecordTx(ctx, tx, payload.OwnerID, "stage", payload.StageID, false)
			if err != nil {
				return coreexecutionv2.GenericRunEnvelope{}, err
			}
			currentTask, err = NewCoreTaskStore(s.store).taskTx(ctx, tx, supplied.ID, false)
			if err != nil {
				return coreexecutionv2.GenericRunEnvelope{}, err
			}
			if err = tx.Commit(ctx); err != nil {
				return coreexecutionv2.GenericRunEnvelope{}, err
			}
			return coreexecutionv2.GenericRunEnvelope{Run: run, Stage: stage, Task: currentTask, Confirmation: confirmation}, nil
		}
		if run.Status != "queued" || stage.Status != "queued" {
			return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
		}
		updated, updateErr := tx.Exec(ctx, `UPDATE core_confirmations SET state='consumed',revision=revision+1,updated_at=$2
			WHERE confirmation_id=$1 AND state='confirmed' AND consumed_released=false AND revision=$3`, confirmation.ConfirmationID, now, confirmation.Revision)
		if updateErr != nil || updated.RowsAffected() != 1 {
			if updateErr != nil {
				return coreexecutionv2.GenericRunEnvelope{}, updateErr
			}
			return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
		}
		if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_reservations(
			confirmation_id,task_id,acquired_attempt,acquired_lease_epoch,task_revision,acquired_lease_expires_at,active)
			VALUES($1,$2,$3,$4,$5,$6,true)`, confirmation.ConfirmationID, currentTask.ID,
			currentTask.Attempt, currentTask.LeaseEpoch, currentTask.Revision, currentTask.Lease.ExpiresAt); err != nil {
			return coreexecutionv2.GenericRunEnvelope{}, mapExecutionV2RunPGError(err)
		}
		confirmation.State = coreconfirmation.StateConsumed
		confirmation.Revision++
		confirmation.UpdatedAt = now
		run, stage, err = projectGenericRunRecordsTx(ctx, tx, run, stage, "running", nil, nil, now)
		if err != nil {
			return coreexecutionv2.GenericRunEnvelope{}, err
		}
	case coreconfirmation.StateConsumed:
		if released {
			return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
		}
		var reservationTask string
		var attempt int
		var epoch, revision int64
		var active bool
		if err = tx.QueryRow(ctx, `SELECT task_id::text,acquired_attempt,acquired_lease_epoch,task_revision,active
			FROM core_confirmation_reservations WHERE confirmation_id=$1 FOR UPDATE`, confirmation.ConfirmationID).
			Scan(&reservationTask, &attempt, &epoch, &revision, &active); err != nil {
			return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
		}
		if !active || reservationTask != currentTask.ID || attempt != int(currentTask.Attempt) ||
			epoch > int64(currentTask.LeaseEpoch) || revision > int64(currentTask.Revision) {
			return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
		}
		if epoch != int64(currentTask.LeaseEpoch) || revision != int64(currentTask.Revision) {
			updated, updateErr := tx.Exec(ctx, `UPDATE core_confirmation_reservations SET
				acquired_attempt=$2,acquired_lease_epoch=$3,task_revision=$4,acquired_lease_expires_at=$5,active=true
				WHERE confirmation_id=$1 AND active=true AND acquired_attempt=$6 AND acquired_lease_epoch=$7 AND task_revision=$8`,
				confirmation.ConfirmationID, currentTask.Attempt, currentTask.LeaseEpoch, currentTask.Revision,
				currentTask.Lease.ExpiresAt, attempt, epoch, revision)
			if updateErr != nil || updated.RowsAffected() != 1 {
				if updateErr != nil {
					return coreexecutionv2.GenericRunEnvelope{}, updateErr
				}
				return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
			}
		}
	default:
		return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	return coreexecutionv2.GenericRunEnvelope{Run: run, Stage: stage, Task: currentTask, Confirmation: confirmation}, nil
}

func (s *CoreExecutionV2RunStore) ProjectGenericRun(
	ctx context.Context,
	command coreexecutionv2.GenericRunProjectCommand,
) (coreexecutionv2.GenericRunEnvelope, error) {
	command.At = command.At.UTC().Truncate(time.Microsecond)
	if s == nil || s.store == nil || s.store.pool == nil || ctx == nil || validateGenericRunProject(command) != nil {
		return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrInvalid
	}
	payload := command.Task.Spec.Payload.ExecutionV2Run
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	defer tx.Rollback(ctx)
	currentTask, err := NewCoreTaskStore(s.store).taskTxLocked(ctx, tx, command.Task.ID, false)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, mapGenericRunTaskError(err)
	}
	confirmation, released, err := genericRunConfirmationTx(ctx, tx, payload.ConfirmationID, true)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, mapGenericRunConfirmationError(err)
	}
	run, err := executionV2RecordTx(ctx, tx, payload.OwnerID, "run", payload.RunID, true)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	stage, err := executionV2RecordTx(ctx, tx, payload.OwnerID, "stage", payload.StageID, true)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	if err = validateGenericRunAuthorityTx(ctx, tx, currentTask, confirmation, released, run, stage); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}

	expectedRun, expectedStage, err := genericRunProjectedRecords(run, stage, command.Status, command.RunPayload, command.StagePayload, command.At, command.ExpectedRunRevision+1, command.ExpectedStageRevision+1)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	// A committed projection may have lost its response. Exact record content,
	// the one-revision advance and the terminal task fence make this a replay;
	// a merely similar status is never sufficient.
	if run.Revision == command.ExpectedRunRevision+1 && stage.Revision == command.ExpectedStageRevision+1 &&
		sameExecutionV2Record(run, expectedRun) && sameExecutionV2Record(stage, expectedStage) {
		if genericRunTerminal(command.Status) {
			if !genericRunTaskTerminal(currentTask.Status) || confirmation.State != coreconfirmation.StateConsumed || !released {
				return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
			}
		} else if !sameActiveGenericRunFence(currentTask, command.Task, command.At) ||
			confirmation.State != coreconfirmation.StateConsumed || released {
			return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return coreexecutionv2.GenericRunEnvelope{}, err
		}
		return coreexecutionv2.GenericRunEnvelope{Run: run, Stage: stage, Task: currentTask, Confirmation: confirmation}, nil
	}
	if run.Revision != command.ExpectedRunRevision || stage.Revision != command.ExpectedStageRevision ||
		genericRunTerminal(run.Status) || genericRunTerminal(stage.Status) ||
		confirmation.State != coreconfirmation.StateConsumed || released ||
		!sameActiveGenericRunFence(currentTask, command.Task, command.At) {
		return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
	}
	if err = validateGenericRunReservationTx(ctx, tx, confirmation.ConfirmationID, currentTask); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}

	run, err = updateExecutionV2RecordTx(ctx, tx, expectedRun, command.ExpectedRunRevision, "run_status_"+command.Status)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	stage, err = updateExecutionV2RecordTx(ctx, tx, expectedStage, command.ExpectedStageRevision, "stage_status_"+command.Status)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	if !genericRunTerminal(command.Status) {
		if err = tx.Commit(ctx); err != nil {
			return coreexecutionv2.GenericRunEnvelope{}, err
		}
		return coreexecutionv2.GenericRunEnvelope{Run: run, Stage: stage, Task: currentTask, Confirmation: confirmation}, nil
	}

	taskStatus, failureCode, failureSummary, resultRaw, err := genericRunTerminalTaskProjection(command)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	updated, updateErr := tx.Exec(ctx, `UPDATE core_tasks SET status=$2,result_json=$3,failure_code=$4,failure_summary=$5,
		lease_holder='',lease_expires_at=NULL,revision=revision+1,progress_sequence=progress_sequence+1,updated_at=$6
		WHERE task_id=$1 AND status='running' AND attempt=$7 AND lease_epoch=$8 AND revision=$9 AND lease_expires_at>$6`,
		currentTask.ID, taskStatus, resultRaw, failureCode, failureSummary, command.At,
		currentTask.Attempt, currentTask.LeaseEpoch, currentTask.Revision)
	if updateErr != nil || updated.RowsAffected() != 1 {
		if updateErr != nil {
			return coreexecutionv2.GenericRunEnvelope{}, updateErr
		}
		return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
	}
	if err = insertGenericRunTaskTerminalEventTx(ctx, tx, currentTask.ID, taskStatus, failureCode, failureSummary, resultRaw, command.At); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	if err = decrementGenericRunConcurrencyTx(ctx, tx, command.At); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	reservationUpdate, updateErr := tx.Exec(ctx, `UPDATE core_confirmation_reservations SET active=false
		WHERE confirmation_id=$1 AND task_id=$2 AND acquired_attempt=$3 AND acquired_lease_epoch=$4 AND task_revision=$5 AND active=true`,
		confirmation.ConfirmationID, currentTask.ID, currentTask.Attempt, currentTask.LeaseEpoch, currentTask.Revision)
	if updateErr != nil || reservationUpdate.RowsAffected() != 1 {
		if updateErr != nil {
			return coreexecutionv2.GenericRunEnvelope{}, updateErr
		}
		return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
	}
	confirmationUpdate, updateErr := tx.Exec(ctx, `UPDATE core_confirmations SET consumed_released=true,revision=revision+1,updated_at=$2
		WHERE confirmation_id=$1 AND state='consumed' AND consumed_released=false AND revision=$3`,
		confirmation.ConfirmationID, command.At, confirmation.Revision)
	if updateErr != nil || confirmationUpdate.RowsAffected() != 1 {
		if updateErr != nil {
			return coreexecutionv2.GenericRunEnvelope{}, updateErr
		}
		return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
	}
	currentTask, err = NewCoreTaskStore(s.store).taskTx(ctx, tx, currentTask.ID, false)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	confirmation, _, err = genericRunConfirmationTx(ctx, tx, confirmation.ConfirmationID, false)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	return coreexecutionv2.GenericRunEnvelope{Run: run, Stage: stage, Task: currentTask, Confirmation: confirmation}, nil
}

func (s *CoreExecutionV2RunStore) CancelGenericRun(
	ctx context.Context,
	command coreexecutionv2.GenericRunCancelCommand,
) (coreexecutionv2.GenericRunEnvelope, error) {
	command.Authority.OwnerID = strings.TrimSpace(command.Authority.OwnerID)
	command.RunID = strings.TrimSpace(command.RunID)
	command.IdempotencyKey = strings.TrimSpace(command.IdempotencyKey)
	command.At = command.At.UTC().Truncate(time.Microsecond)
	if s == nil || s.store == nil || s.store.pool == nil || ctx == nil || command.Authority.OwnerID == "" ||
		command.Authority.AccountGeneration == 0 || !coretask.ValidUUID(command.RunID) ||
		command.ExpectedRevision == 0 || !coretask.ValidUUID(command.IdempotencyKey) || command.At.IsZero() {
		return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrInvalid
	}
	requestDigest := genericRunCancelDigest(command)
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "execution-v2-run:cancel:"+command.IdempotencyKey); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	var replayDigest string
	var replayRaw []byte
	err = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_task_replays WHERE operation=$1 AND idempotency_key=$2 FOR UPDATE`,
		executionV2RunCancelOperation, command.IdempotencyKey).Scan(&replayDigest, &replayRaw)
	if err == nil {
		if replayDigest != requestDigest {
			return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
		}
		var replay coreexecutionv2.GenericRunEnvelope
		if json.Unmarshal(replayRaw, &replay) != nil || replay.Run.OwnerID != command.Authority.OwnerID || replay.Run.ID != command.RunID {
			return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return coreexecutionv2.GenericRunEnvelope{}, err
		}
		return replay, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}

	// Resolve immutable IDs before locking, then use the common Task ->
	// Confirmation -> run/stage lock order used by Begin and Project.
	probe, err := executionV2RecordTx(ctx, tx, command.Authority.OwnerID, "run", command.RunID, false)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	taskID, confirmationID, stageID := genericRunRecordIDs(probe)
	if !coretask.ValidUUID(taskID) || !coretask.ValidUUID(confirmationID) || !coretask.ValidUUID(stageID) {
		return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
	}
	currentTask, err := NewCoreTaskStore(s.store).taskTxLocked(ctx, tx, taskID, false)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, mapGenericRunTaskError(err)
	}
	confirmation, released, err := genericRunConfirmationTx(ctx, tx, confirmationID, true)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, mapGenericRunConfirmationError(err)
	}
	run, err := executionV2RecordTx(ctx, tx, command.Authority.OwnerID, "run", command.RunID, true)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	stage, err := executionV2RecordTx(ctx, tx, command.Authority.OwnerID, "stage", stageID, true)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	if err = validateGenericRunAuthorityTx(ctx, tx, currentTask, confirmation, released, run, stage); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	payload := currentTask.Spec.Payload.ExecutionV2Run
	if payload.AccountGeneration != command.Authority.AccountGeneration {
		return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
	}
	if run.Revision != command.ExpectedRevision {
		return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
	}
	if genericRunTerminal(run.Status) || genericRunTerminal(stage.Status) || genericRunTaskTerminal(currentTask.Status) {
		if run.Status != "canceled" || stage.Status != "canceled" || currentTask.Status != coretask.StatusCanceled {
			return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
		}
	} else {
		wasRunning := currentTask.Status == coretask.StatusRunning
		switch confirmation.State {
		case coreconfirmation.StatePending, coreconfirmation.StateConfirmed:
			if released || (currentTask.Status != coretask.StatusWaitingUser && currentTask.Status != coretask.StatusQueued && currentTask.Status != coretask.StatusRunning) {
				return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
			}
			confirmationUpdate, updateErr := tx.Exec(ctx, `UPDATE core_confirmations SET state='expired',revision=revision+1,
				updated_at=$2,terminal_code='user_canceled',terminal_reason='user_canceled',terminal_note='Execution V2 run canceled'
				WHERE confirmation_id=$1 AND state=$3 AND consumed_released=false AND revision=$4`,
				confirmation.ConfirmationID, command.At, confirmation.State, confirmation.Revision)
			if updateErr != nil || confirmationUpdate.RowsAffected() != 1 {
				if updateErr != nil {
					return coreexecutionv2.GenericRunEnvelope{}, updateErr
				}
				return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
			}
		case coreconfirmation.StateConsumed:
			if released || currentTask.Status != coretask.StatusRunning || validateGenericRunReservationTx(ctx, tx, confirmation.ConfirmationID, currentTask) != nil {
				return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
			}
			reservationUpdate, updateErr := tx.Exec(ctx, `UPDATE core_confirmation_reservations SET active=false
				WHERE confirmation_id=$1 AND task_id=$2 AND acquired_attempt=$3 AND acquired_lease_epoch=$4 AND task_revision=$5 AND active=true`,
				confirmation.ConfirmationID, currentTask.ID, currentTask.Attempt, currentTask.LeaseEpoch, currentTask.Revision)
			if updateErr != nil || reservationUpdate.RowsAffected() != 1 {
				if updateErr != nil {
					return coreexecutionv2.GenericRunEnvelope{}, updateErr
				}
				return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
			}
			confirmationUpdate, updateErr := tx.Exec(ctx, `UPDATE core_confirmations SET consumed_released=true,revision=revision+1,updated_at=$2
				WHERE confirmation_id=$1 AND state='consumed' AND consumed_released=false AND revision=$3`,
				confirmation.ConfirmationID, command.At, confirmation.Revision)
			if updateErr != nil || confirmationUpdate.RowsAffected() != 1 {
				if updateErr != nil {
					return coreexecutionv2.GenericRunEnvelope{}, updateErr
				}
				return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
			}
		default:
			return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
		}
		taskUpdate, updateErr := tx.Exec(ctx, `UPDATE core_tasks SET status='canceled',attempt=GREATEST(attempt,1),
			failure_code='user_canceled',failure_summary='Execution V2 run canceled',lease_holder='',lease_expires_at=NULL,
			revision=revision+1,progress_sequence=progress_sequence+1,updated_at=$2
			WHERE task_id=$1 AND status=$3 AND revision=$4`, currentTask.ID, command.At, currentTask.Status, currentTask.Revision)
		if updateErr != nil || taskUpdate.RowsAffected() != 1 {
			if updateErr != nil {
				return coreexecutionv2.GenericRunEnvelope{}, updateErr
			}
			return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrConflict
		}
		if err = insertGenericRunTaskTerminalEventTx(ctx, tx, currentTask.ID, "canceled", "user_canceled", "Execution V2 run canceled", nil, command.At); err != nil {
			return coreexecutionv2.GenericRunEnvelope{}, err
		}
		if wasRunning {
			if err = decrementGenericRunConcurrencyTx(ctx, tx, command.At); err != nil {
				return coreexecutionv2.GenericRunEnvelope{}, err
			}
		}
		run, stage, err = projectGenericRunRecordsTx(ctx, tx, run, stage, "canceled", nil, nil, command.At)
		if err != nil {
			return coreexecutionv2.GenericRunEnvelope{}, err
		}
		currentTask, err = NewCoreTaskStore(s.store).taskTx(ctx, tx, currentTask.ID, false)
		if err != nil {
			return coreexecutionv2.GenericRunEnvelope{}, err
		}
		confirmation, _, err = genericRunConfirmationTx(ctx, tx, confirmation.ConfirmationID, false)
		if err != nil {
			return coreexecutionv2.GenericRunEnvelope{}, err
		}
	}
	envelope := coreexecutionv2.GenericRunEnvelope{Run: run, Stage: stage, Task: currentTask, Confirmation: confirmation}
	replayRaw, err = json.Marshal(envelope)
	if err != nil || len(replayRaw) > coretask.MaxResultBytes {
		return coreexecutionv2.GenericRunEnvelope{}, coreexecutionv2.ErrInvalid
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_replays(operation,idempotency_key,request_hash,response_json,created_at)
		VALUES($1,$2,$3,$4,$5)`, executionV2RunCancelOperation, command.IdempotencyKey, requestDigest, replayRaw, command.At); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, mapExecutionV2RunPGError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	return envelope, nil
}

func (s *CoreExecutionV2RunStore) ReadGenericRunConfirmation(ctx context.Context, owner, confirmationID string) (coreconfirmation.Confirmation, error) {
	owner, confirmationID = strings.TrimSpace(owner), strings.TrimSpace(confirmationID)
	if s == nil || s.store == nil || s.store.pool == nil || ctx == nil || owner == "" || !coretask.ValidUUID(confirmationID) {
		return coreconfirmation.Confirmation{}, coreexecutionv2.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return coreconfirmation.Confirmation{}, err
	}
	defer tx.Rollback(ctx)
	confirmation, released, err := genericRunConfirmationTx(ctx, tx, confirmationID, false)
	if err != nil {
		return coreconfirmation.Confirmation{}, mapGenericRunConfirmationError(err)
	}
	if confirmation.OwnerID != owner || confirmation.Binding.OwnerID != owner ||
		confirmation.Binding.OperationDomain != executionV2RunConfirmationDomain ||
		confirmation.Binding.AccountGeneration == 0 || !coretask.ValidUUID(confirmation.Binding.TargetID) {
		return coreconfirmation.Confirmation{}, coreexecutionv2.ErrNotFound
	}
	var taskKind string
	var payloadRaw []byte
	if err = tx.QueryRow(ctx, `SELECT task_kind,payload_json FROM core_tasks WHERE task_id=$1 AND deleted_at IS NULL`, confirmation.TaskID).Scan(&taskKind, &payloadRaw); err != nil {
		return coreconfirmation.Confirmation{}, coreexecutionv2.ErrNotFound
	}
	var payload coretask.TaskPayload
	if taskKind != string(coretask.TaskKindExecutionV2Run) || json.Unmarshal(payloadRaw, &payload) != nil || payload.ExecutionV2Run == nil ||
		payload.ExecutionV2Run.OwnerID != owner || payload.ExecutionV2Run.AccountGeneration != confirmation.Binding.AccountGeneration ||
		payload.ExecutionV2Run.RunID != confirmation.Binding.TargetID || payload.ExecutionV2Run.ConfirmationID != confirmationID {
		return coreconfirmation.Confirmation{}, coreexecutionv2.ErrConflict
	}
	run, err := executionV2RecordTx(ctx, tx, owner, "run", payload.ExecutionV2Run.RunID, false)
	if err != nil || stringValue(run.Payload, "confirmation_id") != confirmationID || stringValue(run.Payload, "task_id") != confirmation.TaskID {
		return coreconfirmation.Confirmation{}, coreexecutionv2.ErrConflict
	}
	if err = validateGenericRunBindingsTx(ctx, tx, confirmation, false); err != nil {
		return coreconfirmation.Confirmation{}, err
	}
	if confirmation.State != coreconfirmation.StateConsumed && released {
		return coreconfirmation.Confirmation{}, coreexecutionv2.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		return coreconfirmation.Confirmation{}, err
	}
	return confirmation, nil
}

func normalizeGenericRunCreate(command coreexecutionv2.GenericRunCreateCommand) (coreexecutionv2.GenericRunCreateCommand, error) {
	if command.At.IsZero() || command.At.Location() != time.UTC || command.Task.Validate() != nil ||
		command.Task.Status != coretask.StatusWaitingUser || command.Task.Attempt != 1 || command.Task.Lease != nil ||
		command.Task.Revision != 1 || command.Task.ProgressSequence != 1 || command.Task.Spec.Kind != coretask.TaskKindExecutionV2Run ||
		command.Task.Spec.Payload.ExecutionV2Run == nil || command.Run.Kind != "run" || command.Stage.Kind != "stage" ||
		command.Run.Revision != 1 || command.Stage.Revision != 1 || command.Run.Status != "waiting_user" ||
		command.Stage.Status != "waiting_user" || command.Run.OwnerID == "" || command.Stage.OwnerID != command.Run.OwnerID ||
		!coretask.ValidUUID(command.Run.ID) || !coretask.ValidUUID(command.Stage.ID) || !coretask.ValidUUID(command.Task.ID) {
		return command, coreexecutionv2.ErrInvalid
	}
	payload := command.Task.Spec.Payload.ExecutionV2Run
	if payload.OwnerID != command.Run.OwnerID || payload.RunID != command.Run.ID || payload.StageID != command.Stage.ID ||
		payload.AccountGeneration == 0 || payload.PlanRevision == 0 || !coretask.ValidDigest(payload.PlanDigest) ||
		payload.ConfirmationID != command.Confirmation.ConfirmationID || command.Confirmation.TaskID != command.Task.ID ||
		command.Confirmation.OwnerID != payload.OwnerID || command.Confirmation.State != coreconfirmation.StatePending ||
		command.Confirmation.Revision != 1 || !command.Confirmation.ExpiresAt.After(command.At) ||
		command.Confirmation.TerminalCode != "" || command.Confirmation.TerminalNote != "" || command.Confirmation.TerminalReason != "" {
		return command, coreexecutionv2.ErrInvalid
	}
	binding, err := command.Confirmation.Binding.Normalize()
	if err != nil || binding.OwnerID != payload.OwnerID || binding.AccountGeneration != payload.AccountGeneration ||
		binding.OperationDomain != executionV2RunConfirmationDomain || binding.TargetID != payload.RunID ||
		binding.TargetRevision != 1 || binding.TargetKind != "execution_v2_run" ||
		string(binding.ContentDigest) != payload.PlanDigest {
		return command, coreexecutionv2.ErrInvalid
	}
	if !genericRunRecordLinks(command.Run, command.Stage, command.Task, command.Confirmation) {
		return command, coreexecutionv2.ErrInvalid
	}
	if executionV2PayloadDigest(command.Run.Payload) != command.Run.Digest ||
		executionV2PayloadDigest(command.Stage.Payload) != command.Stage.Digest {
		return command, coreexecutionv2.ErrInvalid
	}
	at := command.At.UTC().Truncate(time.Microsecond)
	if !sameInstantWithinPostgres(command.Run.CreatedAt, command.At) || !sameInstantWithinPostgres(command.Run.UpdatedAt, command.At) ||
		!sameInstantWithinPostgres(command.Stage.CreatedAt, command.At) || !sameInstantWithinPostgres(command.Stage.UpdatedAt, command.At) ||
		!sameInstantWithinPostgres(command.Task.CreatedAt, command.At) || !sameInstantWithinPostgres(command.Task.UpdatedAt, command.At) ||
		!sameInstantWithinPostgres(command.Task.AvailableAt, command.At) ||
		!sameInstantWithinPostgres(command.Confirmation.CreatedAt, command.At) || !sameInstantWithinPostgres(command.Confirmation.UpdatedAt, command.At) {
		return command, coreexecutionv2.ErrInvalid
	}
	command.At = at
	command.Run.CreatedAt, command.Run.UpdatedAt = at, at
	command.Stage.CreatedAt, command.Stage.UpdatedAt = at, at
	command.Task.CreatedAt, command.Task.UpdatedAt, command.Task.AvailableAt = at, at, at
	command.Task.Spec.AvailableAt = at
	command.Confirmation.Binding = binding
	command.Confirmation.CreatedAt, command.Confirmation.UpdatedAt = at, at
	command.Confirmation.ExpiresAt = command.Confirmation.ExpiresAt.UTC().Truncate(time.Microsecond)
	command.Run.Payload = cloneExecutionV2Payload(command.Run.Payload)
	command.Stage.Payload = cloneExecutionV2Payload(command.Stage.Payload)
	return command, nil
}

func validateSuppliedGenericRunTask(task coretask.Task) error {
	if task.Validate() != nil || task.Status != coretask.StatusRunning || task.Spec.Kind != coretask.TaskKindExecutionV2Run ||
		task.Spec.Payload.ExecutionV2Run == nil || task.Lease == nil || task.Attempt == 0 || task.LeaseEpoch == 0 ||
		task.Lease.TaskID != task.ID || task.Lease.Attempt != task.Attempt || task.Lease.Epoch != task.LeaseEpoch {
		return coreexecutionv2.ErrInvalid
	}
	return nil
}

func validateGenericRunProject(command coreexecutionv2.GenericRunProjectCommand) error {
	if validateSuppliedGenericRunTask(command.Task) != nil || command.ExpectedRunRevision == 0 ||
		command.ExpectedStageRevision == 0 || command.At.IsZero() || command.At.Location() != time.UTC ||
		command.RunPayload == nil || command.StagePayload == nil || !genericRunProjectStatus(command.Status) ||
		command.Result.Validate() != nil {
		return coreexecutionv2.ErrInvalid
	}
	if genericRunTerminal(command.Status) {
		switch command.Status {
		case "succeeded":
			if command.FailureCode != "" || command.FailureSummary != "" {
				return coreexecutionv2.ErrInvalid
			}
		case "failed", "expired":
			if strings.TrimSpace(command.FailureCode) == "" || strings.TrimSpace(command.FailureSummary) == "" {
				return coreexecutionv2.ErrInvalid
			}
		case "canceled", "rejected":
			if strings.TrimSpace(command.FailureSummary) == "" {
				return coreexecutionv2.ErrInvalid
			}
		}
	} else if command.FailureCode != "" || command.FailureSummary != "" {
		return coreexecutionv2.ErrInvalid
	}
	for _, value := range []map[string]any{command.RunPayload, command.StagePayload} {
		raw, err := json.Marshal(value)
		if err != nil || len(raw) == 0 || len(raw) > 4<<20 {
			return coreexecutionv2.ErrInvalid
		}
	}
	return nil
}

func insertGenericRunTaskTx(ctx context.Context, tx pgx.Tx, task coretask.Task) error {
	payloadRaw, _ := json.Marshal(task.Spec.Payload)
	emptyArray := []byte(`[]`)
	result, err := tx.Exec(ctx, `INSERT INTO core_tasks(
		task_id,goal,conversation_id,model_profile_id,create_idempotency_key,attachment_refs,extensions_json,knowledge_refs,
		timeout_seconds,status,attempt,progress_sequence,lease_epoch,lease_holder,available_at,revision,created_at,updated_at,
		task_kind,payload_json)
		VALUES($1,$2,NULL,NULL,$3,$4,$4,$4,$5,'waiting_user',1,1,0,'',$6,1,$7,$7,'execution_v2_run',$8)`,
		task.ID, task.Spec.Goal, task.Spec.IdempotencyKey, emptyArray, task.Spec.TimeoutSeconds,
		task.AvailableAt, task.CreatedAt, payloadRaw)
	if err != nil || result.RowsAffected() != 1 {
		if err != nil {
			return err
		}
		return coreexecutionv2.ErrConflict
	}
	result, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at)
		VALUES($1,1,$2,1,'waiting_user','confirmation','waiting for owner confirmation',$3)`,
		task.ID, uuid.New(), task.CreatedAt)
	if err != nil || result.RowsAffected() != 1 {
		if err != nil {
			return err
		}
		return coreexecutionv2.ErrConflict
	}
	return nil
}

func insertExecutionV2RecordTx(ctx context.Context, tx pgx.Tx, record coreexecutionv2.Record, eventType string) error {
	payloadRaw, err := json.Marshal(record.Payload)
	if err != nil || executionV2PayloadDigest(record.Payload) != record.Digest {
		return coreexecutionv2.ErrInvalid
	}
	result, err := tx.Exec(ctx, `INSERT INTO core_execution_v2_records(
		owner_id,resource_type,resource_id,revision,status,digest,payload_json,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, record.OwnerID, record.Kind, record.ID,
		record.Revision, record.Status, record.Digest, payloadRaw, record.CreatedAt, record.UpdatedAt)
	if err != nil || result.RowsAffected() != 1 {
		if err != nil {
			return err
		}
		return coreexecutionv2.ErrConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_execution_v2_revisions(
		owner_id,resource_type,resource_id,revision,status,digest,payload_json,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, record.OwnerID, record.Kind, record.ID,
		record.Revision, record.Status, record.Digest, payloadRaw, record.CreatedAt); err != nil {
		return err
	}
	return appendExecutionV2RecordEventTx(ctx, tx, record, eventType)
}

func updateExecutionV2RecordTx(ctx context.Context, tx pgx.Tx, record coreexecutionv2.Record, expected uint64, eventType string) (coreexecutionv2.Record, error) {
	if record.Revision != expected+1 || record.UpdatedAt.Before(record.CreatedAt) || executionV2PayloadDigest(record.Payload) != record.Digest {
		return coreexecutionv2.Record{}, coreexecutionv2.ErrInvalid
	}
	payloadRaw, _ := json.Marshal(record.Payload)
	result, err := tx.Exec(ctx, `UPDATE core_execution_v2_records SET revision=$1,status=$2,digest=$3,payload_json=$4,updated_at=$5
		WHERE owner_id=$6 AND resource_type=$7 AND resource_id=$8 AND revision=$9`, record.Revision,
		record.Status, record.Digest, payloadRaw, record.UpdatedAt, record.OwnerID, record.Kind, record.ID, expected)
	if err != nil || result.RowsAffected() != 1 {
		if err != nil {
			return coreexecutionv2.Record{}, err
		}
		return coreexecutionv2.Record{}, coreexecutionv2.ErrConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_execution_v2_revisions(
		owner_id,resource_type,resource_id,revision,status,digest,payload_json,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, record.OwnerID, record.Kind, record.ID,
		record.Revision, record.Status, record.Digest, payloadRaw, record.UpdatedAt); err != nil {
		return coreexecutionv2.Record{}, err
	}
	if err = appendExecutionV2RecordEventTx(ctx, tx, record, eventType); err != nil {
		return coreexecutionv2.Record{}, err
	}
	return record, nil
}

func appendExecutionV2RecordEventTx(ctx context.Context, tx pgx.Tx, record coreexecutionv2.Record, eventType string) error {
	var sequence uint64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM core_execution_v2_events
		WHERE owner_id=$1 AND resource_type=$2 AND resource_id=$3`, record.OwnerID, record.Kind, record.ID).Scan(&sequence); err != nil {
		return err
	}
	payloadRaw, _ := json.Marshal(record.Payload)
	result, err := tx.Exec(ctx, `INSERT INTO core_execution_v2_events(
		owner_id,resource_type,resource_id,sequence,event_id,event_type,payload_json,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, record.OwnerID, record.Kind, record.ID,
		sequence, uuid.New(), eventType, payloadRaw, record.UpdatedAt)
	if err != nil || result.RowsAffected() != 1 {
		if err != nil {
			return err
		}
		return coreexecutionv2.ErrConflict
	}
	return nil
}

const executionV2RunRecordSelect = `SELECT owner_id,resource_type,resource_id::text,revision,status,digest,payload_json,created_at,updated_at FROM core_execution_v2_records`

func executionV2RecordTx(ctx context.Context, tx pgx.Tx, owner, kind, id string, lock bool) (coreexecutionv2.Record, error) {
	query := executionV2RunRecordSelect + ` WHERE owner_id=$1 AND resource_type=$2 AND resource_id=$3`
	if lock {
		query += ` FOR UPDATE`
	}
	return scanExecutionV2RunRecord(tx.QueryRow(ctx, query, owner, kind, id))
}

func executionV2RevisionTx(ctx context.Context, tx pgx.Tx, owner, kind, id string, revision uint64) (coreexecutionv2.Record, error) {
	var record coreexecutionv2.Record
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT owner_id,resource_type,resource_id::text,revision,status,digest,payload_json,created_at
		FROM core_execution_v2_revisions WHERE owner_id=$1 AND resource_type=$2 AND resource_id=$3 AND revision=$4`,
		owner, kind, id, revision).Scan(&record.OwnerID, &record.Kind, &record.ID, &record.Revision,
		&record.Status, &record.Digest, &raw, &record.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return record, coreexecutionv2.ErrNotFound
	}
	if err != nil || json.Unmarshal(raw, &record.Payload) != nil {
		if err != nil {
			return record, err
		}
		return record, coreexecutionv2.ErrConflict
	}
	record.CreatedAt = record.CreatedAt.UTC()
	record.UpdatedAt = record.CreatedAt
	if executionV2PayloadDigest(record.Payload) != record.Digest {
		return record, coreexecutionv2.ErrConflict
	}
	return record, nil
}

func scanExecutionV2RunRecord(row interface{ Scan(...any) error }) (coreexecutionv2.Record, error) {
	var record coreexecutionv2.Record
	var raw []byte
	err := row.Scan(&record.OwnerID, &record.Kind, &record.ID, &record.Revision, &record.Status,
		&record.Digest, &raw, &record.CreatedAt, &record.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return record, coreexecutionv2.ErrNotFound
	}
	if err != nil {
		return record, err
	}
	if json.Unmarshal(raw, &record.Payload) != nil {
		return record, coreexecutionv2.ErrConflict
	}
	record.CreatedAt, record.UpdatedAt = record.CreatedAt.UTC(), record.UpdatedAt.UTC()
	if record.Revision == 0 || record.OwnerID == "" || !coretask.ValidUUID(record.ID) ||
		executionV2PayloadDigest(record.Payload) != record.Digest || record.UpdatedAt.Before(record.CreatedAt) {
		return record, coreexecutionv2.ErrConflict
	}
	return record, nil
}

const genericRunConfirmationSelect = `SELECT confirmation_id,binding_json,task_id,state,consumed_released,revision,created_at,updated_at,expires_at,terminal_reason,terminal_code,terminal_note FROM core_confirmations`

func genericRunConfirmationTx(ctx context.Context, tx pgx.Tx, confirmationID string, lock bool) (coreconfirmation.Confirmation, bool, error) {
	query := genericRunConfirmationSelect + ` WHERE confirmation_id=$1`
	if lock {
		query += ` FOR UPDATE`
	}
	var confirmation coreconfirmation.Confirmation
	var bindingRaw []byte
	var state string
	var released bool
	err := tx.QueryRow(ctx, query, confirmationID).Scan(&confirmation.ConfirmationID, &bindingRaw,
		&confirmation.TaskID, &state, &released, &confirmation.Revision, &confirmation.CreatedAt,
		&confirmation.UpdatedAt, &confirmation.ExpiresAt, &confirmation.TerminalReason,
		&confirmation.TerminalCode, &confirmation.TerminalNote)
	if err != nil {
		return confirmation, false, err
	}
	if json.Unmarshal(bindingRaw, &confirmation.Binding) != nil {
		return confirmation, false, coreexecutionv2.ErrConflict
	}
	confirmation.OwnerID = confirmation.Binding.OwnerID
	confirmation.State = coreconfirmation.State(state)
	confirmation.CreatedAt, confirmation.UpdatedAt, confirmation.ExpiresAt = confirmation.CreatedAt.UTC(), confirmation.UpdatedAt.UTC(), confirmation.ExpiresAt.UTC()
	return confirmation, released, nil
}

func (s *CoreExecutionV2RunStore) loadGenericRunEnvelopeTx(
	ctx context.Context,
	tx pgx.Tx,
	owner, runID, taskID, confirmationID, stageID string,
	lock bool,
) (coreexecutionv2.GenericRunEnvelope, error) {
	var task coretask.Task
	var err error
	if lock {
		task, err = NewCoreTaskStore(s.store).taskTxLocked(ctx, tx, taskID, false)
	} else {
		task, err = NewCoreTaskStore(s.store).taskTx(ctx, tx, taskID, false)
	}
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, mapGenericRunTaskError(err)
	}
	confirmation, released, err := genericRunConfirmationTx(ctx, tx, confirmationID, lock)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, mapGenericRunConfirmationError(err)
	}
	run, err := executionV2RecordTx(ctx, tx, owner, "run", runID, lock)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	stage, err := executionV2RecordTx(ctx, tx, owner, "stage", stageID, lock)
	if err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	if err = validateGenericRunAuthorityTx(ctx, tx, task, confirmation, released, run, stage); err != nil {
		return coreexecutionv2.GenericRunEnvelope{}, err
	}
	return coreexecutionv2.GenericRunEnvelope{Run: run, Stage: stage, Task: task, Confirmation: confirmation}, nil
}

// projectExecutionV2RunConfirmationTx keeps the real CoreConfirmation,
// CoreTask, run and stage in one PostgreSQL transaction. It is called only
// after the confirmation repository has fenced and mutated the confirmation
// and task rows; provider code is never reachable from this path.
func projectExecutionV2RunConfirmationTx(
	ctx context.Context,
	tx pgx.Tx,
	current coreconfirmation.Confirmation,
	status string,
	at time.Time,
) error {
	if current.Binding.OperationDomain != executionV2RunConfirmationDomain {
		return nil
	}
	if status != "queued" && status != "rejected" && status != "expired" {
		return coreconfirmation.ErrInvalid
	}
	confirmation, released, err := genericRunConfirmationTx(ctx, tx, current.ConfirmationID, true)
	if err != nil {
		return mapGenericRunConfirmationProjectionError(err)
	}
	if released || confirmation.ConfirmationID != current.ConfirmationID || confirmation.TaskID != current.TaskID ||
		!confirmation.Binding.Equal(current.Binding) {
		return coreconfirmation.ErrStale
	}
	task, err := scanCoreTask(tx.QueryRow(ctx, taskSelect+` WHERE task_id=$1 AND deleted_at IS NULL`, confirmation.TaskID))
	if err != nil {
		return mapGenericRunConfirmationProjectionError(err)
	}
	payload := task.Spec.Payload.ExecutionV2Run
	if task.Spec.Kind != coretask.TaskKindExecutionV2Run || payload == nil {
		return coreconfirmation.ErrStale
	}
	run, err := executionV2RecordTx(ctx, tx, payload.OwnerID, "run", payload.RunID, true)
	if err != nil {
		return mapGenericRunConfirmationProjectionError(err)
	}
	stage, err := executionV2RecordTx(ctx, tx, payload.OwnerID, "stage", payload.StageID, true)
	if err != nil {
		return mapGenericRunConfirmationProjectionError(err)
	}
	if err = validateGenericRunTerminalAuthorityTx(ctx, tx, task, confirmation, released, run, stage); err != nil {
		return mapGenericRunConfirmationProjectionError(err)
	}

	validTransition := false
	switch status {
	case "queued":
		validTransition = confirmation.State == coreconfirmation.StateConfirmed && task.Status == coretask.StatusQueued &&
			run.Status == "waiting_user" && stage.Status == "waiting_user"
	case "rejected":
		validTransition = confirmation.State == coreconfirmation.StateRejected && task.Status == coretask.StatusCanceled &&
			run.Status == "waiting_user" && stage.Status == "waiting_user"
	case "expired":
		validTransition = confirmation.State == coreconfirmation.StateExpired && task.Status == coretask.StatusFailed &&
			(run.Status == "waiting_user" || run.Status == "queued") && stage.Status == run.Status
	}
	if !validTransition {
		return coreconfirmation.ErrStale
	}
	if _, _, err = projectGenericRunRecordsTx(ctx, tx, run, stage, status, nil, nil, at.UTC().Truncate(time.Microsecond)); err != nil {
		return mapGenericRunConfirmationProjectionError(err)
	}
	return nil
}

func validateGenericRunAuthorityTx(
	ctx context.Context,
	tx pgx.Tx,
	task coretask.Task,
	confirmation coreconfirmation.Confirmation,
	released bool,
	run, stage coreexecutionv2.Record,
) error {
	return validateGenericRunAuthoritySnapshotTx(ctx, tx, task, confirmation, released, run, stage, true)
}

func validateGenericRunTerminalAuthorityTx(
	ctx context.Context,
	tx pgx.Tx,
	task coretask.Task,
	confirmation coreconfirmation.Confirmation,
	released bool,
	run, stage coreexecutionv2.Record,
) error {
	return validateGenericRunAuthoritySnapshotTx(ctx, tx, task, confirmation, released, run, stage, false)
}

func validateGenericRunAuthoritySnapshotTx(
	ctx context.Context,
	tx pgx.Tx,
	task coretask.Task,
	confirmation coreconfirmation.Confirmation,
	released bool,
	run, stage coreexecutionv2.Record,
	requireCurrentBinding bool,
) error {
	if task.Spec.Kind != coretask.TaskKindExecutionV2Run || task.Spec.Payload.ExecutionV2Run == nil || task.Validate() != nil {
		return coreexecutionv2.ErrConflict
	}
	payload := task.Spec.Payload.ExecutionV2Run
	confirmationSnapshot := coreexecutionv2.GenericRunAuthoritySnapshot{
		OwnerID: payload.OwnerID, AccountGeneration: payload.AccountGeneration,
		RunID: payload.RunID, StageID: payload.StageID, TaskID: task.ID,
		PlanID: payload.PlanID, PlanRevision: payload.PlanRevision, PlanDigest: payload.PlanDigest,
		ConfirmationID: payload.ConfirmationID, Operation: payload.Operation,
	}
	if payload.OwnerID == "" || payload.AccountGeneration == 0 || payload.RunID != run.ID || payload.StageID != stage.ID ||
		payload.ConfirmationID != confirmation.ConfirmationID || task.ID != confirmation.TaskID ||
		run.OwnerID != payload.OwnerID || stage.OwnerID != payload.OwnerID || run.Kind != "run" || stage.Kind != "stage" ||
		confirmation.OwnerID != payload.OwnerID || confirmation.Binding.OwnerID != payload.OwnerID ||
		confirmation.Binding.AccountGeneration != payload.AccountGeneration ||
		confirmation.Binding.OperationDomain != executionV2RunConfirmationDomain ||
		confirmation.Binding.TargetID != payload.RunID || confirmation.Binding.TargetRevision != 1 ||
		confirmation.Binding.TargetKind != "execution_v2_run" ||
		string(confirmation.Binding.ContentDigest) != payload.PlanDigest ||
		(released && confirmation.State != coreconfirmation.StateConsumed) || run.Status != stage.Status ||
		stringValue(run.Payload, "owner_id") != payload.OwnerID || stringValue(stage.Payload, "owner_id") != payload.OwnerID ||
		stringValue(run.Payload, "status") != run.Status || stringValue(stage.Payload, "status") != stage.Status ||
		stringValue(run.Payload, "stage_id") != payload.StageID || stringValue(stage.Payload, "run_id") != payload.RunID ||
		stringValue(run.Payload, "task_id") != task.ID || stringValue(stage.Payload, "task_id") != task.ID ||
		stringValue(run.Payload, "confirmation_id") != payload.ConfirmationID ||
		stringValue(stage.Payload, "confirmation_id") != payload.ConfirmationID ||
		stringValue(run.Payload, "plan_id") != payload.PlanID || stringValue(stage.Payload, "plan_id") != payload.PlanID ||
		uintValue(run.Payload, "plan_revision") != payload.PlanRevision ||
		uintValue(stage.Payload, "plan_revision") != payload.PlanRevision ||
		stringValue(run.Payload, "plan_digest") != payload.PlanDigest ||
		stringValue(stage.Payload, "plan_digest") != payload.PlanDigest ||
		uintValue(run.Payload, "account_generation") != payload.AccountGeneration ||
		uintValue(stage.Payload, "account_generation") != payload.AccountGeneration ||
		stringValue(run.Payload, "operation") != payload.Operation ||
		stringValue(stage.Payload, "operation") != payload.Operation ||
		coreexecutionv2.ValidateGenericRunConfirmation(confirmation, confirmationSnapshot, confirmation.State) != nil {
		return coreexecutionv2.ErrConflict
	}
	plan, err := executionV2RevisionTx(ctx, tx, payload.OwnerID, "plan", payload.PlanID, payload.PlanRevision)
	if err != nil || plan.Digest != payload.PlanDigest {
		return coreexecutionv2.ErrConflict
	}
	if requireCurrentBinding {
		if err = validateGenericRunBindingsTx(ctx, tx, confirmation, true); err != nil {
			return err
		}
	} else if err = validateGenericRunTargetBindingTx(ctx, tx, confirmation, true); err != nil {
		return err
	}
	return nil
}

func validateGenericRunTargetBindingTx(ctx context.Context, tx pgx.Tx, confirmation coreconfirmation.Confirmation, lock bool) error {
	query := `SELECT binding_json FROM core_confirmation_target_bindings WHERE confirmation_id=$1`
	if lock {
		query += ` FOR UPDATE`
	}
	var raw []byte
	if err := tx.QueryRow(ctx, query, confirmation.ConfirmationID).Scan(&raw); err != nil {
		return coreexecutionv2.ErrConflict
	}
	var target coreconfirmation.Binding
	if json.Unmarshal(raw, &target) != nil || !confirmation.Binding.Equal(target) {
		return coreexecutionv2.ErrConflict
	}
	return nil
}

func validateGenericRunBindingsTx(ctx context.Context, tx pgx.Tx, confirmation coreconfirmation.Confirmation, lock bool) error {
	queryTarget := `SELECT binding_json FROM core_confirmation_target_bindings WHERE confirmation_id=$1`
	queryCurrent := `SELECT binding_json FROM core_confirmation_current_bindings WHERE operation_domain=$1 AND target_id=$2`
	if lock {
		queryTarget += ` FOR UPDATE`
		queryCurrent += ` FOR UPDATE`
	}
	var targetRaw, currentRaw []byte
	if err := tx.QueryRow(ctx, queryTarget, confirmation.ConfirmationID).Scan(&targetRaw); err != nil {
		return coreexecutionv2.ErrConflict
	}
	if err := tx.QueryRow(ctx, queryCurrent, confirmation.Binding.OperationDomain, confirmation.Binding.TargetID).Scan(&currentRaw); err != nil {
		return coreexecutionv2.ErrConflict
	}
	var target, current coreconfirmation.Binding
	if json.Unmarshal(targetRaw, &target) != nil || json.Unmarshal(currentRaw, &current) != nil ||
		!confirmation.Binding.Equal(target) || !confirmation.Binding.Equal(current) {
		return coreexecutionv2.ErrConflict
	}
	return nil
}

func genericRunCreateReplayOperation(command coreexecutionv2.GenericRunCreateCommand) string {
	if stringValue(command.Run.Payload, "retry_of_run_id") != "" {
		return executionV2RunRetryOperation
	}
	return executionV2RunCreateOperation
}

// genericRunCreateDigest deliberately excludes wall-clock fields. A retry
// after lifecycle commit but before the public action replay is saved creates
// a fresh command timestamp and expiry; those values must not change the
// business mutation or replace the originally persisted response snapshot.
func genericRunCreateDigest(command coreexecutionv2.GenericRunCreateCommand) string {
	run, stage, task, confirmation := command.Run, command.Stage, command.Task, command.Confirmation
	run.CreatedAt, run.UpdatedAt = time.Time{}, time.Time{}
	stage.CreatedAt, stage.UpdatedAt = time.Time{}, time.Time{}
	task.CreatedAt, task.UpdatedAt, task.AvailableAt = time.Time{}, time.Time{}, time.Time{}
	task.Spec.AvailableAt = time.Time{}
	confirmation.CreatedAt, confirmation.UpdatedAt, confirmation.ExpiresAt = time.Time{}, time.Time{}, time.Time{}
	raw, _ := json.Marshal(struct {
		Run          coreexecutionv2.Record        `json:"run"`
		Stage        coreexecutionv2.Record        `json:"stage"`
		Task         coretask.Task                 `json:"task"`
		Confirmation coreconfirmation.Confirmation `json:"confirmation"`
	}{run, stage, task, confirmation})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func genericRunEnvelopeCreateDigest(envelope coreexecutionv2.GenericRunEnvelope) string {
	return genericRunCreateDigest(coreexecutionv2.GenericRunCreateCommand{
		Run: envelope.Run, Stage: envelope.Stage, Task: envelope.Task, Confirmation: envelope.Confirmation,
	})
}

func genericRunRecordLinks(run, stage coreexecutionv2.Record, task coretask.Task, confirmation coreconfirmation.Confirmation) bool {
	payload := task.Spec.Payload.ExecutionV2Run
	if payload == nil {
		return false
	}
	binding, _ := stage.Payload["binding"].(map[string]any)
	return stringValue(run.Payload, "owner_id") == payload.OwnerID &&
		stringValue(stage.Payload, "owner_id") == payload.OwnerID &&
		stringValue(run.Payload, "status") == "waiting_user" && stringValue(stage.Payload, "status") == "waiting_user" &&
		stringValue(run.Payload, "stage_id") == stage.ID && stringValue(stage.Payload, "run_id") == run.ID &&
		stringValue(run.Payload, "task_id") == task.ID && stringValue(stage.Payload, "task_id") == task.ID &&
		stringValue(run.Payload, "confirmation_id") == confirmation.ConfirmationID &&
		stringValue(stage.Payload, "confirmation_id") == confirmation.ConfirmationID &&
		stringValue(run.Payload, "plan_id") == payload.PlanID && stringValue(stage.Payload, "plan_id") == payload.PlanID &&
		uintValue(run.Payload, "plan_revision") == payload.PlanRevision && uintValue(stage.Payload, "plan_revision") == payload.PlanRevision &&
		stringValue(run.Payload, "plan_digest") == payload.PlanDigest && stringValue(stage.Payload, "plan_digest") == payload.PlanDigest &&
		uintValue(run.Payload, "account_generation") == payload.AccountGeneration && uintValue(stage.Payload, "account_generation") == payload.AccountGeneration &&
		stringValue(run.Payload, "operation") == payload.Operation && stringValue(stage.Payload, "operation") == payload.Operation &&
		stringValue(binding, "run_id") == run.ID && stringValue(binding, "stage_id") == stage.ID &&
		stringValue(binding, "task_id") == task.ID && stringValue(binding, "confirmation_id") == confirmation.ConfirmationID
}

func sameActiveGenericRunFence(current, supplied coretask.Task, at time.Time) bool {
	if validateSuppliedGenericRunTask(supplied) != nil || current.Validate() != nil || current.Status != coretask.StatusRunning ||
		current.Lease == nil || current.ID != supplied.ID || current.Attempt != supplied.Attempt ||
		current.LeaseEpoch != supplied.LeaseEpoch || current.Revision != supplied.Revision ||
		current.Lease.Holder != supplied.Lease.Holder || current.Lease.ExpiresAt.Before(supplied.Lease.ExpiresAt) ||
		!current.Lease.ExpiresAt.After(at.UTC()) || !sameGenericRunTaskSpec(current.Spec, supplied.Spec) {
		return false
	}
	return true
}

func sameGenericRunTaskSpec(left, right coretask.TaskSpec) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func validateGenericRunReservationTx(ctx context.Context, tx pgx.Tx, confirmationID string, task coretask.Task) error {
	var taskID string
	var attempt int
	var epoch, revision int64
	var active bool
	err := tx.QueryRow(ctx, `SELECT task_id::text,acquired_attempt,acquired_lease_epoch,task_revision,active
		FROM core_confirmation_reservations WHERE confirmation_id=$1 FOR UPDATE`, confirmationID).
		Scan(&taskID, &attempt, &epoch, &revision, &active)
	if err != nil || !active || taskID != task.ID || attempt != int(task.Attempt) ||
		epoch != int64(task.LeaseEpoch) || revision != int64(task.Revision) {
		return coreexecutionv2.ErrConflict
	}
	return nil
}

func genericRunProjectedRecords(
	run, stage coreexecutionv2.Record,
	status string,
	runPayload, stagePayload map[string]any,
	at time.Time,
	targetRunRevision, targetStageRevision uint64,
) (coreexecutionv2.Record, coreexecutionv2.Record, error) {
	if !genericRunProjectStatus(status) || at.IsZero() || at.Location() != time.UTC {
		return coreexecutionv2.Record{}, coreexecutionv2.Record{}, coreexecutionv2.ErrInvalid
	}
	if runPayload == nil {
		runPayload = cloneExecutionV2Payload(run.Payload)
	} else {
		runPayload = cloneExecutionV2Payload(runPayload)
	}
	if stagePayload == nil {
		stagePayload = cloneExecutionV2Payload(stage.Payload)
	} else {
		stagePayload = cloneExecutionV2Payload(stagePayload)
	}
	if targetRunRevision == 0 {
		targetRunRevision = run.Revision + 1
	}
	if targetStageRevision == 0 {
		targetStageRevision = stage.Revision + 1
	}
	runPayload["status"], runPayload["owner_id"] = status, run.OwnerID
	stagePayload["status"], stagePayload["owner_id"] = status, stage.OwnerID
	stagePayload["run_revision"] = targetRunRevision
	nextRun := coreexecutionv2.Record{OwnerID: run.OwnerID, Kind: run.Kind, ID: run.ID,
		Revision: targetRunRevision, Status: status, Payload: runPayload, CreatedAt: run.CreatedAt,
		UpdatedAt: at.UTC().Truncate(time.Microsecond)}
	nextStage := coreexecutionv2.Record{OwnerID: stage.OwnerID, Kind: stage.Kind, ID: stage.ID,
		Revision: targetStageRevision, Status: status, Payload: stagePayload, CreatedAt: stage.CreatedAt,
		UpdatedAt: at.UTC().Truncate(time.Microsecond)}
	nextRun.Digest, nextStage.Digest = executionV2PayloadDigest(nextRun.Payload), executionV2PayloadDigest(nextStage.Payload)
	if stringValue(nextRun.Payload, "stage_id") != nextStage.ID || stringValue(nextStage.Payload, "run_id") != nextRun.ID ||
		stringValue(nextRun.Payload, "task_id") == "" || stringValue(nextRun.Payload, "task_id") != stringValue(nextStage.Payload, "task_id") ||
		stringValue(nextRun.Payload, "confirmation_id") == "" ||
		stringValue(nextRun.Payload, "confirmation_id") != stringValue(nextStage.Payload, "confirmation_id") ||
		stringValue(nextRun.Payload, "plan_id") == "" || stringValue(nextRun.Payload, "plan_id") != stringValue(nextStage.Payload, "plan_id") ||
		uintValue(nextRun.Payload, "plan_revision") == 0 ||
		uintValue(nextRun.Payload, "plan_revision") != uintValue(nextStage.Payload, "plan_revision") ||
		stringValue(nextRun.Payload, "operation") == "" ||
		stringValue(nextRun.Payload, "operation") != stringValue(nextStage.Payload, "operation") {
		return coreexecutionv2.Record{}, coreexecutionv2.Record{}, coreexecutionv2.ErrConflict
	}
	return nextRun, nextStage, nil
}

func projectGenericRunRecordsTx(
	ctx context.Context,
	tx pgx.Tx,
	run, stage coreexecutionv2.Record,
	status string,
	runPayload, stagePayload map[string]any,
	at time.Time,
) (coreexecutionv2.Record, coreexecutionv2.Record, error) {
	nextRun, nextStage, err := genericRunProjectedRecords(run, stage, status, runPayload, stagePayload, at, 0, 0)
	if err != nil {
		return run, stage, err
	}
	run, err = updateExecutionV2RecordTx(ctx, tx, nextRun, run.Revision, "run_status_"+status)
	if err != nil {
		return run, stage, err
	}
	stage, err = updateExecutionV2RecordTx(ctx, tx, nextStage, stage.Revision, "stage_status_"+status)
	return run, stage, err
}

func genericRunTerminalTaskProjection(command coreexecutionv2.GenericRunProjectCommand) (string, string, string, []byte, error) {
	if !genericRunTerminal(command.Status) || command.Result.Validate() != nil {
		return "", "", "", nil, coreexecutionv2.ErrInvalid
	}
	resultRaw, err := json.Marshal(command.Result)
	if err != nil || len(resultRaw) > coretask.MaxResultBytes {
		return "", "", "", nil, coreexecutionv2.ErrInvalid
	}
	switch command.Status {
	case "succeeded":
		return "succeeded", "", "", resultRaw, nil
	case "failed", "expired":
		code, summary := strings.TrimSpace(command.FailureCode), strings.TrimSpace(command.FailureSummary)
		if code == "" || summary == "" {
			return "", "", "", nil, coreexecutionv2.ErrInvalid
		}
		return "failed", code, summary, resultRaw, nil
	case "canceled":
		return "canceled", "user_canceled", strings.TrimSpace(command.FailureSummary), resultRaw, nil
	case "rejected":
		return "canceled", "user_rejected", strings.TrimSpace(command.FailureSummary), resultRaw, nil
	default:
		return "", "", "", nil, coreexecutionv2.ErrInvalid
	}
}

func insertGenericRunTaskTerminalEventTx(ctx context.Context, tx pgx.Tx, taskID, status, code, summary string, result []byte, at time.Time) error {
	resultValue := any(nil)
	if len(result) > 0 {
		resultValue = result
	}
	inserted, err := tx.Exec(ctx, `INSERT INTO core_task_events(
		task_id,sequence,event_id,attempt,status,phase,result_json,error_code,error_summary,occurred_at)
		SELECT task_id,progress_sequence,$2,attempt,$3,'execution_v2_terminal',$4,$5,$6,$7
		FROM core_tasks WHERE task_id=$1 AND status=$3`, taskID, uuid.New(), status, resultValue, code, summary, at)
	if err != nil || inserted.RowsAffected() != 1 {
		if err != nil {
			return err
		}
		return coreexecutionv2.ErrConflict
	}
	return nil
}

func decrementGenericRunConcurrencyTx(ctx context.Context, tx pgx.Tx, at time.Time) error {
	updated, err := tx.Exec(ctx, `UPDATE core_task_runtime_concurrency SET running_count=running_count-1,
		revision=revision+1,updated_at=$1 WHERE singleton=true AND running_count>0`, at)
	if err != nil || updated.RowsAffected() != 1 {
		if err != nil {
			return err
		}
		return coreexecutionv2.ErrConflict
	}
	return nil
}

func genericRunCancelDigest(command coreexecutionv2.GenericRunCancelCommand) string {
	raw, _ := json.Marshal(struct {
		OwnerID           string `json:"owner_id"`
		AccountGeneration uint64 `json:"account_generation"`
		RunID             string `json:"run_id"`
		ExpectedRevision  uint64 `json:"expected_revision"`
	}{command.Authority.OwnerID, command.Authority.AccountGeneration, command.RunID, command.ExpectedRevision})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func genericRunRecordIDs(run coreexecutionv2.Record) (string, string, string) {
	return stringValue(run.Payload, "task_id"), stringValue(run.Payload, "confirmation_id"), stringValue(run.Payload, "stage_id")
}

func genericRunProjectStatus(status string) bool {
	switch strings.TrimSpace(status) {
	case "queued", "running", "uncertain", "succeeded", "failed", "canceled", "rejected", "expired":
		return true
	default:
		return false
	}
}

func genericRunTerminal(status string) bool {
	switch strings.TrimSpace(status) {
	case "succeeded", "failed", "canceled", "rejected", "expired":
		return true
	default:
		return false
	}
}

func genericRunTaskTerminal(status coretask.Status) bool {
	return status == coretask.StatusSucceeded || status == coretask.StatusFailed || status == coretask.StatusCanceled
}

func executionV2PayloadDigest(payload map[string]any) string {
	raw, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func cloneExecutionV2Payload(payload map[string]any) map[string]any {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	var cloned map[string]any
	if json.Unmarshal(raw, &cloned) != nil {
		return nil
	}
	return cloned
}

func stringValue(payload map[string]any, key string) string {
	value, _ := payload[key].(string)
	return strings.TrimSpace(value)
}

func uintValue(payload map[string]any, key string) uint64 {
	switch value := payload[key].(type) {
	case uint64:
		return value
	case uint32:
		return uint64(value)
	case int:
		if value >= 0 {
			return uint64(value)
		}
	case int64:
		if value >= 0 {
			return uint64(value)
		}
	case float64:
		if value >= 0 && value == float64(uint64(value)) {
			return uint64(value)
		}
	case json.Number:
		parsed, err := value.Int64()
		if err == nil && parsed >= 0 {
			return uint64(parsed)
		}
	}
	return 0
}

func sameExecutionV2Record(left, right coreexecutionv2.Record) bool {
	leftRaw, leftErr := json.Marshal(left.Payload)
	rightRaw, rightErr := json.Marshal(right.Payload)
	return leftErr == nil && rightErr == nil && left.OwnerID == right.OwnerID && left.Kind == right.Kind &&
		left.ID == right.ID && left.Revision == right.Revision && left.Status == right.Status && left.Digest == right.Digest &&
		bytes.Equal(leftRaw, rightRaw) && sameInstantWithinPostgres(left.CreatedAt, right.CreatedAt) &&
		sameInstantWithinPostgres(left.UpdatedAt, right.UpdatedAt)
}

func sameInstantWithinPostgres(left, right time.Time) bool {
	if left.IsZero() || right.IsZero() {
		return left.IsZero() && right.IsZero()
	}
	return left.UTC().Truncate(time.Microsecond).Equal(right.UTC().Truncate(time.Microsecond))
}

func postgresClockTx(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return time.Time{}, err
	}
	return now.UTC().Truncate(time.Microsecond), nil
}

func mapExecutionV2RunPGError(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505", "23503":
			return fmt.Errorf("%w: %s", coreexecutionv2.ErrConflict, pgErr.ConstraintName)
		case "23514", "22P02":
			return fmt.Errorf("%w: %s", coreexecutionv2.ErrInvalid, pgErr.ConstraintName)
		}
	}
	return err
}

func mapGenericRunTaskError(err error) error {
	if errors.Is(err, coretask.ErrNotFound) || errors.Is(err, pgx.ErrNoRows) {
		return coreexecutionv2.ErrNotFound
	}
	if errors.Is(err, coretask.ErrInvalid) || errors.Is(err, coretask.ErrLeaseConflict) || errors.Is(err, coretask.ErrRevisionConflict) {
		return coreexecutionv2.ErrConflict
	}
	return err
}

func mapGenericRunConfirmationError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, coreconfirmation.ErrNotFound) {
		return coreexecutionv2.ErrNotFound
	}
	if errors.Is(err, coreconfirmation.ErrInvalid) || errors.Is(err, coreconfirmation.ErrConflict) ||
		errors.Is(err, coreconfirmation.ErrTaskFenceConflict) || errors.Is(err, coreconfirmation.ErrStale) {
		return coreexecutionv2.ErrConflict
	}
	return err
}

func mapGenericRunConfirmationProjectionError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, coreexecutionv2.ErrInvalid) || errors.Is(err, coreexecutionv2.ErrNotFound) ||
		errors.Is(err, coreexecutionv2.ErrConflict) || errors.Is(err, coretask.ErrInvalid) ||
		errors.Is(err, coretask.ErrNotFound) || errors.Is(err, pgx.ErrNoRows) {
		return coreconfirmation.ErrStale
	}
	return err
}
