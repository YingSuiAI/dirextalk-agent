package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const extensionUncertainAckOperation = "extension_execution_uncertain_ack"

// AcknowledgeExtensionExecutionUncertain atomically closes the consumed
// reservation after an owner explicitly accepts the unknown outcome. It never
// queues, retries, or re-dispatches the task.
func (s *CoreConfirmationStore) AcknowledgeExtensionExecutionUncertain(ctx context.Context, command coreconfirmation.AcknowledgeExtensionExecutionUncertainCommand) (coreconfirmation.AcknowledgeExtensionExecutionUncertainResult, error) {
	if s == nil || s.store == nil || strings.TrimSpace(command.OwnerID) == "" || command.AccountGeneration == 0 || !coretask.ValidUUID(command.ConfirmationID) || !coretask.ValidUUID(command.TaskID) || !coretask.ValidUUID(command.InstallationID) || !coretask.ValidUUID(command.IdempotencyKey) || command.ExpectedTaskRevision < 1 || command.ExpectedConfirmationRevision < 1 || command.Resolution != coreconfirmation.ExtensionUncertainAcknowledgedUnknownNoRetry {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, coreconfirmation.ErrInvalid
	}
	digest := coreconfirmation.AcknowledgeExtensionExecutionUncertainDigest(command)
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, extensionUncertainAckOperation+":"+command.IdempotencyKey); err != nil {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "core_extension_installation:"+command.InstallationID); err != nil {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, err
	}
	var previousHash string
	var previousRaw []byte
	err = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_confirmation_replays WHERE operation=$1 AND idempotency_key=$2 FOR UPDATE`, extensionUncertainAckOperation, command.IdempotencyKey).Scan(&previousHash, &previousRaw)
	if err == nil {
		if previousHash != string(digest) {
			return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, coreconfirmation.ErrIdempotencyConflict
		}
		var replayed coreconfirmation.AcknowledgeExtensionExecutionUncertainResult
		if json.Unmarshal(previousRaw, &replayed) != nil {
			return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, coreconfirmation.ErrBindingUnavailable
		}
		if err = tx.Commit(ctx); err != nil {
			return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, err
		}
		return replayed, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, err
	}

	cur, err := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, command.ConfirmationID))
	if errors.Is(err, pgx.ErrNoRows) {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, coreconfirmation.ErrNotFound
	}
	if err != nil {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, err
	}
	if cur.ConfirmationID != command.ConfirmationID || cur.TaskID != command.TaskID || cur.Binding.OperationDomain != "extension.execute" || cur.Binding.TargetID != command.InstallationID || cur.Binding.OwnerID != command.OwnerID || cur.Binding.AccountGeneration != command.AccountGeneration || cur.State != coreconfirmation.StateConsumed || cur.Revision != command.ExpectedConfirmationRevision {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, coreconfirmation.ErrConflict
	}
	taskStore := NewCoreTaskStore(s.store)
	task, err := taskStore.taskTxLocked(ctx, tx, command.TaskID, false)
	if errors.Is(err, pgx.ErrNoRows) {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, coreconfirmation.ErrNotFound
	}
	if err != nil {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, err
	}
	if task.Status != coretask.StatusFailed || task.FailureCode != "extension_execution_uncertain" || int64(task.Revision) != command.ExpectedTaskRevision || task.Spec.Payload.Extension == nil || task.Spec.Payload.Extension.Operation != coretask.ExtensionOperationExecuteTool && task.Spec.Payload.Extension.Operation != coretask.ExtensionOperationExecuteSkill || task.Spec.Payload.Extension.InstallationID != command.InstallationID || task.Spec.Payload.Extension.ConfirmationID != command.ConfirmationID {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, coreconfirmation.ErrTaskFenceConflict
	}
	var reservationTask string
	var acquiredAttempt, acquiredEpoch, reservationRevision int64
	var active bool
	err = tx.QueryRow(ctx, `SELECT task_id::text,acquired_attempt,acquired_lease_epoch,task_revision,active FROM core_confirmation_reservations WHERE confirmation_id=$1 FOR UPDATE`, command.ConfirmationID).Scan(&reservationTask, &acquiredAttempt, &acquiredEpoch, &reservationRevision, &active)
	if errors.Is(err, pgx.ErrNoRows) {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, coreconfirmation.ErrConflict
	}
	if err != nil {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, err
	}
	if !active || reservationTask != command.TaskID || acquiredAttempt != int64(task.Attempt) || acquiredEpoch >= int64(task.LeaseEpoch) || reservationRevision >= int64(task.Revision) {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, coreconfirmation.ErrTaskFenceConflict
	}

	// Rehydrate the exact immutable installation/version binding and lock the
	// current binding projection while the transaction holds the task fence.
	current, err := extensionExecutionBindingTx(ctx, tx, cur)
	if err != nil {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, err
	}
	if !cur.Binding.Equal(current) {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, coreconfirmation.ErrStale
	}
	var currentRaw []byte
	if err = tx.QueryRow(ctx, `SELECT binding_json FROM core_confirmation_current_bindings WHERE operation_domain=$1 AND target_id=$2 FOR UPDATE`, cur.Binding.OperationDomain, cur.Binding.TargetID).Scan(&currentRaw); err != nil {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, coreconfirmation.ErrBindingUnavailable
	}
	var recorded coreconfirmation.Binding
	if json.Unmarshal(currentRaw, &recorded) != nil || !cur.Binding.Equal(recorded) {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, coreconfirmation.ErrStale
	}

	now := time.Now().UTC()
	if _, err = tx.Exec(ctx, `UPDATE core_confirmation_reservations SET active=false WHERE confirmation_id=$1 AND active=true`, command.ConfirmationID); err != nil {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_confirmations SET consumed_released=true,terminal_code='acknowledged_unknown_no_retry',terminal_reason='acknowledged_unknown_no_retry',revision=revision+1,updated_at=$2 WHERE confirmation_id=$1 AND state='consumed' AND revision=$3 AND consumed_released=false`, command.ConfirmationID, now, command.ExpectedConfirmationRevision); err != nil {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_tasks SET revision=revision+1,progress_sequence=progress_sequence+1,updated_at=$2 WHERE task_id=$1 AND status='failed' AND failure_code='extension_execution_uncertain' AND revision=$3`, command.TaskID, now, command.ExpectedTaskRevision); err != nil {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,error_code,error_summary,occurred_at) SELECT task_id,progress_sequence,$2,attempt,'failed','extension_execution_reconciled','extension_execution_acknowledged_unknown_no_retry','owner acknowledged unknown extension execution; automatic retry is forbidden',$3 FROM core_tasks WHERE task_id=$1`, command.TaskID, uuid.New(), now); err != nil {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, err
	}
	confirmation := cur
	confirmation.State = coreconfirmation.StateConsumed
	confirmation.Revision++
	confirmation.UpdatedAt = now
	confirmation.TerminalCode = "acknowledged_unknown_no_retry"
	confirmation.TerminalReason = "acknowledged_unknown_no_retry"
	task, err = taskStore.taskTxLocked(ctx, tx, command.TaskID, false)
	if err != nil {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, err
	}
	result := coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{Confirmation: confirmation, Task: task, Resolution: command.Resolution, ReservationReleased: true}
	raw, err := json.Marshal(result)
	if err != nil {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_replays(operation,idempotency_key,request_hash,response_json) VALUES($1,$2,$3,$4)`, extensionUncertainAckOperation, command.IdempotencyKey, string(digest), raw); err != nil {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreconfirmation.AcknowledgeExtensionExecutionUncertainResult{}, err
	}
	return result, nil
}
