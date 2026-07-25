package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (c *CoreAWSChangeCoordinator) CompleteChange(ctx context.Context, cmd coreaws.CompleteChangeCommand) (coreaws.Change, error) {
	now := c.now().UTC()
	status := cmd.Status
	stage := coreaws.StageSucceeded
	if status == coreaws.ChangeFailed {
		stage = coreaws.StageFailed
	}
	if status == coreaws.ChangeCanceled {
		stage = coreaws.StageCanceled
	}
	tx, e := c.store.pool.Begin(ctx)
	if e != nil {
		return coreaws.Change{}, e
	}
	defer tx.Rollback(ctx)
	if cmd.OperationKey == "" {
		cmd.OperationKey = uuid.NewSHA1(uuid.NameSpaceOID, []byte(cmd.ChangeID+"\x00complete")).String()
	}
	reqRaw, _ := json.Marshal(cmd)
	reqHash := sha256.Sum256(reqRaw)
	var replayRaw []byte
	if e = tx.QueryRow(ctx, `SELECT response_json FROM core_aws_replays WHERE operation='complete_change' AND idempotency_key=$1 AND request_hash=$2`, cmd.OperationKey, hex.EncodeToString(reqHash[:])).Scan(&replayRaw); e == nil {
		var out coreaws.Change
		if json.Unmarshal(replayRaw, &out) == nil {
			return out, nil
		}
		return coreaws.Change{}, coreaws.ErrConflict
	}
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return coreaws.Change{}, e
	}
	if errors.Is(e, pgx.ErrNoRows) {
		var old string
		if qe := tx.QueryRow(ctx, `SELECT request_hash FROM core_aws_replays WHERE operation='complete_change' AND idempotency_key=$1`, cmd.OperationKey).Scan(&old); qe == nil && old != hex.EncodeToString(reqHash[:]) {
			return coreaws.Change{}, coreaws.ErrIdempotencyConflict
		}
	}
	var currentTaskStatus string
	var taskAttempt uint32
	var taskEpoch uint64
	var taskRevision int64
	var leaseExpires *time.Time
	if e = tx.QueryRow(ctx, `SELECT status,attempt,lease_epoch,revision,lease_expires_at FROM core_tasks WHERE task_id=$1 FOR UPDATE`, cmd.TaskID).Scan(&currentTaskStatus, &taskAttempt, &taskEpoch, &taskRevision, &leaseExpires); e != nil {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	var confState string
	var confRevision int64
	if e = tx.QueryRow(ctx, `SELECT state,revision FROM core_confirmations WHERE confirmation_id=$1 AND task_id=$2 FOR UPDATE`, cmd.ConfirmationID, cmd.TaskID).Scan(&confState, &confRevision); e != nil {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	var active bool
	var reservationRevision int64
	if e = tx.QueryRow(ctx, `SELECT active,task_revision FROM core_confirmation_reservations WHERE confirmation_id=$1 AND task_id=$2 FOR UPDATE`, cmd.ConfirmationID, cmd.TaskID).Scan(&active, &reservationRevision); e != nil {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	if currentTaskStatus != "running" || taskAttempt != cmd.Attempt || taskEpoch != cmd.LeaseEpoch || taskRevision != cmd.ExpectedTaskRevision || leaseExpires == nil || !leaseExpires.After(now) || confState != "consumed" || confRevision != cmd.ExpectedConfirmationRevision || !active || reservationRevision != cmd.ExpectedTaskRevision {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	tag, e := tx.Exec(ctx, `UPDATE core_aws_changes SET status=$2,stage=$3,error_code=$4,error_summary=$5,revision=revision+1,updated_at=$6 WHERE change_id=$1 AND confirmation_id=$7 AND task_id=$8 AND revision=$9`, cmd.ChangeID, status, stage, cmd.ErrorCode, cmd.ErrorSummary, now, cmd.ConfirmationID, cmd.TaskID, cmd.ExpectedChangeRevision)
	if e != nil || tag.RowsAffected() == 0 {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	taskStatus := "succeeded"
	if status != coreaws.ChangeSucceeded {
		taskStatus = "failed"
	}
	if _, e = tx.Exec(ctx, `UPDATE core_tasks SET status=$2,attempt=GREATEST(attempt,1),result_json=CASE WHEN $2='succeeded' THEN '{}'::jsonb ELSE NULL END,failure_code=$3,failure_summary=$4,lease_holder='',lease_expires_at=NULL,revision=revision+1,updated_at=$5 WHERE task_id=$1 AND status='running' AND attempt=$6 AND lease_epoch=$7 AND revision=$8`, cmd.TaskID, taskStatus, cmd.ErrorCode, cmd.ErrorSummary, now, cmd.Attempt, cmd.LeaseEpoch, cmd.ExpectedTaskRevision); e != nil {
		return coreaws.Change{}, e
	}
	// Generic Task claims reserve one runtime slot.  Core AWS owns the same
	// durable terminal boundary, so release that slot in this transaction or
	// later queued AWS work would remain FIFO-blocked after a successful change.
	if _, e = tx.Exec(ctx, `UPDATE core_task_runtime_concurrency SET running_count=GREATEST(0,running_count-1),revision=revision+1,updated_at=$1 WHERE singleton=true`, now); e != nil {
		return coreaws.Change{}, e
	}
	_, _ = tx.Exec(ctx, `UPDATE core_confirmation_reservations SET active=false WHERE confirmation_id=$1`, cmd.ConfirmationID)
	// A consumed confirmation keeps the target reservation until the provider
	// outcome and task terminal state commit together.  Releasing only the
	// reservation row is insufficient: the partial unique index deliberately
	// continues to fence the target until this durable marker is set.
	if _, e = tx.Exec(ctx, `UPDATE core_confirmations SET consumed_released=true,updated_at=$2 WHERE confirmation_id=$1 AND task_id=$3 AND state='consumed'`, cmd.ConfirmationID, now, cmd.TaskID); e != nil {
		return coreaws.Change{}, e
	}
	if e = appendAWSAndTaskEvent(ctx, tx, cmd.ChangeID, cmd.TaskID, "completed", cmd.ExpectedChangeRevision+1, cmd.Attempt, taskStatus, now); e != nil {
		return coreaws.Change{}, e
	}
	out, e := NewCoreAWSStore(c.store).scanChange(tx.QueryRow(ctx, `SELECT change_id::text,plan_id::text,credential_id::text,task_id::text,confirmation_id::text,operation,status,stage,change_set_id,provider_request_digest,provider_token,revision,error_code,error_summary,created_at,updated_at FROM core_aws_changes WHERE change_id=$1`, cmd.ChangeID))
	if e != nil {
		return coreaws.Change{}, e
	}
	snap, _ := json.Marshal(out)
	if _, e = tx.Exec(ctx, `INSERT INTO core_aws_replays(operation,idempotency_key,request_hash,response_json) VALUES('complete_change',$1,$2,$3)`, cmd.OperationKey, hex.EncodeToString(reqHash[:]), snap); e != nil {
		return coreaws.Change{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return coreaws.Change{}, e
	}
	return out, nil
}
func (c *CoreAWSChangeCoordinator) ExecutionFence(ctx context.Context, id string) (coreaws.ExecutionFence, error) {
	ch, e := NewCoreAWSStore(c.store).GetChangeByConfirmation(ctx, id)
	if e != nil {
		return coreaws.ExecutionFence{}, e
	}
	var t coreaws.Task
	var st string
	e = c.store.pool.QueryRow(ctx, `SELECT task_id::text,status,revision,attempt,lease_epoch FROM core_tasks WHERE task_id=$1`, ch.TaskID).Scan(&t.ID, &st, &t.Revision, &t.Attempt, &t.LeaseEpoch)
	if e != nil {
		return coreaws.ExecutionFence{}, e
	}
	t.Status = st
	cc, e := NewCoreConfirmationStore(c.store).Get(ctx, id)
	if e != nil {
		return coreaws.ExecutionFence{}, e
	}
	var active bool
	var reservationAttempt uint32
	var reservationEpoch uint64
	var reservationRevision int64
	e = c.store.pool.QueryRow(ctx, `SELECT active,acquired_attempt,acquired_lease_epoch,task_revision FROM core_confirmation_reservations WHERE confirmation_id=$1`, id).Scan(&active, &reservationAttempt, &reservationEpoch, &reservationRevision)
	if errors.Is(e, pgx.ErrNoRows) {
		active = false
	} else if e != nil {
		return coreaws.ExecutionFence{}, e
	}
	return coreaws.ExecutionFence{Change: ch, Task: t, Confirmation: cc, Reservation: coreaws.Reservation{ConfirmationID: id, TaskID: ch.TaskID, Attempt: reservationAttempt, LeaseEpoch: reservationEpoch, TaskRevision: reservationRevision, Active: active}}, nil
}
func (c *CoreAWSChangeCoordinator) ReconcileChange(ctx context.Context, cmd coreaws.ReconcileChangeCommand) (coreaws.Change, error) {
	if _, e := uuid.Parse(cmd.ChangeID); e != nil {
		return coreaws.Change{}, coreaws.ErrInvalid
	}
	if _, e := uuid.Parse(cmd.ConfirmationID); e != nil {
		return coreaws.Change{}, coreaws.ErrInvalid
	}
	if _, e := uuid.Parse(cmd.TaskID); e != nil || cmd.Attempt == 0 || cmd.LeaseEpoch == 0 || cmd.ExpectedChangeRevision < 1 || cmd.ExpectedTaskRevision < 1 || cmd.ExpectedConfirmationRevision < 1 || cmd.ProviderToken == "" || cmd.ProviderRequestDigest == "" {
		return coreaws.Change{}, coreaws.ErrInvalid
	}
	now := c.now().UTC()
	tx, e := c.store.pool.Begin(ctx)
	if e != nil {
		return coreaws.Change{}, e
	}
	defer tx.Rollback(ctx)
	operationKey := uuid.NewSHA1(uuid.NameSpaceOID, []byte(cmd.ChangeID+"\x00"+cmd.ProviderToken+"\x00reconcile")).String()
	reqRaw, _ := json.Marshal(cmd)
	reqHash := sha256.Sum256(reqRaw)
	var replayRaw []byte
	if e = tx.QueryRow(ctx, `SELECT response_json FROM core_aws_replays WHERE operation='reconcile_change' AND idempotency_key=$1 AND request_hash=$2`, operationKey, hex.EncodeToString(reqHash[:])).Scan(&replayRaw); e == nil {
		var out coreaws.Change
		if json.Unmarshal(replayRaw, &out) == nil {
			return out, nil
		}
		return coreaws.Change{}, coreaws.ErrConflict
	}
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return coreaws.Change{}, e
	}
	if errors.Is(e, pgx.ErrNoRows) {
		var old string
		if qe := tx.QueryRow(ctx, `SELECT request_hash FROM core_aws_replays WHERE operation='reconcile_change' AND idempotency_key=$1`, operationKey).Scan(&old); qe == nil && old != hex.EncodeToString(reqHash[:]) {
			return coreaws.Change{}, coreaws.ErrIdempotencyConflict
		}
	}
	ch, e := NewCoreAWSStore(c.store).scanChange(tx.QueryRow(ctx, `SELECT change_id::text,plan_id::text,credential_id::text,task_id::text,confirmation_id::text,operation,status,stage,change_set_id,provider_request_digest,provider_token,revision,error_code,error_summary,created_at,updated_at FROM core_aws_changes WHERE change_id=$1 FOR UPDATE`, cmd.ChangeID))
	if e != nil {
		return coreaws.Change{}, e
	}
	if ch.TaskID != cmd.TaskID || ch.ConfirmationID != cmd.ConfirmationID || ch.Status != coreaws.ChangeRunning || ch.Stage != coreaws.StageReconciliationRequired || ch.Revision != cmd.ExpectedChangeRevision || ch.ProviderToken != cmd.ProviderToken || ch.ProviderRequestDigest != cmd.ProviderRequestDigest || ch.ChangeSetID != cmd.ProviderChangeSetID {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	var taskStatus string
	var taskRevision int64
	if e = tx.QueryRow(ctx, `SELECT status,revision FROM core_tasks WHERE task_id=$1 FOR UPDATE`, cmd.TaskID).Scan(&taskStatus, &taskRevision); e != nil || taskRevision != cmd.ExpectedTaskRevision || (taskStatus != string(coretask.StatusCanceled) && taskStatus != string(coretask.StatusSucceeded) && taskStatus != string(coretask.StatusFailed)) {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	var confirmationState string
	var confirmationRevision int64
	var consumedReleased bool
	if e = tx.QueryRow(ctx, `SELECT state,revision,consumed_released FROM core_confirmations WHERE confirmation_id=$1 AND task_id=$2 FOR UPDATE`, cmd.ConfirmationID, cmd.TaskID).Scan(&confirmationState, &confirmationRevision, &consumedReleased); e != nil || confirmationState != string(coreconfirmation.StateConsumed) || confirmationRevision != cmd.ExpectedConfirmationRevision || consumedReleased {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	var active bool
	var reservationAttempt uint32
	var reservationEpoch uint64
	if e = tx.QueryRow(ctx, `SELECT active,acquired_attempt,acquired_lease_epoch FROM core_confirmation_reservations WHERE confirmation_id=$1 AND task_id=$2 FOR UPDATE`, cmd.ConfirmationID, cmd.TaskID).Scan(&active, &reservationAttempt, &reservationEpoch); e != nil || !active || reservationAttempt != cmd.Attempt || reservationEpoch != cmd.LeaseEpoch {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	status, stage := coreaws.ChangeSucceeded, coreaws.StageSucceeded
	if !cmd.Success {
		status, stage = coreaws.ChangeFailed, coreaws.StageFailed
	}
	tag, e := tx.Exec(ctx, `UPDATE core_aws_changes SET status=$2,stage=$3,error_code=$4,error_summary=$5,revision=revision+1,updated_at=$6 WHERE change_id=$1 AND revision=$7`, cmd.ChangeID, status, stage, cmd.ErrorCode, cmd.ErrorSummary, now, cmd.ExpectedChangeRevision)
	if e != nil || tag.RowsAffected() != 1 {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	if _, e = tx.Exec(ctx, `UPDATE core_confirmation_reservations SET active=false WHERE confirmation_id=$1 AND task_id=$2 AND active=true`, cmd.ConfirmationID, cmd.TaskID); e != nil {
		return coreaws.Change{}, e
	}
	if _, e = tx.Exec(ctx, `UPDATE core_confirmations SET consumed_released=true,updated_at=$2 WHERE confirmation_id=$1 AND task_id=$3 AND state='consumed' AND consumed_released=false`, cmd.ConfirmationID, now, cmd.TaskID); e != nil {
		return coreaws.Change{}, e
	}
	if e = appendAWSAndTaskEvent(ctx, tx, cmd.ChangeID, cmd.TaskID, "reconciled", cmd.ExpectedChangeRevision+1, cmd.Attempt, taskStatus, now); e != nil {
		return coreaws.Change{}, e
	}
	out, e := NewCoreAWSStore(c.store).scanChange(tx.QueryRow(ctx, `SELECT change_id::text,plan_id::text,credential_id::text,task_id::text,confirmation_id::text,operation,status,stage,change_set_id,provider_request_digest,provider_token,revision,error_code,error_summary,created_at,updated_at FROM core_aws_changes WHERE change_id=$1`, cmd.ChangeID))
	if e != nil {
		return coreaws.Change{}, e
	}
	snap, _ := json.Marshal(out)
	if _, e = tx.Exec(ctx, `INSERT INTO core_aws_replays(operation,idempotency_key,request_hash,response_json) VALUES('reconcile_change',$1,$2,$3)`, operationKey, hex.EncodeToString(reqHash[:]), snap); e != nil {
		return coreaws.Change{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return coreaws.Change{}, e
	}
	return out, nil
}
