package postgres

import (
	"context"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (c *CoreAWSChangeCoordinator) ClaimProviderMutation(ctx context.Context, cmd coreaws.ProviderMutationCommand) (coreaws.ExecutionFence, error) {
	tx, e := c.store.pool.Begin(ctx)
	if e != nil {
		return coreaws.ExecutionFence{}, e
	}
	defer tx.Rollback(ctx)
	if cmd.OperationKey == "" {
		cmd.OperationKey = uuid.NewSHA1(uuid.NameSpaceOID, []byte(cmd.ChangeID+"\x00"+string(cmd.Kind))).String()
	}
	var status, stage, operation, changeSetID, taskID, confID, token string
	var rev int64
	if e = tx.QueryRow(ctx, `SELECT status,stage,operation,change_set_id,task_id::text,confirmation_id::text,provider_token,revision FROM core_aws_changes WHERE change_id=$1 FOR UPDATE`, cmd.ChangeID).Scan(&status, &stage, &operation, &changeSetID, &taskID, &confID, &token, &rev); e != nil {
		return coreaws.ExecutionFence{}, coreaws.ErrNotFound
	}
	if taskID != cmd.TaskID || confID != cmd.ConfirmationID || rev != cmd.ExpectedChangeRevision || status != "running" {
		return coreaws.ExecutionFence{}, coreaws.ErrConflict
	}
	switch cmd.Kind {
	case coreaws.ProviderMutationCreate:
		if stage != string(coreaws.StageChangeSetCreating) || operation == string(coreaws.OperationDelete) {
			return coreaws.ExecutionFence{}, coreaws.ErrRevisionConflict
		}
	case coreaws.ProviderMutationExecute:
		if stage != string(coreaws.StageChangeSetReady) || changeSetID == "" || changeSetID != cmd.ProviderChangeSetID {
			return coreaws.ExecutionFence{}, coreaws.ErrRevisionConflict
		}
	case coreaws.ProviderMutationDelete:
		if operation != string(coreaws.OperationDelete) || (stage != string(coreaws.StageChangeSetCreating) && stage != string(coreaws.StageExecuting)) {
			return coreaws.ExecutionFence{}, coreaws.ErrRevisionConflict
		}
	default:
		return coreaws.ExecutionFence{}, coreaws.ErrInvalid
	}
	var ts, holder string
	var att uint32
	var lease uint64
	var tr int64
	var leaseExpires *time.Time
	if e = tx.QueryRow(ctx, `SELECT status,attempt,lease_epoch,revision,lease_holder,lease_expires_at FROM core_tasks WHERE task_id=$1 FOR UPDATE`, cmd.TaskID).Scan(&ts, &att, &lease, &tr, &holder, &leaseExpires); e != nil || ts != "running" || att != cmd.Attempt || lease != cmd.LeaseEpoch || tr != cmd.ExpectedTaskRevision || leaseExpires == nil || !leaseExpires.After(c.now().UTC()) {
		return coreaws.ExecutionFence{}, coreaws.ErrConflict
	}
	var cs string
	var cr int64
	var active bool
	var reservationAttempt uint32
	var reservationEpoch uint64
	var reservationRevision int64
	if e = tx.QueryRow(ctx, `SELECT state,revision FROM core_confirmations WHERE confirmation_id=$1 FOR UPDATE`, cmd.ConfirmationID).Scan(&cs, &cr); e != nil || cs != "consumed" || cr != cmd.ExpectedConfirmationRevision {
		return coreaws.ExecutionFence{}, coreaws.ErrConflict
	}
	if e = tx.QueryRow(ctx, `SELECT active,acquired_attempt,acquired_lease_epoch,task_revision FROM core_confirmation_reservations WHERE confirmation_id=$1 AND task_id=$2 FOR UPDATE`, cmd.ConfirmationID, cmd.TaskID).Scan(&active, &reservationAttempt, &reservationEpoch, &reservationRevision); e != nil || !active || reservationAttempt != cmd.Attempt || reservationEpoch != cmd.LeaseEpoch || reservationRevision != cmd.ExpectedTaskRevision {
		return coreaws.ExecutionFence{}, coreaws.ErrConflict
	}
	claimToken := cmd.ConfirmationID
	if token != "" && token != cmd.ConfirmationID {
		return coreaws.ExecutionFence{}, coreaws.ErrConflict
	}
	now := c.now().UTC()
	claimStage := stage
	if cmd.Kind == coreaws.ProviderMutationExecute || cmd.Kind == coreaws.ProviderMutationDelete {
		claimStage = string(coreaws.StageExecuting)
	}
	if _, e = tx.Exec(ctx, `UPDATE core_aws_changes SET provider_token=$2,stage=$3,revision=revision+1,updated_at=$4 WHERE change_id=$1 AND revision=$5`, cmd.ChangeID, claimToken, claimStage, now, cmd.ExpectedChangeRevision); e != nil {
		return coreaws.ExecutionFence{}, e
	}
	if e = appendAWSAndTaskEvent(ctx, tx, cmd.ChangeID, cmd.TaskID, "provider_claimed:"+string(cmd.Kind), cmd.ExpectedChangeRevision+1, cmd.Attempt, "running", now); e != nil {
		return coreaws.ExecutionFence{}, e
	}
	ch, e := NewCoreAWSStore(c.store).scanChange(tx.QueryRow(ctx, `SELECT change_id::text,plan_id::text,credential_id::text,task_id::text,confirmation_id::text,operation,status,stage,change_set_id,provider_request_digest,provider_token,revision,error_code,error_summary,created_at,updated_at FROM core_aws_changes WHERE change_id=$1`, cmd.ChangeID))
	if e != nil {
		return coreaws.ExecutionFence{}, e
	}
	out := coreaws.ExecutionFence{Change: ch, Task: coreaws.Task{ID: cmd.TaskID, Status: ts, Revision: tr, Attempt: att, LeaseEpoch: lease}, Confirmation: coreconfirmation.Confirmation{ConfirmationID: cmd.ConfirmationID, TaskID: cmd.TaskID, State: coreconfirmation.StateConsumed, Revision: cr}, Reservation: coreaws.Reservation{ConfirmationID: cmd.ConfirmationID, TaskID: cmd.TaskID, Attempt: reservationAttempt, LeaseEpoch: reservationEpoch, TaskRevision: reservationRevision, Active: active}}
	if e = tx.Commit(ctx); e != nil {
		return coreaws.ExecutionFence{}, e
	}
	return out, nil
}
func (c *CoreAWSChangeCoordinator) CommitProviderMutation(ctx context.Context, r coreaws.ProviderMutationResult) (coreaws.Change, error) {
	tx, e := c.store.pool.Begin(ctx)
	if e != nil {
		return coreaws.Change{}, e
	}
	defer tx.Rollback(ctx)
	cmd := r.Command
	if cmd.OperationKey == "" {
		cmd.OperationKey = uuid.NewSHA1(uuid.NameSpaceOID, []byte(cmd.ChangeID+"\x00"+string(cmd.Kind))).String()
		r.Command = cmd
	}
	ch, e := NewCoreAWSStore(c.store).scanChange(tx.QueryRow(ctx, `SELECT change_id::text,plan_id::text,credential_id::text,task_id::text,confirmation_id::text,operation,status,stage,change_set_id,provider_request_digest,provider_token,revision,error_code,error_summary,created_at,updated_at FROM core_aws_changes WHERE change_id=$1 FOR UPDATE`, cmd.ChangeID))
	if e != nil {
		return coreaws.Change{}, e
	}
	if ch.TaskID != cmd.TaskID || ch.ConfirmationID != cmd.ConfirmationID || ch.Revision != cmd.ExpectedChangeRevision || ch.Status != coreaws.ChangeRunning {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	switch cmd.Kind {
	case coreaws.ProviderMutationCreate:
		if ch.Stage != coreaws.StageChangeSetCreating || ch.Operation == coreaws.OperationDelete || (r.Success && !r.ResponseUncertain && r.ProviderChangeSetID == "") {
			return coreaws.Change{}, coreaws.ErrRevisionConflict
		}
	case coreaws.ProviderMutationExecute:
		if ch.Stage != coreaws.StageExecuting || ch.ChangeSetID == "" || ch.ChangeSetID != cmd.ProviderChangeSetID {
			return coreaws.Change{}, coreaws.ErrRevisionConflict
		}
	case coreaws.ProviderMutationDelete:
		if ch.Operation != coreaws.OperationDelete || ch.Stage != coreaws.StageExecuting {
			return coreaws.Change{}, coreaws.ErrRevisionConflict
		}
	default:
		return coreaws.Change{}, coreaws.ErrInvalid
	}
	var ts, cs string
	var att uint32
	var epoch uint64
	var trev, crev, rrev int64
	var active bool
	var expires *time.Time
	if e = tx.QueryRow(ctx, `SELECT status,attempt,lease_epoch,revision,lease_expires_at FROM core_tasks WHERE task_id=$1 FOR UPDATE`, cmd.TaskID).Scan(&ts, &att, &epoch, &trev, &expires); e != nil || ts != "running" || att != cmd.Attempt || epoch != cmd.LeaseEpoch || trev != cmd.ExpectedTaskRevision || expires == nil || !expires.After(c.now().UTC()) {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	if e = tx.QueryRow(ctx, `SELECT state,revision FROM core_confirmations WHERE confirmation_id=$1 AND task_id=$2 FOR UPDATE`, cmd.ConfirmationID, cmd.TaskID).Scan(&cs, &crev); e != nil || cs != "consumed" || crev != cmd.ExpectedConfirmationRevision {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	if e = tx.QueryRow(ctx, `SELECT active,task_revision FROM core_confirmation_reservations WHERE confirmation_id=$1 AND task_id=$2 FOR UPDATE`, cmd.ConfirmationID, cmd.TaskID).Scan(&active, &rrev); e != nil || !active || rrev != cmd.ExpectedTaskRevision {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	if r.ResponseUncertain {
		ch.Stage = coreaws.StageReconciling
	} else if !r.Success {
		ch.Stage = coreaws.StageFailed
		ch.ErrorCode = r.ErrorCode
		ch.ErrorSummary = r.ErrorSummary
	} else if cmd.Kind == coreaws.ProviderMutationCreate {
		ch.ChangeSetID = r.ProviderChangeSetID
		ch.Stage = coreaws.StageChangeSetReady
	} else {
		ch.Stage = coreaws.StageExecuting
	}
	now := c.now().UTC()
	ch.Revision++
	ch.UpdatedAt = now
	tag, e := tx.Exec(ctx, `UPDATE core_aws_changes SET status=$2,stage=$3,change_set_id=$4,revision=$5,error_code=$6,error_summary=$7,updated_at=$8 WHERE change_id=$1 AND revision=$9`, ch.ID, ch.Status, ch.Stage, ch.ChangeSetID, ch.Revision, ch.ErrorCode, ch.ErrorSummary, now, cmd.ExpectedChangeRevision)
	if e != nil || tag.RowsAffected() != 1 {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	if e = appendAWSAndTaskEvent(ctx, tx, ch.ID, cmd.TaskID, "provider_committed:"+string(cmd.Kind), ch.Revision, cmd.Attempt, "running", now); e != nil {
		return coreaws.Change{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return coreaws.Change{}, e
	}
	return ch, nil
}
func (c *CoreAWSChangeCoordinator) PersistChangeSetEvidence(ctx context.Context, cmd coreaws.ChangeSetEvidenceCommand) (coreaws.Change, error) {
	if cmd.ProviderChangeSetID == "" {
		return coreaws.Change{}, coreaws.ErrInvalid
	}
	tx, e := c.store.pool.Begin(ctx)
	if e != nil {
		return coreaws.Change{}, e
	}
	defer tx.Rollback(ctx)
	ch, e := NewCoreAWSStore(c.store).scanChange(tx.QueryRow(ctx, `SELECT change_id::text,plan_id::text,credential_id::text,task_id::text,confirmation_id::text,operation,status,stage,change_set_id,provider_request_digest,provider_token,revision,error_code,error_summary,created_at,updated_at FROM core_aws_changes WHERE change_id=$1 FOR UPDATE`, cmd.ChangeID))
	if e != nil {
		return coreaws.Change{}, e
	}
	if ch.TaskID != cmd.TaskID || ch.ConfirmationID != cmd.ConfirmationID || ch.Status != coreaws.ChangeRunning || ch.Revision != cmd.ExpectedChangeRevision || ch.Stage != coreaws.StageReconciling {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	var taskStatus, confirmationState string
	var taskAttempt uint32
	var taskRevision, confirmationRevision, reservationRevision int64
	var reservationActive bool
	if e = tx.QueryRow(ctx, `SELECT status,attempt,revision FROM core_tasks WHERE task_id=$1 FOR UPDATE`, cmd.TaskID).Scan(&taskStatus, &taskAttempt, &taskRevision); e != nil || taskStatus != "running" || taskRevision != cmd.ExpectedTaskRevision {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	if e = tx.QueryRow(ctx, `SELECT state,revision FROM core_confirmations WHERE confirmation_id=$1 AND task_id=$2 FOR UPDATE`, cmd.ConfirmationID, cmd.TaskID).Scan(&confirmationState, &confirmationRevision); e != nil || confirmationState != "consumed" || confirmationRevision != cmd.ExpectedConfirmationRevision {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	if e = tx.QueryRow(ctx, `SELECT active,task_revision FROM core_confirmation_reservations WHERE confirmation_id=$1 AND task_id=$2 FOR UPDATE`, cmd.ConfirmationID, cmd.TaskID).Scan(&reservationActive, &reservationRevision); e != nil || !reservationActive || reservationRevision != cmd.ExpectedTaskRevision {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	ch.ChangeSetID = cmd.ProviderChangeSetID
	ch.Stage = coreaws.StageChangeSetReady
	ch.Revision++
	ch.UpdatedAt = c.now().UTC()
	tag, e := tx.Exec(ctx, `UPDATE core_aws_changes SET change_set_id=$2,stage=$3,revision=$4,updated_at=$5 WHERE change_id=$1 AND revision=$6`, ch.ID, ch.ChangeSetID, ch.Stage, ch.Revision, ch.UpdatedAt, cmd.ExpectedChangeRevision)
	if e != nil || tag.RowsAffected() != 1 {
		return coreaws.Change{}, coreaws.ErrRevisionConflict
	}
	if e = appendAWSAndTaskEvent(ctx, tx, ch.ID, cmd.TaskID, "change_set_evidence", ch.Revision, taskAttempt, "running", ch.UpdatedAt); e != nil {
		return coreaws.Change{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return coreaws.Change{}, e
	}
	return ch, nil
}

// appendAWSAndTaskEvent advances both durable event streams in the same
// transaction as the fenced state transition.  The task sequence is allocated
// from its persisted cursor, so generic task consumers observe the AWS action.
func appendAWSAndTaskEvent(ctx context.Context, tx pgx.Tx, changeID, taskID, kind string, revision int64, attempt uint32, taskStatus string, at time.Time) error {
	if _, err := tx.Exec(ctx, `INSERT INTO core_aws_events(change_id,sequence,event_id,task_id,kind,revision,at) SELECT $1,COALESCE(MAX(sequence),0)+1,$2,$3,$4,$5,$6 FROM core_aws_events WHERE change_id=$1`, changeID, uuid.New(), taskID, kind, revision, at); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE core_tasks SET progress_sequence=progress_sequence+1 WHERE task_id=$1`, taskID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) SELECT task_id,progress_sequence,$2,attempt,$3,'aws_' || $4,$4,$5 FROM core_tasks WHERE task_id=$1`, taskID, uuid.New(), taskStatus, kind, at)
	return err
}

var _ coreaws.Repository = (*CoreAWSStore)(nil)

var _ coreaws.Repository = (*CoreAWSStore)(nil)
var _ coreaws.ChangeCoordinator = (*CoreAWSChangeCoordinator)(nil)
