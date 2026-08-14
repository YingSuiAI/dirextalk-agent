package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CoreConfirmationStore struct{ store *Store }

func NewCoreConfirmationStore(s *Store) *CoreConfirmationStore {
	return &CoreConfirmationStore{store: s}
}

func (s *CoreConfirmationStore) SweepExpired(ctx context.Context, now time.Time, limit int) (int, error) {
	if s == nil || s.store == nil || limit < 1 || limit > 1000 || now.IsZero() {
		return 0, coreconfirmation.ErrInvalid
	}
	rows, err := s.store.pool.Query(ctx, `SELECT confirmation_id::text,task_id::text FROM core_confirmations
		WHERE state IN ('pending','confirmed') AND expires_at <= $1 ORDER BY expires_at,confirmation_id LIMIT $2`, now.UTC(), limit)
	if err != nil {
		return 0, err
	}
	type expiryCandidate struct{ confirmationID, taskID string }
	var candidates []expiryCandidate
	for rows.Next() {
		var candidate expiryCandidate
		if err = rows.Scan(&candidate.confirmationID, &candidate.taskID); err != nil {
			rows.Close()
			return 0, err
		}
		candidates = append(candidates, candidate)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	count := 0
	var recordConflict error
	for _, candidate := range candidates {
		expired, expireErr := s.sweepExpiredConfirmation(ctx, candidate.confirmationID, candidate.taskID, now.UTC())
		if expireErr != nil {
			if confirmationExpiryRecordConflict(expireErr) {
				if recordConflict == nil {
					recordConflict = fmt.Errorf("expire confirmation %s: %w", candidate.confirmationID, expireErr)
				}
				continue
			}
			return count, expireErr
		}
		if expired {
			count++
		}
	}
	return count, recordConflict
}

func confirmationExpiryRecordConflict(err error) bool {
	return errors.Is(err, coreconfirmation.ErrConflict) ||
		errors.Is(err, coreconfirmation.ErrRevisionConflict) ||
		errors.Is(err, coreconfirmation.ErrStale) ||
		errors.Is(err, cloudworker.ErrConflict) ||
		errors.Is(err, cloudworker.ErrRevisionConflict)
}

func (s *CoreConfirmationStore) sweepExpiredConfirmation(ctx context.Context, confirmationID, taskID string, now time.Time) (bool, error) {
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var taskStatus string
	if err = tx.QueryRow(ctx, `SELECT status FROM core_tasks WHERE task_id=$1 FOR UPDATE`, taskID).Scan(&taskStatus); err != nil {
		return false, err
	}
	confirmation, err := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, confirmationID))
	if err != nil {
		return false, err
	}
	if (confirmation.State != coreconfirmation.StatePending && confirmation.State != coreconfirmation.StateConfirmed) || confirmation.ExpiresAt.After(now) {
		return false, nil
	}
	if _, err = terminalizeExpiredTx(ctx, tx, s.store.instanceID, confirmation, now, coreconfirmation.ReasonExpired); err != nil {
		return false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (s *CoreConfirmationStore) ReadTargetBinding(ctx context.Context, id string) (coreconfirmation.Binding, error) {
	var domain, target string
	var raw []byte
	if err := s.store.pool.QueryRow(ctx, `SELECT operation_domain,target_id FROM core_confirmations WHERE confirmation_id=$1`, id).Scan(&domain, &target); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coreconfirmation.Binding{}, coreconfirmation.ErrNotFound
		}
		return coreconfirmation.Binding{}, err
	}
	if err := s.store.pool.QueryRow(ctx, `SELECT binding_json FROM core_confirmation_current_bindings WHERE operation_domain=$1 AND target_id=$2`, domain, target).Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coreconfirmation.Binding{}, coreconfirmation.ErrBindingUnavailable
		}
		return coreconfirmation.Binding{}, err
	}
	var b coreconfirmation.Binding
	if err := json.Unmarshal(raw, &b); err != nil {
		return coreconfirmation.Binding{}, coreconfirmation.ErrBindingUnavailable
	}
	return b, nil
}
func (s *CoreConfirmationStore) ReadCurrentTargetBinding(ctx context.Context, domain, target string) (coreconfirmation.Binding, error) {
	var raw []byte
	if e := s.store.pool.QueryRow(ctx, `SELECT binding_json FROM core_confirmation_current_bindings WHERE operation_domain=$1 AND target_id=$2`, domain, target).Scan(&raw); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return coreconfirmation.Binding{}, coreconfirmation.ErrBindingUnavailable
		}
		return coreconfirmation.Binding{}, e
	}
	var b coreconfirmation.Binding
	if e := json.Unmarshal(raw, &b); e != nil {
		return coreconfirmation.Binding{}, coreconfirmation.ErrBindingUnavailable
	}
	return b, nil
}
func (s *CoreConfirmationStore) UpsertCurrentTargetBinding(ctx context.Context, b coreconfirmation.Binding) error {
	n, e := b.Normalize()
	if e != nil {
		return coreconfirmation.ErrInvalid
	}
	raw, e := bindingJSON(n)
	if e != nil {
		return coreconfirmation.ErrInvalid
	}
	_, e = s.store.pool.Exec(ctx, `INSERT INTO core_confirmation_current_bindings(operation_domain,target_id,target_revision,binding_json,updated_at) VALUES($1,$2,$3,$4,clock_timestamp()) ON CONFLICT(operation_domain,target_id) DO UPDATE SET target_revision=EXCLUDED.target_revision,binding_json=EXCLUDED.binding_json,updated_at=clock_timestamp()`, n.OperationDomain, n.TargetID, n.TargetRevision, raw)
	return e
}
func bindingJSON(b coreconfirmation.Binding) ([]byte, error) { return json.Marshal(b) }

func scanConfirmation(row interface{ Scan(...any) error }) (coreconfirmation.Confirmation, error) {
	var c coreconfirmation.Confirmation
	var braw []byte
	var st string
	e := row.Scan(&c.ConfirmationID, &braw, &c.TaskID, &st, &c.Revision, &c.CreatedAt, &c.UpdatedAt, &c.ExpiresAt, &c.TerminalReason, &c.TerminalCode, &c.TerminalNote)
	if e != nil {
		return c, e
	}
	c.State = coreconfirmation.State(st)
	if e = json.Unmarshal(braw, &c.Binding); e != nil {
		return c, e
	}
	// Owner identity is part of the immutable authorization binding; project it
	// onto the public confirmation without duplicating a mutable owner column.
	c.OwnerID = c.Binding.OwnerID
	return c, nil
}

func projectCloudWorkerConfirmationTx(ctx context.Context, tx pgx.Tx, cur coreconfirmation.Confirmation, next cloudworker.ExecutionState, kind string, at time.Time) error {
	if cur.Binding.OperationDomain != cloudworker.OperationDomain {
		return nil
	}
	execution, err := scanCloudWorkerExecution(tx.QueryRow(ctx, cloudWorkerExecutionSelect+` WHERE execution_id=$1 FOR UPDATE`, cur.Binding.ExecutionID))
	if err != nil {
		return err
	}
	if execution.TaskID != cur.TaskID || execution.ConfirmationID != cur.ConfirmationID || execution.PlanID != cur.Binding.PlanID ||
		execution.PlanDigest != string(cur.Binding.PlanDigest) || execution.ExecutionDigest != string(cur.Binding.ExecutionDigest) {
		return coreconfirmation.ErrStale
	}
	transitioned, err := execution.Transition(next, at.UTC())
	if err != nil {
		return coreconfirmation.ErrConflict
	}
	if err = saveCloudWorkerExecutionTx(ctx, tx, execution, transitioned, kind); err != nil {
		return err
	}
	if next != cloudworker.StateRejected && next != cloudworker.StateExpired {
		return nil
	}
	plan, err := scanCloudWorkerPlan(tx.QueryRow(ctx, cloudWorkerPlanSelect+` WHERE plan_id=$1`, execution.PlanID))
	if err != nil || plan.ExecutionID != transitioned.ExecutionID || plan.TaskID != cur.TaskID || plan.ConfirmationID != cur.ConfirmationID {
		return coreconfirmation.ErrStale
	}
	return terminalizeCloudWorkerTurnTx(ctx, tx, cur, plan, transitioned, next, at.UTC())
}

// terminalizeCloudWorkerTurnTx closes the original Native Agent turn when an
// offer is rejected or expires before any provider mutation. The conversation
// receives an explicit durable assistant message and turn event; App caches
// are never expected to invent a terminal response from a stale offer card.
func terminalizeCloudWorkerTurnTx(
	ctx context.Context,
	tx pgx.Tx,
	confirmation coreconfirmation.Confirmation,
	plan cloudworker.Plan,
	execution cloudworker.Execution,
	terminal cloudworker.ExecutionState,
	at time.Time,
) error {
	if terminal != cloudworker.StateRejected && terminal != cloudworker.StateExpired && terminal != cloudworker.StateCanceled {
		return coreconfirmation.ErrStale
	}
	var turn struct {
		OwnerID, ConversationID, ProfileID, State string
		AccountGeneration, Revision, LastSequence uint64
	}
	if err := tx.QueryRow(ctx, `SELECT owner_id,account_generation,conversation_id::text,profile_id::text,state,revision,last_sequence
		FROM core_conversation_turns WHERE turn_id=$1 FOR UPDATE`, plan.TurnID).Scan(
		&turn.OwnerID, &turn.AccountGeneration, &turn.ConversationID, &turn.ProfileID, &turn.State, &turn.Revision, &turn.LastSequence); err != nil {
		return err
	}
	if turn.OwnerID != plan.OwnerID || turn.AccountGeneration != plan.AccountGeneration ||
		turn.ConversationID != plan.ConversationID || turn.ProfileID != plan.ModelAuthorization.ModelProfileID ||
		turn.State != string(core.TurnWaitingConfirmation) {
		return coreconfirmation.ErrStale
	}
	var conversationRevision uint64
	var conversationDeletedAt *time.Time
	if err := tx.QueryRow(ctx, `SELECT revision,deleted_at FROM core_conversations WHERE conversation_id=$1 FOR UPDATE`, plan.ConversationID).Scan(&conversationRevision, &conversationDeletedAt); err != nil {
		return err
	}
	// Conversation deletion makes the user-visible projection intentionally
	// unreachable, but it does not cancel the durable confirmation, task, or
	// Cloud Worker execution. Let those owner records reach their terminal
	// states without trying to append a message to a deleted conversation.
	if conversationDeletedAt != nil {
		return nil
	}
	binding, err := cloudworker.BindingForPlan(plan)
	if err != nil || !confirmation.Binding.Equal(binding) {
		return coreconfirmation.ErrStale
	}
	confirmationState := string(coreconfirmation.StateExpired)
	turnState, eventKind := string(core.TurnFailed), core.TurnEventError
	code := confirmation.TerminalReason
	if code == "" {
		code = coreconfirmation.ReasonExpired
	}
	summary := "Cloud Worker offer expired before authorization. No AWS resources were created."
	if terminal == cloudworker.StateRejected {
		confirmationState = string(coreconfirmation.StateRejected)
		turnState, eventKind = string(core.TurnCanceled), core.TurnEventCanceled
		code = coreconfirmation.ReasonUserRejected
		summary = "Cloud Worker offer was rejected. No AWS resources were created."
	} else if terminal == cloudworker.StateCanceled {
		turnState, eventKind = string(core.TurnCanceled), core.TurnEventCanceled
		code = "user_canceled"
		summary = "Cloud Worker task was canceled before dispatch. No AWS resources were created."
	}
	references := cloudWorkerReferences(plan, execution, uint64(confirmation.Revision+1), confirmationState)
	message := core.Message{
		ID:   deterministicCloudWorkerUUID("cloud-worker-offer-terminal-message", plan.ExecutionID+":"+string(terminal)),
		Role: core.RoleAssistant, Content: summary, ModelProfileID: turn.ProfileID,
		RelatedTaskIDs: []string{plan.TaskID}, RelatedPlanIDs: []string{plan.PlanID},
		References: references, CreatedAt: at,
	}
	if message.Validate() != nil {
		return coreconfirmation.ErrStale
	}
	var messageSequence int64
	if err = tx.QueryRow(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM core_messages WHERE conversation_id=$1`, plan.ConversationID).Scan(&messageSequence); err != nil {
		return err
	}
	if err = insertCloudWorkerMessageTx(ctx, tx, plan.ConversationID, messageSequence, message); err != nil {
		return err
	}
	event := core.TurnEvent{
		TurnID: plan.TurnID, Sequence: int64(turn.LastSequence + 1), Revision: turn.Revision + 1, Kind: eventKind,
		Message: &message, ConfirmationID: plan.ConfirmationID, ExecutionID: plan.ExecutionID,
		Status: string(terminal), RelatedTaskIDs: []string{plan.TaskID}, RelatedPlanIDs: []string{plan.PlanID},
		References: references, ErrorCode: code, ErrorSummary: summary, CreatedAt: at,
	}
	eventRaw, _ := json.Marshal(event)
	if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_turn_events(turn_id,sequence,kind,payload_json,created_at)
		VALUES($1,$2,$3,$4,$5)`, plan.TurnID, event.Sequence, string(event.Kind), eventRaw, at); err != nil {
		return err
	}
	turnUpdate, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET state=$2,terminal_code=$3,terminal_summary=$4,
		revision=revision+1,last_sequence=$5,lease_id=NULL,lease_expires_at=NULL,updated_at=$6
		WHERE turn_id=$1 AND state='waiting_confirmation' AND revision=$7`, plan.TurnID, turnState, code, summary,
		event.Sequence, at, turn.Revision)
	if err != nil || turnUpdate.RowsAffected() != 1 {
		return coreconfirmation.ErrConflict
	}
	conversationUpdate, err := tx.Exec(ctx, `UPDATE core_conversations SET revision=revision+1,updated_at=$2
		WHERE conversation_id=$1 AND revision=$3`, plan.ConversationID, at, conversationRevision)
	if err != nil || conversationUpdate.RowsAffected() != 1 {
		return coreconfirmation.ErrConflict
	}
	return nil
}
func terminalizeExpiredTx(ctx context.Context, tx pgx.Tx, ownerID any, cur coreconfirmation.Confirmation, at time.Time, reason string) (coreconfirmation.Confirmation, error) {
	if cur.Binding.OperationDomain == "workload:apply" || cur.Binding.OperationDomain == "workload:destroy" {
		status := "expired"
		if reason == coreconfirmation.ReasonUserRejected {
			status = "rejected"
		}
		if reason == "canceled" {
			status = "canceled"
		}
		return terminalizeWorkloadBeforeDispatchTx(ctx, tx, ownerID, cur, "expired", status, "failed", reason, reason, at)
	}
	confirmationUpdate, e := tx.Exec(ctx, `UPDATE core_confirmations SET state='expired',revision=revision+1,
		updated_at=$2,terminal_code=$3,terminal_reason=$3 WHERE confirmation_id=$1 AND state=$4 AND revision=$5`,
		cur.ConfirmationID, at, reason, cur.State, cur.Revision)
	if e != nil || confirmationUpdate.RowsAffected() != 1 {
		if e != nil {
			return cur, e
		}
		return cur, coreconfirmation.ErrConflict
	}
	var st string
	if e := tx.QueryRow(ctx, `SELECT status FROM core_tasks WHERE task_id=$1 FOR UPDATE`, cur.TaskID).Scan(&st); e == nil && (st == "waiting_user" || st == "queued" || st == "running") {
		taskUpdate, updateErr := tx.Exec(ctx, `UPDATE core_tasks SET status='failed',attempt=GREATEST(attempt,1),failure_code=$2,
			failure_summary=$3,lease_holder='',lease_expires_at=NULL,revision=revision+1,progress_sequence=progress_sequence+1,updated_at=$4
			WHERE task_id=$1 AND status=$5`, cur.TaskID, reason, reason, at, st)
		if updateErr != nil || taskUpdate.RowsAffected() != 1 {
			if updateErr != nil {
				return cur, updateErr
			}
			return cur, coreconfirmation.ErrConflict
		}
		eventInsert, insertErr := tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,error_code,error_summary,occurred_at)
			SELECT task_id,progress_sequence,$2,attempt,'failed',$3,$4,$5,$6 FROM core_tasks WHERE task_id=$1 AND status='failed'`,
			cur.TaskID, uuid.New(), reason, reason, reason, at)
		if insertErr != nil || eventInsert.RowsAffected() != 1 {
			if insertErr != nil {
				return cur, insertErr
			}
			return cur, coreconfirmation.ErrConflict
		}
		if st == "running" {
			concurrencyUpdate, updateErr := tx.Exec(ctx, `UPDATE core_task_runtime_concurrency SET running_count=GREATEST(0,running_count-1),revision=revision+1,updated_at=$1 WHERE singleton=true`, at)
			if updateErr != nil || concurrencyUpdate.RowsAffected() != 1 {
				if updateErr != nil {
					return cur, updateErr
				}
				return cur, coreconfirmation.ErrConflict
			}
		}
	}
	if cur.Binding.OperationDomain == "extension" {
		if e := rollbackExtensionLifecycleTx(ctx, tx, cur.ConfirmationID); e != nil {
			return cur, e
		}
	}
	if e := terminalizeConversationToolTx(ctx, tx, cur, "denied", reason, at, true); e != nil {
		return cur, e
	}
	if e := projectCloudWorkerConfirmationTx(ctx, tx, cur, cloudworker.StateExpired, "confirmation_expired", at); e != nil {
		return cur, e
	}
	cur.State, cur.Revision, cur.UpdatedAt, cur.TerminalCode, cur.TerminalReason = coreconfirmation.StateExpired, cur.Revision+1, at, reason, reason
	return cur, nil
}

// terminalizeWorkloadBeforeDispatchTx is deliberately narrower than generic
// confirmation termination: it can only touch the owner-scoped prepared,
// claimless workload before any provider dispatch. Actual snapshots are never
// written on this path.
func terminalizeWorkloadBeforeDispatchTx(ctx context.Context, tx pgx.Tx, ownerID any, cur coreconfirmation.Confirmation, confirmationState, operationState, taskState, code, summary string, at time.Time) (coreconfirmation.Confirmation, error) {
	cur, err := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, cur.ConfirmationID))
	if err != nil {
		return cur, err
	}
	if cur.State != coreconfirmation.StatePending && cur.State != coreconfirmation.StateConfirmed {
		return cur, coreconfirmation.ErrConflict
	}
	var taskStatus string
	if err = tx.QueryRow(ctx, `SELECT status FROM core_tasks WHERE task_id=$1 FOR UPDATE`, cur.TaskID).Scan(&taskStatus); err != nil {
		return cur, err
	}
	var operationID, opStatus, dispatchState, claim string
	if err = tx.QueryRow(ctx, `SELECT operation_id::text,status,dispatch_state,COALESCE(dispatch_claim::text,'') FROM core_workload_operations WHERE owner_id=$1 AND confirmation_id=$2 FOR UPDATE`, ownerID, cur.ConfirmationID).Scan(&operationID, &opStatus, &dispatchState, &claim); err != nil {
		return cur, coreconfirmation.ErrConflict
	}
	if taskStatus != "waiting_user" || opStatus != "waiting_user" || dispatchState != "prepared" || claim != "" {
		return cur, coreconfirmation.ErrConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE core_confirmations SET state=$2,terminal_code=$3,terminal_reason=$3,terminal_note=$4,revision=revision+1,updated_at=$5 WHERE confirmation_id=$1`, cur.ConfirmationID, confirmationState, code, summary, at); err != nil {
		return cur, err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_tasks SET status=$2,attempt=GREATEST(attempt,1),failure_code=$3,failure_summary=$4,lease_holder='',lease_expires_at=NULL,revision=revision+1,progress_sequence=progress_sequence+1,updated_at=$5 WHERE task_id=$1 AND status='waiting_user'`, cur.TaskID, taskState, code, summary, at); err != nil {
		return cur, err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_workload_operations SET status=$2,dispatch_state='terminal',failure_code=$3,failure_summary=$4,revision=revision+1,updated_at=$5 WHERE owner_id=$1 AND operation_id=$6 AND status='waiting_user' AND dispatch_state='prepared' AND dispatch_claim IS NULL`, ownerID, operationState, code, summary, at, operationID); err != nil {
		return cur, err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_confirmation_reservations SET active=false WHERE confirmation_id=$1`, cur.ConfirmationID); err != nil {
		return cur, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,error_code,error_summary,occurred_at) SELECT task_id,progress_sequence,$2,attempt,$3,'confirmation_terminal',$4,$5,$6 FROM core_tasks WHERE task_id=$1`, cur.TaskID, uuid.New(), taskState, code, summary, at); err != nil {
		return cur, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_workload_events(owner_id,operation_id,sequence,kind,status,message,at) SELECT $1,$2,COALESCE(MAX(sequence),0)+1,'terminal',$3,$4,$5 FROM core_workload_events WHERE owner_id=$1 AND operation_id=$2`, ownerID, operationID, operationState, summary, at); err != nil {
		return cur, err
	}
	cur.State, cur.Revision, cur.UpdatedAt, cur.TerminalCode, cur.TerminalReason, cur.TerminalNote = coreconfirmation.State(confirmationState), cur.Revision+1, at, code, code, summary
	return cur, nil
}

func (s *CoreConfirmationStore) staleAndReplay(ctx context.Context, tx pgx.Tx, cur coreconfirmation.Confirmation, op, key string, dig coreconfirmation.Digest, at time.Time) (coreconfirmation.Confirmation, error) {
	var e error
	cur, e = terminalizeExpiredTx(ctx, tx, s.store.instanceID, cur, at, coreconfirmation.ReasonStale)
	if e != nil {
		return cur, e
	}
	if e = s.putReplay(ctx, tx, op, key, dig, cur); e != nil {
		return cur, e
	}
	if e = tx.Commit(ctx); e != nil {
		return cur, e
	}
	return cur, coreconfirmation.ErrStale
}

func confirmationBindingMatchesTx(
	ctx context.Context,
	tx pgx.Tx,
	store *Store,
	cur coreconfirmation.Confirmation,
	resolve func(context.Context) (coreconfirmation.Binding, error),
	at time.Time,
) (bool, error) {
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT binding_json FROM core_confirmation_target_bindings WHERE confirmation_id=$1 FOR UPDATE`, cur.ConfirmationID).Scan(&raw); err != nil {
		return false, coreconfirmation.ErrBindingUnavailable
	}
	var immutable coreconfirmation.Binding
	if json.Unmarshal(raw, &immutable) != nil || !cur.Binding.Equal(immutable) {
		return false, nil
	}
	if resolve != nil {
		current, err := resolve(ctx)
		if err != nil {
			return false, coreconfirmation.ErrBindingUnavailable
		}
		if !cur.Binding.Equal(current) {
			return false, nil
		}
	}
	if cur.Binding.OperationDomain == "extension.execute" {
		var currentRaw []byte
		if err := tx.QueryRow(ctx, `SELECT binding_json FROM core_confirmation_current_bindings WHERE operation_domain=$1 AND target_id=$2 FOR UPDATE`, cur.Binding.OperationDomain, cur.Binding.TargetID).Scan(&currentRaw); err != nil {
			return false, coreconfirmation.ErrBindingUnavailable
		}
		var recorded coreconfirmation.Binding
		if json.Unmarshal(currentRaw, &recorded) != nil || !cur.Binding.Equal(recorded) {
			return false, nil
		}
		current, err := extensionExecutionBindingTx(ctx, tx, cur)
		if err != nil {
			return false, err
		}
		if !cur.Binding.Equal(current) {
			return false, nil
		}
		return true, nil
	}
	if resolve == nil {
		if err := tx.QueryRow(ctx, `SELECT binding_json FROM core_confirmation_current_bindings WHERE operation_domain=$1 AND target_id=$2 FOR UPDATE`, cur.Binding.OperationDomain, cur.Binding.TargetID).Scan(&raw); err != nil {
			return false, coreconfirmation.ErrBindingUnavailable
		}
		var current coreconfirmation.Binding
		if json.Unmarshal(raw, &current) != nil || !cur.Binding.Equal(current) {
			return false, nil
		}
	}
	return true, nil
}

// extensionExecutionBindingTx rehydrates the immutable execution proposal
// from the task payload and the currently installed version. It is evaluated
// while the confirmation transaction holds the target rows, so an update or
// uninstall cannot race owner confirmation.
func extensionExecutionBindingTx(ctx context.Context, tx pgx.Tx, cur coreconfirmation.Confirmation) (coreconfirmation.Binding, error) {
	var payloadRaw []byte
	if err := tx.QueryRow(ctx, `SELECT payload_json FROM core_tasks WHERE task_id=$1 FOR UPDATE`, cur.TaskID).Scan(&payloadRaw); err != nil {
		return coreconfirmation.Binding{}, coreconfirmation.ErrBindingUnavailable
	}
	var payload coretask.TaskPayload
	if json.Unmarshal(payloadRaw, &payload) != nil || payload.Extension == nil || payload.Extension.Operation != coretask.ExtensionOperationExecuteTool && payload.Extension.Operation != coretask.ExtensionOperationExecuteSkill {
		return coreconfirmation.Binding{}, coreconfirmation.ErrBindingUnavailable
	}
	var kind, transport, state, activeID string
	var enabled bool
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT kind,transport,state,revision,enabled,COALESCE(active_version_id::text,'') FROM core_extension_installations WHERE installation_id=$1 FOR UPDATE`, payload.Extension.InstallationID).Scan(&kind, &transport, &state, &revision, &enabled, &activeID); err != nil {
		return coreconfirmation.Binding{}, coreconfirmation.ErrBindingUnavailable
	}
	if state != string(coreextension.StateInstalled) || !enabled || revision != int64(payload.Extension.ExpectedRevision) || activeID == "" {
		return coreconfirmation.Binding{}, coreconfirmation.ErrStale
	}
	var versionRaw []byte
	if err := tx.QueryRow(ctx, `SELECT version_json FROM core_extension_versions WHERE installation_id=$1 AND version_id=$2 FOR UPDATE`, payload.Extension.InstallationID, activeID).Scan(&versionRaw); err != nil {
		return coreconfirmation.Binding{}, coreconfirmation.ErrBindingUnavailable
	}
	var version coreextension.VersionRecord
	if json.Unmarshal(versionRaw, &version) != nil {
		return coreconfirmation.Binding{}, coreconfirmation.ErrBindingUnavailable
	}
	if versionPin(version) != payload.Extension.Version {
		return coreconfirmation.Binding{}, coreconfirmation.ErrStale
	}
	installation := coreextension.Installation{ID: payload.Extension.InstallationID, Kind: coreextension.Kind(kind), Transport: coreextension.Transport(transport), Revision: revision}
	return extensionExecutionBinding(cur.Binding.OwnerID, cur.Binding.AccountGeneration, installation, version, payload.Extension.ToolName, payload.Extension.CanonicalInputJSON)
}

func (s *CoreConfirmationStore) replay(ctx context.Context, tx pgx.Tx, op, key string, dig coreconfirmation.Digest) (coreconfirmation.Confirmation, bool, error) {
	var d string
	var raw []byte
	e := tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_confirmation_replays WHERE operation=$1 AND idempotency_key=$2 FOR UPDATE`, op, key).Scan(&d, &raw)
	if errors.Is(e, pgx.ErrNoRows) {
		return coreconfirmation.Confirmation{}, false, nil
	}
	if e != nil {
		return coreconfirmation.Confirmation{}, false, e
	}
	if d != string(dig) {
		return coreconfirmation.Confirmation{}, false, coreconfirmation.ErrIdempotencyConflict
	}
	var c coreconfirmation.Confirmation
	e = json.Unmarshal(raw, &c)
	if e == nil {
		if c.State == coreconfirmation.StateExpired {
			if c.TerminalReason == coreconfirmation.ReasonStale {
				return c, true, coreconfirmation.ErrStale
			}
			return c, true, coreconfirmation.ErrExpired
		}
		if c.State == coreconfirmation.StateRejected {
			return c, true, coreconfirmation.ErrConflict
		}
	}
	return c, true, e
}
func (s *CoreConfirmationStore) putReplay(ctx context.Context, tx pgx.Tx, op, key string, dig coreconfirmation.Digest, c coreconfirmation.Confirmation) error {
	raw, _ := json.Marshal(c)
	_, e := tx.Exec(ctx, `INSERT INTO core_confirmation_replays(operation,idempotency_key,request_hash,response_json) VALUES($1,$2,$3,$4)`, op, key, string(dig), raw)
	return e
}

const confirmationSelect = `SELECT confirmation_id,binding_json,task_id,state,revision,created_at,updated_at,expires_at,terminal_reason,terminal_code,terminal_note FROM core_confirmations`

// terminalizeConversationToolTx is deliberately called while the confirmation
// and task rows are locked by their owning lifecycle mutation. It makes a
// rejected/expired/canceled approval incapable of later reaching a runner and
// releases the turn for the next model round.
func terminalizeConversationToolTx(ctx context.Context, tx pgx.Tx, cur coreconfirmation.Confirmation, attemptState, reason string, at time.Time, resumeTurn bool) error {
	if cur.Binding.OperationDomain != "conversation_tool" {
		return nil
	}
	var turnID string
	if err := tx.QueryRow(ctx, `SELECT turn_id::text FROM core_conversation_tool_attempts WHERE task_id=$1 AND attempt_id=$2 FOR UPDATE`, cur.TaskID, cur.Binding.TargetID).Scan(&turnID); err != nil {
		return err
	}
	attemptUpdate, err := tx.Exec(ctx, `UPDATE core_conversation_tool_attempts SET state=$2::text,result_json=jsonb_build_object('status',$2::text,'code',$3::text),updated_at=$4 WHERE task_id=$1 AND attempt_id=$5 AND state='waiting_confirmation'`, cur.TaskID, attemptState, reason, at.UTC(), cur.Binding.TargetID)
	if err != nil || attemptUpdate.RowsAffected() != 1 {
		if err != nil {
			return err
		}
		return coreconfirmation.ErrConflict
	}
	if resumeTurn {
		// A user response is a durable wake: no worker holds this turn lease while
		// waiting, so clearing it cannot race a provider dispatch.
		if _, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET state='accepted',lease_id=NULL,lease_expires_at=NULL,revision=revision+1,updated_at=$2 WHERE turn_id=$1 AND state='waiting_confirmation' AND cancel_requested=false`, turnID, at.UTC()); err != nil {
			return err
		}
	}
	return nil
}

// terminalizeConfirmationForTaskTx compensates pending/confirmed work while
// preserving consumed provider reservations for reconciliation.
func terminalizeConfirmationForTaskTx(ctx context.Context, tx pgx.Tx, taskID, reason string, at time.Time) error {
	return terminalizeConfirmationForTaskModeTx(ctx, tx, taskID, reason, at, true)
}

func terminalizeConfirmationForTaskModeTx(ctx context.Context, tx pgx.Tx, taskID, reason string, at time.Time, resumeConversationTurn bool) error {
	cur, err := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE task_id=$1 AND state IN ('pending','confirmed','consumed') FOR UPDATE`, taskID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if cur.State == coreconfirmation.StateConsumed {
		return nil
	}
	if _, err = tx.Exec(ctx, `UPDATE core_confirmations SET state='expired',revision=revision+1,terminal_code=$2,terminal_reason=$2,updated_at=$3 WHERE confirmation_id=$1 AND state IN ('pending','confirmed')`, cur.ConfirmationID, reason, at.UTC()); err != nil {
		return err
	}
	if cur.Binding.OperationDomain == "extension" {
		if err = rollbackExtensionLifecycleTx(ctx, tx, cur.ConfirmationID); err != nil {
			return err
		}
	}
	if err = terminalizeConversationToolTx(ctx, tx, cur, "canceled", reason, at, resumeConversationTurn); err != nil {
		return err
	}
	if cur.Binding.OperationDomain == "workload:apply" || cur.Binding.OperationDomain == "workload:destroy" {
		if _, err = tx.Exec(ctx, `UPDATE core_workload_operations SET status='canceled',revision=revision+1,failure_code='task_canceled',failure_summary='task canceled before dispatch',updated_at=$2 WHERE confirmation_id=$1 AND status='waiting_user'`, cur.ConfirmationID, at.UTC()); err != nil {
			return err
		}
	}
	return err
}
