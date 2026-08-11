package postgres

// This file is deliberately a single transaction boundary.  A conversation
// tool may not become observable as queued unless the turn, attempt, task and
// confirmation all describe the same immutable invocation.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func conversationArgsDigest(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func (s *CoreConversationStore) PrepareConversationTool(ctx context.Context, c core.PrepareToolCommand) (core.ToolAttempt, coretask.Task, coreconfirmation.Confirmation, error) {
	if s == nil || c.Lease.Turn.ID == "" || c.Lease.LeaseID == "" || c.Lease.Epoch == 0 || c.Call.Validate() != nil || !coretask.ValidUUID(c.IdempotencyKey) || c.ExpiresAt.IsZero() || !c.ExpiresAt.After(time.Now().UTC()) || len(c.SafeSummary) > coretask.MaxSummaryBytes {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrInvalid
	}
	args, err := canonicalJSON(c.CanonicalArguments, core.MaxToolArgumentsBytes)
	if err != nil || conversationArgsDigest(args) != c.ArgumentsDigest || c.Snapshot.Validate() != nil || !containsTool(c.Snapshot.ToolNames, c.Call.Name) {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "conversation_tool:"+c.IdempotencyKey); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	// A replay is accepted only for the same durable attempt; using the caller
	// idempotency key as a task create key makes changed replays conflict.
	var oldTask string
	if err = tx.QueryRow(ctx, `SELECT task_id::text FROM core_tasks WHERE create_idempotency_key=$1 AND task_kind='conversation_tool'`, c.IdempotencyKey).Scan(&oldTask); err == nil {
		var a core.ToolAttempt
		var state, storedCallID string
		if e := tx.QueryRow(ctx, `SELECT attempt_id::text,turn_id::text,task_id::text,COALESCE(confirmation_id::text,''),round,call_id::text,execution_id::text,tool_name,state,arguments_digest,safe_summary FROM core_conversation_tool_attempts WHERE task_id=$1`, oldTask).Scan(&a.ID, &a.TurnID, &a.TaskID, &a.ConfirmationID, &a.Round, &storedCallID, &a.ExecutionID, &a.ToolName, &state, &a.ArgumentsDigest, &a.SafeSummary); e != nil {
			return a, coretask.Task{}, coreconfirmation.Confirmation{}, e
		}
		a.State = state
		if a.TurnID != c.Lease.Turn.ID || storedCallID != a.ID || a.ArgumentsDigest != c.ArgumentsDigest {
			return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
		}
		t, e := NewCoreTaskStore(s.Store).taskTx(ctx, tx, oldTask, false)
		if e != nil {
			return a, t, coreconfirmation.Confirmation{}, e
		}
		if t.Spec.Payload.ConversationTool == nil || t.Spec.Payload.ConversationTool.CallID != c.Call.ID {
			return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
		}
		a.CallID = t.Spec.Payload.ConversationTool.CallID
		conf, e := NewCoreConfirmationStore(s.Store).Get(ctx, a.ConfirmationID)
		if e != nil {
			return a, t, conf, e
		}
		if e = tx.Commit(ctx); e != nil {
			return a, t, conf, e
		}
		return a, t, conf, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	var extensionRaw []byte
	var turnRevision uint64
	var state string
	if err = tx.QueryRow(ctx, `SELECT extension_snapshot_json,revision,state FROM core_conversation_turns WHERE turn_id=$1 AND lease_id=$2 AND lease_epoch=$3 FOR UPDATE`, c.Lease.Turn.ID, c.Lease.LeaseID, c.Lease.Epoch).Scan(&extensionRaw, &turnRevision, &state); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
	}
	if state != string(core.TurnRunning) || turnRevision != c.Lease.Turn.Revision {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
	}
	var snaps []core.ExtensionExecutionSnapshot
	if json.Unmarshal(extensionRaw, &snaps) != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
	}
	matched := false
	for _, x := range snaps {
		if x.InstallationID == c.Snapshot.InstallationID && x.VersionID == c.Snapshot.VersionID && x.ContentDigest == c.Snapshot.ContentDigest && x.ArtifactDigest == c.Snapshot.ArtifactDigest && x.ToolSchemaDigest == c.Snapshot.ToolSchemaDigest {
			matched = true
		}
	}
	if !matched {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
	}
	now := time.Now().UTC()
	attemptID, taskID, confID, executionID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	payload := coretask.ConversationToolTaskPayload{TurnID: c.Lease.Turn.ID, AttemptID: attemptID, Round: c.Round, CallID: c.Call.ID, ExtensionSnapshotDigest: c.Snapshot.ContentDigest, InstallationID: c.Snapshot.InstallationID, VersionID: c.Snapshot.VersionID, InstallationRevision: c.Snapshot.InstallationRevision, ToolName: c.Call.Name, ToolSchemaDigest: c.Snapshot.ToolSchemaDigest, ArgumentsDigest: c.ArgumentsDigest, ConfirmationID: confID, SafeSummary: c.SafeSummary}
	spec := coretask.TaskSpec{Kind: coretask.TaskKindConversationTool, Goal: "conversation tool " + c.Call.Name, ConversationID: c.Lease.Turn.ConversationID, IdempotencyKey: c.IdempotencyKey, Payload: coretask.TaskPayload{ConversationTool: &payload}, AvailableAt: now}
	raw, _ := json.Marshal(spec.Payload)
	if _, err = tx.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,conversation_id,create_idempotency_key,attachment_refs,extensions_json,knowledge_refs,timeout_seconds,status,attempt,progress_sequence,available_at,revision,created_at,updated_at,task_kind,payload_json) VALUES($1,$2,$3,$4,'[]','[]','[]',0,'waiting_user',1,1,$5,1,$5,$5,'conversation_tool',$6)`, taskID, spec.Goal, c.Lease.Turn.ConversationID, c.IdempotencyKey, now, raw); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_tool_attempts(turn_id,attempt_id,task_id,round,call_id,execution_id,extension_snapshot_digest,installation_id,version_id,installation_revision,tool_name,tool_schema_digest,arguments_digest,arguments_json,confirmation_id,state,safe_summary,created_at,updated_at,lease_epoch) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'waiting_confirmation',$16,$17,$17,1)`, c.Lease.Turn.ID, attemptID, taskID, c.Round, attemptID, executionID, c.Snapshot.ContentDigest, c.Snapshot.InstallationID, c.Snapshot.VersionID, c.Snapshot.InstallationRevision, c.Call.Name, c.Snapshot.ToolSchemaDigest, c.ArgumentsDigest, args, confID, c.SafeSummary, now); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	b := coreconfirmation.Binding{OperationDomain: "conversation_tool", TargetID: attemptID, TargetRevision: 1, SourceVersion: c.Snapshot.VersionID, SourceCommit: c.Snapshot.ArtifactDigest, ContentDigest: coreconfirmation.Digest(c.Snapshot.ContentDigest), ParameterDigest: coreconfirmation.Digest(c.ArgumentsDigest), NetworkDigest: coreconfirmation.Digest(c.Snapshot.NetworkBindingDigest), SecretGrantDigest: coreconfirmation.Digest(c.Snapshot.SecretBindingDigest)}
	br, be := b.Normalize()
	if be != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, be
	}
	b = br
	braw, _ := json.Marshal(b)
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmations(confirmation_id,operation_domain,target_id,target_revision,binding_json,task_id,state,revision,created_at,updated_at,expires_at) VALUES($1,'conversation_tool',$2,1,$3,$4,'pending',1,$5,$5,$6)`, confID, attemptID, braw, taskID, now, c.ExpiresAt.UTC()); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_target_bindings(confirmation_id,binding_json,updated_at) VALUES($1,$2,$3)`, confID, braw, now); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_current_bindings(operation_domain,target_id,target_revision,binding_json,updated_at) VALUES('conversation_tool',$1,1,$2,$3)`, attemptID, braw, now); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_conversation_turns SET state='waiting_confirmation',lease_id=NULL,lease_expires_at=NULL,revision=revision+1,updated_at=$2 WHERE turn_id=$1`, c.Lease.Turn.ID, now); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) VALUES($1,1,$2,1,'waiting_user','confirmation','waiting for owner confirmation',$3)`, taskID, uuid.New(), now); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	a := core.ToolAttempt{ID: attemptID, TurnID: c.Lease.Turn.ID, TaskID: taskID, ConfirmationID: confID, Round: c.Round, CallID: c.Call.ID, ExecutionID: executionID, ToolName: c.Call.Name, State: "waiting_confirmation", ArgumentsDigest: c.ArgumentsDigest, SafeSummary: c.SafeSummary}
	t := coretask.Task{ID: taskID, Spec: spec, Status: coretask.StatusWaitingUser, Attempt: 1, Revision: 1, CreatedAt: now, UpdatedAt: now, AvailableAt: now}
	conf := coreconfirmation.Confirmation{ConfirmationID: confID, Binding: b, TaskID: taskID, State: coreconfirmation.StatePending, Revision: 1, CreatedAt: now, UpdatedAt: now, ExpiresAt: c.ExpiresAt.UTC()}
	return a, t, conf, nil
}

func containsTool(in []string, want string) bool {
	for _, v := range in {
		if strings.TrimSpace(v) == want {
			return true
		}
	}
	return false
}

func (s *CoreConversationStore) ObserveConversationTool(ctx context.Context, turnID string) (core.ToolAttempt, error) {
	if s == nil || s.Store == nil || !coretask.ValidUUID(turnID) {
		return core.ToolAttempt{}, core.ErrInvalid
	}
	var a core.ToolAttempt
	var state string
	var result []byte
	var durableCallBound bool
	err := s.pool.QueryRow(ctx, `SELECT a.attempt_id::text,a.turn_id::text,a.task_id::text,COALESCE(a.confirmation_id::text,''),a.round,COALESCE(t.payload_json#>>'{conversation_tool,call_id}',''),a.execution_id::text,a.tool_name,a.state,a.arguments_digest,a.safe_summary,a.result_json,a.call_id=a.attempt_id FROM core_conversation_tool_attempts a JOIN core_tasks t ON t.task_id=a.task_id WHERE a.turn_id=$1 ORDER BY a.round DESC,a.created_at DESC LIMIT 1`, turnID).Scan(&a.ID, &a.TurnID, &a.TaskID, &a.ConfirmationID, &a.Round, &a.CallID, &a.ExecutionID, &a.ToolName, &state, &a.ArgumentsDigest, &a.SafeSummary, &result, &durableCallBound)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ToolAttempt{}, core.ErrConflict
	}
	if err != nil {
		return core.ToolAttempt{}, err
	}
	if !durableCallBound || strings.TrimSpace(a.CallID) == "" || len(a.CallID) > core.MaxToolCallIDBytes {
		return core.ToolAttempt{}, core.ErrConflict
	}
	a.State, a.Result = state, result
	return a, nil
}

func (s *CoreConversationStore) ResumeConversationTurn(ctx context.Context, turnID string) error {
	if s == nil || s.Store == nil || !coretask.ValidUUID(turnID) {
		return core.ErrInvalid
	}
	_, err := s.pool.Exec(ctx, `UPDATE core_conversation_turns SET state='accepted',dispatch_state='',dispatch_epoch=0,dispatch_result_json=NULL,lease_id=NULL,lease_expires_at=NULL,revision=revision+1,updated_at=clock_timestamp() WHERE turn_id=$1 AND state='waiting_confirmation' AND cancel_requested=false`, turnID)
	return err
}

// BeginConversationTool is the sole transition into provider dispatch.  It
// consumes the exact confirmation only after the queue has granted this task
// holder/attempt/epoch/revision fence.
func (s *CoreConversationStore) BeginConversationTool(ctx context.Context, task coretask.Task) (core.ToolAttempt, error) {
	if s == nil || task.Spec.Kind != coretask.TaskKindConversationTool || task.Spec.Payload.ConversationTool == nil || task.Status != coretask.StatusRunning || task.Lease == nil {
		return core.ToolAttempt{}, coretask.ErrInvalid
	}
	p := task.Spec.Payload.ConversationTool
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return core.ToolAttempt{}, err
	}
	defer tx.Rollback(ctx)
	var status, holder, attemptState, confirmationState string
	var attempt int
	var epoch, revision, dispatchedEpoch int64
	var expiry time.Time
	if err = tx.QueryRow(ctx, `SELECT status,attempt,lease_epoch,lease_holder,revision,lease_expires_at FROM core_tasks WHERE task_id=$1 FOR UPDATE`, task.ID).Scan(&status, &attempt, &epoch, &holder, &revision, &expiry); err != nil {
		return core.ToolAttempt{}, err
	}
	if status != "running" || attempt != int(task.Attempt) || epoch != int64(task.LeaseEpoch) || holder != task.Lease.Holder || revision != int64(task.Revision) || !expiry.After(time.Now().UTC()) {
		return core.ToolAttempt{}, coretask.ErrLeaseConflict
	}
	var a core.ToolAttempt
	var storedCallID string
	if err = tx.QueryRow(ctx, `SELECT attempt_id::text,turn_id::text,task_id::text,COALESCE(confirmation_id::text,''),round,call_id::text,execution_id::text,tool_name,state,arguments_digest,safe_summary,lease_epoch FROM core_conversation_tool_attempts WHERE task_id=$1 FOR UPDATE`, task.ID).Scan(&a.ID, &a.TurnID, &a.TaskID, &a.ConfirmationID, &a.Round, &storedCallID, &a.ExecutionID, &a.ToolName, &attemptState, &a.ArgumentsDigest, &a.SafeSummary, &dispatchedEpoch); err != nil {
		return a, err
	}
	a.CallID = p.CallID
	a.State = attemptState
	if a.ID != p.AttemptID || storedCallID != a.ID || a.TurnID != p.TurnID || a.ConfirmationID != p.ConfirmationID || strings.TrimSpace(a.CallID) == "" || len(a.CallID) > core.MaxToolCallIDBytes || a.ArgumentsDigest != p.ArgumentsDigest || (attemptState != "waiting_confirmation" && attemptState != "dispatched") {
		return a, coretask.ErrLeaseConflict
	}
	if err = tx.QueryRow(ctx, `SELECT state FROM core_confirmations WHERE confirmation_id=$1 AND task_id=$2 FOR UPDATE`, a.ConfirmationID, task.ID).Scan(&confirmationState); err != nil {
		return a, err
	}
	if attemptState == "dispatched" {
		if confirmationState != "consumed" || dispatchedEpoch <= 0 || dispatchedEpoch >= int64(task.LeaseEpoch) {
			return a, coretask.ErrLeaseConflict
		}
		return a, core.ErrToolDispatchStarted
	}
	if confirmationState != "confirmed" {
		return a, coretask.ErrLeaseConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE core_confirmations SET state='consumed',revision=revision+1,updated_at=clock_timestamp() WHERE confirmation_id=$1 AND state='confirmed'`, a.ConfirmationID); err != nil {
		return a, err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_conversation_tool_attempts SET state='dispatched',lease_epoch=$2,updated_at=clock_timestamp() WHERE task_id=$1 AND state='waiting_confirmation'`, task.ID, task.LeaseEpoch); err != nil {
		return a, err
	}
	if err = tx.Commit(ctx); err != nil {
		return a, err
	}
	a.State = "dispatched"
	return a, nil
}

// FinishConversationTool atomically owns both generic task terminal state and
// the attempt terminal record.  A lost lease can never leave a successful
// provider dispatch eligible for a second execution.
func (s *CoreConversationStore) FinishConversationTool(ctx context.Context, task coretask.Task, state string, result json.RawMessage, code, summary string) error {
	if s == nil || task.Spec.Kind != coretask.TaskKindConversationTool || task.Spec.Payload.ConversationTool == nil || task.Lease == nil || (state != "completed" && state != "failed" && state != "uncertain") || (state == "completed" && (!json.Valid(result) || len(result) == 0)) {
		return coretask.ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	status := "succeeded"
	attemptState := "completed"
	if state == "failed" {
		status = "failed"
		attemptState = "denied"
	}
	if state == "uncertain" {
		status = "failed"
		attemptState = "uncertain"
		code = "tool_uncertain"
		summary = "tool dispatch outcome is unknown"
	}
	now := time.Now().UTC()
	tag, err := tx.Exec(ctx, `UPDATE core_tasks SET status=$1,result_json=$2,failure_code=$3,failure_summary=$4,lease_holder='',lease_expires_at=NULL,revision=revision+1,updated_at=$5 WHERE task_id=$6 AND status='running' AND attempt=$7 AND lease_epoch=$8 AND revision=$9 AND lease_expires_at>$5`, status, result, code, summary, now, task.ID, task.Attempt, task.LeaseEpoch, task.Revision)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return coretask.ErrLeaseConflict
	}
	var turnID string
	if err = tx.QueryRow(ctx, `UPDATE core_conversation_tool_attempts SET state=$2,result_json=CASE WHEN $2 IN ('completed','denied','canceled') THEN CASE WHEN $3::jsonb IS NULL THEN jsonb_build_object('status',$2,'code',$4::text) ELSE $3::jsonb END ELSE NULL END,updated_at=$5 WHERE task_id=$1 AND state='dispatched' RETURNING turn_id::text`, task.ID, attemptState, result, code, now).Scan(&turnID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coretask.ErrLeaseConflict
		}
		return err
	}
	if turnID != task.Spec.Payload.ConversationTool.TurnID {
		return coretask.ErrLeaseConflict
	}
	if state == "uncertain" {
		var lastSequence int64
		if err = tx.QueryRow(ctx, `UPDATE core_conversation_turns SET state='failed',terminal_code=$2,terminal_summary=$3,revision=revision+1,updated_at=$4 WHERE turn_id=$1 AND state='waiting_confirmation' RETURNING last_sequence`, turnID, code, summary, now).Scan(&lastSequence); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return coretask.ErrLeaseConflict
			}
			return err
		}
		if err = insertTurnEventTx(ctx, tx, turnID, lastSequence+1, core.TurnEvent{Kind: core.TurnEventError, ErrorCode: code, ErrorSummary: summary}, now); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE core_tasks SET progress_sequence=progress_sequence+1 WHERE task_id=$1`, task.ID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,error_code,error_summary,occurred_at) SELECT task_id,progress_sequence,$2,attempt,status,'conversation_tool_terminal',$3,$4,clock_timestamp() FROM core_tasks WHERE task_id=$1`, task.ID, uuid.New(), code, summary); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_task_runtime_concurrency SET running_count=GREATEST(0,running_count-1),revision=revision+1,updated_at=clock_timestamp() WHERE singleton=true`); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}
