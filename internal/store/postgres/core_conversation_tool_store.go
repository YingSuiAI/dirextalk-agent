package postgres

// This file is deliberately a single transaction boundary.  A conversation
// tool may not become observable as queued unless the turn, attempt, task and
// optional confirmation all describe the same immutable invocation.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
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
		if e := validateConversationToolWaitingEventTx(ctx, tx, a); e != nil {
			return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, e
		}
		var conf coreconfirmation.Confirmation
		if a.ConfirmationID != "" {
			conf, e = NewCoreConfirmationStore(s.Store).Get(ctx, a.ConfirmationID)
			if e != nil {
				return a, t, conf, e
			}
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
	var lastSequence int64
	var state string
	if err = tx.QueryRow(ctx, `SELECT extension_snapshot_json,revision,last_sequence,state FROM core_conversation_turns WHERE turn_id=$1 AND lease_id=$2 AND lease_epoch=$3 FOR UPDATE`, c.Lease.Turn.ID, c.Lease.LeaseID, c.Lease.Epoch).Scan(&extensionRaw, &turnRevision, &lastSequence, &state); err != nil {
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
	// Seal the exact version's execution lane into the task payload now. The
	// scheduler must never reclassify this task from a later installation or
	// version projection while claiming it.
	var versionRaw []byte
	if err = tx.QueryRow(ctx, `SELECT version_json FROM core_extension_versions WHERE installation_id=$1 AND version_id=$2`, c.Snapshot.InstallationID, c.Snapshot.VersionID).Scan(&versionRaw); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
	}
	var version coreextension.VersionRecord
	if json.Unmarshal(versionRaw, &version) != nil || version.ContentDigest != c.Snapshot.ContentDigest || version.ArtifactDigest != c.Snapshot.ArtifactDigest {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
	}
	executionTarget, targetErr := extensionExecutionTarget(version.Execution)
	if targetErr != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
	}
	now := time.Now().UTC()
	attemptID, taskID, executionID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	confID := ""
	if c.Snapshot.RequiresConfirmation {
		confID = uuid.NewString()
	}
	payload := coretask.ConversationToolTaskPayload{TurnID: c.Lease.Turn.ID, AttemptID: attemptID, Round: c.Round, CallID: c.Call.ID, ExtensionSnapshotDigest: c.Snapshot.ContentDigest, InstallationID: c.Snapshot.InstallationID, VersionID: c.Snapshot.VersionID, InstallationRevision: c.Snapshot.InstallationRevision, ToolName: c.Call.Name, ToolSchemaDigest: c.Snapshot.ToolSchemaDigest, ArgumentsDigest: c.ArgumentsDigest, ConfirmationID: confID, SafeSummary: c.SafeSummary, ExecutionTarget: executionTarget, ReadOnly: c.Snapshot.ReadOnly}
	spec := coretask.TaskSpec{Kind: coretask.TaskKindConversationTool, Goal: "conversation tool " + c.Call.Name, ConversationID: c.Lease.Turn.ConversationID, IdempotencyKey: c.IdempotencyKey, Payload: coretask.TaskPayload{ConversationTool: &payload}, AvailableAt: now}
	raw, _ := json.Marshal(spec.Payload)
	taskStatus := coretask.StatusWaitingUser
	if !c.Snapshot.RequiresConfirmation {
		taskStatus = coretask.StatusQueued
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,conversation_id,create_idempotency_key,attachment_refs,extensions_json,knowledge_refs,timeout_seconds,status,attempt,progress_sequence,available_at,revision,created_at,updated_at,task_kind,payload_json) VALUES($1,$2,$3,$4,'[]','[]','[]',0,$7,1,1,$5,1,$5,$5,'conversation_tool',$6)`, taskID, spec.Goal, c.Lease.Turn.ConversationID, c.IdempotencyKey, now, raw, string(taskStatus)); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_tool_attempts(turn_id,attempt_id,task_id,round,call_id,execution_id,extension_snapshot_digest,installation_id,version_id,installation_revision,tool_name,tool_schema_digest,arguments_digest,arguments_json,confirmation_id,state,safe_summary,created_at,updated_at,lease_epoch) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'waiting_confirmation',$16,$17,$17,1)`, c.Lease.Turn.ID, attemptID, taskID, c.Round, attemptID, executionID, c.Snapshot.ContentDigest, c.Snapshot.InstallationID, c.Snapshot.VersionID, c.Snapshot.InstallationRevision, c.Call.Name, c.Snapshot.ToolSchemaDigest, c.ArgumentsDigest, args, nullableUUIDPG(confID), c.SafeSummary, now); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	var binding coreconfirmation.Binding
	var waitingEvent core.TurnEvent
	nextSequence := lastSequence
	if c.Snapshot.RequiresConfirmation {
		binding = coreconfirmation.Binding{OperationDomain: "conversation_tool", TargetID: attemptID, TargetRevision: 1, SourceVersion: c.Snapshot.VersionID, SourceCommit: c.Snapshot.ArtifactDigest, ContentDigest: coreconfirmation.Digest(c.Snapshot.ContentDigest), ParameterDigest: coreconfirmation.Digest(c.ArgumentsDigest), NetworkDigest: coreconfirmation.Digest(c.Snapshot.NetworkBindingDigest), SecretGrantDigest: coreconfirmation.Digest(c.Snapshot.SecretBindingDigest)}
		binding, err = binding.Normalize()
		if err != nil {
			return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
		}
		braw, _ := json.Marshal(binding)
		if _, err = tx.Exec(ctx, `INSERT INTO core_confirmations(confirmation_id,operation_domain,target_id,target_revision,binding_json,task_id,state,revision,created_at,updated_at,expires_at) VALUES($1,'conversation_tool',$2,1,$3,$4,'pending',1,$5,$5,$6)`, confID, attemptID, braw, taskID, now, c.ExpiresAt.UTC()); err != nil {
			return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_target_bindings(confirmation_id,binding_json,updated_at) VALUES($1,$2,$3)`, confID, braw, now); err != nil {
			return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_current_bindings(operation_domain,target_id,target_revision,binding_json,updated_at) VALUES('conversation_tool',$1,1,$2,$3)`, attemptID, braw, now); err != nil {
			return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
		}
		waitingEvent, err = core.NewWaitingConfirmationTurnEvent(confID, executionID)
		if err != nil {
			return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrInvalid
		}
		nextSequence++
		waitingEvent.TurnID, waitingEvent.Sequence, waitingEvent.Revision, waitingEvent.CreatedAt = c.Lease.Turn.ID, nextSequence, turnRevision+1, now
	}
	turnUpdate, updateErr := tx.Exec(ctx, `UPDATE core_conversation_turns
		SET state='waiting_confirmation',lease_id=NULL,lease_expires_at=NULL,revision=revision+1,last_sequence=$6,updated_at=$2
		WHERE turn_id=$1 AND state='running' AND lease_id=$3 AND lease_epoch=$4 AND revision=$5`,
		c.Lease.Turn.ID, now, c.Lease.LeaseID, c.Lease.Epoch, turnRevision, nextSequence)
	if updateErr != nil || turnUpdate.RowsAffected() != 1 {
		if updateErr != nil {
			return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, updateErr
		}
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
	}
	if c.Snapshot.RequiresConfirmation {
		waitingRaw, _ := json.Marshal(waitingEvent)
		if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_turn_events(turn_id,sequence,kind,payload_json,created_at)
			VALUES($1,$2,$3,$4,$5)`, waitingEvent.TurnID, waitingEvent.Sequence, string(waitingEvent.Kind), waitingRaw, now); err != nil {
			return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
		}
	}
	phase, message := "confirmation", "waiting for owner confirmation"
	if !c.Snapshot.RequiresConfirmation {
		phase, message = "queued", "local sandbox task queued"
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) VALUES($1,1,$2,1,$3,$4,$5,$6)`, taskID, uuid.New(), string(taskStatus), phase, message, now); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	a := core.ToolAttempt{ID: attemptID, TurnID: c.Lease.Turn.ID, TaskID: taskID, ConfirmationID: confID, Round: c.Round, CallID: c.Call.ID, ExecutionID: executionID, ToolName: c.Call.Name, State: "waiting_confirmation", ArgumentsDigest: c.ArgumentsDigest, SafeSummary: c.SafeSummary}
	t := coretask.Task{ID: taskID, Spec: spec, Status: taskStatus, Attempt: 1, Revision: 1, CreatedAt: now, UpdatedAt: now, AvailableAt: now}
	conf := coreconfirmation.Confirmation{}
	if c.Snapshot.RequiresConfirmation {
		conf = coreconfirmation.Confirmation{ConfirmationID: confID, Binding: binding, TaskID: taskID, State: coreconfirmation.StatePending, Revision: 1, CreatedAt: now, UpdatedAt: now, ExpiresAt: c.ExpiresAt.UTC()}
	}
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

func validateConversationToolWaitingEventTx(ctx context.Context, tx pgx.Tx, attempt core.ToolAttempt) error {
	rows, err := tx.Query(ctx, `SELECT payload_json FROM core_conversation_turn_events
		WHERE turn_id=$1 AND kind=$2 ORDER BY sequence`, attempt.TurnID, string(core.TurnEventWaitingConfirmation))
	if err != nil {
		return err
	}
	defer rows.Close()
	matches := 0
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return err
		}
		var event core.TurnEvent
		if json.Unmarshal(raw, &event) != nil || event.ValidateWaitingConfirmationAuthority() != nil ||
			event.TurnID != attempt.TurnID || event.Sequence <= 0 || event.Revision == 0 {
			return core.ErrConflict
		}
		if event.ConfirmationID == attempt.ConfirmationID && event.ExecutionID == attempt.ExecutionID {
			matches++
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	want := 1
	if attempt.ConfirmationID == "" {
		want = 0
	}
	if matches != want {
		return core.ErrConflict
	}
	return nil
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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var state string
	var lastSequence int64
	var dispatchRaw []byte
	if err = tx.QueryRow(ctx, `SELECT state,last_sequence,dispatch_result_json FROM core_conversation_turns WHERE turn_id=$1 AND state IN ('accepted','waiting_confirmation') AND cancel_requested=false AND dispatch_state='completed' FOR UPDATE`, turnID).Scan(&state, &lastSequence, &dispatchRaw); errors.Is(err, pgx.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	var attempt core.ToolAttempt
	var resultRaw []byte
	if err = tx.QueryRow(ctx, `SELECT a.attempt_id::text,a.task_id::text,a.round,t.payload_json#>>'{conversation_tool,call_id}',a.execution_id::text,a.tool_name,a.state,a.safe_summary,a.result_json
		FROM core_conversation_tool_attempts a JOIN core_tasks t ON t.task_id=a.task_id
		WHERE a.turn_id=$1 AND a.state IN ('completed','denied','canceled','uncertain') ORDER BY a.round DESC,a.created_at DESC LIMIT 1`, turnID).
		Scan(&attempt.ID, &attempt.TaskID, &attempt.Round, &attempt.CallID, &attempt.ExecutionID, &attempt.ToolName, &attempt.State, &attempt.SafeSummary, &resultRaw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.ErrConflict
		}
		return err
	}
	attempt.TurnID, attempt.Result = turnID, resultRaw
	envelope, err := loadDurableTurnDispatchEnvelope(dispatchRaw)
	if err != nil {
		return err
	}
	callIndex := -1
	for index := range envelope.Calls {
		if envelope.Calls[index].CallID == attempt.CallID {
			callIndex = index
			break
		}
	}
	calls := durableTurnModelCalls(envelope.Result)
	if callIndex < 0 || callIndex >= len(calls) || calls[callIndex].Name != attempt.ToolName {
		return core.ErrConflict
	}
	authority, err := conversationToolEventAuthorityTx(ctx, tx, turnID, attempt.CallID)
	if err != nil || authority.state == conversationToolCallAbsent || authority.call.Name != attempt.ToolName {
		if err != nil {
			return err
		}
		return core.ErrConflict
	}
	now := time.Now().UTC()
	resultSequence := authority.resultSequence
	references, referenceErr := conversationToolAttemptReferences(attempt)
	if referenceErr != nil {
		return core.ErrConflict
	}
	var result core.ToolResult
	if json.Unmarshal(attempt.Result, &result) != nil || result.CallID != attempt.CallID || result.ToolName != attempt.ToolName ||
		!reflect.DeepEqual(result.RelatedTaskIDs, []string{attempt.TaskID}) {
		return core.ErrConflict
	}
	result.References = references
	if result.ValidateObservation() != nil {
		return core.ErrConflict
	}
	if authority.state != conversationToolCallTerminal {
		// Durable local/remote calls carry their dispatch fence in the task
		// attempt ledger. Their turn event remains pending until that terminal
		// attempt is projected back as the tool result.
		if authority.state != conversationToolCallPending {
			return core.ErrConflict
		}
		if err = insertTurnEventTx(ctx, tx, turnID, lastSequence+1, core.TurnEvent{Kind: core.TurnEventToolResult, ToolResult: &result}, now); err != nil {
			return err
		}
		lastSequence++
		resultSequence = lastSequence
	} else if authority.result == nil || !reflect.DeepEqual(*authority.result, result) {
		return core.ErrConflict
	}
	if resultSequence <= 0 {
		return core.ErrConflict
	}
	stalled, err := recordConversationProgressTx(ctx, tx, turnID, result.CallID, result, resultSequence, now)
	if err != nil {
		return err
	}
	entry := &envelope.Calls[callIndex]
	if entry.State == durableTurnToolCallTerminal {
		if entry.ResultDigest != durableTurnToolResultDigest(result) {
			return core.ErrConflict
		}
	} else {
		if entry.State != durableTurnToolCallPending && entry.State != durableTurnToolCallDispatched {
			return core.ErrConflict
		}
		entry.State, entry.ResultDigest = durableTurnToolCallTerminal, durableTurnToolResultDigest(result)
	}
	dispatchRaw, _ = json.Marshal(envelope)
	if stalled {
		var turn core.Turn
		if err = s.scanTurn(ctx, tx, turnID, &turn); err != nil {
			return err
		}
		if err = prepareTurnNoProgressFinalizationTx(ctx, tx, turn, lastSequence, now); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	revisionIncrement := 0
	if state == string(core.TurnWaitingConfirmation) {
		revisionIncrement = 1
	}
	if _, err = tx.Exec(ctx, `UPDATE core_conversation_turns SET state='accepted',lease_id=NULL,lease_expires_at=NULL,revision=revision+$2,last_sequence=$3,dispatch_result_json=$4,updated_at=$5 WHERE turn_id=$1`, turnID, revisionIncrement, lastSequence, dispatchRaw, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func conversationToolAttemptReferences(attempt core.ToolAttempt) ([]core.Reference, error) {
	if attempt.ToolName != coreextension.BuiltinLocalSandboxToolName || attempt.State != "completed" || len(attempt.Result) == 0 {
		return nil, nil
	}
	var stored core.ToolResult
	if json.Unmarshal(attempt.Result, &stored) != nil || stored.ValidateObservation() != nil {
		return nil, core.ErrConflict
	}
	if len(stored.References) == 0 || len(stored.References) > core.MaxReferences {
		return nil, core.ErrConflict
	}
	for _, reference := range stored.References {
		if reference.Kind != "execution_artifact" || reference.Validate() != nil {
			return nil, core.ErrConflict
		}
	}
	return append([]core.Reference(nil), stored.References...), nil
}

func localSandboxResultReferences(raw json.RawMessage) ([]core.Reference, error) {
	var payload struct {
		Structured struct {
			Artifacts []struct {
				AccountGeneration uint64  `json:"account_generation"`
				RecordKind        string  `json:"record_kind"`
				ArtifactID        string  `json:"artifact_id"`
				ExecutionID       string  `json:"execution_id"`
				Name              string  `json:"name"`
				MediaType         string  `json:"media_type"`
				SizeBytes         *uint64 `json:"size_bytes"`
				SHA256            string  `json:"sha256"`
			} `json:"artifacts"`
		} `json:"structuredContent"`
	}
	if json.Unmarshal(raw, &payload) != nil || len(payload.Structured.Artifacts) == 0 || len(payload.Structured.Artifacts) > core.MaxReferences {
		return nil, core.ErrConflict
	}
	result := make([]core.Reference, 0, len(payload.Structured.Artifacts))
	for _, artifact := range payload.Structured.Artifacts {
		reference := core.Reference{Kind: "execution_artifact", AccountGeneration: artifact.AccountGeneration,
			RecordKind: artifact.RecordKind, ArtifactID: artifact.ArtifactID, ExecutionID: artifact.ExecutionID,
			Name: artifact.Name, MediaType: artifact.MediaType, SizeBytes: artifact.SizeBytes, SHA256: artifact.SHA256}
		if reference.Validate() != nil {
			return nil, core.ErrConflict
		}
		result = append(result, reference)
	}
	return result, nil
}

func conversationToolTerminalResult(task coretask.Task, state string, raw json.RawMessage, code, summary string) (core.ToolResult, error) {
	payload := task.Spec.Payload.ConversationTool
	if payload == nil {
		return core.ToolResult{}, coretask.ErrInvalid
	}
	content := strings.TrimSpace(summary)
	observationSummary := content
	outcome := core.ToolOutcomeFatal
	mutation := core.ToolMutationNone
	stateChanged := false
	var resultReferences []core.Reference
	if !payload.ReadOnly {
		outcome = core.ToolOutcomeUnknownMutation
		mutation = core.ToolMutationUnknown
	}
	if state == "completed" {
		var stored coretask.Result
		if json.Unmarshal(raw, &stored) != nil || stored.Validate() != nil {
			return core.ToolResult{}, coretask.ErrInvalid
		}
		var references []core.Reference
		if payload.ToolName == coreextension.BuiltinLocalSandboxToolName {
			var referencesErr error
			references, referencesErr = localSandboxResultReferences(stored.JSON)
			if referencesErr != nil {
				return core.ToolResult{}, coretask.ErrInvalid
			}
		}
		switch {
		case stored.Text != "":
			content = stored.Text
		case len(stored.JSON) != 0:
			content = string(stored.JSON)
		case stored.Summary != "":
			content = stored.Summary
		default:
			content = payload.SafeSummary
		}
		observationSummary = strings.TrimSpace(stored.Summary)
		if observationSummary == "" {
			observationSummary = "Conversation tool completed"
		}
		outcome = core.ToolOutcomeSuccess
		resultReferences = references
		if payload.ReadOnly {
			mutation = core.ToolMutationNone
		} else {
			mutation = core.ToolMutationChanged
			stateChanged = true
		}
	} else if state == "uncertain" {
		if payload.ReadOnly {
			outcome = core.ToolOutcomeFatal
			mutation = core.ToolMutationNone
		} else {
			outcome = core.ToolOutcomeUnknownMutation
			mutation = core.ToolMutationUnknown
		}
	} else if code == "tool_arguments_invalid" {
		outcome = core.ToolOutcomeInvalid
		mutation = core.ToolMutationNone
	} else if !payload.ReadOnly && (code == "tool_resolution_failed" || code == "local_resource_busy") {
		outcome = core.ToolOutcomeFatal
		mutation = core.ToolMutationUnchanged
	}
	if content == "" {
		content = "conversation tool returned no additional detail"
	}
	if observationSummary == "" {
		observationSummary = "Conversation tool failed"
	}
	result := core.ToolResult{
		CallID: payload.CallID, ToolName: payload.ToolName, Content: content,
		RelatedTaskIDs: []string{task.ID}, References: resultReferences, StateChanged: stateChanged,
	}.WithObservation(outcome, observationSummary, mutation)
	if outcome == core.ToolOutcomeInvalid {
		result.Retry.ValidationCorrections = 1
	}
	if result.Validate() != nil {
		return core.ToolResult{}, coretask.ErrInvalid
	}
	return result, nil
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
	if a.ConfirmationID != "" {
		if err = tx.QueryRow(ctx, `SELECT state FROM core_confirmations WHERE confirmation_id=$1 AND task_id=$2 FOR UPDATE`, a.ConfirmationID, task.ID).Scan(&confirmationState); err != nil {
			return a, err
		}
	}
	if attemptState == "dispatched" {
		if (a.ConfirmationID != "" && confirmationState != "consumed") || dispatchedEpoch <= 0 || dispatchedEpoch >= int64(task.LeaseEpoch) {
			return a, coretask.ErrLeaseConflict
		}
		return a, core.ErrToolDispatchStarted
	}
	if a.ConfirmationID == "" {
		if p.ConfirmationID != "" {
			return a, coretask.ErrLeaseConflict
		}
		if _, err = tx.Exec(ctx, `UPDATE core_conversation_tool_attempts SET state='dispatched',lease_epoch=$2,updated_at=clock_timestamp() WHERE task_id=$1 AND state='waiting_confirmation' AND confirmation_id IS NULL`, task.ID, task.LeaseEpoch); err != nil {
			return a, err
		}
		if err = tx.Commit(ctx); err != nil {
			return a, err
		}
		a.State = "dispatched"
		return a, nil
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
	taskResult := result
	if state == "failed" {
		// Known terminal failures are resumed through ToolAttempt.Result. Persist
		// only the caller's already-classified safe summary in the common Result
		// shape; runner stderr and raw provider errors never enter this record.
		recovered := coretask.Result{Summary: summary}
		if strings.TrimSpace(code) == "" || strings.TrimSpace(summary) == "" || strings.TrimSpace(summary) != summary || recovered.Validate() != nil {
			return coretask.ErrInvalid
		}
		// The generic Task schema represents failure through code/summary and
		// requires result_json to remain NULL. The attempt owns the recoverable
		// tool result used by the next model round.
		taskResult = nil
	}
	attemptResult, resultErr := conversationToolTerminalResult(task, state, result, code, summary)
	if resultErr != nil {
		return resultErr
	}
	attemptResultRaw, marshalErr := json.Marshal(attemptResult)
	if marshalErr != nil || len(attemptResultRaw) > coretask.MaxResultBytes {
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
	tag, err := tx.Exec(ctx, `UPDATE core_tasks SET status=$1,result_json=$2,failure_code=$3,failure_summary=$4,lease_holder='',lease_expires_at=NULL,revision=revision+1,updated_at=$5 WHERE task_id=$6 AND status='running' AND attempt=$7 AND lease_epoch=$8 AND revision=$9 AND lease_expires_at>$5`, status, taskResult, code, summary, now, task.ID, task.Attempt, task.LeaseEpoch, task.Revision)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return coretask.ErrLeaseConflict
	}
	var turnID string
	if err = tx.QueryRow(ctx, `UPDATE core_conversation_tool_attempts SET state=$2,result_json=$3,updated_at=$4 WHERE task_id=$1 AND state='dispatched' RETURNING turn_id::text`, task.ID, attemptState, attemptResultRaw, now).Scan(&turnID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coretask.ErrLeaseConflict
		}
		return err
	}
	if turnID != task.Spec.Payload.ConversationTool.TurnID {
		return coretask.ErrLeaseConflict
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
