package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func intrinsicToolDigest(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func intrinsicDomainUUID(domain, value string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk:intrinsic-domain:"+domain+":"+value)).String()
}

func (s *CoreConversationStore) PrepareIntrinsicTool(ctx context.Context, c core.PrepareIntrinsicToolCommand) (core.ToolAttempt, coretask.Task, coreconfirmation.Confirmation, error) {
	operation, operationDomain := "", ""
	switch c.Call.Name {
	case coremodel.IntrinsicCloudWorkerDomainBindToolName:
		operation, operationDomain = "bind", "cloud_worker.domain.bind"
	case coremodel.IntrinsicCloudWorkerDomainUnbindToolName:
		operation, operationDomain = "unbind", "cloud_worker.domain.unbind"
	}
	if s == nil || s.Store == nil || c.Lease.Turn.ID == "" || c.Lease.LeaseID == "" || c.Lease.Epoch == 0 ||
		c.Call.Validate() != nil || operation == "" || !coretask.ValidUUID(c.IdempotencyKey) ||
		c.ExpiresAt.IsZero() || !c.ExpiresAt.After(time.Now().UTC()) || len(c.SafeSummary) > coretask.MaxSummaryBytes {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrInvalid
	}
	args, err := canonicalJSON(c.CanonicalArguments, core.MaxToolArgumentsBytes)
	callArgs, callArgsErr := canonicalJSON(json.RawMessage(c.Call.Arguments), core.MaxToolArgumentsBytes)
	if err != nil || callArgsErr != nil || !bytes.Equal(callArgs, args) || conversationArgsDigest(args) != c.ArgumentsDigest || c.Payload.ExecutionTarget != coretask.ExtensionExecutionTargetCoreIntrinsic ||
		c.Payload.CloudWorkerDomain == nil || c.Payload.TurnID != c.Lease.Turn.ID || c.Payload.AttemptID != c.IdempotencyKey ||
		c.Payload.CallID != c.Call.ID || c.Payload.ToolName != c.Call.Name || c.Payload.ArgumentsDigest != c.ArgumentsDigest ||
		c.Binding.TargetID != c.Payload.AttemptID || c.Binding.SelectedTool != c.Call.Name ||
		c.Payload.CloudWorkerDomain.Operation != operation || c.Payload.CloudWorkerDomain.OwnerID != c.Lease.Turn.OwnerID ||
		c.Payload.CloudWorkerDomain.AccountGeneration != c.Lease.Turn.AccountGeneration || c.Binding.OperationDomain != operationDomain ||
		c.Binding.OwnerID != c.Payload.CloudWorkerDomain.OwnerID || c.Binding.AccountGeneration != c.Payload.CloudWorkerDomain.AccountGeneration ||
		c.Binding.ContentDigest != coreconfirmation.Digest(c.Payload.CloudWorkerDomain.IntentDigest) ||
		c.Binding.NetworkDigest != coreconfirmation.Digest(c.Payload.CloudWorkerDomain.IntentDigest) {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrInvalid
	}
	binding, err := c.Binding.Normalize()
	if err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrInvalid
	}
	zeroDigest := coreconfirmation.Digest(strings.Repeat("0", 64))
	credentialSum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", c.Payload.CloudWorkerDomain.CredentialID, c.Payload.CloudWorkerDomain.CredentialRevision)))
	credentialDigest := hex.EncodeToString(credentialSum[:])
	expectedBinding, err := (coreconfirmation.Binding{
		OwnerID: c.Payload.CloudWorkerDomain.OwnerID, AccountGeneration: c.Payload.CloudWorkerDomain.AccountGeneration,
		OperationDomain: operationDomain, TargetID: c.Payload.AttemptID, TargetRevision: 1,
		TargetKind: coreconfirmation.TargetKindPersistentService, SourceVersion: "cloud-worker-domain/v1",
		ContentDigest: coreconfirmation.Digest(c.Payload.CloudWorkerDomain.IntentDigest), ParameterDigest: coreconfirmation.Digest(c.ArgumentsDigest),
		NetworkDigest: coreconfirmation.Digest(c.Payload.CloudWorkerDomain.IntentDigest), SecretGrantDigest: coreconfirmation.Digest(credentialDigest),
		ManifestDigest: zeroDigest, ExecutionDigest: zeroDigest, PermissionDigest: zeroDigest, SelectedTool: c.Call.Name,
	}).Normalize()
	if err != nil || !binding.Equal(expectedBinding) {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "intrinsic_tool:"+c.IdempotencyKey); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	var oldTask string
	if err = tx.QueryRow(ctx, `SELECT task_id::text FROM core_tasks WHERE create_idempotency_key=$1 AND task_kind='conversation_tool'`, c.IdempotencyKey).Scan(&oldTask); err == nil {
		var attempt core.ToolAttempt
		var state, storedCallID string
		if err = tx.QueryRow(ctx, `SELECT attempt_id::text,turn_id::text,task_id::text,COALESCE(confirmation_id::text,''),round,call_id::text,execution_id::text,tool_name,state,arguments_digest,safe_summary FROM core_conversation_tool_attempts WHERE task_id=$1`, oldTask).Scan(&attempt.ID, &attempt.TurnID, &attempt.TaskID, &attempt.ConfirmationID, &attempt.Round, &storedCallID, &attempt.ExecutionID, &attempt.ToolName, &state, &attempt.ArgumentsDigest, &attempt.SafeSummary); err != nil {
			return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
		}
		attempt.State = state
		if storedCallID != attempt.ID || attempt.ID != c.Payload.AttemptID || attempt.TurnID != c.Lease.Turn.ID || attempt.ArgumentsDigest != c.ArgumentsDigest {
			return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
		}
		task, loadErr := NewCoreTaskStore(s.Store).taskTx(ctx, tx, oldTask, false)
		if loadErr != nil {
			return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, loadErr
		}
		stored := task.Spec.Payload.ConversationTool
		if stored == nil || stored.TurnID != c.Payload.TurnID || stored.AttemptID != c.Payload.AttemptID || stored.Round != c.Payload.Round ||
			stored.CallID != c.Payload.CallID || stored.ToolName != c.Payload.ToolName || stored.ArgumentsDigest != c.Payload.ArgumentsDigest ||
			stored.SafeSummary != c.Payload.SafeSummary || stored.ExecutionTarget != c.Payload.ExecutionTarget ||
			!reflect.DeepEqual(stored.CloudWorkerDomain, c.Payload.CloudWorkerDomain) {
			return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
		}
		attempt.CallID = stored.CallID
		if loadErr = validateConversationToolWaitingEventTx(ctx, tx, attempt); loadErr != nil {
			return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, loadErr
		}
		confirmation, loadErr := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1`, attempt.ConfirmationID))
		if loadErr != nil {
			return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, loadErr
		}
		if confirmation.TaskID != task.ID || !confirmation.Binding.Equal(binding) {
			return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
		}
		return attempt, task, confirmation, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	var runtimeRaw, dispatchRaw []byte
	var turnRevision uint64
	var lastSequence int64
	var state, dispatchState string
	if err = tx.QueryRow(ctx, `SELECT runtime_snapshot_json,revision,last_sequence,state,dispatch_state,dispatch_result_json FROM core_conversation_turns WHERE turn_id=$1 AND lease_id=$2 AND lease_epoch=$3 FOR UPDATE`, c.Lease.Turn.ID, c.Lease.LeaseID, c.Lease.Epoch).Scan(&runtimeRaw, &turnRevision, &lastSequence, &state, &dispatchState, &dispatchRaw); err != nil || state != string(core.TurnRunning) || dispatchState != "completed" || turnRevision != c.Lease.Turn.Revision {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
	}
	var runtime core.TurnRuntimeSnapshot
	if json.Unmarshal(runtimeRaw, &runtime) != nil || runtime.Validate() != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
	}
	var tool *coremodel.Tool
	for i := range runtime.IntrinsicTools {
		if runtime.IntrinsicTools[i].Name == c.Call.Name {
			if tool != nil {
				return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
			}
			tool = &runtime.IntrinsicTools[i]
		}
	}
	if tool == nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
	}
	authority, err := conversationToolEventAuthorityTx(ctx, tx, c.Lease.Turn.ID, c.Call.ID)
	if err != nil || authority.state != conversationToolCallPending || !reflect.DeepEqual(authority.call, c.Call) {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
	}
	contentDigest := intrinsicToolDigest(struct{ Name, Runtime string }{c.Call.Name, runtime.IntrinsicDigest})
	schemaDigest := intrinsicToolDigest(tool.InputSchema)
	installationID := intrinsicDomainUUID("installation", c.Call.Name)
	versionID := intrinsicDomainUUID("version", c.Call.Name+":v1")
	confirmationID := intrinsicDomainUUID("confirmation", c.IdempotencyKey)
	taskID := intrinsicDomainUUID("task", c.IdempotencyKey)
	executionID := intrinsicDomainUUID("execution", c.IdempotencyKey)
	payload := c.Payload
	payload.ExtensionSnapshotDigest, payload.InstallationID, payload.VersionID, payload.InstallationRevision = contentDigest, installationID, versionID, 1
	payload.ToolSchemaDigest, payload.ConfirmationID = schemaDigest, confirmationID
	spec := coretask.TaskSpec{Kind: coretask.TaskKindConversationTool, Goal: "conversation intrinsic " + c.Call.Name, ConversationID: c.Lease.Turn.ConversationID, IdempotencyKey: c.IdempotencyKey, AvailableAt: time.Now().UTC(), Payload: coretask.TaskPayload{ConversationTool: &payload}}
	spec, err = spec.Normalize()
	if err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrInvalid
	}
	now := time.Now().UTC()
	payloadRaw, _ := json.Marshal(spec.Payload)
	if _, err = tx.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,conversation_id,create_idempotency_key,attachment_refs,extensions_json,knowledge_refs,timeout_seconds,status,attempt,progress_sequence,available_at,revision,created_at,updated_at,task_kind,payload_json) VALUES($1,$2,$3,$4,'[]','[]','[]',0,'waiting_user',1,1,$5,1,$5,$5,'conversation_tool',$6)`, taskID, spec.Goal, c.Lease.Turn.ConversationID, c.IdempotencyKey, now, payloadRaw); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_tool_attempts(turn_id,attempt_id,task_id,round,call_id,execution_id,extension_snapshot_digest,installation_id,version_id,installation_revision,tool_name,tool_schema_digest,arguments_digest,arguments_json,confirmation_id,state,safe_summary,created_at,updated_at,lease_epoch) VALUES($1,$2,$3,$4,$2,$5,$6,$7,$8,1,$9,$10,$11,$12,$13,'waiting_confirmation',$14,$15,$15,1)`, c.Lease.Turn.ID, payload.AttemptID, taskID, c.Round, executionID, contentDigest, installationID, versionID, c.Call.Name, schemaDigest, c.ArgumentsDigest, args, confirmationID, c.SafeSummary, now); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	bindingRaw, _ := json.Marshal(binding)
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmations(confirmation_id,operation_domain,target_id,target_revision,binding_json,task_id,state,revision,created_at,updated_at,expires_at) VALUES($1,$2,$3,1,$4,$5,'pending',1,$6,$6,$7)`, confirmationID, binding.OperationDomain, binding.TargetID, bindingRaw, taskID, now, c.ExpiresAt.UTC()); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_target_bindings(confirmation_id,binding_json,updated_at) VALUES($1,$2,$3)`, confirmationID, bindingRaw, now); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_current_bindings(operation_domain,target_id,target_revision,binding_json,updated_at) VALUES($1,$2,1,$3,$4)`, binding.OperationDomain, binding.TargetID, bindingRaw, now); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	waiting, err := core.NewWaitingConfirmationTurnEvent(confirmationID, executionID)
	if err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrInvalid
	}
	waiting.TurnID, waiting.Sequence, waiting.Revision, waiting.CreatedAt = c.Lease.Turn.ID, lastSequence+1, turnRevision+1, now
	waitingRaw, _ := json.Marshal(waiting)
	if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_turn_events(turn_id,sequence,kind,payload_json,created_at) VALUES($1,$2,$3,$4,$5)`, waiting.TurnID, waiting.Sequence, string(waiting.Kind), waitingRaw, now); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	updated, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET state='waiting_confirmation',lease_id=NULL,lease_expires_at=NULL,revision=revision+1,last_sequence=$2,updated_at=$3 WHERE turn_id=$1 AND state='running' AND lease_id=$4 AND lease_epoch=$5 AND revision=$6`, c.Lease.Turn.ID, waiting.Sequence, now, c.Lease.LeaseID, c.Lease.Epoch, turnRevision)
	if err != nil || updated.RowsAffected() != 1 {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, core.ErrConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) VALUES($1,1,$2,1,'waiting_user','confirmation','waiting for owner confirmation',$3)`, taskID, uuid.New(), now); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, err
	}
	attempt := core.ToolAttempt{ID: payload.AttemptID, TurnID: c.Lease.Turn.ID, TaskID: taskID, ConfirmationID: confirmationID, Round: c.Round, CallID: c.Call.ID, ExecutionID: executionID, ToolName: c.Call.Name, State: "waiting_confirmation", ArgumentsDigest: c.ArgumentsDigest, SafeSummary: c.SafeSummary}
	task := coretask.Task{ID: taskID, Spec: spec, Status: coretask.StatusWaitingUser, Attempt: 1, Revision: 1, CreatedAt: now, UpdatedAt: now, AvailableAt: now}
	confirmation := coreconfirmation.Confirmation{ConfirmationID: confirmationID, OwnerID: binding.OwnerID, Binding: binding, TaskID: taskID, State: coreconfirmation.StatePending, Revision: 1, CreatedAt: now, UpdatedAt: now, ExpiresAt: c.ExpiresAt.UTC()}
	return attempt, task, confirmation, nil
}

var _ core.IntrinsicToolStore = (*CoreConversationStore)(nil)
