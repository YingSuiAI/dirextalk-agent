package postgres

// This file is the PostgreSQL adapter for the simple persistent SSH Worker
// flow. It reuses the current offer rows as immutable proposal input, but does
// not use the legacy S3 artifact table or the legacy resource graph.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshflow"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var errSSHWorkerStoreInvalid = errors.New("invalid SSH Worker store request")

// SSHWorkerStore terminalizes a confirmed task and resumes its original
// durable turn. artifactRoot is the relative prefix used by the local
// artifact repository, normally "cloud-worker/artifacts".
type SSHWorkerStore struct {
	store        *Store
	artifactRoot string
}

func NewSSHWorkerStore(store *Store, artifactRoot string) (*SSHWorkerStore, error) {
	artifactRoot = filepath.ToSlash(filepath.Clean(strings.TrimSpace(artifactRoot)))
	if store == nil || store.pool == nil || artifactRoot == "." || filepath.IsAbs(artifactRoot) ||
		strings.HasPrefix(artifactRoot, "../") || strings.Contains(artifactRoot, `\`) {
		return nil, errSSHWorkerStoreInvalid
	}
	return &SSHWorkerStore{store: store, artifactRoot: artifactRoot}, nil
}

func (store *SSHWorkerStore) Begin(ctx context.Context, supplied coretask.Task) (sshflow.Run, error) {
	if store == nil || store.store == nil || ctx == nil || supplied.Spec.Kind != coretask.TaskKindCloudWorker ||
		supplied.Spec.Payload.CloudWorker == nil || supplied.Status != coretask.StatusRunning || supplied.Lease == nil {
		return sshflow.Run{}, errSSHWorkerStoreInvalid
	}
	tx, err := store.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return sshflow.Run{}, err
	}
	defer tx.Rollback(ctx)
	current, err := NewCoreTaskStore(store.store).taskTxLocked(ctx, tx, supplied.ID, false)
	now := time.Now().UTC()
	if err != nil || validateSSHWorkerTaskFence(current, supplied, now) != nil {
		return sshflow.Run{}, cloudworker.ErrLeaseConflict
	}
	plan, execution, err := cloudWorkerPlanAndExecutionTx(ctx, tx, current.Spec.Payload.CloudWorker, true)
	if err != nil {
		return sshflow.Run{}, err
	}
	confirmation, err := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, plan.ConfirmationID))
	if err != nil || confirmation.State != coreconfirmation.StateConsumed {
		return sshflow.Run{}, cloudworker.ErrStaleAuthorization
	}
	binding, err := cloudworker.BindingForPlan(plan)
	if err != nil || !confirmation.Binding.Equal(binding) || execution.State != cloudworker.StateProvisioning {
		return sshflow.Run{}, cloudworker.ErrStaleAuthorization
	}
	var reservationTask string
	var reservationAttempt uint32
	var reservationEpoch uint64
	var reservationActive bool
	if err = tx.QueryRow(ctx, `SELECT task_id::text,acquired_attempt,acquired_lease_epoch,active
		FROM core_confirmation_reservations WHERE confirmation_id=$1 FOR UPDATE`, plan.ConfirmationID).Scan(
		&reservationTask, &reservationAttempt, &reservationEpoch, &reservationActive,
	); err != nil || reservationTask != current.ID || reservationAttempt != current.Attempt ||
		reservationEpoch != current.LeaseEpoch || !reservationActive {
		return sshflow.Run{}, cloudworker.ErrStaleAuthorization
	}
	conversationStore, err := NewCoreConversationStore(store.store)
	if err != nil {
		return sshflow.Run{}, err
	}
	var turn core.Turn
	err = conversationStore.scanTurn(ctx, tx, plan.TurnID, &turn)
	if err != nil || turn.ID != plan.TurnID || turn.OwnerID != plan.OwnerID ||
		turn.AccountGeneration != plan.AccountGeneration || turn.ConversationID != plan.ConversationID ||
		turn.State != core.TurnWaitingConfirmation || turn.ProfileSnapshot.Validate() != nil ||
		turn.ProfileSnapshot.Digest() != turn.ProfileSnapshotDigest ||
		turn.ProfileSnapshot.ProfileID != plan.ModelAuthorization.ModelProfileID ||
		uint64(turn.ProfileSnapshot.Revision) != plan.ModelAuthorization.ModelProfileRevision ||
		uint64(turn.ProfileSnapshot.CredentialVersion) != plan.ModelAuthorization.CredentialVersion {
		return sshflow.Run{}, cloudworker.ErrStaleAuthorization
	}
	proof := fmt.Sprintf("%s:%d:%s", confirmation.ConfirmationID, confirmation.Revision, confirmation.Binding.Digest)
	if err = tx.Commit(ctx); err != nil {
		return sshflow.Run{}, err
	}
	return sshflow.Run{Task: current, Plan: plan, Execution: execution,
		ConfirmationProof: proof, ModelSnapshot: turn.ProfileSnapshot}, nil
}

func (store *SSHWorkerStore) Complete(ctx context.Context, run sshflow.Run, result sshflow.Result) error {
	return store.terminal(ctx, run, result, cloudworker.StateSucceeded, "", strings.TrimSpace(result.Summary))
}

func (store *SSHWorkerStore) Fail(ctx context.Context, run sshflow.Run, result sshflow.Result, code, summary string) error {
	return store.terminal(ctx, run, result, cloudworker.StateFailed, strings.TrimSpace(code), strings.TrimSpace(summary))
}

func (store *SSHWorkerStore) terminal(ctx context.Context, run sshflow.Run, workerResult sshflow.Result, terminal cloudworker.ExecutionState, code, summary string) error {
	if store == nil || store.store == nil || ctx == nil || run.Task.Lease == nil ||
		(terminal != cloudworker.StateSucceeded && terminal != cloudworker.StateFailed) ||
		strings.TrimSpace(workerResult.WorkerID) == "" || summary == "" ||
		(terminal == cloudworker.StateFailed && code == "") || len(summary) > core.MaxSummaryBytes {
		return errSSHWorkerStoreInvalid
	}
	tx, err := store.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC().Truncate(time.Microsecond)
	currentTask, err := NewCoreTaskStore(store.store).taskTxLocked(ctx, tx, run.Task.ID, false)
	if err != nil || validateSSHWorkerTaskFence(currentTask, run.Task, now) != nil {
		return cloudworker.ErrLeaseConflict
	}
	plan, currentExecution, err := cloudWorkerPlanAndExecutionTx(ctx, tx, currentTask.Spec.Payload.CloudWorker, true)
	if err != nil || !sameSSHWorkerRun(run, plan, currentExecution) {
		return cloudworker.ErrStaleAuthorization
	}
	confirmation, err := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, plan.ConfirmationID))
	if err != nil || confirmation.State != coreconfirmation.StateConsumed {
		return cloudworker.ErrStaleAuthorization
	}
	binding, err := cloudworker.BindingForPlan(plan)
	proof := fmt.Sprintf("%s:%d:%s", confirmation.ConfirmationID, confirmation.Revision, confirmation.Binding.Digest)
	if err != nil || !confirmation.Binding.Equal(binding) || proof != run.ConfirmationProof {
		return cloudworker.ErrStaleAuthorization
	}
	conversationStore, err := NewCoreConversationStore(store.store)
	if err != nil {
		return err
	}
	var turn core.Turn
	err = conversationStore.scanTurn(ctx, tx, plan.TurnID, &turn)
	if err != nil || turn.State != core.TurnWaitingConfirmation || turn.DispatchState != "completed" ||
		turn.ProfileSnapshot.Validate() != nil || turn.ProfileSnapshot.Digest() != run.ModelSnapshot.Digest() {
		return cloudworker.ErrStaleAuthorization
	}
	artifacts, err := store.persistArtifactsTx(ctx, tx, plan, workerResult.Artifacts, now)
	if err != nil {
		return err
	}
	artifactIDs := make([]string, 0, len(artifacts))
	files := make([]coretask.FileRef, 0, len(artifacts))
	for _, artifact := range artifacts {
		artifactIDs = append(artifactIDs, artifact.ArtifactID)
		files = append(files, coretask.FileRef{Path: artifact.RelativePath, Digest: artifact.SHA256, Size: artifact.SizeBytes})
	}
	resultJSON, _ := json.Marshal(map[string]any{"execution_id": plan.ExecutionID, "worker_id": workerResult.WorkerID,
		"exit_code": workerResult.ExitCode, "artifact_ids": artifactIDs})
	taskResult := coretask.Result{Text: summary, Summary: summary, JSON: resultJSON, Files: files}
	if taskResult.Validate() != nil {
		return errSSHWorkerStoreInvalid
	}
	taskResultRaw, _ := json.Marshal(taskResult)
	taskStatus := string(coretask.StatusSucceeded)
	if terminal == cloudworker.StateFailed {
		taskStatus = string(coretask.StatusFailed)
		taskResultRaw = nil
	}
	updated, err := tx.Exec(ctx, `UPDATE core_tasks SET status=$2,result_json=$3,failure_code=$4,failure_summary=$5,
		lease_holder='',lease_expires_at=NULL,revision=revision+1,progress_sequence=progress_sequence+1,updated_at=$6
		WHERE task_id=$1 AND status='running' AND attempt=$7 AND lease_epoch=$8 AND revision=$9 AND lease_expires_at>$6`,
		plan.TaskID, taskStatus, taskResultRaw, code, summary, now, currentTask.Attempt, currentTask.LeaseEpoch, currentTask.Revision)
	if err != nil || updated.RowsAffected() != 1 {
		return cloudworker.ErrLeaseConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,result_json,error_code,error_summary,occurred_at)
		SELECT task_id,progress_sequence,$2,attempt,$3,'ssh_worker_terminal',$4,$5,$6,$7 FROM core_tasks WHERE task_id=$1`,
		plan.TaskID, sshWorkerUUID("task-terminal", plan.ExecutionID), taskStatus, taskResultRaw, code, summary, now); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_task_runtime_concurrency SET running_count=GREATEST(0,running_count-1),revision=revision+1,updated_at=$1 WHERE singleton=true`, now); err != nil {
		return err
	}
	released, err := tx.Exec(ctx, `UPDATE core_confirmation_reservations SET active=false WHERE confirmation_id=$1 AND task_id=$2 AND active=true`, plan.ConfirmationID, plan.TaskID)
	if err != nil {
		return err
	}
	if released.RowsAffected() != 1 {
		return cloudworker.ErrStaleAuthorization
	}
	confirmationUpdate, err := tx.Exec(ctx, `UPDATE core_confirmations SET consumed_released=true,revision=revision+1,updated_at=$2
		WHERE confirmation_id=$1 AND state='consumed' AND consumed_released=false`, plan.ConfirmationID, now)
	if err != nil {
		return err
	}
	if confirmationUpdate.RowsAffected() != 1 {
		return cloudworker.ErrStaleAuthorization
	}
	next := currentExecution
	next.State, next.Status, next.Revision, next.UpdatedAt = terminal, terminal, currentExecution.Revision+1, now
	next.ProviderMutationStarted = true
	next.TerminalIntent = ""
	next.ArtifactIDs = artifactIDs
	if terminal == cloudworker.StateFailed {
		next.FailureCode, next.FailureSummary = code, summary
	}
	// Deliberately do not call the legacy Execution.Seal: its exact eight-item
	// ephemeral cleanup invariant belongs to the removed S3/Worker-Control path.
	// The simple SSH projection is persisted independently below.
	projectionRaw, _ := json.Marshal(map[string]any{
		"execution_id": plan.ExecutionID, "plan_id": plan.PlanID, "task_id": plan.TaskID,
		"state": terminal, "worker_id": workerResult.WorkerID, "persistent_worker": true,
		"artifact_ids": artifactIDs, "summary": summary, "failure_code": code, "updated_at": now,
	})
	digest := sha256.Sum256(projectionRaw)
	executionUpdate, err := tx.Exec(ctx, `UPDATE core_cloud_worker_executions SET state=$2,revision=revision+1,digest=$3,
		provider_mutation_started=true,terminal_intent='',needs_reconcile=false,execution_json=$4,updated_at=$5
		WHERE execution_id=$1 AND revision=$6`, plan.ExecutionID, terminal, hex.EncodeToString(digest[:]), projectionRaw, now, currentExecution.Revision)
	if err != nil {
		return err
	}
	if executionUpdate.RowsAffected() != 1 {
		return cloudworker.ErrConflict
	}
	toolCall, toolResult, err := sshWorkerContinuation(turn.DispatchResult, plan, terminal, summary, workerResult, artifacts)
	if err != nil {
		return err
	}
	if err = insertTurnEventTx(ctx, tx, plan.TurnID, turn.LastSequence+1, core.TurnEvent{Kind: core.TurnEventToolCall, ToolCall: &toolCall}, now); err != nil {
		return err
	}
	if err = insertTurnEventTx(ctx, tx, plan.TurnID, turn.LastSequence+2, core.TurnEvent{Kind: core.TurnEventToolResult, ToolResult: &toolResult}, now); err != nil {
		return err
	}
	turnUpdate, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET state='accepted',response_json=NULL,
		dispatch_state='',dispatch_epoch=0,dispatch_result_json=NULL,lease_id=NULL,lease_expires_at=NULL,
		revision=revision+1,last_sequence=$2,updated_at=$3
		WHERE turn_id=$1 AND state='waiting_confirmation' AND revision=$4 AND cancel_requested=false`,
		plan.TurnID, turn.LastSequence+2, now, turn.Revision)
	if err != nil || turnUpdate.RowsAffected() != 1 {
		return cloudworker.ErrConflict
	}
	return tx.Commit(ctx)
}

func validateSSHWorkerTaskFence(current, supplied coretask.Task, now time.Time) error {
	if current.ID != supplied.ID || current.Spec.Kind != coretask.TaskKindCloudWorker || supplied.Spec.Kind != coretask.TaskKindCloudWorker ||
		current.Spec.Payload.CloudWorker == nil || supplied.Spec.Payload.CloudWorker == nil || current.Status != coretask.StatusRunning ||
		current.Attempt != supplied.Attempt || current.LeaseEpoch != supplied.LeaseEpoch || current.Revision != supplied.Revision ||
		current.Lease == nil || supplied.Lease == nil || current.Lease.Holder != supplied.Lease.Holder ||
		current.Lease.ExpiresAt.Before(now) || !reflect.DeepEqual(current.Spec.Payload.CloudWorker, supplied.Spec.Payload.CloudWorker) {
		return cloudworker.ErrLeaseConflict
	}
	return nil
}

func sameSSHWorkerRun(run sshflow.Run, plan cloudworker.Plan, execution cloudworker.Execution) bool {
	return run.Task.ID == plan.TaskID && run.Plan.PlanID == plan.PlanID && run.Plan.Digest == plan.Digest &&
		run.Execution.ExecutionID == execution.ExecutionID && run.Execution.Revision == execution.Revision
}

func (store *SSHWorkerStore) persistArtifactsTx(ctx context.Context, tx pgx.Tx, plan cloudworker.Plan, values []sshflow.Artifact, at time.Time) ([]sshflow.Artifact, error) {
	if len(values) > coretask.MaxFileCount {
		return nil, errSSHWorkerStoreInvalid
	}
	out := make([]sshflow.Artifact, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, artifact := range values {
		expectedPrefix := store.artifactRoot + "/" + plan.ExecutionID + "/"
		if uuid.Validate(artifact.ArtifactID) != nil || artifact.ExecutionID != plan.ExecutionID ||
			artifact.Kind == "" || artifact.Name == "" || artifact.MediaType == "" || artifact.SizeBytes < 0 ||
			!coretask.ValidDigest(artifact.SHA256) || !strings.HasPrefix(artifact.RelativePath, expectedPrefix) ||
			filepath.ToSlash(filepath.Clean(artifact.RelativePath)) != artifact.RelativePath {
			return nil, errSSHWorkerStoreInvalid
		}
		if _, duplicate := seen[artifact.ArtifactID]; duplicate {
			return nil, errSSHWorkerStoreInvalid
		}
		seen[artifact.ArtifactID] = struct{}{}
		payload, _ := json.Marshal(map[string]any{"artifact_id": artifact.ArtifactID, "execution_id": artifact.ExecutionID,
			"kind": artifact.Kind, "name": artifact.Name, "media_type": artifact.MediaType,
			"relative_path": artifact.RelativePath, "size_bytes": artifact.SizeBytes, "sha256": artifact.SHA256})
		digest := sha256.Sum256(payload)
		result, err := tx.Exec(ctx, `INSERT INTO core_execution_v2_records(owner_id,resource_type,resource_id,revision,status,digest,payload_json,created_at,updated_at)
			VALUES($1,'artifact',$2,1,'ready',$3,$4,$5,$5) ON CONFLICT(owner_id,resource_type,resource_id) DO NOTHING`,
			plan.OwnerID, artifact.ArtifactID, hex.EncodeToString(digest[:]), payload, at)
		if err != nil {
			return nil, err
		}
		if result.RowsAffected() == 0 {
			var existing []byte
			if err = tx.QueryRow(ctx, `SELECT payload_json FROM core_execution_v2_records WHERE owner_id=$1 AND resource_type='artifact' AND resource_id=$2`, plan.OwnerID, artifact.ArtifactID).Scan(&existing); err != nil || !jsonEquivalent(existing, payload) {
				return nil, cloudworker.ErrConflict
			}
		} else if _, err = tx.Exec(ctx, `INSERT INTO core_execution_v2_revisions(owner_id,resource_type,resource_id,revision,status,digest,payload_json,created_at)
			VALUES($1,'artifact',$2,1,'ready',$3,$4,$5)`, plan.OwnerID, artifact.ArtifactID, hex.EncodeToString(digest[:]), payload, at); err != nil {
			return nil, err
		}
		out = append(out, artifact)
	}
	return out, nil
}

func sshWorkerContinuation(dispatch *core.ModelRunResult, plan cloudworker.Plan, terminal cloudworker.ExecutionState, summary string, result sshflow.Result, artifacts []sshflow.Artifact) (core.ToolCall, core.ToolResult, error) {
	if dispatch == nil {
		return core.ToolCall{}, core.ToolResult{}, cloudworker.ErrConflict
	}
	calls := dispatch.ToolCalls
	if len(calls) == 0 {
		calls = dispatch.Message.ToolCalls
	}
	if len(calls) != 1 || calls[0].Name != coremodel.IntrinsicCloudWorkerProposeToolName || calls[0].Validate() != nil {
		return core.ToolCall{}, core.ToolResult{}, cloudworker.ErrConflict
	}
	payload, _ := json.Marshal(map[string]any{"schema": "dirextalk.ssh-worker-completion/v1",
		"execution_id": plan.ExecutionID, "status": terminal, "worker_id": result.WorkerID,
		"persistent_worker": true, "worker_report": summary, "artifacts": artifacts,
		"central_instruction": "Continue the current conversation using the Worker report and local artifacts."})
	toolResult := core.ToolResult{CallID: calls[0].ID, ToolName: coremodel.IntrinsicCloudWorkerProposeToolName,
		Content: string(payload), IsError: terminal != cloudworker.StateSucceeded,
		RelatedTaskIDs: []string{plan.TaskID}, RelatedPlanIDs: []string{plan.PlanID}, Summary: "Cloud Worker result returned"}
	if toolResult.Validate() != nil {
		return core.ToolCall{}, core.ToolResult{}, errSSHWorkerStoreInvalid
	}
	return calls[0], toolResult, nil
}

func sshWorkerUUID(domain, value string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk-ssh-worker:"+domain+":"+value)).String()
}
