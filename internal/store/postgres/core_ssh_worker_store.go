package postgres

// This file is the PostgreSQL adapter for the simple persistent SSH Worker
// flow. It reuses the current offer rows as immutable proposal input, but does
// not use the legacy S3 artifact table or the legacy resource graph.

import (
	"context"
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
	if err != nil || !confirmation.Binding.Equal(binding) ||
		(execution.State != cloudworker.StateProvisioning && execution.State != cloudworker.StateRunning) {
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
	if execution.State == cloudworker.StateProvisioning {
		nextExecution, transitionErr := execution.Transition(cloudworker.StateRunning, now)
		if transitionErr != nil {
			return sshflow.Run{}, transitionErr
		}
		if err = saveCloudWorkerExecutionTx(ctx, tx, execution, nextExecution, "execution_running"); err != nil {
			return sshflow.Run{}, err
		}
		execution = nextExecution
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

func (store *SSHWorkerStore) Progress(ctx context.Context, run *sshflow.Run, phase, message string) error {
	if store == nil || store.store == nil || ctx == nil || run == nil || run.Task.Lease == nil ||
		strings.TrimSpace(phase) == "" || strings.TrimSpace(message) == "" {
		return errSSHWorkerStoreInvalid
	}
	phase, message = strings.TrimSpace(phase), strings.TrimSpace(message)
	now := time.Now().UTC().Truncate(time.Microsecond)
	tx, err := store.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tasks := NewCoreTaskStore(store.store)
	current, err := tasks.taskTxLocked(ctx, tx, run.Task.ID, false)
	if err != nil || validateSSHWorkerTaskFence(current, run.Task, now) != nil {
		return cloudworker.ErrLeaseConflict
	}
	progress := coretask.Progress{TaskID: current.ID, Attempt: current.Attempt, Sequence: current.ProgressSequence + 1,
		At: now, Status: coretask.StatusRunning, Phase: phase, Message: message}
	command := coretask.ProgressCommand{
		Fence:            coretask.Fence{TaskID: current.ID, Attempt: current.Attempt, LeaseEpoch: current.LeaseEpoch, ExpectedRevision: current.Revision},
		ExpectedSequence: current.ProgressSequence, Progress: progress,
	}
	if err = coretask.ValidateProgress(current, command); err != nil {
		return err
	}
	updated, err := tx.Exec(ctx, `UPDATE core_tasks SET progress_sequence=progress_sequence+1,revision=revision+1,updated_at=$2
		WHERE task_id=$1 AND status='running' AND attempt=$3 AND lease_epoch=$4 AND revision=$5
		  AND progress_sequence=$6 AND lease_expires_at>$2`, current.ID, now, current.Attempt, current.LeaseEpoch,
		current.Revision, current.ProgressSequence)
	if err != nil || updated.RowsAffected() != 1 {
		return cloudworker.ErrLeaseConflict
	}
	payload := current.Spec.Payload.CloudWorker
	reservation, err := tx.Exec(ctx, `UPDATE core_confirmation_reservations SET task_revision=$2
		WHERE confirmation_id=$1 AND task_id=$3 AND acquired_attempt=$4 AND acquired_lease_epoch=$5
		  AND task_revision=$6 AND active=true`, payload.ConfirmationID, current.Revision+1, current.ID,
		current.Attempt, current.LeaseEpoch, current.Revision)
	if err != nil || reservation.RowsAffected() != 1 {
		return cloudworker.ErrLeaseConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at)
		VALUES($1,$2,$3,$4,'running',$5,$6,$7)`, current.ID, progress.Sequence, uuid.New(), current.Attempt, phase, message, now); err != nil {
		return err
	}
	var turnState, turnOwner, turnConversation string
	var turnGeneration uint64
	var lastSequence int64
	if err = tx.QueryRow(ctx, `SELECT state,owner_id,account_generation,conversation_id::text,last_sequence
		FROM core_conversation_turns WHERE turn_id=$1 FOR UPDATE`, run.Plan.TurnID).Scan(
		&turnState, &turnOwner, &turnGeneration, &turnConversation, &lastSequence,
	); err != nil || turnState != string(core.TurnWaitingConfirmation) || turnOwner != run.Plan.OwnerID ||
		turnGeneration != run.Plan.AccountGeneration || turnConversation != run.Plan.ConversationID {
		return cloudworker.ErrStaleAuthorization
	}
	turnEvent, err := core.NewWorkerProgressTurnEvent(run.Plan.ExecutionID, phase)
	if err != nil {
		return err
	}
	if err = insertTurnEventTx(ctx, tx, run.Plan.TurnID, lastSequence+1, turnEvent, now); err != nil {
		return err
	}
	current, err = tasks.taskTx(ctx, tx, current.ID, false)
	if err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	run.Task = current
	return nil
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
	for _, artifact := range artifacts {
		catalogID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk:cloud-worker-artifact:"+artifact.ArtifactID)).String()
		if _, err = tx.Exec(ctx, `INSERT INTO core_server_artifacts
			(artifact_id,owner_id,account_generation,server_id,server_kind,artifact_kind,source_kind,source_id,name,status,record_kind,execution_id,media_type,size_bytes,metadata_json,deletion_state,created_at,updated_at)
			VALUES($1,$2,$3,$4,'worker','execution_file','cloud_worker_artifact',$5,$6,'verified','cloud_worker',$7,$8,$9,jsonb_build_object('sha256',$10::text),'active',$11,$11)
			ON CONFLICT(owner_id,account_generation,source_kind,source_id) DO NOTHING`, catalogID, plan.OwnerID, plan.AccountGeneration,
			workerResult.WorkerID, artifact.ArtifactID, artifact.Name, plan.ExecutionID, artifact.MediaType, artifact.SizeBytes, artifact.SHA256, now); err != nil {
			return err
		}
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
	failureSummary := ""
	if terminal == cloudworker.StateFailed {
		taskStatus = string(coretask.StatusFailed)
		taskResultRaw = nil
		failureSummary = summary
	}
	updated, err := tx.Exec(ctx, `UPDATE core_tasks SET status=$2,result_json=$3,failure_code=$4,failure_summary=$5,
		lease_holder='',lease_expires_at=NULL,revision=revision+1,progress_sequence=progress_sequence+1,updated_at=$6
		WHERE task_id=$1 AND status='running' AND attempt=$7 AND lease_epoch=$8 AND revision=$9 AND lease_expires_at>$6`,
		plan.TaskID, taskStatus, taskResultRaw, code, failureSummary, now, currentTask.Attempt, currentTask.LeaseEpoch, currentTask.Revision)
	if err != nil || updated.RowsAffected() != 1 {
		return cloudworker.ErrLeaseConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,result_json,error_code,error_summary,occurred_at)
		SELECT task_id,progress_sequence,$2,attempt,$3,'ssh_worker_terminal',$4,$5,$6,$7 FROM core_tasks WHERE task_id=$1`,
		plan.TaskID, sshWorkerUUID("task-terminal", plan.ExecutionID), taskStatus, taskResultRaw, code, failureSummary, now); err != nil {
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
	next, err := currentExecution.Transition(terminal, now)
	if err != nil {
		return err
	}
	next.ArtifactIDs = artifactIDs
	next.WorkerID, next.PersistentWorker = workerResult.WorkerID, true
	if terminal == cloudworker.StateFailed {
		next.FailureCode, next.FailureSummary = code, summary
	}
	if err = next.Seal(); err != nil {
		return err
	}
	eventType := "execution_succeeded"
	if terminal == cloudworker.StateFailed {
		eventType = "execution_failed"
	}
	if err = saveCloudWorkerExecutionTx(ctx, tx, currentExecution, next, eventType); err != nil {
		return err
	}
	var statusSequence int64
	if err = tx.QueryRow(ctx, `SELECT last_sequence FROM core_conversation_turns WHERE turn_id=$1`, plan.TurnID).Scan(&statusSequence); err != nil {
		return err
	}
	toolCall, toolResult, err := sshWorkerContinuation(turn.DispatchResult, plan, next, summary, workerResult, artifacts)
	if err != nil {
		return err
	}
	if err = insertTurnEventTx(ctx, tx, plan.TurnID, statusSequence+1, core.TurnEvent{Kind: core.TurnEventToolCall, ToolCall: &toolCall}, now); err != nil {
		return err
	}
	if err = insertTurnEventTx(ctx, tx, plan.TurnID, statusSequence+2, core.TurnEvent{Kind: core.TurnEventToolResult, ToolResult: &toolResult}, now); err != nil {
		return err
	}
	turnUpdate, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET state='accepted',response_json=NULL,
		dispatch_state='',dispatch_epoch=0,dispatch_result_json=NULL,lease_id=NULL,lease_expires_at=NULL,
		revision=revision+1,last_sequence=$2,updated_at=$3
		WHERE turn_id=$1 AND state='waiting_confirmation' AND revision=$4 AND cancel_requested=false`,
		plan.TurnID, statusSequence+2, now, turn.Revision)
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
		out = append(out, artifact)
	}
	return out, nil
}

func sshWorkerContinuation(dispatch *core.ModelRunResult, plan cloudworker.Plan, execution cloudworker.Execution, summary string, result sshflow.Result, artifacts []sshflow.Artifact) (core.ToolCall, core.ToolResult, error) {
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
	terminal := execution.State
	completion := map[string]any{"schema": "dirextalk.ssh-worker-completion/v1",
		"execution_id": plan.ExecutionID, "status": terminal, "worker_id": result.WorkerID,
		"persistent_worker": true, "worker_report": summary, "artifacts": artifacts,
		"central_instruction": "Continue the current conversation using the Worker report and local artifacts."}
	if len(result.AppliedSteerIDs) != 0 {
		completion["applied_steer_ids"] = append([]string(nil), result.AppliedSteerIDs...)
	}
	if terminal == cloudworker.StateSucceeded {
		completion["next_action"] = map[string]any{
			"kind": "confirm_destroy_worker", "operation": "destroy_worker", "worker_id": result.WorkerID, "default": "retain",
			"question": "The Worker is retained for reuse. Ask the user whether to destroy it now.",
		}
		completion["central_instruction"] = "Continue the current conversation using the Worker report and local artifacts. Tell the user which Worker was retained and ask whether to destroy it now; do not destroy it without their explicit choice."
	}
	payload, _ := json.Marshal(completion)
	toolResult := core.ToolResult{CallID: calls[0].ID, ToolName: coremodel.IntrinsicCloudWorkerProposeToolName,
		Content: string(payload), IsError: terminal != cloudworker.StateSucceeded,
		RelatedTaskIDs: []string{plan.TaskID}, RelatedPlanIDs: []string{plan.PlanID}, Summary: "Cloud Worker result returned",
		References: []core.Reference{
			{Kind: "execution_plan", AccountGeneration: plan.AccountGeneration, TaskID: plan.TaskID,
				PlanID: plan.PlanID, PlanRevision: plan.Revision, Status: plan.Status},
			{Kind: "execution_run", AccountGeneration: plan.AccountGeneration, TaskID: plan.TaskID,
				PlanID: plan.PlanID, PlanRevision: plan.Revision, RunID: execution.RunID,
				RunRevision: execution.Revision, ExecutionID: execution.ExecutionID, Status: string(execution.State)},
		},
	}
	if toolResult.Validate() != nil {
		return core.ToolCall{}, core.ToolResult{}, errSSHWorkerStoreInvalid
	}
	return calls[0], toolResult, nil
}

func sshWorkerUUID(domain, value string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk-ssh-worker:"+domain+":"+value)).String()
}
