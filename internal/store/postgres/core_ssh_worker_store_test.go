package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshflow"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

func TestCloudWorkerOfferReferencesTrackConfirmedAndRunningState(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	offer := h.propose(t)
	conversationStore, err := NewCoreConversationStore(h.store)
	if err != nil {
		t.Fatal(err)
	}
	assertState := func(wantConfirmation, wantRun string) {
		conversation, loadErr := conversationStore.LoadConversation(h.ctx, offer.Plan.ConversationID)
		if loadErr != nil || len(conversation.Messages) < 2 || len(conversation.Messages[1].References) != 3 {
			t.Fatalf("conversation=%+v err=%v", conversation, loadErr)
		}
		var confirmationState, runState string
		for _, reference := range conversation.Messages[1].References {
			switch reference.Kind {
			case "execution_confirmation":
				confirmationState = reference.State
			case "execution_run":
				runState = reference.Status
			}
		}
		if confirmationState != wantConfirmation || runState != wantRun {
			t.Fatalf("confirmation=%q run=%q references=%+v", confirmationState, runState, conversation.Messages[1].References)
		}
	}
	assertState(string(coreconfirmation.StatePending), string(cloudworker.StateWaitingUser))
	confirmationService, err := coreconfirmation.NewService(h.confirmations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = confirmationService.Confirm(h.ctx, coreconfirmation.ConfirmCommand{
		ConfirmationID: offer.Confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(),
		ExpectedRevision: offer.Confirmation.Revision, At: h.now,
	}); err != nil {
		t.Fatal(err)
	}
	assertState(string(coreconfirmation.StateConfirmed), string(cloudworker.StateQueued))
	running, _, err := NewCoreTaskStore(h.store).ClaimNextDue(h.ctx, "offer-reference", h.now, 2*time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	assertState(string(coreconfirmation.StateConsumed), string(cloudworker.StateProvisioning))
	sshStore, err := NewSSHWorkerStore(h.store, "cloud-worker/artifacts")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sshStore.Begin(h.ctx, running); err != nil {
		t.Fatal(err)
	}
	assertState(string(coreconfirmation.StateConsumed), string(cloudworker.StateRunning))
	turn, err := conversationStore.GetTurn(h.ctx, offer.Plan.TurnID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conversationStore.RequestTurnCancel(h.ctx, core.TurnCancelCommand{
		RequestID: uuid.NewString(), TurnID: turn.ID,
	}); err != nil {
		t.Fatal(err)
	}
	assertState(string(coreconfirmation.StateConsumed), string(cloudworker.StateCanceled))
}

func TestConversationHistoryOmitsCloudWorkerRunWithoutDurableAuthority(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	offer := h.propose(t)

	var messageID string
	var raw []byte
	if err := h.store.pool.QueryRow(h.ctx, `SELECT message_id::text,references_json
		FROM core_messages WHERE conversation_id=$1 AND references_json @> '[{"kind":"execution_run"}]'::jsonb`,
		offer.Plan.ConversationID).Scan(&messageID, &raw); err != nil {
		t.Fatal(err)
	}
	var references []core.Reference
	if json.Unmarshal(raw, &references) != nil {
		t.Fatal("stored Cloud Worker references are invalid")
	}
	missingRunID := uuid.NewString()
	for index := range references {
		if references[index].Kind == "execution_run" {
			references[index].RunID = missingRunID
		}
	}
	encoded, err := referenceArrayJSONPG(references)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.pool.Exec(h.ctx, `UPDATE core_messages SET references_json=$2 WHERE message_id=$1`, messageID, encoded); err != nil {
		t.Fatal(err)
	}

	conversationStore, err := NewCoreConversationStore(h.store)
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := conversationStore.LoadConversation(h.ctx, offer.Plan.ConversationID)
	if err != nil {
		t.Fatal(err)
	}
	var planReferences, runReferences, confirmationReferences int
	for _, message := range conversation.Messages {
		for _, reference := range message.References {
			switch reference.Kind {
			case "execution_plan":
				planReferences++
			case "execution_run":
				runReferences++
			case "execution_confirmation":
				confirmationReferences++
			}
		}
	}
	if planReferences != 1 || runReferences != 0 || confirmationReferences != 1 {
		t.Fatalf("history references = plan:%d run:%d confirmation:%d", planReferences, runReferences, confirmationReferences)
	}
}

func TestRejectedCloudWorkerPlanRemainsAvailableToLaterModelContext(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	offer := h.propose(t)
	confirmationService, err := coreconfirmation.NewService(h.confirmations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = confirmationService.Reject(h.ctx, coreconfirmation.RejectCommand{
		ConfirmationID: offer.Confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(),
		ExpectedRevision: offer.Confirmation.Revision, Reason: coreconfirmation.ReasonUserRejected, At: h.now,
	}); err != nil {
		t.Fatal(err)
	}
	const legacySummary = "Cloud Worker offer was rejected. No AWS resources were created."
	if _, err = h.store.pool.Exec(h.ctx, `UPDATE core_messages SET content=$2 WHERE conversation_id=$1 AND content LIKE 'Cloud Worker offer was rejected.%'`, offer.Plan.ConversationID, legacySummary); err != nil {
		t.Fatal(err)
	}
	conversationStore, err := NewCoreConversationStore(h.store)
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := conversationStore.LoadConversation(h.ctx, offer.Plan.ConversationID)
	if err != nil || conversation.Messages[len(conversation.Messages)-1].Content != legacySummary {
		t.Fatalf("legacy transcript=%+v err=%v", conversation.Messages, err)
	}
	projected, err := conversationStore.ProjectModelContext(h.ctx, conversation, offer.Plan.OwnerID, offer.Plan.AccountGeneration)
	wantCompute := cloudworker.PublicComputeSummary(offer.Plan.Compute)
	if err != nil || !strings.Contains(projected.Messages[len(projected.Messages)-1].Content, wantCompute) {
		t.Fatalf("projected context=%+v err=%v want=%q", projected.Messages, err, wantCompute)
	}
	reloaded, err := conversationStore.LoadConversation(h.ctx, offer.Plan.ConversationID)
	if err != nil || reloaded.Messages[len(reloaded.Messages)-1].Content != legacySummary {
		t.Fatalf("model projection mutated transcript=%+v err=%v", reloaded.Messages, err)
	}
}

func TestSSHWorkerStoreTerminalizesQuotaFailureAndResumesTurn(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	offer := h.propose(t)
	confirmationService, err := coreconfirmation.NewService(h.confirmations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = confirmationService.Confirm(h.ctx, coreconfirmation.ConfirmCommand{ConfirmationID: offer.Confirmation.ConfirmationID,
		IdempotencyKey: uuid.NewString(), ExpectedRevision: offer.Confirmation.Revision, At: h.now}); err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(h.store)
	claimed, _, err := tasks.ClaimNextDue(h.ctx, "quota-failure", h.now, 2*time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	sshStore, err := NewSSHWorkerStore(h.store, "cloud-worker/artifacts")
	if err != nil {
		t.Fatal(err)
	}
	run, err := sshStore.Begin(h.ctx, claimed)
	if err != nil {
		t.Fatal(err)
	}
	if err = sshStore.Progress(h.ctx, &run, "provisioning_worker", "Selecting or provisioning Worker"); err != nil {
		t.Fatal(err)
	}
	summary := "AWS EC2 quota is insufficient in us-east-1; request quota-request-1 is PENDING."
	if err = sshStore.Fail(h.ctx, run, sshflow.Result{WorkerID: offer.Execution.ExecutionID}, "aws_quota_increase_pending", summary); err != nil {
		t.Fatal(err)
	}
	failed, err := tasks.GetTask(h.ctx, claimed.ID)
	if err != nil || failed.Status != coretask.StatusFailed || failed.FailureCode != "aws_quota_increase_pending" || failed.FailureSummary != summary {
		t.Fatalf("task=%+v err=%v", failed, err)
	}
	execution, err := h.cloud.GetExecutionForAuthority(h.ctx, h.owner, h.generation, offer.Execution.RunID)
	if err != nil || execution.State != cloudworker.StateFailed || execution.FailureCode != "aws_quota_increase_pending" || execution.FailureSummary != summary {
		t.Fatalf("execution=%+v err=%v", execution, err)
	}
	turn, err := h.conversation.GetTurn(h.ctx, offer.Plan.TurnID)
	if err != nil || turn.State != core.TurnAccepted || turn.DispatchState != "" {
		t.Fatalf("turn=%+v err=%v", turn, err)
	}
}

type interruptedSSHWorkerExecutor struct{ err error }

func (executor interruptedSSHWorkerExecutor) Execute(ctx context.Context, request sshflow.Request) (sshflow.Result, error) {
	if err := request.ReportProgress(ctx, "connecting_worker", "Connecting to Worker"); err != nil {
		return sshflow.Result{}, err
	}
	return sshflow.Result{WorkerID: request.ExecutionID}, executor.err
}

func TestSSHWorkerHandlerPersistsDestroyedWorkerFailureAndResumesTurn(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "active execution canceled", err: context.Canceled},
		{name: "failed execution recovered after restart", err: sshworker.ErrExecutionFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newPGCloudWorkerHarness(t)
			defer h.cleanup()
			offer := h.propose(t)
			confirmations, err := coreconfirmation.NewService(h.confirmations)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = confirmations.Confirm(h.ctx, coreconfirmation.ConfirmCommand{
				ConfirmationID: offer.Confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(),
				ExpectedRevision: offer.Confirmation.Revision, At: h.now,
			}); err != nil {
				t.Fatal(err)
			}
			tasks := NewCoreTaskStore(h.store)
			claimed, _, err := tasks.ClaimNextDue(h.ctx, "worker-destroy", h.now, 2*time.Minute, 1)
			if err != nil {
				t.Fatal(err)
			}
			store, err := NewSSHWorkerStore(h.store, "cloud-worker/artifacts")
			if err != nil {
				t.Fatal(err)
			}
			handler, err := sshflow.NewHandler(store, interruptedSSHWorkerExecutor{err: test.err})
			if err != nil {
				t.Fatal(err)
			}
			outcome := handler.Handle(h.ctx, claimed)
			if !errors.Is(outcome.Err, test.err) || !outcome.TerminalOwned {
				t.Fatalf("outcome=%+v", outcome)
			}
			failed, err := tasks.GetTask(h.ctx, claimed.ID)
			if err != nil || failed.Status != coretask.StatusFailed || failed.FailureCode != "ssh_worker_failed" || failed.Lease != nil {
				t.Fatalf("task=%+v err=%v", failed, err)
			}
			execution, err := h.cloud.GetExecutionForAuthority(h.ctx, h.owner, h.generation, offer.Execution.RunID)
			if err != nil || execution.State != cloudworker.StateFailed || execution.FailureSummary != test.err.Error() {
				t.Fatalf("execution=%+v err=%v", execution, err)
			}
			turn, err := h.conversation.GetTurn(h.ctx, offer.Plan.TurnID)
			if err != nil || turn.State != core.TurnAccepted || turn.DispatchState != "" {
				t.Fatalf("turn=%+v err=%v", turn, err)
			}
			var terminalEvents, toolResults int
			if err = h.store.pool.QueryRow(h.ctx, `SELECT count(*) FROM core_task_events WHERE task_id=$1 AND phase='ssh_worker_terminal' AND status='failed'`, claimed.ID).Scan(&terminalEvents); err != nil {
				t.Fatal(err)
			}
			if err = h.store.pool.QueryRow(h.ctx, `SELECT count(*) FROM core_conversation_turn_events WHERE turn_id=$1 AND kind=$2`, turn.ID, string(core.TurnEventToolResult)).Scan(&toolResults); err != nil {
				t.Fatal(err)
			}
			if terminalEvents != 1 || toolResults != 1 {
				t.Fatalf("terminal events=%d conversation tool results=%d", terminalEvents, toolResults)
			}
		})
	}
}

func TestSSHWorkerDestroyFencesLateResultCatalogCommit(t *testing.T) {
	for _, test := range []struct {
		name        string
		reuse       bool
		queued      bool
		finishFirst bool
	}{
		{name: "new Worker running"},
		{name: "reused Worker running", reuse: true},
		{name: "reused Worker queued", reuse: true, queued: true},
		{name: "result committed before destroy", finishFirst: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newPGCloudWorkerHarness(t)
			defer h.cleanup()
			workerID := uuid.NewString()
			if test.reuse {
				if err := h.service.EnablePersistentWorkerReuse(pgCloudRetainedReuseResolver{workerID: workerID}); err != nil {
					t.Fatal(err)
				}
			}
			offer := h.propose(t)
			if !test.reuse {
				workerID = offer.Plan.ExecutionID
				confirmations, err := coreconfirmation.NewService(h.confirmations)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = confirmations.Confirm(h.ctx, coreconfirmation.ConfirmCommand{
					ConfirmationID: offer.Confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(),
					ExpectedRevision: offer.Confirmation.Revision, At: h.now,
				}); err != nil {
					t.Fatal(err)
				}
			}
			store, err := NewSSHWorkerStore(h.store, "cloud-worker/artifacts")
			if err != nil {
				t.Fatal(err)
			}
			tasks := NewCoreTaskStore(h.store)
			var run sshflow.Run
			if !test.queued {
				task, _, err := tasks.ClaimNextDue(h.ctx, "destroy-race", h.now, 2*time.Minute, 1)
				if err != nil {
					t.Fatal(err)
				}
				run, err = store.Begin(h.ctx, task)
				if err != nil {
					t.Fatal(err)
				}
			}
			result := sshflow.Result{Summary: "finished", WorkerID: workerID, Artifacts: []sshflow.Artifact{{
				ArtifactID: uuid.NewString(), ExecutionID: offer.Plan.ExecutionID, Kind: "file", Name: "result.txt",
				MediaType: "text/plain", RelativePath: "cloud-worker/artifacts/" + offer.Plan.ExecutionID + "/result.txt",
				SizeBytes: 4, SHA256: strings.Repeat("a", 64),
			}}}
			if test.finishFirst {
				if err = store.Complete(h.ctx, run, result); err != nil {
					t.Fatal(err)
				}
			}
			authority := sshworker.OwnerAuthority{OwnerID: h.owner, AccountGeneration: h.generation}
			foreign := authority
			foreign.AccountGeneration++
			if err = store.StopWorkerExecutions(h.ctx, foreign, workerID); err != nil {
				t.Fatal(err)
			}
			if task, err := tasks.GetTask(h.ctx, offer.Plan.TaskID); err != nil || task.Status == coretask.StatusCanceled {
				t.Fatalf("foreign destroy changed task=%+v err=%v", task, err)
			}
			for range 2 {
				if err = store.StopWorkerExecutions(h.ctx, authority, workerID); err != nil {
					t.Fatal(err)
				}
			}
			if !test.finishFirst && !test.queued {
				if err = store.Complete(h.ctx, run, result); !errors.Is(err, cloudworker.ErrLeaseConflict) {
					t.Fatalf("late successful result escaped destroyed-task fence: %v", err)
				}
			}
			var artifacts int
			if err = h.store.pool.QueryRow(h.ctx, `SELECT count(*) FROM core_server_artifacts WHERE server_id=$1`, workerID).Scan(&artifacts); err != nil {
				t.Fatal(err)
			}
			wantArtifacts := 0
			if test.finishFirst {
				wantArtifacts = 1
			}
			if artifacts != wantArtifacts {
				t.Fatalf("catalog artifacts=%d want=%d", artifacts, wantArtifacts)
			}
			if !test.finishFirst {
				task, err := tasks.GetTask(h.ctx, offer.Plan.TaskID)
				if err != nil || task.Status != coretask.StatusCanceled || task.FailureCode != "user_canceled" || task.Lease != nil {
					t.Fatalf("task=%+v err=%v", task, err)
				}
				turn, err := h.conversation.GetTurn(h.ctx, offer.Plan.TurnID)
				if err != nil || turn.State != core.TurnCanceled || !strings.Contains(turn.TerminalSummary, "Worker is being destroyed") {
					t.Fatalf("turn=%+v err=%v", turn, err)
				}
			}
		})
	}
}

func TestSSHWorkerStoreRebindsConsumedReservationAfterTaskReclaim(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	offer := h.propose(t)
	confirmationService, err := coreconfirmation.NewService(h.confirmations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = confirmationService.Confirm(h.ctx, coreconfirmation.ConfirmCommand{
		ConfirmationID: offer.Confirmation.ConfirmationID,
		IdempotencyKey: uuid.NewString(), ExpectedRevision: offer.Confirmation.Revision, At: h.now,
	}); err != nil {
		t.Fatal(err)
	}

	tasks := NewCoreTaskStore(h.store)
	first, _, err := tasks.ClaimNextDue(h.ctx, "ssh-worker-first", h.now, 2*time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	sshStore, err := NewSSHWorkerStore(h.store, "cloud-worker/artifacts")
	if err != nil {
		t.Fatal(err)
	}
	firstRun, err := sshStore.Begin(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	consumed, err := h.confirmations.Get(h.ctx, offer.Confirmation.ConfirmationID)
	if err != nil || consumed.State != coreconfirmation.StateConsumed {
		t.Fatalf("confirmation=%+v err=%v", consumed, err)
	}

	reclaimAt := first.Lease.ExpiresAt.Add(time.Microsecond)
	reclaimed, _, err := tasks.ClaimNextDue(h.ctx, "ssh-worker-reclaimed", reclaimAt, 2*time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if reclaimed.ID != first.ID || reclaimed.Attempt != first.Attempt || reclaimed.LeaseEpoch != first.LeaseEpoch+1 ||
		reclaimed.Revision != first.Revision+1 {
		t.Fatalf("first=%+v reclaimed=%+v", first, reclaimed)
	}
	secondRun, err := sshStore.Begin(context.Background(), reclaimed)
	if err != nil {
		t.Fatalf("reclaimed Begin() error=%v", err)
	}
	if secondRun.Execution.ExecutionID != firstRun.Execution.ExecutionID || secondRun.Plan.PlanID != firstRun.Plan.PlanID {
		t.Fatalf("first run=%+v reclaimed run=%+v", firstRun, secondRun)
	}
	if err = sshStore.Progress(h.ctx, &secondRun, "connecting_worker", "Connecting to Worker"); err != nil {
		t.Fatalf("append Worker progress: %v", err)
	}

	after, err := h.confirmations.Get(h.ctx, offer.Confirmation.ConfirmationID)
	if err != nil || after.State != coreconfirmation.StateConsumed || after.Revision != consumed.Revision {
		t.Fatalf("confirmation after reclaim=%+v err=%v", after, err)
	}
	var reservationCount int
	var taskID string
	var attempt uint32
	var epoch, revision uint64
	var expiresAt time.Time
	if err = h.store.pool.QueryRow(h.ctx, `SELECT count(*) OVER(),task_id::text,acquired_attempt,
		acquired_lease_epoch,task_revision,acquired_lease_expires_at
		FROM core_confirmation_reservations WHERE confirmation_id=$1 AND active=true`,
		offer.Confirmation.ConfirmationID).Scan(&reservationCount, &taskID, &attempt, &epoch, &revision, &expiresAt); err != nil {
		t.Fatal(err)
	}
	if reservationCount != 1 || taskID != reclaimed.ID || attempt != reclaimed.Attempt ||
		epoch != reclaimed.LeaseEpoch || revision != secondRun.Task.Revision || !expiresAt.Equal(reclaimed.Lease.ExpiresAt) {
		t.Fatalf("reservation count=%d task=%s attempt=%d epoch=%d revision=%d expires=%s reclaimed=%+v",
			reservationCount, taskID, attempt, epoch, revision, expiresAt, reclaimed)
	}
	if err = sshStore.Complete(h.ctx, secondRun, sshflow.Result{Summary: "deployment complete", WorkerID: "worker-one"}); err != nil {
		t.Fatal(err)
	}
	var runEventKind, runEventState string
	var runEventRevision uint64
	if err = h.store.pool.QueryRow(h.ctx, `SELECT kind,state,revision FROM core_cloud_worker_events
		WHERE execution_id=$1 ORDER BY sequence DESC LIMIT 1`, offer.Execution.ExecutionID).
		Scan(&runEventKind, &runEventState, &runEventRevision); err != nil {
		t.Fatal(err)
	}
	if runEventKind != "execution_succeeded" || runEventState != string(cloudworker.StateSucceeded) ||
		runEventRevision != secondRun.Execution.Revision+1 {
		t.Fatalf("terminal run event kind=%s state=%s revision=%d", runEventKind, runEventState, runEventRevision)
	}
	completed, err := tasks.GetTask(h.ctx, reclaimed.ID)
	if err != nil || completed.Status != coretask.StatusSucceeded || completed.Result == nil || completed.Result.Summary != "deployment complete" || completed.FailureCode != "" || completed.FailureSummary != "" {
		t.Fatalf("completed task=%+v err=%v", completed, err)
	}
	progress, _, err := tasks.ListProgress(h.ctx, reclaimed.ID, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	foundProgress := false
	for _, event := range progress {
		if event.Phase == "connecting_worker" && event.Message == "Connecting to Worker" {
			foundProgress = true
		}
	}
	if !foundProgress {
		t.Fatalf("Worker progress event missing: %+v", progress)
	}
	conversationStore, err := NewCoreConversationStore(h.store)
	if err != nil {
		t.Fatal(err)
	}
	events, err := conversationStore.LoadTurnEvents(h.ctx, offer.Plan.TurnID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var workerStatuses, workerProgress []string
	for _, event := range events {
		if event.Kind != core.TurnEventWorkerStatus {
			continue
		}
		if event.ExecutionID != offer.Execution.ExecutionID || event.Revision == 0 || event.CreatedAt.IsZero() ||
			event.ValidateWorkerStatusAuthority() != nil {
			t.Fatalf("invalid Worker status event: %+v", event)
		}
		workerStatuses = append(workerStatuses, event.Status)
		if event.Phase != "" {
			workerProgress = append(workerProgress, event.Phase)
		}
	}
	if want := []string{"queued", "provisioning", "running", "running", "succeeded"}; !reflect.DeepEqual(workerStatuses, want) {
		t.Fatalf("Worker status sequence=%v want=%v events=%+v", workerStatuses, want, events)
	}
	if !reflect.DeepEqual(workerProgress, []string{"connecting_worker"}) {
		t.Fatalf("Worker progress=%v events=%+v", workerProgress, events)
	}
	resumed, err := conversationStore.GetTurn(h.ctx, offer.Plan.TurnID)
	if err != nil || resumed.State != core.TurnAccepted {
		t.Fatalf("resumed turn=%+v err=%v", resumed, err)
	}
	lease, err := conversationStore.ClaimTurn(h.ctx, resumed.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := conversationStore.LoadConversation(h.ctx, offer.Plan.ConversationID)
	if err != nil {
		t.Fatal(err)
	}
	response := core.ChatResponse{RequestID: resumed.RequestID, ConversationID: resumed.ConversationID,
		Revision: conversation.Revision + 1, Done: true, ModelProfileID: resumed.ProfileID,
		Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "deployment complete",
			ModelProfileID: resumed.ProfileID, CreatedAt: time.Now().UTC()}}
	if _, err = conversationStore.CommitTurn(h.ctx, lease, response); err != nil {
		t.Fatalf("commit resumed Worker turn: %v", err)
	}
	conversation, err = conversationStore.LoadConversation(h.ctx, offer.Plan.ConversationID)
	if err != nil || len(conversation.Messages) != 3 || conversation.Messages[0].Role != core.RoleUser ||
		!strings.Contains(conversation.Messages[1].Content, "Cloud Worker quote is ready for confirmation. Selected configuration:") ||
		conversation.Messages[2].Content != "deployment complete" {
		t.Fatalf("terminal Worker transcript=%+v err=%v", conversation.Messages, err)
	}
}

func TestSSHWorkerStorePreservesRunningWorkerWhenTurnIsSteered(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	offer := h.propose(t)
	confirmationService, err := coreconfirmation.NewService(h.confirmations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = confirmationService.Confirm(h.ctx, coreconfirmation.ConfirmCommand{
		ConfirmationID: offer.Confirmation.ConfirmationID,
		IdempotencyKey: uuid.NewString(), ExpectedRevision: offer.Confirmation.Revision, At: h.now,
	}); err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(h.store)
	running, _, err := tasks.ClaimNextDue(h.ctx, "ssh-worker-steer", h.now, 2*time.Minute, 1)
	if err != nil || running.Lease == nil {
		t.Fatalf("running task=%+v err=%v", running, err)
	}
	sshStore, err := NewSSHWorkerStore(h.store, "cloud-worker/artifacts")
	if err != nil {
		t.Fatal(err)
	}
	run, err := sshStore.Begin(h.ctx, running)
	if err != nil {
		t.Fatal(err)
	}
	if err = sshStore.Progress(h.ctx, &run, "executing_remote_task", "Executing task on Worker"); err != nil {
		t.Fatal(err)
	}
	conversationStore, err := NewCoreConversationStore(h.store)
	if err != nil {
		t.Fatal(err)
	}
	waiting, err := conversationStore.GetTurn(h.ctx, offer.Plan.TurnID)
	if err != nil || waiting.State != core.TurnWaitingConfirmation || waiting.DispatchState != "completed" || waiting.DispatchResult == nil {
		t.Fatalf("waiting turn=%+v err=%v", waiting, err)
	}
	steerID := uuid.NewString()
	steered, interrupt, err := conversationStore.RequestTurnSteer(h.ctx, core.TurnSteerCommand{
		RequestID: steerID, TurnID: waiting.ID, ExpectedRevision: waiting.Revision,
		Instruction: "also report the service URL",
	})
	if err != nil || interrupt || steered.State != core.TurnWaitingConfirmation || steered.Revision != waiting.Revision+1 ||
		steered.DispatchState != waiting.DispatchState || !reflect.DeepEqual(steered.DispatchResult, waiting.DispatchResult) {
		t.Fatalf("steered=%+v interrupt=%v err=%v", steered, interrupt, err)
	}
	afterSteer, err := tasks.GetTask(h.ctx, running.ID)
	if err != nil || afterSteer.Status != coretask.StatusRunning || afterSteer.Lease == nil ||
		afterSteer.Lease.Holder != run.Task.Lease.Holder || afterSteer.LeaseEpoch != run.Task.LeaseEpoch ||
		!afterSteer.Lease.ExpiresAt.Equal(run.Task.Lease.ExpiresAt) || afterSteer.Revision != run.Task.Revision ||
		afterSteer.ProgressSequence != run.Task.ProgressSequence {
		t.Fatalf("steer changed Worker task authority before=%+v after=%+v err=%v", run.Task, afterSteer, err)
	}
	if err = sshStore.Progress(h.ctx, &run, "executing_remote_task", "Executing task on Worker"); err != nil {
		t.Fatalf("progress after steer: %v", err)
	}
	afterTask, err := tasks.GetTask(h.ctx, running.ID)
	if err != nil || afterTask.Status != coretask.StatusRunning || afterTask.Lease == nil ||
		afterTask.Lease.Holder != run.Task.Lease.Holder || afterTask.LeaseEpoch != run.Task.LeaseEpoch ||
		!afterTask.Lease.ExpiresAt.Equal(run.Task.Lease.ExpiresAt) || afterTask.Revision != afterSteer.Revision+1 ||
		afterTask.ProgressSequence != afterSteer.ProgressSequence+1 {
		t.Fatalf("Worker progress changed authority before=%+v after=%+v err=%v", afterSteer, afterTask, err)
	}
	if err = sshStore.Complete(h.ctx, run, sshflow.Result{Summary: "deployment complete", WorkerID: "worker-one"}); err != nil {
		t.Fatal(err)
	}
	resumed, err := conversationStore.GetTurn(h.ctx, waiting.ID)
	steers, steerErr := conversationStore.ListTurnSteers(h.ctx, waiting.ID)
	if err != nil || resumed.State != core.TurnAccepted || steerErr != nil || len(steers) != 1 || steers[0].RequestID != steerID || !steers[0].Deferred {
		t.Fatalf("resumed=%+v steers=%+v err=%v steer_err=%v", resumed, steers, err, steerErr)
	}
}

func TestConversationTurnSteerAcceptsUnconfirmedCloudWorkerOffer(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	offer := h.propose(t)
	conversationStore, err := NewCoreConversationStore(h.store)
	if err != nil {
		t.Fatal(err)
	}
	waiting, err := conversationStore.GetTurn(h.ctx, offer.Plan.TurnID)
	if err != nil || waiting.State != core.TurnWaitingConfirmation || waiting.Revision != 2 || waiting.DispatchState != "completed" {
		t.Fatalf("waiting turn=%+v err=%v", waiting, err)
	}
	var planStatus, taskStatus string
	if err = h.store.pool.QueryRow(h.ctx, `SELECT p.status,t.status FROM core_cloud_worker_plans p
		JOIN core_tasks t ON t.task_id=p.task_id WHERE p.plan_id=$1`, offer.Plan.PlanID).Scan(&planStatus, &taskStatus); err != nil {
		t.Fatal(err)
	}
	if planStatus != string(cloudworker.StateWaitingUser) || taskStatus != string(coretask.StatusWaitingUser) {
		t.Fatalf("offer plan_status=%q task_status=%q", planStatus, taskStatus)
	}
	steerID := uuid.NewString()
	steered, interrupt, err := conversationStore.RequestTurnSteer(h.ctx, core.TurnSteerCommand{
		RequestID: steerID, TurnID: waiting.ID, ExpectedRevision: waiting.Revision,
		Instruction: "add RIVER-LANTERN-7392 to both reports",
	})
	if err != nil || interrupt || steered.State != core.TurnWaitingConfirmation || steered.Revision != waiting.Revision+1 ||
		steered.DispatchState != waiting.DispatchState || !reflect.DeepEqual(steered.DispatchResult, waiting.DispatchResult) {
		t.Fatalf("steered=%+v interrupt=%v err=%v", steered, interrupt, err)
	}
	steers, err := conversationStore.ListTurnSteers(h.ctx, waiting.ID)
	if err != nil || len(steers) != 1 || steers[0].RequestID != steerID || !steers[0].Deferred {
		t.Fatalf("steers=%+v err=%v", steers, err)
	}
	if err = h.store.pool.QueryRow(h.ctx, `SELECT p.status,t.status FROM core_cloud_worker_plans p
		JOIN core_tasks t ON t.task_id=p.task_id WHERE p.plan_id=$1`, offer.Plan.PlanID).Scan(&planStatus, &taskStatus); err != nil ||
		planStatus != string(cloudworker.StateWaitingUser) || taskStatus != string(coretask.StatusWaitingUser) {
		t.Fatalf("steer changed unconfirmed offer plan_status=%q task_status=%q err=%v", planStatus, taskStatus, err)
	}
}

func TestSSHWorkerContinuationPersistsRetainedWorkerNextAction(t *testing.T) {
	call := core.ToolCall{ID: uuid.NewString(), Name: coremodel.IntrinsicCloudWorkerProposeToolName, Arguments: `{}`}
	plan := cloudworker.Plan{TaskID: uuid.NewString(), PlanID: uuid.NewString(), ExecutionID: uuid.NewString(),
		AccountGeneration: 1, Revision: 1, Status: string(cloudworker.StateWaitingUser)}
	execution := cloudworker.Execution{RunID: uuid.NewString(), ExecutionID: plan.ExecutionID, Revision: 2, State: cloudworker.StateSucceeded}
	steerID := uuid.NewString()
	_, result, err := sshWorkerContinuation(
		&core.ModelRunResult{ToolCalls: []core.ToolCall{call}},
		plan,
		execution,
		"deployment complete",
		sshflow.Result{WorkerID: "worker-one", AppliedSteerIDs: []string{steerID}},
		[]sshflow.Artifact{
			{ArtifactID: uuid.NewString(), Kind: "stdout", Name: "stdout.txt"},
			{ArtifactID: uuid.NewString(), Kind: "stderr", Name: "stderr.txt"},
			{ArtifactID: uuid.NewString(), Kind: "file", Name: "legacy/STDOUT"},
			{ArtifactID: uuid.NewString(), Kind: "file", Name: "legacy/stdout.TXT"},
			{ArtifactID: uuid.NewString(), Kind: "file", Name: "diagnostics/STDERR"},
			{ArtifactID: uuid.NewString(), Kind: "file", Name: `legacy\stderr.txt`},
			{ArtifactID: uuid.NewString(), Kind: "file", Name: "reports/Final-Report.MD"},
			{ArtifactID: uuid.NewString(), Kind: "file", Name: "completion-report.md"},
			{ArtifactID: uuid.NewString(), Kind: "file", Name: "legacy/final.json"},
			{ArtifactID: uuid.NewString(), ExecutionID: plan.ExecutionID, Kind: "file", Name: "requested-result.html", MediaType: "text/html", SizeBytes: 4, SHA256: strings.Repeat("a", 64)},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	var completion struct {
		WorkerID         string   `json:"worker_id"`
		PersistentWorker bool     `json:"persistent_worker"`
		AppliedSteerIDs  []string `json:"applied_steer_ids"`
		Artifacts        []struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"artifacts"`
		NextAction struct {
			Kind      string `json:"kind"`
			Operation string `json:"operation"`
			WorkerID  string `json:"worker_id"`
			Default   string `json:"default"`
			Question  string `json:"question"`
		} `json:"next_action"`
	}
	if err = json.Unmarshal([]byte(result.Content), &completion); err != nil ||
		completion.WorkerID != "worker-one" || !completion.PersistentWorker ||
		!reflect.DeepEqual(completion.AppliedSteerIDs, []string{steerID}) ||
		len(completion.Artifacts) != 1 || completion.Artifacts[0].Kind != "execution_artifact" || completion.Artifacts[0].Name != "requested-result.html" ||
		completion.NextAction.Kind != "confirm_destroy_worker" || completion.NextAction.Operation != "destroy_worker" ||
		completion.NextAction.WorkerID != completion.WorkerID || completion.NextAction.Default != "retain" ||
		!strings.Contains(completion.NextAction.Question, "whether to destroy") {
		t.Fatalf("completion=%+v err=%v", completion, err)
	}
	if len(result.References) != 3 || result.References[0].Kind != "execution_plan" ||
		result.References[1].Kind != "execution_run" || result.References[1].RunID != execution.RunID {
		t.Fatalf("completion references=%+v", result.References)
	}
}
