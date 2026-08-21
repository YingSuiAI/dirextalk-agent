package postgres

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshflow"
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
		if loadErr != nil || len(conversation.Messages) != 2 || len(conversation.Messages[1].References) != 3 {
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
		conversation.Messages[1].Content != "Cloud Worker quote is ready for confirmation." ||
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
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	var completion struct {
		WorkerID         string   `json:"worker_id"`
		PersistentWorker bool     `json:"persistent_worker"`
		AppliedSteerIDs  []string `json:"applied_steer_ids"`
		NextAction       struct {
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
		completion.NextAction.Kind != "confirm_destroy_worker" || completion.NextAction.Operation != "destroy_worker" ||
		completion.NextAction.WorkerID != completion.WorkerID || completion.NextAction.Default != "retain" ||
		!strings.Contains(completion.NextAction.Question, "whether to destroy") {
		t.Fatalf("completion=%+v err=%v", completion, err)
	}
	if len(result.References) != 2 || result.References[0].Kind != "execution_plan" ||
		result.References[1].Kind != "execution_run" || result.References[1].RunID != execution.RunID {
		t.Fatalf("completion references=%+v", result.References)
	}
}
