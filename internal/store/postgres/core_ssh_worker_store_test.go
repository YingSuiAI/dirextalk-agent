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
		epoch != reclaimed.LeaseEpoch || revision != reclaimed.Revision || !expiresAt.Equal(reclaimed.Lease.ExpiresAt) {
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
	conversationStore, err := NewCoreConversationStore(h.store)
	if err != nil {
		t.Fatal(err)
	}
	events, err := conversationStore.LoadTurnEvents(h.ctx, offer.Plan.TurnID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var workerStatuses []string
	for _, event := range events {
		if event.Kind != core.TurnEventWorkerStatus {
			continue
		}
		if event.ExecutionID != offer.Execution.ExecutionID || event.Revision == 0 || event.CreatedAt.IsZero() ||
			event.ValidateWorkerStatusAuthority() != nil {
			t.Fatalf("invalid Worker status event: %+v", event)
		}
		workerStatuses = append(workerStatuses, event.Status)
	}
	if want := []string{"queued", "provisioning", "running", "succeeded"}; !reflect.DeepEqual(workerStatuses, want) {
		t.Fatalf("Worker status sequence=%v want=%v events=%+v", workerStatuses, want, events)
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
	afterTask, err := tasks.GetTask(h.ctx, running.ID)
	if err != nil || afterTask.Status != coretask.StatusRunning || afterTask.Lease == nil ||
		afterTask.Lease.Holder != running.Lease.Holder || afterTask.LeaseEpoch != running.LeaseEpoch ||
		!afterTask.Lease.ExpiresAt.Equal(running.Lease.ExpiresAt) || afterTask.Revision != running.Revision {
		t.Fatalf("Worker task authority changed before=%+v after=%+v err=%v", running, afterTask, err)
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

func TestSSHWorkerContinuationPersistsRetainedWorkerNextAction(t *testing.T) {
	call := core.ToolCall{ID: uuid.NewString(), Name: coremodel.IntrinsicCloudWorkerProposeToolName, Arguments: `{}`}
	plan := cloudworker.Plan{TaskID: uuid.NewString(), PlanID: uuid.NewString(), ExecutionID: uuid.NewString(),
		AccountGeneration: 1, Revision: 1, Status: string(cloudworker.StateWaitingUser)}
	execution := cloudworker.Execution{RunID: uuid.NewString(), ExecutionID: plan.ExecutionID, Revision: 2, State: cloudworker.StateSucceeded}
	_, result, err := sshWorkerContinuation(
		&core.ModelRunResult{ToolCalls: []core.ToolCall{call}},
		plan,
		execution,
		"deployment complete",
		sshflow.Result{WorkerID: "worker-one"},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	var completion struct {
		WorkerID         string `json:"worker_id"`
		PersistentWorker bool   `json:"persistent_worker"`
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
