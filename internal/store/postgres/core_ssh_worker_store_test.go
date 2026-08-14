package postgres

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshflow"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
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
}

func TestSSHWorkerContinuationPersistsRetainedWorkerNextAction(t *testing.T) {
	call := core.ToolCall{ID: uuid.NewString(), Name: coremodel.IntrinsicCloudWorkerProposeToolName, Arguments: `{}`}
	plan := cloudworker.Plan{TaskID: uuid.NewString(), PlanID: uuid.NewString(), ExecutionID: uuid.NewString()}
	_, result, err := sshWorkerContinuation(
		&core.ModelRunResult{ToolCalls: []core.ToolCall{call}},
		plan,
		cloudworker.StateSucceeded,
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
}
