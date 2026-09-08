package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshflow"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

func TestWorkerRunReusesWithoutNewConfirmationAndResumesReplyPostgres(t *testing.T) {
	h := newPGCloudWorkerHarnessForTool(t, "reply_to_user", coremodel.IntrinsicCloudWorkerRunToolName)
	defer h.cleanup()
	workerID := uuid.NewString()
	h.command.WorkerID = workerID
	if err := h.service.EnablePersistentWorkerReuse(pgCloudRetainedReuseResolver{workerID: workerID}); err != nil {
		t.Fatal(err)
	}
	offer := h.propose(t)
	if offer.Plan.RequiresWorkerCreationConfirmation() || offer.Confirmation.State != coreconfirmation.StateConfirmed || offer.Plan.ReuseWorkerID != workerID || offer.Execution.State != cloudworker.StateQueued {
		t.Fatalf("run requested a new machine: plan=%+v confirmation=%s", offer.Plan, offer.Confirmation.State)
	}
	events, err := h.conversation.LoadTurnEvents(h.ctx, offer.Plan.TurnID, 0, 256)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Kind == core.TurnEventWaitingConfirmation {
			t.Fatal("existing run emitted new-machine confirmation card")
		}
	}
	tasks := NewCoreTaskStore(h.store)
	claimed, _, err := tasks.ClaimNextDue(h.ctx, "worker-run", h.now, 2*time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	workerStore, err := NewSSHWorkerStore(h.store, "cloud-worker/artifacts")
	if err != nil {
		t.Fatal(err)
	}
	run, err := workerStore.Begin(h.ctx, claimed)
	if err != nil {
		t.Fatal(err)
	}
	if run.Plan.ReuseWorkerID != workerID {
		t.Fatal("execution changed target")
	}
	if err := workerStore.Complete(h.ctx, run, sshflow.Result{WorkerID: workerID, Summary: "Existing task completed", Report: "已在原服务器完成优化，域名保持不变。"}); err != nil {
		t.Fatal(err)
	}
	model := &workerReplyForbiddenModel{}
	service, err := core.NewService(h.conversation, model, nil, staticConversationProfile{snapshot: run.ModelSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if err := service.RecoverTurns(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := waitConversationTurnState(t, h.conversation, offer.Plan.TurnID, core.TurnCompleted, 3*time.Second)
	if model.calls.Load() != 0 || done.Response == nil || !strings.Contains(done.Response.Message.Content, "原服务器完成优化") {
		t.Fatalf("unexpected re-synthesis: calls=%d response=%+v", model.calls.Load(), done.Response)
	}
}

func TestWorkerRunCannotPersistCreationPlanPostgres(t *testing.T) {
	h := newPGCloudWorkerHarnessForTool(t, "continue", coremodel.IntrinsicCloudWorkerRunToolName)
	defer h.cleanup()
	// Even an invalid internal caller that drops the target cannot turn the
	// recorded existing-only tool authority into a paid creation confirmation.
	_, err := h.service.Propose(h.ctx, h.command)
	if !errors.Is(err, cloudworker.ErrInvalid) {
		t.Fatalf("run creation plan was admitted: %v", err)
	}
	var count int
	if err := h.store.pool.QueryRow(h.ctx, `SELECT count(*) FROM core_cloud_worker_plans WHERE turn_id=$1`, h.command.TurnID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("plans=%d err=%v", count, err)
	}
}

type balanceFailedWorker struct{ worker string }

func (e balanceFailedWorker) Execute(ctx context.Context, r sshflow.Request) (sshflow.Result, error) {
	for _, phase := range []string{"worker_thinking", "worker_reading", "worker_model_failed"} {
		if err := r.ReportProgress(ctx, phase, phase); err != nil {
			return sshflow.Result{}, err
		}
	}
	return sshflow.Result{WorkerID: e.worker, ExitCode: 1, FailureCode: "provider_request_failed", HTTPStatus: 402}, errors.New("remote Worker exited with code 1")
}

func TestWorkerBalanceAndActivitiesSurviveActualHandlerAndRestartPostgres(t *testing.T) {
	h := newPGCloudWorkerHarnessForTool(t, "continue", coremodel.IntrinsicCloudWorkerRunToolName)
	defer h.cleanup()
	workerID := uuid.NewString()
	h.command.WorkerID = workerID
	if err := h.service.EnablePersistentWorkerReuse(pgCloudRetainedReuseResolver{workerID: workerID}); err != nil {
		t.Fatal(err)
	}
	offer := h.propose(t)
	tasks := NewCoreTaskStore(h.store)
	claimed, _, err := tasks.ClaimNextDue(h.ctx, "visible-worker-error", h.now, 2*time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewSSHWorkerStore(h.store, "cloud-worker/artifacts")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := sshflow.NewHandler(store, balanceFailedWorker{worker: workerID})
	if err != nil {
		t.Fatal(err)
	}
	result := handler.Handle(h.ctx, claimed)
	if result.Err == nil {
		t.Fatal("failure was marked successful")
	}
	task, err := tasks.GetTask(h.ctx, claimed.ID)
	if err != nil || task.FailureCode != "model_balance_insufficient" || !strings.Contains(task.FailureSummary, "HTTP 402") {
		t.Fatalf("failure=%s %s err=%v", task.FailureCode, task.FailureSummary, err)
	}
	turn, err := h.conversation.GetTurn(h.ctx, offer.Plan.TurnID)
	if err != nil {
		t.Fatal(err)
	}
	model := &workerReplyForbiddenModel{}
	service, err := core.NewService(h.conversation, model, nil, staticConversationProfile{snapshot: turn.ProfileSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if err := service.RecoverTurns(h.ctx); err != nil {
		t.Fatal(err)
	}
	done := waitConversationTurnState(t, h.conversation, turn.ID, core.TurnCompleted, 3*time.Second)
	if model.calls.Load() != 0 || !strings.Contains(done.Response.Message.Content, "HTTP 402") || !strings.Contains(done.Response.Message.Content, "model_balance_insufficient") {
		t.Fatalf("failure was hidden: calls=%d response=%+v", model.calls.Load(), done.Response)
	}
	events, err := h.conversation.LoadTurnEvents(h.ctx, turn.ID, 0, 256)
	if err != nil {
		t.Fatal(err)
	}
	visible := false
	for _, event := range events {
		if event.Phase == "worker_reading" {
			raw, err := agentcapability.ProjectDurableTurnEventJSON(done, event)
			if err != nil || !strings.Contains(string(raw), "worker_reading") {
				t.Fatal("public activity projection missing")
			}
			visible = true
		}
	}
	if !visible {
		t.Fatal("activity was lost during persistence")
	}
}
