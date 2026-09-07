package postgres

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshflow"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/google/uuid"
)

func TestWorkerReplyCommitFencesCancellationAndNewEventsPostgres(t *testing.T) {
	for _, change := range []string{"none", "cancel", "steer", "event"} {
		t.Run(change, func(t *testing.T) {
			h := openTurnDB(t)
			ctx := context.Background()
			cmd := turnCommand()
			turn, err := h.store.StartTurn(ctx, cmd)
			if err != nil {
				t.Fatal(err)
			}
			createTestProfile(ctx, t, h.store.Store, turn.ProfileID, "test", "integration-secret")
			lease, err := h.store.ClaimTurn(ctx, turn.ID, time.Now().UTC(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "cancel":
				_, err = h.store.RequestTurnCancel(ctx, core.TurnCancelCommand{RequestID: uuid.NewString(), TurnID: turn.ID})
			case "steer":
				_, _, err = h.store.RequestTurnSteer(ctx, core.TurnSteerCommand{RequestID: uuid.NewString(), TurnID: turn.ID, ExpectedRevision: lease.Turn.Revision, Instruction: "Send it to Alice too"})
			case "event":
				_, err = h.store.AppendTurnEvent(ctx, turn.ID, core.TurnEvent{Kind: core.TurnEventStarted, CreatedAt: time.Now().UTC()})
			}
			if err != nil {
				t.Fatal(err)
			}
			response := core.ChatResponse{RequestID: cmd.RequestID, ConversationID: turn.ConversationID, Revision: 2, Done: true, ModelProfileID: turn.ProfileID,
				Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "网站已完成。", ModelProfileID: turn.ProfileID, CreatedAt: time.Now().UTC()}}
			got, err := h.store.CommitTurnWorkerReply(ctx, lease, response)
			if change == "none" {
				if err != nil || got.State != core.TurnCompleted || got.ModelDispatchCount != 0 {
					t.Fatalf("direct commit=%+v err=%v", got, err)
				}
				fresh, e := h.store.GetTurn(ctx, turn.ID)
				if e != nil || fresh.Response == nil || fresh.Response.Message.Content != response.Message.Content {
					t.Fatalf("fresh response=%+v err=%v", fresh.Response, e)
				}
			} else if err == nil {
				t.Fatalf("direct completion ignored %s", change)
			}
		})
	}
}

type workerReplyForbiddenModel struct{ calls atomic.Int64 }

func (m *workerReplyForbiddenModel) Run(context.Context, core.ModelRunRequest) (core.ModelRunResult, error) {
	m.calls.Add(1)
	return core.ModelRunResult{}, errors.New("unexpected parent rewrite")
}
func (m *workerReplyForbiddenModel) Stream(ctx context.Context, req core.ModelRunRequest, _ func(core.ModelDelta) error) (core.ModelRunResult, error) {
	return m.Run(ctx, req)
}

func TestWorkerReplyResumesFromDurableCompletionWithoutModelPostgres(t *testing.T) {
	h := newPGCloudWorkerHarnessWithResponseMode(t, "reply_to_user")
	defer h.cleanup()
	offer := h.propose(t)
	confirmations, err := coreconfirmation.NewService(h.confirmations)
	if err != nil {
		t.Fatal(err)
	}
	_, err = confirmations.Confirm(h.ctx, coreconfirmation.ConfirmCommand{ConfirmationID: offer.Confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: offer.Confirmation.Revision, At: h.now})
	if err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(h.store)
	claimed, _, err := tasks.ClaimNextDue(h.ctx, "direct-answer", h.now, 2*time.Minute, 1)
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
	const reply = "The website is ready to use."
	if err := workerStore.Complete(h.ctx, run, sshflow.Result{Summary: "Worker completed", Report: reply, WorkerID: offer.Plan.ExecutionID}); err != nil {
		t.Fatal(err)
	}
	// Reconstruct the real service after Worker persistence, as on restart.
	model := &workerReplyForbiddenModel{}
	service, err := core.NewService(h.conversation, model, nil, staticConversationProfile{snapshot: run.ModelSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if err := service.RecoverTurns(h.ctx); err != nil {
		t.Fatal(err)
	}
	turn := waitConversationTurnState(t, h.conversation, offer.Plan.TurnID, core.TurnCompleted, 3*time.Second)
	if model.calls.Load() != 0 || turn.Response == nil || !strings.HasPrefix(turn.Response.Message.Content, reply) {
		t.Fatalf("calls=%d response=%+v", model.calls.Load(), turn.Response)
	}
	conversation, err := h.conversation.LoadConversation(h.ctx, turn.ConversationID)
	if err != nil {
		t.Fatal(err)
	}
	last := conversation.Messages[len(conversation.Messages)-1]
	if last.Content != turn.Response.Message.Content {
		t.Fatal("history differs from terminal answer")
	}
	if err := service.RecoverTurns(h.ctx); err != nil {
		t.Fatal(err)
	}
	if model.calls.Load() != 0 {
		t.Fatal("restart duplicated summary")
	}
}
