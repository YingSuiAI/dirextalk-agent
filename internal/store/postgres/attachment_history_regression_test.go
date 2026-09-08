package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

func uploadHistoryCSV(t *testing.T, ctx context.Context, store *CoreConversationStore, command *core.TurnStartCommand) {
	t.Helper()
	content := []byte("name,time\r\nrefresh,12\r\n")
	hash := sha256.Sum256(content)
	digest := hex.EncodeToString(hash[:])
	begin, err := store.BeginTurnAttachmentUpload(ctx, core.BeginTurnAttachmentUploadCommand{OwnerID: command.OwnerID, AccountGeneration: command.AccountGeneration, IdempotencyKey: uuid.NewString(), TurnRequestID: command.RequestID, Kind: core.TurnAttachmentKindFile, Name: "refresh.csv", MediaType: "text/csv", DeclaredSize: uint64(len(content)), ContentSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	appended, err := store.AppendTurnAttachmentUpload(ctx, core.AppendTurnAttachmentUploadCommand{OwnerID: command.OwnerID, AccountGeneration: command.AccountGeneration, IdempotencyKey: uuid.NewString(), UploadID: begin.UploadID, ExpectedRevision: begin.Revision, Data: content, ChunkSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	committed, err := store.CommitTurnAttachmentUpload(ctx, core.CommitTurnAttachmentUploadCommand{OwnerID: command.OwnerID, AccountGeneration: command.AccountGeneration, IdempotencyKey: uuid.NewString(), UploadID: begin.UploadID, ExpectedRevision: appended.Revision, ContentSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	command.AcceptedAttachmentIDs = []string{committed.SourceID}
}

func TestWorkerOfferPreservesAttachmentInAuthoritativeHistory(t *testing.T) {
	h := newPGCloudWorkerHarnessForTool(t, "continue", coremodel.IntrinsicCloudWorkerProposeToolName, func(ctx context.Context, s *CoreConversationStore, c *core.TurnStartCommand) {
		uploadHistoryCSV(t, ctx, s, c)
	})
	defer h.cleanup()
	offer := h.propose(t)
	assertHistory := func() {
		restarted, err := NewCoreConversationStore(h.store)
		if err != nil {
			t.Fatal(err)
		}
		conversation, err := restarted.LoadConversation(h.ctx, h.command.ConversationID)
		if err != nil {
			t.Fatal(err)
		}
		var found int
		for _, message := range conversation.Messages {
			if message.Role != core.RoleUser || message.TurnID != h.command.TurnID {
				continue
			}
			found++
			if len(message.Attachments) != 1 || message.Attachments[0].Name != "refresh.csv" || message.Attachments[0].MediaType != "text/csv" || message.Attachments[0].SourceID != h.lease.Turn.AttachmentSources[0].SourceID {
				t.Fatalf("Worker offer lost attachment presentation: %+v", message.Attachments)
			}
		}
		if found != 1 {
			t.Fatalf("user messages=%d", found)
		}
	}
	assertHistory()
	// A receipt retry may not duplicate or erase the user's attachment card.
	replay, err := h.service.Propose(h.ctx, h.command)
	if err != nil || replay.Plan.PlanID != offer.Plan.PlanID {
		t.Fatalf("replay: %v", err)
	}
	assertHistory()
	canceled, err := h.cloud.RequestCancel(h.ctx, h.owner, h.generation, offer.Execution.RunID, offer.Execution.Revision, uuid.NewString())
	if err != nil || canceled.State != cloudworker.StateCanceled {
		t.Fatalf("cancel: %v", err)
	}
	assertHistory()
}

func TestCSVUploadReachesConversationModelWithoutWorker(t *testing.T) {
	h := openTurnDB(t)
	ctx := context.Background()
	profileID := uuid.NewString()
	createTestProfile(ctx, t, h.store.Store, profileID, "test", "test")
	command := core.TurnStartCommand{RequestID: uuid.NewString(), OwnerID: "@csv:example.test", AccountGeneration: 7,
		ConversationID: uuid.NewString(), Prompt: "read this CSV", ProfileID: profileID, ExpectedProfileRevision: 1, ExpectedCredentialVersion: 1}
	uploadHistoryCSV(t, ctx, h.store, &command)
	model := &finalizationConversationModel{result: core.ModelRunResult{Done: true, Message: core.Message{Role: core.RoleAssistant, Content: "Refresh time is 12."}}}
	service, err := core.NewService(h.store, model, nil, core.AdaptProfileResolver(h.store.Store))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	turn, err := service.StartTurn(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	waitConversationTurnState(t, h.store, turn.ID, core.TurnCompleted, 5*time.Second)
	requests := model.snapshotRequests()
	if len(requests) != 1 {
		t.Fatalf("model calls=%d", len(requests))
	}
	var found bool
	for _, parts := range requests[0].InputPartsByMessageID {
		for _, part := range parts {
			if part.Type == coremodel.MessageInputPartText && strings.Contains(part.Text, "name,time\r\nrefresh,12\r\n") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("committed CSV content did not reach the actual model consumer")
	}
	conversation, err := h.store.LoadConversation(ctx, turn.ConversationID)
	if err != nil || len(conversation.Messages) < 2 || len(conversation.Messages[0].Attachments) != 1 {
		t.Fatalf("CSV history lost metadata: %v", err)
	}
	var offers int
	if err = h.pool.QueryRow(ctx, `SELECT count(*) FROM core_cloud_worker_plans`).Scan(&offers); err != nil || offers != 0 {
		t.Fatalf("plain CSV caused Worker offers=%d err=%v", offers, err)
	}
}
