package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/google/uuid"
)

func TestAutomaticContextCompactionRejectsStaleAdmissionPlanPostgres(t *testing.T) {
	h := openTurnDB(t)
	ctx := context.Background()
	tests := []struct {
		name   string
		mutate func(*testing.T, core.TurnStartCommand, core.Conversation)
	}{
		{name: "conversation revision", mutate: func(t *testing.T, cmd core.TurnStartCommand, _ core.Conversation) {
			if result, err := h.pool.Exec(ctx, `UPDATE core_conversations SET revision=revision+1 WHERE conversation_id=$1`, cmd.ConversationID); err != nil || result.RowsAffected() != 1 {
				t.Fatalf("mutate revision rows=%d err=%v", result.RowsAffected(), err)
			}
		}},
		{name: "previous offset", mutate: func(t *testing.T, cmd core.TurnStartCommand, _ core.Conversation) {
			insertCompactionContextFixture(t, h, cmd.ConversationID, core.NewWorkingContext(), 1)
		}},
		{name: "previous protected digest", mutate: func(t *testing.T, cmd core.TurnStartCommand, _ core.Conversation) {
			working := core.NewWorkingContext()
			working.OriginalGoal = "different protected state"
			insertCompactionContextFixture(t, h, cmd.ConversationID, working, 0)
		}},
		{name: "transcript count", mutate: func(t *testing.T, cmd core.TurnStartCommand, conversation core.Conversation) {
			insertCompactionMessageFixture(t, h, cmd, 4, core.RoleAssistant, "late append", conversation.Messages[2].CreatedAt.Add(time.Second))
		}},
		{name: "first boundary", mutate: func(t *testing.T, cmd core.TurnStartCommand, conversation core.Conversation) {
			replaceCompactionMessageFixture(t, h, cmd, 1, core.RoleUser, "replacement first", conversation.Messages[0].CreatedAt)
		}},
		{name: "through boundary", mutate: func(t *testing.T, cmd core.TurnStartCommand, conversation core.Conversation) {
			replaceCompactionMessageFixture(t, h, cmd, 2, core.RoleAssistant, "replacement through", conversation.Messages[1].CreatedAt)
		}},
		{name: "retained boundary", mutate: func(t *testing.T, cmd core.TurnStartCommand, conversation core.Conversation) {
			replaceCompactionMessageFixture(t, h, cmd, 3, core.RoleUser, "replacement retained", conversation.Messages[2].CreatedAt)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd, conversation := seedCompactionAdmissionFixture(t, h)
			cmd.ContextCompaction = automaticCompactionPlanFixture(t, conversation)
			test.mutate(t, cmd, conversation)
			runtime, err := core.NewTurnRuntimeSnapshotForMode("stale plan runtime", cmd.ProfileSnapshot, nil, "", "", cmd.ExecutionMode)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = h.store.StartTurnWithRuntime(ctx, cmd, runtime); !errors.Is(err, core.ErrConflict) {
				t.Fatalf("stale admission plan err=%v", err)
			}
			var turns int
			if err = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM core_conversation_turns WHERE request_id=$1`, cmd.RequestID).Scan(&turns); err != nil || turns != 0 {
				t.Fatalf("stale plan admitted turn count=%d err=%v", turns, err)
			}
		})
	}
}

func seedCompactionAdmissionFixture(t *testing.T, h *turnDBHarness) (core.TurnStartCommand, core.Conversation) {
	t.Helper()
	ctx := context.Background()
	cmd := turnCommand()
	cmd.ProfileSnapshot.ContextWindow = 1024
	cmd.ProfileSnapshot.MaxOutputTokens = 128
	createTestProfile(ctx, t, h.store.Store, cmd.ProfileID, cmd.ProfileSnapshot.Model, cmd.ProfileSnapshot.APIKey)
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	conversation := core.Conversation{ID: cmd.ConversationID, Title: "stale plan", Revision: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := h.store.CreateConversationMutation(ctx, core.CreateConversationCommand{RequestID: uuid.NewString(), Conversation: conversation, Fingerprint: digestConversationPG(conversation)}); err != nil {
		t.Fatal(err)
	}
	insertCompactionMessageFixture(t, h, cmd, 1, core.RoleUser, "original goal", now.Add(time.Minute))
	insertCompactionMessageFixture(t, h, cmd, 2, core.RoleAssistant, strings.Repeat("old answer ", 80), now.Add(2*time.Minute))
	insertCompactionMessageFixture(t, h, cmd, 3, core.RoleUser, "retained request", now.Add(3*time.Minute))
	loaded, err := h.store.LoadConversation(ctx, cmd.ConversationID)
	if err != nil {
		t.Fatal(err)
	}
	expectedRevision := uint64(1)
	cmd.ExpectedRevision = &expectedRevision
	return cmd, loaded
}

func automaticCompactionPlanFixture(t *testing.T, conversation core.Conversation) *core.TurnContextCompaction {
	t.Helper()
	previousDigest := conversation.WorkingContextProtectedDigest
	working, err := core.AdvanceWorkingContextFromTranscript(conversation.WorkingContext, conversation.Messages[:2])
	if err != nil {
		t.Fatal(err)
	}
	working.Projection = &core.WorkingContextProjection{
		Source: core.WorkingContextProjectionAuthoritativeTranscript,
		Scope: core.WorkingContextProjectionScope{
			FirstMessageID: conversation.Messages[0].ID, ThroughMessageID: conversation.Messages[1].ID, MessageCount: 2,
		},
		SupersedesProtectedDigest: previousDigest,
	}
	plan := &core.TurnContextCompaction{
		Offset: 2, WorkingContext: working, Summary: working.SummaryText(),
		ExpectedRevision: conversation.Revision, ExpectedPreviousOffset: conversation.ContextMessageOffset,
		ExpectedPreviousProtectedDigest: previousDigest, ExpectedTranscriptCount: uint64(len(conversation.Messages)),
		FirstMessageID: conversation.Messages[0].ID, ThroughMessageID: conversation.Messages[1].ID,
		RetainedFirstMessageID: conversation.Messages[2].ID,
		EstimatedTokensBefore:  101, EstimatedTokensAfter: 80, ThresholdTokens: 100,
	}
	if err = plan.Validate(); err != nil {
		t.Fatal(err)
	}
	return plan
}

func insertCompactionContextFixture(t *testing.T, h *turnDBHarness, conversationID string, working core.WorkingContext, offset int64) {
	t.Helper()
	raw, err := json.Marshal(working)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.pool.Exec(context.Background(), `INSERT INTO core_conversation_contexts(conversation_id,summary,message_offset,working_context_version,working_context_json,protected_digest,updated_at) VALUES($1,'',$2,$3,$4,$5,clock_timestamp())`, conversationID, offset, core.WorkingContextVersion, raw, working.ProtectedDigest()); err != nil {
		t.Fatal(err)
	}
}

func insertCompactionMessageFixture(t *testing.T, h *turnDBHarness, cmd core.TurnStartCommand, sequence int, role core.Role, content string, createdAt time.Time) {
	t.Helper()
	message := core.Message{ID: uuid.NewString(), Role: role, Content: content, ModelProfileID: cmd.ProfileID, CreatedAt: createdAt.UTC()}
	payload, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.pool.Exec(context.Background(), `INSERT INTO core_messages(message_id,conversation_id,sequence,role,content,model_profile_id,payload_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, message.ID, cmd.ConversationID, sequence, role, content, cmd.ProfileID, payload, message.CreatedAt); err != nil {
		t.Fatal(err)
	}
}

func replaceCompactionMessageFixture(t *testing.T, h *turnDBHarness, cmd core.TurnStartCommand, sequence int, role core.Role, content string, createdAt time.Time) {
	t.Helper()
	if result, err := h.pool.Exec(context.Background(), `DELETE FROM core_messages WHERE conversation_id=$1 AND sequence=$2`, cmd.ConversationID, sequence); err != nil || result.RowsAffected() != 1 {
		t.Fatalf("delete boundary rows=%d err=%v", result.RowsAffected(), err)
	}
	insertCompactionMessageFixture(t, h, cmd, sequence, role, content, createdAt)
}

func TestAutomaticContextCompactionIsAtomicAndRestartStablePostgres(t *testing.T) {
	h := openTurnDB(t)
	ctx := context.Background()
	cmd := turnCommand()
	cmd.ProfileSnapshot.ContextWindow = 2048
	cmd.ProfileSnapshot.MaxOutputTokens = 256
	cmd.Prompt = "answer from the bounded durable context"
	cmd.OwnerID, cmd.AccountGeneration = "@owner:example.test", 7
	createTestProfile(ctx, t, h.store.Store, cmd.ProfileID, cmd.ProfileSnapshot.Model, cmd.ProfileSnapshot.APIKey)
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	conversation := core.Conversation{ID: cmd.ConversationID, Title: "automatic context", Revision: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := h.store.CreateConversationMutation(ctx, core.CreateConversationCommand{
		RequestID: uuid.NewString(), Conversation: conversation, Fingerprint: digestConversationPG(conversation),
	}); err != nil {
		t.Fatal(err)
	}
	const historicalMessages = 8
	messageIDs := make([]string, 0, historicalMessages)
	for index := 0; index < historicalMessages; index++ {
		role := core.RoleUser
		if index%2 == 1 {
			role = core.RoleAssistant
		}
		message := core.Message{
			ID: uuid.NewString(), Role: role,
			Content:        strings.Repeat(fmt.Sprintf("history-%d ", index), 120),
			ModelProfileID: cmd.ProfileID,
			CreatedAt:      now.Add(time.Duration(index+1) * time.Minute),
		}
		payload, err := json.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = h.pool.Exec(ctx, `INSERT INTO core_messages(message_id,conversation_id,sequence,role,content,model_profile_id,payload_json,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, message.ID, cmd.ConversationID, index+1, message.Role, message.Content, message.ModelProfileID, payload, message.CreatedAt); err != nil {
			t.Fatal(err)
		}
		messageIDs = append(messageIDs, message.ID)
	}
	expectedRevision := uint64(1)
	cmd.ExpectedRevision = &expectedRevision
	blocked := &blockingModelDispatchStore{CoreConversationStore: h.store, reached: make(chan struct{}), blockOrdinary: true}
	firstModel := &finalizationConversationModel{result: core.ModelRunResult{Done: true, Message: core.Message{
		ID: uuid.NewString(), Role: core.RoleAssistant, Content: "must not dispatch before restart", CreatedAt: time.Now().UTC(),
	}}}
	service, err := core.NewService(blocked, firstModel, staticConversationExtensions{}, staticConversationProfile{snapshot: cmd.ProfileSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	turn, err := service.StartTurn(ctx, cmd)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked.reached:
	case <-time.After(8 * time.Second):
		t.Fatal("automatic context admission did not reach the pre-dispatch fence")
	}
	compacted, err := h.store.LoadConversation(ctx, cmd.ConversationID)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(compacted.WorkingContext)
	if err != nil || compacted.Revision != expectedRevision || compacted.ContextMessageOffset == 0 ||
		len(compacted.Messages) != historicalMessages || !strings.Contains(string(metadata), `"source":"authoritative_transcript"`) ||
		compacted.WorkingContextProtectedDigest != compacted.WorkingContext.ProtectedDigest() {
		t.Fatalf("automatic compacted conversation=%+v metadata=%s err=%v", compacted, metadata, err)
	}
	for index, message := range compacted.Messages {
		if message.ID != messageIDs[index] {
			t.Fatalf("authoritative transcript changed at %d: got=%s want=%s", index, message.ID, messageIDs[index])
		}
	}
	if len(firstModel.snapshotRequests()) != 0 || turn.RuntimeSnapshot == nil || turn.OwnerID != cmd.OwnerID || turn.AccountGeneration != cmd.AccountGeneration {
		t.Fatalf("provider dispatched before restart or runtime missing: requests=%d turn=%+v", len(firstModel.snapshotRequests()), turn)
	}
	runtimeDigest := turn.RuntimeSnapshot.Digest()
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := h.pool.Exec(ctx, `UPDATE core_conversation_turns SET lease_expires_at=clock_timestamp()-interval '1 second'
		WHERE turn_id=$1 AND request_id=$2 AND state='running' AND dispatch_state=''`, turn.ID, turn.RequestID)
	if err != nil || result.RowsAffected() != 1 {
		t.Fatalf("expire exact simulated-lost lease: rows=%d err=%v", result.RowsAffected(), err)
	}
	restarted, err := NewCoreConversationStore(h.store.Store)
	if err != nil {
		t.Fatal(err)
	}
	finalModel := &finalizationConversationModel{result: core.ModelRunResult{Done: true, Message: core.Message{
		ID: uuid.NewString(), Role: core.RoleAssistant, Content: "completed from compacted context", CreatedAt: time.Now().UTC(),
	}}}
	restartedService, err := core.NewService(restarted, finalModel, staticConversationExtensions{}, staticConversationProfile{snapshot: cmd.ProfileSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	terminal := recoverConversationTurnUntilTerminal(t, restartedService, restarted, turn.ID, 8*time.Second)
	if err = restartedService.Close(); err != nil {
		t.Fatal(err)
	}
	requests := finalModel.snapshotRequests()
	recovered, err := restarted.GetTurn(ctx, turn.ID)
	if err != nil || recovered.RuntimeSnapshot == nil || recovered.RuntimeSnapshot.Digest() != runtimeDigest ||
		recovered.OwnerID != cmd.OwnerID || recovered.AccountGeneration != cmd.AccountGeneration || terminal.State != core.TurnCompleted || len(requests) != 1 {
		t.Fatalf("recovered turn=%+v terminal=%+v requests=%d err=%v", recovered, terminal, len(requests), err)
	}
	requestConversation := requests[0].Conversation
	if requestConversation.ContextMessageOffset != compacted.ContextMessageOffset ||
		requestConversation.WorkingContextProtectedDigest != compacted.WorkingContextProtectedDigest ||
		!reflect.DeepEqual(requestConversation.WorkingContext, compacted.WorkingContext) {
		t.Fatalf("restart model context drifted: request=%+v compacted=%+v", requestConversation, compacted)
	}
	var messageCount int
	if err = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM core_messages WHERE conversation_id=$1`, cmd.ConversationID).Scan(&messageCount); err != nil || messageCount != historicalMessages+2 {
		t.Fatalf("authoritative transcript rows=%d err=%v", messageCount, err)
	}
}
