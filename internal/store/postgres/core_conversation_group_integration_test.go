package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/google/uuid"
)

type groupConversationModelPG struct {
	mu       sync.Mutex
	requests []core.ModelRunRequest
}

func (m *groupConversationModelPG) Run(_ context.Context, request core.ModelRunRequest) (core.ModelRunResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, request)
	return core.ModelRunResult{Done: true, Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant,
		Content: fmt.Sprintf("group answer %d", len(m.requests)), CreatedAt: time.Now().UTC()}}, nil
}

func (m *groupConversationModelPG) Stream(ctx context.Context, request core.ModelRunRequest, _ func(core.ModelDelta) error) (core.ModelRunResult, error) {
	return m.Run(ctx, request)
}

type allowGroupGuardPG struct{}

func (allowGroupGuardPG) ValidateGroupOrigin(context.Context, core.GroupOrigin) error { return nil }

func groupTurnCommandPG() core.TurnStartCommand {
	command := turnCommand()
	origin := core.GroupOrigin{RequestID: command.RequestID, RoomID: "!room:example.test", EventID: "$source-event",
		ActorID: "@member:example.test", OwnerID: "@owner:example.test", AgentMXID: "@ying:example.test",
		AccountGeneration: 4, BindingRevision: 12}
	command.GroupOrigin = &origin
	command.ConversationID, command.OwnerID, command.AccountGeneration = origin.ConversationID(), origin.OwnerID, origin.AccountGeneration
	return command
}

func groupTurnRuntimePG(t *testing.T, command core.TurnStartCommand) core.TurnRuntimeSnapshot {
	t.Helper()
	runtime, err := core.NewTurnRuntimeSnapshotForMode("isolated group policy", command.ProfileSnapshot, nil,
		command.ExtensionSnapshotDigest(), core.TurnAttachmentSnapshotDigest(command.AttachmentSources), command.ExecutionMode)
	if err != nil {
		t.Fatal(err)
	}
	runtime.GroupOrigin = command.GroupOrigin
	return runtime
}

func TestGroupConversationScopePersistenceIsolationAndMemoryExclusionPostgres(t *testing.T) {
	h := openTurnDB(t)
	ctx := context.Background()
	command := groupTurnCommandPG()
	runtime := groupTurnRuntimePG(t, command)
	if _, err := h.store.StartTurn(ctx, command); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("group admission bypassed runtime authority: %v", err)
	}
	turn, err := h.store.StartTurnWithRuntime(ctx, command, runtime)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := h.store.GetTurn(ctx, turn.ID)
	if err != nil || loaded.GroupOrigin == nil || *loaded.GroupOrigin != *command.GroupOrigin || loaded.RuntimeSnapshot.Digest() != runtime.Digest() {
		t.Fatalf("origin persistence failed: err=%v", err)
	}
	replay, err := h.store.StartTurnWithRuntime(ctx, command, runtime)
	if err != nil || replay.ID != turn.ID || replay.RequestFingerprint != turn.RequestFingerprint {
		t.Fatalf("durable event replay changed turn: err=%v", err)
	}
	conversation, err := h.store.LoadConversation(ctx, turn.ConversationID)
	if err != nil || conversation.GroupScope == nil || *conversation.GroupScope != command.GroupOrigin.Scope() {
		t.Fatalf("group scope not recovered: err=%v", err)
	}
	private := turnCommand()
	if _, err := h.store.StartTurn(ctx, private); err != nil {
		t.Fatal(err)
	}
	listed, _, err := h.store.ListConversations(ctx, "", 100)
	if err != nil || len(listed) != 1 || listed[0].ID != private.ConversationID {
		t.Fatalf("private conversation list mixed group history: count=%d err=%v", len(listed), err)
	}
	active, err := h.store.ListActiveGroupTurns(ctx)
	if err != nil || len(active) != 1 || active[0].ID != turn.ID {
		t.Fatalf("group revoke scan mixed private turns: count=%d err=%v", len(active), err)
	}
	privateInjection := turnCommand()
	privateInjection.ConversationID = turn.ConversationID
	if _, err := h.store.StartTurn(ctx, privateInjection); !errors.Is(err, core.ErrGroupAuthorization) {
		t.Fatalf("private turn entered group scope: %v", err)
	}
	if _, err := h.pool.Exec(ctx, `UPDATE core_conversations SET group_scope_json=NULL WHERE conversation_id=$1`, turn.ConversationID); err == nil {
		t.Fatal("database allowed immutable group scope removal")
	}
	if _, _, err := h.store.RequestTurnSteer(ctx, core.TurnSteerCommand{RequestID: uuid.NewString(), TurnID: turn.ID, ExpectedRevision: turn.Revision, Instruction: "private owner instruction"}); !errors.Is(err, core.ErrGroupAuthorization) {
		t.Fatalf("owner private steering entered group transcript: %v", err)
	}
	createTestProfile(ctx, t, h.store.Store, command.ProfileID, command.ProfileSnapshot.Model, command.ProfileSnapshot.APIKey)
	h.store.EnableMemoryCapture()
	if _, err := h.pool.Exec(ctx, `INSERT INTO core_memory_configs(singleton,enabled,revision) VALUES(true,true,1)`); err != nil {
		t.Fatal(err)
	}
	lease, err := h.store.ClaimTurn(ctx, turn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.CommitTurn(ctx, lease, core.ChatResponse{RequestID: turn.RequestID, ConversationID: turn.ConversationID,
		Revision: 2, ModelProfileID: turn.ProfileID, Done: true, ConversationTitle: "group only",
		Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "Group-only answer", ModelProfileID: turn.ProfileID, CreatedAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	var observations int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM core_memory_observations`).Scan(&observations); err != nil || observations != 0 {
		t.Fatalf("group conversation extracted into private memory: count=%d err=%v", observations, err)
	}
	next := command
	nextOrigin := *command.GroupOrigin
	nextOrigin.RequestID, nextOrigin.EventID, nextOrigin.ActorID = uuid.NewString(), "$next-event", "@other-member:example.test"
	next.GroupOrigin, next.RequestID = &nextOrigin, nextOrigin.RequestID
	second, err := h.store.StartTurnWithRuntime(ctx, next, groupTurnRuntimePG(t, next))
	if err != nil || second.ConversationID != turn.ConversationID || second.GroupOrigin.ActorID != nextOrigin.ActorID {
		t.Fatalf("another member could not use same isolated group conversation: err=%v", err)
	}
	after, err := h.store.LoadConversation(ctx, second.ConversationID)
	if err != nil || len(after.Messages) != 2 || after.Messages[1].Content != "Group-only answer" {
		t.Fatalf("group-local transcript not preserved: err=%v", err)
	}
	if _, err := h.pool.Exec(ctx, `UPDATE core_conversation_turns SET state='waiting_confirmation' WHERE turn_id=$1`, second.ID); err != nil {
		t.Fatal(err)
	}
	active, err = h.store.ListActiveGroupTurns(ctx)
	if err != nil || len(active) != 1 || active[0].ID != second.ID || active[0].State != core.TurnWaitingConfirmation {
		t.Fatalf("confirmation wait missing from revoke scan: count=%d err=%v", len(active), err)
	}
}

func TestGroupConversationCannotAdoptPrivateScopeOrChangedEpochPostgres(t *testing.T) {
	h := openTurnDB(t)
	ctx := context.Background()
	command := groupTurnCommandPG()
	// Even an empty private conversation with the predictable UUID may not be
	// relabeled or read as group context by the trusted adapter.
	if _, err := h.pool.Exec(ctx, `INSERT INTO core_conversations(conversation_id,title) VALUES($1,'private')`, command.ConversationID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.StartTurnWithRuntime(ctx, command, groupTurnRuntimePG(t, command)); !errors.Is(err, core.ErrGroupAuthorization) {
		t.Fatalf("private conversation was adopted as group context: %v", err)
	}
	next := *command.GroupOrigin
	next.BindingRevision++
	command.GroupOrigin = &next
	command.ConversationID = next.ConversationID()
	turn, err := h.store.StartTurnWithRuntime(ctx, command, groupTurnRuntimePG(t, command))
	if err != nil {
		t.Fatal(err)
	}
	tampered := *turn.RuntimeSnapshot
	changed := *tampered.GroupOrigin
	changed.ActorID = "@forged:example.test"
	tampered.GroupOrigin = &changed
	raw, _ := json.Marshal(tampered)
	if _, err := h.pool.Exec(ctx, `UPDATE core_conversation_turns SET runtime_snapshot_json=$2 WHERE turn_id=$1`, turn.ID, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.GetTurn(ctx, turn.ID); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("changed origin passed stored digest validation: %v", err)
	}
}

func TestGroupConversationServiceAdmissionMultipleActorsReplayAndNewEpochPostgres(t *testing.T) {
	h := openTurnDB(t)
	ctx := context.Background()
	command := groupTurnCommandPG()
	origin := *command.GroupOrigin
	command.GroupOrigin = nil
	command.ProfileSnapshot.SystemPrompt = "PRIVATE OWNER GLOBAL PROMPT"
	createTestProfile(ctx, t, h.store.Store, command.ProfileID, command.ProfileSnapshot.Model, command.ProfileSnapshot.APIKey)
	model := &groupConversationModelPG{}
	service, err := core.NewService(h.store, model, nil, staticConversationProfile{snapshot: command.ProfileSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	service.SetGroupAuthorizationGuard(allowGroupGuardPG{})
	first, err := service.StartGroupTurn(ctx, command, origin)
	if err != nil {
		t.Fatal(err)
	}
	waitConversationTurnState(t, h.store, first.ID, core.TurnCompleted, 5*time.Second)
	nextOrigin := origin
	nextOrigin.RequestID, nextOrigin.EventID, nextOrigin.ActorID = uuid.NewString(), "$second-group-question", "@second:example.test"
	next := command
	next.RequestID, next.Prompt = nextOrigin.RequestID, "另外一个群成员的问题"
	second, err := service.StartGroupTurn(ctx, next, nextOrigin)
	if err != nil || second.ExpectedRevision == nil || *second.ExpectedRevision != 2 || second.ConversationID != first.ConversationID {
		t.Fatalf("continued group admission did not pin revision: err=%v", err)
	}
	waitConversationTurnState(t, h.store, second.ID, core.TurnCompleted, 5*time.Second)
	replay, err := service.StartGroupTurn(ctx, next, nextOrigin)
	if err != nil || replay.ID != second.ID || replay.RequestFingerprint != second.RequestFingerprint {
		t.Fatalf("completed group replay changed its revision identity: err=%v", err)
	}
	newEpoch := nextOrigin
	newEpoch.RequestID, newEpoch.EventID = uuid.NewString(), "$after-enable"
	newEpoch.BindingRevision++
	fresh := next
	fresh.RequestID, fresh.ConversationID = newEpoch.RequestID, ""
	third, err := service.StartGroupTurn(ctx, fresh, newEpoch)
	if err != nil || third.ConversationID == first.ConversationID {
		t.Fatalf("new binding retained old context: err=%v", err)
	}
	waitConversationTurnState(t, h.store, third.ID, core.TurnCompleted, 5*time.Second)
	model.mu.Lock()
	defer model.mu.Unlock()
	if len(model.requests) != 3 || len(model.requests[0].Conversation.Messages) != 1 || len(model.requests[1].Conversation.Messages) != 3 || len(model.requests[2].Conversation.Messages) != 1 {
		t.Fatalf("group context windows or replay count changed: requests=%d", len(model.requests))
	}
	for _, request := range model.requests {
		if request.Snapshot.SystemPrompt != "" || strings.Contains(request.Profile.SystemPrompt, "PRIVATE OWNER GLOBAL PROMPT") {
			t.Fatal("group execution inherited private profile instructions")
		}
	}
	if !strings.Contains(model.requests[1].Profile.SystemPrompt, nextOrigin.ActorID) {
		t.Fatal("current group author lost from trusted system metadata")
	}
}
