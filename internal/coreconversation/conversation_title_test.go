package coreconversation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type conversationTitleGeneratorFunc func(context.Context, string, string) (string, error)

func (f conversationTitleGeneratorFunc) GenerateConversationTitle(ctx context.Context, userText, assistantText string) (string, error) {
	return f(ctx, userText, assistantText)
}

func TestProvisionalConversationTitleIsImmediateDeterministicAndBounded(t *testing.T) {
	input := "  `请帮我部署服务。后面还有很长的说明`  "
	if got := ProvisionalConversationTitle(input); got != "请帮我部署服务" || got != ProvisionalConversationTitle(input) || len([]rune(got)) > conversationTitleMaxRunes {
		t.Fatalf("provisional title=%q", got)
	}
	if got := ProvisionalConversationTitle("？！"); got != "？！" {
		t.Fatalf("punctuation-only provisional title=%q", got)
	}
}

type titleCapturingTurnStore struct {
	*readOnlyTurnStore
	conversationTitle       string
	conversationTitleSource string
	turns                   []Turn
}

func (s *titleCapturingTurnStore) CommitTurn(ctx context.Context, lease TurnLease, response ChatResponse) (Turn, error) {
	s.conversationTitle, s.conversationTitleSource = response.ConversationTitle, response.ConversationTitleSource
	return s.readOnlyTurnStore.CommitTurn(ctx, lease, response)
}

func (s *titleCapturingTurnStore) ListTurns(context.Context, string, string, int) ([]Turn, string, error) {
	return append([]Turn(nil), s.turns...), "", nil
}

func TestDurableTurnCarriesAutomaticTitleIntoAtomicCommit(t *testing.T) {
	snapshot := testTurnSnapshot()
	conversationID := uuid.NewString()
	turn := Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: conversationID,
		Prompt: "请帮我部署一个 AWS 服务", ProfileID: snapshot.ProfileID,
		ProfileSnapshot: snapshot, ProfileSnapshotDigest: snapshot.Digest(),
		State: TurnAccepted, Revision: 1, LastSequence: 1, CreatedAt: time.Now().UTC(),
	}
	base := newFakeStore()
	base.conv[conversationID] = Conversation{ID: conversationID, Revision: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	store := &titleCapturingTurnStore{readOnlyTurnStore: &readOnlyTurnStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: turn},
		events:                []TurnEvent{{TurnID: turn.ID, Sequence: 1, Revision: 1, Kind: TurnEventAccepted, CreatedAt: turn.CreatedAt}},
	}}
	service, err := NewService(store, &capturingTurnModel{}, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) {
		return snapshot, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	var userText, assistantText string
	service.SetConversationTitleGenerator(conversationTitleGeneratorFunc(func(_ context.Context, user, assistant string) (string, error) {
		userText, assistantText = user, assistant
		return "  `AWS 服务部署。`  ", nil
	}))
	service.executeTurn(context.Background(), turn.ID)
	if store.conversationTitle != "AWS 服务部署" || userText != turn.Prompt || assistantText != "ok" {
		t.Fatalf("committed title=%q user=%q assistant=%q", store.conversationTitle, userText, assistantText)
	}
}

func TestDurableTurnDoesNotOverwriteManualConversationTitle(t *testing.T) {
	snapshot := testTurnSnapshot()
	conversationID := uuid.NewString()
	turn := Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: conversationID,
		Prompt: "当前消息", ProfileID: snapshot.ProfileID, ProfileSnapshot: snapshot,
		ProfileSnapshotDigest: snapshot.Digest(), State: TurnAccepted, Revision: 1, LastSequence: 1, CreatedAt: time.Now().UTC(),
	}
	base := newFakeStore()
	base.conv[conversationID] = Conversation{ID: conversationID, Title: "用户标题", Revision: 1, CreatedAt: turn.CreatedAt, UpdatedAt: turn.CreatedAt}
	store := &titleCapturingTurnStore{readOnlyTurnStore: &readOnlyTurnStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: turn},
		events:                []TurnEvent{{TurnID: turn.ID, Sequence: 1, Revision: 1, Kind: TurnEventAccepted, CreatedAt: turn.CreatedAt}},
	}}
	service, err := NewService(store, &capturingTurnModel{}, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) {
		return snapshot, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	called := false
	service.SetConversationTitleGenerator(conversationTitleGeneratorFunc(func(context.Context, string, string) (string, error) {
		called = true
		return "模型标题", nil
	}))
	service.executeTurn(context.Background(), turn.ID)
	if called || store.conversationTitle != "用户标题" {
		t.Fatalf("generator_called=%v committed_title=%q", called, store.conversationTitle)
	}
}

func TestDurableTurnUsesFirstPersistedUserMessageAsTitleSource(t *testing.T) {
	snapshot := testTurnSnapshot()
	conversationID := uuid.NewString()
	createdAt := time.Now().UTC()
	turn := Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: conversationID,
		Prompt: "当前消息", ProfileID: snapshot.ProfileID, ProfileSnapshot: snapshot,
		ProfileSnapshotDigest: snapshot.Digest(), State: TurnAccepted, Revision: 1, LastSequence: 1, CreatedAt: createdAt,
	}
	firstUserText := "第一条用户消息。后续说明"
	base := newFakeStore()
	base.conv[conversationID] = Conversation{
		ID: conversationID, Revision: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
		Messages: []Message{
			{ID: uuid.NewString(), Role: RoleUser, Content: firstUserText, ModelProfileID: snapshot.ProfileID, CreatedAt: createdAt.Add(time.Microsecond)},
			{ID: uuid.NewString(), Role: RoleAssistant, Content: "旧回复", ModelProfileID: snapshot.ProfileID, CreatedAt: createdAt.Add(2 * time.Microsecond)},
		},
	}
	store := &titleCapturingTurnStore{readOnlyTurnStore: &readOnlyTurnStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: turn},
		events:                []TurnEvent{{TurnID: turn.ID, Sequence: 1, Revision: 1, Kind: TurnEventAccepted, CreatedAt: turn.CreatedAt}},
	}}
	service, err := NewService(store, &capturingTurnModel{}, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) {
		return snapshot, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	var source string
	service.SetConversationTitleGenerator(conversationTitleGeneratorFunc(func(_ context.Context, userText, _ string) (string, error) {
		source = userText
		return "", errors.New("tool model unavailable")
	}))
	service.executeTurn(context.Background(), turn.ID)
	if source != firstUserText || store.conversationTitleSource != firstUserText || store.conversationTitle != "第一条用户消息" {
		t.Fatalf("source=%q committed_source=%q committed_title=%q", source, store.conversationTitleSource, store.conversationTitle)
	}
}

func TestSuccessfulTurnReplacesProvisionalTitleLeftByStoppedFirstTurn(t *testing.T) {
	snapshot := testTurnSnapshot()
	conversationID := uuid.NewString()
	stopped := Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: conversationID,
		Prompt: "请帮我部署一个服务", ProfileID: snapshot.ProfileID,
		State: TurnCanceled, Revision: 2, CreatedAt: time.Now().UTC().Add(-time.Minute),
	}
	current := Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: conversationID,
		Prompt: "继续完成", ProfileID: snapshot.ProfileID,
		ProfileSnapshot: snapshot, ProfileSnapshotDigest: snapshot.Digest(),
		State: TurnAccepted, Revision: 1, LastSequence: 1, CreatedAt: time.Now().UTC(),
	}
	base := newFakeStore()
	base.conv[conversationID] = Conversation{
		ID: conversationID, Title: ProvisionalConversationTitle(stopped.Prompt), Revision: 1,
		CreatedAt: stopped.CreatedAt, UpdatedAt: stopped.CreatedAt,
	}
	store := &titleCapturingTurnStore{
		readOnlyTurnStore: &readOnlyTurnStore{
			publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: current},
			events:                []TurnEvent{{TurnID: current.ID, Sequence: 1, Revision: 1, Kind: TurnEventAccepted, CreatedAt: current.CreatedAt}},
		},
		turns: []Turn{stopped},
	}
	service, err := NewService(store, &capturingTurnModel{}, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) {
		return snapshot, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	var source string
	service.SetConversationTitleGenerator(conversationTitleGeneratorFunc(func(_ context.Context, userText, _ string) (string, error) {
		source = userText
		return "服务部署进度", nil
	}))
	service.executeTurn(context.Background(), current.ID)
	if source != stopped.Prompt || store.conversationTitle != "服务部署进度" || store.conversationTitleSource != stopped.Prompt {
		t.Fatalf("source=%q committed_title=%q committed_source=%q", source, store.conversationTitle, store.conversationTitleSource)
	}
}
