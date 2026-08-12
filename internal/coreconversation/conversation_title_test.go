package coreconversation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type conversationTitleGeneratorFunc func(context.Context, string, string) (string, error)

func (f conversationTitleGeneratorFunc) GenerateConversationTitle(ctx context.Context, userText, assistantText string) (string, error) {
	return f(ctx, userText, assistantText)
}

func TestFirstSuccessfulChatPersistsGeneratedConversationTitle(t *testing.T) {
	store := newFakeStore()
	service, err := NewService(store, &fakeModel{}, nil, fakeProfile{})
	if err != nil {
		t.Fatal(err)
	}
	var gotUser, gotAssistant string
	service.SetConversationTitleGenerator(conversationTitleGeneratorFunc(func(_ context.Context, userText, assistantText string) (string, error) {
		gotUser, gotAssistant = userText, assistantText
		return "  `AWS 服务部署。`  ", nil
	}))
	cmd := command()
	cmd.Prompt = "请帮我部署一个 AWS 服务"
	response, err := service.Chat(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := store.LoadConversation(context.Background(), response.ConversationID)
	if err != nil {
		t.Fatal(err)
	}
	if conversation.Title != "AWS 服务部署" {
		t.Fatalf("title=%q", conversation.Title)
	}
	if gotUser != cmd.Prompt || gotAssistant != "ok" {
		t.Fatalf("generator input user=%q assistant=%q", gotUser, gotAssistant)
	}
}

func TestConversationTitleFallsBackToFirstSentence(t *testing.T) {
	for _, test := range []struct {
		name     string
		generate conversationTitleGeneratorFunc
	}{
		{name: "tool model unavailable", generate: func(context.Context, string, string) (string, error) {
			return "", errors.New("tool model unavailable")
		}},
		{name: "empty model title", generate: func(context.Context, string, string) (string, error) {
			return "  `。`  ", nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newFakeStore()
			service, err := NewService(store, &fakeModel{}, nil, fakeProfile{})
			if err != nil {
				t.Fatal(err)
			}
			service.SetConversationTitleGenerator(test.generate)
			cmd := command()
			cmd.Prompt = "请帮我部署服务。后面还有很长的说明"
			response, err := service.Chat(context.Background(), cmd)
			if err != nil {
				t.Fatal(err)
			}
			conversation, err := store.LoadConversation(context.Background(), response.ConversationID)
			if err != nil {
				t.Fatal(err)
			}
			if conversation.Title != "请帮我部署服务" || len([]rune(conversation.Title)) > conversationTitleMaxRunes || strings.Contains(conversation.Title, "后面还有") {
				t.Fatalf("fallback title=%q", conversation.Title)
			}
		})
	}
}

func TestAutomaticConversationTitleDoesNotOverwriteManualTitle(t *testing.T) {
	store := newFakeStore()
	cmd := command()
	cmd.ConversationID = uuid.NewString()
	now := time.Now().UTC()
	store.conv[cmd.ConversationID] = Conversation{ID: cmd.ConversationID, Title: "用户标题", Revision: 1, CreatedAt: now, UpdatedAt: now}
	service, err := NewService(store, &fakeModel{}, nil, fakeProfile{})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	service.SetConversationTitleGenerator(conversationTitleGeneratorFunc(func(context.Context, string, string) (string, error) {
		called = true
		return "模型标题", nil
	}))
	if _, err = service.Chat(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.LoadConversation(context.Background(), cmd.ConversationID)
	if err != nil {
		t.Fatal(err)
	}
	if conversation.Title != "用户标题" || called {
		t.Fatalf("title=%q generator_called=%v", conversation.Title, called)
	}
}

func TestUntitledExistingConversationUsesFirstPersistedUserMessage(t *testing.T) {
	store := newFakeStore()
	cmd := command()
	cmd.ConversationID = uuid.NewString()
	now := time.Now().UTC()
	store.conv[cmd.ConversationID] = Conversation{
		ID: cmd.ConversationID, Revision: 1, CreatedAt: now, UpdatedAt: now,
		Messages: []Message{
			{ID: uuid.NewString(), Role: RoleUser, Content: "第一条用户消息。后续说明", ModelProfileID: cmd.ProfileID, CreatedAt: now.Add(time.Microsecond)},
			{ID: uuid.NewString(), Role: RoleAssistant, Content: "旧回复", ModelProfileID: cmd.ProfileID, CreatedAt: now.Add(2 * time.Microsecond)},
		},
	}
	service, err := NewService(store, &fakeModel{}, nil, fakeProfile{})
	if err != nil {
		t.Fatal(err)
	}
	var gotUser string
	service.SetConversationTitleGenerator(conversationTitleGeneratorFunc(func(_ context.Context, userText, _ string) (string, error) {
		gotUser = userText
		return "", errors.New("tool model unavailable")
	}))
	cmd.Prompt = "当前消息"
	response, err := service.Chat(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := store.LoadConversation(context.Background(), response.ConversationID)
	if err != nil {
		t.Fatal(err)
	}
	if gotUser != "第一条用户消息。后续说明" || conversation.Title != "第一条用户消息" {
		t.Fatalf("generator user=%q title=%q", gotUser, conversation.Title)
	}
}

type titleCapturingTurnStore struct {
	*readOnlyTurnStore
	conversationTitle string
}

func (s *titleCapturingTurnStore) CommitTurn(ctx context.Context, lease TurnLease, response ChatResponse) (Turn, error) {
	s.conversationTitle = response.ConversationTitle
	return s.readOnlyTurnStore.CommitTurn(ctx, lease, response)
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
	service.SetConversationTitleGenerator(conversationTitleGeneratorFunc(func(context.Context, string, string) (string, error) {
		return "AWS 服务部署", nil
	}))
	service.executeTurn(context.Background(), turn.ID)
	if store.conversationTitle != "AWS 服务部署" {
		t.Fatalf("committed title=%q", store.conversationTitle)
	}
}
