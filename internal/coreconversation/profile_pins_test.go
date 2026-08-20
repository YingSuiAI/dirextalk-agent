package coreconversation

import (
	"context"
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

func TestChatRejectsPartialProfilePins(t *testing.T) {
	base := command()
	cases := map[string]func(*ChatCommand){
		"missing revision":           func(c *ChatCommand) { c.ExpectedProfileRevision = 0 },
		"missing credential version": func(c *ChatCommand) { c.ExpectedCredentialVersion = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cmd := base
			mutate(&cmd)
			if err := cmd.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("partial profile pin accepted: %v", err)
			}
		})
	}
}

func TestChatRejectsMismatchedResolvedProfilePinsBeforeModelExecution(t *testing.T) {
	profileID := uuid.NewString()
	current := pinTestSnapshot(profileID, 2, 3)
	store := &publicActiveTurnStore{fakeStore: newFakeStore()}
	model := &trackingModel{}
	service, err := NewService(store, model, noopExtensions{}, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) {
		return current, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Chat(context.Background(), ChatCommand{
		RequestID:                 uuid.NewString(),
		Prompt:                    "stale",
		ProfileID:                 profileID,
		ExpectedProfileRevision:   1,
		ExpectedCredentialVersion: 1,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("stale profile pins err=%v", err)
	}
	if model.count() != 0 {
		t.Fatalf("model ran before stale profile pins were rejected: %d", model.count())
	}
}

func TestChatReplayUsesBoundPinsAfterCredentialRotation(t *testing.T) {
	profileID := uuid.NewString()
	resolver := &mutableSnapshotResolver{snapshot: pinTestSnapshot(profileID, 1, 1)}
	store := &terminalChatAdapterStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: newFakeStore()},
		state:                 TurnCompleted, content: "pinned response",
	}
	model := &trackingModel{}
	service, err := NewService(store, model, noopExtensions{}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	first := ChatCommand{RequestID: uuid.NewString(), Prompt: "hello", ProfileID: profileID, ExpectedProfileRevision: 1, ExpectedCredentialVersion: 1}
	if _, err := service.Chat(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	resolver.snapshot = pinTestSnapshot(profileID, 2, 2)
	stale := first
	stale.RequestID = uuid.NewString()
	if _, err := service.Chat(context.Background(), stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale pins after credential rotation err=%v", err)
	}
	if model.count() != 0 || store.startCalls != 1 {
		t.Fatalf("stale request ran model after rotation: %d", model.count())
	}
	if _, err := service.Chat(context.Background(), first); err != nil {
		t.Fatalf("bound replay after rotation failed: %v", err)
	}
	if model.count() != 0 || store.startCalls != 1 {
		t.Fatalf("bound replay invoked model after rotation: %d", model.count())
	}
}

type mutableSnapshotResolver struct {
	snapshot coremodel.ExecutionSnapshot
}

func (r *mutableSnapshotResolver) ResolveProfileSnapshot(context.Context, string) (coremodel.ExecutionSnapshot, error) {
	return r.snapshot, nil
}

func pinTestSnapshot(profileID string, revision, credentialVersion int64) coremodel.ExecutionSnapshot {
	return coremodel.ExecutionSnapshot{
		ProfileID:         profileID,
		Revision:          revision,
		CredentialVersion: credentialVersion,
		Provider:          coremodel.ProviderOpenAICompatible,
		RequestDialect:    coremodel.DialectOpenAICompatibleChatV1,
		BaseURL:           "https://example.invalid",
		Model:             "test-model",
		APIKey:            "test-key",
	}
}
