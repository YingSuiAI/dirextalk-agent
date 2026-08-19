package coremodel

import (
	"context"
	"testing"
)

func TestResolveDefaultToolProfileUsesIndependentAutoBinding(t *testing.T) {
	repository := NewMemoryProfileRepository()
	service, err := NewService(repository, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := "tool-secret"
	_, err = service.Sync(context.Background(), SyncProfileCommand{
		IdempotencyKey:               "b0000000-0000-4000-8000-000000000001",
		DefaultConversationProfileID: "chat",
		Entries:                      []SyncProfileEntry{{ClientProfileID: "chat", DisplayName: "Chat", Provider: ProviderOpenAICompatible, ModelKind: ModelKindConversation, BaseURL: "https://example.test/v1", Model: "model", APIKey: &key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := service.ResolveDefaultToolProfile(context.Background())
	if err != nil || resolved.ClientProfileID != "chat" {
		t.Fatalf("unique tool role did not auto-bind its configured candidate: resolved=%+v err=%v", resolved.Public(), err)
	}
	_, err = service.Sync(context.Background(), SyncProfileCommand{
		IdempotencyKey:       "b0000000-0000-4000-8000-000000000002",
		DefaultToolProfileID: "tool",
		Entries:              []SyncProfileEntry{{ClientProfileID: "tool", DisplayName: "Tool", Provider: ProviderOpenAICompatible, ModelKind: ModelKindConversation, BaseURL: "https://example.test/v1", Model: "model", APIKey: &key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err = service.ResolveDefaultToolProfile(context.Background())
	if err != nil || resolved.ClientProfileID != "tool" || resolved.APIKey != key {
		t.Fatalf("resolved=%+v err=%v", resolved.Public(), err)
	}
}
