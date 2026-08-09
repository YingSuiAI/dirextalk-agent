package runtimeapp

import (
	"context"
	"testing"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
)

func TestServiceSerializesAndRebasesConversationBeforeModelExecution(t *testing.T) {
	store := &serialRuntimeStoreFake{
		runtimeStoreFake: newRuntimeStoreFake(),
		conversation: runtimeapi.Conversation{
			OwnerID:        "owner-1",
			ConversationID: "conversation-1",
			Revision:       2,
		},
	}
	store.beforeComplete = func(runtimeapi.CompleteRuntimeRequestCommand) {
		if !store.lockHeld {
			t.Fatal("conversation lock was released before durable completion")
		}
	}
	executor := &executorFake{chat: func(
		_ context.Context,
		request runtimeapi.ChatRequest,
	) (runtimeapi.ChatResult, error) {
		if !store.lockHeld || request.ExpectedConversationRevision != 2 {
			t.Fatalf("serialized runtime request = %#v", request)
		}
		message := modelapi.Message{
			Role:    modelapi.RoleAssistant,
			Content: "reply using the newly completed Team context",
		}
		pending := runtimeapi.Conversation{
			OwnerID:        request.OwnerID,
			ConversationID: request.ConversationID,
			Revision:       request.ExpectedConversationRevision,
			Messages: []modelapi.Message{
				request.Messages[0],
				message,
			},
		}
		return runtimeapi.ChatResult{
			Message:                      message,
			PendingConversation:          &pending,
			ExpectedConversationRevision: request.ExpectedConversationRevision,
		}, nil
	}}
	service, err := NewService(store, executor)
	if err != nil {
		t.Fatal(err)
	}
	request := validChatRequest()
	request.ExpectedConversationRevision = 1
	result, err := service.Chat(context.Background(), validScope(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.ConversationRevision != 3 || store.lockCalls != 1 ||
		store.lockHeld {
		t.Fatalf(
			"serialized result=%#v lock_calls=%d lock_held=%t",
			result,
			store.lockCalls,
			store.lockHeld,
		)
	}
}

type serialRuntimeStoreFake struct {
	*runtimeStoreFake
	conversation runtimeapi.Conversation
	lockCalls    int
	lockHeld     bool
}

func (store *serialRuntimeStoreFake) AcquireRuntimeConversation(
	context.Context,
	string,
	string,
) (func(), error) {
	store.lockCalls++
	if store.lockHeld {
		return nil, ErrDurabilityUnavailable
	}
	store.lockHeld = true
	return func() {
		store.lockHeld = false
	}, nil
}

func (store *serialRuntimeStoreFake) LoadConversation(
	context.Context,
	string,
	string,
) (runtimeapi.Conversation, bool, error) {
	return store.conversation, true, nil
}
