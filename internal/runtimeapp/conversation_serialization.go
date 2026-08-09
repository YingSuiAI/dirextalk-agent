package runtimeapp

import (
	"context"

	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
)

type runtimeConversationExecutionLocker interface {
	AcquireRuntimeConversation(
		context.Context,
		string,
		string,
	) (func(), error)
}

type runtimeConversationReader interface {
	LoadConversation(
		context.Context,
		string,
		string,
	) (runtimeapi.Conversation, bool, error)
}

func (service *Service) lockAndReconcileConversation(
	ctx context.Context,
	request *runtimeapi.ChatRequest,
) (func(), error) {
	noop := func() {}
	if request == nil || request.MemoryDisabled || request.ConversationID == "" {
		return noop, nil
	}
	locker, ok := service.store.(runtimeConversationExecutionLocker)
	if !ok {
		return noop, nil
	}
	release, err := locker.AcquireRuntimeConversation(
		ctx,
		request.OwnerID,
		request.ConversationID,
	)
	if err != nil {
		return noop, stableDurabilityError(err)
	}
	if release == nil {
		return noop, ErrInvalidDependencies
	}
	reader, ok := service.store.(runtimeConversationReader)
	if !ok {
		release()
		return noop, ErrInvalidDependencies
	}
	conversation, found, err := reader.LoadConversation(
		ctx,
		request.OwnerID,
		request.ConversationID,
	)
	if err != nil {
		release()
		return noop, stableDurabilityError(err)
	}
	if !found {
		if request.ExpectedConversationRevision != 0 {
			release()
			return noop, runtimeapi.ErrRuntimeRevisionConflict
		}
		return release, nil
	}
	if conversation.OwnerID != request.OwnerID ||
		conversation.ConversationID != request.ConversationID ||
		conversation.Revision < 1 {
		release()
		return noop, runtimeapi.ErrInvalidConversation
	}
	if conversation.Revision < request.ExpectedConversationRevision {
		release()
		return noop, runtimeapi.ErrRuntimeRevisionConflict
	}
	request.ExpectedConversationRevision = conversation.Revision
	return release, nil
}
