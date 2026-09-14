package main

import (
	"context"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
)

// groupModelBindingAdapter exposes the durable per-group model choice to both
// the group loop (which answers with it) and the owner capability (which sets
// it). It keeps only a pointer to an existing model profile: the credential
// stays in that profile's own encrypted envelope.
type groupModelBindingAdapter struct {
	store *postgres.CoreGroupModelBindingStore
}

var _ groupModelOverrides = (*groupModelBindingAdapter)(nil)
var _ agentcapability.GroupModelBindings = (*groupModelBindingAdapter)(nil)

func (a *groupModelBindingAdapter) ResolveGroupConversationModel(ctx context.Context, ownerID string, accountGeneration uint64, roomID string) (string, bool, error) {
	if a == nil || a.store == nil {
		return "", false, nil
	}
	profileID, ok, err := a.store.ResolveGroupConversationModel(ctx, ownerID, accountGeneration, roomID)
	if err != nil {
		return "", false, err
	}
	return profileID, ok, nil
}

func (a *groupModelBindingAdapter) GetGroupModelBinding(ctx context.Context, ownerID string, accountGeneration uint64, roomID string) (agentcapability.GroupModelBinding, bool, error) {
	if a == nil || a.store == nil {
		return agentcapability.GroupModelBinding{}, false, postgres.ErrGroupModelBindingStore
	}
	binding, err := a.store.GetGroupConversationModel(ctx, ownerID, accountGeneration, roomID)
	if errors.Is(err, postgres.ErrGroupModelBindingMissing) {
		return agentcapability.GroupModelBinding{RoomID: strings.TrimSpace(roomID)}, false, nil
	}
	if err != nil {
		return agentcapability.GroupModelBinding{}, false, err
	}
	return agentcapability.GroupModelBinding{RoomID: binding.RoomID, ProfileID: binding.ProfileID, Revision: binding.Revision}, true, nil
}

func (a *groupModelBindingAdapter) SetGroupModelBinding(ctx context.Context, ownerID string, accountGeneration uint64, roomID, profileID string, expectedRevision int64) (agentcapability.GroupModelBinding, error) {
	if a == nil || a.store == nil {
		return agentcapability.GroupModelBinding{}, postgres.ErrGroupModelBindingStore
	}
	binding, err := a.store.SetGroupConversationModel(ctx, ownerID, accountGeneration, roomID, profileID, expectedRevision)
	if err != nil {
		return agentcapability.GroupModelBinding{}, err
	}
	return agentcapability.GroupModelBinding{RoomID: binding.RoomID, ProfileID: binding.ProfileID, Revision: binding.Revision}, nil
}

func (a *groupModelBindingAdapter) DeleteGroupModelBinding(ctx context.Context, ownerID string, accountGeneration uint64, roomID string, expectedRevision int64) error {
	if a == nil || a.store == nil {
		return postgres.ErrGroupModelBindingStore
	}
	return a.store.DeleteGroupConversationModel(ctx, ownerID, accountGeneration, roomID, expectedRevision)
}
