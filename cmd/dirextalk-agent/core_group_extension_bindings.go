package main

import (
	"context"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
)

// groupExtensionBindingAdapter exposes the durable per-group third-party MCP
// binding to both the group tool chain (which marks bound installations for the
// turn) and the owner capability (which binds them).
type groupExtensionBindingAdapter struct {
	store *postgres.CoreGroupExtensionBindingStore
}

var _ groupExtensionBindings = (*groupExtensionBindingAdapter)(nil)
var _ agentcapability.GroupExtensionBindings = (*groupExtensionBindingAdapter)(nil)

func (a *groupExtensionBindingAdapter) ListGroupExtensionBindings(ctx context.Context, ownerID string, accountGeneration uint64, roomID string) ([]string, error) {
	if a == nil || a.store == nil {
		return nil, postgres.ErrGroupExtensionBindingStore
	}
	return a.store.ListGroupExtensionBindings(ctx, ownerID, accountGeneration, roomID)
}

func (a *groupExtensionBindingAdapter) SetGroupExtensionBinding(ctx context.Context, ownerID string, accountGeneration uint64, roomID, installationID string) error {
	if a == nil || a.store == nil {
		return postgres.ErrGroupExtensionBindingStore
	}
	return a.store.SetGroupExtensionBinding(ctx, ownerID, accountGeneration, roomID, installationID)
}

func (a *groupExtensionBindingAdapter) ClearGroupExtensionBinding(ctx context.Context, ownerID string, accountGeneration uint64, roomID, installationID string) error {
	if a == nil || a.store == nil {
		return postgres.ErrGroupExtensionBindingStore
	}
	return a.store.ClearGroupExtensionBinding(ctx, ownerID, accountGeneration, roomID, installationID)
}
