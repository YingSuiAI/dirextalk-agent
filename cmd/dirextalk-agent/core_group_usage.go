package main

import (
	"context"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
)

// groupUsageAdapter exposes the derived per-group usage to the owner
// capability. It reads only the group's own conversations and turns.
type groupUsageAdapter struct {
	store *postgres.CoreConversationStore
}

var _ agentcapability.GroupUsageReader = (*groupUsageAdapter)(nil)

func (a *groupUsageAdapter) GroupUsage(ctx context.Context, roomID string) (agentcapability.GroupUsage, error) {
	if a == nil || a.store == nil {
		return agentcapability.GroupUsage{}, postgres.ErrGroupUsageUnavailable
	}
	usage, err := a.store.GroupUsage(ctx, roomID)
	if err != nil {
		return agentcapability.GroupUsage{}, err
	}
	return agentcapability.GroupUsage{
		RoomID:            usage.RoomID,
		Turns:             usage.Turns,
		CompletedTurns:    usage.CompletedTurns,
		FailedTurns:       usage.FailedTurns,
		ModelDispatches:   usage.ModelDispatches,
		ModelActiveMillis: usage.ModelActiveMillis,
		ToolCalls:         usage.ToolCalls,
		WorkerPlans:       usage.WorkerPlans,
		LastActivityAt:    usage.LastActivityAt,
	}, nil
}
