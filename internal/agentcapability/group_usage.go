package agentcapability

import (
	"context"
	"time"
)

// GroupUsage is the bounded per-group consumption of this node's Agent: the
// group's own turns, model dispatches, tool calls and Worker proposals. It never
// mixes in the owner's private usage, and the group is addressed by the room of
// the authenticated owner request.
type GroupUsage struct {
	RoomID            string
	Turns             int64
	CompletedTurns    int64
	FailedTurns       int64
	ModelDispatches   int64
	ModelActiveMillis int64
	ToolCalls         int64
	WorkerPlans       int64
	LastActivityAt    *time.Time
}

// GroupUsageReader aggregates one group's usage.
type GroupUsageReader interface {
	GroupUsage(ctx context.Context, roomID string) (GroupUsage, error)
}
