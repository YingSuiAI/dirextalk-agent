package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	errGroupUsageInvalid = errors.New("group usage requires a room")
	// ErrGroupUsageUnavailable reports a persistence failure while aggregating
	// one group's usage.
	ErrGroupUsageUnavailable = errors.New("group usage is unavailable")
)

// GroupUsage is the bounded per-group consumption of this node's Agent. It is
// derived from the group's own conversations, turns, tool-call events and
// Worker plans, so it never mixes in the owner's private usage.
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

// GroupUsage aggregates one group's usage. The group is addressed by its room,
// taken from the authenticated owner request, never from a model.
func (s *CoreConversationStore) GroupUsage(ctx context.Context, roomID string) (GroupUsage, error) {
	roomID = strings.TrimSpace(roomID)
	out := GroupUsage{RoomID: roomID}
	if s == nil || s.pool == nil || roomID == "" {
		return out, errGroupUsageInvalid
	}
	var lastActivity *time.Time
	err := s.pool.QueryRow(ctx, `
		WITH conv AS (
			SELECT conversation_id FROM core_conversations
			WHERE group_scope_json IS NOT NULL AND group_scope_json->>'room_id' = $1
		),
		grouped_turns AS (
			SELECT t.turn_id, t.state, t.model_dispatch_count, t.model_active_milliseconds, t.updated_at
			FROM core_conversation_turns t
			WHERE t.conversation_id IN (SELECT conversation_id FROM conv)
		)
		SELECT
			(SELECT count(*) FROM grouped_turns),
			(SELECT count(*) FROM grouped_turns WHERE state = 'completed'),
			(SELECT count(*) FROM grouped_turns WHERE state = 'failed'),
			(SELECT COALESCE(sum(model_dispatch_count), 0) FROM grouped_turns),
			(SELECT COALESCE(sum(model_active_milliseconds), 0) FROM grouped_turns),
			(SELECT count(*) FROM core_conversation_turn_events e WHERE e.kind = 'tool_call' AND e.turn_id IN (SELECT turn_id FROM grouped_turns)),
			(SELECT count(*) FROM core_cloud_worker_plans p WHERE p.turn_id IN (SELECT turn_id FROM grouped_turns)),
			(SELECT max(updated_at) FROM grouped_turns)
	`, roomID).Scan(&out.Turns, &out.CompletedTurns, &out.FailedTurns, &out.ModelDispatches,
		&out.ModelActiveMillis, &out.ToolCalls, &out.WorkerPlans, &lastActivity)
	if err != nil {
		if err == pgx.ErrNoRows {
			return out, nil
		}
		return GroupUsage{}, ErrGroupUsageUnavailable
	}
	if lastActivity != nil {
		utc := lastActivity.UTC()
		out.LastActivityAt = &utc
	}
	return out, nil
}
