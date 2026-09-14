package postgres

import (
	"context"
	"testing"
)

// TestGroupUsageAggregatesOnlyTheGroupPostgres pins per-group usage
// attribution: the numbers come from that group's own conversation, the owner's
// private turn in the same store is never counted, and an unknown room reports
// zero.
func TestGroupUsageAggregatesOnlyTheGroupPostgres(t *testing.T) {
	h := openTurnDB(t)
	ctx := context.Background()
	command := groupTurnCommandPG()
	createTestProfile(ctx, t, h.store.Store, command.ProfileID, command.ProfileSnapshot.Model, command.ProfileSnapshot.APIKey)
	turn, err := h.store.StartTurnWithRuntime(ctx, command, groupTurnRuntimePG(t, command))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `UPDATE core_conversation_turns SET state='completed', response_json='{}'::jsonb,
		model_dispatch_count=3, model_active_milliseconds=1500, updated_at=clock_timestamp() WHERE turn_id=$1`, turn.ID); err != nil {
		t.Fatal(err)
	}

	usage, err := h.store.GroupUsage(ctx, command.GroupOrigin.RoomID)
	if err != nil {
		t.Fatal(err)
	}
	if usage.RoomID != command.GroupOrigin.RoomID || usage.Turns != 1 || usage.CompletedTurns != 1 || usage.FailedTurns != 0 {
		t.Fatalf("group usage=%+v", usage)
	}
	if usage.ModelDispatches != 3 || usage.ModelActiveMillis != 1500 {
		t.Fatalf("group dispatch usage=%+v", usage)
	}
	if usage.ToolCalls != 0 || usage.WorkerPlans != 0 || usage.LastActivityAt == nil ||
		usage.WorkerQuoteMicros != 0 || usage.WorkerStartedMicros != 0 || usage.WorkerQuoteCurrency != "" {
		t.Fatalf("group usage bounds=%+v", usage)
	}
	// The owner's own durable turn (created by the shared fixture) must never be
	// attributed to the group.
	if usage.Turns != 1 {
		t.Fatalf("private turns leaked into the group usage: %+v", usage)
	}
	// A room the owner shares nothing with reports zero, not the owner's usage.
	other, err := h.store.GroupUsage(ctx, "!no-such-room:example.test")
	if err != nil || other.Turns != 0 || other.ModelDispatches != 0 || other.LastActivityAt != nil {
		t.Fatalf("unknown room usage=%+v err=%v", other, err)
	}
	if _, err := h.store.GroupUsage(ctx, "   "); err == nil {
		t.Fatal("empty room was accepted")
	}
}
