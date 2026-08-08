package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

func conversationScheduleCommand(t *testing.T, h *turnDBHarness) core.ConversationScheduleCommand {
	t.Helper()
	start := turnCommand()
	start.OwnerID = "@owner:example.test"
	start.AccountGeneration = 7
	turn, err := h.store.StartTurn(context.Background(), start)
	if err != nil {
		t.Fatal(err)
	}
	createTestProfile(context.Background(), t, h.store.Store, turn.ProfileID, "test", "integration-secret")
	lease, err := h.store.ClaimTurn(context.Background(), turn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	runAt := now.Add(time.Hour)
	schedule := coretask.Schedule{
		ID: uuid.NewString(), Name: "one-time reminder",
		Spec: coretask.TaskTemplate{
			Kind: coretask.TaskKindAgent, Payload: coretask.TaskPayload{Agent: &coretask.AgentTaskPayload{OwnerID: turn.OwnerID, AccountGeneration: turn.AccountGeneration}},
			Goal: "send reminder", ConversationID: turn.ConversationID, ModelProfileID: turn.ProfileID, TimeoutSeconds: 30,
		},
		RunAt: &runAt, Timezone: "UTC", Revision: 1, NextRunAt: runAt, CreatedAt: now, UpdatedAt: now,
	}
	response := core.ChatResponse{
		RequestID: turn.RequestID, ConversationID: turn.ConversationID, Revision: 2, Done: true, ModelProfileID: turn.ProfileID,
		Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "Scheduled reminder.", ModelProfileID: turn.ProfileID, CreatedAt: now},
	}
	return core.ConversationScheduleCommand{
		Lease: lease, Schedule: schedule,
		Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("a", 64)},
		Response: response,
	}
}

func TestConversationScheduleCommitIsAtomicAndReplaySafePostgres(t *testing.T) {
	h := openTurnDB(t)
	command := conversationScheduleCommand(t, h)
	created, err := h.store.CommitConversationSchedule(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != command.Schedule.ID || created.Replayed {
		t.Fatalf("created=%+v", created)
	}
	replayed, err := h.store.CommitConversationSchedule(context.Background(), command)
	if err != nil || !replayed.Replayed || replayed.ID != created.ID {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
	turn, err := h.store.GetTurn(context.Background(), command.Lease.Turn.ID)
	if err != nil || turn.State != core.TurnCompleted || turn.Response == nil || turn.Response.Message.ID != command.Response.Message.ID {
		t.Fatalf("turn=%+v err=%v", turn, err)
	}
	conversation, err := h.store.LoadConversation(context.Background(), command.Lease.Turn.ConversationID)
	if err != nil || len(conversation.Messages) != 2 || conversation.Messages[1].ID != command.Response.Message.ID {
		t.Fatalf("conversation=%+v err=%v", conversation, err)
	}
	events, err := h.store.LoadTurnEvents(context.Background(), command.Lease.Turn.ID, 0, 10)
	if err != nil || len(events) != 2 || events[1].Kind != core.TurnEventDone {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	var scheduleCount, replayCount int
	if err = h.pool.QueryRow(context.Background(), `SELECT count(*) FROM core_schedules WHERE schedule_id=$1`, command.Schedule.ID).Scan(&scheduleCount); err != nil {
		t.Fatal(err)
	}
	if err = h.pool.QueryRow(context.Background(), `SELECT count(*) FROM core_schedule_replays WHERE operation='create' AND idempotency_key=$1`, command.Mutation.IdempotencyKey).Scan(&replayCount); err != nil {
		t.Fatal(err)
	}
	if scheduleCount != 1 || replayCount != 1 {
		t.Fatalf("schedule_count=%d replay_count=%d", scheduleCount, replayCount)
	}
	changed := command
	changed.Mutation.RequestDigest = strings.Repeat("b", 64)
	if _, err = h.store.CommitConversationSchedule(context.Background(), changed); err != coretask.ErrConflict {
		t.Fatalf("changed replay err=%v", err)
	}
}

func TestConversationScheduleRollsBackWhenTurnCompletionConflictsPostgres(t *testing.T) {
	h := openTurnDB(t)
	command := conversationScheduleCommand(t, h)
	command.Response.Revision = 99
	if _, err := h.store.CommitConversationSchedule(context.Background(), command); err == nil {
		t.Fatal("invalid conversation revision unexpectedly committed")
	}
	var scheduleCount, replayCount int
	if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM core_schedules WHERE schedule_id=$1`, command.Schedule.ID).Scan(&scheduleCount); err != nil {
		t.Fatal(err)
	}
	if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM core_schedule_replays WHERE operation='create' AND idempotency_key=$1`, command.Mutation.IdempotencyKey).Scan(&replayCount); err != nil {
		t.Fatal(err)
	}
	turn, err := h.store.GetTurn(context.Background(), command.Lease.Turn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if scheduleCount != 0 || replayCount != 0 || turn.State != core.TurnRunning || turn.Response != nil {
		t.Fatalf("partial commit: schedule=%d replay=%d turn=%+v", scheduleCount, replayCount, turn)
	}
}
