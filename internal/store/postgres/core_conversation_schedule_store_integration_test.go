package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
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
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err = h.store.Store.CreateProfile(context.Background(), coremodel.Profile{
		ID: turn.ProfileID, ClientProfileID: "scheduled-default", DisplayName: "scheduled default",
		Provider: coremodel.ProviderOpenAICompatible, RequestDialect: coremodel.DialectOpenAICompatibleChatV1,
		ModelKind: coremodel.ModelKindConversation, BaseURL: "https://example.invalid", Model: "test",
		APIKey: "integration-secret", Revision: 1, CredentialVersion: 1, CreatedAt: now, UpdatedAt: now,
	}, uuid.NewString(), strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err = h.pool.Exec(context.Background(), `INSERT INTO core_model_profile_defaults(singleton,default_conversation_client_profile_id,updated_at) VALUES(true,'scheduled-default',clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	lease, err := h.store.ClaimTurn(context.Background(), turn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	runAt := now.Add(time.Hour)
	schedule := coretask.Schedule{
		ID: uuid.NewString(), Name: "one-time reminder",
		Spec: coretask.TaskTemplate{
			Kind: coretask.TaskKindAgent, Payload: coretask.TaskPayload{Agent: &coretask.AgentTaskPayload{
				OwnerID: turn.OwnerID, AccountGeneration: turn.AccountGeneration,
				ScheduledConversation: &coretask.ScheduledConversationOrigin{
					Capability: coretask.ScheduledCapabilityScheduledNote, Timezone: "UTC", ExtensionSnapshots: []coretask.ScheduledExtensionSnapshot{},
				},
			}},
			Goal: "send reminder", ConversationID: turn.ConversationID, TimeoutSeconds: 30,
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
	var scheduleCount, replayCount, scheduleProfileRefs int
	if err = h.pool.QueryRow(context.Background(), `SELECT count(*) FROM core_schedules WHERE schedule_id=$1`, command.Schedule.ID).Scan(&scheduleCount); err != nil {
		t.Fatal(err)
	}
	if err = h.pool.QueryRow(context.Background(), `SELECT count(*) FROM core_schedule_replays WHERE operation='create' AND idempotency_key=$1`, command.Mutation.IdempotencyKey).Scan(&replayCount); err != nil {
		t.Fatal(err)
	}
	if err = h.pool.QueryRow(context.Background(), `SELECT count(*) FROM core_model_profile_active_refs WHERE owner_kind='schedule' AND owner_id=$1`, command.Schedule.ID).Scan(&scheduleProfileRefs); err != nil {
		t.Fatal(err)
	}
	if scheduleCount != 1 || replayCount != 1 || scheduleProfileRefs != 0 {
		t.Fatalf("schedule_count=%d replay_count=%d schedule_profile_refs=%d", scheduleCount, replayCount, scheduleProfileRefs)
	}
	changed := command
	changed.Mutation.RequestDigest = strings.Repeat("b", 64)
	if _, err = h.store.CommitConversationSchedule(context.Background(), changed); err != coretask.ErrConflict {
		t.Fatalf("changed replay err=%v", err)
	}
}

func TestNativeSchedulePinsCurrentDefaultPerOccurrenceAndReplaysExactTaskPostgres(t *testing.T) {
	h := openTurnDB(t)
	ctx := context.Background()
	command := conversationScheduleCommand(t, h)
	created, err := h.store.CommitConversationSchedule(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	createProfile := func(clientID string, dialect coremodel.RequestDialect) string {
		profileID := uuid.NewString()
		now := time.Now().UTC().Truncate(time.Microsecond)
		if _, createErr := h.store.Store.CreateProfile(ctx, coremodel.Profile{
			ID: profileID, ClientProfileID: clientID, DisplayName: clientID,
			Provider: coremodel.ProviderOpenAICompatible, RequestDialect: dialect, ModelKind: coremodel.ModelKindConversation,
			BaseURL: "https://example.invalid", Model: "test", APIKey: "integration-secret",
			Revision: 1, CredentialVersion: 1, CreatedAt: now, UpdatedAt: now,
		}, uuid.NewString(), strings.Repeat("e", 64)); createErr != nil {
			t.Fatal(createErr)
		}
		return profileID
	}
	profileB := createProfile("scheduled-b", coremodel.DialectOpenAIReasoningChatV1)
	profileC := createProfile("scheduled-c", coremodel.DialectOpenAICompatibleChatV1)
	setDefault := func(clientID string) {
		if _, updateErr := h.pool.Exec(ctx, `UPDATE core_model_profile_defaults SET default_conversation_client_profile_id=$1,updated_at=clock_timestamp() WHERE singleton=true`, clientID); updateErr != nil {
			t.Fatal(updateErr)
		}
	}
	schedules := NewCoreScheduleStore(h.store.Store)
	setDefault("scheduled-b")
	triggerKey := uuid.NewString()
	trigger := coretask.TriggerScheduleCommand{ScheduleID: created.ID, Mutation: coretask.MutationCommand{
		IdempotencyKey: triggerKey, RequestDigest: strings.Repeat("f", 64),
	}, At: time.Now().UTC()}
	_, firstOccurrence, firstTask, err := schedules.TriggerNow(ctx, trigger)
	if err != nil {
		t.Fatal(err)
	}
	if firstTask.Spec.ModelProfileID != profileB || firstTask.Snapshot == nil || firstTask.Snapshot.Model.ProfileID != profileB ||
		firstTask.Snapshot.Model.RequestDialect != string(coremodel.DialectOpenAIReasoningChatV1) ||
		firstTask.Snapshot.Model.ModelKind != coremodel.ModelKindConversation || firstTask.Snapshot.Model.CredentialVersion != 1 {
		t.Fatalf("first occurrence did not pin default B: task=%+v snapshot=%+v", firstTask.Spec, firstTask.Snapshot)
	}
	setDefault("scheduled-c")
	replayedSchedule, replayedOccurrence, replayedTask, err := schedules.TriggerNow(ctx, trigger)
	if err != nil || !replayedSchedule.Replayed || replayedOccurrence.ID != firstOccurrence.ID || replayedTask.ID != firstTask.ID ||
		replayedTask.Spec.ModelProfileID != profileB || replayedTask.Snapshot == nil || replayedTask.Snapshot.Model.ProfileID != profileB {
		t.Fatalf("trigger replay drifted after default change: schedule=%+v occurrence=%+v task=%+v err=%v", replayedSchedule, replayedOccurrence, replayedTask, err)
	}
	secondKey := uuid.NewString()
	_, _, secondTask, err := schedules.TriggerNow(ctx, coretask.TriggerScheduleCommand{ScheduleID: created.ID, Mutation: coretask.MutationCommand{
		IdempotencyKey: secondKey, RequestDigest: strings.Repeat("1", 64),
	}, At: time.Now().UTC().Add(time.Second)})
	if err != nil || secondTask.Spec.ModelProfileID != profileC || secondTask.Snapshot == nil || secondTask.Snapshot.Model.ProfileID != profileC {
		t.Fatalf("next occurrence did not pin default C: task=%+v err=%v", secondTask, err)
	}
	var taskRefs int
	var occurrenceTemplateModel string
	if err = h.pool.QueryRow(ctx, `SELECT count(*) FROM core_model_profile_active_refs WHERE owner_kind='task' AND owner_id IN ($1,$2)`, firstTask.ID, secondTask.ID).Scan(&taskRefs); err != nil {
		t.Fatal(err)
	}
	if err = h.pool.QueryRow(ctx, `SELECT COALESCE(spec_snapshot_json->>'model_profile_id','') FROM core_schedule_occurrences WHERE occurrence_id=$1`, firstOccurrence.ID).Scan(&occurrenceTemplateModel); err != nil {
		t.Fatal(err)
	}
	if taskRefs != 2 || occurrenceTemplateModel != "" {
		t.Fatalf("occurrence ownership drift: task_refs=%d occurrence_template_model=%q", taskRefs, occurrenceTemplateModel)
	}
}

func TestNativeScheduleTriggerWithoutCurrentDefaultCreatesNothingPostgres(t *testing.T) {
	h := openTurnDB(t)
	ctx := context.Background()
	command := conversationScheduleCommand(t, h)
	created, err := h.store.CommitConversationSchedule(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.pool.Exec(ctx, `DELETE FROM core_model_profile_defaults WHERE singleton=true`); err != nil {
		t.Fatal(err)
	}
	trigger := coretask.TriggerScheduleCommand{ScheduleID: created.ID, Mutation: coretask.MutationCommand{
		IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("2", 64),
	}, At: time.Now().UTC()}
	if _, _, _, err = NewCoreScheduleStore(h.store.Store).TriggerNow(ctx, trigger); !errors.Is(err, coretask.ErrNotFound) {
		t.Fatalf("trigger without current default err=%v", err)
	}
	var occurrences, tasks, replays int
	if err = h.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM core_schedule_occurrences WHERE schedule_id=$1),
		(SELECT count(*) FROM core_tasks WHERE create_idempotency_key=$2),
		(SELECT count(*) FROM core_schedule_replays WHERE operation='trigger_now' AND idempotency_key=$2)`,
		created.ID, trigger.Mutation.IdempotencyKey).Scan(&occurrences, &tasks, &replays); err != nil {
		t.Fatal(err)
	}
	if occurrences != 0 || tasks != 0 || replays != 0 {
		t.Fatalf("failed trigger wrote state: occurrences=%d tasks=%d replays=%d", occurrences, tasks, replays)
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

func TestConversationScheduleRejectsMissingCurrentDefaultPostgres(t *testing.T) {
	h := openTurnDB(t)
	command := conversationScheduleCommand(t, h)
	if _, err := h.pool.Exec(context.Background(), `DELETE FROM core_model_profile_defaults WHERE singleton=true`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.CommitConversationSchedule(context.Background(), command); !errors.Is(err, coretask.ErrNotFound) {
		t.Fatalf("commit without current default err=%v", err)
	}
	turn, err := h.store.GetTurn(context.Background(), command.Lease.Turn.ID)
	if err != nil || turn.State != core.TurnRunning {
		t.Fatalf("turn=%+v err=%v", turn, err)
	}
}
