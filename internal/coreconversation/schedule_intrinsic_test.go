package coreconversation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type conversationScheduleStoreStub struct {
	commands []ConversationScheduleCommand
	err      error
}

type scheduleCapableTurnStore struct {
	*replayTurnStore
	*conversationScheduleStoreStub
}

func (s *conversationScheduleStoreStub) CommitConversationSchedule(_ context.Context, command ConversationScheduleCommand) (coretask.Schedule, error) {
	if s.err != nil {
		return coretask.Schedule{}, s.err
	}
	s.commands = append(s.commands, command)
	return command.Schedule, nil
}

func scheduleIntrinsicLease() TurnLease {
	revision := uint64(4)
	createdAt := time.Date(2026, 8, 8, 1, 2, 3, 0, time.UTC)
	return TurnLease{
		Turn: Turn{
			ID: uuid.NewString(), RequestID: uuid.NewString(), OwnerID: "@owner:example.test", AccountGeneration: 9,
			ConversationID: uuid.NewString(), ProfileID: uuid.NewString(), ExpectedRevision: &revision, Revision: 2, State: TurnRunning, CreatedAt: createdAt, UpdatedAt: createdAt,
		},
		LeaseID: uuid.NewString(), Epoch: 3, ExpiresAt: time.Now().UTC().Add(time.Minute),
	}
}

func executeScheduleForTest(t *testing.T, store *conversationScheduleStoreStub, lease TurnLease, callID string, arguments map[string]any) error {
	t.Helper()
	raw, err := json.Marshal(arguments)
	if err != nil {
		t.Fatal(err)
	}
	intrinsic := scheduleIntrinsic(store, lease)
	result, err := intrinsic.Execute(context.Background(), IntrinsicExecutionRequest{
		Lease:              lease,
		Call:               ToolCall{ID: callID, Name: coremodel.IntrinsicScheduleCreateToolName, Arguments: string(raw)},
		CanonicalArguments: raw,
	})
	if err == nil && !result.TurnCommitted {
		t.Fatal("schedule intrinsic returned success without committing the turn")
	}
	return err
}

func TestScheduleIntrinsicInjectsTurnAuthorityAndUsesDeterministicIdentity(t *testing.T) {
	lease := scheduleIntrinsicLease()
	store := &conversationScheduleStoreStub{}
	arguments := map[string]any{
		"name": "daily summary", "goal": "summarize the conversation", "cron": "0 9 * * *", "timezone": "Asia/Shanghai", "timeout_seconds": 120,
	}
	if err := executeScheduleForTest(t, store, lease, "call-1", arguments); err != nil {
		t.Fatalf("execute schedule intrinsic: %v", err)
	}
	if err := executeScheduleForTest(t, store, lease, "call-1", arguments); err != nil {
		t.Fatalf("replay schedule intrinsic: %v", err)
	}
	if len(store.commands) != 2 {
		t.Fatalf("commands=%d", len(store.commands))
	}
	first, second := store.commands[0], store.commands[1]
	if first.Schedule.ID != second.Schedule.ID || first.Mutation.IdempotencyKey != second.Mutation.IdempotencyKey || first.Mutation.RequestDigest != second.Mutation.RequestDigest {
		t.Fatalf("intrinsic identity was not deterministic: first=%+v second=%+v", first.Mutation, second.Mutation)
	}
	template := first.Schedule.Spec
	if template.Kind != coretask.TaskKindAgent || template.ConversationID != lease.Turn.ConversationID || template.ModelProfileID != lease.Turn.ProfileID ||
		template.Goal != "summarize the conversation" || template.TimeoutSeconds != 120 || len(template.AttachmentRefs) != 0 || len(template.Extensions) != 0 || len(template.KnowledgeRefs) != 0 ||
		template.Payload.Agent == nil || template.Payload.Agent.OwnerID != lease.Turn.OwnerID || template.Payload.Agent.AccountGeneration != lease.Turn.AccountGeneration {
		t.Fatalf("untrusted schedule template: %+v", template)
	}
	if first.Lease.Turn.OwnerID != lease.Turn.OwnerID || first.Lease.Turn.AccountGeneration != lease.Turn.AccountGeneration || first.Response.Revision != 5 || first.Response.ConversationID != lease.Turn.ConversationID || first.Response.ModelProfileID != lease.Turn.ProfileID {
		t.Fatalf("turn authority was not injected: %+v", first)
	}
}

func TestServiceComposesScheduleWithConfiguredCoreIntrinsics(t *testing.T) {
	lease := scheduleIntrinsicLease()
	store := &scheduleCapableTurnStore{replayTurnStore: &replayTurnStore{}, conversationScheduleStoreStub: &conversationScheduleStoreStub{}}
	service := &Service{turns: store}
	service.SetIntrinsicResolver(intrinsicResolverFunc(func(context.Context, TurnLease) ([]ResolvedIntrinsic, error) {
		return []ResolvedIntrinsic{{Tool: coremodel.Tool{Name: coremodel.IntrinsicCloudWorkerProposeToolName, InputSchema: map[string]any{"type": "object"}}, Execute: func(context.Context, IntrinsicExecutionRequest) (IntrinsicExecutionResult, error) {
			return IntrinsicExecutionResult{TurnCommitted: true}, nil
		}}}, nil
	}))
	tools, err := service.resolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(tools) != 2 || tools[0].Tool.Name != coremodel.IntrinsicScheduleCreateToolName || tools[1].Tool.Name != coremodel.IntrinsicCloudWorkerProposeToolName {
		t.Fatalf("tools=%+v err=%v", tools, err)
	}
}

func TestScheduleIntrinsicAcceptsOneTimeTriggerAndRejectsForgedOrAmbiguousInput(t *testing.T) {
	lease := scheduleIntrinsicLease()
	store := &conversationScheduleStoreStub{}
	if err := executeScheduleForTest(t, store, lease, "call-once", map[string]any{
		"name": "once", "goal": "send reminder", "run_at": "2026-08-09T02:03:04+08:00",
	}); err != nil {
		t.Fatalf("one-time schedule: %v", err)
	}
	if got := store.commands[0].Schedule.RunAt; got == nil || !got.Equal(time.Date(2026, 8, 8, 18, 3, 4, 0, time.UTC)) {
		t.Fatalf("run_at=%v", got)
	}
	cases := []map[string]any{
		{"name": "forged", "goal": "x", "run_at": "2026-08-09T00:00:00Z", "owner_id": "attacker"},
		{"name": "ambiguous", "goal": "x", "run_at": "2026-08-09T00:00:00Z", "cron": "0 9 * * *", "timezone": "UTC"},
		{"name": "missing zone", "goal": "x", "cron": "0 9 * * *"},
		{"name": "bad zone", "goal": "x", "cron": "0 9 * * *", "timezone": "Mars/Olympus"},
		{"name": "refs", "goal": "x", "run_at": "2026-08-09T00:00:00Z", "attachment_refs": []string{uuid.NewString()}},
	}
	for index, arguments := range cases {
		if err := executeScheduleForTest(t, store, lease, "bad-"+string(rune('a'+index)), arguments); !errors.Is(err, ErrInvalid) {
			t.Fatalf("case %d err=%v", index, err)
		}
	}
}

func TestScheduleIntrinsicStoreFailureDoesNotReportCommittedTurn(t *testing.T) {
	lease := scheduleIntrinsicLease()
	store := &conversationScheduleStoreStub{err: errors.New("persistence unavailable")}
	if err := executeScheduleForTest(t, store, lease, "call-1", map[string]any{
		"name": "once", "goal": "send reminder", "run_at": "2026-08-09T00:00:00Z",
	}); err == nil {
		t.Fatal("store failure was ignored")
	}
}

func TestScheduleIntrinsicFailureClassificationIsSpecificAndRedacted(t *testing.T) {
	lease := scheduleIntrinsicLease()
	invalidErr := executeScheduleForTest(t, &conversationScheduleStoreStub{}, lease, "call-invalid", map[string]any{
		"name": "invalid", "goal": "send reminder", "cron": "not a cron", "timezone": "UTC",
	})
	code, summary := intrinsicTerminalFailure(coremodel.IntrinsicScheduleCreateToolName, invalidErr)
	if code != "invalid_intrinsic_arguments" || summary != "Core intrinsic arguments are invalid" {
		t.Fatalf("invalid classification code=%q summary=%q err=%v", code, summary, invalidErr)
	}

	privateErr := errors.New("database unavailable: private connection detail")
	persistenceErr := executeScheduleForTest(t, &conversationScheduleStoreStub{err: privateErr}, lease, "call-persistence", map[string]any{
		"name": "once", "goal": "send reminder", "run_at": "2026-08-09T00:00:00Z",
	})
	code, summary = intrinsicTerminalFailure(coremodel.IntrinsicScheduleCreateToolName, persistenceErr)
	if code != "schedule_persistence_failed" || summary != "Schedule could not be saved" || strings.Contains(summary, "private") {
		t.Fatalf("persistence classification code=%q summary=%q err=%v", code, summary, persistenceErr)
	}
}
