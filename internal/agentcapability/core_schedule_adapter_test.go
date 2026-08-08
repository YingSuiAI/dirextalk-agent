package agentcapability

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

type scheduleStoreFake struct {
	schedule coretask.Schedule
	create   coretask.CreateScheduleCommand
	listPage string
	listSize int
}

func (f *scheduleStoreFake) FindOccurrence(context.Context, string, string) (coretask.Occurrence, error) {
	return coretask.Occurrence{}, coretask.ErrNotFound
}
func (f *scheduleStoreFake) CreateOccurrence(context.Context, coretask.Schedule, coretask.TriggerNowCommand, coretask.Occurrence) (coretask.Occurrence, error) {
	return coretask.Occurrence{}, coretask.ErrInvalid
}
func (f *scheduleStoreFake) CreateSchedule(_ context.Context, command coretask.CreateScheduleCommand) (coretask.Schedule, error) {
	f.create, f.schedule = command, command.Schedule
	return command.Schedule, nil
}
func (f *scheduleStoreFake) GetSchedule(context.Context, string) (coretask.Schedule, error) {
	return f.schedule, nil
}
func (f *scheduleStoreFake) ListSchedules(_ context.Context, page string, size int) ([]coretask.Schedule, string, error) {
	f.listPage, f.listSize = page, size
	return []coretask.Schedule{f.schedule}, "next", nil
}
func (f *scheduleStoreFake) UpdateSchedule(context.Context, coretask.UpdateScheduleCommand) (coretask.Schedule, error) {
	return f.schedule, nil
}
func (f *scheduleStoreFake) PauseSchedule(context.Context, coretask.ScheduleMutationCommand) (coretask.Schedule, error) {
	return f.schedule, nil
}
func (f *scheduleStoreFake) ResumeSchedule(context.Context, coretask.ScheduleMutationCommand) (coretask.Schedule, error) {
	return f.schedule, nil
}
func (f *scheduleStoreFake) TriggerNow(context.Context, coretask.TriggerScheduleCommand) (coretask.Schedule, coretask.Occurrence, coretask.Task, error) {
	return f.schedule, coretask.Occurrence{}, coretask.Task{}, nil
}
func (f *scheduleStoreFake) DeleteSchedule(context.Context, coretask.ScheduleMutationCommand) (coretask.Schedule, error) {
	return f.schedule, nil
}

func TestScheduleCapabilityPublishesOnlyCanonicalCoreOperations(t *testing.T) {
	descriptor := (&coreScheduleCapability{}).Descriptor()
	seen := map[string]bool{}
	for _, operation := range descriptor.GetOperations() {
		seen[operation.GetOperationId()] = true
		if operation.GetInputSchemaJson() == "" || operation.GetResultSchemaJson() == "" {
			t.Fatalf("operation %q lacks exact schemas", operation.GetOperationId())
		}
	}
	for _, name := range []string{"create_schedule", "get_schedule", "list_schedules", "update_schedule", "pause_schedule", "resume_schedule", "trigger_schedule", "delete_schedule"} {
		if !seen[name] {
			t.Fatalf("canonical operation %q missing", name)
		}
	}
	for _, removed := range []string{"list_runs", "get_run"} {
		if seen[removed] {
			t.Fatalf("legacy operation %q remains published", removed)
		}
	}
}

func TestScheduleProjectionMatchesCoreScheduleContract(t *testing.T) {
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	runAt := at.Add(time.Hour)
	schedule := coretask.Schedule{
		ID: "00000000-0000-4000-8000-000000000201", Name: "once",
		Spec:  coretask.TaskTemplate{Kind: coretask.TaskKindAgent, Goal: "summarize", ModelProfileID: "00000000-0000-4000-8000-000000000301"},
		RunAt: &runAt, Timezone: "UTC", Revision: 3, NextRunAt: runAt, CreatedAt: at, UpdatedAt: at,
	}
	projection := scheduleProjection(schedule)
	if projection["schedule_id"] != schedule.ID || projection["state"] != "active" || projection["task_template"] == nil || projection["trigger"] == nil {
		t.Fatalf("projection=%#v", projection)
	}
	for _, forbidden := range []string{"id", "spec", "paused", "prompt", "trigger_kind", "status"} {
		if _, ok := projection[forbidden]; ok {
			t.Fatalf("private/legacy field %q leaked: %#v", forbidden, projection)
		}
	}
	raw, err := json.Marshal(projection)
	if err != nil || !json.Valid(raw) {
		t.Fatalf("projection JSON=%s err=%v", raw, err)
	}
}

func TestScheduleCapabilityCreateAndListUseCanonicalCoreContract(t *testing.T) {
	store := &scheduleStoreFake{}
	capability := &coreScheduleCapability{store: store}
	input := []byte(`{"idempotency_key":"00000000-0000-4000-8000-000000000111","name":"once","task_template":{"kind":"agent","goal":"summarize","model_profile_id":"00000000-0000-4000-8000-000000000301"},"trigger":{"run_at":"2026-08-09T12:00:00Z"}}`)
	created, err := capability.HandleOperation(capabilityTestContext(), "create_schedule", input)
	if err != nil {
		t.Fatalf("create_schedule: %v", err)
	}
	if store.create.Schedule.Spec.Payload.Agent == nil || store.create.Schedule.Spec.Payload.Agent.OwnerID != "owner-1" || store.create.Schedule.Spec.Payload.Agent.AccountGeneration != 1 {
		t.Fatalf("server authority was not injected: %#v", store.create.Schedule.Spec.Payload.Agent)
	}
	var createResult map[string]any
	if json.Unmarshal(created, &createResult) != nil {
		t.Fatalf("create result=%s", created)
	}
	schedule, ok := createResult["schedule"].(map[string]any)
	if !ok || schedule["schedule_id"] == "" || schedule["state"] != "active" || schedule["task_template"] == nil || schedule["trigger"] == nil {
		t.Fatalf("canonical create result=%#v", createResult)
	}
	for _, forbidden := range []string{"id", "spec", "paused", "prompt", "trigger_kind", "status", "replayed"} {
		if _, exists := schedule[forbidden]; exists {
			t.Fatalf("legacy/private field %q leaked: %#v", forbidden, schedule)
		}
	}

	listed, err := capability.HandleOperation(capabilityTestContext(), "list_schedules", []byte(`{"page_size":7,"page_token":"cursor"}`))
	if err != nil {
		t.Fatalf("list_schedules: %v", err)
	}
	if store.listPage != "cursor" || store.listSize != 7 {
		t.Fatalf("list request page=%q size=%d", store.listPage, store.listSize)
	}
	var listResult map[string]any
	if json.Unmarshal(listed, &listResult) != nil || listResult["next_page_token"] != "next" {
		t.Fatalf("canonical list result=%s", listed)
	}
}

func TestScheduleCapabilityRejectsClientAuthorityAndNonAgentTemplates(t *testing.T) {
	capability := &coreScheduleCapability{store: &scheduleStoreFake{}}
	inputs := []string{
		`{"idempotency_key":"00000000-0000-4000-8000-000000000111","name":"forged","task_template":{"kind":"agent","goal":"summarize","model_profile_id":"00000000-0000-4000-8000-000000000301","payload":{"agent":{"owner_id":"attacker","account_generation":9}}},"trigger":{"run_at":"2026-08-09T12:00:00Z"}}`,
		`{"idempotency_key":"00000000-0000-4000-8000-000000000112","name":"extension","task_template":{"kind":"extension","goal":"run","payload":{"extension":{"operation":"execute_tool"}}},"trigger":{"run_at":"2026-08-09T12:00:00Z"}}`,
	}
	for _, input := range inputs {
		if _, err := capability.HandleOperation(capabilityTestContext(), "create_schedule", []byte(input)); err == nil {
			t.Fatalf("unsafe schedule input accepted: %s", input)
		}
	}
}
