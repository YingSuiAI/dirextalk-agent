package agentcapability

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

type occurrenceReaderFake struct {
	coretask.ScheduleStore
	items     []coretask.Occurrence
	seenToken string
	seenLimit int
	seenID    string
}

func (f *occurrenceReaderFake) ListOccurrences(_ context.Context, _ string, token string, limit int) ([]coretask.Occurrence, string, error) {
	f.seenToken, f.seenLimit = token, limit
	return append([]coretask.Occurrence(nil), f.items...), "next-token", nil
}

func (f *occurrenceReaderFake) GetOccurrence(_ context.Context, id string) (coretask.Occurrence, error) {
	f.seenID = id
	for _, item := range f.items {
		if item.ID == id {
			return item, nil
		}
	}
	return coretask.Occurrence{}, coretask.ErrNotFound
}

func TestScheduleOccurrenceReadIsOwnerScopedAndPaginated(t *testing.T) {
	at := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	items := []coretask.Occurrence{{ID: "00000000-0000-4000-8000-000000000101", ScheduleID: "00000000-0000-4000-8000-000000000201", TaskID: "00000000-0000-4000-8000-000000000301", ScheduledFor: at, CreatedAt: at}}
	store := &occurrenceReaderFake{items: items}
	capability := &coreScheduleCapability{store: store}
	ctx := capabilityTestContext()
	result, err := capability.HandleOperation(ctx, "list_runs", []byte(`{"schedule_id":"00000000-0000-4000-8000-000000000201","page_token":"cursor","limit":7}`))
	if err != nil {
		t.Fatalf("list_runs: %v", err)
	}
	if store.seenToken != "cursor" || store.seenLimit != 7 {
		t.Fatalf("pagination not forwarded: token=%q limit=%d", store.seenToken, store.seenLimit)
	}
	var listed struct {
		Runs          []coretask.Occurrence `json:"runs"`
		NextPageToken string                `json:"next_page_token"`
	}
	if err := json.Unmarshal(result, &listed); err != nil || len(listed.Runs) != 1 || listed.NextPageToken != "next-token" {
		t.Fatalf("list_runs result=%s err=%v", result, err)
	}
	if _, err := capability.HandleOperation(ctx, "get_run", []byte(`{"run_id":"00000000-0000-4000-8000-000000000101"}`)); err != nil {
		t.Fatalf("get_run: %v", err)
	}
	if store.seenID != items[0].ID {
		t.Fatalf("get_run id=%q", store.seenID)
	}
	if _, err := capability.HandleOperation(ctx, "list_runs", []byte(`{"schedule_id":"00000000-0000-4000-8000-000000000201","owner_id":"attacker"}`)); err == nil {
		t.Fatal("owner override was accepted")
	}
	if _, err := capability.HandleOperation(context.Background(), "list_runs", []byte(`{"schedule_id":"00000000-0000-4000-8000-000000000201"}`)); err == nil {
		t.Fatal("missing owner context was accepted")
	}
}

func TestScheduleCapabilityOptionalOwnerBinding(t *testing.T) {
	store := &occurrenceReaderFake{}
	capability := NewScheduleCapability(store, func() string { return "owner-2" })
	_, err := capability.HandleOperation(capabilityTestContext(), "list_runs", []byte(`{"schedule_id":"00000000-0000-4000-8000-000000000201"}`))
	if err == nil {
		t.Fatal("owner mismatch was accepted")
	}
	capability = NewScheduleCapability(store, func() string { return "owner-1" })
	if _, err := capability.HandleOperation(capabilityTestContext(), "list_runs", []byte(`{"schedule_id":"00000000-0000-4000-8000-000000000201"}`)); err != nil {
		t.Fatalf("matching owner rejected: %v", err)
	}
}

func TestScheduleMutationReceiptsPreserveIDsAndReplayMarker(t *testing.T) {
	scheduleID := "00000000-0000-4000-8000-000000000201"
	occurrenceID := "00000000-0000-4000-8000-000000000101"
	taskID := "00000000-0000-4000-8000-000000000301"
	deleted, ok := scheduleDeleteResult(coretask.Schedule{ID: scheduleID, Deleted: true, Replayed: true})["schedule_id"]
	if !ok || deleted != scheduleID {
		t.Fatalf("delete receipt lost schedule id: %#v", deleted)
	}
	deleteReceipt := scheduleDeleteResult(coretask.Schedule{ID: scheduleID, Deleted: true, Replayed: true})
	if deleteReceipt["deleted"] != true || deleteReceipt["replayed"] != true {
		t.Fatalf("delete receipt=%#v", deleteReceipt)
	}
	triggerReceipt := scheduleTriggerResult(coretask.Schedule{ID: scheduleID, Replayed: true}, coretask.Occurrence{ID: occurrenceID}, coretask.Task{ID: taskID})
	if triggerReceipt["occurrence_id"] != occurrenceID || triggerReceipt["task_id"] != taskID || triggerReceipt["replayed"] != true {
		t.Fatalf("trigger receipt=%#v", triggerReceipt)
	}
}
