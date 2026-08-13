package cloudworker

import (
	"testing"
	"time"
)

func TestPersistentWorkerTerminalExecutionNeedsNoEphemeralCleanupGraph(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	fixture := Execution{
		OwnerID: "owner", AccountGeneration: 1,
		RunID: "00000000-0000-4000-8000-000000000001", ExecutionID: "00000000-0000-4000-8000-000000000001",
		PlanID: "00000000-0000-4000-8000-000000000002", PlanRevision: 1, PlanDigest: digestValue("plan"),
		TaskID: "00000000-0000-4000-8000-000000000003", ConfirmationID: "00000000-0000-4000-8000-000000000004",
		ConversationID: "00000000-0000-4000-8000-000000000005", TurnID: "00000000-0000-4000-8000-000000000006",
		Status: StateSucceeded, State: StateSucceeded, Revision: 2, WorkspaceMode: WorkspaceNone,
		ModelBindingDigest: digestValue("model"), QuoteDigest: digestValue("quote"), ExecutionDigest: digestValue("execution"),
		WorkerID: "00000000-0000-4000-8000-000000000001", PersistentWorker: true, ProviderMutationStarted: true,
		ArtifactIDs: []string{}, CreatedAt: now, UpdatedAt: now,
	}
	if err := fixture.Seal(); err != nil {
		t.Fatal(err)
	}
	public, err := fixture.Public()
	if err != nil || !public.PersistentWorker || public.WorkerID != fixture.WorkerID || public.Cleanup.ResourcesTotal != 0 {
		t.Fatalf("projection=%#v err=%v", public, err)
	}
}
