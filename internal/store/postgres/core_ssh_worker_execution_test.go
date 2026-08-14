package postgres

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
)

type persistentExecutionRow struct {
	raw      []byte
	state    string
	revision int64
	digest   string
}

func (row persistentExecutionRow) Scan(dest ...any) error {
	*dest[0].(*[]byte), *dest[1].(*string), *dest[2].(*int64), *dest[3].(*string) = row.raw, row.state, row.revision, row.digest
	return nil
}

func TestScanPersistentWorkerTerminalExecution(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	execution := cloudworker.Execution{OwnerID: "owner", AccountGeneration: 7,
		RunID: "00000000-0000-4000-8000-000000000001", ExecutionID: "00000000-0000-4000-8000-000000000001",
		PlanID: "00000000-0000-4000-8000-000000000002", PlanRevision: 1, PlanDigest: strings.Repeat("a", 64),
		TaskID: "00000000-0000-4000-8000-000000000003", ConfirmationID: "00000000-0000-4000-8000-000000000004",
		ConversationID: "00000000-0000-4000-8000-000000000005", TurnID: "00000000-0000-4000-8000-000000000006",
		Status: cloudworker.StateSucceeded, State: cloudworker.StateSucceeded, Revision: 2, WorkspaceMode: cloudworker.WorkspaceNone,
		ModelBindingDigest: strings.Repeat("b", 64), QuoteDigest: strings.Repeat("c", 64), ExecutionDigest: strings.Repeat("d", 64),
		WorkerID: "00000000-0000-4000-8000-000000000001", PersistentWorker: true,
		ArtifactIDs: []string{}, CreatedAt: now, UpdatedAt: now}
	if err := execution.Seal(); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(execution)
	got, err := scanCloudWorkerExecution(persistentExecutionRow{raw: raw, state: string(execution.State), revision: int64(execution.Revision), digest: execution.Digest})
	if err != nil || got.WorkerID != execution.WorkerID || !got.PersistentWorker || got.Digest != execution.Digest {
		t.Fatalf("execution=%#v err=%v", got, err)
	}
}
