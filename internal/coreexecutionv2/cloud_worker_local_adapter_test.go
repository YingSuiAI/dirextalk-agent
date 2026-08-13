package coreexecutionv2

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/localartifact"
	"github.com/google/uuid"
)

func TestLocalCloudWorkerArtifactReadAndDownload(t *testing.T) {
	repository, err := localartifact.NewRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	authority := localartifact.Authority{OwnerID: "owner", AccountGeneration: 7}
	executionID := uuid.NewString()
	sink, _ := repository.Bind(authority, executionID)
	if err = sink.StoreArtifact(context.Background(), "report.html", bytes.NewBufferString("worker report"), 13); err != nil {
		t.Fatal(err)
	}
	items, _, _ := repository.List(context.Background(), authority, executionID, "", 10)
	adapter := &localCloudWorkerExecutionAdapter{artifacts: repository}
	requestAuthority := Authority{OwnerID: authority.OwnerID, AccountGeneration: authority.AccountGeneration}
	artifact, err := adapter.GetArtifact(context.Background(), CloudWorkerArtifactGetRequest{Authority: requestAuthority, ArtifactID: items[0].ArtifactID})
	if err != nil || artifact["execution_id"] != executionID {
		t.Fatalf("artifact=%#v err=%v", artifact, err)
	}
	chunk, err := adapter.DownloadArtifact(context.Background(), CloudWorkerArtifactDownloadRequest{Authority: requestAuthority, ArtifactID: items[0].ArtifactID, MaxChunkBytes: 64})
	if err != nil || string(chunk.Data) != "worker report" || !chunk.EOF {
		t.Fatalf("chunk=%#v err=%v", chunk, err)
	}
}

func TestPersistentWorkerExecutionProjection(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	execution := cloudworker.Execution{OwnerID: "owner", AccountGeneration: 7,
		RunID: cloudRunID, ExecutionID: cloudRunID, PlanID: cloudPlanID, PlanRevision: 1, PlanDigest: strings.Repeat("a", 64),
		TaskID: "00000000-0000-4000-8000-000000000003", ConfirmationID: "00000000-0000-4000-8000-000000000004",
		ConversationID: "00000000-0000-4000-8000-000000000005", TurnID: "00000000-0000-4000-8000-000000000006",
		Status: cloudworker.StateSucceeded, State: cloudworker.StateSucceeded, Revision: 2, WorkspaceMode: cloudworker.WorkspaceNone,
		ModelBindingDigest: strings.Repeat("b", 64), QuoteDigest: strings.Repeat("c", 64), ExecutionDigest: strings.Repeat("d", 64),
		WorkerID: cloudRunID, PersistentWorker: true, ProviderMutationStarted: true, ArtifactIDs: []string{}, CreatedAt: now, UpdatedAt: now}
	if err := execution.Seal(); err != nil {
		t.Fatal(err)
	}
	projection := cloudWorkerExecutionProjection(execution)
	if projection["worker_id"] != cloudRunID || projection["persistent_worker"] != true {
		t.Fatalf("projection=%#v", projection)
	}
}
