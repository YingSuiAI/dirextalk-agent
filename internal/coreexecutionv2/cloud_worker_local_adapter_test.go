package coreexecutionv2

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sort"
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
	artifact, err := adapter.GetArtifact(context.Background(), CloudWorkerArtifactGetRequest{Authority: requestAuthority, RecordKind: RecordKindCloudWorker, ArtifactID: items[0].ArtifactID})
	if err != nil || artifact["execution_id"] != executionID {
		t.Fatalf("artifact=%#v err=%v", artifact, err)
	}
	chunk, err := adapter.DownloadArtifact(context.Background(), CloudWorkerArtifactDownloadRequest{Authority: requestAuthority, RecordKind: RecordKindCloudWorker, ArtifactID: items[0].ArtifactID, MaxChunkBytes: 64})
	if err != nil || string(chunk.Data) != "worker report" || !chunk.EOF {
		t.Fatalf("chunk=%#v err=%v", chunk, err)
	}
	idempotencyKey := uuid.NewString()
	deleted, err := adapter.DeleteArtifact(context.Background(), CloudWorkerArtifactDeleteRequest{Authority: requestAuthority, RecordKind: RecordKindCloudWorker, ArtifactID: items[0].ArtifactID, IdempotencyKey: idempotencyKey})
	if err != nil || deleted["artifact_id"] != items[0].ArtifactID {
		t.Fatalf("deleted=%#v err=%v", deleted, err)
	}
	if _, err = adapter.DeleteArtifact(context.Background(), CloudWorkerArtifactDeleteRequest{Authority: requestAuthority, RecordKind: RecordKindCloudWorker, ArtifactID: items[0].ArtifactID, IdempotencyKey: idempotencyKey}); err != nil {
		t.Fatalf("Cloud Worker delete replay: %v", err)
	}
}

func TestLocalArtifactAdapterFencesRecordKindAndDeletesOnlyArtifact(t *testing.T) {
	repository, err := localartifact.NewRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	authority := localartifact.Authority{OwnerID: "owner", AccountGeneration: 7}
	executionID := uuid.NewString()
	sink, err := repository.BindLocalSandbox(authority, executionID)
	if err != nil {
		t.Fatal(err)
	}
	if err = sink.StoreArtifact(context.Background(), "report.html", bytes.NewBufferString("local report"), 12); err != nil {
		t.Fatal(err)
	}
	items, _, err := repository.ListLocalSandbox(context.Background(), authority, executionID, "", 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%#v err=%v", items, err)
	}
	adapter := &localCloudWorkerExecutionAdapter{artifacts: repository}
	requestAuthority := Authority{OwnerID: authority.OwnerID, AccountGeneration: authority.AccountGeneration}
	if _, err = adapter.GetArtifact(context.Background(), CloudWorkerArtifactGetRequest{Authority: requestAuthority, RecordKind: RecordKindCloudWorker, ArtifactID: items[0].ArtifactID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong record kind read error = %v", err)
	}
	idempotencyKey := uuid.NewString()
	deleted, err := adapter.DeleteArtifact(context.Background(), CloudWorkerArtifactDeleteRequest{Authority: requestAuthority, RecordKind: RecordKindLocalSandbox, ArtifactID: items[0].ArtifactID, IdempotencyKey: idempotencyKey})
	if err != nil || deleted["artifact_id"] != items[0].ArtifactID {
		t.Fatalf("deleted=%#v err=%v", deleted, err)
	}
	replayed, err := adapter.DeleteArtifact(context.Background(), CloudWorkerArtifactDeleteRequest{Authority: requestAuthority, RecordKind: RecordKindLocalSandbox, ArtifactID: items[0].ArtifactID, IdempotencyKey: idempotencyKey})
	if err != nil || replayed["artifact_id"] != items[0].ArtifactID {
		t.Fatalf("replayed=%#v err=%v", replayed, err)
	}
	if _, err = repository.GetLocalSandbox(context.Background(), authority, items[0].ArtifactID); !errors.Is(err, localartifact.ErrNotFound) {
		t.Fatalf("artifact remains after delete: %v", err)
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
		WorkerID: cloudRunID, PersistentWorker: true, ArtifactIDs: []string{}, CreatedAt: now, UpdatedAt: now}
	if err := execution.Seal(); err != nil {
		t.Fatal(err)
	}
	projection := cloudWorkerExecutionProjection(execution)
	if projection["worker_id"] != cloudRunID || projection["persistent_worker"] != true {
		t.Fatalf("projection=%#v", projection)
	}
	assertCloudWorkerProjectionKeys(t, projection, []string{
		"owner_id", "account_generation", "run_id", "execution_id", "plan_id", "plan_revision", "task_id",
		"confirmation_id", "conversation_id", "turn_id", "status", "revision", "worker_id", "persistent_worker",
		"artifact_ids", "failure_code", "failure_summary", "created_at", "updated_at",
	})
}

func TestCloudWorkerPlanProjectionContainsOnlyCurrentUIFields(t *testing.T) {
	plan := cloudworker.Plan{OwnerID: "owner", AccountGeneration: 7, PlanID: cloudPlanID, Revision: 1, Status: "waiting_user",
		ExecutionID: cloudRunID, TaskID: "00000000-0000-4000-8000-000000000003", ConfirmationID: "00000000-0000-4000-8000-000000000004",
		ConversationID: "00000000-0000-4000-8000-000000000005", TurnID: "00000000-0000-4000-8000-000000000006",
		ObjectiveSummary: "deploy service", ProposalReason: cloudworker.ProposalReasonLocalBudgetExceeded, PersistentWorkerReuse: true,
		WorkloadKind: cloudworker.WorkloadService, Service: &cloudworker.ServiceSpec{WorkloadID: "web", Port: 8080, HealthPath: "/health"},
		WorkspaceMode: cloudworker.WorkspaceWrite, AWS: cloudworker.AWSBinding{AccountID: "123456789012", Region: "ap-east-1"},
		Compute:   cloudworker.ComputeSpec{InstanceType: "t3.small", VCPU: 2, MemoryGiB: 2, VolumeGiB: 20, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125},
		Limits:    cloudworker.Limits{MaxRuntimeSeconds: 3600},
		Quote:     cloudworker.Quote{ComputeMicrosPerHour: 25_000, Currency: "USD", SourceTime: time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 8, 13, 12, 5, 0, 0, time.UTC)},
		CreatedAt: time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)}
	projection := cloudWorkerPlanProjection(plan)
	if projection["persistent_worker_reuse"] != true {
		t.Fatalf("projection=%#v", projection)
	}
	quote := projection["quote"].(map[string]any)
	if quote["compute_micros_per_hour"] != uint64(25_000) || quote["currency"] != "USD" {
		t.Fatalf("service hourly quote=%#v", quote)
	}
	if _, exists := quote["amount_micros"]; exists {
		t.Fatalf("service quote exposed estimated cost: %#v", quote)
	}
	if _, exists := quote["maximum_authorized_cost_micros"]; exists {
		t.Fatalf("service quote exposed authorized ceiling: %#v", quote)
	}
	plan.WorkloadKind, plan.Service = cloudworker.WorkloadJob, nil
	jobQuote := cloudWorkerPlanProjection(plan)["quote"].(map[string]any)
	if _, exists := jobQuote["amount_micros"]; !exists {
		t.Fatalf("bounded job quote omitted estimated cost: %#v", jobQuote)
	}
	if _, exists := jobQuote["maximum_authorized_cost_micros"]; !exists {
		t.Fatalf("bounded job quote omitted authorized ceiling: %#v", jobQuote)
	}
	assertCloudWorkerProjectionKeys(t, projection, []string{
		"owner_id", "account_generation", "plan_id", "revision", "status", "execution_id", "task_id", "confirmation_id",
		"conversation_id", "turn_id", "objective_summary", "proposal_reason", "persistent_worker_reuse", "workspace_mode",
		"aws", "compute", "limits", "quote", "created_at", "updated_at",
	})
}

func assertCloudWorkerProjectionKeys(t *testing.T, projection CloudWorkerObject, want []string) {
	t.Helper()
	got := make([]string, 0, len(projection))
	for key := range projection {
		got = append(got, key)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projection keys=%v want=%v", got, want)
	}
}
