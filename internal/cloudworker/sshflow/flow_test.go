package sshflow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

type flowStore struct {
	run       Run
	completed int
	failed    int
}

func (store *flowStore) Begin(context.Context, coretask.Task) (Run, error) { return store.run, nil }
func (store *flowStore) Complete(_ context.Context, _ Run, _ Result) error {
	store.completed++
	return nil
}
func (store *flowStore) Fail(_ context.Context, _ Run, _ Result, _, _ string) error {
	store.failed++
	return nil
}

type flowExecutor struct {
	request Request
	result  Result
	err     error
}

func (executor *flowExecutor) Execute(_ context.Context, request Request) (Result, error) {
	executor.request = request
	return executor.result, executor.err
}

func runningCloudTask() coretask.Task {
	id := "11111111-1111-4111-8111-111111111111"
	return coretask.Task{ID: id, Spec: coretask.TaskSpec{Kind: coretask.TaskKindCloudWorker,
		Payload: coretask.TaskPayload{CloudWorker: &coretask.CloudWorkerTaskPayload{ExecutionID: id}}},
		Status: coretask.StatusRunning, Attempt: 1, LeaseEpoch: 1,
		Lease: &coretask.Lease{TaskID: id, Attempt: 1, Epoch: 1, Holder: "test", ExpiresAt: time.Now().Add(time.Hour)}}
}

func TestHandlerPassesOnlyConfirmedMinimalExecutionInputAndOwnsTerminal(t *testing.T) {
	snapshot := coremodel.ExecutionSnapshot{ProfileID: "22222222-2222-4222-8222-222222222222", Revision: 3,
		CredentialVersion: 4, Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://example.test/v1",
		Model: "test", APIKey: "secret"}
	manifest := cloudworker.InputManifest{Schema: cloudworker.InputManifestSchema, Items: []cloudworker.InputManifestItem{{
		InputID: "44444444-4444-4444-8444-444444444444", Kind: "file", Name: "input.txt", MountPath: "inputs/input.txt",
		MediaType: "text/plain", SizeBytes: 4, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourceRef: "55555555-5555-4555-8555-555555555555", SourceRevision: 1,
	}}}
	if _, err := manifest.Seal(); err != nil {
		t.Fatal(err)
	}
	store := &flowStore{run: Run{Plan: cloudworker.Plan{OwnerID: "owner", AccountGeneration: 7,
		ExecutionID: "33333333-3333-4333-8333-333333333333", Objective: "deploy service",
		WorkloadKind: cloudworker.WorkloadService, Service: &cloudworker.ServiceSpec{WorkloadID: "memory-api", Port: 8080, HealthPath: "/health"},
		InputManifest: manifest, WorkspaceMode: cloudworker.WorkspaceReadOnly,
		AWS:     cloudworker.AWSBinding{AccountID: "123456789012", Region: "ap-east-1"},
		Compute: cloudworker.ComputeSpec{InstanceType: "t3.small", VolumeGiB: 20}},
		ConfirmationProof: "confirmed-proof", ModelSnapshot: snapshot}}
	executor := &flowExecutor{result: Result{Summary: "done", WorkerID: "i-0123456789abcdef0"}}
	handler, err := NewHandler(store, executor)
	if err != nil {
		t.Fatal(err)
	}
	outcome := handler.Handle(context.Background(), runningCloudTask())
	if outcome.Err != nil || !outcome.TerminalOwned || store.completed != 1 || store.failed != 0 {
		t.Fatalf("outcome=%+v store=%+v", outcome, store)
	}
	if executor.request.Objective != "deploy service" || executor.request.AWS.Region != "ap-east-1" ||
		executor.request.Compute.InstanceType != "t3.small" || executor.request.ConfirmationProof != "confirmed-proof" ||
		executor.request.ModelSnapshot.APIKey != "secret" {
		t.Fatalf("request=%+v", executor.request)
	}
	if executor.request.WorkloadKind != cloudworker.WorkloadService || executor.request.Service == nil || executor.request.Service.Port != 8080 {
		t.Fatalf("service contract was not propagated: %+v", executor.request)
	}
	if executor.request.WorkspaceMode != cloudworker.WorkspaceReadOnly || len(executor.request.InputManifest.Items) != 1 ||
		executor.request.InputManifest.Items[0] != manifest.Items[0] {
		t.Fatalf("sealed workspace authority was not propagated: %+v", executor.request)
	}
}

func TestHandlerTerminalizesFailureWithoutDestroyingPersistentWorker(t *testing.T) {
	store := &flowStore{run: Run{Plan: cloudworker.Plan{ExecutionID: "33333333-3333-4333-8333-333333333333"}}}
	executor := &flowExecutor{result: Result{WorkerID: "i-0123456789abcdef0"}, err: errors.New("remote command failed")}
	handler, _ := NewHandler(store, executor)
	outcome := handler.Handle(context.Background(), runningCloudTask())
	if outcome.Err == nil || !outcome.TerminalOwned || store.completed != 0 || store.failed != 1 {
		t.Fatalf("outcome=%+v store=%+v", outcome, store)
	}
}

func TestHandlerRejectsSuccessWithoutWorkerIdentity(t *testing.T) {
	store := &flowStore{run: Run{Plan: cloudworker.Plan{ExecutionID: "33333333-3333-4333-8333-333333333333"}}}
	executor := &flowExecutor{result: Result{Summary: "done"}}
	handler, _ := NewHandler(store, executor)
	outcome := handler.Handle(context.Background(), runningCloudTask())
	if outcome.Err == nil || outcome.TerminalOwned || store.failed != 0 || store.completed != 0 {
		t.Fatalf("outcome=%+v store=%+v", outcome, store)
	}
}

func TestHandlerLeavesUncertainExecutionRecoverable(t *testing.T) {
	store := &flowStore{run: Run{Plan: cloudworker.Plan{ExecutionID: "33333333-3333-4333-8333-333333333333"}}}
	executor := &flowExecutor{result: Result{WorkerID: "worker-a"}, err: errors.Join(ErrExecutionUncertain, errors.New("SSH status unavailable"))}
	handler, _ := NewHandler(store, executor)
	outcome := handler.Handle(context.Background(), runningCloudTask())
	if !errors.Is(outcome.Err, ErrExecutionUncertain) || !outcome.TerminalOwned || store.failed != 0 || store.completed != 0 {
		t.Fatalf("outcome=%+v store=%+v", outcome, store)
	}
}
