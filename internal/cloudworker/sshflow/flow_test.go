package sshflow

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

type flowStore struct {
	run         Run
	beginErr    error
	completeErr error
	failErr     error
	completed   int
	failed      int
	summary     string
	progress    []string
}

func (store *flowStore) Begin(context.Context, coretask.Task) (Run, error) {
	return store.run, store.beginErr
}
func (store *flowStore) Progress(_ context.Context, _ *Run, phase, _ string) error {
	store.progress = append(store.progress, phase)
	return nil
}
func (store *flowStore) Complete(_ context.Context, _ Run, _ Result) error {
	store.completed++
	return store.completeErr
}
func (store *flowStore) Fail(_ context.Context, _ Run, _ Result, _, summary string) error {
	store.failed++
	store.summary = summary
	return store.failErr
}

type flowExecutor struct {
	calls          int
	request        Request
	result         Result
	err            error
	progressStages []string
}

func (executor *flowExecutor) Execute(_ context.Context, request Request) (Result, error) {
	executor.calls++
	executor.request = request
	for _, phase := range executor.progressStages {
		if request.ReportProgress != nil {
			_ = request.ReportProgress(context.Background(), phase, phase)
		}
	}
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
		PersistentWorkerReuse: true, ReuseWorkerID: "66666666-6666-4666-8666-666666666666",
		WorkloadKind: cloudworker.WorkloadService, Service: &cloudworker.ServiceSpec{WorkloadID: "memory-api", Port: 8080, HealthPath: "/health"},
		InputManifest: manifest, WorkspaceMode: cloudworker.WorkspaceReadOnly,
		AWS:     cloudworker.AWSBinding{AccountID: "123456789012", Region: "ap-east-1"},
		Compute: cloudworker.ComputeSpec{InstanceType: "t3.small", VolumeGiB: 20}},
		ConfirmationProof: "confirmed-proof", ModelSnapshot: snapshot}}
	executor := &flowExecutor{result: Result{Summary: "done", WorkerID: "i-0123456789abcdef0"}, progressStages: []string{"connecting_worker", "executing_remote_task", "collecting_result"}}
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
	if !executor.request.ReuseOnly || executor.request.ReuseWorkerID != store.run.Plan.ReuseWorkerID {
		t.Fatalf("exact reuse binding was not propagated: %+v", executor.request)
	}
	if executor.request.WorkspaceMode != cloudworker.WorkspaceReadOnly || len(executor.request.InputManifest.Items) != 1 ||
		executor.request.InputManifest.Items[0] != manifest.Items[0] {
		t.Fatalf("sealed workspace authority was not propagated: %+v", executor.request)
	}
	if got := strings.Join(store.progress, ","); got != "preparing_environment,connecting_worker,executing_remote_task,collecting_result" {
		t.Fatalf("progress stages=%q", got)
	}
}

func TestHandlerTerminalizesFailureWithoutDestroyingPersistentWorker(t *testing.T) {
	store := &flowStore{run: Run{Plan: cloudworker.Plan{ExecutionID: "33333333-3333-4333-8333-333333333333"}}}
	executor := &flowExecutor{result: Result{WorkerID: "i-0123456789abcdef0"}, err: errors.New("remote command failed: " + strings.Repeat("detail", 1000))}
	handler, _ := NewHandler(store, executor)
	outcome := handler.Handle(context.Background(), runningCloudTask())
	if outcome.Err == nil || !outcome.TerminalOwned || store.completed != 0 || store.failed != 1 ||
		len([]byte(store.summary)) != coretask.MaxSummaryBytes || !strings.HasPrefix(store.summary, "remote command failed") {
		t.Fatalf("outcome=%+v store=%+v", outcome, store)
	}
}

func TestHandlerRejectsSuccessWithoutWorkerIdentity(t *testing.T) {
	store := &flowStore{run: Run{Plan: cloudworker.Plan{ExecutionID: "33333333-3333-4333-8333-333333333333"}}}
	executor := &flowExecutor{result: Result{Summary: "done"}}
	handler, _ := NewHandler(store, executor)
	outcome := handler.Handle(context.Background(), runningCloudTask())
	if outcome.Err == nil || !outcome.TerminalOwned || store.failed != 1 || store.completed != 0 {
		t.Fatalf("outcome=%+v store=%+v", outcome, store)
	}
}

func TestHandlerNeverFallsBackToTaskOnlyTerminalOnDomainStoreFailure(t *testing.T) {
	tests := []struct {
		name  string
		store *flowStore
		exec  *flowExecutor
	}{
		{name: "begin", store: &flowStore{beginErr: errors.New("begin unavailable")}, exec: &flowExecutor{}},
		{name: "complete", store: &flowStore{run: Run{Plan: cloudworker.Plan{ExecutionID: "33333333-3333-4333-8333-333333333333"}}, completeErr: errors.New("commit unavailable")}, exec: &flowExecutor{result: Result{Summary: "done", WorkerID: "worker-a"}}},
		{name: "fail", store: &flowStore{run: Run{Plan: cloudworker.Plan{ExecutionID: "33333333-3333-4333-8333-333333333333"}}, failErr: errors.New("failure commit unavailable")}, exec: &flowExecutor{err: errors.New("remote failed")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, err := NewHandler(test.store, test.exec)
			if err != nil {
				t.Fatal(err)
			}
			outcome := handler.Handle(context.Background(), runningCloudTask())
			if outcome.Err == nil || !outcome.TerminalOwned {
				t.Fatalf("outcome=%+v", outcome)
			}
		})
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
