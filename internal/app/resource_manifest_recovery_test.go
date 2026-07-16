package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

type manifestRecoveryRepositoryFake struct {
	record postgres.ResourceManifestRecord
	failed int
}

func (fake *manifestRecoveryRepositoryFake) ListResourceManifestsNeedingRecovery(context.Context, int) ([]postgres.ResourceManifestRecord, error) {
	return []postgres.ResourceManifestRecord{fake.record}, nil
}

func (fake *manifestRecoveryRepositoryFake) GetResourceManifestRecord(context.Context, string) (postgres.ResourceManifestRecord, error) {
	return fake.record, nil
}

func (fake *manifestRecoveryRepositoryFake) MarkResourceManifestFailed(_ context.Context, _ string, generation int64, _ error) (postgres.ResourceManifestRecord, error) {
	if generation != fake.record.Generation {
		return postgres.ResourceManifestRecord{}, resource.ErrRevisionConflict
	}
	fake.failed++
	fake.record.Status = postgres.ResourceManifestFailedRetriable
	return fake.record, nil
}

type manifestRecoveryLaunchFake struct{ operation cloudexecution.Operation }

func (fake manifestRecoveryLaunchFake) GetByDeployment(context.Context, string) (cloudexecution.Operation, error) {
	return fake.operation, nil
}

type manifestRecoveryConnectionFake struct{ connection cloudapp.Connection }

func (fake manifestRecoveryConnectionFake) LoadConnection(context.Context, string, string) (cloudapp.Connection, error) {
	return fake.connection, nil
}

type manifestRecoveryRemote struct{}

func (manifestRecoveryRemote) Put(context.Context, resource.Manifest) error { return nil }
func (manifestRecoveryRemote) Get(context.Context, string) (resource.Manifest, error) {
	return resource.Manifest{}, resource.ErrNotFound
}
func (manifestRecoveryRemote) ListExpired(context.Context, time.Time) ([]resource.Manifest, error) {
	return nil, nil
}

type manifestRecoveryRuntimeFake struct{ calls int }

func (fake *manifestRecoveryRuntimeFake) RemoteManifest(context.Context, cloudapp.Connection) (recoverableManifestMirror, error) {
	fake.calls++
	return manifestRecoveryRemote{}, nil
}

type manifestRecoveryReplayerFake struct {
	calls int
	run   func() error
}

func (fake *manifestRecoveryReplayerFake) Replay(context.Context, postgres.ResourceManifestRecord, resource.ManifestMirror) error {
	fake.calls++
	if fake.run != nil {
		return fake.run()
	}
	return nil
}

func TestResourceManifestRecoveryReplaysOnlyMatchingCurrentScope(t *testing.T) {
	agentID, record, operation, connection := manifestRecoveryFixture()
	tests := []struct {
		name           string
		expectedFailed int
		mutate         func(*postgres.ResourceManifestRecord)
	}{
		{name: "stale generation", mutate: func(record *postgres.ResourceManifestRecord) { record.Generation++ }},
		{name: "wrong owner", expectedFailed: 1, mutate: func(record *postgres.ResourceManifestRecord) {
			record.Manifest.OwnerID = "other-owner"
			record.Manifest.Resources[0].OwnerID = "other-owner"
		}},
		{name: "mixed managed scope", expectedFailed: 1, mutate: func(record *postgres.ResourceManifestRecord) { record.Manifest.Managed = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scanned := record
			repositoryRecord := record
			test.mutate(&repositoryRecord)
			if test.name != "stale generation" {
				scanned = repositoryRecord
			}
			repository := &manifestRecoveryRepositoryFake{record: repositoryRecord}
			runtimes := &manifestRecoveryRuntimeFake{}
			replayer := &manifestRecoveryReplayerFake{}
			recovery, err := newResourceManifestRecovery(
				agentID, repositoryWithScan{manifestRecoveryRepositoryFake: repository, scanned: scanned},
				manifestRecoveryLaunchFake{operation}, manifestRecoveryConnectionFake{connection}, runtimes, replayer, time.Second,
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := recovery.RunOnce(context.Background()); err != nil {
				t.Fatalf("durably recorded recovery failure blocked retries: %v", err)
			}
			if replayer.calls != 0 || runtimes.calls != 0 || repository.failed != test.expectedFailed {
				t.Fatalf("invalid scope reached remote: replay=%d runtime=%d failed=%d", replayer.calls, runtimes.calls, repository.failed)
			}
		})
	}
}

func TestResourceManifestRecoveryAcceptsConsistentManagedScope(t *testing.T) {
	agentID, record, operation, connection := manifestRecoveryFixture()
	record.Manifest.Managed = true
	record.Manifest.Retention = task.RetentionManaged
	record.Manifest.DestroyDeadline = time.Time{}
	record.Manifest.AutoDestroyApproved = false
	record.Manifest.AutoDestroyApprovalID = ""
	record.Manifest.Resources[0].Retention = task.RetentionManaged
	record.Manifest.Resources[0].DestroyDeadline = time.Time{}
	record.Manifest.Resources[0].AutoDestroyApproved = false
	record.Manifest.Resources[0].State = resource.StateRetainedManaged
	repository := &manifestRecoveryRepositoryFake{record: record}
	runtimes := &manifestRecoveryRuntimeFake{}
	replayer := &manifestRecoveryReplayerFake{}
	recovery, err := newResourceManifestRecovery(
		agentID, repository, manifestRecoveryLaunchFake{operation}, manifestRecoveryConnectionFake{connection},
		runtimes, replayer, time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if replayer.calls != 1 || runtimes.calls != 1 || repository.failed != 0 {
		t.Fatalf("managed recovery state: replay=%d runtime=%d failed=%d", replayer.calls, runtimes.calls, repository.failed)
	}
}

type repositoryWithScan struct {
	*manifestRecoveryRepositoryFake
	scanned postgres.ResourceManifestRecord
}

func (repository repositoryWithScan) ListResourceManifestsNeedingRecovery(context.Context, int) ([]postgres.ResourceManifestRecord, error) {
	return []postgres.ResourceManifestRecord{repository.scanned}, nil
}

func TestResourceManifestRecoveryRetriesContinuouslyAfterPersistedFailure(t *testing.T) {
	agentID, record, operation, connection := manifestRecoveryFixture()
	repository := &manifestRecoveryRepositoryFake{record: record}
	runtimes := &manifestRecoveryRuntimeFake{}
	done := make(chan struct{})
	var once sync.Once
	replayer := &manifestRecoveryReplayerFake{run: func() error {
		if repository.failed == 0 {
			return errors.New("temporary DynamoDB outage")
		}
		once.Do(func() { close(done) })
		return nil
	}}
	recovery, err := newResourceManifestRecovery(
		agentID, repository, manifestRecoveryLaunchFake{operation}, manifestRecoveryConnectionFake{connection},
		runtimes, replayer, time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- recovery.Run(ctx) }()
	select {
	case <-done:
		cancel()
	case <-time.After(time.Second):
		cancel()
		t.Fatal("manifest recovery did not retry")
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("run error=%v", err)
	}
	if repository.failed != 1 || replayer.calls < 2 || runtimes.calls < 2 {
		t.Fatalf("retry state: failed=%d replay=%d runtime=%d", repository.failed, replayer.calls, runtimes.calls)
	}
}

func manifestRecoveryFixture() (string, postgres.ResourceManifestRecord, cloudexecution.Operation, cloudapp.Connection) {
	agentID, deploymentID, taskID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	approvalID, connectionID := uuid.NewString(), uuid.NewString()
	now := time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC)
	deadline := now.Add(time.Hour)
	planHash := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	manifest := resource.Manifest{
		ManifestID: deploymentID, AgentInstanceID: agentID, OwnerID: "owner-recovery", TaskID: taskID,
		DeploymentID: deploymentID, Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: deadline,
		AutoDestroyApproved: true, AutoDestroyApprovalID: approvalID, ApprovedPlanHash: planHash,
		Revision: 3, UpdatedAt: now,
	}
	manifest.Resources = []resource.ResourceV1{{
		ResourceID: uuid.NewString(), AgentInstanceID: agentID, OwnerID: manifest.OwnerID, TaskID: taskID,
		DeploymentID: deploymentID, Region: "us-west-2", ApprovedPlanHash: planHash, ApprovalID: approvalID,
		Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: deadline, AutoDestroyApproved: true,
		State: resource.StateActive,
	}}
	operation := cloudexecution.Operation{
		Intent: cloudexecution.Intent{
			Launch:       cloudexecution.LaunchRequest{OwnerID: manifest.OwnerID, ApprovalID: approvalID},
			ConnectionID: connectionID, ApprovedPlanHash: planHash, DeploymentID: deploymentID,
		},
		State: cloudexecution.StateActive, TaskID: taskID,
	}
	connection := cloudapp.Connection{
		ConnectionID: connectionID, OwnerID: manifest.OwnerID, AccountID: "123456789012", Region: "us-west-2",
		ControlRoleARN: "arn:aws:iam::123456789012:role/control", Status: "active", Revision: 1,
	}
	return agentID, postgres.ResourceManifestRecord{Manifest: manifest, Generation: 7, Status: postgres.ResourceManifestPending}, operation, connection
}
