package app

import (
	"context"
	"errors"
	"sort"
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
	markManifestRecoveryResourceManaged(&record.Manifest.Resources[0])
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

func TestResourceManifestRecoveryAcceptsBoundedManagedPreparationSnapshot(t *testing.T) {
	agentID, record, operation, connection := managedPreparationRecoveryFixture(t)
	repository := &manifestRecoveryRepositoryFake{record: record}
	runtimes := &manifestRecoveryRuntimeFake{}
	replayer := &manifestRecoveryReplayerFake{}
	recovery, err := newResourceManifestRecovery(
		agentID, repository, manifestRecoveryLaunchFake{operation}, manifestRecoveryConnectionFake{connection}, runtimes, replayer, time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if replayer.calls != 1 || runtimes.calls != 1 || repository.failed != 0 {
		t.Fatalf("mixed managed recovery state: replay=%d runtime=%d failed=%d", replayer.calls, runtimes.calls, repository.failed)
	}
}

func TestResourceManifestRecoveryRejectsPreparationResourceOutsideCurrentScope(t *testing.T) {
	agentID, record, operation, connection := managedPreparationRecoveryFixture(t)
	foreignPlanHash := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	preparationApprovalID := ""
	for index := range record.Manifest.Resources {
		item := &record.Manifest.Resources[index]
		if item.IntentOrigin == resource.IntentOriginManagedPreparation {
			preparationApprovalID = item.ApprovalID
			item.ApprovedPlanHash = foreignPlanHash
			item.Tags[resource.TagApprovedPlanHash] = foreignPlanHash
		}
	}
	record.Manifest.ApprovalBindings = []resource.ApprovalBinding{
		{ApprovedPlanHash: operation.ApprovedPlanHash, ApprovalID: operation.Launch.ApprovalID},
		{ApprovedPlanHash: foreignPlanHash, ApprovalID: preparationApprovalID},
	}
	if err := record.Manifest.ValidateResourceApprovalScope(); err != nil {
		t.Fatalf("fixture must reach recovery scope validation: %v", err)
	}
	repository := &manifestRecoveryRepositoryFake{record: record}
	runtimes := &manifestRecoveryRuntimeFake{}
	replayer := &manifestRecoveryReplayerFake{}
	recovery, err := newResourceManifestRecovery(
		agentID, repository, manifestRecoveryLaunchFake{operation}, manifestRecoveryConnectionFake{connection}, runtimes, replayer, time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if replayer.calls != 0 || runtimes.calls != 0 || repository.failed != 1 {
		t.Fatalf("foreign preparation scope reached remote: replay=%d runtime=%d failed=%d", replayer.calls, runtimes.calls, repository.failed)
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
	resourceID := uuid.NewString()
	manifest.Resources = []resource.ResourceV1{{
		ResourceID: resourceID, AgentInstanceID: agentID, OwnerID: manifest.OwnerID, TaskID: taskID,
		DeploymentID: deploymentID, Region: "us-west-2", ApprovedPlanHash: planHash, ApprovalID: approvalID,
		Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: deadline, AutoDestroyApproved: true,
		Type: resource.TypeEBS, SpecDigest: planHash, State: resource.StateActive,
		Tags: map[string]string{
			resource.TagAgentInstanceID: agentID, resource.TagOwnerID: manifest.OwnerID, resource.TagTaskID: taskID,
			resource.TagDeploymentID: deploymentID, resource.TagResourceID: resourceID,
			resource.TagRetention: string(task.RetentionEphemeralAutoDestroy), resource.TagDestroyDeadline: deadline.UTC().Format(time.RFC3339),
			resource.TagApprovedPlanHash: planHash, resource.TagApprovalID: approvalID,
		},
	}}
	manifest.ApprovalBindings = []resource.ApprovalBinding{{ApprovedPlanHash: planHash, ApprovalID: approvalID}}
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

func markManifestRecoveryResourceManaged(item *resource.ResourceV1) {
	item.Retention = task.RetentionManaged
	item.DestroyDeadline = time.Time{}
	item.AutoDestroyApproved = false
	item.State = resource.StateRetainedManaged
	item.Tags[resource.TagRetention] = string(task.RetentionManaged)
	item.Tags[resource.TagDestroyDeadline] = "managed"
}

func managedPreparationRecoveryFixture(t *testing.T) (string, postgres.ResourceManifestRecord, cloudexecution.Operation, cloudapp.Connection) {
	t.Helper()
	agentID, record, operation, connection := manifestRecoveryFixture()
	record.Manifest.Managed = true
	record.Manifest.Retention = task.RetentionManaged
	record.Manifest.DestroyDeadline = time.Time{}
	record.Manifest.AutoDestroyApproved = false
	record.Manifest.AutoDestroyApprovalID = ""
	markManifestRecoveryResourceManaged(&record.Manifest.Resources[0])

	preparationApprovalID := uuid.NewString()
	snapshotID, replacementID := uuid.NewString(), uuid.NewString()
	scopeDigest := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	deadline := record.Manifest.UpdatedAt.Add(24 * time.Hour)
	preparationTags := func(resourceID string, retention task.RetentionPolicy, destroyDeadline string) map[string]string {
		return map[string]string{
			resource.TagAgentInstanceID: agentID, resource.TagOwnerID: record.Manifest.OwnerID, resource.TagTaskID: record.Manifest.TaskID,
			resource.TagDeploymentID: record.Manifest.DeploymentID, resource.TagResourceID: resourceID,
			resource.TagRetention: string(retention), resource.TagDestroyDeadline: destroyDeadline,
			resource.TagApprovedPlanHash: operation.ApprovedPlanHash, resource.TagApprovalID: preparationApprovalID,
			resource.TagIntentOrigin: string(resource.IntentOriginManagedPreparation), resource.TagOriginScopeDigest: scopeDigest,
		}
	}
	snapshot := resource.ResourceV1{
		ResourceID: snapshotID, AgentInstanceID: agentID, OwnerID: record.Manifest.OwnerID, TaskID: record.Manifest.TaskID,
		DeploymentID: record.Manifest.DeploymentID, Region: connection.Region, Type: resource.TypeSnapshot, SpecDigest: operation.ApprovedPlanHash,
		ApprovedPlanHash: operation.ApprovedPlanHash, ApprovalID: preparationApprovalID, IntentOrigin: resource.IntentOriginManagedPreparation,
		OriginScopeDigest: scopeDigest, DependsOn: []string{record.Manifest.Resources[0].ResourceID}, Retention: task.RetentionEphemeralAutoDestroy,
		DestroyDeadline: deadline, AutoDestroyApproved: true, State: resource.StateActive,
		Tags: preparationTags(snapshotID, task.RetentionEphemeralAutoDestroy, deadline.UTC().Format(time.RFC3339)),
	}
	replacement := resource.ResourceV1{
		ResourceID: replacementID, AgentInstanceID: agentID, OwnerID: record.Manifest.OwnerID, TaskID: record.Manifest.TaskID,
		DeploymentID: record.Manifest.DeploymentID, Region: connection.Region, Type: resource.TypeEBS, SpecDigest: operation.ApprovedPlanHash,
		ApprovedPlanHash: operation.ApprovedPlanHash, ApprovalID: preparationApprovalID, IntentOrigin: resource.IntentOriginManagedPreparation,
		OriginScopeDigest: scopeDigest, DependsOn: []string{snapshotID}, Retention: task.RetentionManaged, State: resource.StateRetainedManaged,
		Tags: preparationTags(replacementID, task.RetentionManaged, "managed"),
	}
	record.Manifest.Resources = append(record.Manifest.Resources, snapshot, replacement)
	record.Manifest.ApprovedPlanHash = ""
	record.Manifest.ApprovalBindings = []resource.ApprovalBinding{
		{ApprovedPlanHash: operation.ApprovedPlanHash, ApprovalID: operation.Launch.ApprovalID},
		{ApprovedPlanHash: operation.ApprovedPlanHash, ApprovalID: preparationApprovalID},
	}
	sort.Slice(record.Manifest.ApprovalBindings, func(left, right int) bool {
		return record.Manifest.ApprovalBindings[left].ApprovalID < record.Manifest.ApprovalBindings[right].ApprovalID
	})
	if err := record.Manifest.ValidateResourceApprovalScope(); err != nil {
		t.Fatalf("managed preparation fixture is invalid: %v", err)
	}
	return agentID, record, operation, connection
}
