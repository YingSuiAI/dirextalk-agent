package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

type responseLossManifestMirror struct {
	manifest       resource.Manifest
	puts           int
	failAfterWrite bool
}

func (mirror *responseLossManifestMirror) Put(_ context.Context, manifest resource.Manifest) error {
	mirror.puts++
	encoded, _ := json.Marshal(manifest)
	_ = json.Unmarshal(encoded, &mirror.manifest)
	if mirror.failAfterWrite {
		mirror.failAfterWrite = false
		return errors.New("simulated DynamoDB response loss")
	}
	return nil
}

func (mirror *responseLossManifestMirror) Get(_ context.Context, deploymentID string) (resource.Manifest, error) {
	if mirror.manifest.DeploymentID != deploymentID {
		return resource.Manifest{}, resource.ErrNotFound
	}
	return mirror.manifest, nil
}

func (*responseLossManifestMirror) ListExpired(context.Context, time.Time) ([]resource.Manifest, error) {
	return nil, nil
}

func TestTrackedManifestReplayPersistsReadBackAndFencesOldGeneration(t *testing.T) {
	_, baseStore, instanceID := newPlanningTestStore(t)
	ctx := context.Background()
	store, err := baseStore.NewResourceStore()
	if err != nil {
		t.Fatal(err)
	}
	manifest := recoveryManifestFixture(instanceID)
	record, err := store.PutResourceManifestPending(ctx, manifest, 0)
	if err != nil {
		t.Fatal(err)
	}
	remote := &responseLossManifestMirror{failAfterWrite: true}
	tracked, err := postgres.NewTrackedResourceManifestMirror(store, remote)
	if err != nil {
		t.Fatal(err)
	}
	if err := tracked.Replay(ctx, record); err != nil {
		t.Fatalf("response-loss replay: %v", err)
	}
	mirrored, err := store.GetResourceManifestRecord(ctx, manifest.DeploymentID)
	if err != nil || mirrored.Status != postgres.ResourceManifestMirrored || mirrored.Generation != record.Generation {
		t.Fatalf("mirrored record=%+v err=%v", mirrored, err)
	}

	manifest.Revision++
	manifest.UpdatedAt = manifest.UpdatedAt.Add(time.Second)
	manifest.Resources[0].UpdatedAt = manifest.UpdatedAt
	manifest.Resources[0].ReadBack.TagDigest = "sha256:" + strings.Repeat("b", 64)
	failedRecord, err := store.PutResourceManifestPending(ctx, manifest, mirrored.Generation)
	if err != nil {
		t.Fatal(err)
	}
	failedRecord, err = store.MarkResourceManifestFailed(ctx, manifest.DeploymentID, failedRecord.Generation, errors.New("temporary mirror failure"))
	if err != nil {
		t.Fatal(err)
	}
	firstFailureAt := failedRecord.UpdatedAt
	failedRecord, err = store.MarkResourceManifestFailed(ctx, manifest.DeploymentID, failedRecord.Generation, errors.New("temporary mirror failure"))
	if err != nil || !failedRecord.UpdatedAt.After(firstFailureAt) {
		t.Fatalf("retry did not rotate failed generation: record=%+v err=%v", failedRecord, err)
	}
	if err := tracked.Replay(ctx, failedRecord); err != nil {
		t.Fatalf("failed_retriable replay: %v", err)
	}
	recovered, err := store.GetResourceManifestRecord(ctx, manifest.DeploymentID)
	if err != nil || recovered.Status != postgres.ResourceManifestMirrored || recovered.Generation != failedRecord.Generation {
		t.Fatalf("recovered record=%+v err=%v", recovered, err)
	}

	newer := manifest
	newer.Revision++
	newer.UpdatedAt = newer.UpdatedAt.Add(time.Second)
	newer.Resources[0].UpdatedAt = newer.UpdatedAt
	newer.Resources[0].ReadBack.TagDigest = "sha256:" + strings.Repeat("c", 64)
	if _, err := store.PutResourceManifestPending(ctx, newer, recovered.Generation); err != nil {
		t.Fatal(err)
	}
	putsBefore := remote.puts
	if err := tracked.Replay(ctx, failedRecord); !errors.Is(err, resource.ErrRevisionConflict) {
		t.Fatalf("stale generation replay error=%v", err)
	}
	if remote.puts != putsBefore {
		t.Fatal("stale PostgreSQL generation reached the remote mirror")
	}
}

func recoveryManifestFixture(agentInstanceID string) resource.Manifest {
	now := time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC)
	deploymentID, taskID, resourceID, approvalID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	deadline := now.Add(time.Hour)
	planHash := "sha256:" + strings.Repeat("a", 64)
	tags := map[string]string{
		resource.TagAgentInstanceID: agentInstanceID, resource.TagOwnerID: "owner-manifest-recovery",
		resource.TagTaskID: taskID, resource.TagDeploymentID: deploymentID, resource.TagResourceID: resourceID,
		resource.TagRetention: string(task.RetentionEphemeralAutoDestroy), resource.TagDestroyDeadline: deadline.Format(time.RFC3339),
	}
	item := resource.ResourceV1{
		ResourceID: resourceID, AgentInstanceID: agentInstanceID, OwnerID: "owner-manifest-recovery",
		TaskID: taskID, DeploymentID: deploymentID, Type: resource.TypeEC2, LogicalName: "manifest-worker",
		Region: "us-west-2", SpecDigest: planHash, ApprovedPlanHash: planHash, ApprovalID: approvalID,
		ProviderID: "i-manifest-fixture", Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: deadline,
		AutoDestroyApproved: true, Tags: tags, State: resource.StateActive,
		ReadBack: resource.ReadBackEvidence{
			Exists: true, ProviderID: "i-manifest-fixture", ObservedAt: now, TagDigest: "sha256:" + strings.Repeat("d", 64),
		},
		Revision: 2, CreatedAt: now, UpdatedAt: now,
	}
	return resource.Manifest{
		ManifestID: deploymentID, AgentInstanceID: agentInstanceID, OwnerID: item.OwnerID, TaskID: taskID,
		DeploymentID: deploymentID, Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: deadline,
		AutoDestroyApproved: true, AutoDestroyApprovalID: approvalID, ApprovedPlanHash: planHash,
		Resources: []resource.ResourceV1{item}, Revision: 1, UpdatedAt: now,
	}
}
