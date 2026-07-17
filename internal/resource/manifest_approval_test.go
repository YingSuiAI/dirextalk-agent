package resource

import (
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestManifestFromBindsMixedApprovalsAndPreservesSingleLegacyFields(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	scope := newManifestApprovalScope()
	worker := manifestApprovalResource(now, scope, "sha256:"+repeatHex('a'), uuid.NewString())
	entry := manifestApprovalResource(now, scope, "sha256:"+repeatHex('b'), uuid.NewString())
	entry.Type, entry.LogicalName = TypeALB, "approved-entry"
	entry.DependsOn = []string{worker.ResourceID}

	mixed, err := manifestFrom([]ResourceV1{entry, worker}, true, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(mixed.ApprovalBindings) != 2 || mixed.ApprovalBindings[0].ApprovedPlanHash != worker.ApprovedPlanHash ||
		mixed.ApprovedPlanHash != "" || mixed.AutoDestroyApprovalID != "" {
		t.Fatalf("mixed manifest bindings=%+v legacy=%q/%q", mixed.ApprovalBindings, mixed.ApprovedPlanHash, mixed.AutoDestroyApprovalID)
	}
	if err := mixed.ValidateResourceApprovalScope(); err != nil {
		t.Fatalf("mixed approval scope = %v", err)
	}

	single, err := manifestFrom([]ResourceV1{worker}, true, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(single.ApprovalBindings) != 1 || single.ApprovedPlanHash != worker.ApprovedPlanHash || single.AutoDestroyApprovalID != worker.ApprovalID {
		t.Fatalf("single manifest lost legacy compatibility: %+v", single)
	}
	legacy := single
	legacy.ApprovalBindings = nil
	if err := NormalizeLegacyApprovalBindings(&legacy); err != nil || len(legacy.ApprovalBindings) != 1 ||
		legacy.ApprovalBindings[0].ApprovalID != worker.ApprovalID || legacy.ValidateResourceApprovalScope() != nil {
		t.Fatalf("legacy single normalization = %+v err=%v", legacy, err)
	}
}

func TestManifestApprovalBindingsRejectUnboundOrTamperedResource(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	scope := newManifestApprovalScope()
	worker := manifestApprovalResource(now, scope, "sha256:"+repeatHex('a'), uuid.NewString())
	entry := manifestApprovalResource(now, scope, "sha256:"+repeatHex('b'), uuid.NewString())
	manifest, err := manifestFrom([]ResourceV1{worker, entry}, true, now)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Resources[0].ApprovedPlanHash = "sha256:" + repeatHex('c')
	if err := manifest.ValidateResourceApprovalScope(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbound resource approval error = %v", err)
	}

	manifest, err = manifestFrom([]ResourceV1{worker, entry}, true, now)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ApprovalBindings[0].ApprovalID = uuid.NewString()
	if err := manifest.ValidateResourceApprovalScope(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered binding error = %v", err)
	}
}

type manifestApprovalScope struct {
	agentID      string
	taskID       string
	deploymentID string
}

func newManifestApprovalScope() manifestApprovalScope {
	return manifestApprovalScope{agentID: uuid.NewString(), taskID: uuid.NewString(), deploymentID: uuid.NewString()}
}

func manifestApprovalResource(now time.Time, scope manifestApprovalScope, planHash, approvalID string) ResourceV1 {
	resourceID := uuid.NewString()
	deadline := now.Add(time.Hour)
	return ResourceV1{
		ResourceID: resourceID, AgentInstanceID: scope.agentID, OwnerID: "owner-manifest", TaskID: scope.taskID, DeploymentID: scope.deploymentID,
		Type: TypeEC2, LogicalName: "worker", Region: "us-west-2", SpecDigest: "sha256:" + repeatHex('c'),
		ApprovedPlanHash: planHash, ApprovalID: approvalID, ProviderID: "i-manifest", Retention: task.RetentionEphemeralAutoDestroy,
		DestroyDeadline: deadline, AutoDestroyApproved: true, State: StateActive, Revision: 1, CreatedAt: now, UpdatedAt: now,
		Tags: map[string]string{
			TagAgentInstanceID: scope.agentID, TagOwnerID: "owner-manifest", TagTaskID: scope.taskID, TagDeploymentID: scope.deploymentID,
			TagResourceID: resourceID, TagRetention: string(task.RetentionEphemeralAutoDestroy), TagDestroyDeadline: deadline.Format(time.RFC3339),
			TagApprovedPlanHash: planHash, TagApprovalID: approvalID,
		},
	}
}
