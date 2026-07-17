package postgres

import (
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestResourceManifestValidatorRequiresPerResourceApprovalBindings(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	instanceID := uuid.New()
	manifest := postgresMixedApprovalManifest(instanceID.String(), now)
	store := &ResourceStore{instanceID: instanceID}
	if err := store.validateManifest(manifest); err != nil {
		t.Fatalf("mixed approval manifest validation = %v", err)
	}

	manifest.Resources[1].ApprovalID = uuid.NewString()
	if err := store.validateManifest(manifest); err == nil {
		t.Fatal("unbound entry resource approval was accepted")
	}
}

func postgresMixedApprovalManifest(agentID string, now time.Time) resource.Manifest {
	deadline := now.Add(time.Hour)
	taskID, deploymentID := uuid.NewString(), uuid.NewString()
	workerPlan, entryPlan := manifestDigest("a"), manifestDigest("b")
	newResource := func(kind resource.Type, logicalName, providerID, planHash, approvalID string, dependsOn ...string) resource.ResourceV1 {
		resourceID := uuid.NewString()
		return resource.ResourceV1{
			ResourceID: resourceID, AgentInstanceID: agentID, OwnerID: "owner-manifest", TaskID: taskID, DeploymentID: deploymentID,
			Type: kind, LogicalName: logicalName, Region: "us-west-2", SpecDigest: manifestDigest("c"), ApprovedPlanHash: planHash,
			ApprovalID: approvalID, ProviderID: providerID, DependsOn: dependsOn, Retention: task.RetentionEphemeralAutoDestroy,
			DestroyDeadline: deadline, AutoDestroyApproved: true, State: resource.StateActive,
			ReadBack: resource.ReadBackEvidence{Exists: true, ProviderID: providerID, ObservedAt: now, TagDigest: manifestDigest("d")},
			Revision: 1, CreatedAt: now, UpdatedAt: now,
			Tags: map[string]string{
				resource.TagAgentInstanceID: agentID, resource.TagOwnerID: "owner-manifest", resource.TagTaskID: taskID,
				resource.TagDeploymentID: deploymentID, resource.TagResourceID: resourceID,
				resource.TagRetention: string(task.RetentionEphemeralAutoDestroy), resource.TagDestroyDeadline: deadline.Format(time.RFC3339),
			},
		}
	}
	workerApproval, entryApproval := uuid.NewString(), uuid.NewString()
	worker := newResource(resource.TypeEC2, "worker", "i-manifest", workerPlan, workerApproval)
	entry := newResource(resource.TypeALB, "approved-entry", "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/dtx/example", entryPlan, entryApproval, worker.ResourceID)
	return resource.Manifest{
		ManifestID: deploymentID, AgentInstanceID: agentID, OwnerID: "owner-manifest", TaskID: taskID, DeploymentID: deploymentID,
		Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: deadline, AutoDestroyApproved: true,
		ApprovalBindings: []resource.ApprovalBinding{
			{ApprovedPlanHash: workerPlan, ApprovalID: workerApproval},
			{ApprovedPlanHash: entryPlan, ApprovalID: entryApproval},
		},
		Resources: []resource.ResourceV1{worker, entry}, Revision: 1, UpdatedAt: now,
	}
}

func manifestDigest(value string) string { return "sha256:" + strings.Repeat(value, 64) }
