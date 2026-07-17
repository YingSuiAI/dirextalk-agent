package resource

import (
	"context"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

type entryOrderProvider struct {
	Provider
	resources map[string]ProviderObservation
	deletes   []string
}

func (provider *entryOrderProvider) ReadBack(_ context.Context, kind Type, providerID, _ string) (ProviderObservation, error) {
	observation, ok := provider.resources[providerID]
	if !ok {
		return ProviderObservation{ProviderID: providerID, Type: kind, Exists: false}, nil
	}
	return observation, nil
}

func (provider *entryOrderProvider) Delete(_ context.Context, _ Type, providerID, _ string, _ map[string]string) error {
	provider.deletes = append(provider.deletes, providerID)
	observation := provider.resources[providerID]
	observation.Exists = false
	provider.resources[providerID] = observation
	return nil
}

func TestReaperUsesManifestDependenciesForPublicEntryGraph(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	agentID, taskID, deploymentID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	workerApprovalID, entryApprovalID := uuid.NewString(), uuid.NewString()
	deadline := now.Add(-time.Minute)
	workerPlanHash, entryPlanHash := "sha256:"+repeatHex('a'), "sha256:"+repeatHex('b')
	newResource := func(kind Type, providerID, planHash, approvalID string, dependencies ...string) ResourceV1 {
		resourceID := uuid.NewString()
		return ResourceV1{
			ResourceID: resourceID, AgentInstanceID: agentID, OwnerID: "owner-1", TaskID: taskID, DeploymentID: deploymentID,
			Type: kind, LogicalName: "ephemeral-entry", Region: "us-west-2", SpecDigest: "sha256:" + repeatHex('c'), ApprovedPlanHash: planHash, ApprovalID: approvalID,
			ProviderID: providerID, DependsOn: dependencies, Retention: task.RetentionEphemeralAutoDestroy,
			DestroyDeadline: deadline, AutoDestroyApproved: true, State: StateActive, Revision: 1, CreatedAt: now, UpdatedAt: now,
			Tags: map[string]string{
				TagAgentInstanceID: agentID, TagOwnerID: "owner-1", TagTaskID: taskID, TagDeploymentID: deploymentID,
				TagResourceID: resourceID, TagRetention: string(task.RetentionEphemeralAutoDestroy), TagDestroyDeadline: deadline.Format(time.RFC3339),
				TagApprovedPlanHash: planHash, TagApprovalID: approvalID,
			},
		}
	}

	worker := newResource(TypeEC2, "worker", workerPlanHash, workerApprovalID)
	workerSecurityGroup := newResource(TypeSG, "worker-security-group", workerPlanHash, workerApprovalID)
	albSecurityGroup := newResource(TypeSG, "alb-security-group", entryPlanHash, entryApprovalID)
	alb := newResource(TypeALB, "application-load-balancer", entryPlanHash, entryApprovalID, albSecurityGroup.ResourceID)
	targetGroup := newResource(TypeTargetGroup, "target-group", entryPlanHash, entryApprovalID, worker.ResourceID)
	listener := newResource(TypeListener, "https-listener", entryPlanHash, entryApprovalID, alb.ResourceID, targetGroup.ResourceID)
	rule := newResource(TypeSecurityGroupRule, "worker-ingress-rule", entryPlanHash, entryApprovalID, albSecurityGroup.ResourceID, workerSecurityGroup.ResourceID)
	resources := []ResourceV1{worker, albSecurityGroup, workerSecurityGroup, alb, targetGroup, listener, rule}

	provider := &entryOrderProvider{resources: make(map[string]ProviderObservation, len(resources))}
	for _, item := range resources {
		provider.resources[item.ProviderID] = ProviderObservation{ProviderID: item.ProviderID, Type: item.Type, Exists: true, Tags: item.Tags, ObservedAt: now}
	}
	mirror := newFakeMirror()
	manifest := Manifest{
		ManifestID: deploymentID, AgentInstanceID: agentID, OwnerID: "owner-1", TaskID: taskID, DeploymentID: deploymentID,
		Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: deadline, AutoDestroyApproved: true,
		ApprovalBindings: []ApprovalBinding{
			{ApprovedPlanHash: workerPlanHash, ApprovalID: workerApprovalID},
			{ApprovedPlanHash: entryPlanHash, ApprovalID: entryApprovalID},
		},
		Resources: resources, Revision: 1, UpdatedAt: now,
	}
	mirror.manifests[manifest.ManifestID] = manifest
	reaper, err := NewReaper(provider, mirror)
	if err != nil {
		t.Fatal(err)
	}
	reaper.now = func() time.Time { return now }
	report, err := reaper.Sweep(context.Background())
	if err != nil || report.VerifiedDestroyed != len(resources) || report.Blocked != 0 {
		t.Fatalf("Sweep report=%+v error=%v", report, err)
	}

	position := make(map[string]int, len(provider.deletes))
	for index, providerID := range provider.deletes {
		position[providerID] = index
	}
	assertDeletesBefore := func(dependent, dependency ResourceV1) {
		t.Helper()
		if position[dependent.ProviderID] >= position[dependency.ProviderID] {
			t.Fatalf("dependency order = %v; %s must precede %s", provider.deletes, dependent.ProviderID, dependency.ProviderID)
		}
	}
	assertDeletesBefore(listener, targetGroup)
	assertDeletesBefore(listener, alb)
	assertDeletesBefore(targetGroup, worker)
	assertDeletesBefore(alb, albSecurityGroup)
	assertDeletesBefore(rule, albSecurityGroup)
	assertDeletesBefore(rule, workerSecurityGroup)
}
