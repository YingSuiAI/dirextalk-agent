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

func TestReaperExpiresOnlyBoundedManagedPreparationSnapshot(t *testing.T) {
	now := time.Date(2026, 7, 18, 9, 0, 0, 0, time.UTC)
	agentID, taskID, deploymentID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	planHash, workerApprovalID, preparationID := "sha256:"+repeatHex('a'), uuid.NewString(), uuid.NewString()
	scopeDigest := "sha256:" + repeatHex('b')
	managed := func(kind Type, resourceID, providerID string, dependencies ...string) ResourceV1 {
		return ResourceV1{
			ResourceID: resourceID, AgentInstanceID: agentID, OwnerID: "owner-managed-snapshot", TaskID: taskID,
			DeploymentID: deploymentID, Type: kind, LogicalName: string(kind), Region: "us-west-2",
			SpecDigest: "sha256:" + repeatHex('c'), ApprovedPlanHash: planHash, ApprovalID: workerApprovalID,
			ProviderID: providerID, DependsOn: dependencies, Retention: task.RetentionManaged, State: StateActive,
			ReadBack: ReadBackEvidence{Exists: true, ProviderID: providerID, ObservedAt: now, TagDigest: "sha256:" + repeatHex('d')},
			Revision: 1, CreatedAt: now, UpdatedAt: now,
			Tags: map[string]string{
				TagAgentInstanceID: agentID, TagOwnerID: "owner-managed-snapshot", TagTaskID: taskID,
				TagDeploymentID: deploymentID, TagResourceID: resourceID, TagRetention: string(task.RetentionManaged),
				TagDestroyDeadline: "managed", TagApprovedPlanHash: planHash, TagApprovalID: workerApprovalID,
			},
		}
	}
	source := managed(TypeEBS, uuid.NewString(), "vol-source")
	snapshotDeadline := now.Add(-time.Minute)
	snapshot := ResourceV1{
		ResourceID: "00000000-0000-4000-8000-000000000010", AgentInstanceID: agentID, OwnerID: "owner-managed-snapshot", TaskID: taskID,
		DeploymentID: deploymentID, Type: TypeSnapshot, LogicalName: "managed-backup-data", Region: "us-west-2",
		SpecDigest: "sha256:" + repeatHex('e'), ApprovedPlanHash: planHash, ApprovalID: preparationID,
		IntentOrigin: IntentOriginManagedPreparation, OriginScopeDigest: scopeDigest, ProviderID: "snap-retained",
		DependsOn: []string{source.ResourceID}, Retention: task.RetentionEphemeralAutoDestroy,
		DestroyDeadline: snapshotDeadline, AutoDestroyApproved: true, State: StateActive,
		ReadBack: ReadBackEvidence{Exists: true, ProviderID: "snap-retained", ObservedAt: now, TagDigest: "sha256:" + repeatHex('f')},
		Revision: 1, CreatedAt: now, UpdatedAt: now,
		Tags: map[string]string{
			TagAgentInstanceID: agentID, TagOwnerID: "owner-managed-snapshot", TagTaskID: taskID,
			TagDeploymentID: deploymentID, TagResourceID: "", TagRetention: string(task.RetentionEphemeralAutoDestroy),
			TagDestroyDeadline: snapshotDeadline.Format(time.RFC3339), TagApprovedPlanHash: planHash, TagApprovalID: preparationID,
			TagIntentOrigin: string(IntentOriginManagedPreparation), TagOriginScopeDigest: scopeDigest,
		},
	}
	snapshot.Tags[TagResourceID] = snapshot.ResourceID
	replacement := managed(TypeEBS, uuid.NewString(), "vol-replacement", snapshot.ResourceID)
	replacement.IntentOrigin, replacement.OriginScopeDigest, replacement.ApprovalID = IntentOriginManagedPreparation, scopeDigest, preparationID
	replacement.Tags[TagIntentOrigin], replacement.Tags[TagOriginScopeDigest], replacement.Tags[TagApprovalID] = string(IntentOriginManagedPreparation), scopeDigest, preparationID
	sourceSecond := managed(TypeEBS, uuid.NewString(), "vol-source-second")
	sourceSecond.State, sourceSecond.ReadBack.Exists = StateVerifiedDestroyed, false
	preparationSecondID := uuid.NewString()
	scopeSecondDigest := "sha256:" + repeatHex('d')
	snapshotSecond := snapshot.clone()
	snapshotSecond.ResourceID, snapshotSecond.ProviderID = "00000000-0000-4000-8000-000000000020", "snap-retained-second"
	snapshotSecond.ApprovalID, snapshotSecond.OriginScopeDigest = preparationSecondID, scopeSecondDigest
	snapshotSecond.DependsOn = []string{sourceSecond.ResourceID}
	snapshotSecond.ReadBack.ProviderID, snapshotSecond.ReadBack.Exists = snapshotSecond.ProviderID, true
	snapshotSecond.Tags[TagResourceID], snapshotSecond.Tags[TagApprovalID] = snapshotSecond.ResourceID, preparationSecondID
	snapshotSecond.Tags[TagOriginScopeDigest] = scopeSecondDigest
	replacementSecond := managed(TypeEBS, uuid.NewString(), "vol-replacement-second", snapshotSecond.ResourceID)
	replacementSecond.IntentOrigin, replacementSecond.OriginScopeDigest, replacementSecond.ApprovalID = IntentOriginManagedPreparation, scopeSecondDigest, preparationSecondID
	replacementSecond.Tags[TagIntentOrigin], replacementSecond.Tags[TagOriginScopeDigest], replacementSecond.Tags[TagApprovalID] = string(IntentOriginManagedPreparation), scopeSecondDigest, preparationSecondID

	manifest, err := manifestFrom([]ResourceV1{source, snapshot, replacement, sourceSecond, snapshotSecond, replacementSecond}, false, now)
	if err != nil || !manifest.Managed || !HasExpiredManagedPreparationSnapshot(manifest, now) {
		t.Fatalf("bounded managed manifest=%+v error=%v", manifest, err)
	}
	manifest.Revision = 1
	provider := &entryOrderProvider{resources: map[string]ProviderObservation{
		source.ProviderID:            {ProviderID: source.ProviderID, Type: source.Type, Exists: true, Tags: source.Tags, ObservedAt: now},
		snapshot.ProviderID:          {ProviderID: snapshot.ProviderID, Type: snapshot.Type, Exists: true, Tags: snapshot.Tags, ObservedAt: now},
		replacement.ProviderID:       {ProviderID: replacement.ProviderID, Type: replacement.Type, Exists: true, Tags: replacement.Tags, ObservedAt: now},
		sourceSecond.ProviderID:      {ProviderID: sourceSecond.ProviderID, Type: sourceSecond.Type, Exists: false, Tags: sourceSecond.Tags, ObservedAt: now},
		snapshotSecond.ProviderID:    {ProviderID: snapshotSecond.ProviderID, Type: snapshotSecond.Type, Exists: true, Tags: snapshotSecond.Tags, ObservedAt: now},
		replacementSecond.ProviderID: {ProviderID: replacementSecond.ProviderID, Type: replacementSecond.Type, Exists: true, Tags: replacementSecond.Tags, ObservedAt: now},
	}}
	mirror := newFakeMirror()
	mirror.manifests[manifest.ManifestID] = manifest
	reaper, err := NewReaper(provider, mirror)
	if err != nil {
		t.Fatal(err)
	}
	reaper.now = func() time.Time { return now }
	report, err := reaper.Sweep(context.Background())
	if err != nil || report.VerifiedDestroyed != 0 || report.Blocked != 1 || len(provider.deletes) != 0 {
		t.Fatalf("unsafe bounded snapshot was not blocked: report=%+v deletes=%v error=%v", report, provider.deletes, err)
	}
	report, err = reaper.Sweep(context.Background())
	if err != nil || report.VerifiedDestroyed != 1 || report.Blocked != 0 || len(provider.deletes) != 1 || provider.deletes[0] != snapshotSecond.ProviderID {
		t.Fatalf("blocked snapshot prevented another ready snapshot from expiring: report=%+v deletes=%v error=%v", report, provider.deletes, err)
	}
	blocked := mirror.manifests[manifest.ManifestID]
	for index := range blocked.Resources {
		item := &blocked.Resources[index]
		if item.ResourceID == source.ResourceID {
			item.State = StateVerifiedDestroyed
			item.ReadBack.Exists = false
			item.Revision++
			item.UpdatedAt = now
		}
	}
	mirror.manifests[manifest.ManifestID] = blocked
	sourceObservation := provider.resources[source.ProviderID]
	sourceObservation.Exists = false
	provider.resources[source.ProviderID] = sourceObservation

	report, err = reaper.Sweep(context.Background())
	if err != nil || report.VerifiedDestroyed != 1 || report.Blocked != 0 || len(provider.deletes) != 2 || provider.deletes[1] != snapshot.ProviderID {
		t.Fatalf("bounded snapshot Sweep report=%+v deletes=%v error=%v", report, provider.deletes, err)
	}
	if provider.resources[source.ProviderID].Exists || !provider.resources[replacement.ProviderID].Exists || provider.resources[snapshot.ProviderID].Exists ||
		provider.resources[sourceSecond.ProviderID].Exists || !provider.resources[replacementSecond.ProviderID].Exists || provider.resources[snapshotSecond.ProviderID].Exists {
		t.Fatalf("managed graph changed beyond snapshot: %+v", provider.resources)
	}
	updated := mirror.manifests[manifest.ManifestID]
	if HasExpiredManagedPreparationSnapshot(updated, now) {
		t.Fatalf("verified snapshots remained eligible for reaping: %+v", updated)
	}
	for _, item := range updated.Resources {
		if (item.ResourceID == snapshot.ResourceID || item.ResourceID == snapshotSecond.ResourceID) && item.State != StateVerifiedDestroyed {
			t.Fatalf("snapshot was not independently verified destroyed: %+v", item)
		}
		if (item.ResourceID == source.ResourceID || item.ResourceID == sourceSecond.ResourceID) && item.State != StateVerifiedDestroyed {
			t.Fatalf("source was not already retired: %+v", item)
		}
		if (item.ResourceID == replacement.ResourceID || item.ResourceID == replacementSecond.ResourceID) && item.State != StateActive {
			t.Fatalf("managed resource was mutated: %+v", item)
		}
	}
}
