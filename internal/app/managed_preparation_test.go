package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/serviceoperation"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/healthprobe"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
)

func TestManagedPreparationScopeBuilderFailsClosedUntilSnapshotRetentionIsExecutable(t *testing.T) {
	fixture := newManagedPreparationScopeFixture(t)
	builder, err := newManagedPreparationScopeBuilder(fixture.agentID, fixture.facts, fixture.current, fixture.monitor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := builder.BuildManagedPreparationScope(context.Background(), fixture.ownerID, fixture.deploymentID, uuid.NewString(), 12_345); !errors.Is(err, serviceoperation.ErrRevisionConflict) {
		t.Fatalf("bounded V2 snapshot template reached legacy managed-preparation mutation: %v", err)
	}
}

type managedPreparationScopeFixture struct {
	agentID, ownerID, deploymentID string
	facts                          *managedPreparationFactsFake
	current                        *managedPreparationCurrentFake
	monitor                        *managedPreparationMonitorFake
}

func newManagedPreparationScopeFixture(t *testing.T) managedPreparationScopeFixture {
	t.Helper()
	now := time.Date(2026, time.July, 17, 15, 0, 0, 0, time.UTC)
	agentID, ownerID, deploymentID, taskID, connectionID, planID := uuid.NewString(), "owner-managed", uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	currentRecipe := cloudGoalProviderRecipe(now)
	currentRecipe.VolumeSlots = []recipe.VolumeSlotRequirementV1{{SlotID: "knowledge", Purpose: "knowledge", MountPath: "/srv/knowledge", Persistent: true, EncryptionRequired: true}}
	recipeDigest, err := currentRecipe.Digest()
	if err != nil {
		t.Fatal(err)
	}
	quoteID := uuid.NewString()
	plan := cloudapproval.PlanV1{
		SchemaVersion: cloudapproval.PlanSchemaV2, AgentInstanceID: agentID, OwnerID: ownerID, PlanID: planID,
		Revision: 3, Status: cloudapproval.PlanApproved, ConnectionID: connectionID,
		Recipe: cloudapproval.RecipeBindingV1{RecipeID: currentRecipe.RecipeID, Digest: recipeDigest, Maturity: currentRecipe.Maturity},
		Quote:  cloudapproval.QuoteBindingV1{QuoteID: quoteID, CandidateID: string(cloudquote.CandidateRecommended), ValidUntil: now.Add(15 * time.Minute)},
		ResourceScope: cloudapproval.ResourceScopeV1{
			Region: "us-east-1", AvailabilityZones: []string{"us-east-1a"}, InstanceType: "m7i.large", InstanceCount: 1,
			Architecture: recipe.ArchitectureAMD64, VCPU: 2, MemoryMiB: 8192, DiskGiB: 40, VolumeType: "gp3",
			VolumeIOPS: 3000, VolumeThroughputMiBPS: 125, VolumeEncrypted: true, PurchaseOption: cloudapproval.PurchaseOnDemand,
			WorkerImageID: "ami-0123456789abcdef0", WorkerImageDigest: managedPreparationDigest('1'),
			VolumeScopes: []cloudapproval.VolumeScopeV1{{
				SlotID: "knowledge", SizeGiB: 80, VolumeType: "gp3", IOPS: 3000, ThroughputMiBPS: 125,
				Encrypted: true, KMSKeyID: "alias/dtx-agent-test-foundation", DeviceName: "/dev/sdf",
				MountPath: "/srv/knowledge", Persistent: true, Disposition: cloudapproval.VolumeRetainWithManagedService,
			}},
		},
		NetworkScope:   cloudapproval.NetworkScopeV1{VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0", SecurityGroupMode: cloudapproval.SecurityGroupCreateDedicated, EntryPoint: cloudapproval.EntryPointNone},
		RetentionScope: cloudapproval.RetentionScopeV1{Class: cloudapproval.RetentionManaged},
	}
	volumeScopeDigest, err := cloudquote.VolumeScopeDigest(plan.ResourceScope.VolumeScopes[0])
	if err != nil {
		t.Fatal(err)
	}
	plan.ServiceOperations = &cloudapproval.ServiceOperationScopeV1{Snapshots: []cloudapproval.SnapshotOperationSpecV1{{
		OperationKey: "managed-snapshot-knowledge", SourceVolumeSlotID: "knowledge", SourceVolumeSpecDigest: volumeScopeDigest,
		Disposition: cloudapproval.SnapshotRetainWithManagedService, MaxRetentionSeconds: 30 * 24 * 60 * 60,
	}}}
	plan.Quote.ScopeDigest, err = plan.PricingScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	quoted := managedPreparationQuote(t, now, quoteID, plan)
	plan.Quote.Digest, err = quoted.Digest()
	if err != nil || plan.Validate() != nil {
		t.Fatalf("plan fixture invalid: digest=%v plan=%v", err, plan.Validate())
	}
	planHash, _ := plan.Hash()
	volumeSpec := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, Volume: &resource.AWSEBSVolumeSpecV1{
		AvailabilityZone: "us-east-1a", SizeGiB: 80, VolumeType: "gp3", IOPS: 3000, ThroughputMiBPS: 125,
		KMSKeyID: "alias/dtx-agent-test-foundation", SlotID: "knowledge", DeviceName: "/dev/sdf",
		MountPath: "/srv/knowledge", Persistent: true, Disposition: resource.AWSVolumeRetainWithManagedService,
	}}
	volumeDigest, _ := volumeSpec.Digest(resource.TypeEBS)
	ec2 := managedPreparationResource(agentID, ownerID, deploymentID, taskID, planHash, resource.TypeEC2,
		"exclusive-cloud-worker", "i-0123456789abcdef0", managedPreparationDigest('2'), now)
	volume := managedPreparationResource(agentID, ownerID, deploymentID, taskID, planHash, resource.TypeEBS,
		"recipe-volume-knowledge", "vol-0123456789abcdef0", volumeDigest, now)
	executionDigest := sha256.Sum256([]byte("execution"))
	delivery := &installer.DeliveryV1{
		SignedPlan: installer.SignedInstallerPlanV1{Plan: installer.InstallerPlanV1{
			Commands: []installer.CommandV1{{CommandID: currentRecipe.Lifecycle.Restart}},
		}},
		ArtifactManifest: installer.SignedArtifactManifestV1{Manifest: installer.ArtifactManifestV1{
			SchemaVersion: installer.ArtifactManifestSchemaV1, Binding: installer.BindingV1{DeploymentID: deploymentID, RecipeDigest: recipeDigest},
		}},
	}
	deployment := cloudstatus.Deployment{PlanID: planID, ConnectionID: connectionID, Worker: worker.Deployment{
		DeploymentID: deploymentID, OwnerID: ownerID, TaskID: taskID, ProviderInstanceID: ec2.ProviderID,
		State: worker.StateFinished, Outcome: worker.OutcomeSucceeded, Revision: 7,
		ExecutionBundle:   worker.BundleRef{S3Ref: "s3://agent-artifacts/deployments/execution.cbor", SHA256: executionDigest},
		InstallerDelivery: delivery, UpdatedAt: now,
	}}
	probe, err := healthprobe.Bind(healthprobe.SpecV1{SchemaVersion: healthprobe.SchemaV1,
		Binding: healthprobe.BindingV1{DeploymentID: deploymentID, PlanHash: planHash, RecipeDigest: recipeDigest},
		Purpose: healthprobe.PurposeSemantic, Protocol: healthprobe.ProtocolHTTPS, Target: "https://service.example.com/semantic",
		TimeoutMillis: 1000, MaxAttempts: 1, ExpectedStatusCode: 200, ExpectedSummaryDigest: managedPreparationDigest('3')})
	if err != nil {
		t.Fatal(err)
	}
	monitor := resource.ProbeMonitorRecord{DeploymentID: deploymentID, MonitorKind: resource.ProbeMonitorService, OwnerID: ownerID,
		Suite:    healthprobe.SuiteV1{SchemaVersion: healthprobe.SuiteSchemaV1, Probes: []healthprobe.SpecV1{probe}},
		Interval: time.Minute, Status: healthprobe.AggregatePending, NextRunAt: now.Add(time.Minute),
		Revision: 4, CreatedAt: now.Add(-time.Hour), UpdatedAt: now}
	if monitor.Validate() != nil {
		t.Fatal("monitor fixture invalid")
	}
	return managedPreparationScopeFixture{agentID: agentID, ownerID: ownerID, deploymentID: deploymentID,
		facts:   &managedPreparationFactsFake{plan: plan, quote: quoted, draft: planning.RecipeDraft{RecipeID: currentRecipe.RecipeID, Recipe: currentRecipe, Digest: recipeDigest, Revision: 5}},
		current: &managedPreparationCurrentFake{deployment: deployment, connection: cloudstatus.Connection{ConnectionID: connectionID, OwnerID: ownerID, Region: "us-east-1", Status: "active", Revision: 2}, resources: []resource.ResourceV1{ec2, volume}},
		monitor: &managedPreparationMonitorFake{record: monitor}}
}

// managedPreparationScopeForDownstreamTest supplies a validated historical
// scope to unit-test dormant downstream components. Production creation is
// intentionally fail-closed until runtime resource retention can honor the
// V2 Plan's signed snapshot deadline.
func managedPreparationScopeForDownstreamTest(t *testing.T, fixture managedPreparationScopeFixture, operationID string) serviceoperation.ScopeV1 {
	t.Helper()
	plan := fixture.facts.plan
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	planHash, err := plan.Hash()
	if err != nil {
		t.Fatal(err)
	}
	deployment := fixture.current.deployment
	ec2, volumes, ok := exactPreparationResources(fixture.current.resources, fixture.agentID, fixture.ownerID, deployment, plan, planHash)
	if !ok {
		t.Fatal("managed preparation fixture no longer has exact authoritative resource facts")
	}
	monitor := fixture.monitor.record
	monitorDigest, err := canonical.Digest(monitor.Suite)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest, err := canonical.Digest(deployment.Worker.InstallerDelivery.ArtifactManifest.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	scope := serviceoperation.ScopeV1{
		SchemaVersion: serviceoperation.ScopeSchemaV1, Intent: serviceoperation.IntentManagedPreparation,
		PreparationOperationID: operationID, OwnerID: fixture.ownerID, AgentInstanceID: fixture.agentID,
		DeploymentID: fixture.deploymentID, DeploymentRevision: deployment.Worker.Revision,
		ConnectionID: deployment.ConnectionID, ConnectionRevision: fixture.current.connection.Revision,
		PlanID: plan.PlanID, PlanRevision: int64(plan.Revision), PlanHash: planHash,
		RecipeID: fixture.facts.draft.RecipeID, RecipeDigest: fixture.facts.draft.Digest, RecipeRevision: fixture.facts.draft.Revision,
		EC2: ec2, SourceVolumes: make([]serviceoperation.ResourceFactV1, 0, len(volumes)),
		Restart: serviceoperation.RestartReferenceV1{
			OperationID:             uuid.NewSHA1(uuid.MustParse(operationID), []byte("restart")).String(),
			ExpectedInitialRevision: 1, Action: "restart", LifecycleRestartRef: fixture.facts.draft.Recipe.Lifecycle.Restart,
			ExecutionBundleDigest: "sha256:" + hex.EncodeToString(deployment.Worker.ExecutionBundle.SHA256[:]),
		},
		ServiceMonitorRevision: monitor.Revision, ServiceMonitorSuiteDigest: monitorDigest,
		Currency: fixture.facts.quote.Currency, CostAlertAmountMinor: 12_345, ExpectedInstalledManifestDigest: manifestDigest,
	}
	for _, item := range volumes {
		snapshotID, replacementID, err := serviceoperation.DeriveVolumeResourceIDs(operationID, item.fact.ResourceID, item.slot.SlotID)
		if err != nil {
			t.Fatal(err)
		}
		scope.SourceVolumes = append(scope.SourceVolumes, item.fact)
		scope.Volumes = append(scope.Volumes, serviceoperation.VolumePreparationV1{
			SlotID: item.slot.SlotID, SourceVolume: item.fact, SnapshotResourceID: snapshotID,
			ReplacementVolumeResourceID: replacementID, AvailabilityZone: plan.ResourceScope.AvailabilityZones[0],
			SizeGiB: item.slot.SizeGiB, VolumeType: item.slot.VolumeType, IOPS: item.slot.IOPS,
			ThroughputMiBPS: item.slot.ThroughputMiBPS, KMSKeyID: item.slot.KMSKeyID,
			DeviceName: item.slot.DeviceName, MountPath: item.slot.MountPath, ReadOnly: item.slot.ReadOnly,
			Persistent: item.slot.Persistent, Disposition: string(item.slot.Disposition),
		})
	}
	if err := scope.Validate(); err != nil {
		t.Fatal(err)
	}
	return scope
}

func managedPreparationQuote(t *testing.T, now time.Time, quoteID string, plan cloudapproval.PlanV1) cloudquote.QuoteV1 {
	t.Helper()
	value := cloudquote.QuoteV1{SchemaVersion: cloudquote.SchemaV1, QuoteID: quoteID, QuotedAt: now,
		ValidUntil: plan.Quote.ValidUntil, Currency: "USD", Usage: cloudquote.UsageV1{RuntimeHoursPerMonth: 730, SnapshotGiBMonths: 80},
		Assumptions: []string{"one worker"}, Exclusions: []string{"taxes"}}
	for _, profile := range []cloudquote.CandidateProfile{cloudquote.CandidateEconomic, cloudquote.CandidateRecommended, cloudquote.CandidatePerformance} {
		scope := plan.PricingScope()
		scope.Resource.CandidateID = profile
		scopeDigest, err := scope.Digest()
		if err != nil {
			t.Fatal(err)
		}
		var items []cloudquote.CostItemV1
		for _, category := range []cloudquote.CostCategory{cloudquote.CostComputeOnDemand, cloudquote.CostEBS, cloudquote.CostPublicIPv4, cloudquote.CostLogs, cloudquote.CostSnapshot, cloudquote.CostEntry, cloudquote.CostTraffic} {
			items = append(items, cloudquote.CostItemV1{Category: category, Description: string(category), SourceID: string(profile) + "-" + string(category), HourlyEstimateMicros: 1000, MonthlyEstimateMicros: 730_000, MaximumLaunchAmountMicros: 1000})
		}
		value.Candidates = append(value.Candidates, cloudquote.CandidateV1{CandidateID: profile, Scope: scope, ScopeDigest: scopeDigest,
			OfferedAvailabilityZones: []string{"us-east-1a"}, Quotas: []cloudquote.QuotaEvidenceV1{{ServiceCode: "ec2", QuotaCode: "L-1216C47A", LimitUnits: 10, UsedUnits: 1, RequiredUnits: 1}},
			CostItems: items, HourlyEstimateMicros: 7000, MonthlyEstimateMicros: 5_110_000, MaximumLaunchAmountMicros: 7000})
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("quote fixture invalid: %v", err)
	}
	return value
}

func managedPreparationResource(agentID, ownerID, deploymentID, taskID, planHash string, kind resource.Type, logical, providerID, specDigest string, now time.Time) resource.ResourceV1 {
	return resource.ResourceV1{ResourceID: uuid.NewString(), AgentInstanceID: agentID, OwnerID: ownerID, TaskID: taskID,
		DeploymentID: deploymentID, Type: kind, LogicalName: logical, Region: "us-east-1", SpecDigest: specDigest,
		ApprovedPlanHash: planHash, ApprovalID: uuid.NewString(), ProviderID: providerID, State: resource.StateActive,
		ReadBack: resource.ReadBackEvidence{Exists: true, ProviderID: providerID, ObservedAt: now, TagDigest: managedPreparationDigest('4')},
		Revision: 3, CreatedAt: now.Add(-time.Hour), UpdatedAt: now}
}

type managedPreparationFactsFake struct {
	plan  cloudapproval.PlanV1
	quote cloudquote.QuoteV1
	draft planning.RecipeDraft
}

func (fake *managedPreparationFactsFake) LoadPlan(context.Context, string, string) (cloudapproval.PlanV1, error) {
	return fake.plan, nil
}
func (fake *managedPreparationFactsFake) LoadQuote(context.Context, string, string) (cloudquote.QuoteV1, error) {
	return fake.quote, nil
}
func (fake *managedPreparationFactsFake) ResolveRecipeDraft(context.Context, string, string, string) (planning.RecipeDraft, error) {
	return fake.draft, nil
}

type managedPreparationCurrentFake struct {
	deployment cloudstatus.Deployment
	connection cloudstatus.Connection
	resources  []resource.ResourceV1
}

func (fake *managedPreparationCurrentFake) GetDeployment(context.Context, string, string) (cloudstatus.Deployment, error) {
	return fake.deployment, nil
}
func (fake *managedPreparationCurrentFake) GetConnection(context.Context, string, string) (cloudstatus.Connection, error) {
	return fake.connection, nil
}
func (fake *managedPreparationCurrentFake) ListDeploymentResources(context.Context, string, string) ([]resource.ResourceV1, error) {
	return append([]resource.ResourceV1(nil), fake.resources...), nil
}

type managedPreparationMonitorFake struct{ record resource.ProbeMonitorRecord }

func (fake *managedPreparationMonitorFake) GetProbeMonitor(context.Context, string, resource.ProbeMonitorKind) (resource.ProbeMonitorRecord, error) {
	return fake.record, nil
}

func managedPreparationDigest(fill byte) string { return "sha256:" + strings.Repeat(string(fill), 64) }
