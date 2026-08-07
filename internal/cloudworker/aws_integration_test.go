package cloudworker

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
)

func TestProjectAWSResourceGraphBindsEightResourcesAndNeverReplacesProviderIdentity(t *testing.T) {
	plan, execution, awsPlan, intent := awsIntegrationFixture(t)
	active := activeAWSGraph(t, awsPlan, intent, intent.RecordedAt.Add(time.Second))
	resources, err := ProjectAWSResourceGraph(plan, execution, awsPlan, intent, active, nil)
	if err != nil || len(resources) != len(cloudaws.AllResourceKinds()) {
		t.Fatalf("active projection resources=%d err=%v", len(resources), err)
	}
	for _, resource := range resources {
		if resource.Provider != "aws" || resource.ProviderID == "" || resource.State != ResourceCreated || resource.Revision != 1 || resource.VerifiedAt != nil {
			t.Fatalf("invalid active resource: %+v", resource)
		}
	}

	destroyed := active
	destroyed.Resources = slices.Clone(active.Resources)
	destroyed.State = cloudaws.GraphVerifiedDestroyed
	destroyed.ObservedAt = active.ObservedAt.Add(time.Minute)
	destroyed.StackProviderID = active.StackProviderID
	for index := range destroyed.Resources {
		destroyed.Resources[index].Exists = false
		destroyed.Resources[index].ObservedAt = destroyed.ObservedAt
	}
	cleaned, err := ProjectAWSResourceGraph(plan, execution, awsPlan, intent, destroyed, resources)
	if err != nil || len(cleaned) != len(resources) {
		t.Fatalf("destroyed projection resources=%d err=%v", len(cleaned), err)
	}
	for index := range cleaned {
		if cleaned[index].ProviderID != resources[index].ProviderID || cleaned[index].State != ResourceVerifiedDestroyed || cleaned[index].Revision != 2 || cleaned[index].VerifiedAt == nil {
			t.Fatalf("invalid destroyed resource: before=%+v after=%+v", resources[index], cleaned[index])
		}
	}

	drift := active
	drift.Resources = slices.Clone(active.Resources)
	drift.Resources[0].ProviderID += "-replacement"
	if _, err := ProjectAWSResourceGraph(plan, execution, awsPlan, intent, drift, resources); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-name replacement was accepted: %v", err)
	}
}

func TestProjectAWSProvisioningGraphCreatesStableEmptyTombstones(t *testing.T) {
	plan, execution, awsPlan, intent := awsIntegrationFixture(t)
	graph := cloudaws.ObservedGraph{
		Identity: awsPlan.Identity, PlanDigest: awsPlan.Digest, InfrastructureDigest: awsPlan.InfrastructureDigest,
		IntentDigest: intent.IntentDigest, State: cloudaws.GraphProvisioning, Resources: []cloudaws.ResourceObservation{},
		ObservedAt: intent.RecordedAt.Add(time.Second),
	}
	resources, err := ProjectAWSResourceGraph(plan, execution, awsPlan, intent, graph, nil)
	if err != nil || len(resources) != len(cloudaws.AllResourceKinds()) {
		t.Fatalf("provisioning projection resources=%d err=%v", len(resources), err)
	}
	for _, resource := range resources {
		if resource.State != ResourcePlanned || resource.ProviderID != "" || resource.Revision != 1 {
			t.Fatalf("planned tombstone is not unbound: %+v", resource)
		}
	}
}

func TestProjectAWSCleanupProjectionPublishesVerifiedDestroyedAtomically(t *testing.T) {
	plan, execution, awsPlan, intent := awsIntegrationFixture(t)
	active := activeAWSGraph(t, awsPlan, intent, intent.RecordedAt.Add(time.Second))
	resources, err := ProjectAWSResourceGraph(plan, execution, awsPlan, intent, active, nil)
	if err != nil {
		t.Fatal(err)
	}

	destroying := active
	destroying.State = cloudaws.GraphDestroying
	destroying.ObservedAt = active.ObservedAt.Add(time.Minute)
	destroying.Resources = slices.Clone(active.Resources)
	for index := range destroying.Resources {
		destroying.Resources[index].ObservedAt = destroying.ObservedAt
		if index%2 == 0 {
			destroying.Resources[index].Exists = false
		}
	}
	partial, err := ProjectAWSResourceGraph(plan, execution, awsPlan, intent, destroying, resources)
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range partial {
		if resource.State != ResourceDeleteRequested || resource.VerifiedAt != nil {
			t.Fatalf("partial cleanup leaked per-resource terminal evidence: %+v", resource)
		}
	}

	destroyed := destroying
	destroyed.State = cloudaws.GraphVerifiedDestroyed
	destroyed.ObservedAt = destroying.ObservedAt.Add(time.Minute)
	destroyed.Resources = slices.Clone(destroying.Resources)
	for index := range destroyed.Resources {
		destroyed.Resources[index].Exists = false
		destroyed.Resources[index].ObservedAt = destroyed.ObservedAt
	}
	complete, err := ProjectAWSResourceGraph(plan, execution, awsPlan, intent, destroyed, partial)
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range complete {
		if resource.State != ResourceVerifiedDestroyed || resource.VerifiedAt == nil {
			t.Fatalf("complete cleanup did not publish terminal evidence: %+v", resource)
		}
	}
}

func TestBuildWorkerIdentityExpectationRequiresActiveQualifiedGraph(t *testing.T) {
	_, _, awsPlan, intent := awsIntegrationFixture(t)
	active := activeAWSGraph(t, awsPlan, intent, intent.RecordedAt.Add(time.Second))
	expectation, err := BuildWorkerIdentityExpectation(awsPlan, intent, active)
	if err != nil || expectation.InstanceID == "" || expectation.InstanceID != providerIDForGraph(cloudaws.ResourceEC2) ||
		expectation.LaunchIdentity != awsPlan.Identity.LaunchIdentity || expectation.RoleARN != "arn:aws:iam::123456789012:role/"+awsPlan.IAMRoleName ||
		expectation.RoleID != providerIDForGraph(cloudaws.ResourceIAMRole) ||
		expectation.InstanceProfileID != providerIDForGraph(cloudaws.ResourceInstanceProfile) ||
		expectation.RequiredTags[cloudaws.TagIntentDigest] != intent.IntentDigest {
		t.Fatalf("expectation=%+v err=%v", expectation, err)
	}
	partial := active
	partial.State = cloudaws.GraphProvisioning
	if _, err := BuildWorkerIdentityExpectation(awsPlan, intent, partial); !errors.Is(err, ErrInvalid) {
		t.Fatalf("partial graph issued identity expectation: %v", err)
	}
}

func TestCleanupCoordinatorAdvancesAWSAndStagingAndRequiresBothProofs(t *testing.T) {
	plan, _, awsPlan, intent := awsIntegrationFixture(t)
	active := activeAWSGraph(t, awsPlan, intent, intent.RecordedAt.Add(time.Second))
	destroyed := active
	destroyed.Resources = slices.Clone(active.Resources)
	destroyed.State, destroyed.ObservedAt = cloudaws.GraphVerifiedDestroyed, active.ObservedAt.Add(time.Minute)
	for index := range destroyed.Resources {
		destroyed.Resources[index].Exists = false
		destroyed.Resources[index].ObservedAt = destroyed.ObservedAt
	}

	lifecycle := &cleanupLifecycleFake{observed: active, destroyed: destroyed}
	staging := &cleanupStagingFake{}
	coordinator, err := NewCleanupCoordinator(lifecycle, staging)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := coordinator.Reconcile(context.Background(), plan, awsPlan, intent)
	if err != nil || !evidence.Verified() || lifecycle.observeCalls != 1 || lifecycle.destroyCalls != 1 || staging.calls != 1 {
		t.Fatalf("cleanup evidence=%+v observe=%d destroy=%d staging=%d err=%v", evidence, lifecycle.observeCalls, lifecycle.destroyCalls, staging.calls, err)
	}

	lifecycle = &cleanupLifecycleFake{observeErr: cloudaws.ErrCloudReadback}
	staging = &cleanupStagingFake{}
	coordinator, _ = NewCleanupCoordinator(lifecycle, staging)
	evidence, err = coordinator.Reconcile(context.Background(), plan, awsPlan, intent)
	if !errors.Is(err, ErrCleanupPending) || evidence.InputsVerifiedDestroyed != true || evidence.AWSVerifiedDestroyed || staging.calls != 1 {
		t.Fatalf("AWS failure suppressed independent staging cleanup: evidence=%+v calls=%d err=%v", evidence, staging.calls, err)
	}

	lifecycle = &cleanupLifecycleFake{observed: destroyed}
	staging = &cleanupStagingFake{err: ErrStagingPending}
	coordinator, _ = NewCleanupCoordinator(lifecycle, staging)
	evidence, err = coordinator.Reconcile(context.Background(), plan, awsPlan, intent)
	if !errors.Is(err, ErrCleanupPending) || !evidence.AWSVerifiedDestroyed || evidence.InputsVerifiedDestroyed || lifecycle.destroyCalls != 0 {
		t.Fatalf("staging uncertainty incorrectly closed cleanup: evidence=%+v err=%v", evidence, err)
	}
}

type cleanupLifecycleFake struct {
	observed, destroyed        cloudaws.ObservedGraph
	observeErr, destroyErr     error
	observeCalls, destroyCalls int
}

func (fake *cleanupLifecycleFake) Observe(context.Context, cloudaws.ExecutionIdentity) (cloudaws.ObservedGraph, error) {
	fake.observeCalls++
	return fake.observed, fake.observeErr
}

func (fake *cleanupLifecycleFake) Destroy(context.Context, cloudaws.ExecutionIdentity, cloudaws.ObservedGraph) (cloudaws.ObservedGraph, error) {
	fake.destroyCalls++
	return fake.destroyed, fake.destroyErr
}

type cleanupStagingFake struct {
	calls int
	err   error
}

func (fake *cleanupStagingFake) Cleanup(context.Context, Plan) error {
	fake.calls++
	return fake.err
}

func awsIntegrationFixture(t *testing.T) (Plan, Execution, cloudaws.Plan, cloudaws.DispatchIntent) {
	t.Helper()
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, execution, prerequisite, _ := stagingFixture(t, now)
	var err error
	execution, err = execution.Transition(StateQueued, now)
	if err != nil {
		t.Fatalf("queue execution: %v", err)
	}
	execution, err = execution.Transition(StateProvisioning, now)
	if err != nil {
		t.Fatalf("provision execution: %v", err)
	}
	source := plan.InputManifest.Items[0]
	staged := StagedInputManifest{Schema: StagedInputManifestSchemaV1, ExecutionID: plan.ExecutionID, SourceManifestDigest: plan.InputManifestDigest,
		Items: []StagedInputManifestItem{{InputID: source.InputID, MountPath: source.MountPath, MediaType: source.MediaType,
			SizeBytes: source.SizeBytes, SHA256: source.SHA256, S3Bucket: plan.ArtifactGrant.Bucket,
			S3Key: plan.ArtifactGrant.KeyPrefix + "inputs/" + source.InputID, S3VersionID: "version-1"}}}
	if _, err = staged.Seal(plan.InputManifest); err != nil {
		t.Fatalf("seal staged manifest: %v", err)
	}
	if _, _, err = sanitizedRuntimeInputManifest(plan.InputManifest, staged); err != nil {
		t.Fatalf("sanitize runtime manifest: %v", err)
	}
	prerequisite.ConfirmedAt = now
	fence, err := prerequisite.RuntimeFence(plan)
	if err != nil {
		t.Fatalf("build runtime fence: %v", err)
	}
	material, err := BuildRuntimeTask(plan, execution, staged, fence, RuntimeQualification{
		PiRuntimeDigest: plan.Compute.PiRuntimeDigest, PiVersion: "0.83.0",
		PiExecutableSHA256: digestValue("pi-executable"), ResultExtensionSHA256: digestValue("result-extension"),
	})
	if err != nil {
		t.Fatalf("build runtime task: %v", err)
	}
	t.Cleanup(material.Destroy)
	authorization := LaunchAuthorization{LaunchPrerequisite: prerequisite, RuntimeTaskSHA256: material.RuntimeTaskSHA256,
		InputManifestSHA256: material.InputManifestSHA256, StagedManifestSHA256: material.StagedManifestSHA256,
		AuthorizedAt: now.Add(time.Second)}
	awsPlan, intent, err := BuildAWSDispatch(plan, execution, authorization, staged, material, plan.Quote, now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("build AWS dispatch: %v", err)
	}
	return plan, execution, awsPlan, intent
}

func activeAWSGraph(t *testing.T, plan cloudaws.Plan, intent cloudaws.DispatchIntent, observedAt time.Time) cloudaws.ObservedGraph {
	t.Helper()
	policy, err := plan.Network.SecurityGroupPolicy()
	if err != nil {
		t.Fatal(err)
	}
	tags := cloudaws.RequiredTags(plan.Identity, plan.Digest, plan.InfrastructureDigest, intent.IntentDigest)
	resources := make([]cloudaws.ResourceObservation, 0, len(cloudaws.AllResourceKinds()))
	for _, kind := range cloudaws.AllResourceKinds() {
		providerID := providerIDForGraph(kind)
		resources = append(resources, cloudaws.ResourceObservation{Kind: kind, LogicalID: cloudaws.LogicalID(kind), ProviderID: providerID,
			Exists: true, Tags: tags, LaunchIdentity: plan.Identity.LaunchIdentity, Generation: plan.Identity.Generation, ObservedAt: observedAt})
	}
	graph := cloudaws.ObservedGraph{Identity: plan.Identity, PlanDigest: plan.Digest, InfrastructureDigest: plan.InfrastructureDigest,
		IntentDigest: intent.IntentDigest, StackProviderID: providerIDForGraph(cloudaws.ResourceStack), State: cloudaws.GraphActive,
		Resources: resources, Topology: cloudaws.TopologyProof{EC2InstanceCount: 1,
			Ingress: []cloudaws.NetworkRule{}, Egress: policy.Egress, SSMEnabled: false,
			FQDNEnforcement: policy.FQDNEnforcement, FQDNPolicyDigest: policy.FQDNPolicyDigest}, ObservedAt: observedAt}
	if err := graph.Validate(plan, intent); err != nil {
		t.Fatal(err)
	}
	return graph
}

func providerIDForGraph(kind cloudaws.ResourceKind) string {
	switch kind {
	case cloudaws.ResourceEC2:
		return "i-0123456789abcdef0"
	case cloudaws.ResourceIAMRole:
		return "AROA1234567890ABCDEFG"
	case cloudaws.ResourceInstanceProfile:
		return "AIPA1234567890ABCDEFG"
	}
	return "provider-" + string(kind)
}
