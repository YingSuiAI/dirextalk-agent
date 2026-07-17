package stackobservation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestAssemblerBindsExactStackAndRejectsAttachmentDrift(t *testing.T) {
	request := observationFixture(t)
	reader := &attachmentFake{now: request.ObservedAt}
	assembler, err := New(reader)
	if err != nil {
		t.Fatal(err)
	}
	first, err := assembler.Observe(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest == "" || len(first.Resources) != 4 || len(first.Attachments) != 1 ||
		first.PlanRevision != request.Plan.Revision || first.HealthRevision != request.Health.Revision {
		t.Fatalf("incomplete observation: %#v", first)
	}
	second, err := assembler.Observe(context.Background(), request)
	if err != nil || second.Digest != first.Digest {
		t.Fatalf("canonical replay changed: digest=%q err=%v", second.Digest, err)
	}

	reader.drift = true
	if _, err := assembler.Observe(context.Background(), request); !errors.Is(err, ErrDrift) {
		t.Fatalf("attachment drift error = %v", err)
	}
}

func TestAssemblerRejectsMissingDuplicateAndStaleFacts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Request)
	}{
		{"missing snapshot", func(v *Request) { v.Resources = v.Resources[:3] }},
		{"duplicate provider", func(v *Request) {
			v.Resources[1].ProviderID = v.Resources[2].ProviderID
			v.Resources[1].ReadBack.ProviderID = v.Resources[1].ProviderID
		}},
		{"resource revision drift", func(v *Request) { v.Resources[0].Revision = 0 }},
		{"stale health", func(v *Request) { v.Health.ObservedAt = v.ObservedAt.Add(-6 * time.Minute) }},
		{"approval drift", func(v *Request) { v.Approval.PlanRevision++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := observationFixture(t)
			test.mutate(&request)
			assembler, _ := New(&attachmentFake{now: request.ObservedAt})
			if _, err := assembler.Observe(context.Background(), request); err == nil {
				t.Fatal("invalid observation was accepted")
			}
		})
	}
}

type attachmentFake struct {
	now   time.Time
	drift bool
}

func (fake *attachmentFake) ReadBackVolumeAttachment(_ context.Context, spec awsprovider.VolumeAttachmentSpecV1) (awsprovider.VolumeAttachmentObservationV1, error) {
	if fake.drift {
		spec.DeviceName = "/dev/sdz"
	}
	return awsprovider.VolumeAttachmentObservationV1{
		IntentID: spec.IntentID, Region: spec.Region, InstanceID: spec.InstanceID, VolumeID: spec.VolumeID,
		DeviceName: spec.DeviceName, State: awsprovider.VolumeAttachmentStateAttached, Exists: true, ObservedAt: fake.now,
	}, nil
}

func observationFixture(t *testing.T) Request {
	t.Helper()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	agentID, planID, deploymentID, approvalID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	quoteID, connectionID, recipeID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	digest := "sha256:" + strings.Repeat("a", 64)
	plan := cloudapproval.PlanV1{
		SchemaVersion: cloudapproval.PlanSchemaV1, AgentInstanceID: agentID, OwnerID: "owner-a", PlanID: planID,
		Revision: 3, Status: cloudapproval.PlanApproved, ConnectionID: connectionID,
		Recipe: cloudapproval.RecipeBindingV1{RecipeID: recipeID, Digest: digest, Maturity: recipe.MaturityManaged},
		Quote:  cloudapproval.QuoteBindingV1{QuoteID: quoteID, Digest: digest, ScopeDigest: digest, CandidateID: string(cloudquote.CandidateRecommended), ValidUntil: now.Add(time.Hour)},
		ResourceScope: cloudapproval.ResourceScopeV1{
			Region: "us-east-1", AvailabilityZones: []string{"us-east-1a"}, InstanceType: "m7i.large", InstanceCount: 1,
			Architecture: recipe.ArchitectureAMD64, VCPU: 2, MemoryMiB: 8192, DiskGiB: 20, VolumeType: "gp3",
			VolumeEncrypted: true, PurchaseOption: cloudapproval.PurchaseOnDemand, WorkerImageID: "ami-0123456789abcdef0",
			WorkerImageDigest: digest, VolumeScopes: []cloudapproval.VolumeScopeV1{{
				SlotID: "data", SizeGiB: 10, VolumeType: "gp3", IOPS: 3_000, ThroughputMiBPS: 125,
				Encrypted: true, KMSKeyID: "alias/dtx-agent-test-foundation",
				DeviceName: "/dev/sdf", MountPath: "/srv/data", Persistent: true,
				Disposition: cloudapproval.VolumeRetainWithManagedService,
			}},
		},
		NetworkScope: cloudapproval.NetworkScopeV1{
			VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0",
			SecurityGroupMode: cloudapproval.SecurityGroupExisting, SecurityGroupID: "sg-0123456789abcdef0",
			EntryPoint: cloudapproval.EntryPointNone,
		},
		RetentionScope: cloudapproval.RetentionScopeV1{Class: cloudapproval.RetentionManaged},
	}
	scopeDigest, err := plan.PricingScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	plan.Quote.ScopeDigest = scopeDigest
	planHash, err := plan.Hash()
	if err != nil {
		t.Fatal(err)
	}
	approval := cloudapproval.ApprovalV1{
		ApprovalID: approvalID, AgentInstanceID: agentID, OwnerID: plan.OwnerID, PlanID: planID, PlanRevision: plan.Revision,
		PlanHash: planHash, ConnectionID: connectionID, RecipeDigest: digest, QuoteID: quoteID, QuoteDigest: digest,
		QuoteScopeDigest: scopeDigest, QuoteCandidateID: string(cloudquote.CandidateRecommended),
		QuoteValidUntil: plan.Quote.ValidUntil, ResourceScope: plan.ResourceScope, NetworkScope: plan.NetworkScope,
		SecretScope: plan.SecretScope, IntegrationScope: plan.IntegrationScope, RetentionScope: plan.RetentionScope,
	}
	resourceIDs := []string{uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()}
	providers := []string{"i-0123456789abcdef0", "vol-0123456789abcdef0", "eni-0123456789abcdef0", "snap-0123456789abcdef0"}
	kinds := []resource.Type{resource.TypeEC2, resource.TypeEBS, resource.TypeENI, resource.TypeSnapshot}
	names := []string{"worker", "recipe-volume-data", "worker-network-interface", "managed-backup"}
	resources := make([]resource.ResourceV1, 4)
	for index := range resources {
		resources[index] = resource.ResourceV1{
			ResourceID: resourceIDs[index], AgentInstanceID: agentID, OwnerID: plan.OwnerID, DeploymentID: deploymentID,
			Type: kinds[index], LogicalName: names[index], Region: "us-east-1", ApprovedPlanHash: planHash,
			ApprovalID: approvalID, ProviderID: providers[index], State: resource.StateActive, Retention: task.RetentionManaged,
			ReadBack: resource.ReadBackEvidence{Exists: true, ProviderID: providers[index], ObservedAt: now.Add(-time.Minute), TagDigest: digest},
			Revision: int64(index + 1),
		}
	}
	resources[3].DependsOn = []string{resources[1].ResourceID}
	return Request{
		AgentInstanceID: agentID, OwnerID: plan.OwnerID, DeploymentID: deploymentID, Plan: plan, Approval: approval,
		Resources: resources, Health: cloudstatus.HealthSummary{
			Status: cloudstatus.HealthHealthy, Revision: 5, ObservedAt: now.Add(-time.Minute),
			EvidenceDigest: digest, EvidenceType: cloudstatus.HealthEvidenceIndependent,
		}, ObservedAt: now,
	}
}
