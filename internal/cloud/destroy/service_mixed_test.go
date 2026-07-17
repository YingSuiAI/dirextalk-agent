package destroy

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
)

func TestPrepareBuildsManualChallengeForVerifiedMixedApprovalGraph(t *testing.T) {
	fixture := newMixedDestroyFixture(t)
	challenge, err := fixture.service(t).Prepare(context.Background(), fixture.command())
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(challenge.Scope.Resources) != 2 {
		t.Fatalf("challenge resources=%d, want Worker plus entry resource", len(challenge.Scope.Resources))
	}
	for _, item := range challenge.Scope.Resources {
		if item.ApprovedPlanHash != fixture.resources[item.ResourceID].ApprovedPlanHash || item.OriginalApprovalID != fixture.resources[item.ResourceID].ApprovalID {
			t.Fatalf("challenge resource %s lost source approval binding", item.ResourceID)
		}
	}
	if len(fixture.verifier.proofs) != 2 {
		t.Fatalf("verifier calls=%d, want every resource checked", len(fixture.verifier.proofs))
	}

	for _, test := range []struct {
		name   string
		mutate func(*mixedDestroyFixture)
	}{
		{"entry hash", func(value *mixedDestroyFixture) {
			value.entry.ApprovedPlanHash = mixedDigest("8")
			value.reader.resources[1] = value.entry
		}},
		{"entry approval", func(value *mixedDestroyFixture) {
			value.entry.ApprovalID = uuid.NewString()
			value.reader.resources[1] = value.entry
		}},
		{"entry owner", func(value *mixedDestroyFixture) {
			value.entry.OwnerID = "other-owner"
			value.reader.resources[1] = value.entry
		}},
		{"connection", func(value *mixedDestroyFixture) { value.reader.deployment.ConnectionID = uuid.NewString() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			forged := newMixedDestroyFixture(t)
			test.mutate(forged)
			if _, err := forged.service(t).Prepare(context.Background(), forged.command()); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Prepare() forged %s error=%v, want ErrInvalid", test.name, err)
			}
		})
	}
}

func TestNewServiceRequiresResourceApprovalVerifier(t *testing.T) {
	fixture := newMixedDestroyFixture(t)
	if _, err := NewService(fixture.agentID, fixture.repository, mixedDeviceRepository{device: fixture.device}, fixture.reader,
		mixedPlanReader{plan: fixture.plan}, nil, mixedNotifier{}, func() time.Time { return fixture.now }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("NewService() error = %v, want ErrInvalid", err)
	}
}

type mixedDestroyFixture struct {
	now        time.Time
	agentID    string
	ownerID    string
	plan       cloudapproval.PlanV1
	deployment cloudstatus.Deployment
	resources  map[string]resource.ResourceV1
	entry      resource.ResourceV1
	reader     *mixedStatusReader
	verifier   *mixedResourceVerifier
	device     cloudapproval.DeviceKeyV1
	repository *mixedDestroyRepository
}

func newMixedDestroyFixture(t *testing.T) *mixedDestroyFixture {
	t.Helper()
	now := time.Date(2026, 7, 17, 11, 0, 0, 0, time.UTC)
	agentID, ownerID, planID, connectionID := uuid.NewString(), "mixed-owner", uuid.NewString(), uuid.NewString()
	deploymentID, taskID := uuid.NewString(), uuid.NewString()
	plan := mixedApprovedPlan(t, now, agentID, ownerID, planID, connectionID)
	planHash, err := plan.Hash()
	if err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(time.Hour)
	workerResource := resource.ResourceV1{
		ResourceID: uuid.NewString(), AgentInstanceID: agentID, OwnerID: ownerID, TaskID: taskID, DeploymentID: deploymentID,
		Type: resource.TypeEC2, LogicalName: "exclusive-worker", Region: "us-east-1", SpecDigest: mixedDigest("1"),
		ApprovedPlanHash: planHash, ApprovalID: uuid.NewString(), ProviderID: "i-0123456789abcdef0",
		Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: deadline, AutoDestroyApproved: true, State: resource.StateActive,
		ReadBack: resource.ReadBackEvidence{Exists: true, ProviderID: "i-0123456789abcdef0", ObservedAt: now.Add(time.Second), TagDigest: mixedDigest("2")}, Revision: 1,
	}
	entry := resource.ResourceV1{
		ResourceID: uuid.NewString(), AgentInstanceID: agentID, OwnerID: ownerID, TaskID: taskID, DeploymentID: deploymentID,
		Type: resource.TypeALB, LogicalName: "approved-entry", Region: "us-east-1", SpecDigest: mixedDigest("3"),
		ApprovedPlanHash: mixedDigest("4"), ApprovalID: uuid.NewString(), ProviderID: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/dtx/0123456789abcdef",
		Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: deadline, AutoDestroyApproved: true, State: resource.StateActive,
		ReadBack: resource.ReadBackEvidence{Exists: true, ProviderID: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/dtx/0123456789abcdef", ObservedAt: now.Add(time.Second), TagDigest: mixedDigest("5")}, Revision: 1,
	}
	deployment := cloudstatus.Deployment{Worker: worker.Deployment{DeploymentID: deploymentID, OwnerID: ownerID, TaskID: taskID, Revision: 1}, PlanID: planID, ConnectionID: connectionID}
	resources := map[string]resource.ResourceV1{workerResource.ResourceID: workerResource, entry.ResourceID: entry}
	reader := &mixedStatusReader{deployment: deployment, resources: []resource.ResourceV1{workerResource, entry}}
	verifier := &mixedResourceVerifier{expected: map[string]ResourceApprovalProofV1{
		workerResource.ResourceID: mixedProof(agentID, ownerID, taskID, deploymentID, connectionID, planID, planHash, workerResource),
		entry.ResourceID:          mixedProof(agentID, ownerID, taskID, deploymentID, connectionID, planID, planHash, entry),
	}}
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("m", ed25519.SeedSize)))
	device := cloudapproval.DeviceKeyV1{KeyID: "mixed-destroy-device", AgentInstanceID: agentID, OwnerID: ownerID, Revision: 1,
		Status: cloudapproval.DeviceKeyActive, PublicKey: private.Public().(ed25519.PublicKey), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	return &mixedDestroyFixture{now: now, agentID: agentID, ownerID: ownerID, plan: plan, deployment: deployment, resources: resources,
		entry: entry, reader: reader, verifier: verifier, device: device, repository: &mixedDestroyRepository{}}
}

func (fixture *mixedDestroyFixture) command() PrepareCommand {
	return PrepareCommand{Caller: MutationScope{ClientID: "mixed-destroy-caller", CredentialID: uuid.NewString()}, IdempotencyKey: uuid.NewString(),
		OwnerID: fixture.ownerID, DeploymentID: fixture.deployment.Worker.DeploymentID, ExpectedRevision: 3, SignerKeyID: fixture.device.KeyID}
}

func (fixture *mixedDestroyFixture) service(t *testing.T) *Service {
	t.Helper()
	service, err := NewService(fixture.agentID, fixture.repository, mixedDeviceRepository{device: fixture.device}, fixture.reader,
		mixedPlanReader{plan: fixture.plan}, fixture.verifier, mixedNotifier{}, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func mixedProof(agentID, ownerID, taskID, deploymentID, connectionID, planID, planHash string, item resource.ResourceV1) ResourceApprovalProofV1 {
	return ResourceApprovalProofV1{AgentInstanceID: agentID, OwnerID: ownerID, TaskID: taskID, DeploymentID: deploymentID, ConnectionID: connectionID,
		OriginalPlanID: planID, OriginalPlanHash: planHash, ResourceID: item.ResourceID, ApprovedPlanHash: item.ApprovedPlanHash,
		ApprovalID: item.ApprovalID, Retention: item.Retention, DestroyDeadline: item.DestroyDeadline, AutoDestroy: item.AutoDestroyApproved, State: item.State}
}

func mixedApprovedPlan(t *testing.T, now time.Time, agentID, ownerID, planID, connectionID string) cloudapproval.PlanV1 {
	t.Helper()
	plan := cloudapproval.PlanV1{
		SchemaVersion: cloudapproval.PlanSchemaV1, AgentInstanceID: agentID, OwnerID: ownerID, PlanID: planID, Revision: 1, Status: cloudapproval.PlanApproved, ConnectionID: connectionID,
		Recipe: cloudapproval.RecipeBindingV1{RecipeID: "mixed-recipe", Digest: mixedDigest("a"), Maturity: recipe.MaturityExperimental},
		Quote:  cloudapproval.QuoteBindingV1{QuoteID: "mixed-quote", Digest: mixedDigest("b"), CandidateID: "recommended", ValidUntil: now.Add(time.Hour)},
		ResourceScope: cloudapproval.ResourceScopeV1{Region: "us-east-1", AvailabilityZones: []string{"us-east-1a"}, InstanceType: "m7i.xlarge",
			Architecture: recipe.ArchitectureAMD64, InstanceCount: 1, VCPU: 4, MemoryMiB: 16384, DiskGiB: 80, VolumeType: "gp3", VolumeEncrypted: true,
			PurchaseOption: cloudapproval.PurchaseOnDemand, WorkerImageID: "ami-0123456789abcdef0", WorkerImageDigest: mixedDigest("c")},
		NetworkScope: cloudapproval.NetworkScopeV1{VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0", SecurityGroupMode: cloudapproval.SecurityGroupExisting,
			SecurityGroupID: "sg-0123456789abcdef0", EntryPoint: cloudapproval.EntryPointNone},
		RetentionScope: cloudapproval.RetentionScopeV1{Class: cloudapproval.RetentionEphemeral, AutoDestroy: true, GracePeriodSeconds: 1800, MaxLifetimeSeconds: 3600},
	}
	var err error
	plan.Quote.ScopeDigest, err = plan.PricingScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func mixedDigest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }

type mixedStatusReader struct {
	deployment cloudstatus.Deployment
	resources  []resource.ResourceV1
}

func (reader *mixedStatusReader) GetDeployment(context.Context, string, string) (cloudstatus.Deployment, error) {
	return reader.deployment, nil
}
func (reader *mixedStatusReader) ListDeploymentResources(context.Context, string, string) ([]resource.ResourceV1, error) {
	return append([]resource.ResourceV1(nil), reader.resources...), nil
}
func (*mixedStatusReader) ListPlans(context.Context, cloudstatus.ListQuery) (cloudstatus.PlanPage, error) {
	return cloudstatus.PlanPage{}, cloudstatus.ErrNotFound
}
func (*mixedStatusReader) GetConnection(context.Context, string, string) (cloudstatus.Connection, error) {
	return cloudstatus.Connection{}, cloudstatus.ErrNotFound
}
func (*mixedStatusReader) ListConnections(context.Context, cloudstatus.ListQuery) (cloudstatus.ConnectionPage, error) {
	return cloudstatus.ConnectionPage{}, cloudstatus.ErrNotFound
}
func (*mixedStatusReader) ListDeployments(context.Context, cloudstatus.ListQuery) (cloudstatus.DeploymentPage, error) {
	return cloudstatus.DeploymentPage{}, cloudstatus.ErrNotFound
}
func (*mixedStatusReader) GetWorker(context.Context, string, string) (worker.Deployment, error) {
	return worker.Deployment{}, cloudstatus.ErrNotFound
}
func (*mixedStatusReader) ListWorkers(context.Context, cloudstatus.ListQuery) (cloudstatus.WorkerPage, error) {
	return cloudstatus.WorkerPage{}, cloudstatus.ErrNotFound
}
func (*mixedStatusReader) GetResource(context.Context, string, string) (resource.ResourceV1, error) {
	return resource.ResourceV1{}, cloudstatus.ErrNotFound
}
func (*mixedStatusReader) ListResources(context.Context, cloudstatus.ListQuery) (cloudstatus.ResourcePage, error) {
	return cloudstatus.ResourcePage{}, cloudstatus.ErrNotFound
}

type mixedPlanReader struct{ plan cloudapproval.PlanV1 }

func (reader mixedPlanReader) LoadPlan(context.Context, string, string) (cloudapproval.PlanV1, error) {
	return reader.plan, nil
}

type mixedResourceVerifier struct {
	expected map[string]ResourceApprovalProofV1
	proofs   []ResourceApprovalProofV1
}

func (verifier *mixedResourceVerifier) VerifyResourceApproval(_ context.Context, proof ResourceApprovalProofV1) error {
	verifier.proofs = append(verifier.proofs, proof)
	expected, ok := verifier.expected[proof.ResourceID]
	if !ok || !reflect.DeepEqual(expected, proof) {
		return ErrInvalid
	}
	return nil
}

type mixedDeviceRepository struct{ device cloudapproval.DeviceKeyV1 }

func (repository mixedDeviceRepository) GetDeviceKey(context.Context, string) (cloudapproval.DeviceKeyV1, error) {
	return repository.device, nil
}

type mixedDestroyRepository struct{ challenge ChallengeV1 }

func (repository *mixedDestroyRepository) CreateDestroyChallenge(_ context.Context, _ Mutation, challenge ChallengeV1) (ChallengeV1, error) {
	repository.challenge = challenge
	return challenge, nil
}
func (*mixedDestroyRepository) GetDestroyChallenge(context.Context, string, string) (ChallengeV1, error) {
	return ChallengeV1{}, ErrNotFound
}
func (*mixedDestroyRepository) ApproveDestroy(context.Context, Mutation, string, int64, SignatureV1, time.Time) (OperationV1, error) {
	return OperationV1{}, ErrNotFound
}
func (*mixedDestroyRepository) GetDestroyOperation(context.Context, string, string) (OperationV1, error) {
	return OperationV1{}, ErrNotFound
}
func (*mixedDestroyRepository) ListPendingDestroy(context.Context, int) ([]OperationV1, error) {
	return nil, nil
}
func (*mixedDestroyRepository) SaveDestroyOperation(context.Context, OperationV1, int64) (OperationV1, error) {
	return OperationV1{}, ErrNotFound
}

type mixedNotifier struct{}

func (mixedNotifier) NotifyManualDestroy() {}

var _ cloudstatus.Reader = (*mixedStatusReader)(nil)
