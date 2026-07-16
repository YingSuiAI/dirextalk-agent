package cloudexecution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
)

func TestLaunchApprovedPlanCreatesOneDurableWorkerAndReplaysTerminalOperation(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	fixture := newLaunchFixture(t, now)

	first, err := fixture.service.LaunchApprovedPlan(context.Background(), fixture.caller, fixture.request)
	if err != nil {
		t.Fatalf("LaunchApprovedPlan() error = %v", err)
	}
	if first.State != StateActive || first.TaskID == "" || len(first.ResourceIDs) != 1 {
		t.Fatalf("operation = %#v", first)
	}
	if fixture.tasks.calls != 1 || fixture.bundles.calls != 1 || fixture.workers.calls != 1 || fixture.bootstraps.calls != 1 || fixture.resources.calls != 1 {
		t.Fatalf("side effects task=%d bundles=%d worker=%d bootstrap=%d resource=%d", fixture.tasks.calls, fixture.bundles.calls, fixture.workers.calls, fixture.bootstraps.calls, fixture.resources.calls)
	}
	approval := fixture.service.facts.(fakeFacts).approval
	if !fixture.resources.authorization.ApprovalExpiresAt.Equal(approval.ExpiresAt) || !fixture.resources.authorization.QuoteValidUntil.Equal(approval.QuoteValidUntil) {
		t.Fatalf("provider create authorization = %+v, approval expiry=%v quote expiry=%v", fixture.resources.authorization, approval.ExpiresAt, approval.QuoteValidUntil)
	}
	if !fixture.bootstraps.destroyedAfterCall {
		t.Fatal("enrollment credential was not wiped after bootstrap publication")
	}

	replayed, err := fixture.service.LaunchApprovedPlan(context.Background(), fixture.caller, fixture.request)
	if err != nil {
		t.Fatalf("replay error = %v", err)
	}
	if replayed.OperationID != first.OperationID || replayed.Revision != first.Revision {
		t.Fatalf("replay = %#v, first = %#v", replayed, first)
	}
	if fixture.tasks.calls != 1 || fixture.bundles.calls != 1 || fixture.workers.calls != 1 || fixture.bootstraps.calls != 1 || fixture.resources.calls != 1 {
		t.Fatal("terminal replay repeated a mutating side effect")
	}
}

func TestLaunchApprovedPlanFailsClosedBeforeMutationWithoutMatchingConnection(t *testing.T) {
	fixture := newLaunchFixture(t, time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC))
	fixture.connections.err = cloudapp.ErrNotFound
	_, err := fixture.service.LaunchApprovedPlan(context.Background(), fixture.caller, fixture.request)
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("error = %v, want ErrNotReady", err)
	}
	if fixture.tasks.calls+fixture.bundles.calls+fixture.workers.calls+fixture.bootstraps.calls+fixture.resources.calls != 0 {
		t.Fatal("a cloud mutation ran before connection verification")
	}
}

func TestCompileBundlesNeverFallsBackToUnknownAction(t *testing.T) {
	value := launchRecipe(time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC))
	value.Install.Steps[0].Action = "shell.run"
	_, _, err := compileBundles(value)
	if !errors.Is(err, ErrUnsupportedRecipe) {
		t.Fatalf("error = %v, want ErrUnsupportedRecipe", err)
	}
}

func TestAWSResourcePlanUsesOnlyApprovedExistingSecurityGroup(t *testing.T) {
	fixture := newLaunchFixture(t, time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC))
	plan := fixture.service.facts.(fakeFacts).plan
	connection := fixture.connections.value
	recipeValue := fixture.service.recipes.(fakeRecipes).value
	operation := Operation{
		Intent: Intent{Launch: fixture.request, ConnectionID: connection.ConnectionID, ApprovedPlanHash: fixture.service.facts.(fakeFacts).approval.PlanHash, DeploymentID: uuid.NewString()},
		State:  StateBootstrapReady, TaskID: uuid.NewString(), Bootstrap: BootstrapArtifact{Reference: "s3://agent-bucket/launch/config.json", SHA256: sha256.Sum256([]byte("launch"))},
		CreatedAt: time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 7, 16, 10, 0, 1, 0, time.UTC),
	}
	builder, err := NewAWSResourcePlanBuilder(plan.AgentInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := builder.Build(plan, connection, recipeValue, operation)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(specs) != 2 || specs[0].Type != resource.TypeENI || specs[1].Type != resource.TypeEC2 {
		t.Fatalf("specs = %#v", specs)
	}
	if specs[0].AWS.NetworkInterface.ExistingSecurityGroupID != plan.NetworkScope.SecurityGroupID || len(specs[0].DependsOn) != 0 {
		t.Fatal("approved existing security group was replaced by an unapproved owned group")
	}
	if len(specs[1].DependsOn) != 1 || specs[1].DependsOn[0] != specs[0].ResourceID {
		t.Fatal("instance is not bound to its exclusive ENI")
	}
}

type launchFixture struct {
	service     *Service
	caller      cloudapp.MutationScope
	request     LaunchRequest
	tasks       *fakeTasks
	bundles     *fakeBundles
	workers     *fakeWorkers
	bootstraps  *fakeBootstraps
	resources   *fakeResources
	connections *fakeConnections
}

func newLaunchFixture(t *testing.T, now time.Time) launchFixture {
	t.Helper()
	agentID, ownerID, planID := uuid.NewString(), "owner-1", uuid.NewString()
	connectionID, approvalID := uuid.NewString(), uuid.NewString()
	value := launchRecipe(now)
	digest, err := value.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan := cloudapproval.PlanV1{
		SchemaVersion: cloudapproval.PlanSchemaV1, AgentInstanceID: agentID, OwnerID: ownerID, PlanID: planID,
		Revision: 1, Status: cloudapproval.PlanReadyForConfirmation, ConnectionID: connectionID,
		Recipe: cloudapproval.RecipeBindingV1{RecipeID: value.RecipeID, Digest: digest, Maturity: value.Maturity},
		Quote:  cloudapproval.QuoteBindingV1{QuoteID: uuid.NewString(), Digest: testDigest("b"), CandidateID: "recommended", ValidUntil: now.Add(15 * time.Minute)},
		ResourceScope: cloudapproval.ResourceScopeV1{
			Region: "us-east-1", AvailabilityZones: []string{"us-east-1a"}, InstanceType: "m7i.large", InstanceCount: 1,
			Architecture: recipe.ArchitectureAMD64, VCPU: 2, MemoryMiB: 8192, DiskGiB: 40, VolumeType: "gp3",
			VolumeEncrypted: true, PurchaseOption: cloudapproval.PurchaseOnDemand,
			WorkerImageID: "ami-0123456789abcdef0", WorkerImageDigest: testDigest("c"),
		},
		NetworkScope:   cloudapproval.NetworkScopeV1{VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0", SecurityGroupID: "sg-0123456789abcdef0", EntryPoint: cloudapproval.EntryPointNone},
		RetentionScope: cloudapproval.RetentionScopeV1{Class: cloudapproval.RetentionEphemeral, AutoDestroy: true, GracePeriodSeconds: 1800, MaxLifetimeSeconds: 86400},
	}
	scopeDigest, err := plan.PricingScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	plan.Quote.ScopeDigest = scopeDigest
	approval, err := cloudapproval.NewApprovalV1(plan, approvalID, strings.Repeat("c", 48), "device-1", now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	plan.Status, plan.Revision = cloudapproval.PlanApproved, 2

	tasks := &fakeTasks{task: task.Task{TaskID: uuid.NewString(), OwnerID: ownerID}}
	bundles, workers, bootstraps, resources := &fakeBundles{}, &fakeWorkers{}, &fakeBootstraps{}, &fakeResources{}
	connections := &fakeConnections{value: cloudapp.Connection{ConnectionID: connectionID, OwnerID: ownerID, AccountID: "123456789012", Region: "us-east-1", ControlRoleARN: "arn:aws:iam::123456789012:role/control", FoundationStack: "stack", Status: "active", Revision: 1}}
	operations := &memoryOperations{}
	service, err := NewService(
		agentID, fakeFacts{plan: plan, approval: approval}, connections, fakeRecipes{value: value}, tasks,
		bundles, workers, bootstraps, fakeResourcePlans{}, resources, operations, func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	return launchFixture{
		service: service, caller: cloudapp.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()},
		request: LaunchRequest{IdempotencyKey: uuid.NewString(), OwnerID: ownerID, PlanID: planID, ApprovalID: approvalID, ControlPlaneTarget: "grpcs://agent.example.com:7443"},
		tasks:   tasks, bundles: bundles, workers: workers, bootstraps: bootstraps, resources: resources, connections: connections,
	}
}

func launchRecipe(now time.Time) recipe.RecipeV1 {
	return recipe.RecipeV1{
		SchemaVersion: recipe.SchemaV1, RecipeID: uuid.NewString(), Name: "Validation Worker", Maturity: recipe.MaturityExperimental,
		Sources:      []recipe.SourceV1{{URL: "https://example.com/worker", Version: "v0.1.0", Commit: "abcdef0123456789", ArtifactDigest: testDigest("a"), ContentDigest: testDigest("d"), License: "Apache-2.0", RetrievedAt: now, Official: true}},
		Requirements: recipe.ResourceRequirementsV1{MinVCPU: 1, MinMemoryMiB: 1024, MinDiskGiB: 8, Architecture: recipe.ArchitectureAMD64},
		Install:      recipe.InstallContractV1{TimeoutSeconds: 30, CheckpointNames: []string{"done"}, Steps: []recipe.InstallStepV1{{ID: "smoke", Summary: "Validate typed Worker", TimeoutSeconds: 5, Action: "worker.noop", Checkpoint: "done"}}},
		Health: recipe.HealthContractV1{
			Liveness:  recipe.ProbeV1{Kind: recipe.ProbeAction, Target: "worker.noop", TimeoutSeconds: 5},
			Readiness: recipe.ProbeV1{Kind: recipe.ProbeAction, Target: "worker.noop", TimeoutSeconds: 5},
			Semantic:  recipe.ProbeV1{Kind: recipe.ProbeAction, Target: "worker.noop", TimeoutSeconds: 5},
		},
		Lifecycle: recipe.LifecycleContractV1{Start: "worker.start", Stop: "worker.stop", Restart: "worker.restart", Upgrade: "worker.upgrade", Rollback: "worker.rollback", Backup: "worker.backup", Restore: "worker.restore", Destroy: "worker.destroy"},
	}
}

type fakeFacts struct {
	plan     cloudapproval.PlanV1
	approval cloudapproval.ApprovalV1
}

func (facts fakeFacts) LoadPlan(context.Context, string, string) (cloudapproval.PlanV1, error) {
	return facts.plan, nil
}
func (facts fakeFacts) LoadApproval(context.Context, string, string) (cloudapproval.ApprovalV1, error) {
	return facts.approval, nil
}

type fakeConnections struct {
	value cloudapp.Connection
	err   error
}

func (connections *fakeConnections) LoadConnection(context.Context, string, string) (cloudapp.Connection, error) {
	return connections.value, connections.err
}

type fakeRecipes struct{ value recipe.RecipeV1 }

func (recipes fakeRecipes) ResolveRecipe(context.Context, string, string, string) (recipe.RecipeV1, error) {
	return recipes.value, nil
}

type fakeTasks struct {
	task  task.Task
	calls int
}

func (tasks *fakeTasks) Create(context.Context, task.MutationScope, task.CreateCommand) (task.Task, error) {
	tasks.calls++
	return tasks.task, nil
}

type fakeBundles struct{ calls int }

func (publisher *fakeBundles) PublishBundles(_ context.Context, _ cloudapp.Connection, deploymentID string, recipeBytes, executionBytes []byte, _ []string) (PublishedBundles, error) {
	publisher.calls++
	recipeDigest, executionDigest := sha256.Sum256(recipeBytes), sha256.Sum256(executionBytes)
	base := "s3://agent-bucket/workers/" + deploymentID + "/"
	return PublishedBundles{
		Recipe: worker.BundleRef{S3Ref: base + "recipe.cbor", SHA256: recipeDigest}, Execution: worker.BundleRef{S3Ref: base + "execution.json", SHA256: executionDigest},
		Launch: BootstrapArtifact{Reference: base + "launch/config.json", SHA256: sha256.Sum256([]byte("launch"))},
		Access: worker.AccessScope{ArtifactPrefix: base + "artifacts/", CheckpointPrefix: base + "checkpoints/", EvidencePrefix: base + "evidence/", LogPrefix: "cloudwatch://worker-log/" + deploymentID}, SecretBindings: map[string]string{},
	}, nil
}

type fakeCredential struct {
	value     []byte
	destroyed bool
}

func (credential *fakeCredential) Reveal() []byte { return bytes.Clone(credential.value) }
func (credential *fakeCredential) Destroy() {
	clear(credential.value)
	credential.destroyed = true
}

type fakeWorkers struct{ calls int }

func (workers *fakeWorkers) CreateDeployment(_ context.Context, _ WorkerCreateMutation, request worker.CreateDeploymentRequest) (worker.Deployment, SensitiveCredential, error) {
	workers.calls++
	return worker.Deployment{DeploymentID: request.DeploymentID, TaskID: request.TaskID, StepID: request.StepID, Revision: 1}, &fakeCredential{value: bytes.Repeat([]byte{0x42}, 48)}, nil
}

type fakeBootstraps struct {
	calls              int
	destroyedAfterCall bool
}

func (publisher *fakeBootstraps) PublishBootstrap(_ context.Context, _ cloudapp.Connection, request BootstrapRequest) (BootstrapArtifact, error) {
	publisher.calls++
	publisher.destroyedAfterCall = len(request.EnrollmentCredential) == 48
	result := request.Launch
	result.EnrollmentMaterialRef = "secret://aws/" + request.DeploymentID
	return result, nil
}

type fakeResourcePlans struct{}

func (fakeResourcePlans) Build(_ cloudapproval.PlanV1, _ cloudapp.Connection, _ recipe.RecipeV1, operation Operation) ([]resource.ProvisionSpec, error) {
	return []resource.ProvisionSpec{{ResourceID: deterministicID(operation.DeploymentID, "ec2")}}, nil
}

type fakeResources struct {
	calls         int
	authorization resource.ProviderCreateAuthorization
}

func (resources *fakeResources) Provision(_ context.Context, _ cloudapp.Connection, spec resource.ProvisionSpec, authorization resource.ProviderCreateAuthorization) (resource.ResourceV1, error) {
	resources.calls++
	resources.authorization = authorization
	return resource.ResourceV1{ResourceID: spec.ResourceID}, nil
}

type memoryOperations struct{ value *Operation }

func (repository *memoryOperations) Begin(_ context.Context, intent Intent) (Operation, bool, error) {
	if repository.value != nil {
		if repository.value.RequestHash != intent.RequestHash {
			return Operation{}, false, ErrRevisionConflict
		}
		return *repository.value, false, nil
	}
	value := Operation{Intent: intent, State: StateIntent, Revision: 1, CreatedAt: intent.RecordedAt, UpdatedAt: intent.RecordedAt}
	repository.value = &value
	return value, true, nil
}
func (repository *memoryOperations) Save(_ context.Context, value Operation, expected int64) (Operation, error) {
	if repository.value == nil || repository.value.Revision != expected {
		return Operation{}, ErrRevisionConflict
	}
	value.Revision++
	repository.value = &value
	return value, nil
}
func (repository *memoryOperations) GetByPlan(context.Context, string, string) (Operation, error) {
	if repository.value == nil {
		return Operation{}, ErrNotReady
	}
	return *repository.value, nil
}
func (repository *memoryOperations) ListRecoverable(context.Context, int) ([]Operation, error) {
	if repository.value == nil || repository.value.State == StateActive {
		return nil, nil
	}
	return []Operation{*repository.value}, nil
}

func testDigest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }
