package entryexecution

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestRunOnceProvisionsClosedALBGraphAndActivates(t *testing.T) {
	t.Parallel()
	fixture := newExecutorFixture(t)
	executor := fixture.executor(t)

	if err := executor.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	operation := fixture.operations.current()
	if operation.Status != entrypoint.StatusActive || operation.ErrorCode != entrypoint.ErrorCodeNone {
		t.Fatalf("operation = %#v, want active without error", operation)
	}
	if got := fixture.provisioner.callCount(); got != 5 {
		t.Fatalf("provision calls = %d, want 5", got)
	}
	for _, scope := range fixture.provisioner.scopes {
		if scope.OwnerID != fixture.plan.Scope.OwnerID || scope.ConnectionID != fixture.plan.Scope.ConnectionID || scope.Region != fixture.plan.Scope.Region {
			t.Fatalf("provision received an unsigned or mismatched scope: %#v", scope)
		}
	}
	if fixture.resources.ownerID != fixture.plan.Scope.OwnerID || fixture.resources.deploymentID != fixture.plan.Scope.Worker.DeploymentID {
		t.Fatalf("resource ledger lookup = (%q, %q), want signed owner/deployment", fixture.resources.ownerID, fixture.resources.deploymentID)
	}
	if got := fixture.scopes.calls; got != 7 { // approved gate + every provision + verification gate
		t.Fatalf("scope revalidations = %d, want 7", got)
	}

	specs := fixture.provisioner.specs()
	if got, want := resourceKinds(specs), []resource.Type{resource.TypeSG, resource.TypeSecurityGroupRule, resource.TypeTargetGroup, resource.TypeALB, resource.TypeListener}; !sameTypes(got, want) {
		t.Fatalf("resource types = %v, want %v", got, want)
	}
	assertClosedEntrySpecs(t, fixture, specs)
	entryPlanHash, err := fixture.plan.Hash()
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range specs {
		if spec.ApprovedPlanHash != entryPlanHash || spec.ApprovalID != operation.Challenge.ApprovalID {
			t.Fatalf("entry resource %s approval binding = (%q, %q), want entry plan/device approval", spec.LogicalName, spec.ApprovedPlanHash, spec.ApprovalID)
		}
		if spec.ApprovedPlanHash == fixture.plan.Scope.Worker.OriginalPlanHash || spec.ApprovalID == fixture.plan.Scope.Worker.OriginalApprovalID {
			t.Fatalf("entry resource %s reused the historical Worker approval", spec.LogicalName)
		}
	}
	worker := fixture.workerResource()
	if worker.ApprovedPlanHash != fixture.plan.Scope.Worker.OriginalPlanHash || worker.ApprovalID != fixture.plan.Scope.Worker.OriginalApprovalID {
		t.Fatal("existing Worker binding must remain tied to its original approval")
	}
}

func TestRunOnceRecoversProvisioningOperationWithoutDuplicatingResources(t *testing.T) {
	t.Parallel()
	fixture := newExecutorFixture(t)
	operation := fixture.operations.current()
	operation.Status = entrypoint.StatusProvisioning
	operation.Revision++
	operation.UpdatedAt = fixture.now.Add(2 * time.Second)
	fixture.operations.replace(operation)

	bindings, err := fixture.executor(t).bindWorkerResources(context.Background(), fixture.plan.Scope)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := resourceSpecs(operation, fixture.plan, bindings)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a process crash after the first two typed resource intents have
	// reached active state but before the entry operation moved forward.
	for _, spec := range specs[:2] {
		fixture.provisioner.seedActive(spec)
	}

	executor := fixture.executor(t)
	if err := executor.RunOnce(context.Background()); err != nil {
		t.Fatalf("recovery RunOnce() error = %v", err)
	}
	if got := fixture.operations.current().Status; got != entrypoint.StatusActive {
		t.Fatalf("recovered status = %q, want active", got)
	}
	if got := fixture.provisioner.newCreateCount(); got != 3 {
		t.Fatalf("new resource creates = %d, want 3 after two recovered intents", got)
	}
	if got := fixture.provisioner.callCount(); got != 5 {
		t.Fatalf("provision calls = %d, want all 5 reconciliation calls", got)
	}
	if fixture.provisioner.hasDuplicateID() {
		t.Fatal("recovery generated a different resource identity for an existing entry resource")
	}
}

func TestRunOnceFailsClosedBeforeProvisionWhenScopeDrifts(t *testing.T) {
	t.Parallel()
	fixture := newExecutorFixture(t)
	fixture.scopes.err = entrypoint.ErrReadBackRequired

	if err := fixture.executor(t).RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	operation := fixture.operations.current()
	if operation.Status != entrypoint.StatusFailed || operation.ErrorCode != entrypoint.ErrorCodeReadBackMismatch {
		t.Fatalf("operation = %#v, want read-back-mismatch failure", operation)
	}
	if fixture.provisioner.callCount() != 0 {
		t.Fatal("scope drift allowed a typed provider request")
	}
	if strings.Contains(operation.ErrorSummary, "sk-") || operation.ErrorSummary != summaryReadBackMismatch {
		t.Fatalf("unsafe failure summary %q", operation.ErrorSummary)
	}
}

func TestRunOnceTreatsResponseLossAsRetryNotPublicFailure(t *testing.T) {
	t.Parallel()
	fixture := newExecutorFixture(t)
	fixture.provisioner.errAt = map[int]error{1: resource.ErrCreateAmbiguous}

	err := fixture.executor(t).RunOnce(context.Background())
	if !errors.Is(err, resource.ErrCreateAmbiguous) {
		t.Fatalf("RunOnce() error = %v, want create ambiguity", err)
	}
	if got := fixture.operations.current().Status; got != entrypoint.StatusProvisioning {
		t.Fatalf("operation status after response loss = %q, want provisioning for reconciliation", got)
	}
}

func TestRunOnceRetriesUnavailableSignedProvisioner(t *testing.T) {
	t.Parallel()
	fixture := newExecutorFixture(t)
	fixture.provisioner.errAt = map[int]error{1: entrypoint.ErrUnavailable}

	err := fixture.executor(t).RunOnce(context.Background())
	if !errors.Is(err, entrypoint.ErrUnavailable) {
		t.Fatalf("RunOnce() error = %v, want temporary signed-provisioner failure", err)
	}
	if got := fixture.operations.current().Status; got != entrypoint.StatusProvisioning {
		t.Fatalf("operation status after temporary provisioner failure = %q, want provisioning", got)
	}
}

type executorFixture struct {
	now         time.Time
	plan        entrypoint.PlanV1
	operations  *operationRepositoryFake
	plans       *planResolverFake
	scopes      *scopeRevalidatorFake
	resources   *deploymentResourcesFake
	provisioner *provisionerFake
}

func newExecutorFixture(t *testing.T) *executorFixture {
	t.Helper()
	now := time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC)
	scope := executorTestScope(now)
	plan, err := entrypoint.NewPlanV1(uuid.NewString(), 1, entrypoint.PlanReadyForApproval, scope)
	if err != nil {
		t.Fatalf("NewPlanV1() error = %v", err)
	}
	challenge, err := entrypoint.NewChallengeV1(plan, uuid.NewString(), uuid.NewString(), uuid.NewString(), "device-key", now, now.Add(4*time.Minute))
	if err != nil {
		t.Fatalf("NewChallengeV1() error = %v", err)
	}
	plan.Status = entrypoint.PlanApproved
	approvedAt := now.Add(time.Second)
	signature := entrypoint.SignatureV1{ApprovalID: challenge.ApprovalID, ChallengeID: challenge.ChallengeID, EntryPlanID: challenge.EntryPlanID,
		EntryPlanRevision: challenge.EntryPlanRevision, PlanHash: challenge.PlanHash, ScopeDigest: challenge.ScopeDigest, SignerKeyID: challenge.SignerKeyID,
		ExpiresAt: challenge.ExpiresAt, Signature: make([]byte, 64)}
	operation := entrypoint.OperationV1{Challenge: challenge, Status: entrypoint.StatusApproved, Signature: &signature, Revision: 2,
		CreatedAt: now, UpdatedAt: approvedAt, ApprovedAt: &approvedAt}
	if err := operation.Validate(); err != nil {
		t.Fatalf("fixture operation invalid: %v", err)
	}
	fixture := &executorFixture{now: now, plan: plan, operations: &operationRepositoryFake{operation: operation}, plans: &planResolverFake{plan: plan},
		scopes: &scopeRevalidatorFake{}, resources: &deploymentResourcesFake{}, provisioner: newProvisionerFake(now)}
	fixture.resources.items = []resource.ResourceV1{fixture.workerResource(), fixture.workerSecurityGroup()}
	fixture.provisioner.ledger = fixture.resources
	return fixture
}

func (fixture *executorFixture) executor(t *testing.T) *Executor {
	t.Helper()
	executor, err := NewExecutor(Config{Operations: fixture.operations, Plans: fixture.plans, Scopes: fixture.scopes, Resources: fixture.resources,
		Provision: fixture.provisioner, PollInterval: time.Second, Now: func() time.Time { return fixture.now.Add(10 * time.Second) }})
	if err != nil {
		t.Fatalf("NewExecutor() error = %v", err)
	}
	return executor
}

func (fixture *executorFixture) workerResource() resource.ResourceV1 {
	scope := fixture.plan.Scope
	return resource.ResourceV1{ResourceID: scope.Worker.WorkerResourceID, AgentInstanceID: scope.AgentInstanceID, OwnerID: scope.OwnerID,
		TaskID: scope.Worker.TaskID, DeploymentID: scope.Worker.DeploymentID, Type: resource.TypeEC2, LogicalName: "exclusive-cloud-worker", Region: scope.Region,
		SpecDigest: scope.Worker.WorkerSpecDigest, ApprovedPlanHash: scope.Worker.OriginalPlanHash, ApprovalID: scope.Worker.OriginalApprovalID,
		ProviderID: scope.Worker.InstanceID, Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: scope.Retention.DestroyDeadline,
		AutoDestroyApproved: true, Tags: fixture.tags(scope.Worker.WorkerResourceID), State: resource.StateActive,
		ReadBack: resource.ReadBackEvidence{Exists: true, ProviderID: scope.Worker.InstanceID, ObservedAt: fixture.now.Add(time.Second), TagDigest: scope.Worker.ReadBack.TagDigest},
		Revision: scope.Worker.WorkerResourceRevision}
}

func (fixture *executorFixture) workerSecurityGroup() resource.ResourceV1 {
	scope := fixture.plan.Scope
	resourceID := uuid.NewString()
	return resource.ResourceV1{ResourceID: resourceID, AgentInstanceID: scope.AgentInstanceID, OwnerID: scope.OwnerID,
		TaskID: scope.Worker.TaskID, DeploymentID: scope.Worker.DeploymentID, Type: resource.TypeSG, LogicalName: "worker-security-group", Region: scope.Region,
		SpecDigest: digest('c'), ApprovedPlanHash: scope.Worker.OriginalPlanHash, ApprovalID: scope.Worker.OriginalApprovalID,
		ProviderID: scope.Worker.SecurityGroupID, Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: scope.Retention.DestroyDeadline,
		AutoDestroyApproved: true, Tags: fixture.tags(resourceID), State: resource.StateActive,
		ReadBack: resource.ReadBackEvidence{Exists: true, ProviderID: scope.Worker.SecurityGroupID, ObservedAt: fixture.now.Add(time.Second), TagDigest: digest('d')}, Revision: 1}
}

func (fixture *executorFixture) tags(resourceID string) map[string]string {
	scope := fixture.plan.Scope
	return map[string]string{resource.TagAgentInstanceID: scope.AgentInstanceID, resource.TagOwnerID: scope.OwnerID,
		resource.TagTaskID: scope.Worker.TaskID, resource.TagDeploymentID: scope.Worker.DeploymentID, resource.TagResourceID: resourceID,
		resource.TagRetention: string(task.RetentionEphemeralAutoDestroy), resource.TagDestroyDeadline: scope.Retention.DestroyDeadline.UTC().Format(time.RFC3339)}
}

type operationRepositoryFake struct{ operation entrypoint.OperationV1 }

func (fake *operationRepositoryFake) ListPendingEntry(_ context.Context, _ int) ([]entrypoint.OperationV1, error) {
	return []entrypoint.OperationV1{fake.operation}, nil
}

func (fake *operationRepositoryFake) SaveEntryOperation(_ context.Context, next entrypoint.OperationV1, expectedRevision int64) (entrypoint.OperationV1, error) {
	if fake.operation.Revision != expectedRevision {
		return entrypoint.OperationV1{}, entrypoint.ErrRevisionConflict
	}
	if next.Validate() != nil {
		return entrypoint.OperationV1{}, entrypoint.ErrInvalid
	}
	next.Revision = expectedRevision + 1
	fake.operation = next
	return next, nil
}

func (fake *operationRepositoryFake) current() entrypoint.OperationV1      { return fake.operation }
func (fake *operationRepositoryFake) replace(value entrypoint.OperationV1) { fake.operation = value }

type planResolverFake struct {
	plan entrypoint.PlanV1
	err  error
}

func (fake *planResolverFake) ResolveApprovedPlan(_ context.Context, operationID string) (entrypoint.PlanV1, error) {
	if fake.err != nil {
		return entrypoint.PlanV1{}, fake.err
	}
	if operationID == "" {
		return entrypoint.PlanV1{}, entrypoint.ErrNotFound
	}
	return fake.plan, nil
}

type scopeRevalidatorFake struct {
	err   error
	calls int
}

func (fake *scopeRevalidatorFake) RevalidateScope(_ context.Context, _ entrypoint.ScopeV1) error {
	fake.calls++
	return fake.err
}

type deploymentResourcesFake struct {
	items        []resource.ResourceV1
	err          error
	ownerID      string
	deploymentID string
}

func (fake *deploymentResourcesFake) ListDeployment(_ context.Context, ownerID, deploymentID string) ([]resource.ResourceV1, error) {
	fake.ownerID, fake.deploymentID = ownerID, deploymentID
	if fake.err != nil {
		return nil, fake.err
	}
	result := make([]resource.ResourceV1, len(fake.items))
	copy(result, fake.items)
	return result, nil
}

type provisionerFake struct {
	now        time.Time
	byID       map[string]resource.ResourceV1
	requests   []resource.ProvisionSpec
	scopes     []entrypoint.ScopeV1
	errAt      map[int]error
	newCreates int
	logicalIDs map[string]string
	mismatch   bool
	ledger     *deploymentResourcesFake
}

func newProvisionerFake(now time.Time) *provisionerFake {
	return &provisionerFake{now: now, byID: map[string]resource.ResourceV1{}, logicalIDs: map[string]string{}}
}

func (fake *provisionerFake) Provision(_ context.Context, scope entrypoint.ScopeV1, spec resource.ProvisionSpec, authorization resource.ProviderCreateAuthorization) (resource.ResourceV1, error) {
	fake.scopes = append(fake.scopes, scope)
	fake.requests = append(fake.requests, spec)
	call := len(fake.requests)
	if err := spec.Validate(fake.now); err != nil {
		return resource.ResourceV1{}, err
	}
	if !fake.now.Before(authorization.ApprovalExpiresAt) || !fake.now.Before(authorization.QuoteValidUntil) {
		return resource.ResourceV1{}, resource.ErrCreateAuthorizationExpired
	}
	if prior, found := fake.logicalIDs[spec.LogicalName]; found && prior != spec.ResourceID {
		fake.mismatch = true
	} else {
		fake.logicalIDs[spec.LogicalName] = spec.ResourceID
	}
	if err := fake.errAt[call]; err != nil {
		return resource.ResourceV1{}, err
	}
	if existing, found := fake.byID[spec.ResourceID]; found {
		if existing.SpecDigest != spec.SpecDigest || existing.Type != spec.Type {
			return resource.ResourceV1{}, resource.ErrReadBack
		}
		return existing, nil
	}
	fake.newCreates++
	created := resource.ResourceV1{ResourceID: spec.ResourceID, AgentInstanceID: spec.AgentInstanceID, OwnerID: spec.OwnerID, TaskID: spec.TaskID,
		DeploymentID: spec.DeploymentID, Type: spec.Type, LogicalName: spec.LogicalName, Region: spec.Region, SpecDigest: spec.SpecDigest,
		ApprovedPlanHash: spec.ApprovedPlanHash, ApprovalID: spec.ApprovalID, ProviderID: "provider-" + spec.ResourceID,
		Retention: spec.Retention, DestroyDeadline: spec.DestroyDeadline, AutoDestroyApproved: spec.AutoDestroyApproved, State: resource.StateActive,
		ReadBack: resource.ReadBackEvidence{Exists: true, ProviderID: "provider-" + spec.ResourceID, ObservedAt: fake.now}}
	fake.byID[spec.ResourceID] = created
	if fake.ledger != nil {
		fake.ledger.items = append(fake.ledger.items, created)
	}
	return created, nil
}

func (fake *provisionerFake) seedActive(spec resource.ProvisionSpec) {
	seeded := resource.ResourceV1{ResourceID: spec.ResourceID, AgentInstanceID: spec.AgentInstanceID, OwnerID: spec.OwnerID, TaskID: spec.TaskID,
		DeploymentID: spec.DeploymentID, Type: spec.Type, LogicalName: spec.LogicalName, Region: spec.Region, SpecDigest: spec.SpecDigest,
		ApprovedPlanHash: spec.ApprovedPlanHash, ApprovalID: spec.ApprovalID, ProviderID: "provider-" + spec.ResourceID,
		Retention: spec.Retention, DestroyDeadline: spec.DestroyDeadline, AutoDestroyApproved: spec.AutoDestroyApproved, State: resource.StateActive,
		ReadBack: resource.ReadBackEvidence{Exists: true, ProviderID: "provider-" + spec.ResourceID, ObservedAt: fake.now}}
	fake.byID[spec.ResourceID] = seeded
	fake.logicalIDs[spec.LogicalName] = spec.ResourceID
	if fake.ledger != nil {
		fake.ledger.items = append(fake.ledger.items, seeded)
	}
}

func (fake *provisionerFake) callCount() int      { return len(fake.requests) }
func (fake *provisionerFake) newCreateCount() int { return fake.newCreates }
func (fake *provisionerFake) specs() []resource.ProvisionSpec {
	return append([]resource.ProvisionSpec(nil), fake.requests...)
}
func (fake *provisionerFake) hasDuplicateID() bool {
	return fake.mismatch
}

func assertClosedEntrySpecs(t *testing.T, fixture *executorFixture, specs []resource.ProvisionSpec) {
	t.Helper()
	if len(specs) != 5 {
		t.Fatalf("spec count = %d, want 5", len(specs))
	}
	byType := map[resource.Type]resource.ProvisionSpec{}
	for _, spec := range specs {
		byType[spec.Type] = spec
		if spec.Type == resource.TypeEC2 || spec.Type == resource.TypeEIP {
			t.Fatalf("entry graph attempted forbidden resource type %q", spec.Type)
		}
	}
	group := byType[resource.TypeSG]
	if group.AWS.SecurityGroup == nil || len(group.AWS.SecurityGroup.Ingress) != 1 || group.AWS.SecurityGroup.Ingress[0].FromPort != 443 || group.AWS.SecurityGroup.Ingress[0].CIDRv4 != "0.0.0.0/0" {
		t.Fatalf("ALB security-group scope = %#v", group.AWS.SecurityGroup)
	}
	bridge := byType[resource.TypeSecurityGroupRule]
	if bridge.AWS.SecurityGroupRule == nil || bridge.AWS.SecurityGroupRule.SourceSecurityGroupResourceID != group.ResourceID || bridge.AWS.SecurityGroupRule.TargetSecurityGroupResourceID != fixture.resources.items[1].ResourceID {
		t.Fatalf("bridge scope = %#v", bridge.AWS.SecurityGroupRule)
	}
	target := byType[resource.TypeTargetGroup]
	if target.AWS.TargetGroup == nil || target.AWS.TargetGroup.Registration.InstanceID != fixture.plan.Scope.Worker.InstanceID || target.AWS.TargetGroup.HealthCheckPath != fixture.plan.Scope.Health.Path {
		t.Fatalf("target-group scope = %#v", target.AWS.TargetGroup)
	}
	listener := byType[resource.TypeListener]
	if listener.AWS.Listener == nil || listener.AWS.Listener.CertificateARN != fixture.plan.Scope.Certificate.CertificateARN || listener.AWS.Listener.Hostname != fixture.plan.Scope.Certificate.Hostname {
		t.Fatalf("listener scope = %#v", listener.AWS.Listener)
	}
}

func resourceKinds(values []resource.ProvisionSpec) []resource.Type {
	result := make([]resource.Type, 0, len(values))
	for _, value := range values {
		result = append(result, value.Type)
	}
	return result
}

func sameTypes(left, right []resource.Type) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func executorTestScope(now time.Time) entrypoint.ScopeV1 {
	deadline := now.Add(time.Hour)
	return entrypoint.ScopeV1{
		SchemaVersion: entrypoint.ScopeSchemaV1, Kind: entrypoint.EntryKindALB, AgentInstanceID: uuid.NewString(), OwnerID: "owner-1", ConnectionID: uuid.NewString(), Region: "us-east-1",
		Worker: entrypoint.WorkerReadBackScopeV1{DeploymentID: uuid.NewString(), DeploymentRevision: 1, TaskID: uuid.NewString(), OriginalPlanID: uuid.NewString(), OriginalPlanHash: digest('a'),
			OriginalApprovalID: uuid.NewString(), WorkerResourceID: uuid.NewString(), WorkerResourceRevision: 1, WorkerSpecDigest: digest('b'), InstanceID: "i-0123456789abcdef0",
			VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0", SecurityGroupID: "sg-0123456789abcdef0", ExecutionOutcome: entrypoint.WorkerOutcomeSucceeded,
			SucceededAt: now, ReadBack: entrypoint.AWSReadBackV1{Observed: true, Exists: true, State: entrypoint.EC2InstanceRunning, ObservedAt: now.Add(time.Second), TagDigest: digest('c')},
			Retention: entrypoint.RetentionScopeV1{Class: entrypoint.RetentionEphemeral, AutoDestroy: true, DestroyDeadline: deadline}},
		Recipe: entrypoint.RecipeHealthBindingV1{RecipeDigest: digest('d'), HealthContractDigest: digest('e'), AuthenticationContractDigest: digest('f')},
		Certificate: entrypoint.CertificateScopeV1{CertificateARN: "arn:aws:acm:us-east-1:123456789012:certificate/11111111-1111-4111-8111-111111111111", Region: "us-east-1", Hostname: "service.example.test",
			SubjectAlternativeNames: []string{"service.example.test"}, Status: entrypoint.CertificateStatusIssued, ReadBackDigest: digest('1'), ObservedAt: now.Add(time.Second)},
		ALB: entrypoint.ALBScopeV1{Scheme: entrypoint.ALBSchemeInternetFacing, ListenerPort: entrypoint.HTTPSPort, ListenerProtocol: entrypoint.ListenerProtocolHTTPS,
			TLSPolicy: entrypoint.TLSPolicyTLS13_2021_06, IngressCIDRs: []string{"0.0.0.0/0"}, TargetProtocol: entrypoint.TargetProtocolHTTP, TargetPort: 8080,
			TargetSource: entrypoint.TargetSourceApprovedWorkerReadBack, PublicSubnets: []entrypoint.PublicSubnetScopeV1{
				{SubnetID: "subnet-0123456789abcdef0", VPCID: "vpc-0123456789abcdef0", AvailabilityZone: "us-east-1a", Public: true, ReadBackDigest: digest('2'), ObservedAt: now.Add(time.Second)},
				{SubnetID: "subnet-0fedcba9876543210", VPCID: "vpc-0123456789abcdef0", AvailabilityZone: "us-east-1b", Public: true, ReadBackDigest: digest('3'), ObservedAt: now.Add(time.Second)},
			}},
		Health:         entrypoint.HealthRouteScopeV1{Path: "/healthz", ExpectedStatusCode: 200, EvidenceDigest: digest('e'), NoCredentialRoute: true},
		Authentication: entrypoint.AuthenticationScopeV1{Required: true, ContractDigest: digest('f')},
		Cost: entrypoint.EntryCostScopeV1{QuoteID: uuid.NewString(), QuoteDigest: digest('4'), Currency: "USD", QuotedAt: now, ValidUntil: now.Add(10 * time.Minute),
			ALBHourlyEstimateMicros: 100, LCUHourlyEstimateMicros: 100, EstimatedLCUMilliUnits: 1000, EstimatedEgressMiB: 100, TrafficEstimateMicros: 10, MaximumLaunchAmountMicros: 210, AssumptionsDigest: digest('5')},
		Retention: entrypoint.RetentionScopeV1{Class: entrypoint.RetentionEphemeral, AutoDestroy: true, DestroyDeadline: deadline},
	}
}

func digest(character byte) string { return "sha256:" + strings.Repeat(string(character), 64) }
