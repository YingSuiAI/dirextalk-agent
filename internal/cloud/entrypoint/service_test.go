package entrypoint

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
)

func TestServiceRequiresFreshReadBackAndBoundDeviceApproval(t *testing.T) {
	now := time.Date(2026, time.July, 17, 3, 30, 0, 0, time.UTC)
	scope := validScope(now)
	builder := &entryScopeBuilderFake{current: scope}
	repository := newEntryRepositoryFake()
	devices := cloudapproval.NewMemoryRegistry()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const signerKeyID = "device-0123456789abcdef01234567"
	if err := devices.PutDeviceKey(cloudapproval.DeviceKeyV1{KeyID: signerKeyID, AgentInstanceID: scope.AgentInstanceID, OwnerID: scope.OwnerID,
		Revision: 1, Status: cloudapproval.DeviceKeyActive, PublicKey: publicKey, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	notifier := &entryNotifierFake{}
	service, err := NewService(scope.AgentInstanceID, repository, devices, builder, notifier, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	caller := task.MutationScope{ClientID: "message-server", CredentialID: "78787878-7878-4787-8787-787878787878"}
	draft := draftFromScope(scope)
	plan, err := service.CreatePlan(context.Background(), CreatePlanCommand{Caller: caller, IdempotencyKey: "67676767-6767-4767-8767-676767676767",
		OwnerID: scope.OwnerID, DeploymentID: scope.Worker.DeploymentID, ExpectedDeploymentRevision: scope.Worker.DeploymentRevision, Draft: draft})
	if err != nil {
		t.Fatalf("CreatePlan() error = %v", err)
	}
	challenge, err := service.Prepare(context.Background(), PrepareCommand{Caller: caller, IdempotencyKey: "57575757-5757-4757-8757-575757575757",
		OwnerID: scope.OwnerID, EntryPlanID: plan.EntryPlanID, ExpectedRevision: plan.Revision, SignerKeyID: signerKeyID})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	signature := SignatureV1{ApprovalID: challenge.ApprovalID, ChallengeID: challenge.ChallengeID, EntryPlanID: challenge.EntryPlanID,
		EntryPlanRevision: challenge.EntryPlanRevision, PlanHash: challenge.PlanHash, ScopeDigest: challenge.ScopeDigest, SignerKeyID: challenge.SignerKeyID,
		ExpiresAt: challenge.ExpiresAt, Signature: ed25519.Sign(privateKey, challenge.SigningCBOR)}

	// A current AWS read-back mismatch fences the approval even though a real
	// device signed the original payload. The endpoint never comes from Worker
	// output: only the independently rebuilt scope is compared.
	builder.current.Worker.ReadBack.TagDigest = digest('f')
	if _, err := service.Approve(context.Background(), ApproveCommand{Caller: caller, IdempotencyKey: "47474747-4747-4747-8747-474747474747",
		OwnerID: scope.OwnerID, EntryPlanID: plan.EntryPlanID, ExpectedRevision: plan.Revision, Signature: signature}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("Approve() stale read-back error = %v, want revision conflict", err)
	}

	builder.current = scope
	operation, err := service.Approve(context.Background(), ApproveCommand{Caller: caller, IdempotencyKey: "37373737-3737-4737-8737-373737373737",
		OwnerID: scope.OwnerID, EntryPlanID: plan.EntryPlanID, ExpectedRevision: plan.Revision, Signature: signature})
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if operation.Status != StatusApproved || operation.Signature == nil || notifier.count != 1 {
		t.Fatalf("approved operation = %+v, notify=%d", operation, notifier.count)
	}
	if persisted, err := service.GetPlan(context.Background(), scope.OwnerID, plan.EntryPlanID); err != nil || persisted.Status != PlanApproved {
		t.Fatalf("approved plan = %+v, %v", persisted, err)
	}
}

func TestServiceRechecksDeviceAtApproval(t *testing.T) {
	now := time.Date(2026, time.July, 17, 4, 30, 0, 0, time.UTC)
	scope := validScope(now)
	builder := &entryScopeBuilderFake{current: scope}
	repository := newEntryRepositoryFake()
	devices := cloudapproval.NewMemoryRegistry()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const signerKeyID = "device-0123456789abcdef01234567"
	if err := devices.PutDeviceKey(cloudapproval.DeviceKeyV1{KeyID: signerKeyID, AgentInstanceID: scope.AgentInstanceID, OwnerID: scope.OwnerID,
		Revision: 1, Status: cloudapproval.DeviceKeyActive, PublicKey: publicKey, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(scope.AgentInstanceID, repository, devices, builder, &entryNotifierFake{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	caller := task.MutationScope{ClientID: "message-server", CredentialID: "78787878-7878-4787-8787-787878787878"}
	plan, err := service.CreatePlan(context.Background(), CreatePlanCommand{Caller: caller, IdempotencyKey: "67676767-6767-4767-8767-676767676767",
		OwnerID: scope.OwnerID, DeploymentID: scope.Worker.DeploymentID, ExpectedDeploymentRevision: scope.Worker.DeploymentRevision, Draft: draftFromScope(scope)})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := service.Prepare(context.Background(), PrepareCommand{Caller: caller, IdempotencyKey: "57575757-5757-4757-8757-575757575757",
		OwnerID: scope.OwnerID, EntryPlanID: plan.EntryPlanID, ExpectedRevision: plan.Revision, SignerKeyID: signerKeyID})
	if err != nil {
		t.Fatal(err)
	}
	// The challenge was signed by a device that is no longer valid when the
	// approval arrives. The service must re-read the registry rather than rely
	// on the prepare-time lookup.
	if err := devices.PutDeviceKey(cloudapproval.DeviceKeyV1{KeyID: signerKeyID, AgentInstanceID: scope.AgentInstanceID, OwnerID: scope.OwnerID,
		Revision: 2, Status: cloudapproval.DeviceKeyRevoked, PublicKey: publicKey, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), RevokedAt: &now}); err != nil {
		t.Fatal(err)
	}
	signature := SignatureV1{ApprovalID: challenge.ApprovalID, ChallengeID: challenge.ChallengeID, EntryPlanID: challenge.EntryPlanID,
		EntryPlanRevision: challenge.EntryPlanRevision, PlanHash: challenge.PlanHash, ScopeDigest: challenge.ScopeDigest, SignerKeyID: challenge.SignerKeyID,
		ExpiresAt: challenge.ExpiresAt, Signature: ed25519.Sign(privateKey, challenge.SigningCBOR)}
	if _, err := service.Approve(context.Background(), ApproveCommand{Caller: caller, IdempotencyKey: "37373737-3737-4737-8737-373737373737",
		OwnerID: scope.OwnerID, EntryPlanID: plan.EntryPlanID, ExpectedRevision: plan.Revision, Signature: signature}); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("Approve() revoked device error = %v, want approval required", err)
	}
}

func TestServiceDoesNotExposeBuilderErrorDetails(t *testing.T) {
	now := time.Date(2026, time.July, 17, 5, 30, 0, 0, time.UTC)
	scope := validScope(now)
	builder := &entryScopeBuilderFake{current: scope, buildErr: errors.New("provider diagnostic contains a credential-shaped canary: sk-1234567890abcdef")}
	service, err := NewService(scope.AgentInstanceID, newEntryRepositoryFake(), cloudapproval.NewMemoryRegistry(), builder, &entryNotifierFake{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.CreatePlan(context.Background(), CreatePlanCommand{Caller: task.MutationScope{ClientID: "message-server", CredentialID: "78787878-7878-4787-8787-787878787878"},
		IdempotencyKey: "67676767-6767-4767-8767-676767676767", OwnerID: scope.OwnerID, DeploymentID: scope.Worker.DeploymentID,
		ExpectedDeploymentRevision: scope.Worker.DeploymentRevision, Draft: draftFromScope(scope)})
	if !errors.Is(err, ErrReadBackRequired) || strings.Contains(err.Error(), "sk-1234567890abcdef") {
		t.Fatalf("CreatePlan() error = %v, want de-sensitized read-back error", err)
	}
}

func draftFromScope(scope ScopeV1) DraftV1 {
	publicSubnets := make([]string, 0, len(scope.ALB.PublicSubnets))
	for _, subnet := range scope.ALB.PublicSubnets {
		publicSubnets = append(publicSubnets, subnet.SubnetID)
	}
	return DraftV1{Hostname: scope.Certificate.Hostname, CertificateARN: scope.Certificate.CertificateARN, PublicSubnetIDs: publicSubnets,
		TargetPort: scope.ALB.TargetPort, HealthPath: scope.Health.Path, ExpectedHealthStatusCode: scope.Health.ExpectedStatusCode,
		RecipeHealthContractDigest: scope.Recipe.HealthContractDigest, RecipeAuthenticationDigest: scope.Recipe.AuthenticationContractDigest, Cost: scope.Cost}
}

type entryScopeBuilderFake struct {
	current  ScopeV1
	buildErr error
}

func (fake *entryScopeBuilderFake) BuildEntryScope(_ context.Context, _ ScopeBuildRequest) (ScopeV1, error) {
	if fake.buildErr != nil {
		return ScopeV1{}, fake.buildErr
	}
	return fake.current, nil
}

func (fake *entryScopeBuilderFake) RevalidateEntryScope(_ context.Context, _ ScopeV1) (ScopeV1, error) {
	return fake.current, nil
}

type entryNotifierFake struct{ count int }

func (fake *entryNotifierFake) NotifyEntrypoint() { fake.count++ }

type entryRepositoryFake struct {
	plans      map[string]PlanV1
	challenges map[string]ChallengeV1
	operations map[string]OperationV1
}

func newEntryRepositoryFake() *entryRepositoryFake {
	return &entryRepositoryFake{plans: map[string]PlanV1{}, challenges: map[string]ChallengeV1{}, operations: map[string]OperationV1{}}
}

func (fake *entryRepositoryFake) CreateEntryPlan(_ context.Context, mutation Mutation, plan PlanV1) (PlanV1, error) {
	if err := mutation.Validate(); err != nil {
		return PlanV1{}, err
	}
	if existing, found := fake.plans[plan.EntryPlanID]; found {
		return existing, nil
	}
	fake.plans[plan.EntryPlanID] = plan
	return plan, nil
}

func (fake *entryRepositoryFake) GetEntryPlan(_ context.Context, ownerID, entryPlanID string) (PlanV1, error) {
	plan, found := fake.plans[entryPlanID]
	if !found || plan.Scope.OwnerID != ownerID {
		return PlanV1{}, ErrNotFound
	}
	return plan, nil
}

func (fake *entryRepositoryFake) CreateEntryChallenge(_ context.Context, mutation Mutation, challenge ChallengeV1) (ChallengeV1, error) {
	if err := mutation.Validate(); err != nil {
		return ChallengeV1{}, err
	}
	if existing, found := fake.challenges[challenge.ChallengeID]; found {
		return existing, nil
	}
	fake.challenges[challenge.ChallengeID] = challenge
	fake.operations[challenge.OperationID] = OperationV1{Challenge: challenge, Status: StatusAwaitingApproval, Revision: 1, CreatedAt: challenge.IssuedAt, UpdatedAt: challenge.IssuedAt}
	return challenge, nil
}

func (fake *entryRepositoryFake) GetEntryChallenge(_ context.Context, ownerID, challengeID string) (ChallengeV1, error) {
	challenge, found := fake.challenges[challengeID]
	if !found {
		return ChallengeV1{}, ErrNotFound
	}
	plan, found := fake.plans[challenge.EntryPlanID]
	if !found || plan.Scope.OwnerID != ownerID {
		return ChallengeV1{}, ErrNotFound
	}
	return challenge, nil
}

func (fake *entryRepositoryFake) ApproveEntry(_ context.Context, mutation Mutation, challengeID string, expectedRevision uint64, signature SignatureV1, approvedAt time.Time) (OperationV1, error) {
	if err := mutation.Validate(); err != nil {
		return OperationV1{}, err
	}
	challenge, found := fake.challenges[challengeID]
	if !found {
		return OperationV1{}, ErrNotFound
	}
	operation := fake.operations[challenge.OperationID]
	if operation.Status != StatusAwaitingApproval {
		return operation, nil
	}
	plan, found := fake.plans[challenge.EntryPlanID]
	if !found || plan.Revision != expectedRevision || challenge.EntryPlanRevision != expectedRevision {
		return OperationV1{}, ErrRevisionConflict
	}
	approved := approvedAt
	operation.Status, operation.Signature, operation.ApprovedAt = StatusApproved, &signature, &approved
	operation.Revision++
	operation.UpdatedAt = approved
	fake.operations[operation.Challenge.OperationID] = operation
	plan.Status = PlanApproved
	fake.plans[plan.EntryPlanID] = plan
	return operation, nil
}

func (fake *entryRepositoryFake) GetEntryOperation(_ context.Context, ownerID, operationID string) (OperationV1, error) {
	operation, found := fake.operations[operationID]
	if !found {
		return OperationV1{}, ErrNotFound
	}
	plan, found := fake.plans[operation.Challenge.EntryPlanID]
	if !found || plan.Scope.OwnerID != ownerID {
		return OperationV1{}, ErrNotFound
	}
	return operation, nil
}

func (fake *entryRepositoryFake) ListPendingEntry(_ context.Context, _ int) ([]OperationV1, error) {
	result := make([]OperationV1, 0)
	for _, operation := range fake.operations {
		if operation.Status == StatusApproved || operation.Status == StatusProvisioning || operation.Status == StatusVerifying || operation.Status == StatusDestroying {
			result = append(result, operation)
		}
	}
	return result, nil
}

func (fake *entryRepositoryFake) SaveEntryOperation(_ context.Context, operation OperationV1, expectedRevision int64) (OperationV1, error) {
	existing, found := fake.operations[operation.Challenge.OperationID]
	if !found {
		return OperationV1{}, ErrNotFound
	}
	if existing.Revision != expectedRevision {
		return OperationV1{}, ErrRevisionConflict
	}
	operation.Revision = expectedRevision + 1
	fake.operations[operation.Challenge.OperationID] = operation
	return operation, nil
}
