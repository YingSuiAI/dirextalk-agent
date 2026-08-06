package coreteam

import (
	"context"
	"errors"
	"testing"
	"time"
)

type serviceRepository struct {
	plan      PlanRecord
	execution Execution
	page      Page
	scope     Scope
}

func (r *serviceRepository) CreatePlan(context.Context, CreatePlanCommand) (PlanRecord, bool, error) {
	return PlanRecord{}, false, ErrInvalid
}
func (r *serviceRepository) GetPlan(_ context.Context, scope Scope, _ string) (PlanRecord, error) {
	r.scope = scope
	return r.plan, nil
}
func (r *serviceRepository) CreateExecution(context.Context, CreateExecutionCommand) (Execution, bool, error) {
	return Execution{}, false, ErrInvalid
}
func (r *serviceRepository) GetExecution(_ context.Context, scope Scope, _ string) (Execution, error) {
	r.scope = scope
	return r.execution, nil
}
func (r *serviceRepository) ListExecutions(_ context.Context, query ListQuery) (Page, error) {
	r.scope = query.Scope
	return r.page, nil
}
func (r *serviceRepository) CompareAndSwapExecution(context.Context, Scope, Execution, uint64) (Execution, error) {
	return Execution{}, ErrInvalid
}
func (r *serviceRepository) ListRunnableRoles(context.Context, Scope, string, uint32) ([]RoleRun, error) {
	return nil, ErrInvalid
}

type serviceCancellationPort struct {
	request CancelExecutionRequest
	result  Execution
}

func (p *serviceCancellationPort) CancelExecution(_ context.Context, request CancelExecutionRequest) (Execution, error) {
	p.request = request
	return p.result, nil
}

func TestTeamCapabilityServiceRequiresAllDependencies(t *testing.T) {
	repository := &serviceRepository{}
	cancellation := &serviceCancellationPort{}
	if NewService(nil, cancellation).ReadyForPublication() || NewService(repository, nil).ReadyForPublication() {
		t.Fatal("Team service published without every dependency")
	}
	if !NewService(repository, cancellation).ReadyForPublication() {
		t.Fatal("fully wired Team service was not ready")
	}
}

func TestTeamCapabilityServicePreservesOwnerScopeAndClosedCancellation(t *testing.T) {
	now := time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)
	scope := Scope{OwnerID: "@team-owner:example.test", AccountGeneration: 7}
	plan := serviceTestPlan(t, scope, now)
	execution := Execution{
		ExecutionID: "66666666-6666-4666-8666-666666666666", PlanID: plan.PlanID,
		TaskID: plan.TaskID, ConfirmationID: plan.ConfirmationID,
		OwnerID: scope.OwnerID, AccountGeneration: scope.AccountGeneration,
		Status: ExecutionQueued, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	repository := &serviceRepository{
		plan: PlanRecord{Plan: plan, CreatedAt: now}, execution: execution,
		page: Page{Executions: []Execution{execution}, NextID: "77777777-7777-4777-8777-777777777777"},
	}
	cancellation := &serviceCancellationPort{result: execution}
	service := NewService(repository, cancellation)

	if _, err := service.GetPlan(context.Background(), scope, plan.PlanID); err != nil || repository.scope != scope {
		t.Fatalf("GetPlan scope=%+v err=%v", repository.scope, err)
	}
	if _, err := service.GetExecution(context.Background(), scope, execution.ExecutionID); err != nil || repository.scope != scope {
		t.Fatalf("GetExecution scope=%+v err=%v", repository.scope, err)
	}
	if _, err := service.ListExecutions(context.Background(), ListQuery{Scope: scope, Limit: 20}); err != nil || repository.scope != scope {
		t.Fatalf("ListExecutions scope=%+v err=%v", repository.scope, err)
	}
	request := CancelExecutionRequest{
		Scope: scope, ExecutionID: execution.ExecutionID, ExpectedRevision: 1,
		IdempotencyKey: "88888888-8888-4888-8888-888888888888",
	}
	if _, err := service.CancelExecution(context.Background(), request); err != nil || cancellation.request != request {
		t.Fatalf("CancelExecution request=%+v err=%v", cancellation.request, err)
	}

	invalid := request
	invalid.IdempotencyKey = "not-a-uuid"
	if _, err := service.CancelExecution(context.Background(), invalid); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid cancellation err=%v", err)
	}
}

func serviceTestPlan(t *testing.T, scope Scope, now time.Time) Plan {
	t.Helper()
	plan := Plan{
		PlanID: "11111111-1111-4111-8111-111111111111", OwnerID: scope.OwnerID,
		AccountGeneration: scope.AccountGeneration,
		TaskID:            "22222222-2222-4222-8222-222222222222",
		ConversationID:    "33333333-3333-4333-8333-333333333333",
		CredentialID:      "44444444-4444-4444-8444-444444444444",
		ConfirmationID:    "55555555-5555-4555-8555-555555555555",
		Revision:          1, CredentialRevision: 2, Goal: "prepare a release", Status: PlanWaitingUser,
		Runtime: RuntimeBinding{RuntimeID: OfficialRuntimeID, Adapter: AdapterPiV1, ImageDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", AMIID: "ami-0123456789abcdef0", OutputTokens: 4096},
		Quote:   QuoteBinding{Region: OsakaRegion, AvailabilityZone: "ap-northeast-3a", InstanceType: MVPInstanceType, Currency: "USD", Amount: "0.10", HardBudget: "1.00", ExpiresAt: now.Add(time.Hour)},
		Roles:   []Role{{RoleID: "builder", Goal: "build and test", Capabilities: []Capability{CapabilityShell, CapabilityTest}}},
	}
	var err error
	plan.Digest, err = plan.SemanticDigest()
	if err != nil || plan.Validate() != nil {
		t.Fatalf("fixture Plan invalid: %v", err)
	}
	return plan
}
