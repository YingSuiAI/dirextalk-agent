package cloudexecution

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	clouddestroy "github.com/YingSuiAI/dirextalk-agent/internal/cloud/destroy"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestEphemeralDestroyControllerRunsAfterTerminalGrace(t *testing.T) {
	fixture := newEphemeralDestroyFixture(t)
	fixture.now = fixture.task.UpdatedAt.Add(30 * time.Minute)

	if err := fixture.controller(t).RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if fixture.lifecycle.scheduleCalls != 1 || fixture.lifecycle.destroyCalls != 1 {
		t.Fatalf("lifecycle calls schedule=%d destroy=%d", fixture.lifecycle.scheduleCalls, fixture.lifecycle.destroyCalls)
	}
	if got := fixture.lifecycle.lastDestroy; got.DeploymentID != fixture.operation.DeploymentID || got.OwnerID != fixture.plan.OwnerID || got.ApprovalID != fixture.approval.ApprovalID {
		t.Fatalf("Destroy() request = %#v", got)
	}
}

func TestEphemeralDestroyControllerWaitsForTerminalGrace(t *testing.T) {
	fixture := newEphemeralDestroyFixture(t)
	fixture.now = fixture.task.UpdatedAt.Add(30*time.Minute - time.Nanosecond)

	if err := fixture.controller(t).RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	fixture.requireNoLifecycleCalls(t)
}

func TestEphemeralDestroyControllerNeverDestroysManagedResources(t *testing.T) {
	fixture := newEphemeralDestroyFixture(t)
	fixture.resources[0].Retention = task.RetentionManaged
	fixture.resources[0].State = resource.StateRetainedManaged
	fixture.resources[0].DestroyDeadline = time.Time{}
	fixture.resources[0].AutoDestroyApproved = false
	fixture.now = fixture.operation.CreatedAt.Add(48 * time.Hour)

	if err := fixture.controller(t).RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	fixture.requireNoLifecycleCalls(t)
}

func TestEphemeralDestroyControllerEnforcesMaximumLifetimeBeforeTaskTerminal(t *testing.T) {
	fixture := newEphemeralDestroyFixture(t)
	fixture.task.ExecutionStatus = task.ExecutionRunning
	fixture.task.OutcomeStatus = task.OutcomePending
	fixture.now = fixture.operation.CreatedAt.Add(24 * time.Hour)

	if err := fixture.controller(t).RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if fixture.lifecycle.destroyCalls != 1 {
		t.Fatalf("Destroy() calls = %d, want 1", fixture.lifecycle.destroyCalls)
	}
}

func TestEphemeralDestroyControllerFailsClosedOnFactMismatch(t *testing.T) {
	fixture := newEphemeralDestroyFixture(t)
	fixture.connection.OwnerID = "different-owner"
	fixture.now = fixture.operation.CreatedAt.Add(24 * time.Hour)

	err := fixture.controller(t).RunOnce(context.Background())
	if !errors.Is(err, ErrLifecycleFactsMismatch) {
		t.Fatalf("RunOnce() error = %v, want ErrLifecycleFactsMismatch", err)
	}
	fixture.requireNoLifecycleCalls(t)
}

func TestEphemeralDestroyControllerRetriesBlockedDestruction(t *testing.T) {
	fixture := newEphemeralDestroyFixture(t)
	fixture.now = fixture.operation.CreatedAt.Add(24 * time.Hour)
	fixture.lifecycle.destroyResults = []resource.DestroyResult{{Blocked: true}, {Blocked: false}}
	controller := fixture.controller(t)

	if err := controller.RunOnce(context.Background()); err != nil {
		t.Fatalf("first RunOnce() error = %v", err)
	}
	if err := controller.RunOnce(context.Background()); err != nil {
		t.Fatalf("second RunOnce() error = %v", err)
	}
	if fixture.lifecycle.scheduleCalls != 2 || fixture.lifecycle.destroyCalls != 2 {
		t.Fatalf("lifecycle calls schedule=%d destroy=%d, want two retry attempts", fixture.lifecycle.scheduleCalls, fixture.lifecycle.destroyCalls)
	}
}

func TestEphemeralDestroyControllerExecutesPersistedManualApprovalAndRequiresReadBack(t *testing.T) {
	fixture := newEphemeralDestroyFixture(t)
	prepareManualDestroyResource(&fixture.resources[0], fixture.plan, fixture.approval)
	verified := fixture.resources[0]
	verified.State = resource.StateVerifiedDestroyed
	verified.ReadBack.Exists = false
	verified.ReadBack.ObservedAt = fixture.now.Add(time.Second)
	fixture.lifecycle.scheduled = append([]resource.ResourceV1(nil), fixture.resources...)
	fixture.lifecycle.destroyResults = []resource.DestroyResult{{Resources: []resource.ResourceV1{verified}}}
	scope := manualDestroyScope(fixture)
	repository := &fakeManualDestroyRepository{operation: manualDestroyOperation(t, scope)}
	controller := fixture.controller(t)
	if err := controller.ConfigureManualDestroy(repository, fakeManualScopeReader{scope: scope}); err != nil {
		t.Fatal(err)
	}

	if err := controller.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if repository.operation.Status != clouddestroy.StatusVerifiedDestroyed || fixture.lifecycle.destroyCalls != 1 {
		t.Fatalf("manual destroy status=%s destroy_calls=%d", repository.operation.Status, fixture.lifecycle.destroyCalls)
	}
}

func TestEphemeralDestroyControllerBlocksManualApprovalOnExactScopeDrift(t *testing.T) {
	fixture := newEphemeralDestroyFixture(t)
	prepareManualDestroyResource(&fixture.resources[0], fixture.plan, fixture.approval)
	scope := manualDestroyScope(fixture)
	drifted := scope
	drifted.Resources = append([]clouddestroy.ResourceScopeV1(nil), scope.Resources...)
	drifted.Resources[0].Revision++
	repository := &fakeManualDestroyRepository{operation: manualDestroyOperation(t, scope)}
	controller := fixture.controller(t)
	if err := controller.ConfigureManualDestroy(repository, fakeManualScopeReader{scope: drifted}); err != nil {
		t.Fatal(err)
	}

	if err := controller.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if repository.operation.Status != clouddestroy.StatusDestroyBlocked || repository.operation.ErrorCode != "scope_revision_changed" {
		t.Fatalf("manual destroy operation=%#v", repository.operation)
	}
	fixture.requireNoLifecycleCalls(t)
}

type ephemeralDestroyFixture struct {
	agentID    string
	now        time.Time
	operation  Operation
	plan       cloudapproval.PlanV1
	approval   cloudapproval.ApprovalV1
	connection cloudapp.Connection
	task       task.Task
	resources  []resource.ResourceV1
	lifecycle  *fakeDestroyLifecycle
}

func newEphemeralDestroyFixture(t *testing.T) *ephemeralDestroyFixture {
	t.Helper()
	planTime := time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)
	launch := newLaunchFixture(t, planTime)
	plan := launch.service.facts.(fakeFacts).plan
	approval := launch.service.facts.(fakeFacts).approval
	connection := launch.connections.value
	deploymentID, taskID := uuid.NewString(), uuid.NewString()
	operationCreatedAt := planTime.Add(time.Hour)
	operation := Operation{
		Intent: Intent{
			Launch:       LaunchRequest{OwnerID: plan.OwnerID, PlanID: plan.PlanID, ApprovalID: approval.ApprovalID},
			ConnectionID: plan.ConnectionID, ApprovedPlanHash: approval.PlanHash, DeploymentID: deploymentID,
		},
		State: StateActive, TaskID: taskID, CreatedAt: operationCreatedAt, UpdatedAt: operationCreatedAt,
	}
	taskValue := task.Task{
		TaskID: taskID, OwnerID: plan.OwnerID, ExecutionStatus: task.ExecutionFinished, OutcomeStatus: task.OutcomeSucceeded,
		RetentionPolicy: task.RetentionEphemeralAutoDestroy, ApprovedPlanID: plan.PlanID,
		Revision: 2, CreatedAt: operationCreatedAt, UpdatedAt: operationCreatedAt.Add(time.Hour),
	}
	resourceValue := resource.ResourceV1{
		ResourceID: uuid.NewString(), AgentInstanceID: plan.AgentInstanceID, OwnerID: plan.OwnerID, TaskID: taskID,
		DeploymentID: deploymentID, ApprovedPlanHash: approval.PlanHash, ApprovalID: approval.ApprovalID,
		Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: operationCreatedAt.Add(24 * time.Hour),
		AutoDestroyApproved: true, State: resource.StateActive,
	}
	lifecycle := &fakeDestroyLifecycle{scheduled: []resource.ResourceV1{resourceValue}}
	return &ephemeralDestroyFixture{
		agentID: plan.AgentInstanceID, now: operationCreatedAt, operation: operation, plan: plan, approval: approval,
		connection: connection, task: taskValue, resources: []resource.ResourceV1{resourceValue}, lifecycle: lifecycle,
	}
}

func (fixture *ephemeralDestroyFixture) controller(t *testing.T) *EphemeralDestroyController {
	t.Helper()
	controller, err := NewEphemeralDestroyController(EphemeralDestroyConfig{
		AgentInstanceID: fixture.agentID,
		PollInterval:    time.Second,
		Resources:       fakeDestroyResourceReader{resources: fixture.resources},
		Launches:        fakeDestroyLaunchReader{operation: fixture.operation},
		Facts:           fakeDestroyFacts{plan: fixture.plan, approval: fixture.approval},
		Connections:     fakeDestroyConnections{connection: fixture.connection},
		Tasks:           fakeDestroyTasks{task: fixture.task},
		Lifecycles:      &fakeDestroyLifecycleFactory{lifecycle: fixture.lifecycle},
		Now:             func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func (fixture *ephemeralDestroyFixture) requireNoLifecycleCalls(t *testing.T) {
	t.Helper()
	if fixture.lifecycle.scheduleCalls != 0 || fixture.lifecycle.destroyCalls != 0 {
		t.Fatalf("unexpected lifecycle calls schedule=%d destroy=%d", fixture.lifecycle.scheduleCalls, fixture.lifecycle.destroyCalls)
	}
}

type fakeDestroyResourceReader struct{ resources []resource.ResourceV1 }

func (reader fakeDestroyResourceReader) ListByAgent(context.Context, string) ([]resource.ResourceV1, error) {
	return append([]resource.ResourceV1(nil), reader.resources...), nil
}

type fakeDestroyLaunchReader struct{ operation Operation }

func (reader fakeDestroyLaunchReader) GetByDeployment(context.Context, string) (Operation, error) {
	return reader.operation, nil
}

type fakeDestroyFacts struct {
	plan     cloudapproval.PlanV1
	approval cloudapproval.ApprovalV1
}

func (facts fakeDestroyFacts) LoadPlan(context.Context, string, string) (cloudapproval.PlanV1, error) {
	return facts.plan, nil
}

func (facts fakeDestroyFacts) LoadApproval(context.Context, string, string) (cloudapproval.ApprovalV1, error) {
	return facts.approval, nil
}

type fakeDestroyConnections struct{ connection cloudapp.Connection }

func (connections fakeDestroyConnections) LoadConnection(context.Context, string, string) (cloudapp.Connection, error) {
	return connections.connection, nil
}

type fakeDestroyTasks struct{ task task.Task }

func (tasks fakeDestroyTasks) Get(context.Context, string) (task.Task, error) { return tasks.task, nil }

type fakeDestroyLifecycleFactory struct{ lifecycle ResourceLifecycle }

func (factory *fakeDestroyLifecycleFactory) ForConnection(context.Context, cloudapp.Connection) (ResourceLifecycle, error) {
	return factory.lifecycle, nil
}

type fakeDestroyLifecycle struct {
	scheduleCalls  int
	destroyCalls   int
	lastDestroy    resource.DestroyRequest
	scheduled      []resource.ResourceV1
	destroyResults []resource.DestroyResult
}

type fakeManualScopeReader struct{ scope clouddestroy.ScopeV1 }

func (reader fakeManualScopeReader) CurrentScope(context.Context, string, string) (clouddestroy.ScopeV1, error) {
	return reader.scope, nil
}

type fakeManualDestroyRepository struct{ operation clouddestroy.OperationV1 }

func (*fakeManualDestroyRepository) CreateDestroyChallenge(context.Context, clouddestroy.Mutation, clouddestroy.ChallengeV1) (clouddestroy.ChallengeV1, error) {
	panic("unused")
}
func (*fakeManualDestroyRepository) GetDestroyChallenge(context.Context, string, string) (clouddestroy.ChallengeV1, error) {
	panic("unused")
}
func (*fakeManualDestroyRepository) ApproveDestroy(context.Context, clouddestroy.Mutation, string, int64, clouddestroy.SignatureV1, time.Time) (clouddestroy.OperationV1, error) {
	panic("unused")
}
func (repository *fakeManualDestroyRepository) GetDestroyOperation(context.Context, string, string) (clouddestroy.OperationV1, error) {
	return repository.operation, nil
}
func (repository *fakeManualDestroyRepository) ListPendingDestroy(context.Context, int) ([]clouddestroy.OperationV1, error) {
	return []clouddestroy.OperationV1{repository.operation}, nil
}
func (repository *fakeManualDestroyRepository) SaveDestroyOperation(_ context.Context, next clouddestroy.OperationV1, expected int64) (clouddestroy.OperationV1, error) {
	if repository.operation.Revision != expected {
		return clouddestroy.OperationV1{}, clouddestroy.ErrRevisionConflict
	}
	next.Revision = expected + 1
	repository.operation = next
	return next, nil
}

func prepareManualDestroyResource(item *resource.ResourceV1, plan cloudapproval.PlanV1, approval cloudapproval.ApprovalV1) {
	item.Type, item.ProviderID, item.Region = resource.TypeEC2, "i-0123456789abcdef0", "us-east-1"
	item.SpecDigest, item.ApprovedPlanHash, item.ApprovalID = "sha256:"+strings.Repeat("1", 64), approval.PlanHash, approval.ApprovalID
	item.ReadBack = resource.ReadBackEvidence{Exists: true, ProviderID: item.ProviderID, ObservedAt: item.CreatedAt.Add(time.Second), TagDigest: "sha256:" + strings.Repeat("2", 64)}
	_ = plan
}

func manualDestroyScope(fixture *ephemeralDestroyFixture) clouddestroy.ScopeV1 {
	item := fixture.resources[0]
	return clouddestroy.NormalizeScope(clouddestroy.ScopeV1{SchemaVersion: clouddestroy.ScopeSchemaV1, AgentInstanceID: fixture.agentID,
		OwnerID: fixture.plan.OwnerID, DeploymentID: fixture.operation.DeploymentID, DeploymentRevision: item.Revision + 1, TaskID: fixture.operation.TaskID,
		PlanID: fixture.plan.PlanID, PlanHash: fixture.approval.PlanHash, ConnectionID: fixture.connection.ConnectionID,
		Resources: []clouddestroy.ResourceScopeV1{{ResourceID: item.ResourceID, Type: item.Type, ProviderID: item.ProviderID, Revision: item.Revision,
			Retention: item.Retention, State: item.State, Region: item.Region, SpecDigest: item.SpecDigest, ApprovedPlanHash: item.ApprovedPlanHash,
			OriginalApprovalID: item.ApprovalID, ReadBack: clouddestroy.ReadBackScopeV1{Observed: true, Exists: true, ProviderID: item.ProviderID,
				ObservedAt: item.ReadBack.ObservedAt, TagDigest: item.ReadBack.TagDigest}, DestroyDeadline: item.DestroyDeadline, AutoDestroyApproved: true}}})
}

func manualDestroyOperation(t *testing.T, scope clouddestroy.ScopeV1) clouddestroy.OperationV1 {
	t.Helper()
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	challenge := clouddestroy.ChallengeV1{OperationID: uuid.NewString(), ChallengeID: uuid.NewString(), ApprovalID: uuid.NewString(), SignerKeyID: "device-key",
		Scope: scope, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Revision: 1}
	var err error
	challenge.ScopeDigest, err = clouddestroy.ScopeDigest(scope)
	if err != nil {
		t.Fatal(err)
	}
	challenge.SigningCBOR, err = challenge.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	approvedAt := now.Add(time.Second)
	return clouddestroy.OperationV1{Challenge: challenge, Status: clouddestroy.StatusApproved, Signature: make([]byte, 64), Revision: 2,
		CreatedAt: now, UpdatedAt: approvedAt, ApprovedAt: &approvedAt}
}

func (lifecycle *fakeDestroyLifecycle) ScheduleDestroy(context.Context, string, string) ([]resource.ResourceV1, error) {
	lifecycle.scheduleCalls++
	result := append([]resource.ResourceV1(nil), lifecycle.scheduled...)
	for index := range result {
		if result[index].State == resource.StateActive {
			result[index].State = resource.StateDestroyScheduled
		}
	}
	return result, nil
}

func (lifecycle *fakeDestroyLifecycle) Destroy(_ context.Context, request resource.DestroyRequest) (resource.DestroyResult, error) {
	lifecycle.destroyCalls++
	lifecycle.lastDestroy = request
	if len(lifecycle.destroyResults) == 0 {
		return resource.DestroyResult{}, nil
	}
	result := lifecycle.destroyResults[0]
	lifecycle.destroyResults = lifecycle.destroyResults[1:]
	return result, nil
}
