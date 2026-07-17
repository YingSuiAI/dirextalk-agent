package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/serviceoperation"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
)

func TestManagedPreparationSnapshotTemplateUsesOnlyCurrentAgentFacts(t *testing.T) {
	fixture := newManagedPreparationScopeFixture(t)
	fixture.current.deployment.Worker.CreatedAt = fixture.current.deployment.Worker.UpdatedAt.Add(-2 * time.Hour)
	fixture.facts.draft.CreatedAt = fixture.current.deployment.Worker.UpdatedAt.Add(-3 * time.Hour)
	fixture.facts.draft.UpdatedAt = fixture.current.deployment.Worker.UpdatedAt.Add(-time.Hour)
	scope := managedPreparationScopeForDownstreamTest(t, fixture, "11111111-1111-4111-8111-111111111111")
	facts := &templateFactsFake{planning: fixture.facts, current: fixture.current}
	port, err := newManagedPreparationSnapshotTemplates(facts)
	if err != nil {
		t.Fatal(err)
	}
	first, resources, err := port.LoadManagedSnapshotTemplate(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := port.LoadManagedSnapshotTemplate(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if first.Scope.ServiceID != second.Scope.ServiceID || first.Scope.AcceptanceID != second.Scope.AcceptanceID ||
		first.Service.Name != fixture.facts.draft.Recipe.Name || first.Recipe.Digest != fixture.facts.draft.Digest ||
		first.Service.Status != "awaiting_management_acceptance" ||
		len(first.Service.Backups) != 0 || len(first.Service.Restores) != 0 || len(resources) != len(fixture.current.resources) {
		t.Fatalf("unexpected template: %#v", first)
	}

	facts.current.deployment.Worker.Revision++
	if _, _, err := port.LoadManagedSnapshotTemplate(context.Background(), scope); !errors.Is(err, serviceoperation.ErrRevisionConflict) {
		t.Fatalf("stale deployment revision error = %v", err)
	}
}

func TestManagedPreparationRecoveryIsDefaultOffAndUsesRecoverableLedger(t *testing.T) {
	repository := &recoverableOperationsFake{values: []serviceoperation.OperationV1{{OperationID: "operation"}}}
	executor := &preparationExecutorFake{}
	disabled, err := newManagedPreparationRecoveryController(repository, executor, staticManagedPreparationAWSGate(false), 16)
	if err != nil {
		t.Fatal(err)
	}
	if err := disabled.RunOnce(context.Background()); err != nil || repository.calls != 0 || executor.calls != 0 {
		t.Fatalf("disabled recovery touched operations: list=%d execute=%d err=%v", repository.calls, executor.calls, err)
	}
	enabled, _ := newManagedPreparationRecoveryController(repository, executor, staticManagedPreparationAWSGate(true), 16)
	if err := enabled.RunOnce(context.Background()); err != nil || repository.calls != 1 || executor.calls != 1 {
		t.Fatalf("enabled recovery: list=%d execute=%d err=%v", repository.calls, executor.calls, err)
	}
}

func TestManagedPreparationAWSCompositionOptionIsDefaultOff(t *testing.T) {
	options := cloudCompositionOptions{}
	if options.enableManagedPreparationAWS {
		t.Fatal("ManagedPreparation AWS unexpectedly enabled by default")
	}
	WithManagedPreparationAWS()(&options)
	if !options.enableManagedPreparationAWS {
		t.Fatal("explicit ManagedPreparation AWS option did not enable the gate")
	}
}

func TestManagedPreparationAWSRuntimeIsBoundToSignedConnectionRevisionAndRegion(t *testing.T) {
	fixture := newManagedPreparationScopeFixture(t)
	scope := managedPreparationScopeForDownstreamTest(t, fixture, "11111111-1111-4111-8111-111111111111")
	connection := cloudapp.Connection{
		ConnectionID: scope.ConnectionID, OwnerID: scope.OwnerID, AccountID: "123456789012",
		Region: "us-east-1", Status: "active", Revision: scope.ConnectionRevision,
	}
	runtimes := &managedPreparationRuntimeFake{err: errors.New("runtime reached")}
	port, err := newManagedPreparationResourceLifecycle(
		&managedPreparationConnectionFake{connection: connection}, runtimes, &managedPreparationResourceReaderFake{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := port.runtime(context.Background(), scope); err == nil || err.Error() != "runtime reached" || runtimes.calls != 1 {
		t.Fatalf("exact connection did not reach runtime: calls=%d err=%v", runtimes.calls, err)
	}

	connection.Revision++
	drifted, _ := newManagedPreparationResourceLifecycle(
		&managedPreparationConnectionFake{connection: connection}, runtimes, &managedPreparationResourceReaderFake{},
	)
	if _, _, err := drifted.runtime(context.Background(), scope); !errors.Is(err, serviceoperation.ErrRevisionConflict) ||
		runtimes.calls != 1 {
		t.Fatalf("revision drift reached AWS runtime: calls=%d err=%v", runtimes.calls, err)
	}
}

type templateFactsFake struct {
	planning *managedPreparationFactsFake
	current  *managedPreparationCurrentFake
}

func (fake *templateFactsFake) GetDeployment(ctx context.Context, ownerID, deploymentID string) (cloudstatus.Deployment, error) {
	return fake.current.GetDeployment(ctx, ownerID, deploymentID)
}
func (fake *templateFactsFake) ListDeploymentResources(ctx context.Context, ownerID, deploymentID string) ([]resource.ResourceV1, error) {
	return fake.current.ListDeploymentResources(ctx, ownerID, deploymentID)
}
func (fake *templateFactsFake) ResolveRecipeDraft(ctx context.Context, ownerID, recipeID, digest string) (planning.RecipeDraft, error) {
	return fake.planning.ResolveRecipeDraft(ctx, ownerID, recipeID, digest)
}

type recoverableOperationsFake struct {
	serviceoperation.Repository
	values []serviceoperation.OperationV1
	calls  int
}

func (fake *recoverableOperationsFake) ListRecoverableServiceOperations(context.Context, int) ([]serviceoperation.OperationV1, error) {
	fake.calls++
	return fake.values, nil
}

type preparationExecutorFake struct{ calls int }

func (fake *preparationExecutorFake) Execute(context.Context, serviceoperation.OperationV1) (serviceoperation.PreparationReceiptV1, error) {
	fake.calls++
	return serviceoperation.PreparationReceiptV1{}, nil
}

type managedPreparationConnectionFake struct {
	connection cloudapp.Connection
}

func (fake *managedPreparationConnectionFake) LoadConnection(context.Context, string, string) (cloudapp.Connection, error) {
	return fake.connection, nil
}

type managedPreparationRuntimeFake struct {
	calls int
	err   error
}

func (fake *managedPreparationRuntimeFake) ManagedPreparationRuntime(context.Context, cloudapp.Connection) (*resource.Service, awsprovider.VolumeAttachmentProvider, error) {
	fake.calls++
	return nil, nil, fake.err
}

type managedPreparationResourceReaderFake struct{}

func (*managedPreparationResourceReaderFake) Get(context.Context, string) (resource.ResourceV1, error) {
	return resource.ResourceV1{}, resource.ErrNotFound
}
