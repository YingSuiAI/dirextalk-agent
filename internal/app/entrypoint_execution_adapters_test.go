package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestEntrypointScopeRevalidatorRejectsChangedReadBackFacts(t *testing.T) {
	signed := entryExecutionAdapterScope(t)
	fresh := signed
	fresh.Certificate.ReadBackDigest = entryTestDigest('a')
	revalidator := entrypointScopeRevalidator{builder: entryExecutionScopeBuilderFake{scope: fresh}}

	err := revalidator.RevalidateScope(context.Background(), signed)
	if !errors.Is(err, entrypoint.ErrRevisionConflict) {
		t.Fatalf("RevalidateScope() error = %v, want fact-drift rejection", err)
	}
}

func TestEntrypointScopeRevalidatorAllowsFreshObservationTimestamps(t *testing.T) {
	signed := entryExecutionAdapterScope(t)
	fresh := signed
	fresh.Worker.ReadBack.ObservedAt = fresh.Worker.ReadBack.ObservedAt.Add(time.Minute)
	fresh.Certificate.ObservedAt = fresh.Certificate.ObservedAt.Add(time.Minute)
	for index := range fresh.ALB.PublicSubnets {
		fresh.ALB.PublicSubnets[index].ObservedAt = fresh.ALB.PublicSubnets[index].ObservedAt.Add(time.Minute)
	}
	revalidator := entrypointScopeRevalidator{builder: entryExecutionScopeBuilderFake{scope: fresh}}

	if err := revalidator.RevalidateScope(context.Background(), signed); err != nil {
		t.Fatalf("RevalidateScope() error = %v, want matching fresh facts", err)
	}
}

func TestEntrypointScopedProvisionerRejectsConnectionAndScopeMismatch(t *testing.T) {
	scope := entryExecutionAdapterScope(t)
	baseConnection := cloudapp.Connection{ConnectionID: scope.ConnectionID, OwnerID: scope.OwnerID, AccountID: "123456789012", Region: scope.Region, Status: "active"}
	for _, test := range []struct {
		name       string
		connection cloudapp.Connection
		mutateSpec func(*resource.ProvisionSpec)
	}{
		{name: "connection owner", connection: cloudapp.Connection{ConnectionID: scope.ConnectionID, OwnerID: "other-owner", AccountID: baseConnection.AccountID, Region: scope.Region, Status: "active"}},
		{name: "connection region", connection: cloudapp.Connection{ConnectionID: scope.ConnectionID, OwnerID: scope.OwnerID, AccountID: baseConnection.AccountID, Region: "us-west-2", Status: "active"}},
		{name: "resource owner", connection: baseConnection, mutateSpec: func(spec *resource.ProvisionSpec) { spec.OwnerID = "other-owner" }},
		{name: "resource region", connection: baseConnection, mutateSpec: func(spec *resource.ProvisionSpec) { spec.Region = "us-west-2" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			connections := &entryExecutionConnectionFake{connection: test.connection}
			dynamic := &entryExecutionDynamicProvisionerFake{}
			provisioner := entrypointScopedProvisioner{connections: connections, provisioner: dynamic}
			spec := entryExecutionProvisionSpec(scope)
			if test.mutateSpec != nil {
				test.mutateSpec(&spec)
			}

			_, err := provisioner.Provision(context.Background(), scope, spec, resource.ProviderCreateAuthorization{})
			if !errors.Is(err, entrypoint.ErrReadBackRequired) {
				t.Fatalf("Provision() error = %v, want scope rejection", err)
			}
			if dynamic.calls != 0 {
				t.Fatal("connection or scope mismatch reached the dynamic AWS provisioner")
			}
			if test.mutateSpec == nil && (connections.ownerID != scope.OwnerID || connections.connectionID != scope.ConnectionID) {
				t.Fatalf("connection lookup = (%q, %q), want signed owner/connection", connections.ownerID, connections.connectionID)
			}
			if test.mutateSpec != nil && connections.calls != 0 {
				t.Fatal("resource-scope mismatch looked up a cloud connection")
			}
		})
	}
}

func TestEntrypointScopedProvisionerUsesOnlySignedConnectionScope(t *testing.T) {
	scope := entryExecutionAdapterScope(t)
	connections := &entryExecutionConnectionFake{connection: cloudapp.Connection{ConnectionID: scope.ConnectionID, OwnerID: scope.OwnerID, AccountID: "123456789012", Region: scope.Region, Status: "active"}}
	dynamic := &entryExecutionDynamicProvisionerFake{result: resource.ResourceV1{ResourceID: uuid.NewString()}}
	provisioner := entrypointScopedProvisioner{connections: connections, provisioner: dynamic}
	spec := entryExecutionProvisionSpec(scope)

	if _, err := provisioner.Provision(context.Background(), scope, spec, resource.ProviderCreateAuthorization{}); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if dynamic.calls != 1 || dynamic.connection != connections.connection {
		t.Fatalf("dynamic provision = calls:%d connection:%#v, want one signed connection", dynamic.calls, dynamic.connection)
	}
	if connections.ownerID != scope.OwnerID || connections.connectionID != scope.ConnectionID {
		t.Fatalf("connection lookup = (%q, %q), want signed owner/connection", connections.ownerID, connections.connectionID)
	}
}

func TestEntrypointOperationPlanResolverAndOwnedResourceReaderKeepRecoveryScoped(t *testing.T) {
	scope := entryExecutionAdapterScope(t)
	plan := entrypoint.PlanV1{EntryPlanID: uuid.NewString()}
	plans := &entryExecutionPlanStoreFake{plan: plan}
	resolver := entrypointOperationPlanResolver{store: plans}
	operationID := uuid.NewString()
	if got, err := resolver.ResolveApprovedPlan(context.Background(), operationID); err != nil || got.EntryPlanID != plan.EntryPlanID || plans.operationID != operationID {
		t.Fatalf("ResolveApprovedPlan() = %#v, %v; store operation=%q", got, err, plans.operationID)
	}

	resources := []resource.ResourceV1{{ResourceID: uuid.NewString(), OwnerID: scope.OwnerID, DeploymentID: scope.Worker.DeploymentID}}
	statuses := &entryExecutionStatusReaderFake{resources: resources}
	reader := entrypointDeploymentResourceReader{statuses: statuses}
	got, err := reader.ListDeployment(context.Background(), scope.OwnerID, scope.Worker.DeploymentID)
	if err != nil || len(got) != 1 || statuses.ownerID != scope.OwnerID || statuses.deploymentID != scope.Worker.DeploymentID {
		t.Fatalf("ListDeployment() = %#v, %v; lookup=(%q,%q)", got, err, statuses.ownerID, statuses.deploymentID)
	}
}

func entryExecutionAdapterScope(t *testing.T) entrypoint.ScopeV1 {
	t.Helper()
	fixture := newEntrypointScopeBuilderFixture(t)
	builder, err := newEntrypointScopeBuilder(fixture.agentID, fixture.facts, fixture.connections, fixture.statuses, fixture.providers, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	scope, err := builder.BuildEntryScope(context.Background(), entrypoint.ScopeBuildRequest{
		AgentInstanceID: fixture.agentID, OwnerID: fixture.ownerID, DeploymentID: fixture.deployment.Worker.DeploymentID,
		ExpectedDeploymentRevision: fixture.deployment.Worker.Revision, Draft: fixture.draft,
	})
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func entryExecutionProvisionSpec(scope entrypoint.ScopeV1) resource.ProvisionSpec {
	retention := task.RetentionManaged
	if scope.Retention.Class == entrypoint.RetentionEphemeral {
		retention = task.RetentionEphemeralAutoDestroy
	}
	return resource.ProvisionSpec{AgentInstanceID: scope.AgentInstanceID, OwnerID: scope.OwnerID, TaskID: scope.Worker.TaskID,
		DeploymentID: scope.Worker.DeploymentID, Region: scope.Region, Retention: retention, DestroyDeadline: scope.Retention.DestroyDeadline,
		AutoDestroyApproved: scope.Retention.AutoDestroy}
}

type entryExecutionScopeBuilderFake struct {
	scope entrypoint.ScopeV1
	err   error
}

func (fake entryExecutionScopeBuilderFake) RevalidateEntryScope(context.Context, entrypoint.ScopeV1) (entrypoint.ScopeV1, error) {
	return fake.scope, fake.err
}

type entryExecutionConnectionFake struct {
	connection   cloudapp.Connection
	err          error
	calls        int
	ownerID      string
	connectionID string
}

func (fake *entryExecutionConnectionFake) LoadConnection(_ context.Context, ownerID, connectionID string) (cloudapp.Connection, error) {
	fake.calls++
	fake.ownerID, fake.connectionID = ownerID, connectionID
	return fake.connection, fake.err
}

type entryExecutionDynamicProvisionerFake struct {
	result     resource.ResourceV1
	err        error
	calls      int
	connection cloudapp.Connection
}

func (fake *entryExecutionDynamicProvisionerFake) Provision(_ context.Context, connection cloudapp.Connection, _ resource.ProvisionSpec, _ resource.ProviderCreateAuthorization) (resource.ResourceV1, error) {
	fake.calls++
	fake.connection = connection
	return fake.result, fake.err
}

type entryExecutionPlanStoreFake struct {
	plan        entrypoint.PlanV1
	err         error
	operationID string
}

func (fake *entryExecutionPlanStoreFake) GetEntryPlanForOperation(_ context.Context, operationID string) (entrypoint.PlanV1, error) {
	fake.operationID = operationID
	return fake.plan, fake.err
}

type entryExecutionStatusReaderFake struct {
	resources    []resource.ResourceV1
	err          error
	ownerID      string
	deploymentID string
}

func (fake *entryExecutionStatusReaderFake) ListDeploymentResources(_ context.Context, ownerID, deploymentID string) ([]resource.ResourceV1, error) {
	fake.ownerID, fake.deploymentID = ownerID, deploymentID
	return append([]resource.ResourceV1(nil), fake.resources...), fake.err
}
