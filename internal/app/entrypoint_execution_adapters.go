package app

import (
	"context"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entryexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
)

// entryOperationPlanStore deliberately has only the recovery lookup needed by
// the executor. The application owns the exceptional operation-ID lookup; it
// is never exposed through a caller-facing API.
type entryOperationPlanStore interface {
	GetEntryPlanForOperation(context.Context, string) (entrypoint.PlanV1, error)
}

type entrypointOperationPlanResolver struct{ store entryOperationPlanStore }

func (resolver entrypointOperationPlanResolver) ResolveApprovedPlan(ctx context.Context, operationID string) (entrypoint.PlanV1, error) {
	if resolver.store == nil || ctx == nil || strings.TrimSpace(operationID) == "" {
		return entrypoint.PlanV1{}, entrypoint.ErrInvalid
	}
	return resolver.store.GetEntryPlanForOperation(ctx, operationID)
}

// entryScopeRevalidationBuilder is intentionally the same narrow scope
// builder used before approval. It cannot obtain a provider mutation surface.
type entryScopeRevalidationBuilder interface {
	RevalidateEntryScope(context.Context, entrypoint.ScopeV1) (entrypoint.ScopeV1, error)
}

// entrypointScopeRevalidator verifies that a fresh read-back retains the same
// signed facts. A nil error alone is insufficient because a different Worker,
// certificate, subnet, connection, or health route could otherwise pass from
// a permissive builder implementation.
type entrypointScopeRevalidator struct{ builder entryScopeRevalidationBuilder }

func (revalidator entrypointScopeRevalidator) RevalidateScope(ctx context.Context, signed entrypoint.ScopeV1) error {
	if revalidator.builder == nil || ctx == nil || signed.Validate() != nil {
		return entrypoint.ErrInvalid
	}
	fresh, err := revalidator.builder.RevalidateEntryScope(ctx, signed)
	if err != nil {
		return mapEntrypointRevalidationError(err)
	}
	want, err := entrypoint.ScopeFactDigest(signed)
	if err != nil {
		return entrypoint.ErrInvalid
	}
	got, err := entrypoint.ScopeFactDigest(fresh)
	if err != nil {
		return entrypoint.ErrReadBackRequired
	}
	if want != got {
		return entrypoint.ErrRevisionConflict
	}
	return nil
}

func mapEntrypointRevalidationError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, entrypoint.ErrUnavailable):
		return err
	case errors.Is(err, entrypoint.ErrWorkerNotReady), errors.Is(err, entrypoint.ErrReadBackRequired), errors.Is(err, entrypoint.ErrUnsupportedEntry),
		errors.Is(err, entrypoint.ErrInvalid), errors.Is(err, entrypoint.ErrRevisionConflict):
		return err
	default:
		// Provider/database detail must not escape the background execution
		// boundary. A future retry receives a freshly constructed scope.
		return entrypoint.ErrReadBackRequired
	}
}

type entryDeploymentStatusReader interface {
	ListDeploymentResources(context.Context, string, string) ([]resource.ResourceV1, error)
}

// entrypointDeploymentResourceReader makes owner scope explicit for the
// executor. This prevents a recovery operation from using an unscoped ledger
// lookup merely because the pending-operation queue itself crosses owners.
type entrypointDeploymentResourceReader struct{ statuses entryDeploymentStatusReader }

func (reader entrypointDeploymentResourceReader) ListDeployment(ctx context.Context, ownerID, deploymentID string) ([]resource.ResourceV1, error) {
	if reader.statuses == nil || ctx == nil || strings.TrimSpace(ownerID) == "" || strings.TrimSpace(deploymentID) == "" {
		return nil, entrypoint.ErrInvalid
	}
	resources, err := reader.statuses.ListDeploymentResources(ctx, ownerID, deploymentID)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, entrypoint.ErrUnavailable
	}
	return resources, nil
}

type entryProvisionConnectionLoader interface {
	LoadConnection(context.Context, string, string) (cloudapp.Connection, error)
}

type entryDynamicProvisioner interface {
	Provision(context.Context, cloudapp.Connection, resource.ProvisionSpec, resource.ProviderCreateAuthorization) (resource.ResourceV1, error)
}

// entrypointScopedProvisioner binds every typed entry mutation to the exact
// signed connection, owner, region, Worker deployment and retention scope.
// The executor cannot infer a connection from a resource spec or gain an AWS
// SDK client through this port.
type entrypointScopedProvisioner struct {
	connections entryProvisionConnectionLoader
	provisioner entryDynamicProvisioner
}

func (provisioner entrypointScopedProvisioner) Provision(ctx context.Context, scope entrypoint.ScopeV1, spec resource.ProvisionSpec, authorization resource.ProviderCreateAuthorization) (resource.ResourceV1, error) {
	if provisioner.connections == nil || provisioner.provisioner == nil || ctx == nil || scope.Validate() != nil {
		return resource.ResourceV1{}, entrypoint.ErrInvalid
	}
	if !entryProvisionMatchesScope(scope, spec) {
		return resource.ResourceV1{}, entrypoint.ErrReadBackRequired
	}
	connection, err := provisioner.connections.LoadConnection(ctx, scope.OwnerID, scope.ConnectionID)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return resource.ResourceV1{}, err
		}
		if errors.Is(err, cloudexecution.ErrUnavailable) {
			return resource.ResourceV1{}, entrypoint.ErrUnavailable
		}
		return resource.ResourceV1{}, entrypoint.ErrReadBackRequired
	}
	if connection.ConnectionID != scope.ConnectionID || connection.OwnerID != scope.OwnerID || connection.Region != scope.Region ||
		connection.Status != "active" || strings.TrimSpace(connection.AccountID) == "" {
		return resource.ResourceV1{}, entrypoint.ErrReadBackRequired
	}
	return provisioner.provisioner.Provision(ctx, connection, spec, authorization)
}

func entryProvisionMatchesScope(scope entrypoint.ScopeV1, spec resource.ProvisionSpec) bool {
	retention := task.RetentionManaged
	if scope.Retention.Class == entrypoint.RetentionEphemeral {
		retention = task.RetentionEphemeralAutoDestroy
	}
	return spec.AgentInstanceID == scope.AgentInstanceID && spec.OwnerID == scope.OwnerID && spec.TaskID == scope.Worker.TaskID &&
		spec.DeploymentID == scope.Worker.DeploymentID && spec.Region == scope.Region && spec.Retention == retention &&
		spec.AutoDestroyApproved == scope.Retention.AutoDestroy && spec.DestroyDeadline.Equal(scope.Retention.DestroyDeadline.UTC())
}

var (
	_ entryexecution.PlanResolver             = entrypointOperationPlanResolver{}
	_ entryexecution.ScopeRevalidator         = entrypointScopeRevalidator{}
	_ entryexecution.DeploymentResourceReader = entrypointDeploymentResourceReader{}
	_ entryexecution.ResourceProvisioner      = entrypointScopedProvisioner{}
)
