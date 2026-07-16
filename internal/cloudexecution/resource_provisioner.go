package cloudexecution

import (
	"context"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
)

type ResourceRuntimeFactory interface {
	Runtime(context.Context, cloudapp.Connection) (resource.Provider, resource.ManifestMirror, error)
}

// DynamicResourceProvisioner creates a short-lived, connection-bound typed
// provider for each mutation. This prevents one AWS account or Region client
// from being accidentally reused for another connection while PostgreSQL
// remains the common authoritative ledger.
type DynamicResourceProvisioner struct {
	repository resource.Repository
	factory    ResourceRuntimeFactory
}

func NewDynamicResourceProvisioner(repository resource.Repository, factory ResourceRuntimeFactory) (*DynamicResourceProvisioner, error) {
	if repository == nil || factory == nil {
		return nil, ErrInvalid
	}
	return &DynamicResourceProvisioner{repository: repository, factory: factory}, nil
}

func (provisioner *DynamicResourceProvisioner) Provision(ctx context.Context, connection cloudapp.Connection, spec resource.ProvisionSpec, authorization resource.ProviderCreateAuthorization) (resource.ResourceV1, error) {
	if provisioner == nil || ctx == nil || connection.Status != "active" || connection.OwnerID != spec.OwnerID || connection.Region != spec.Region {
		return resource.ResourceV1{}, ErrInvalid
	}
	provider, mirror, err := provisioner.factory.Runtime(ctx, connection)
	if err != nil {
		return resource.ResourceV1{}, ErrUnavailable
	}
	service, err := resource.NewService(provisioner.repository, provider, mirror)
	if err != nil {
		return resource.ResourceV1{}, ErrUnavailable
	}
	return service.Provision(ctx, spec, authorization)
}
