package cloudexecution

import (
	"context"

	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
)

type WorkerServiceAdapter struct{ service *worker.Service }

func NewWorkerServiceAdapter(service *worker.Service) (*WorkerServiceAdapter, error) {
	if service == nil {
		return nil, ErrInvalid
	}
	return &WorkerServiceAdapter{service: service}, nil
}

func (adapter *WorkerServiceAdapter) CreateDeployment(ctx context.Context, mutation WorkerCreateMutation, request worker.CreateDeploymentRequest) (worker.Deployment, SensitiveCredential, error) {
	if adapter == nil || adapter.service == nil {
		return worker.Deployment{}, nil, ErrInvalid
	}
	created, credential, err := adapter.service.CreateDeployment(ctx, worker.ControlMutation{
		ClientID: mutation.ClientID, CredentialID: mutation.CredentialID, IdempotencyKey: mutation.IdempotencyKey,
	}, request)
	if err != nil {
		return worker.Deployment{}, nil, err
	}
	return created, &credential, nil
}

func (adapter *WorkerServiceAdapter) GetDeployment(
	ctx context.Context,
	deploymentID string,
) (worker.Deployment, error) {
	if adapter == nil || adapter.service == nil || ctx == nil {
		return worker.Deployment{}, ErrInvalid
	}
	return adapter.service.Get(ctx, deploymentID)
}

func (adapter *WorkerServiceAdapter) RequestCancel(
	ctx context.Context,
	deploymentID,
	reason string,
) (worker.Deployment, error) {
	if adapter == nil || adapter.service == nil || ctx == nil {
		return worker.Deployment{}, ErrInvalid
	}
	return adapter.service.RequestCancel(ctx, deploymentID, reason)
}

func (adapter *WorkerServiceAdapter) ExpireLease(
	ctx context.Context,
	deploymentID string,
) (worker.Deployment, error) {
	if adapter == nil || adapter.service == nil || ctx == nil {
		return worker.Deployment{}, ErrInvalid
	}
	return adapter.service.ExpireLease(ctx, deploymentID)
}
