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
