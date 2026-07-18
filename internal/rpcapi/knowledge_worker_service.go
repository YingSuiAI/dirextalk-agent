package rpcapi

import (
	"context"
	"errors"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/knowledgeworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type knowledgeWorkerControlHandler struct {
	agentv1.UnimplementedKnowledgeWorkerControlServiceServer
	workers workerControlBackend
	broker  *knowledgeworker.Broker
}

// NewKnowledgeWorkerControlService constructs the outbound-only Knowledge
// data plane. It shares the existing Worker session verifier and deliberately
// bypasses Service Key authentication.
func NewKnowledgeWorkerControlService(service *worker.Service, broker *knowledgeworker.Broker) agentv1.KnowledgeWorkerControlServiceServer {
	if service == nil {
		return newKnowledgeWorkerControlHandler(nil, broker)
	}
	return newKnowledgeWorkerControlHandler(domainWorkerBackend{service: service}, broker)
}

func newKnowledgeWorkerControlHandler(workers workerControlBackend, broker *knowledgeworker.Broker) *knowledgeWorkerControlHandler {
	return &knowledgeWorkerControlHandler{workers: workers, broker: broker}
}

func (service *knowledgeWorkerControlHandler) AcquireKnowledgeOperation(ctx context.Context, request *agentv1.AcquireKnowledgeOperationRequest) (*agentv1.AcquireKnowledgeOperationResponse, error) {
	cleanCtx, credential, err := workerCredentialFromContext(ctx, workerSessionAuthorizationScheme, workerSessionTokenPrefix)
	if err != nil {
		return nil, err
	}
	defer wipeWorkerBytes(credential)
	if service == nil || service.workers == nil || service.broker == nil {
		return nil, status.Error(codes.Unavailable, "Knowledge Worker control is not configured")
	}
	assignment, err := service.authorize(cleanCtx, request.GetDeploymentId(), request.GetWorkerId(), credential)
	if err != nil {
		return nil, err
	}
	operation, err := service.broker.Acquire(cleanCtx, assignment.OwnerID, request.GetDeploymentId(), time.Duration(request.GetLeaseDurationSeconds())*time.Second)
	if err != nil {
		return nil, knowledgeWorkerPublicError(err)
	}
	return &agentv1.AcquireKnowledgeOperationResponse{Operation: operation}, nil
}

func (service *knowledgeWorkerControlHandler) CompleteKnowledgeOperation(ctx context.Context, request *agentv1.CompleteKnowledgeOperationRequest) (*agentv1.CompleteKnowledgeOperationResponse, error) {
	cleanCtx, credential, err := workerCredentialFromContext(ctx, workerSessionAuthorizationScheme, workerSessionTokenPrefix)
	if err != nil {
		return nil, err
	}
	defer wipeWorkerBytes(credential)
	if service == nil || service.workers == nil || service.broker == nil {
		return nil, status.Error(codes.Unavailable, "Knowledge Worker control is not configured")
	}
	assignment, err := service.authorize(cleanCtx, request.GetDeploymentId(), request.GetWorkerId(), credential)
	if err != nil {
		return nil, err
	}
	if err := service.broker.Complete(assignment.OwnerID, request.GetDeploymentId(), request.GetOperationId(), request.GetLeaseId(), request.GetResult()); err != nil {
		return nil, knowledgeWorkerPublicError(err)
	}
	return &agentv1.CompleteKnowledgeOperationResponse{}, nil
}

func (service *knowledgeWorkerControlHandler) authorize(ctx context.Context, deploymentID, workerID string, credential []byte) (worker.Assignment, error) {
	assignment, err := service.workers.GetCurrentAssignment(ctx, worker.SessionRequest{
		DeploymentID: deploymentID, WorkerID: workerID, Credential: credential,
	})
	if err != nil {
		return worker.Assignment{}, workerPublicError(err)
	}
	if assignment.DeploymentID != deploymentID || assignment.WorkerID != workerID || assignment.OwnerID == "" {
		return worker.Assignment{}, status.Error(codes.PermissionDenied, "Worker is not authorized for the Knowledge deployment")
	}
	return assignment, nil
}

func knowledgeWorkerPublicError(err error) error {
	switch {
	case errors.Is(err, knowledgeworker.ErrInvalid):
		return status.Error(codes.InvalidArgument, "Knowledge Worker request is invalid")
	case errors.Is(err, knowledgeworker.ErrNotFound):
		return status.Error(codes.NotFound, "no Knowledge Worker operation is available")
	case errors.Is(err, knowledgeworker.ErrLease):
		return status.Error(codes.Aborted, "Knowledge Worker operation lease is stale")
	case errors.Is(err, knowledgeworker.ErrCapacity), errors.Is(err, knowledgeworker.ErrAdapter):
		return status.Error(codes.Unavailable, "Knowledge Worker operation is unavailable")
	default:
		return status.Error(codes.Internal, "Knowledge Worker operation failed")
	}
}
