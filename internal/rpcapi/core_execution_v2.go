package rpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CoreExecutionV2Service is a composition seam. core_serve.go intentionally
// does not construct this service automatically; deployments can register it
// after wiring the Agent-owned PostgresStore and typed provider ports.
type CoreExecutionV2Service struct {
	agentv1.UnimplementedCoreExecutionV2ServiceServer
	Domain     *coreexecutionv2.Service
	OwnerScope func(context.Context) (coretask.OwnerScope, error)
}

func NewCoreExecutionV2Service(domain *coreexecutionv2.Service, ownerScope func(context.Context) (coretask.OwnerScope, error)) (*CoreExecutionV2Service, error) {
	if domain == nil || ownerScope == nil {
		return nil, coreexecutionv2.ErrInvalid
	}
	return &CoreExecutionV2Service{Domain: domain, OwnerScope: ownerScope}, nil
}

func (s *CoreExecutionV2Service) ownerScope(ctx context.Context) (coretask.OwnerScope, error) {
	if s == nil || s.Domain == nil || s.OwnerScope == nil {
		return coretask.OwnerScope{}, coreexecutionv2.ErrNotReady
	}
	scope, err := s.OwnerScope(ctx)
	if err != nil || scope.Validate() != nil {
		return coretask.OwnerScope{}, status.Error(codes.PermissionDenied, "authenticated owner scope is required")
	}
	return scope, nil
}

func (s *CoreExecutionV2Service) Execute(ctx context.Context, req *agentv1.CoreExecutionV2ServiceExecuteRequest) (*agentv1.CoreExecutionV2ServiceExecuteResponse, error) {
	if req == nil || strings.TrimSpace(req.GetAction()) == "" || len(req.GetRequestJson()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "action and request_json are required")
	}
	var input map[string]any
	if err := json.Unmarshal(req.GetRequestJson(), &input); err != nil {
		return nil, status.Error(codes.InvalidArgument, "request_json must be an object")
	}
	scope, err := s.ownerScope(ctx)
	if err != nil {
		return nil, err
	}
	result, err := s.Domain.Handle(ctx, scope, req.GetAction(), input)
	if err != nil {
		return nil, mapExecutionError(err)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, status.Error(codes.Internal, "encode execution result")
	}
	return &agentv1.CoreExecutionV2ServiceExecuteResponse{ResultJson: raw}, nil
}

func (s *CoreExecutionV2Service) Get(ctx context.Context, req *agentv1.CoreExecutionV2ServiceGetRequest) (*agentv1.CoreExecutionV2ServiceGetResponse, error) {
	if req == nil || strings.TrimSpace(req.GetKind()) == "" || strings.TrimSpace(req.GetId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "kind and id are required")
	}
	scope, err := s.ownerScope(ctx)
	if err != nil {
		return nil, err
	}
	record, err := s.Domain.Get(ctx, scope, req.GetKind(), req.GetId(), req.GetRevision())
	if err != nil {
		return nil, mapExecutionError(err)
	}
	raw, _ := json.Marshal(record.Payload)
	return &agentv1.CoreExecutionV2ServiceGetResponse{Record: &agentv1.CoreExecutionV2Record{OwnerId: record.OwnerID, AccountGeneration: record.AccountGeneration, Kind: record.Kind, Id: record.ID, Revision: record.Revision, Status: record.Status, Digest: record.Digest, PayloadJson: raw, CreatedAt: timestamppb.New(record.CreatedAt), UpdatedAt: timestamppb.New(record.UpdatedAt)}}, nil
}

func (s *CoreExecutionV2Service) ListEvents(ctx context.Context, req *agentv1.CoreExecutionV2ServiceListEventsRequest) (*agentv1.CoreExecutionV2ServiceListEventsResponse, error) {
	if req == nil || strings.TrimSpace(req.GetKind()) == "" || strings.TrimSpace(req.GetId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "kind and id are required")
	}
	scope, err := s.ownerScope(ctx)
	if err != nil {
		return nil, err
	}
	limit := int(req.GetLimit())
	if limit == 0 {
		limit = 100
	}
	events, next, err := s.Domain.Events(ctx, scope, req.GetKind(), req.GetId(), req.GetAfterSequence(), limit)
	if err != nil {
		return nil, mapExecutionError(err)
	}
	response := &agentv1.CoreExecutionV2ServiceListEventsResponse{NextSequence: next}
	for _, event := range events {
		raw, _ := json.Marshal(event.Payload)
		response.Events = append(response.Events, &agentv1.CoreExecutionV2Event{OwnerId: event.OwnerID, AccountGeneration: event.AccountGeneration, Kind: event.Kind, ResourceId: event.ResourceID, Sequence: event.Sequence, EventId: event.EventID, Type: event.Type, PayloadJson: raw, CreatedAt: timestamppb.New(event.CreatedAt)})
	}
	return response, nil
}

func mapExecutionError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, coreexecutionv2.ErrInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, coreexecutionv2.ErrNotFound), errors.Is(err, coreexecutionv2.ErrSecretNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, coreexecutionv2.ErrConflict), errors.Is(err, coreexecutionv2.ErrReplayInProgress):
		return status.Error(codes.Aborted, err.Error())
	case errors.Is(err, coreexecutionv2.ErrNotReady), errors.Is(err, coreexecutionv2.ErrMissingPort):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return status.Error(codes.Internal, fmt.Sprintf("execution.v2 request failed: %v", err))
	}
}
