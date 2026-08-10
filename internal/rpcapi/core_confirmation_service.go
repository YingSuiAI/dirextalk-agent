package rpcapi

import (
	"context"
	"errors"
	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"strings"
	"time"
)

type CoreConfirmationService struct {
	agentv1.UnimplementedConfirmationServiceServer
	service *coreconfirmation.Service
}

func NewCoreConfirmationService(s *coreconfirmation.Service) (*CoreConfirmationService, error) {
	if s == nil {
		return nil, errors.New("confirmation service requires service")
	}
	return &CoreConfirmationService{service: s}, nil
}
func (s *CoreConfirmationService) Get(ctx context.Context, r *agentv1.ConfirmationServiceGetRequest) (*agentv1.ConfirmationServiceGetResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	c, e := s.service.Get(ctx, r.GetConfirmationId())
	if e != nil {
		return nil, confirmationError(e)
	}
	return &agentv1.ConfirmationServiceGetResponse{Confirmation: confirmationProto(c)}, nil
}
func (s *CoreConfirmationService) List(ctx context.Context, r *agentv1.ConfirmationServiceListRequest) (*agentv1.ConfirmationServiceListResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	q := coreconfirmation.ListQuery{PageSize: int(r.GetPageSize()), PageToken: r.GetPageToken(), Domain: strings.TrimSpace(r.GetOperationDomain()), TargetID: strings.TrimSpace(r.GetTargetId())}
	for _, st := range r.GetStates() {
		q.States = append(q.States, coreconfirmation.State(strings.ToLower(strings.TrimPrefix(st.String(), "CORE_CONFIRMATION_STATE_"))))
	}
	p, e := s.service.List(ctx, q)
	if e != nil {
		return nil, confirmationError(e)
	}
	out := &agentv1.ConfirmationServiceListResponse{NextPageToken: p.NextPageToken}
	for _, c := range p.Confirmations {
		out.Confirmations = append(out.Confirmations, confirmationProto(c))
	}
	return out, nil
}
func (s *CoreConfirmationService) Confirm(ctx context.Context, r *agentv1.ConfirmationServiceConfirmRequest) (*agentv1.ConfirmationServiceConfirmResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	c, e := s.service.Confirm(ctx, coreconfirmation.ConfirmCommand{ConfirmationID: r.GetConfirmationId(), IdempotencyKey: r.GetIdempotencyKey(), ExpectedRevision: r.GetExpectedRevision(), At: time.Now().UTC()})
	if e != nil {
		return nil, confirmationError(e)
	}
	return &agentv1.ConfirmationServiceConfirmResponse{Confirmation: confirmationProto(c)}, nil
}
func (s *CoreConfirmationService) Reject(ctx context.Context, r *agentv1.ConfirmationServiceRejectRequest) (*agentv1.ConfirmationServiceRejectResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	c, e := s.service.Reject(ctx, coreconfirmation.RejectCommand{ConfirmationID: r.GetConfirmationId(), IdempotencyKey: r.GetIdempotencyKey(), ExpectedRevision: r.GetExpectedRevision(), Reason: r.GetReason(), At: time.Now().UTC()})
	if e != nil {
		return nil, confirmationError(e)
	}
	return &agentv1.ConfirmationServiceRejectResponse{Confirmation: confirmationProto(c)}, nil
}
func confirmationProto(c coreconfirmation.Confirmation) *agentv1.CoreConfirmation {
	publicBinding := c.Binding.Public()
	b := &agentv1.CoreConfirmationBinding{
		OperationDomain: c.Binding.OperationDomain, TargetId: c.Binding.TargetID, TargetRevision: c.Binding.TargetRevision,
		SourceVersion: c.Binding.SourceVersion, SourceCommit: c.Binding.SourceCommit,
		ContentDigest: string(c.Binding.ContentDigest), ParameterDigest: string(c.Binding.ParameterDigest),
		NetworkDigest: string(c.Binding.NetworkDigest), SecretGrantDigest: string(c.Binding.SecretGrantDigest),
		NetworkGrants: append([]string(nil), c.Binding.NetworkGrants...), OwnerId: c.Binding.OwnerID,
		TargetKind: c.Binding.TargetKind, ManifestDigest: string(c.Binding.ManifestDigest),
		ExecutionDigest: string(c.Binding.ExecutionDigest), PermissionDigest: string(c.Binding.PermissionDigest),
		SelectedTool: c.Binding.SelectedTool, SelectedCommand: append([]string(nil), c.Binding.SelectedCommand...),
		AccountGeneration: c.Binding.AccountGeneration, ExecutionId: c.Binding.ExecutionID,
		PlanId: c.Binding.PlanID, PlanRevision: c.Binding.PlanRevision, PlanDigest: string(c.Binding.PlanDigest),
		RunId: c.Binding.RunID, RunRevision: c.Binding.RunRevision, RunDigest: string(c.Binding.RunDigest),
		QuoteDigest: string(c.Binding.QuoteDigest), Digest: string(c.Binding.Digest),
	}
	for _, g := range publicBinding.SecretGrants {
		b.SecretGrants = append(b.SecretGrants, &agentv1.CoreSecretGrantDescriptor{ReferenceId: g.ReferenceID, Purpose: secretPurposeProto(g.Purpose), BindingDigest: string(g.BindingDigest)})
	}
	return &agentv1.CoreConfirmation{ConfirmationId: c.ConfirmationID, OwnerId: c.OwnerID, Binding: b, TaskId: c.TaskID, State: confirmationStateProto(c.State), Revision: c.Revision, CreatedAt: timestamppb.New(c.CreatedAt), UpdatedAt: timestamppb.New(c.UpdatedAt), ExpiresAt: timestamppb.New(c.ExpiresAt), TerminalReason: c.TerminalReason, TerminalCode: c.TerminalCode, TerminalNote: c.TerminalNote}
}
func secretPurposeProto(p coreconfirmation.SecretPurpose) agentv1.CoreSecretGrantPurpose {
	switch p {
	case coreconfirmation.SecretPurposeModelAPIKey:
		return agentv1.CoreSecretGrantPurpose_CORE_SECRET_GRANT_PURPOSE_MODEL_API_KEY
	case coreconfirmation.SecretPurposeMCPCredential:
		return agentv1.CoreSecretGrantPurpose_CORE_SECRET_GRANT_PURPOSE_MCP_CREDENTIAL
	case coreconfirmation.SecretPurposeSkillSecret:
		return agentv1.CoreSecretGrantPurpose_CORE_SECRET_GRANT_PURPOSE_SKILL_SECRET
	case coreconfirmation.SecretPurposeAWSCredential:
		return agentv1.CoreSecretGrantPurpose_CORE_SECRET_GRANT_PURPOSE_AWS_CREDENTIAL
	case coreconfirmation.SecretPurposeOtherExtensionSecret:
		return agentv1.CoreSecretGrantPurpose_CORE_SECRET_GRANT_PURPOSE_OTHER_EXTENSION_SECRET
	}
	return agentv1.CoreSecretGrantPurpose_CORE_SECRET_GRANT_PURPOSE_UNSPECIFIED
}
func confirmationStateProto(s coreconfirmation.State) agentv1.CoreConfirmationState {
	switch s {
	case coreconfirmation.StatePending:
		return agentv1.CoreConfirmationState_CORE_CONFIRMATION_STATE_PENDING
	case coreconfirmation.StateConfirmed:
		return agentv1.CoreConfirmationState_CORE_CONFIRMATION_STATE_CONFIRMED
	case coreconfirmation.StateConsumed:
		return agentv1.CoreConfirmationState_CORE_CONFIRMATION_STATE_CONSUMED
	case coreconfirmation.StateRejected:
		return agentv1.CoreConfirmationState_CORE_CONFIRMATION_STATE_REJECTED
	case coreconfirmation.StateExpired:
		return agentv1.CoreConfirmationState_CORE_CONFIRMATION_STATE_EXPIRED
	}
	return agentv1.CoreConfirmationState_CORE_CONFIRMATION_STATE_UNSPECIFIED
}
func confirmationError(e error) error {
	switch {
	case errors.Is(e, coreconfirmation.ErrInvalid):
		return status.Error(codes.InvalidArgument, e.Error())
	case errors.Is(e, coreconfirmation.ErrNotFound):
		return status.Error(codes.NotFound, e.Error())
	case errors.Is(e, coreconfirmation.ErrRevisionConflict), errors.Is(e, coreconfirmation.ErrStale):
		return status.Error(codes.Aborted, e.Error())
	case errors.Is(e, coreconfirmation.ErrTaskFenceConflict):
		return status.Error(codes.Aborted, e.Error())
	case errors.Is(e, coreconfirmation.ErrBindingUnavailable):
		return status.Error(codes.Unavailable, e.Error())
	case errors.Is(e, coreconfirmation.ErrConflict), errors.Is(e, coreconfirmation.ErrExpired), errors.Is(e, coreconfirmation.ErrInvalidTransition):
		return status.Error(codes.FailedPrecondition, e.Error())
	case errors.Is(e, coreconfirmation.ErrIdempotencyConflict):
		return status.Error(codes.AlreadyExists, e.Error())
	default:
		return status.Error(codes.Internal, "confirmation persistence failed")
	}
}
