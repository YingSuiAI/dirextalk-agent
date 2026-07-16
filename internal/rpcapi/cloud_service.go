package rpcapi

import (
	"context"
	"crypto/ed25519"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type CloudControlService struct {
	agentv1.UnimplementedCloudControlServiceServer
	coordinator     cloudapp.Coordinator
	statusReader    cloudstatus.Reader
	agentInstanceID string
}

func NewCloudControlService(coordinator cloudapp.Coordinator, agentInstanceID string, statusReaders ...cloudstatus.Reader) *CloudControlService {
	service := &CloudControlService{coordinator: coordinator, agentInstanceID: agentInstanceID}
	if len(statusReaders) > 0 {
		service.statusReader = statusReaders[0]
	}
	return service
}

func (service *CloudControlService) GetCapabilities(ctx context.Context, _ *agentv1.CloudControlServiceGetCapabilitiesRequest) (*agentv1.CloudControlServiceGetCapabilitiesResponse, error) {
	capabilities := cloudapp.Capabilities{}
	if service.coordinator != nil {
		capabilities = service.coordinator.Capabilities(ctx)
	}
	return &agentv1.CloudControlServiceGetCapabilitiesResponse{Capabilities: &agentv1.CloudCapabilities{
		Aws: capabilities.AWS, DirectSts: capabilities.DirectSTS, Worker: capabilities.Worker, Reaper: capabilities.Reaper,
	}}, nil
}

func (service *CloudControlService) PreviewAwsIdentity(ctx context.Context, request *agentv1.PreviewAwsIdentityRequest) (*agentv1.PreviewAwsIdentityResponse, error) {
	scope, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service.coordinator == nil {
		return nil, cloudUnavailable()
	}
	if request.GetExpectedSessionRevision() < 1 {
		return nil, status.Error(codes.InvalidArgument, "expected_session_revision must be positive")
	}
	identity, err := service.coordinator.PreviewAWSIdentity(ctx, scope, request.GetBootstrapSessionId(), uint64(request.GetExpectedSessionRevision()), request.GetRegion())
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.PreviewAwsIdentityResponse{Identity: &agentv1.AwsBootstrapIdentity{
		AccountId: identity.AccountID, PrincipalArn: identity.PrincipalARN, PrincipalId: identity.PrincipalID,
		Region: identity.Region, RootIdentity: identity.RootIdentity,
	}}, nil
}

func (service *CloudControlService) CreateCloudQuote(ctx context.Context, request *agentv1.CreateCloudQuoteRequest) (*agentv1.CreateCloudQuoteResponse, error) {
	scope, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service.coordinator == nil {
		return nil, cloudUnavailable()
	}
	if request.GetExpectedSessionRevision() < 0 || (request.GetBootstrapSessionId() == "") != (request.GetExpectedSessionRevision() == 0) {
		return nil, status.Error(codes.InvalidArgument, "bootstrap_session_id and expected_session_revision must be supplied together")
	}
	scopes := make([]cloudquote.ScopeV1, 0, len(request.GetScopes()))
	for _, value := range request.GetScopes() {
		scopes = append(scopes, cloudQuoteScopeFromProto(value, service.agentInstanceID))
	}
	created, err := service.coordinator.CreateQuote(ctx, scope, cloudapp.CreateQuoteCommand{
		IdempotencyKey: request.GetIdempotencyKey(), BootstrapSessionID: request.GetBootstrapSessionId(),
		ExpectedSessionRevision: uint64(request.GetExpectedSessionRevision()), Scopes: scopes, Usage: cloudUsageFromProto(request.GetUsage()),
		SpotQualification: cloudSpotFromProto(request.GetSpotQualification()),
	})
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.CreateCloudQuoteResponse{Quote: cloudQuoteToProto(created)}, nil
}

func (service *CloudControlService) GetCloudQuote(ctx context.Context, request *agentv1.GetCloudQuoteRequest) (*agentv1.GetCloudQuoteResponse, error) {
	if service.coordinator == nil {
		return nil, cloudUnavailable()
	}
	value, err := service.coordinator.GetQuote(ctx, request.GetOwnerId(), request.GetQuoteId())
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.GetCloudQuoteResponse{Quote: cloudQuoteToProto(value)}, nil
}

func (service *CloudControlService) CreateCloudPlan(ctx context.Context, request *agentv1.CreateCloudPlanRequest) (*agentv1.CreateCloudPlanResponse, error) {
	scope, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service.coordinator == nil {
		return nil, cloudUnavailable()
	}
	value, err := service.coordinator.CreatePlan(ctx, scope, cloudapp.CreatePlanCommand{
		IdempotencyKey: request.GetIdempotencyKey(), QuoteID: request.GetQuoteId(),
		CandidateID:  cloudCandidateFromProto(request.GetCandidateProfile()),
		CurrentScope: cloudQuoteScopeFromProto(request.GetCurrentScope(), service.agentInstanceID),
	})
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.CreateCloudPlanResponse{Plan: cloudPlanToProto(value)}, nil
}

func (service *CloudControlService) GetCloudPlan(ctx context.Context, request *agentv1.GetCloudPlanRequest) (*agentv1.GetCloudPlanResponse, error) {
	if service.coordinator == nil {
		return nil, cloudUnavailable()
	}
	value, err := service.coordinator.GetPlan(ctx, request.GetOwnerId(), request.GetPlanId())
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.GetCloudPlanResponse{Plan: cloudPlanToProto(value)}, nil
}

func (service *CloudControlService) CreateApprovalChallenge(ctx context.Context, request *agentv1.CreateApprovalChallengeRequest) (*agentv1.CreateApprovalChallengeResponse, error) {
	scope, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service.coordinator == nil {
		return nil, cloudUnavailable()
	}
	if request.GetExpectedRevision() < 1 {
		return nil, status.Error(codes.InvalidArgument, "expected_revision must be positive")
	}
	value, err := service.coordinator.CreateApprovalChallenge(ctx, scope, cloudapp.CreateChallengeCommand{
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(), PlanID: request.GetPlanId(),
		ExpectedRevision: uint64(request.GetExpectedRevision()), SignerKeyID: request.GetSignerKeyId(),
	})
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.CreateApprovalChallengeResponse{Challenge: &agentv1.ApprovalChallenge{
		ChallengeId: value.Challenge.ChallengeID, SignerKeyId: value.Challenge.SignerKeyID,
		PlanId: value.Challenge.PlanID, PlanRevision: int64(value.Challenge.PlanRevision), PlanHash: value.Challenge.PlanHash,
		ExpiresAt: timestamppb.New(value.ExpiresAt), SigningPayloadCbor: value.SigningCBOR,
		Revision: int64(value.Challenge.Revision), ApprovalId: value.ApprovalID,
	}}, nil
}

func (service *CloudControlService) ApproveCloudPlan(ctx context.Context, request *agentv1.ApproveCloudPlanRequest) (*agentv1.ApproveCloudPlanResponse, error) {
	scope, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service.coordinator == nil {
		return nil, cloudUnavailable()
	}
	approval, err := cloudApprovalFromProto(request.GetApproval())
	if err != nil || request.GetExpectedRevision() < 1 {
		return nil, status.Error(codes.InvalidArgument, "valid device approval and expected_revision are required")
	}
	value, err := service.coordinator.ApprovePlan(ctx, scope, cloudapp.ApprovePlanCommand{
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(), PlanID: request.GetPlanId(),
		ExpectedRevision: uint64(request.GetExpectedRevision()), Approval: approval,
	})
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.ApproveCloudPlanResponse{Plan: cloudPlanToProto(value)}, nil
}

func (service *CloudControlService) EstablishAwsConnection(ctx context.Context, request *agentv1.EstablishAwsConnectionRequest) (*agentv1.EstablishAwsConnectionResponse, error) {
	scope, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service.coordinator == nil {
		return nil, cloudUnavailable()
	}
	approval, err := cloudApprovalFromProto(request.GetApproval())
	if err != nil || request.GetExpectedSessionRevision() < 1 || request.GetExpectedPlanRevision() < 1 {
		return nil, status.Error(codes.InvalidArgument, "valid device approval and revision fences are required")
	}
	value, err := service.coordinator.EstablishAWSConnection(ctx, scope, cloudapp.EstablishConnectionCommand{
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(), BootstrapSessionID: request.GetBootstrapSessionId(),
		ExpectedSessionRevision: uint64(request.GetExpectedSessionRevision()), PlanID: request.GetPlanId(),
		ExpectedPlanRevision: uint64(request.GetExpectedPlanRevision()), Approval: approval,
	})
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.EstablishAwsConnectionResponse{Connection: &agentv1.CloudConnection{
		ConnectionId: value.ConnectionID, OwnerId: value.OwnerID, AccountId: value.AccountID, Region: value.Region,
		ControlRoleArn: value.ControlRoleARN, FoundationStackId: value.FoundationStack,
		Status: value.Status, Revision: value.Revision,
	}}, nil
}

func cloudMutationScope(ctx context.Context) (cloudapp.MutationScope, error) {
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok || principal.ClientID == "" || principal.CredentialID == "" {
		return cloudapp.MutationScope{}, status.Error(codes.Unauthenticated, "authenticated caller is required")
	}
	return cloudapp.MutationScope{ClientID: principal.ClientID, CredentialID: principal.CredentialID}, nil
}

func cloudApprovalFromProto(value *agentv1.DeviceApprovalSignature) (cloudapp.ApprovalSignature, error) {
	if value == nil || len(value.GetSignature()) != ed25519.SignatureSize || value.GetExpiresAt() == nil || !value.GetExpiresAt().IsValid() {
		return cloudapp.ApprovalSignature{}, cloudapp.ErrInvalid
	}
	expiresAt := value.GetExpiresAt().AsTime().UTC()
	if expiresAt.Equal(time.Time{}) {
		return cloudapp.ApprovalSignature{}, cloudapp.ErrInvalid
	}
	return cloudapp.ApprovalSignature{
		ApprovalID: value.GetApprovalId(), ChallengeID: value.GetChallengeId(), SignerKeyID: value.GetSignerKeyId(),
		ExpiresAt: expiresAt, Signature: append([]byte(nil), value.GetSignature()...),
	}, nil
}

func cloudUnavailable() error {
	return status.Error(codes.Unavailable, "cloud control is not configured")
}
