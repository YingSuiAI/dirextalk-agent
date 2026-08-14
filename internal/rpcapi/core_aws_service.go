package rpcapi

import (
	"context"
	"errors"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CoreCloudControlService adapts the Core v1 AWS service to gRPC.
type CoreCloudControlService struct {
	agentv1.UnimplementedCoreCloudControlServiceServer
	service *coreaws.Service
}

func NewCoreCloudControlService(service *coreaws.Service) (*CoreCloudControlService, error) {
	if service == nil {
		return nil, errors.New("core cloud control service requires service")
	}
	return &CoreCloudControlService{service: service}, nil
}

func (s *CoreCloudControlService) CreateCredential(ctx context.Context, r *agentv1.CoreCloudControlServiceCreateCredentialRequest) (*agentv1.CoreCloudControlServiceCreateCredentialResponse, error) {
	if r == nil || !validCoreUUID(r.GetIdempotencyKey()) {
		return nil, status.Error(codes.InvalidArgument, "idempotency_key is invalid")
	}
	v, err := s.service.SaveCredential(ctx, coreaws.CredentialInput{Name: r.GetName(), Region: r.GetRegion(), AccessKeyID: r.GetAccessKeyId(), SecretAccessKey: r.GetSecretAccessKey(), SessionToken: r.GetSessionToken(), IdempotencyKey: r.GetIdempotencyKey()})
	if err != nil {
		return nil, coreAWSRPCError(err)
	}
	return &agentv1.CoreCloudControlServiceCreateCredentialResponse{Credential: credentialProto(v)}, nil
}

func (s *CoreCloudControlService) GetCredential(ctx context.Context, r *agentv1.CoreCloudControlServiceGetCredentialRequest) (*agentv1.CoreCloudControlServiceGetCredentialResponse, error) {
	if r == nil || !validCoreUUID(r.GetCredentialId()) {
		return nil, status.Error(codes.InvalidArgument, "credential_id is invalid")
	}
	v, err := s.service.GetCredential(ctx, r.GetCredentialId())
	if err != nil {
		return nil, coreAWSRPCError(err)
	}
	return &agentv1.CoreCloudControlServiceGetCredentialResponse{Credential: credentialProto(v)}, nil
}

func (s *CoreCloudControlService) ListCredentials(ctx context.Context, r *agentv1.CoreCloudControlServiceListCredentialsRequest) (*agentv1.CoreCloudControlServiceListCredentialsResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	limit, err := pageLimit(r.GetPageSize())
	if err != nil {
		return nil, err
	}
	p, err := s.service.ListCredentials(ctx, limit, r.GetPageToken())
	if err != nil {
		return nil, coreAWSRPCError(err)
	}
	out := &agentv1.CoreCloudControlServiceListCredentialsResponse{NextPageToken: p.NextPageToken}
	for _, v := range p.Items {
		out.Credentials = append(out.Credentials, credentialProto(v))
	}
	return out, nil
}

func (s *CoreCloudControlService) UpdateCredential(ctx context.Context, r *agentv1.CoreCloudControlServiceUpdateCredentialRequest) (*agentv1.CoreCloudControlServiceUpdateCredentialResponse, error) {
	if r == nil || !validCoreUUID(r.GetCredentialId()) || !validCoreUUID(r.GetIdempotencyKey()) || r.GetExpectedRevision() < 1 {
		return nil, status.Error(codes.InvalidArgument, "invalid credential update")
	}
	// Empty secret fields mean preserve; the domain service retains the stored
	// private payload while replacing only values explicitly supplied here.
	name, region := r.GetName(), r.GetRegion()
	if name == "" || region == "" {
		old, err := s.service.GetCredential(ctx, r.GetCredentialId())
		if err != nil {
			return nil, coreAWSRPCError(err)
		}
		if name == "" {
			name = old.Name
		}
		if region == "" {
			region = old.Region
		}
	}
	v, err := s.service.ReplaceCredential(ctx, coreaws.CredentialInput{ID: r.GetCredentialId(), Name: name, Region: region, AccessKeyID: r.GetAccessKeyId(), SecretAccessKey: r.GetSecretAccessKey(), SessionToken: r.GetSessionToken()}, r.GetExpectedRevision(), r.GetIdempotencyKey())
	if err != nil {
		return nil, coreAWSRPCError(err)
	}
	return &agentv1.CoreCloudControlServiceUpdateCredentialResponse{Credential: credentialProto(v)}, nil
}

func (s *CoreCloudControlService) DeleteCredential(ctx context.Context, r *agentv1.CoreCloudControlServiceDeleteCredentialRequest) (*agentv1.CoreCloudControlServiceDeleteCredentialResponse, error) {
	if r == nil || !validCoreUUID(r.GetCredentialId()) || !validCoreUUID(r.GetIdempotencyKey()) || r.GetExpectedRevision() < 1 {
		return nil, status.Error(codes.InvalidArgument, "invalid credential deletion")
	}
	if err := s.service.DeleteCredential(ctx, r.GetCredentialId(), r.GetExpectedRevision(), r.GetIdempotencyKey()); err != nil {
		return nil, coreAWSRPCError(err)
	}
	return &agentv1.CoreCloudControlServiceDeleteCredentialResponse{}, nil
}

func credentialProto(v coreaws.CredentialView) *agentv1.CoreAWSCredential {
	var testedAt *timestamppb.Timestamp
	if !v.TestedAt.IsZero() {
		testedAt = timestamppb.New(v.TestedAt.UTC())
	}
	return &agentv1.CoreAWSCredential{CredentialId: v.ID, Name: v.Name, Region: v.Region, AccountId: v.AccountID, UserArn: v.UserARN, AccessKeyConfigured: v.HasAccessKey, SecretAccessKeyConfigured: v.HasSecretKey, SessionTokenConfigured: v.HasSessionToken, Revision: v.Revision, CreatedAt: timestamppb.New(v.CreatedAt.UTC()), UpdatedAt: timestamppb.New(v.UpdatedAt.UTC()), VerifiedRevision: v.VerifiedRevision, TestedAt: testedAt}
}
func coreAWSRPCError(err error) error {
	switch {
	case errors.Is(err, coreaws.ErrInvalid):
		return status.Error(codes.InvalidArgument, "invalid AWS request")
	case errors.Is(err, coreaws.ErrNotFound):
		return status.Error(codes.NotFound, "AWS resource not found")
	case errors.Is(err, coreaws.ErrIdempotencyConflict):
		return status.Error(codes.AlreadyExists, "idempotency conflict")
	case errors.Is(err, coreaws.ErrRevisionConflict):
		return status.Error(codes.Aborted, "AWS revision conflict")
	case errors.Is(err, coreaws.ErrActiveCredentialExists):
		return status.Error(codes.FailedPrecondition, "delete the active AWS credential before adding another")
	case errors.Is(err, coreaws.ErrConflict):
		return status.Error(codes.FailedPrecondition, "AWS state conflict")
	case errors.Is(err, coreaws.ErrResponseUncertain), errors.Is(err, coreaws.ErrProvider):
		return status.Error(codes.Unavailable, "AWS provider unavailable")
	default:
		return status.Error(codes.Internal, "AWS operation failed")
	}
}

var _ agentv1.CoreCloudControlServiceServer = (*CoreCloudControlService)(nil)
