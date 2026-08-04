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

func (s *CoreCloudControlService) TestCredentialIdentity(ctx context.Context, r *agentv1.CoreCloudControlServiceTestCredentialIdentityRequest) (*agentv1.CoreCloudControlServiceTestCredentialIdentityResponse, error) {
	if r == nil || !validCoreUUID(r.GetCredentialId()) {
		return nil, status.Error(codes.InvalidArgument, "credential_id is invalid")
	}
	v, err := s.service.TestCredential(ctx, r.GetCredentialId())
	if err != nil {
		return nil, coreAWSRPCError(err)
	}
	return &agentv1.CoreCloudControlServiceTestCredentialIdentityResponse{CredentialId: v.CredentialID, AccountId: v.Identity.AccountID, UserArn: v.Identity.UserARN, PrincipalId: v.Identity.PrincipalID, CredentialRevision: v.CredentialRevision, TestedAt: timestamppb.New(v.TestedAt.UTC())}, nil
}

func (s *CoreCloudControlService) CreatePlan(ctx context.Context, r *agentv1.CoreCloudControlServiceCreatePlanRequest) (*agentv1.CoreCloudControlServiceCreatePlanResponse, error) {
	if r == nil || !validCoreUUID(r.GetIdempotencyKey()) || !validCoreUUID(r.GetCredentialId()) {
		return nil, status.Error(codes.InvalidArgument, "invalid plan creation")
	}
	op, ok := operationFromProto(r.GetOperation())
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "operation is invalid")
	}
	v, err := s.service.CreatePlan(ctx, coreaws.PlanInput{CredentialID: r.GetCredentialId(), Region: r.GetRegion(), StackName: r.GetStackName(), Operation: op, Template: r.GetTemplate(), Parameters: r.GetParameters(), Tags: r.GetTags(), Capabilities: r.GetCapabilities(), IdempotencyKey: r.GetIdempotencyKey()})
	if err != nil {
		return nil, coreAWSRPCError(err)
	}
	return &agentv1.CoreCloudControlServiceCreatePlanResponse{Plan: planProto(v)}, nil
}

func (s *CoreCloudControlService) GetPlan(ctx context.Context, r *agentv1.CoreCloudControlServiceGetPlanRequest) (*agentv1.CoreCloudControlServiceGetPlanResponse, error) {
	if r == nil || !validCoreUUID(r.GetPlanId()) {
		return nil, status.Error(codes.InvalidArgument, "plan_id is invalid")
	}
	v, err := s.service.GetPlan(ctx, r.GetPlanId())
	if err != nil {
		return nil, coreAWSRPCError(err)
	}
	return &agentv1.CoreCloudControlServiceGetPlanResponse{Plan: planProto(v)}, nil
}

func (s *CoreCloudControlService) ListPlans(ctx context.Context, r *agentv1.CoreCloudControlServiceListPlansRequest) (*agentv1.CoreCloudControlServiceListPlansResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	limit, err := pageLimit(r.GetPageSize())
	if err != nil {
		return nil, err
	}
	p, err := s.service.ListPlans(ctx, limit, r.GetPageToken())
	if err != nil {
		return nil, coreAWSRPCError(err)
	}
	out := &agentv1.CoreCloudControlServiceListPlansResponse{NextPageToken: p.NextPageToken}
	for _, v := range p.Items {
		out.Plans = append(out.Plans, planProto(v))
	}
	return out, nil
}

func (s *CoreCloudControlService) Quote(ctx context.Context, r *agentv1.CoreCloudControlServiceQuoteRequest) (*agentv1.CoreCloudControlServiceQuoteResponse, error) {
	if r == nil || !validCoreUUID(r.GetPlanId()) {
		return nil, status.Error(codes.InvalidArgument, "plan_id is invalid")
	}
	v, err := s.service.Quote(ctx, r.GetPlanId())
	if err != nil {
		return nil, coreAWSRPCError(err)
	}
	return &agentv1.CoreCloudControlServiceQuoteResponse{Quote: quoteProto(v)}, nil
}

func (s *CoreCloudControlService) RequestChange(ctx context.Context, r *agentv1.CoreCloudControlServiceRequestChangeRequest) (*agentv1.CoreCloudControlServiceRequestChangeResponse, error) {
	if r == nil || !validCoreUUID(r.GetPlanId()) || !validCoreUUID(r.GetIdempotencyKey()) {
		return nil, status.Error(codes.InvalidArgument, "invalid change request")
	}
	v, err := s.service.RequestChange(ctx, coreaws.RequestChangeInput{PlanID: r.GetPlanId(), IdempotencyKey: r.GetIdempotencyKey()})
	if err != nil {
		return nil, coreAWSRPCError(err)
	}
	return &agentv1.CoreCloudControlServiceRequestChangeResponse{Change: changeProto(v.Change), Confirmation: confirmationProto(v.Confirmation), TaskId: v.Task.ID}, nil
}

func (s *CoreCloudControlService) GetChange(ctx context.Context, r *agentv1.CoreCloudControlServiceGetChangeRequest) (*agentv1.CoreCloudControlServiceGetChangeResponse, error) {
	if r == nil || !validCoreUUID(r.GetChangeId()) {
		return nil, status.Error(codes.InvalidArgument, "change_id is invalid")
	}
	v, err := s.service.GetChange(ctx, r.GetChangeId())
	if err != nil {
		return nil, coreAWSRPCError(err)
	}
	return &agentv1.CoreCloudControlServiceGetChangeResponse{Change: changeProto(v)}, nil
}

func (s *CoreCloudControlService) ListChanges(ctx context.Context, r *agentv1.CoreCloudControlServiceListChangesRequest) (*agentv1.CoreCloudControlServiceListChangesResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	limit, err := pageLimit(r.GetPageSize())
	if err != nil {
		return nil, err
	}
	if r.GetPlanId() != "" && !validCoreUUID(r.GetPlanId()) {
		return nil, status.Error(codes.InvalidArgument, "plan_id is invalid")
	}
	p, err := s.service.ListChanges(ctx, limit, r.GetPlanId(), r.GetPageToken())
	if err != nil {
		return nil, coreAWSRPCError(err)
	}
	out := &agentv1.CoreCloudControlServiceListChangesResponse{NextPageToken: p.NextPageToken}
	for _, v := range p.Items {
		out.Changes = append(out.Changes, changeProto(v))
	}
	return out, nil
}

func (s *CoreCloudControlService) GetChangeStatus(ctx context.Context, r *agentv1.CoreCloudControlServiceGetChangeStatusRequest) (*agentv1.CoreCloudControlServiceGetChangeStatusResponse, error) {
	if r == nil || !validCoreUUID(r.GetChangeId()) {
		return nil, status.Error(codes.InvalidArgument, "change_id is invalid")
	}
	v, err := s.service.GetChange(ctx, r.GetChangeId())
	if err != nil {
		return nil, coreAWSRPCError(err)
	}
	return &agentv1.CoreCloudControlServiceGetChangeStatusResponse{Change: changeProto(v), Status: string(v.Status), Stage: string(v.Stage)}, nil
}

func credentialProto(v coreaws.CredentialView) *agentv1.CoreAWSCredential {
	var testedAt *timestamppb.Timestamp
	if !v.TestedAt.IsZero() {
		testedAt = timestamppb.New(v.TestedAt.UTC())
	}
	return &agentv1.CoreAWSCredential{CredentialId: v.ID, Name: v.Name, Region: v.Region, AccountId: v.AccountID, UserArn: v.UserARN, AccessKeyConfigured: v.HasAccessKey, SecretAccessKeyConfigured: v.HasSecretKey, SessionTokenConfigured: v.HasSessionToken, Revision: v.Revision, CreatedAt: timestamppb.New(v.CreatedAt.UTC()), UpdatedAt: timestamppb.New(v.UpdatedAt.UTC()), VerifiedRevision: v.VerifiedRevision, TestedAt: testedAt}
}
func operationFromProto(v agentv1.CoreAWSOperation) (coreaws.Operation, bool) {
	switch v {
	case agentv1.CoreAWSOperation_CORE_AWS_OPERATION_CREATE:
		return coreaws.OperationCreate, true
	case agentv1.CoreAWSOperation_CORE_AWS_OPERATION_UPDATE:
		return coreaws.OperationUpdate, true
	case agentv1.CoreAWSOperation_CORE_AWS_OPERATION_DELETE:
		return coreaws.OperationDelete, true
	default:
		return "", false
	}
}
func operationProto(v coreaws.Operation) agentv1.CoreAWSOperation {
	switch v {
	case coreaws.OperationCreate:
		return agentv1.CoreAWSOperation_CORE_AWS_OPERATION_CREATE
	case coreaws.OperationUpdate:
		return agentv1.CoreAWSOperation_CORE_AWS_OPERATION_UPDATE
	case coreaws.OperationDelete:
		return agentv1.CoreAWSOperation_CORE_AWS_OPERATION_DELETE
	default:
		return agentv1.CoreAWSOperation_CORE_AWS_OPERATION_UNSPECIFIED
	}
}
func planProto(v coreaws.PlanView) *agentv1.CoreAWSPlan {
	return &agentv1.CoreAWSPlan{PlanId: v.ID, CredentialId: v.CredentialID, Region: v.Region, StackName: v.StackName, Operation: operationProto(v.Operation), TemplateSha256: v.TemplateSHA256, Parameters: v.Parameters, Tags: v.Tags, Capabilities: v.Capabilities, Revision: v.Revision, CreatedAt: timestamppb.New(v.CreatedAt.UTC())}
}
func quoteProto(v coreaws.Quote) *agentv1.CoreAWSQuote {
	return &agentv1.CoreAWSQuote{PlanId: v.PlanID, Operation: operationProto(v.Operation), Region: v.Region, StackName: v.StackName, ResourceCount: int32(v.ResourceCount), ParameterCount: int32(v.ParameterCount), TagCount: int32(v.TagCount), EstimatedMonthlyUsd: v.EstimatedMonthlyUSD, Summary: v.Summary, PlanDigest: v.PlanDigest}
}
func changeProto(v coreaws.Change) *agentv1.CoreAWSChange {
	return &agentv1.CoreAWSChange{ChangeId: v.ID, PlanId: v.PlanID, CredentialId: v.CredentialID, TaskId: v.TaskID, ConfirmationId: v.ConfirmationID, Operation: operationProto(v.Operation), Status: string(v.Status), Stage: string(v.Stage), ChangeSetId: v.ChangeSetID, ProviderRequestDigest: v.ProviderRequestDigest, Revision: v.Revision, ErrorCode: v.ErrorCode, ErrorSummary: v.ErrorSummary, CreatedAt: timestamppb.New(v.CreatedAt.UTC()), UpdatedAt: timestamppb.New(v.UpdatedAt.UTC())}
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
	case errors.Is(err, coreaws.ErrUnconfirmed):
		return status.Error(codes.FailedPrecondition, "AWS change requires confirmation")
	case errors.Is(err, coreaws.ErrConflict):
		return status.Error(codes.FailedPrecondition, "AWS state conflict")
	case errors.Is(err, coreaws.ErrResponseUncertain), errors.Is(err, coreaws.ErrProvider):
		return status.Error(codes.Unavailable, "AWS provider unavailable")
	default:
		return status.Error(codes.Internal, "AWS operation failed")
	}
}

var _ agentv1.CoreCloudControlServiceServer = (*CoreCloudControlService)(nil)
