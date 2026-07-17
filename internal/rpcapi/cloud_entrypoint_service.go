package rpcapi

import (
	"context"
	"crypto/ed25519"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CreateCloudDeploymentEntryPlan creates only a separately device-signable
// ALB-entry plan. It cannot create public resources and accepts no caller
// supplied Worker URL, address, EIP, endpoint, security group, or retention.
func (service *CloudControlService) CreateCloudDeploymentEntryPlan(ctx context.Context, request *agentv1.CreateCloudDeploymentEntryPlanRequest) (*agentv1.CreateCloudDeploymentEntryPlanResponse, error) {
	caller, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service.entrypoint == nil {
		return nil, cloudUnavailable()
	}
	if request.GetExpectedRevision() < 1 {
		return nil, status.Error(codes.InvalidArgument, "expected_revision must be positive")
	}
	plan, err := service.entrypoint.CreatePlan(ctx, entrypoint.CreatePlanCommand{
		Caller: entryMutationScope(caller), IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(),
		DeploymentID: request.GetDeploymentId(), ExpectedDeploymentRevision: request.GetExpectedRevision(), Draft: cloudEntryDraftFromProto(request.GetDraft()),
	})
	if err != nil {
		return nil, publicError(err)
	}
	result, ok := cloudEntryPlanToProto(plan)
	if !ok {
		return nil, status.Error(codes.Internal, "stored cloud entrypoint plan is invalid")
	}
	return &agentv1.CreateCloudDeploymentEntryPlanResponse{Plan: result}, nil
}

func (service *CloudControlService) GetCloudEntryPlan(ctx context.Context, request *agentv1.GetCloudEntryPlanRequest) (*agentv1.GetCloudEntryPlanResponse, error) {
	if service.entrypoint == nil {
		return nil, cloudUnavailable()
	}
	plan, err := service.entrypoint.GetPlan(ctx, request.GetOwnerId(), request.GetEntryPlanId())
	if err != nil {
		return nil, publicError(err)
	}
	result, ok := cloudEntryPlanToProto(plan)
	if !ok {
		return nil, status.Error(codes.Internal, "stored cloud entrypoint plan is invalid")
	}
	return &agentv1.GetCloudEntryPlanResponse{Plan: result}, nil
}

func (service *CloudControlService) CreateCloudDeploymentEntryChallenge(ctx context.Context, request *agentv1.CreateCloudDeploymentEntryChallengeRequest) (*agentv1.CreateCloudDeploymentEntryChallengeResponse, error) {
	caller, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service.entrypoint == nil {
		return nil, cloudUnavailable()
	}
	if request.GetExpectedRevision() < 1 {
		return nil, status.Error(codes.InvalidArgument, "expected_revision must be positive")
	}
	challenge, err := service.entrypoint.Prepare(ctx, entrypoint.PrepareCommand{
		Caller: entryMutationScope(caller), IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(),
		EntryPlanID: request.GetEntryPlanId(), ExpectedRevision: uint64(request.GetExpectedRevision()), SignerKeyID: request.GetSignerKeyId(),
	})
	if err != nil {
		return nil, publicError(err)
	}
	plan, err := service.entrypoint.GetPlan(ctx, request.GetOwnerId(), request.GetEntryPlanId())
	if err != nil {
		return nil, publicError(err)
	}
	result, ok := cloudEntryChallengeToProto(challenge, plan)
	if !ok {
		return nil, status.Error(codes.Internal, "stored cloud entrypoint challenge is invalid")
	}
	return &agentv1.CreateCloudDeploymentEntryChallengeResponse{Challenge: result}, nil
}

func (service *CloudControlService) ApproveCloudDeploymentEntry(ctx context.Context, request *agentv1.ApproveCloudDeploymentEntryRequest) (*agentv1.ApproveCloudDeploymentEntryResponse, error) {
	caller, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service.entrypoint == nil {
		return nil, cloudUnavailable()
	}
	if request.GetExpectedRevision() < 1 {
		return nil, status.Error(codes.InvalidArgument, "expected_revision must be positive")
	}
	signature, ok := cloudEntrySignatureFromProto(request.GetApproval())
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "valid entrypoint device approval is required")
	}
	operation, err := service.entrypoint.Approve(ctx, entrypoint.ApproveCommand{
		Caller: entryMutationScope(caller), IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(),
		EntryPlanID: request.GetEntryPlanId(), ExpectedRevision: uint64(request.GetExpectedRevision()), Signature: signature,
	})
	if err != nil {
		return nil, publicError(err)
	}
	plan, err := service.entrypoint.GetPlan(ctx, request.GetOwnerId(), request.GetEntryPlanId())
	if err != nil {
		return nil, publicError(err)
	}
	result, ok := cloudEntryOperationToProto(operation, plan)
	if !ok {
		return nil, status.Error(codes.Internal, "stored cloud entrypoint operation is invalid")
	}
	return &agentv1.ApproveCloudDeploymentEntryResponse{Operation: result}, nil
}

func (service *CloudControlService) GetCloudEntryOperation(ctx context.Context, request *agentv1.GetCloudEntryOperationRequest) (*agentv1.GetCloudEntryOperationResponse, error) {
	if service.entrypoint == nil {
		return nil, cloudUnavailable()
	}
	operation, err := service.entrypoint.Get(ctx, request.GetOwnerId(), request.GetOperationId())
	if err != nil {
		return nil, publicError(err)
	}
	plan, err := service.entrypoint.GetPlan(ctx, request.GetOwnerId(), operation.Challenge.EntryPlanID)
	if err != nil {
		return nil, publicError(err)
	}
	result, ok := cloudEntryOperationToProto(operation, plan)
	if !ok {
		return nil, status.Error(codes.Internal, "stored cloud entrypoint operation is invalid")
	}
	return &agentv1.GetCloudEntryOperationResponse{Operation: result}, nil
}

func cloudEntrySignatureFromProto(value *agentv1.CloudEntryApprovalSignature) (entrypoint.SignatureV1, bool) {
	if value == nil || value.GetExpiresAt() == nil || !value.GetExpiresAt().IsValid() || len(value.GetSignature()) != ed25519.SignatureSize || value.GetEntryPlanRevision() < 1 {
		return entrypoint.SignatureV1{}, false
	}
	expiresAt := value.GetExpiresAt().AsTime().UTC()
	if !expiresAt.After(time.Now().UTC()) {
		return entrypoint.SignatureV1{}, false
	}
	result := entrypoint.SignatureV1{ApprovalID: value.GetApprovalId(), ChallengeID: value.GetChallengeId(), EntryPlanID: value.GetEntryPlanId(),
		EntryPlanRevision: uint64(value.GetEntryPlanRevision()), PlanHash: value.GetPlanHash(), ScopeDigest: value.GetScopeDigest(),
		SignerKeyID: value.GetSignerKeyId(), ExpiresAt: expiresAt, Signature: append([]byte(nil), value.GetSignature()...)}
	return result, result.Validate() == nil
}
