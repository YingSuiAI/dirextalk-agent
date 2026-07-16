package rpcapi

import (
	"context"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	clouddestroy "github.com/YingSuiAI/dirextalk-agent/internal/cloud/destroy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (service *CloudControlService) CreateCloudDeploymentDestroyChallenge(ctx context.Context, request *agentv1.CreateCloudDeploymentDestroyChallengeRequest) (*agentv1.CreateCloudDeploymentDestroyChallengeResponse, error) {
	caller, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service.destroyer == nil {
		return nil, cloudUnavailable()
	}
	if request.GetExpectedRevision() < 1 {
		return nil, status.Error(codes.InvalidArgument, "expected_revision must be positive")
	}
	challenge, err := service.destroyer.Prepare(ctx, clouddestroy.PrepareCommand{
		Caller:         clouddestroy.MutationScope{ClientID: caller.ClientID, CredentialID: caller.CredentialID},
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(), DeploymentID: request.GetDeploymentId(),
		ExpectedRevision: request.GetExpectedRevision(), SignerKeyID: request.GetSignerKeyId(),
	})
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.CreateCloudDeploymentDestroyChallengeResponse{Challenge: cloudDestroyChallengeToProto(challenge)}, nil
}

func (service *CloudControlService) ApproveCloudDeploymentDestroy(ctx context.Context, request *agentv1.ApproveCloudDeploymentDestroyRequest) (*agentv1.ApproveCloudDeploymentDestroyResponse, error) {
	caller, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service.destroyer == nil || service.statusReader == nil {
		return nil, cloudUnavailable()
	}
	approval, err := cloudApprovalFromProto(request.GetApproval())
	if err != nil || request.GetExpectedRevision() < 1 {
		return nil, status.Error(codes.InvalidArgument, "valid device approval and expected_revision are required")
	}
	operation, err := service.destroyer.Approve(ctx, clouddestroy.ApproveCommand{
		Caller:         clouddestroy.MutationScope{ClientID: caller.ClientID, CredentialID: caller.CredentialID},
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(), DeploymentID: request.GetDeploymentId(), ExpectedRevision: request.GetExpectedRevision(),
		Signature: clouddestroy.SignatureV1{ApprovalID: approval.ApprovalID, ChallengeID: approval.ChallengeID, SignerKeyID: approval.SignerKeyID, ExpiresAt: approval.ExpiresAt, Signature: approval.Signature},
	})
	if err != nil {
		return nil, publicError(err)
	}
	deployment, err := service.statusReader.GetDeployment(ctx, request.GetOwnerId(), request.GetDeploymentId())
	if err != nil {
		return nil, publicError(err)
	}
	resources, err := service.statusReader.ListDeploymentResources(ctx, request.GetOwnerId(), request.GetDeploymentId())
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.ApproveCloudDeploymentDestroyResponse{Operation: cloudDestroyOperationToProto(operation), Deployment: cloudDeploymentToProto(deployment, resources)}, nil
}

func (service *CloudControlService) GetCloudDestroyOperation(ctx context.Context, request *agentv1.GetCloudDestroyOperationRequest) (*agentv1.GetCloudDestroyOperationResponse, error) {
	if service.destroyer == nil {
		return nil, cloudUnavailable()
	}
	operation, err := service.destroyer.Get(ctx, request.GetOwnerId(), request.GetOperationId())
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.GetCloudDestroyOperationResponse{Operation: cloudDestroyOperationToProto(operation)}, nil
}

func cloudDestroyChallengeToProto(value clouddestroy.ChallengeV1) *agentv1.CloudDeploymentDestroyChallenge {
	resources := make([]*agentv1.CloudDestroyResourceScope, 0, len(value.Scope.Resources))
	for _, item := range value.Scope.Resources {
		resources = append(resources, cloudDestroyResourceScopeToProto(item))
	}
	return &agentv1.CloudDeploymentDestroyChallenge{OperationId: value.OperationID, ChallengeId: value.ChallengeID, ApprovalId: value.ApprovalID,
		SignerKeyId: value.SignerKeyID, Scope: &agentv1.CloudDeploymentDestroyScope{SchemaVersion: value.Scope.SchemaVersion, AgentInstanceId: value.Scope.AgentInstanceID,
			OwnerId: value.Scope.OwnerID, DeploymentId: value.Scope.DeploymentID, DeploymentRevision: value.Scope.DeploymentRevision, TaskId: value.Scope.TaskID,
			PlanId: value.Scope.PlanID, PlanHash: value.Scope.PlanHash, ConnectionId: value.Scope.ConnectionID, Resources: resources},
		ExpiresAt: timestamppb.New(value.ExpiresAt), SigningPayloadCbor: append([]byte(nil), value.SigningCBOR...), Revision: value.Revision}
}

func cloudDestroyResourceScopeToProto(item clouddestroy.ResourceScopeV1) *agentv1.CloudDestroyResourceScope {
	return &agentv1.CloudDestroyResourceScope{ResourceId: item.ResourceID, Type: cloudResourceTypeToProto(item.Type), ProviderId: item.ProviderID, Revision: item.Revision,
		DependsOnResourceIds: append([]string(nil), item.DependsOn...), RetentionPolicy: retentionToProto(item.Retention), Status: cloudResourceStateToProto(item.State),
		Region: item.Region, SpecDigest: item.SpecDigest, ApprovedPlanHash: item.ApprovedPlanHash, OriginalApprovalId: item.OriginalApprovalID,
		ReadBack: &agentv1.CloudResourceReadBack{Observed: item.ReadBack.Observed, Exists: item.ReadBack.Exists, ProviderId: item.ReadBack.ProviderID,
			ObservedAt: cloudStatusTimestamp(item.ReadBack.ObservedAt), TagDigest: item.ReadBack.TagDigest}, DestroyDeadline: cloudStatusTimestamp(item.DestroyDeadline), AutoDestroyApproved: item.AutoDestroyApproved}
}

func cloudDestroyOperationToProto(value clouddestroy.OperationV1) *agentv1.CloudDestroyOperation {
	return &agentv1.CloudDestroyOperation{OperationId: value.Challenge.OperationID, OwnerId: value.Challenge.Scope.OwnerID, DeploymentId: value.Challenge.Scope.DeploymentID,
		ApprovalId: value.Challenge.ApprovalID, ScopeDigest: value.Challenge.ScopeDigest, Status: cloudDestroyStatusToProto(value.Status),
		BlockedReason: value.BlockedReason, ErrorCode: value.ErrorCode, Revision: value.Revision, CreatedAt: cloudStatusTimestamp(value.CreatedAt), UpdatedAt: cloudStatusTimestamp(value.UpdatedAt)}
}

func cloudDestroyStatusToProto(value clouddestroy.Status) agentv1.CloudDestroyOperationStatus {
	switch value {
	case clouddestroy.StatusAwaitingApproval:
		return agentv1.CloudDestroyOperationStatus_CLOUD_DESTROY_OPERATION_STATUS_AWAITING_APPROVAL
	case clouddestroy.StatusApproved:
		return agentv1.CloudDestroyOperationStatus_CLOUD_DESTROY_OPERATION_STATUS_APPROVED
	case clouddestroy.StatusDestroying:
		return agentv1.CloudDestroyOperationStatus_CLOUD_DESTROY_OPERATION_STATUS_DESTROYING
	case clouddestroy.StatusVerifiedDestroyed:
		return agentv1.CloudDestroyOperationStatus_CLOUD_DESTROY_OPERATION_STATUS_VERIFIED_DESTROYED
	case clouddestroy.StatusDestroyBlocked:
		return agentv1.CloudDestroyOperationStatus_CLOUD_DESTROY_OPERATION_STATUS_DESTROY_BLOCKED
	default:
		return agentv1.CloudDestroyOperationStatus_CLOUD_DESTROY_OPERATION_STATUS_UNSPECIFIED
	}
}
