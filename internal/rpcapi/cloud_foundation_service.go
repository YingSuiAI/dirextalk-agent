package rpcapi

import (
	"context"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	cloudfoundation "github.com/YingSuiAI/dirextalk-agent/internal/cloud/foundation"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (service *CloudControlService) CreateAwsFoundationOperationChallenge(ctx context.Context, request *agentv1.CreateAwsFoundationOperationChallengeRequest) (*agentv1.CreateAwsFoundationOperationChallengeResponse, error) {
	caller, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service.foundation == nil {
		return nil, cloudUnavailable()
	}
	action, ok := foundationActionFromProto(request.GetAction())
	if !ok || request.GetExpectedBootstrapRevision() < 1 {
		return nil, status.Error(codes.InvalidArgument, "valid Foundation action and bootstrap revision are required")
	}
	challenge, err := service.foundation.Prepare(ctx, cloudfoundation.PrepareCommand{Caller: cloudfoundation.MutationScope{ClientID: caller.ClientID, CredentialID: caller.CredentialID},
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(), Action: action, ConnectionID: request.GetConnectionId(),
		BootstrapSessionID: request.GetBootstrapSessionId(), ExpectedBootstrapRevision: uint64(request.GetExpectedBootstrapRevision()), SignerKeyID: request.GetSignerKeyId()})
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.CreateAwsFoundationOperationChallengeResponse{Challenge: foundationChallengeToProto(challenge)}, nil
}

func (service *CloudControlService) ApproveAwsFoundationOperation(ctx context.Context, request *agentv1.ApproveAwsFoundationOperationRequest) (*agentv1.ApproveAwsFoundationOperationResponse, error) {
	caller, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service.foundation == nil {
		return nil, cloudUnavailable()
	}
	approval, err := cloudApprovalFromProto(request.GetApproval())
	action, actionOK := foundationActionFromProto(request.GetAction())
	if err != nil || !actionOK || request.GetExpectedRevision() != 1 {
		return nil, status.Error(codes.InvalidArgument, "valid Foundation device approval is required")
	}
	operation, err := service.foundation.Approve(ctx, cloudfoundation.ApproveCommand{Caller: cloudfoundation.MutationScope{ClientID: caller.ClientID, CredentialID: caller.CredentialID},
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(), OperationID: request.GetOperationId(), ExpectedRevision: request.GetExpectedRevision(),
		ConnectionID: request.GetConnectionId(), Action: action, ScopeDigest: request.GetScopeDigest(), Signature: cloudfoundation.SignatureV1{ApprovalID: approval.ApprovalID,
			ChallengeID: approval.ChallengeID, SignerKeyID: approval.SignerKeyID, ExpiresAt: approval.ExpiresAt, Signature: approval.Signature}})
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.ApproveAwsFoundationOperationResponse{Operation: foundationOperationToProto(operation)}, nil
}

func (service *CloudControlService) GetAwsFoundationOperation(ctx context.Context, request *agentv1.GetAwsFoundationOperationRequest) (*agentv1.GetAwsFoundationOperationResponse, error) {
	if service.foundation == nil {
		return nil, cloudUnavailable()
	}
	operation, err := service.foundation.Get(ctx, request.GetOwnerId(), request.GetOperationId())
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.GetAwsFoundationOperationResponse{Operation: foundationOperationToProto(operation)}, nil
}

func foundationChallengeToProto(value cloudfoundation.ChallengeV1) *agentv1.AwsFoundationOperationChallenge {
	environment := value.Scope.ReleaseEnvironment
	return &agentv1.AwsFoundationOperationChallenge{OperationId: value.OperationID, ChallengeId: value.ChallengeID, ApprovalId: value.ApprovalID,
		SignerKeyId: value.SignerKeyID, ScopeDigest: value.ScopeDigest, ExpiresAt: cloudStatusTimestamp(value.ExpiresAt), SigningPayloadCbor: append([]byte(nil), value.SigningCBOR...), Revision: value.Revision,
		Scope: &agentv1.AwsFoundationOperationScope{SchemaVersion: value.Scope.SchemaVersion, AgentInstanceId: value.Scope.AgentInstanceID, OwnerId: value.Scope.OwnerID,
			Action: foundationActionToProto(value.Scope.Action), ConnectionId: value.Scope.ConnectionID, ExpectedConnectionRevision: value.Scope.ExpectedConnectionRevision,
			AccountId: value.Scope.AccountID, Region: value.Scope.Region, BootstrapSessionId: value.Scope.BootstrapSessionID,
			ExpectedBootstrapRevision: int64(value.Scope.ExpectedBootstrapRevision), ExpectedCredentialGeneration: int64(value.Scope.ExpectedCredentialGeneration),
			FoundationTemplateDigest: value.Scope.FoundationTemplateDigest, ReaperImageUri: value.Scope.ReaperImageURI,
			IdentityObservedAt: cloudStatusTimestamp(value.Scope.IdentityObservedAt), IdentityExpiresAt: cloudStatusTimestamp(value.Scope.IdentityExpiresAt),
			ReleaseEnvironment: &agentv1.AwsFoundationReleaseEnvironment{PrivateSubnetCidr: environment.PrivateSubnetCIDR, ZeroIngress: environment.ZeroIngress,
				ArtifactBucket: environment.ArtifactBucket, KmsAlias: environment.KMSAlias, BucketVersioned: environment.BucketVersioned, BucketSseKms: environment.BucketSSEKMS}}}
}

func foundationOperationToProto(value cloudfoundation.OperationV1) *agentv1.AwsFoundationOperation {
	return &agentv1.AwsFoundationOperation{OperationId: value.Challenge.OperationID, OwnerId: value.Challenge.Scope.OwnerID, ConnectionId: value.Challenge.Scope.ConnectionID,
		Action: foundationActionToProto(value.Challenge.Scope.Action), ApprovalId: value.Challenge.ApprovalID, ScopeDigest: value.Challenge.ScopeDigest,
		Status: foundationStatusToProto(value.Status), ErrorCode: value.ErrorCode, BlockedReason: value.BlockedReason, Revision: value.Revision,
		CreatedAt: cloudStatusTimestamp(value.CreatedAt), UpdatedAt: cloudStatusTimestamp(value.UpdatedAt)}
}

func foundationActionFromProto(value agentv1.AwsFoundationOperationAction) (cloudfoundation.Action, bool) {
	switch value {
	case agentv1.AwsFoundationOperationAction_AWS_FOUNDATION_OPERATION_ACTION_ESTABLISH:
		return cloudfoundation.ActionEstablish, true
	case agentv1.AwsFoundationOperationAction_AWS_FOUNDATION_OPERATION_ACTION_UPGRADE:
		return cloudfoundation.ActionUpgrade, true
	case agentv1.AwsFoundationOperationAction_AWS_FOUNDATION_OPERATION_ACTION_TEARDOWN:
		return cloudfoundation.ActionTeardown, true
	case agentv1.AwsFoundationOperationAction_AWS_FOUNDATION_OPERATION_ACTION_REMEDIATE_DESTROY_BLOCKED:
		return cloudfoundation.ActionRemediate, true
	default:
		return "", false
	}
}

func foundationActionToProto(value cloudfoundation.Action) agentv1.AwsFoundationOperationAction {
	switch value {
	case cloudfoundation.ActionEstablish:
		return agentv1.AwsFoundationOperationAction_AWS_FOUNDATION_OPERATION_ACTION_ESTABLISH
	case cloudfoundation.ActionUpgrade:
		return agentv1.AwsFoundationOperationAction_AWS_FOUNDATION_OPERATION_ACTION_UPGRADE
	case cloudfoundation.ActionTeardown:
		return agentv1.AwsFoundationOperationAction_AWS_FOUNDATION_OPERATION_ACTION_TEARDOWN
	case cloudfoundation.ActionRemediate:
		return agentv1.AwsFoundationOperationAction_AWS_FOUNDATION_OPERATION_ACTION_REMEDIATE_DESTROY_BLOCKED
	default:
		return agentv1.AwsFoundationOperationAction_AWS_FOUNDATION_OPERATION_ACTION_UNSPECIFIED
	}
}

func foundationStatusToProto(value cloudfoundation.Status) agentv1.AwsFoundationOperationStatus {
	switch value {
	case cloudfoundation.StatusAwaitingApproval:
		return agentv1.AwsFoundationOperationStatus_AWS_FOUNDATION_OPERATION_STATUS_AWAITING_APPROVAL
	case cloudfoundation.StatusApproved:
		return agentv1.AwsFoundationOperationStatus_AWS_FOUNDATION_OPERATION_STATUS_APPROVED
	case cloudfoundation.StatusRunning:
		return agentv1.AwsFoundationOperationStatus_AWS_FOUNDATION_OPERATION_STATUS_RUNNING
	case cloudfoundation.StatusSucceeded:
		return agentv1.AwsFoundationOperationStatus_AWS_FOUNDATION_OPERATION_STATUS_SUCCEEDED
	case cloudfoundation.StatusFailedRetriable:
		return agentv1.AwsFoundationOperationStatus_AWS_FOUNDATION_OPERATION_STATUS_FAILED_RETRIABLE
	case cloudfoundation.StatusFailedTerminal:
		return agentv1.AwsFoundationOperationStatus_AWS_FOUNDATION_OPERATION_STATUS_FAILED_TERMINAL
	case cloudfoundation.StatusDestroyBlocked:
		return agentv1.AwsFoundationOperationStatus_AWS_FOUNDATION_OPERATION_STATUS_DESTROY_BLOCKED
	default:
		return agentv1.AwsFoundationOperationStatus_AWS_FOUNDATION_OPERATION_STATUS_UNSPECIFIED
	}
}
