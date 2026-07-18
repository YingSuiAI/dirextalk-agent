package rpcapi

import (
	"context"
	"errors"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/managedlifecycle"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (service *CloudControlService) PrepareManagedKnowledgeLifecycle(ctx context.Context, request *agentv1.PrepareManagedKnowledgeLifecycleRequest) (*agentv1.PrepareManagedKnowledgeLifecycleResponse, error) {
	caller, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service.managedLifecycle == nil || request == nil {
		return nil, managedKnowledgeLifecyclePublicError(managedlifecycle.ErrInvalid)
	}
	action, err := managedKnowledgeLifecycleActionFromProto(request.GetAction())
	if err != nil {
		return nil, managedKnowledgeLifecyclePublicError(err)
	}
	value, err := service.managedLifecycle.Prepare(ctx, managedlifecycle.PrepareCommand{
		Caller:         managedlifecycle.MutationScope{ClientID: caller.ClientID, CredentialID: caller.CredentialID},
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(),
		DeploymentID: request.GetDeploymentId(), ManagedServiceID: request.GetManagedServiceId(),
		KnowledgeBindingID: request.GetKnowledgeBindingId(), SignerKeyID: request.GetSignerKeyId(),
		ExpectedDeploymentRevision: request.GetExpectedDeploymentRevision(), Action: action,
	})
	if err != nil {
		return nil, managedKnowledgeLifecyclePublicError(err)
	}
	converted, err := managedKnowledgeLifecycleChallengeToProto(value)
	if err != nil {
		return nil, status.Error(codes.Internal, "stored managed Knowledge lifecycle challenge is invalid")
	}
	return &agentv1.PrepareManagedKnowledgeLifecycleResponse{Challenge: converted}, nil
}

func (service *CloudControlService) ApproveManagedKnowledgeLifecycle(ctx context.Context, request *agentv1.ApproveManagedKnowledgeLifecycleRequest) (*agentv1.ApproveManagedKnowledgeLifecycleResponse, error) {
	caller, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service.managedLifecycle == nil || request == nil || request.GetApproval() == nil {
		return nil, managedKnowledgeLifecyclePublicError(managedlifecycle.ErrInvalid)
	}
	approval := request.GetApproval()
	value, err := service.managedLifecycle.Approve(ctx, managedlifecycle.ApproveCommand{
		Caller:         managedlifecycle.MutationScope{ClientID: caller.ClientID, CredentialID: caller.CredentialID},
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(),
		DeploymentID: request.GetDeploymentId(), OperationID: request.GetOperationId(),
		ScopeDigest: request.GetScopeDigest(), ExpectedRevision: request.GetExpectedRevision(),
		Signature: managedlifecycle.SignatureV1{
			ChallengeID: approval.GetChallengeId(), ApprovalID: approval.GetApprovalId(),
			SignerKeyID: approval.GetSignerKeyId(), Signature: append([]byte(nil), approval.GetSignature()...),
		},
	})
	if err != nil {
		return nil, managedKnowledgeLifecyclePublicError(err)
	}
	converted, err := managedKnowledgeLifecycleOperationToProto(value)
	if err != nil {
		return nil, status.Error(codes.Internal, "stored managed Knowledge lifecycle operation is invalid")
	}
	return &agentv1.ApproveManagedKnowledgeLifecycleResponse{Operation: converted}, nil
}

func (service *CloudControlService) GetManagedKnowledgeLifecycle(ctx context.Context, request *agentv1.GetManagedKnowledgeLifecycleRequest) (*agentv1.GetManagedKnowledgeLifecycleResponse, error) {
	if _, err := cloudMutationScope(ctx); err != nil {
		return nil, err
	}
	if service.managedLifecycle == nil || request == nil {
		return nil, managedKnowledgeLifecyclePublicError(managedlifecycle.ErrInvalid)
	}
	value, err := service.managedLifecycle.Get(ctx, request.GetOwnerId(), request.GetOperationId())
	if err != nil {
		return nil, managedKnowledgeLifecyclePublicError(err)
	}
	converted, err := managedKnowledgeLifecycleOperationToProto(value)
	if err != nil {
		return nil, status.Error(codes.Internal, "stored managed Knowledge lifecycle operation is invalid")
	}
	return &agentv1.GetManagedKnowledgeLifecycleResponse{Operation: converted}, nil
}

func managedKnowledgeLifecycleChallengeToProto(value managedlifecycle.ChallengeV1) (*agentv1.ManagedKnowledgeLifecycleChallenge, error) {
	if value.Validate() != nil {
		return nil, managedlifecycle.ErrInvalid
	}
	action, err := managedKnowledgeLifecycleActionToProto(value.Scope.Action)
	if err != nil {
		return nil, err
	}
	return &agentv1.ManagedKnowledgeLifecycleChallenge{
		OperationId: value.OperationID, ChallengeId: value.ChallengeID, ApprovalId: value.ApprovalID,
		SignerKeyId: value.SignerKeyID, ScopeDigest: value.ScopeDigest, SigningCbor: append([]byte(nil), value.SigningCBOR...),
		IssuedAt: timestamppb.New(value.IssuedAt), ExpiresAt: timestamppb.New(value.ExpiresAt), Revision: value.Revision,
		Scope: &agentv1.ManagedKnowledgeLifecycleScope{
			SchemaVersion: value.Scope.SchemaVersion, AgentInstanceId: value.Scope.AgentInstanceID,
			OwnerId: value.Scope.OwnerID, DeploymentId: value.Scope.DeploymentID,
			ManagedServiceId: value.Scope.ManagedServiceID, KnowledgeBindingId: value.Scope.KnowledgeBindingID,
			DeploymentRevision: value.Scope.DeploymentRevision, ManagedServiceRevision: value.Scope.ManagedServiceRevision,
			KnowledgeBindingRevision: value.Scope.KnowledgeBindingRevision, RecipeDigest: value.Scope.RecipeDigest,
			Action: action, LifecycleRef: value.Scope.LifecycleRef,
			ExecutionBundleDigest:   value.Scope.ExecutionBundleDigest,
			InstalledManifestDigest: value.Scope.InstalledManifestDigest,
		},
	}, nil
}

func managedKnowledgeLifecycleOperationToProto(value managedlifecycle.OperationV1) (*agentv1.ManagedKnowledgeLifecycleOperation, error) {
	if value.Validate() != nil {
		return nil, managedlifecycle.ErrInvalid
	}
	challenge, err := managedKnowledgeLifecycleChallengeToProto(value.Challenge)
	if err != nil {
		return nil, err
	}
	statusValue := map[managedlifecycle.Status]agentv1.ManagedKnowledgeLifecycleStatus{
		managedlifecycle.StatusAwaitingApproval: agentv1.ManagedKnowledgeLifecycleStatus_MANAGED_KNOWLEDGE_LIFECYCLE_STATUS_AWAITING_APPROVAL,
		managedlifecycle.StatusScheduled:        agentv1.ManagedKnowledgeLifecycleStatus_MANAGED_KNOWLEDGE_LIFECYCLE_STATUS_SCHEDULED,
		managedlifecycle.StatusRunning:          agentv1.ManagedKnowledgeLifecycleStatus_MANAGED_KNOWLEDGE_LIFECYCLE_STATUS_RUNNING,
		managedlifecycle.StatusSucceeded:        agentv1.ManagedKnowledgeLifecycleStatus_MANAGED_KNOWLEDGE_LIFECYCLE_STATUS_SUCCEEDED,
		managedlifecycle.StatusFailed:           agentv1.ManagedKnowledgeLifecycleStatus_MANAGED_KNOWLEDGE_LIFECYCLE_STATUS_FAILED,
		managedlifecycle.StatusDestroyBlocked:   agentv1.ManagedKnowledgeLifecycleStatus_MANAGED_KNOWLEDGE_LIFECYCLE_STATUS_DESTROY_BLOCKED,
	}[value.Status]
	if statusValue == agentv1.ManagedKnowledgeLifecycleStatus_MANAGED_KNOWLEDGE_LIFECYCLE_STATUS_UNSPECIFIED {
		return nil, managedlifecycle.ErrInvalid
	}
	result := &agentv1.ManagedKnowledgeLifecycleOperation{
		Challenge: challenge, Status: statusValue, WorkerOperationId: value.WorkerOperationID,
		ErrorCode: value.ErrorCode, RequiresNewApproval: value.RequiresNewApproval, Revision: value.Revision,
		CreatedAt: timestamppb.New(value.CreatedAt), UpdatedAt: timestamppb.New(value.UpdatedAt),
	}
	if value.ApprovedAt != nil {
		result.ApprovedAt = timestamppb.New(*value.ApprovedAt)
	}
	return result, nil
}

func managedKnowledgeLifecycleActionFromProto(value agentv1.ManagedKnowledgeLifecycleAction) (managedlifecycle.Action, error) {
	switch value {
	case agentv1.ManagedKnowledgeLifecycleAction_MANAGED_KNOWLEDGE_LIFECYCLE_ACTION_STOP:
		return managedlifecycle.ActionStop, nil
	case agentv1.ManagedKnowledgeLifecycleAction_MANAGED_KNOWLEDGE_LIFECYCLE_ACTION_BACKUP:
		return managedlifecycle.ActionBackup, nil
	case agentv1.ManagedKnowledgeLifecycleAction_MANAGED_KNOWLEDGE_LIFECYCLE_ACTION_RESTORE:
		return managedlifecycle.ActionRestore, nil
	case agentv1.ManagedKnowledgeLifecycleAction_MANAGED_KNOWLEDGE_LIFECYCLE_ACTION_UPGRADE:
		return managedlifecycle.ActionUpgrade, nil
	case agentv1.ManagedKnowledgeLifecycleAction_MANAGED_KNOWLEDGE_LIFECYCLE_ACTION_ROLLBACK:
		return managedlifecycle.ActionRollback, nil
	case agentv1.ManagedKnowledgeLifecycleAction_MANAGED_KNOWLEDGE_LIFECYCLE_ACTION_DESTROY:
		return managedlifecycle.ActionDestroy, nil
	default:
		return "", managedlifecycle.ErrInvalid
	}
}

func managedKnowledgeLifecycleActionToProto(value managedlifecycle.Action) (agentv1.ManagedKnowledgeLifecycleAction, error) {
	switch value {
	case managedlifecycle.ActionStop:
		return agentv1.ManagedKnowledgeLifecycleAction_MANAGED_KNOWLEDGE_LIFECYCLE_ACTION_STOP, nil
	case managedlifecycle.ActionBackup:
		return agentv1.ManagedKnowledgeLifecycleAction_MANAGED_KNOWLEDGE_LIFECYCLE_ACTION_BACKUP, nil
	case managedlifecycle.ActionRestore:
		return agentv1.ManagedKnowledgeLifecycleAction_MANAGED_KNOWLEDGE_LIFECYCLE_ACTION_RESTORE, nil
	case managedlifecycle.ActionUpgrade:
		return agentv1.ManagedKnowledgeLifecycleAction_MANAGED_KNOWLEDGE_LIFECYCLE_ACTION_UPGRADE, nil
	case managedlifecycle.ActionRollback:
		return agentv1.ManagedKnowledgeLifecycleAction_MANAGED_KNOWLEDGE_LIFECYCLE_ACTION_ROLLBACK, nil
	case managedlifecycle.ActionDestroy:
		return agentv1.ManagedKnowledgeLifecycleAction_MANAGED_KNOWLEDGE_LIFECYCLE_ACTION_DESTROY, nil
	default:
		return 0, managedlifecycle.ErrInvalid
	}
}

func managedKnowledgeLifecyclePublicError(err error) error {
	switch {
	case errors.Is(err, managedlifecycle.ErrInvalid):
		return status.Error(codes.InvalidArgument, "managed Knowledge lifecycle request is invalid")
	case errors.Is(err, managedlifecycle.ErrNotFound):
		return status.Error(codes.NotFound, "managed Knowledge lifecycle operation was not found")
	case errors.Is(err, managedlifecycle.ErrApprovalRequired):
		return status.Error(codes.PermissionDenied, "managed Knowledge lifecycle device approval is required")
	case errors.Is(err, managedlifecycle.ErrRevisionConflict):
		return status.Error(codes.Aborted, "managed Knowledge lifecycle facts no longer match")
	case errors.Is(err, managedlifecycle.ErrIdempotencyConflict):
		return status.Error(codes.AlreadyExists, "managed Knowledge lifecycle request conflicts with an earlier request")
	default:
		return status.Error(codes.Unavailable, "managed Knowledge lifecycle is unavailable")
	}
}
