package rpcapi

import (
	"context"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/managed"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
)

func (service *CloudControlService) CreateCloudManagedAcceptanceChallenge(ctx context.Context, request *agentv1.CreateCloudManagedAcceptanceChallengeRequest) (*agentv1.CreateCloudManagedAcceptanceChallengeResponse, error) {
	caller, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if err := service.requireWorkerControlPrivateLink(ctx); err != nil {
		return nil, err
	}
	if service.managed == nil {
		return nil, cloudUnavailable()
	}
	value, err := service.managed.Prepare(ctx, managed.PrepareCommand{ClientID: caller.ClientID, CredentialID: caller.CredentialID,
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(), DeploymentID: request.GetDeploymentId(),
		SignerKeyID: request.GetSignerKeyId(), ExpectedDeploymentRevision: request.GetExpectedDeploymentRevision()})
	if err != nil {
		return nil, publicError(err)
	}
	challenge, err := managedChallengeToProto(value)
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.CreateCloudManagedAcceptanceChallengeResponse{Challenge: challenge}, nil
}
func (service *CloudControlService) ApproveCloudManagedAcceptance(ctx context.Context, request *agentv1.ApproveCloudManagedAcceptanceRequest) (*agentv1.ApproveCloudManagedAcceptanceResponse, error) {
	caller, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if err := service.requireWorkerControlPrivateLink(ctx); err != nil {
		return nil, err
	}
	if service.managed == nil {
		return nil, cloudUnavailable()
	}
	approval, err := cloudApprovalFromProto(request.GetApproval())
	if err != nil {
		return nil, publicError(err)
	}
	value, err := service.managed.Approve(ctx, managed.ApproveCommand{ClientID: caller.ClientID, CredentialID: caller.CredentialID,
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(), OperationID: request.GetAcceptanceId(),
		DeploymentID: request.GetDeploymentId(), ScopeDigest: request.GetScopeDigest(), ExpectedRevision: request.GetExpectedRevision(),
		Signature: managed.SignatureV1{ChallengeID: approval.ChallengeID, ApprovalID: approval.ApprovalID, SignerKeyID: approval.SignerKeyID, Signature: approval.Signature}})
	if err != nil {
		return nil, publicError(err)
	}
	operation, err := managedOperationToProto(value)
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.ApproveCloudManagedAcceptanceResponse{Operation: operation}, nil
}
func (service *CloudControlService) GetCloudManagedAcceptanceOperation(ctx context.Context, request *agentv1.GetCloudManagedAcceptanceOperationRequest) (*agentv1.GetCloudManagedAcceptanceOperationResponse, error) {
	if service.managed == nil {
		return nil, cloudUnavailable()
	}
	value, err := service.managed.Get(ctx, request.GetOwnerId(), request.GetOperationId())
	if err != nil {
		return nil, publicError(err)
	}
	operation, err := managedOperationToProto(value)
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.GetCloudManagedAcceptanceOperationResponse{Operation: operation}, nil
}
func managedChallengeToProto(v managed.ChallengeV1) (*agentv1.CloudManagedAcceptanceChallenge, error) {
	payload, err := v.SigningPayload()
	if err != nil {
		return nil, managed.ErrInvalid
	}
	s := v.Scope
	resources := make([]*agentv1.CloudManagedAcceptanceResource, 0, len(s.Resources))
	for _, r := range s.Resources {
		resources = append(resources, &agentv1.CloudManagedAcceptanceResource{ResourceId: r.ResourceID, Type: cloudResourceTypeToProto(resource.Type(r.Type)), Revision: r.Revision, ProviderId: r.ProviderID, TagDigest: r.TagDigest})
	}
	volumes := make([]*agentv1.CloudManagedVolumeSlot, 0, len(s.VolumeSlots))
	for _, slot := range s.VolumeSlots {
		volumes = append(volumes, &agentv1.CloudManagedVolumeSlot{SlotId: slot.SlotID, VolumeRef: slot.VolumeRef, ReadOnly: slot.ReadOnly})
	}
	data := make([]*agentv1.CloudManagedDataSlot, 0, len(s.DataSlots))
	for _, slot := range s.DataSlots {
		data = append(data, &agentv1.CloudManagedDataSlot{SlotId: slot.SlotID, DataRef: slot.DataRef, ReadOnly: slot.ReadOnly})
	}
	secrets := make([]*agentv1.CloudManagedSecretSlot, 0, len(s.SecretSlots))
	for _, slot := range s.SecretSlots {
		secrets = append(secrets, &agentv1.CloudManagedSecretSlot{SlotId: slot.SlotID, SecretRef: slot.SecretRef})
	}
	scope := &agentv1.CloudManagedAcceptanceScope{AgentInstanceId: s.AgentInstanceID, AcceptanceId: s.AcceptanceID, ServiceId: s.ServiceID, ServiceRevision: s.ServiceRevision, OwnerId: s.OwnerID,
		DeploymentId: s.DeploymentID, DeploymentRevision: s.DeploymentRevision, ConnectionId: s.ConnectionID, ConnectionRevision: s.ConnectionRevision, PlanId: s.PlanID, PlanRevision: s.PlanRevision, PlanHash: s.PlanHash,
		RecipeId: s.RecipeID, RecipeDigest: s.RecipeDigest, RecipeRevision: s.RecipeRevision, RecipeMaturity: s.RecipeMaturity, InstalledManifestDigest: s.InstalledManifestDigest,
		ArtifactDigest: s.ArtifactDigest, ReadinessSemanticEvidenceDigest: s.ReadinessSemanticEvidenceDigest, ReadinessStackObservationDigest: s.ReadinessStackObservationDigest,
		RestartOperationId: s.RestartOperationID, RestartOperationRevision: s.RestartOperationRevision, BackupId: s.BackupID, BackupRevision: s.BackupRevision, RestoreId: s.RestoreID, RestoreRevision: s.RestoreRevision,
		SourceArtifactDigests: s.SourceArtifactDigests, HealthRevision: s.HealthRevision, HealthMonitorKind: s.HealthMonitorKind, HealthStatus: s.HealthStatus, HealthEvidenceType: s.HealthEvidenceType, HealthEvidenceDigest: s.HealthEvidenceDigest, HealthObservedAt: cloudStatusTimestamp(s.HealthObservedAt),
		Currency: s.Currency, CostAlertAmountMinor: s.CostAlertAmountMinor, Lifecycle: &agentv1.CloudManagedLifecycleContract{Start: s.Lifecycle.Start, Stop: s.Lifecycle.Stop, Maintenance: s.Lifecycle.Maintenance, Restart: s.Lifecycle.Restart, Backup: s.Lifecycle.Backup, Restore: s.Lifecycle.Restore, Upgrade: s.Lifecycle.Upgrade, Rollback: s.Lifecycle.Rollback, Destroy: s.Lifecycle.Destroy},
		Health: &agentv1.CloudManagedHealthContract{
			Liveness:  &agentv1.CloudManagedHealthProbe{Kind: s.Health.Liveness.Kind, Target: s.Health.Liveness.Target},
			Readiness: &agentv1.CloudManagedHealthProbe{Kind: s.Health.Readiness.Kind, Target: s.Health.Readiness.Target},
			Semantic:  &agentv1.CloudManagedHealthProbe{Kind: s.Health.Semantic.Kind, Target: s.Health.Semantic.Target},
		},
		VolumeSlots: volumes, DataSlots: data, SecretSlots: secrets,
		Resources: resources, DestroyInstanceId: s.DestroyInstanceID, DestroyVolumeIds: s.DestroyVolumeIDs, DestroyNetworkInterfaceIds: s.DestroyNetworkInterfaceIDs, AcceptancePolicy: s.AcceptancePolicy}
	return &agentv1.CloudManagedAcceptanceChallenge{
		OperationId: v.ApprovalID, ChallengeId: v.ChallengeID, ApprovalId: v.ApprovalID, SignerKeyId: v.SignerKeyID,
		Scope: scope, ScopeDigest: v.ScopeDigest, IssuedAt: cloudStatusTimestamp(v.IssuedAt), ExpiresAt: cloudStatusTimestamp(v.ExpiresAt),
		Revision: 1, SigningPayloadCbor: payload, CompatibilityService: managedCompatibilityServiceToProto(v.Service),
		CompatibilityRecipe: managedCompatibilityRecipeToProto(v.Recipe),
	}, nil
}
func managedOperationToProto(v managed.OperationV1) (*agentv1.CloudManagedAcceptanceOperation, error) {
	status := agentv1.CloudManagedAcceptanceOperationStatus_CLOUD_MANAGED_ACCEPTANCE_OPERATION_STATUS_UNSPECIFIED
	switch v.Status {
	case managed.StatusAwaitingApproval:
		status = agentv1.CloudManagedAcceptanceOperationStatus_CLOUD_MANAGED_ACCEPTANCE_OPERATION_STATUS_AWAITING_APPROVAL
	case managed.StatusApproved:
		status = agentv1.CloudManagedAcceptanceOperationStatus_CLOUD_MANAGED_ACCEPTANCE_OPERATION_STATUS_APPROVED
	case managed.StatusRunning:
		status = agentv1.CloudManagedAcceptanceOperationStatus_CLOUD_MANAGED_ACCEPTANCE_OPERATION_STATUS_RUNNING
	case managed.StatusSucceeded:
		status = agentv1.CloudManagedAcceptanceOperationStatus_CLOUD_MANAGED_ACCEPTANCE_OPERATION_STATUS_SUCCEEDED
	case managed.StatusFailedTerminal:
		status = agentv1.CloudManagedAcceptanceOperationStatus_CLOUD_MANAGED_ACCEPTANCE_OPERATION_STATUS_FAILED_TERMINAL
	}
	if status == agentv1.CloudManagedAcceptanceOperationStatus_CLOUD_MANAGED_ACCEPTANCE_OPERATION_STATUS_UNSPECIFIED {
		return nil, managed.ErrInvalid
	}
	challenge, err := managedChallengeToProto(v.Challenge)
	if err != nil {
		return nil, err
	}
	result := &agentv1.CloudManagedAcceptanceOperation{OperationId: v.OperationID, Challenge: challenge, Status: status, Revision: v.Revision, ErrorCode: v.ErrorCode, ErrorSummary: v.ErrorSummary, CreatedAt: cloudStatusTimestamp(v.CreatedAt), UpdatedAt: cloudStatusTimestamp(v.UpdatedAt)}
	if v.Status == managed.StatusSucceeded && v.ApprovedAt != nil {
		service := v.Challenge.Service
		service.Status, service.Revision, service.UpdatedAt = "active", service.Revision+1, v.UpdatedAt.UnixMilli()
		recipe := v.Challenge.Recipe
		recipe.Maturity, recipe.Revision, recipe.UpdatedAt = "managed", recipe.Revision+1, v.UpdatedAt.UnixMilli()
		result.CompatibilityService = managedCompatibilityServiceToProto(service)
		result.CompatibilityRecipe = managedCompatibilityRecipeToProto(recipe)
		result.CompatibilityAcceptance = &agentv1.CloudManagedCompatibilityAcceptance{
			AcceptanceId: v.OperationID, ServiceId: service.ServiceID, RecipeId: recipe.RecipeID, Status: "approved",
			Revision: 1, CreatedAtUnixMs: v.ApprovedAt.UnixMilli(), UpdatedAtUnixMs: v.UpdatedAt.UnixMilli(),
		}
	}
	return result, nil
}

func managedCompatibilityServiceToProto(v managed.CompatibilityServiceV1) *agentv1.CloudManagedCompatibilityService {
	result := &agentv1.CloudManagedCompatibilityService{
		ServiceId: v.ServiceID, DeploymentId: v.DeploymentID, RecipeId: v.RecipeID, Name: v.Name,
		ServiceStatus: v.Status, IntegrationStatus: v.Integration, Revision: v.Revision,
		CreatedAtUnixMs: v.CreatedAt, UpdatedAtUnixMs: v.UpdatedAt,
	}
	for _, backup := range v.Backups {
		result.Backups = append(result.Backups, &agentv1.CloudManagedCompatibilityBackup{
			BackupId: backup.BackupID, ServiceId: backup.ServiceID, DeploymentId: backup.DeploymentID,
			Status: backup.Status, RetentionPolicy: backup.RetentionPolicy, ImageId: backup.ImageID,
			SnapshotIds: backup.SnapshotIDs, Revision: backup.Revision,
			CreatedAtUnixMs: backup.CreatedAt, UpdatedAtUnixMs: backup.UpdatedAt,
		})
	}
	for _, restore := range v.Restores {
		result.Restores = append(result.Restores, &agentv1.CloudManagedCompatibilityRestore{
			RestoreId: restore.RestoreID, RestorePlanId: restore.RestorePlanID, ServiceId: restore.ServiceID,
			DeploymentId: restore.DeploymentID, BackupId: restore.BackupID, Status: restore.Status,
			OriginalVolumeIds: restore.OriginalVolumeIDs, ReplacementVolumeIds: restore.ReplacementVolumeIDs,
			Revision: restore.Revision, CreatedAtUnixMs: restore.CreatedAt, UpdatedAtUnixMs: restore.UpdatedAt,
		})
	}
	return result
}

func managedCompatibilityRecipeToProto(v managed.CompatibilityRecipeV1) *agentv1.CloudManagedCompatibilityRecipe {
	return &agentv1.CloudManagedCompatibilityRecipe{
		RecipeId: v.RecipeID, Name: v.Name, Version: v.Version, Digest: v.Digest, Maturity: v.Maturity,
		Revision: v.Revision, CreatedAtUnixMs: v.CreatedAt, UpdatedAtUnixMs: v.UpdatedAt,
	}
}
