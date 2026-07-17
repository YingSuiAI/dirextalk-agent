package rpcapi

import (
	"context"
	"crypto/ed25519"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/serviceoperation"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (service *CloudControlService) CreateCloudManagedPreparation(ctx context.Context, request *agentv1.CreateCloudManagedPreparationRequest) (*agentv1.CreateCloudManagedPreparationResponse, error) {
	if service.preparation == nil {
		return nil, cloudUnavailable()
	}
	caller, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil {
		return nil, publicError(serviceoperation.ErrInvalid)
	}
	value, err := service.preparation.Prepare(ctx, serviceoperation.PrepareCommand{
		ClientID: caller.ClientID, CredentialID: caller.CredentialID, IdempotencyKey: request.GetIdempotencyKey(),
		OwnerID: request.GetOwnerId(), DeploymentID: request.GetDeploymentId(), SignerKeyID: request.GetSignerKeyId(),
		ExpectedDeploymentRevision: request.GetExpectedDeploymentRevision(), CostAlertAmountMinor: request.GetCostAlertAmountMinor(),
	})
	if err != nil {
		return nil, publicError(err)
	}
	challenge, err := managedPreparationChallengeToProto(value)
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.CreateCloudManagedPreparationResponse{Challenge: challenge}, nil
}

func (service *CloudControlService) ApproveCloudManagedPreparation(ctx context.Context, request *agentv1.ApproveCloudManagedPreparationRequest) (*agentv1.ApproveCloudManagedPreparationResponse, error) {
	if service.preparation == nil {
		return nil, cloudUnavailable()
	}
	caller, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil || request.GetApproval() == nil || request.GetApproval().GetApprovalId() != request.GetOperationId() ||
		len(request.GetApproval().GetSignature()) != ed25519.SignatureSize || request.GetApproval().GetExpiresAt() == nil ||
		!request.GetApproval().GetExpiresAt().IsValid() || request.GetApproval().GetExpiresAt().AsTime().UTC().Equal(time.Time{}) {
		return nil, publicError(serviceoperation.ErrInvalid)
	}
	approval := request.GetApproval()
	value, err := service.preparation.Approve(ctx, serviceoperation.ApproveCommand{
		ClientID: caller.ClientID, CredentialID: caller.CredentialID, IdempotencyKey: request.GetIdempotencyKey(),
		OwnerID: request.GetOwnerId(), OperationID: request.GetOperationId(), DeploymentID: request.GetDeploymentId(),
		ScopeDigest: request.GetScopeDigest(), ExpectedRevision: request.GetExpectedRevision(),
		Signature: serviceoperation.SignatureV1{ChallengeID: approval.GetChallengeId(), OperationID: request.GetOperationId(),
			SignerKeyID: approval.GetSignerKeyId(), Signature: append([]byte(nil), approval.GetSignature()...)},
	})
	if err != nil {
		return nil, publicError(err)
	}
	operation, err := managedPreparationOperationToProto(value)
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.ApproveCloudManagedPreparationResponse{Operation: operation}, nil
}

func (service *CloudControlService) GetCloudManagedPreparation(ctx context.Context, request *agentv1.GetCloudManagedPreparationRequest) (*agentv1.GetCloudManagedPreparationResponse, error) {
	if service.preparation == nil {
		return nil, cloudUnavailable()
	}
	if request == nil {
		return nil, publicError(serviceoperation.ErrInvalid)
	}
	value, err := service.preparation.Get(ctx, request.GetOwnerId(), request.GetOperationId())
	if err != nil {
		return nil, publicError(err)
	}
	operation, err := managedPreparationOperationToProto(value)
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.GetCloudManagedPreparationResponse{Operation: operation}, nil
}

func managedPreparationChallengeToProto(value serviceoperation.ChallengeV1) (*agentv1.CloudManagedPreparationChallenge, error) {
	payload, err := value.SigningPayload()
	if err != nil {
		return nil, serviceoperation.ErrInvalid
	}
	scope := value.Scope
	result := &agentv1.CloudManagedPreparationScope{
		SchemaVersion: scope.SchemaVersion, Intent: scope.Intent, PreparationOperationId: scope.PreparationOperationID,
		OwnerId: scope.OwnerID, AgentInstanceId: scope.AgentInstanceID, DeploymentId: scope.DeploymentID,
		DeploymentRevision: scope.DeploymentRevision, ConnectionId: scope.ConnectionID, ConnectionRevision: scope.ConnectionRevision,
		PlanId: scope.PlanID, PlanRevision: scope.PlanRevision, PlanHash: scope.PlanHash, RecipeId: scope.RecipeID,
		RecipeDigest: scope.RecipeDigest, RecipeRevision: scope.RecipeRevision, Ec2: managedPreparationResourceToProto(scope.EC2),
		Restart: &agentv1.CloudManagedPreparationRestart{OperationId: scope.Restart.OperationID,
			ExpectedInitialRevision: scope.Restart.ExpectedInitialRevision, Action: scope.Restart.Action,
			LifecycleRestartRef: scope.Restart.LifecycleRestartRef, ExecutionBundleDigest: scope.Restart.ExecutionBundleDigest},
		ServiceMonitorRevision: scope.ServiceMonitorRevision, ServiceMonitorSuiteDigest: scope.ServiceMonitorSuiteDigest,
		Currency: scope.Currency, CostAlertAmountMinor: scope.CostAlertAmountMinor,
		ExpectedInstalledManifestDigest: scope.ExpectedInstalledManifestDigest,
	}
	for _, item := range scope.SourceVolumes {
		result.SourceVolumes = append(result.SourceVolumes, managedPreparationResourceToProto(item))
	}
	for _, item := range scope.Volumes {
		result.Volumes = append(result.Volumes, &agentv1.CloudManagedPreparationVolume{
			SlotId: item.SlotID, SourceVolume: managedPreparationResourceToProto(item.SourceVolume),
			SnapshotResourceId: item.SnapshotResourceID, ReplacementVolumeResourceId: item.ReplacementVolumeResourceID,
			AvailabilityZone: item.AvailabilityZone, SizeGib: item.SizeGiB, KmsKeyId: item.KMSKeyID, DeviceName: item.DeviceName,
			VolumeType: item.VolumeType, Iops: item.IOPS, ThroughputMibps: item.ThroughputMiBPS,
			MountPath: item.MountPath, ReadOnly: item.ReadOnly, Persistent: item.Persistent, Disposition: item.Disposition,
		})
	}
	return &agentv1.CloudManagedPreparationChallenge{
		SchemaVersion: value.SchemaVersion, ChallengeId: value.ChallengeID, OperationId: value.OperationID,
		SignerKeyId: value.SignerKeyID, Scope: result, ScopeDigest: value.ScopeDigest,
		IssuedAt: cloudStatusTimestamp(value.IssuedAt), ExpiresAt: cloudStatusTimestamp(value.ExpiresAt),
		SigningPayloadCbor: payload,
	}, nil
}

func managedPreparationResourceToProto(value serviceoperation.ResourceFactV1) *agentv1.CloudManagedPreparationResourceFact {
	return &agentv1.CloudManagedPreparationResourceFact{ResourceId: value.ResourceID, ProviderId: value.ProviderID,
		Revision: value.Revision, SpecDigest: value.SpecDigest, TagDigest: value.TagDigest}
}

func managedPreparationOperationToProto(value serviceoperation.OperationV1) (*agentv1.CloudManagedPreparationOperation, error) {
	challenge, err := managedPreparationChallengeToProto(value.Challenge)
	if err != nil || value.OperationID != value.Challenge.OperationID || value.Revision < 1 ||
		value.CreatedAt.IsZero() || value.UpdatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) ||
		(value.Status == serviceoperation.StatusSucceeded) != (value.Result != nil) {
		return nil, serviceoperation.ErrInvalid
	}
	statuses := map[serviceoperation.Status]agentv1.CloudManagedPreparationStatus{
		serviceoperation.StatusAwaitingApproval: agentv1.CloudManagedPreparationStatus_CLOUD_MANAGED_PREPARATION_STATUS_AWAITING_APPROVAL,
		serviceoperation.StatusApproved:         agentv1.CloudManagedPreparationStatus_CLOUD_MANAGED_PREPARATION_STATUS_APPROVED,
		serviceoperation.StatusRunning:          agentv1.CloudManagedPreparationStatus_CLOUD_MANAGED_PREPARATION_STATUS_RUNNING,
		serviceoperation.StatusSucceeded:        agentv1.CloudManagedPreparationStatus_CLOUD_MANAGED_PREPARATION_STATUS_SUCCEEDED,
		serviceoperation.StatusFailedTerminal:   agentv1.CloudManagedPreparationStatus_CLOUD_MANAGED_PREPARATION_STATUS_FAILED_TERMINAL,
	}
	status, found := statuses[value.Status]
	if !found || len(value.Steps) != len(serviceoperation.Phases()) {
		return nil, serviceoperation.ErrInvalid
	}
	result := &agentv1.CloudManagedPreparationOperation{OperationId: value.OperationID, Challenge: challenge, Status: status,
		CurrentPhase: string(value.CurrentPhase), Revision: value.Revision, CreatedAt: cloudStatusTimestamp(value.CreatedAt),
		UpdatedAt: cloudStatusTimestamp(value.UpdatedAt), ApprovedAt: optionalManagedPreparationTime(value.ApprovedAt)}
	phases := serviceoperation.Phases()
	stepStatuses := map[serviceoperation.StepStatus]agentv1.CloudManagedPreparationStepStatus{
		serviceoperation.StepPending:   agentv1.CloudManagedPreparationStepStatus_CLOUD_MANAGED_PREPARATION_STEP_STATUS_PENDING,
		serviceoperation.StepRunning:   agentv1.CloudManagedPreparationStepStatus_CLOUD_MANAGED_PREPARATION_STEP_STATUS_RUNNING,
		serviceoperation.StepSucceeded: agentv1.CloudManagedPreparationStepStatus_CLOUD_MANAGED_PREPARATION_STEP_STATUS_SUCCEEDED,
	}
	for index, item := range value.Steps {
		stepStatus, ok := stepStatuses[item.Status]
		if !ok || item.Phase != phases[index] || item.Ordinal != index+1 || item.Revision < 1 {
			return nil, serviceoperation.ErrInvalid
		}
		result.Steps = append(result.Steps, &agentv1.CloudManagedPreparationStep{Phase: string(item.Phase), Ordinal: int32(item.Ordinal),
			Status: stepStatus, Revision: item.Revision, IntentDigest: item.IntentDigest,
			StartedAt: optionalManagedPreparationTime(item.StartedAt), CompletedAt: optionalManagedPreparationTime(item.CompletedAt)})
	}
	if value.Result != nil {
		if value.Result.Validate() != nil {
			return nil, serviceoperation.ErrInvalid
		}
		item := value.Result
		result.Result = &agentv1.CloudManagedPreparationResult{
			PreparationId: item.PreparationID, PreparationDigest: item.PreparationDigest,
			FreshHealthDigest: item.FreshHealthDigest, FreshHealthRevision: item.FreshHealthRevision,
			FreshHealthObservedAt: cloudStatusTimestamp(item.FreshHealthObservedAt), CostDigest: item.CostDigest,
			CostPolicyRevision: item.CostPolicyRevision, CostObservedAt: cloudStatusTimestamp(item.CostObservedAt),
			StackDigest: item.StackDigest, StackRevision: item.StackRevision, StackObservedAt: cloudStatusTimestamp(item.StackObservedAt),
		}
	}
	return result, nil
}

func optionalManagedPreparationTime(value *time.Time) *timestamppb.Timestamp {
	if value == nil {
		return nil
	}
	return cloudStatusTimestamp(*value)
}
