package rpcapi

import (
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func cloudEntryDraftFromProto(value *agentv1.CloudEntryPlanDraft) entrypoint.DraftV1 {
	if value == nil {
		return entrypoint.DraftV1{}
	}
	return entrypoint.DraftV1{Hostname: value.GetHostname(), CertificateARN: value.GetCertificateArn(), PublicSubnetIDs: append([]string(nil), value.GetPublicSubnetIds()...),
		TargetPort: value.GetTargetPort(), HealthPath: value.GetHealthPath(), ExpectedHealthStatusCode: value.GetExpectedHealthStatusCode(),
		RecipeHealthContractDigest: value.GetRecipeHealthContractDigest(), RecipeAuthenticationDigest: value.GetRecipeAuthenticationDigest(), Cost: cloudEntryCostFromProto(value.GetCost())}
}

func cloudEntryCostFromProto(value *agentv1.CloudEntryCostScope) entrypoint.EntryCostScopeV1 {
	if value == nil {
		return entrypoint.EntryCostScopeV1{}
	}
	return entrypoint.EntryCostScopeV1{QuoteID: value.GetQuoteId(), QuoteDigest: value.GetQuoteDigest(), Currency: value.GetCurrency(),
		QuotedAt: entryTimestampFromProto(value.GetQuotedAt()), ValidUntil: entryTimestampFromProto(value.GetValidUntil()),
		ALBHourlyEstimateMicros: value.GetAlbHourlyEstimateMicros(), LCUHourlyEstimateMicros: value.GetLcuHourlyEstimateMicros(),
		EstimatedLCUMilliUnits: value.GetEstimatedLcuMilliUnits(), EstimatedEgressMiB: value.GetEstimatedEgressMib(),
		TrafficEstimateMicros: value.GetTrafficEstimateMicros(), MaximumLaunchAmountMicros: value.GetMaximumLaunchAmountMicros(), AssumptionsDigest: value.GetAssumptionsDigest()}
}

func cloudEntryPlanToProto(value entrypoint.PlanV1) (*agentv1.CloudEntryPlan, bool) {
	if err := value.Validate(); err != nil {
		return nil, false
	}
	hash, err := value.Hash()
	if err != nil {
		return nil, false
	}
	return &agentv1.CloudEntryPlan{SchemaVersion: value.SchemaVersion, EntryPlanId: value.EntryPlanID, Status: cloudEntryPlanStatusToProto(value.Status),
		Scope: cloudEntryScopeToProto(value.Scope), ScopeDigest: value.ScopeDigest, Revision: int64(value.Revision), PlanHash: hash}, true
}

func cloudEntryChallengeToProto(value entrypoint.ChallengeV1, plan entrypoint.PlanV1) (*agentv1.CloudEntryApprovalChallenge, bool) {
	if err := value.ValidateAgainstPlan(plan); err != nil {
		return nil, false
	}
	return &agentv1.CloudEntryApprovalChallenge{OperationId: value.OperationID, ChallengeId: value.ChallengeID, ApprovalId: value.ApprovalID,
		EntryPlanId: value.EntryPlanID, EntryPlanRevision: int64(value.EntryPlanRevision), PlanHash: value.PlanHash, ScopeDigest: value.ScopeDigest,
		SignerKeyId: value.SignerKeyID, IssuedAt: entryTimestampToProto(value.IssuedAt), ExpiresAt: entryTimestampToProto(value.ExpiresAt),
		SigningPayloadCbor: append([]byte(nil), value.SigningCBOR...), Revision: value.Revision, Scope: cloudEntryScopeToProto(plan.Scope)}, true
}

func cloudEntryOperationToProto(value entrypoint.OperationV1, plan entrypoint.PlanV1) (*agentv1.CloudEntryOperation, bool) {
	if err := value.Validate(); err != nil || plan.Validate() != nil || value.Challenge.EntryPlanID != plan.EntryPlanID || value.Challenge.ScopeDigest != plan.ScopeDigest {
		return nil, false
	}
	hash, err := plan.Hash()
	if err != nil || value.Challenge.PlanHash != hash {
		return nil, false
	}
	return &agentv1.CloudEntryOperation{OperationId: value.Challenge.OperationID, OwnerId: plan.Scope.OwnerID, DeploymentId: plan.Scope.Worker.DeploymentID,
		EntryPlanId: value.Challenge.EntryPlanID, ApprovalId: value.Challenge.ApprovalID, PlanHash: value.Challenge.PlanHash, ScopeDigest: value.Challenge.ScopeDigest,
		Status: cloudEntryOperationStatusToProto(value.Status), ErrorCode: cloudEntryErrorCodeToProto(value.ErrorCode), ErrorSummary: security.RedactText(value.ErrorSummary),
		Revision: value.Revision, CreatedAt: entryTimestampToProto(value.CreatedAt), UpdatedAt: entryTimestampToProto(value.UpdatedAt)}, true
}

func cloudEntryScopeToProto(value entrypoint.ScopeV1) *agentv1.CloudEntryApprovalScope {
	publicSubnets := make([]*agentv1.CloudEntryPublicSubnetScope, 0, len(value.ALB.PublicSubnets))
	for _, subnet := range value.ALB.PublicSubnets {
		publicSubnets = append(publicSubnets, &agentv1.CloudEntryPublicSubnetScope{SubnetId: subnet.SubnetID, VpcId: subnet.VPCID, AvailabilityZone: subnet.AvailabilityZone,
			Public: subnet.Public, ReadBackDigest: subnet.ReadBackDigest, ObservedAt: entryTimestampToProto(subnet.ObservedAt)})
	}
	return &agentv1.CloudEntryApprovalScope{SchemaVersion: value.SchemaVersion, Kind: cloudEntryKindToProto(value.Kind), AgentInstanceId: value.AgentInstanceID,
		OwnerId: value.OwnerID, ConnectionId: value.ConnectionID, Region: value.Region,
		Worker: &agentv1.CloudEntryWorkerReadBackScope{DeploymentId: value.Worker.DeploymentID, DeploymentRevision: value.Worker.DeploymentRevision,
			TaskId: value.Worker.TaskID, OriginalPlanId: value.Worker.OriginalPlanID, OriginalPlanHash: value.Worker.OriginalPlanHash,
			OriginalApprovalId: value.Worker.OriginalApprovalID, WorkerResourceId: value.Worker.WorkerResourceID, WorkerResourceRevision: value.Worker.WorkerResourceRevision,
			WorkerSpecDigest: value.Worker.WorkerSpecDigest, InstanceId: value.Worker.InstanceID, VpcId: value.Worker.VPCID, SubnetId: value.Worker.SubnetID,
			SecurityGroupId: value.Worker.SecurityGroupID, ExecutionOutcome: cloudEntryOutcomeToProto(value.Worker.ExecutionOutcome), SucceededAt: entryTimestampToProto(value.Worker.SucceededAt),
			ReadBack: &agentv1.CloudEntryAWSReadBack{Observed: value.Worker.ReadBack.Observed, Exists: value.Worker.ReadBack.Exists, State: cloudEntryEC2StateToProto(value.Worker.ReadBack.State),
				ObservedAt: entryTimestampToProto(value.Worker.ReadBack.ObservedAt), TagDigest: value.Worker.ReadBack.TagDigest},
			RetentionPolicy: cloudEntryRetentionToProto(value.Worker.Retention.Class), AutoDestroyApproved: value.Worker.Retention.AutoDestroy, DestroyDeadline: entryTimestampToProto(value.Worker.Retention.DestroyDeadline)},
		Recipe: &agentv1.CloudEntryRecipeHealthBinding{RecipeDigest: value.Recipe.RecipeDigest, HealthContractDigest: value.Recipe.HealthContractDigest, AuthenticationContractDigest: value.Recipe.AuthenticationContractDigest},
		Certificate: &agentv1.CloudEntryCertificateScope{CertificateArn: value.Certificate.CertificateARN, Region: value.Certificate.Region, Hostname: value.Certificate.Hostname,
			SubjectAlternativeNames: append([]string(nil), value.Certificate.SubjectAlternativeNames...), Status: cloudEntryCertificateStatusToProto(value.Certificate.Status), ReadBackDigest: value.Certificate.ReadBackDigest, ObservedAt: entryTimestampToProto(value.Certificate.ObservedAt)},
		Alb: &agentv1.CloudEntryALBScope{Scheme: cloudEntryALBSchemeToProto(value.ALB.Scheme), ListenerPort: value.ALB.ListenerPort, ListenerProtocol: cloudEntryListenerProtocolToProto(value.ALB.ListenerProtocol),
			TlsPolicy: value.ALB.TLSPolicy, IngressCidrs: append([]string(nil), value.ALB.IngressCIDRs...), TargetProtocol: cloudEntryTargetProtocolToProto(value.ALB.TargetProtocol), TargetPort: value.ALB.TargetPort,
			TargetSource: cloudEntryTargetSourceToProto(value.ALB.TargetSource), PublicSubnets: publicSubnets, WorkerPrivateOnly: !value.ALB.WorkerPublicIPv4, ElasticIpProhibited: !value.ALB.EIPRequested},
		Health:         &agentv1.CloudEntryHealthRouteScope{Path: value.Health.Path, ExpectedStatusCode: value.Health.ExpectedStatusCode, EvidenceDigest: value.Health.EvidenceDigest, NoCredentialRoute: value.Health.NoCredentialRoute},
		Authentication: &agentv1.CloudEntryAuthenticationScope{Required: value.Authentication.Required, ContractDigest: value.Authentication.ContractDigest},
		Cost:           cloudEntryCostToProto(value.Cost), Retention: &agentv1.CloudEntryRetentionScope{RetentionPolicy: cloudEntryRetentionToProto(value.Retention.Class), AutoDestroyApproved: value.Retention.AutoDestroy, DestroyDeadline: entryTimestampToProto(value.Retention.DestroyDeadline)}}
}

func cloudEntryCostToProto(value entrypoint.EntryCostScopeV1) *agentv1.CloudEntryCostScope {
	return &agentv1.CloudEntryCostScope{QuoteId: value.QuoteID, QuoteDigest: value.QuoteDigest, Currency: value.Currency, QuotedAt: entryTimestampToProto(value.QuotedAt), ValidUntil: entryTimestampToProto(value.ValidUntil),
		AlbHourlyEstimateMicros: value.ALBHourlyEstimateMicros, LcuHourlyEstimateMicros: value.LCUHourlyEstimateMicros, EstimatedLcuMilliUnits: value.EstimatedLCUMilliUnits,
		EstimatedEgressMib: value.EstimatedEgressMiB, TrafficEstimateMicros: value.TrafficEstimateMicros, MaximumLaunchAmountMicros: value.MaximumLaunchAmountMicros, AssumptionsDigest: value.AssumptionsDigest}
}

func cloudEntryPlanStatusToProto(value entrypoint.PlanStatus) agentv1.CloudEntryPlanStatus {
	switch value {
	case entrypoint.PlanDraft:
		return agentv1.CloudEntryPlanStatus_CLOUD_ENTRY_PLAN_STATUS_DRAFT
	case entrypoint.PlanReadyForApproval:
		return agentv1.CloudEntryPlanStatus_CLOUD_ENTRY_PLAN_STATUS_READY_FOR_APPROVAL
	case entrypoint.PlanApproved:
		return agentv1.CloudEntryPlanStatus_CLOUD_ENTRY_PLAN_STATUS_APPROVED
	case entrypoint.PlanExpired:
		return agentv1.CloudEntryPlanStatus_CLOUD_ENTRY_PLAN_STATUS_EXPIRED
	case entrypoint.PlanSuperseded:
		return agentv1.CloudEntryPlanStatus_CLOUD_ENTRY_PLAN_STATUS_SUPERSEDED
	default:
		return agentv1.CloudEntryPlanStatus_CLOUD_ENTRY_PLAN_STATUS_UNSPECIFIED
	}
}

func cloudEntryOperationStatusToProto(value entrypoint.Status) agentv1.CloudEntryOperationStatus {
	switch value {
	case entrypoint.StatusAwaitingApproval:
		return agentv1.CloudEntryOperationStatus_CLOUD_ENTRY_OPERATION_STATUS_AWAITING_APPROVAL
	case entrypoint.StatusApproved:
		return agentv1.CloudEntryOperationStatus_CLOUD_ENTRY_OPERATION_STATUS_APPROVED
	case entrypoint.StatusProvisioning:
		return agentv1.CloudEntryOperationStatus_CLOUD_ENTRY_OPERATION_STATUS_PROVISIONING
	case entrypoint.StatusVerifying:
		return agentv1.CloudEntryOperationStatus_CLOUD_ENTRY_OPERATION_STATUS_VERIFYING
	case entrypoint.StatusActive:
		return agentv1.CloudEntryOperationStatus_CLOUD_ENTRY_OPERATION_STATUS_ACTIVE
	case entrypoint.StatusFailed:
		return agentv1.CloudEntryOperationStatus_CLOUD_ENTRY_OPERATION_STATUS_FAILED
	case entrypoint.StatusDestroying:
		return agentv1.CloudEntryOperationStatus_CLOUD_ENTRY_OPERATION_STATUS_DESTROYING
	case entrypoint.StatusDestroyed:
		return agentv1.CloudEntryOperationStatus_CLOUD_ENTRY_OPERATION_STATUS_DESTROYED
	case entrypoint.StatusDestroyBlocked:
		return agentv1.CloudEntryOperationStatus_CLOUD_ENTRY_OPERATION_STATUS_DESTROY_BLOCKED
	default:
		return agentv1.CloudEntryOperationStatus_CLOUD_ENTRY_OPERATION_STATUS_UNSPECIFIED
	}
}

func cloudEntryErrorCodeToProto(value entrypoint.ErrorCode) agentv1.CloudEntryErrorCode {
	switch value {
	case entrypoint.ErrorCodeWorkerNotReady:
		return agentv1.CloudEntryErrorCode_CLOUD_ENTRY_ERROR_CODE_WORKER_NOT_READY
	case entrypoint.ErrorCodeReadBackMismatch:
		return agentv1.CloudEntryErrorCode_CLOUD_ENTRY_ERROR_CODE_READ_BACK_MISMATCH
	case entrypoint.ErrorCodeCertificateInvalid:
		return agentv1.CloudEntryErrorCode_CLOUD_ENTRY_ERROR_CODE_CERTIFICATE_NOT_READY
	case entrypoint.ErrorCodeQuoteExpired:
		return agentv1.CloudEntryErrorCode_CLOUD_ENTRY_ERROR_CODE_QUOTE_EXPIRED
	case entrypoint.ErrorCodeProvisioningFailed:
		return agentv1.CloudEntryErrorCode_CLOUD_ENTRY_ERROR_CODE_PROVISION_FAILED
	case entrypoint.ErrorCodeVerificationFailed:
		return agentv1.CloudEntryErrorCode_CLOUD_ENTRY_ERROR_CODE_VERIFICATION_FAILED
	case entrypoint.ErrorCodeDestroyBlocked:
		return agentv1.CloudEntryErrorCode_CLOUD_ENTRY_ERROR_CODE_DESTROY_BLOCKED
	default:
		return agentv1.CloudEntryErrorCode_CLOUD_ENTRY_ERROR_CODE_UNSPECIFIED
	}
}

func cloudEntryKindToProto(value entrypoint.EntryKind) agentv1.CloudEntryKind {
	if value == entrypoint.EntryKindALB {
		return agentv1.CloudEntryKind_CLOUD_ENTRY_KIND_ALB
	}
	return agentv1.CloudEntryKind_CLOUD_ENTRY_KIND_UNSPECIFIED
}

func cloudEntryALBSchemeToProto(value entrypoint.ALBScheme) agentv1.CloudEntryALBScheme {
	if value == entrypoint.ALBSchemeInternetFacing {
		return agentv1.CloudEntryALBScheme_CLOUD_ENTRY_ALB_SCHEME_INTERNET_FACING
	}
	return agentv1.CloudEntryALBScheme_CLOUD_ENTRY_ALB_SCHEME_UNSPECIFIED
}

func cloudEntryListenerProtocolToProto(value entrypoint.ListenerProtocol) agentv1.CloudEntryListenerProtocol {
	if value == entrypoint.ListenerProtocolHTTPS {
		return agentv1.CloudEntryListenerProtocol_CLOUD_ENTRY_LISTENER_PROTOCOL_HTTPS
	}
	return agentv1.CloudEntryListenerProtocol_CLOUD_ENTRY_LISTENER_PROTOCOL_UNSPECIFIED
}

func cloudEntryTargetProtocolToProto(value entrypoint.TargetProtocol) agentv1.CloudEntryTargetProtocol {
	switch value {
	case entrypoint.TargetProtocolHTTP:
		return agentv1.CloudEntryTargetProtocol_CLOUD_ENTRY_TARGET_PROTOCOL_HTTP
	case entrypoint.TargetProtocolHTTPS:
		return agentv1.CloudEntryTargetProtocol_CLOUD_ENTRY_TARGET_PROTOCOL_HTTPS
	default:
		return agentv1.CloudEntryTargetProtocol_CLOUD_ENTRY_TARGET_PROTOCOL_UNSPECIFIED
	}
}

func cloudEntryTargetSourceToProto(value entrypoint.TargetSource) agentv1.CloudEntryTargetSource {
	if value == entrypoint.TargetSourceApprovedWorkerReadBack {
		return agentv1.CloudEntryTargetSource_CLOUD_ENTRY_TARGET_SOURCE_APPROVED_WORKER_READ_BACK
	}
	return agentv1.CloudEntryTargetSource_CLOUD_ENTRY_TARGET_SOURCE_UNSPECIFIED
}

func cloudEntryCertificateStatusToProto(value entrypoint.CertificateStatus) agentv1.CloudEntryCertificateStatus {
	switch value {
	case entrypoint.CertificateStatusIssued:
		return agentv1.CloudEntryCertificateStatus_CLOUD_ENTRY_CERTIFICATE_STATUS_ISSUED
	case entrypoint.CertificateStatusPendingValidation:
		return agentv1.CloudEntryCertificateStatus_CLOUD_ENTRY_CERTIFICATE_STATUS_PENDING_VALIDATION
	default:
		return agentv1.CloudEntryCertificateStatus_CLOUD_ENTRY_CERTIFICATE_STATUS_UNSPECIFIED
	}
}

func cloudEntryEC2StateToProto(value entrypoint.EC2InstanceState) agentv1.CloudEntryEC2State {
	if value == entrypoint.EC2InstanceRunning {
		return agentv1.CloudEntryEC2State_CLOUD_ENTRY_EC2_STATE_RUNNING
	}
	return agentv1.CloudEntryEC2State_CLOUD_ENTRY_EC2_STATE_UNSPECIFIED
}

func cloudEntryOutcomeToProto(value entrypoint.WorkerOutcome) agentv1.OutcomeStatus {
	switch value {
	case entrypoint.WorkerOutcomeSucceeded:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_SUCCEEDED
	case entrypoint.WorkerOutcomeFailed:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_FAILED
	case entrypoint.WorkerOutcomeCanceled:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_CANCELED
	case entrypoint.WorkerOutcomeTimedOut:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_TIMED_OUT
	default:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_UNSPECIFIED
	}
}

func cloudEntryRetentionToProto(value entrypoint.RetentionClass) agentv1.RetentionPolicy {
	switch value {
	case entrypoint.RetentionEphemeral:
		return agentv1.RetentionPolicy_RETENTION_POLICY_EPHEMERAL_AUTO_DESTROY
	case entrypoint.RetentionManaged:
		return agentv1.RetentionPolicy_RETENTION_POLICY_MANAGED_RETAINED
	default:
		return agentv1.RetentionPolicy_RETENTION_POLICY_UNSPECIFIED
	}
}

func entryTimestampFromProto(value *timestamppb.Timestamp) time.Time {
	if value == nil || !value.IsValid() {
		return time.Time{}
	}
	return value.AsTime().UTC()
}

func entryTimestampToProto(value time.Time) *timestamppb.Timestamp {
	if value.IsZero() {
		return nil
	}
	return timestamppb.New(value.UTC())
}
