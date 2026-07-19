package rpcapi

import (
	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func cloudQuoteScopeFromProto(value *agentv1.CloudQuoteScope, agentInstanceID string) cloudquote.ScopeV1 {
	if value == nil {
		return cloudquote.ScopeV1{}
	}
	schemaVersion := value.GetSchemaVersion()
	if schemaVersion == "" {
		schemaVersion = cloudquote.ScopeSchemaV1
	}
	result := cloudquote.ScopeV1{
		SchemaVersion: schemaVersion, AgentInstanceID: agentInstanceID,
		OwnerID: value.GetOwnerId(), ConnectionID: value.GetConnectionId(),
		Recipe: cloudquote.RecipeBindingV1{
			RecipeID: value.GetRecipe().GetRecipeId(), Digest: value.GetRecipe().GetDigest(),
			Maturity: recipe.Maturity(value.GetRecipe().GetMaturity()),
		},
		ServiceOperations: cloudServiceOperationsFromProto(value.GetServiceOperations()),
		Resource:          cloudResourceScopeFromProto(value.GetResource()),
		Network:           cloudNetworkScopeFromProto(value.GetNetwork()),
		Retention: cloudquote.RetentionScopeV1{
			Class:              cloudRetentionFromProto(value.GetRetention().GetRetentionClass()),
			AutoDestroy:        value.GetRetention().GetAutoDestroy(),
			GracePeriodSeconds: value.GetRetention().GetGracePeriodSeconds(),
			MaxLifetimeSeconds: value.GetRetention().GetMaxLifetimeSeconds(),
		},
	}
	for _, secret := range value.GetSecretScope() {
		result.SecretScope = append(result.SecretScope, cloudquote.SecretScopeV1{
			SecretRef: secret.GetSecretRef(), Purpose: secret.GetPurpose(), Delivery: recipe.SecretDelivery(secret.GetDelivery()),
		})
	}
	for _, integration := range value.GetIntegrationScope() {
		result.IntegrationScope = append(result.IntegrationScope, cloudquote.IntegrationScopeV1{
			Kind: cloudquote.IntegrationKind(integration.GetKind()), Name: integration.GetName(), Scopes: integration.GetScopes(),
		})
	}
	return result
}

func cloudResourceScopeFromProto(value *agentv1.CloudResourceScope) cloudquote.ResourceScopeV1 {
	if value == nil {
		return cloudquote.ResourceScopeV1{}
	}
	result := cloudquote.ResourceScopeV1{
		CandidateID: cloudCandidateFromProto(value.GetCandidateProfile()), Region: value.GetRegion(),
		AvailabilityZones: value.GetAvailabilityZones(), InstanceType: value.GetInstanceType(), InstanceCount: value.GetInstanceCount(),
		Architecture: recipe.Architecture(value.GetArchitecture()), VCPU: value.GetVcpu(), MemoryMiB: value.GetMemoryMib(),
		GPUType: value.GetGpuType(), GPUCount: value.GetGpuCount(), GPUMemoryMiB: value.GetGpuMemoryMib(),
		DiskGiB: value.GetDiskGib(), VolumeType: value.GetVolumeType(), VolumeIOPS: value.GetVolumeIops(),
		VolumeThroughputMiBPS: value.GetVolumeThroughputMibps(), VolumeEncrypted: value.GetVolumeEncrypted(),
		PurchaseOption: cloudPurchaseFromProto(value.GetPurchaseOption()), WorkerImageID: value.GetWorkerImageId(),
		WorkerImageDigest: value.GetWorkerImageDigest(),
	}
	for _, volume := range value.GetVolumeScopes() {
		result.VolumeScopes = append(result.VolumeScopes, cloudquote.VolumeScopeV1{
			SlotID: volume.GetSlotId(), SizeGiB: volume.GetSizeGib(), VolumeType: volume.GetVolumeType(), IOPS: volume.GetIops(),
			ThroughputMiBPS: volume.GetThroughputMibps(), Encrypted: volume.GetEncrypted(), KMSKeyID: volume.GetKmsKeyId(),
			DeviceName: volume.GetDeviceName(), MountPath: volume.GetMountPath(), ReadOnly: volume.GetReadOnly(),
			Persistent: volume.GetPersistent(), Disposition: cloudquote.VolumeDisposition(volume.GetDisposition()),
		})
	}
	return result
}

func cloudNetworkScopeFromProto(value *agentv1.CloudNetworkScope) cloudquote.NetworkScopeV1 {
	if value == nil {
		return cloudquote.NetworkScopeV1{}
	}
	return cloudquote.NetworkScopeV1{
		VPCID: value.GetVpcId(), SubnetID: value.GetSubnetId(), SecurityGroupMode: cloudSecurityGroupModeFromProto(value.GetSecurityGroupMode()), SecurityGroupID: value.GetSecurityGroupId(), PublicIPv4: value.GetPublicIpv4(),
		EntryPoint: cloudEntryPointFromProto(value.GetEntryPoint()), PublicExposure: value.GetPublicExposure(),
		IngressPorts: value.GetIngressPorts(), Hostname: value.GetHostname(), TLSRequired: value.GetTlsRequired(),
		AuthenticationRequired: value.GetAuthenticationRequired(),
		RouteTableID:           value.GetRouteTableId(), ControlPlaneEndpoint: value.GetControlPlaneEndpoint(),
		PrivateConnectivity: cloudquote.PrivateConnectivityMode(value.GetPrivateConnectivity()),
	}
}

func cloudUsageFromProto(value *agentv1.CloudUsageEstimate) cloudquote.UsageV1 {
	if value == nil {
		return cloudquote.UsageV1{}
	}
	return cloudquote.UsageV1{
		RuntimeHoursPerMonth: value.GetRuntimeHoursPerMonth(), PublicIPv4Hours: value.GetPublicIpv4Hours(),
		LogIngestMiB: value.GetLogIngestMib(), LogStoredMiBMonths: value.GetLogStoredMibMonths(),
		SnapshotGiBMonths: value.GetSnapshotGibMonths(), EntryHours: value.GetEntryHours(), InternetEgressMiB: value.GetInternetEgressMib(),
		PrivateEndpointHours: value.GetPrivateEndpointHours(), PrivateEndpointDataMiB: value.GetPrivateEndpointDataMib(),
	}
}

func cloudQuoteToProto(value cloudquote.QuoteV1) *agentv1.CloudQuote {
	result := &agentv1.CloudQuote{
		QuoteId: value.QuoteID, QuotedAt: timestamppb.New(value.QuotedAt), ValidUntil: timestamppb.New(value.ValidUntil),
		Currency: value.Currency, Usage: cloudUsageToProto(value.Usage), Assumptions: value.Assumptions, Exclusions: value.Exclusions,
	}
	result.Digest, _ = value.Digest()
	for _, candidate := range value.Candidates {
		converted := &agentv1.CloudQuoteCandidate{
			CandidateProfile: cloudCandidateToProto(candidate.CandidateID), Scope: cloudQuoteScopeToProto(candidate.Scope),
			ScopeDigest: candidate.ScopeDigest, OfferedAvailabilityZones: candidate.OfferedAvailabilityZones,
			HourlyEstimateMicros: candidate.HourlyEstimateMicros, MonthlyEstimateMicros: candidate.MonthlyEstimateMicros,
			MaximumLaunchAmountMicros: candidate.MaximumLaunchAmountMicros,
		}
		for _, quota := range candidate.Quotas {
			converted.Quotas = append(converted.Quotas, &agentv1.CloudQuotaEvidence{
				ServiceCode: quota.ServiceCode, QuotaCode: quota.QuotaCode, LimitUnits: quota.LimitUnits,
				UsedUnits: quota.UsedUnits, RequiredUnits: quota.RequiredUnits,
			})
		}
		for _, item := range candidate.CostItems {
			converted.CostItems = append(converted.CostItems, &agentv1.CloudCostItem{
				Category: string(item.Category), Description: item.Description, SourceId: item.SourceID,
				HourlyEstimateMicros: item.HourlyEstimateMicros, MonthlyEstimateMicros: item.MonthlyEstimateMicros,
				MaximumLaunchAmountMicros: item.MaximumLaunchAmountMicros,
			})
		}
		result.Candidates = append(result.Candidates, converted)
	}
	if value.SpotEvidence != nil {
		result.SpotEvidence = cloudSpotToProto(*value.SpotEvidence)
	}
	return result
}

func cloudQuoteScopeToProto(value cloudquote.ScopeV1) *agentv1.CloudQuoteScope {
	result := &agentv1.CloudQuoteScope{
		OwnerId: value.OwnerID, ConnectionId: value.ConnectionID, SchemaVersion: value.SchemaVersion,
		Recipe:   &agentv1.CloudRecipeBinding{RecipeId: value.Recipe.RecipeID, Digest: value.Recipe.Digest, Maturity: string(value.Recipe.Maturity)},
		Resource: cloudResourceScopeToProto(value.Resource), Network: cloudNetworkScopeToProto(value.Network),
		Retention: &agentv1.CloudRetentionScope{
			RetentionClass: cloudRetentionToProto(value.Retention.Class), AutoDestroy: value.Retention.AutoDestroy,
			GracePeriodSeconds: value.Retention.GracePeriodSeconds, MaxLifetimeSeconds: value.Retention.MaxLifetimeSeconds,
		},
		ServiceOperations: cloudServiceOperationsToProto(value.ServiceOperations),
	}
	for _, secret := range value.SecretScope {
		result.SecretScope = append(result.SecretScope, &agentv1.CloudSecretScope{SecretRef: secret.SecretRef, Purpose: secret.Purpose, Delivery: string(secret.Delivery)})
	}
	for _, integration := range value.IntegrationScope {
		result.IntegrationScope = append(result.IntegrationScope, &agentv1.CloudIntegrationScope{Kind: string(integration.Kind), Name: integration.Name, Scopes: integration.Scopes})
	}
	return result
}

func cloudResourceScopeToProto(value cloudquote.ResourceScopeV1) *agentv1.CloudResourceScope {
	result := &agentv1.CloudResourceScope{
		CandidateProfile: cloudCandidateToProto(value.CandidateID), Region: value.Region, AvailabilityZones: value.AvailabilityZones,
		InstanceType: value.InstanceType, InstanceCount: value.InstanceCount, Architecture: string(value.Architecture),
		Vcpu: value.VCPU, MemoryMib: value.MemoryMiB, GpuType: value.GPUType, GpuCount: value.GPUCount,
		GpuMemoryMib: value.GPUMemoryMiB, DiskGib: value.DiskGiB, VolumeType: value.VolumeType,
		VolumeIops: value.VolumeIOPS, VolumeThroughputMibps: value.VolumeThroughputMiBPS, VolumeEncrypted: value.VolumeEncrypted,
		PurchaseOption: cloudPurchaseToProto(value.PurchaseOption), WorkerImageId: value.WorkerImageID, WorkerImageDigest: value.WorkerImageDigest,
	}
	for _, volume := range value.VolumeScopes {
		result.VolumeScopes = append(result.VolumeScopes, &agentv1.CloudVolumeScope{
			SlotId: volume.SlotID, SizeGib: volume.SizeGiB, VolumeType: volume.VolumeType, Iops: volume.IOPS,
			ThroughputMibps: volume.ThroughputMiBPS, Encrypted: volume.Encrypted, KmsKeyId: volume.KMSKeyID,
			DeviceName: volume.DeviceName, MountPath: volume.MountPath, ReadOnly: volume.ReadOnly,
			Persistent: volume.Persistent, Disposition: string(volume.Disposition),
		})
	}
	return result
}

func cloudNetworkScopeToProto(value cloudquote.NetworkScopeV1) *agentv1.CloudNetworkScope {
	return &agentv1.CloudNetworkScope{
		VpcId: value.VPCID, SubnetId: value.SubnetID, SecurityGroupMode: cloudSecurityGroupModeToProto(value.SecurityGroupMode), SecurityGroupId: value.SecurityGroupID, PublicIpv4: value.PublicIPv4,
		EntryPoint: cloudEntryPointToProto(value.EntryPoint), PublicExposure: value.PublicExposure, IngressPorts: value.IngressPorts,
		Hostname: value.Hostname, TlsRequired: value.TLSRequired, AuthenticationRequired: value.AuthenticationRequired,
		RouteTableId: value.RouteTableID, ControlPlaneEndpoint: value.ControlPlaneEndpoint, PrivateConnectivity: string(value.PrivateConnectivity),
	}
}

func cloudUsageToProto(value cloudquote.UsageV1) *agentv1.CloudUsageEstimate {
	return &agentv1.CloudUsageEstimate{
		RuntimeHoursPerMonth: value.RuntimeHoursPerMonth, PublicIpv4Hours: value.PublicIPv4Hours,
		LogIngestMib: value.LogIngestMiB, LogStoredMibMonths: value.LogStoredMiBMonths,
		SnapshotGibMonths: value.SnapshotGiBMonths, EntryHours: value.EntryHours, InternetEgressMib: value.InternetEgressMiB,
		PrivateEndpointHours: value.PrivateEndpointHours, PrivateEndpointDataMib: value.PrivateEndpointDataMiB,
	}
}

func cloudSpotToProto(value cloudquote.SpotQualificationV1) *agentv1.CloudSpotQualification {
	return &agentv1.CloudSpotQualification{
		EvidenceId: value.EvidenceID, RecipeDigest: value.RecipeDigest, CheckpointName: value.CheckpointName,
		ResumeAction: value.ResumeAction, MaxRetries: value.MaxRetries,
		CheckpointVerifiedAt: timestamppb.New(value.CheckpointVerifiedAt), InterruptionTestedAt: timestamppb.New(value.InterruptionTestedAt),
	}
}

func cloudSpotFromProto(value *agentv1.CloudSpotQualification) *cloudquote.SpotQualificationV1 {
	if value == nil {
		return nil
	}
	result := &cloudquote.SpotQualificationV1{
		EvidenceID: value.GetEvidenceId(), RecipeDigest: value.GetRecipeDigest(), CheckpointName: value.GetCheckpointName(),
		ResumeAction: value.GetResumeAction(), MaxRetries: value.GetMaxRetries(),
	}
	if value.GetCheckpointVerifiedAt() != nil && value.GetCheckpointVerifiedAt().IsValid() {
		result.CheckpointVerifiedAt = value.GetCheckpointVerifiedAt().AsTime().UTC()
	}
	if value.GetInterruptionTestedAt() != nil && value.GetInterruptionTestedAt().IsValid() {
		result.InterruptionTestedAt = value.GetInterruptionTestedAt().AsTime().UTC()
	}
	return result
}

func cloudPlanToProto(value cloudapproval.PlanV1) *agentv1.CloudPlan {
	hash, _ := value.Hash()
	return &agentv1.CloudPlan{
		PlanId: value.PlanID, OwnerId: value.OwnerID, ConnectionId: value.ConnectionID,
		Recipe:  &agentv1.CloudRecipeBinding{RecipeId: value.Recipe.RecipeID, Digest: value.Recipe.Digest, Maturity: string(value.Recipe.Maturity)},
		QuoteId: value.Quote.QuoteID, QuoteDigest: value.Quote.Digest, QuoteScopeDigest: value.Quote.ScopeDigest,
		CandidateProfile: cloudCandidateStringToProto(value.Quote.CandidateID), QuoteValidUntil: timestamppb.New(value.Quote.ValidUntil),
		Resource: approvalResourceScopeToProto(value.ResourceScope), Network: approvalNetworkScopeToProto(value.NetworkScope),
		SecretScope: approvalSecretsToProto(value.SecretScope), IntegrationScope: approvalIntegrationsToProto(value.IntegrationScope),
		Retention: approvalRetentionToProto(value.RetentionScope), Status: cloudPlanStatusToProto(value.Status),
		PlanHash: hash, Revision: int64(value.Revision), SchemaVersion: value.SchemaVersion,
		ServiceOperations: cloudServiceOperationsToProto(value.ServiceOperations),
	}
}

func cloudServiceOperationsFromProto(value *agentv1.CloudServiceOperationScope) *cloudquote.ServiceOperationScopeV1 {
	if value == nil {
		return nil
	}
	result := &cloudquote.ServiceOperationScopeV1{}
	for _, endpoint := range value.GetPrivateEndpoints() {
		result.PrivateEndpoints = append(result.PrivateEndpoints, cloudquote.PrivateEndpointOperationSpecV1{
			OperationKey: endpoint.GetOperationKey(), Service: cloudPrivateEndpointServiceFromProto(endpoint.GetService()),
			ServiceName:         endpoint.GetServiceName(),
			SecurityGroupSource: cloudEndpointSecurityGroupSourceFromProto(endpoint.GetSecurityGroupSource()),
			PrivateDNSEnabled:   endpoint.GetPrivateDnsEnabled(), MonthlyHours: endpoint.GetMonthlyHours(), DataMiBPerMonth: endpoint.GetDataMibPerMonth(),
			EndpointType: cloudPrivateEndpointTypeFromProto(endpoint.GetEndpointType()),
		})
	}
	for _, snapshot := range value.GetSnapshots() {
		result.Snapshots = append(result.Snapshots, cloudquote.SnapshotOperationSpecV1{
			OperationKey: snapshot.GetOperationKey(), SourceVolumeSlotID: snapshot.GetSourceVolumeSlotId(),
			SourceVolumeSpecDigest: snapshot.GetSourceVolumeSpecDigest(), Disposition: cloudSnapshotDispositionFromProto(snapshot.GetDisposition()),
			MaxRetentionSeconds: snapshot.GetMaxRetentionSeconds(),
		})
	}
	return result
}

func cloudServiceOperationsToProto(value *cloudquote.ServiceOperationScopeV1) *agentv1.CloudServiceOperationScope {
	if value == nil {
		return nil
	}
	result := &agentv1.CloudServiceOperationScope{}
	for _, endpoint := range value.PrivateEndpoints {
		result.PrivateEndpoints = append(result.PrivateEndpoints, &agentv1.CloudPrivateEndpointOperation{
			OperationKey: endpoint.OperationKey, Service: cloudPrivateEndpointServiceToProto(endpoint.Service),
			ServiceName:         endpoint.ServiceName,
			SecurityGroupSource: cloudEndpointSecurityGroupSourceToProto(endpoint.SecurityGroupSource),
			PrivateDnsEnabled:   endpoint.PrivateDNSEnabled, MonthlyHours: endpoint.MonthlyHours, DataMibPerMonth: endpoint.DataMiBPerMonth,
			EndpointType: cloudPrivateEndpointTypeToProto(endpoint.EndpointType),
		})
	}
	for _, snapshot := range value.Snapshots {
		result.Snapshots = append(result.Snapshots, &agentv1.CloudSnapshotOperation{
			OperationKey: snapshot.OperationKey, SourceVolumeSlotId: snapshot.SourceVolumeSlotID,
			SourceVolumeSpecDigest: snapshot.SourceVolumeSpecDigest, Disposition: cloudSnapshotDispositionToProto(snapshot.Disposition),
			MaxRetentionSeconds: snapshot.MaxRetentionSeconds,
		})
	}
	return result
}

func cloudPrivateEndpointServiceFromProto(value agentv1.CloudPrivateEndpointService) cloudquote.PrivateEndpointServiceV1 {
	switch value {
	case agentv1.CloudPrivateEndpointService_CLOUD_PRIVATE_ENDPOINT_SERVICE_S3:
		return cloudquote.PrivateEndpointServiceS3
	case agentv1.CloudPrivateEndpointService_CLOUD_PRIVATE_ENDPOINT_SERVICE_SECRETS_MANAGER:
		return cloudquote.PrivateEndpointServiceSecretsManager
	case agentv1.CloudPrivateEndpointService_CLOUD_PRIVATE_ENDPOINT_SERVICE_WORKER_CONTROL:
		return cloudquote.PrivateEndpointServiceWorkerControl
	default:
		return ""
	}
}

func cloudPrivateEndpointServiceToProto(value cloudquote.PrivateEndpointServiceV1) agentv1.CloudPrivateEndpointService {
	switch value {
	case cloudquote.PrivateEndpointServiceS3:
		return agentv1.CloudPrivateEndpointService_CLOUD_PRIVATE_ENDPOINT_SERVICE_S3
	case cloudquote.PrivateEndpointServiceSecretsManager:
		return agentv1.CloudPrivateEndpointService_CLOUD_PRIVATE_ENDPOINT_SERVICE_SECRETS_MANAGER
	case cloudquote.PrivateEndpointServiceWorkerControl:
		return agentv1.CloudPrivateEndpointService_CLOUD_PRIVATE_ENDPOINT_SERVICE_WORKER_CONTROL
	default:
		return agentv1.CloudPrivateEndpointService_CLOUD_PRIVATE_ENDPOINT_SERVICE_UNSPECIFIED
	}
}

func cloudPrivateEndpointTypeFromProto(value agentv1.CloudPrivateEndpointType) cloudquote.PrivateEndpointTypeV1 {
	switch value {
	case agentv1.CloudPrivateEndpointType_CLOUD_PRIVATE_ENDPOINT_TYPE_GATEWAY:
		return cloudquote.PrivateEndpointTypeGateway
	case agentv1.CloudPrivateEndpointType_CLOUD_PRIVATE_ENDPOINT_TYPE_INTERFACE:
		return cloudquote.PrivateEndpointTypeInterface
	default:
		return ""
	}
}

func cloudPrivateEndpointTypeToProto(value cloudquote.PrivateEndpointTypeV1) agentv1.CloudPrivateEndpointType {
	switch value {
	case cloudquote.PrivateEndpointTypeGateway:
		return agentv1.CloudPrivateEndpointType_CLOUD_PRIVATE_ENDPOINT_TYPE_GATEWAY
	case cloudquote.PrivateEndpointTypeInterface:
		return agentv1.CloudPrivateEndpointType_CLOUD_PRIVATE_ENDPOINT_TYPE_INTERFACE
	default:
		return agentv1.CloudPrivateEndpointType_CLOUD_PRIVATE_ENDPOINT_TYPE_UNSPECIFIED
	}
}

func cloudEndpointSecurityGroupSourceFromProto(value agentv1.CloudEndpointSecurityGroupSource) cloudquote.EndpointSecurityGroupSourceV1 {
	switch value {
	case agentv1.CloudEndpointSecurityGroupSource_CLOUD_ENDPOINT_SECURITY_GROUP_SOURCE_PLAN_EXISTING:
		return cloudquote.EndpointSecurityGroupPlanExisting
	case agentv1.CloudEndpointSecurityGroupSource_CLOUD_ENDPOINT_SECURITY_GROUP_SOURCE_WORKER_DEDICATED:
		return cloudquote.EndpointSecurityGroupWorkerDedicated
	case agentv1.CloudEndpointSecurityGroupSource_CLOUD_ENDPOINT_SECURITY_GROUP_SOURCE_ENDPOINT_DEDICATED_FROM_WORKER:
		return cloudquote.EndpointSecurityGroupEndpointDedicatedFromWorker
	default:
		return ""
	}
}

func cloudEndpointSecurityGroupSourceToProto(value cloudquote.EndpointSecurityGroupSourceV1) agentv1.CloudEndpointSecurityGroupSource {
	switch value {
	case cloudquote.EndpointSecurityGroupPlanExisting:
		return agentv1.CloudEndpointSecurityGroupSource_CLOUD_ENDPOINT_SECURITY_GROUP_SOURCE_PLAN_EXISTING
	case cloudquote.EndpointSecurityGroupWorkerDedicated:
		return agentv1.CloudEndpointSecurityGroupSource_CLOUD_ENDPOINT_SECURITY_GROUP_SOURCE_WORKER_DEDICATED
	case cloudquote.EndpointSecurityGroupEndpointDedicatedFromWorker:
		return agentv1.CloudEndpointSecurityGroupSource_CLOUD_ENDPOINT_SECURITY_GROUP_SOURCE_ENDPOINT_DEDICATED_FROM_WORKER
	default:
		return agentv1.CloudEndpointSecurityGroupSource_CLOUD_ENDPOINT_SECURITY_GROUP_SOURCE_UNSPECIFIED
	}
}

func cloudSnapshotDispositionFromProto(value agentv1.CloudSnapshotOperationDisposition) cloudquote.SnapshotOperationDispositionV1 {
	switch value {
	case agentv1.CloudSnapshotOperationDisposition_CLOUD_SNAPSHOT_OPERATION_DISPOSITION_DELETE_WITH_DEPLOYMENT:
		return cloudquote.SnapshotDeleteWithDeployment
	case agentv1.CloudSnapshotOperationDisposition_CLOUD_SNAPSHOT_OPERATION_DISPOSITION_RETAIN_WITH_MANAGED_SERVICE:
		return cloudquote.SnapshotRetainWithManagedService
	default:
		return ""
	}
}

func cloudSnapshotDispositionToProto(value cloudquote.SnapshotOperationDispositionV1) agentv1.CloudSnapshotOperationDisposition {
	switch value {
	case cloudquote.SnapshotDeleteWithDeployment:
		return agentv1.CloudSnapshotOperationDisposition_CLOUD_SNAPSHOT_OPERATION_DISPOSITION_DELETE_WITH_DEPLOYMENT
	case cloudquote.SnapshotRetainWithManagedService:
		return agentv1.CloudSnapshotOperationDisposition_CLOUD_SNAPSHOT_OPERATION_DISPOSITION_RETAIN_WITH_MANAGED_SERVICE
	default:
		return agentv1.CloudSnapshotOperationDisposition_CLOUD_SNAPSHOT_OPERATION_DISPOSITION_UNSPECIFIED
	}
}

func cloudCandidateFromProto(value agentv1.CloudCandidateProfile) cloudquote.CandidateProfile {
	switch value {
	case agentv1.CloudCandidateProfile_CLOUD_CANDIDATE_PROFILE_ECONOMY:
		return cloudquote.CandidateEconomic
	case agentv1.CloudCandidateProfile_CLOUD_CANDIDATE_PROFILE_RECOMMENDED:
		return cloudquote.CandidateRecommended
	case agentv1.CloudCandidateProfile_CLOUD_CANDIDATE_PROFILE_PERFORMANCE:
		return cloudquote.CandidatePerformance
	default:
		return ""
	}
}

func cloudCandidateToProto(value cloudquote.CandidateProfile) agentv1.CloudCandidateProfile {
	return cloudCandidateStringToProto(string(value))
}

func cloudCandidateStringToProto(value string) agentv1.CloudCandidateProfile {
	switch value {
	case string(cloudquote.CandidateEconomic):
		return agentv1.CloudCandidateProfile_CLOUD_CANDIDATE_PROFILE_ECONOMY
	case string(cloudquote.CandidateRecommended):
		return agentv1.CloudCandidateProfile_CLOUD_CANDIDATE_PROFILE_RECOMMENDED
	case string(cloudquote.CandidatePerformance):
		return agentv1.CloudCandidateProfile_CLOUD_CANDIDATE_PROFILE_PERFORMANCE
	default:
		return agentv1.CloudCandidateProfile_CLOUD_CANDIDATE_PROFILE_UNSPECIFIED
	}
}

func cloudPurchaseFromProto(value agentv1.CloudPurchaseOption) cloudquote.PurchaseOption {
	if value == agentv1.CloudPurchaseOption_CLOUD_PURCHASE_OPTION_SPOT {
		return cloudquote.PurchaseSpot
	}
	if value == agentv1.CloudPurchaseOption_CLOUD_PURCHASE_OPTION_ON_DEMAND {
		return cloudquote.PurchaseOnDemand
	}
	return ""
}

func cloudPurchaseToProto(value cloudquote.PurchaseOption) agentv1.CloudPurchaseOption {
	if value == cloudquote.PurchaseSpot {
		return agentv1.CloudPurchaseOption_CLOUD_PURCHASE_OPTION_SPOT
	}
	if value == cloudquote.PurchaseOnDemand {
		return agentv1.CloudPurchaseOption_CLOUD_PURCHASE_OPTION_ON_DEMAND
	}
	return agentv1.CloudPurchaseOption_CLOUD_PURCHASE_OPTION_UNSPECIFIED
}

func cloudEntryPointFromProto(value agentv1.CloudEntryPointKind) cloudquote.EntryPointKind {
	switch value {
	case agentv1.CloudEntryPointKind_CLOUD_ENTRY_POINT_KIND_NONE:
		return cloudquote.EntryPointNone
	case agentv1.CloudEntryPointKind_CLOUD_ENTRY_POINT_KIND_ALB:
		return cloudquote.EntryPointALB
	case agentv1.CloudEntryPointKind_CLOUD_ENTRY_POINT_KIND_CLOUDFRONT:
		return cloudquote.EntryPointCloudFront
	default:
		return ""
	}
}

func cloudEntryPointToProto(value cloudquote.EntryPointKind) agentv1.CloudEntryPointKind {
	switch value {
	case cloudquote.EntryPointNone:
		return agentv1.CloudEntryPointKind_CLOUD_ENTRY_POINT_KIND_NONE
	case cloudquote.EntryPointALB:
		return agentv1.CloudEntryPointKind_CLOUD_ENTRY_POINT_KIND_ALB
	case cloudquote.EntryPointCloudFront:
		return agentv1.CloudEntryPointKind_CLOUD_ENTRY_POINT_KIND_CLOUDFRONT
	default:
		return agentv1.CloudEntryPointKind_CLOUD_ENTRY_POINT_KIND_UNSPECIFIED
	}
}

func cloudSecurityGroupModeFromProto(value agentv1.CloudSecurityGroupMode) cloudquote.SecurityGroupMode {
	switch value {
	case agentv1.CloudSecurityGroupMode_CLOUD_SECURITY_GROUP_MODE_EXISTING:
		return cloudquote.SecurityGroupExisting
	case agentv1.CloudSecurityGroupMode_CLOUD_SECURITY_GROUP_MODE_CREATE_DEDICATED:
		return cloudquote.SecurityGroupCreateDedicated
	default:
		return ""
	}
}

func cloudSecurityGroupModeToProto(value cloudquote.SecurityGroupMode) agentv1.CloudSecurityGroupMode {
	switch value {
	case cloudquote.SecurityGroupExisting:
		return agentv1.CloudSecurityGroupMode_CLOUD_SECURITY_GROUP_MODE_EXISTING
	case cloudquote.SecurityGroupCreateDedicated:
		return agentv1.CloudSecurityGroupMode_CLOUD_SECURITY_GROUP_MODE_CREATE_DEDICATED
	default:
		return agentv1.CloudSecurityGroupMode_CLOUD_SECURITY_GROUP_MODE_UNSPECIFIED
	}
}

func cloudRetentionFromProto(value agentv1.CloudRetentionClass) cloudquote.RetentionClass {
	if value == agentv1.CloudRetentionClass_CLOUD_RETENTION_CLASS_EPHEMERAL {
		return cloudquote.RetentionEphemeral
	}
	if value == agentv1.CloudRetentionClass_CLOUD_RETENTION_CLASS_MANAGED {
		return cloudquote.RetentionManaged
	}
	return ""
}

func cloudRetentionToProto(value cloudquote.RetentionClass) agentv1.CloudRetentionClass {
	if value == cloudquote.RetentionEphemeral {
		return agentv1.CloudRetentionClass_CLOUD_RETENTION_CLASS_EPHEMERAL
	}
	if value == cloudquote.RetentionManaged {
		return agentv1.CloudRetentionClass_CLOUD_RETENTION_CLASS_MANAGED
	}
	return agentv1.CloudRetentionClass_CLOUD_RETENTION_CLASS_UNSPECIFIED
}

func cloudPlanStatusToProto(value cloudapproval.PlanStatus) agentv1.CloudPlanStatus {
	switch value {
	case cloudapproval.PlanResearching:
		return agentv1.CloudPlanStatus_CLOUD_PLAN_STATUS_RESEARCHING
	case cloudapproval.PlanQuoting:
		return agentv1.CloudPlanStatus_CLOUD_PLAN_STATUS_QUOTING
	case cloudapproval.PlanReadyForConfirmation:
		return agentv1.CloudPlanStatus_CLOUD_PLAN_STATUS_READY_FOR_CONFIRMATION
	case cloudapproval.PlanApproved:
		return agentv1.CloudPlanStatus_CLOUD_PLAN_STATUS_APPROVED
	case cloudapproval.PlanExpired:
		return agentv1.CloudPlanStatus_CLOUD_PLAN_STATUS_EXPIRED
	case cloudapproval.PlanSuperseded:
		return agentv1.CloudPlanStatus_CLOUD_PLAN_STATUS_SUPERSEDED
	default:
		return agentv1.CloudPlanStatus_CLOUD_PLAN_STATUS_UNSPECIFIED
	}
}

func approvalResourceScopeToProto(value cloudapproval.ResourceScopeV1) *agentv1.CloudResourceScope {
	return cloudResourceScopeToProto(cloudquote.ResourceScopeV1{
		Region: value.Region, AvailabilityZones: value.AvailabilityZones, InstanceType: value.InstanceType,
		InstanceCount: value.InstanceCount, Architecture: value.Architecture, VCPU: value.VCPU, MemoryMiB: value.MemoryMiB,
		GPUType: value.GPUType, GPUCount: value.GPUCount, GPUMemoryMiB: value.GPUMemoryMiB, DiskGiB: value.DiskGiB,
		VolumeType: value.VolumeType, VolumeIOPS: value.VolumeIOPS, VolumeThroughputMiBPS: value.VolumeThroughputMiBPS,
		VolumeEncrypted: value.VolumeEncrypted, PurchaseOption: cloudquote.PurchaseOption(value.PurchaseOption),
		WorkerImageID: value.WorkerImageID, WorkerImageDigest: value.WorkerImageDigest,
		VolumeScopes: append([]cloudquote.VolumeScopeV1(nil), value.VolumeScopes...),
	})
}

func approvalNetworkScopeToProto(value cloudapproval.NetworkScopeV1) *agentv1.CloudNetworkScope {
	return cloudNetworkScopeToProto(cloudquote.NetworkScopeV1{
		VPCID: value.VPCID, SubnetID: value.SubnetID, SecurityGroupMode: cloudquote.SecurityGroupMode(value.SecurityGroupMode), SecurityGroupID: value.SecurityGroupID, PublicIPv4: value.PublicIPv4,
		EntryPoint: cloudquote.EntryPointKind(value.EntryPoint), PublicExposure: value.PublicExposure,
		IngressPorts: value.IngressPorts, Hostname: value.Hostname, TLSRequired: value.TLSRequired,
		AuthenticationRequired: value.AuthenticationRequired,
		RouteTableID:           value.RouteTableID, ControlPlaneEndpoint: value.ControlPlaneEndpoint,
		PrivateConnectivity: cloudquote.PrivateConnectivityMode(value.PrivateConnectivity),
	})
}

func approvalSecretsToProto(values []cloudapproval.SecretReferenceV1) []*agentv1.CloudSecretScope {
	result := make([]*agentv1.CloudSecretScope, 0, len(values))
	for _, value := range values {
		result = append(result, &agentv1.CloudSecretScope{SecretRef: value.SecretRef, Purpose: value.Purpose, Delivery: string(value.Delivery)})
	}
	return result
}

func approvalIntegrationsToProto(values []cloudapproval.IntegrationScopeV1) []*agentv1.CloudIntegrationScope {
	result := make([]*agentv1.CloudIntegrationScope, 0, len(values))
	for _, value := range values {
		result = append(result, &agentv1.CloudIntegrationScope{Kind: string(value.Kind), Name: value.Name, Scopes: value.Scopes})
	}
	return result
}

func approvalRetentionToProto(value cloudapproval.RetentionScopeV1) *agentv1.CloudRetentionScope {
	return &agentv1.CloudRetentionScope{
		RetentionClass: cloudRetentionToProto(cloudquote.RetentionClass(value.Class)), AutoDestroy: value.AutoDestroy,
		GracePeriodSeconds: value.GracePeriodSeconds, MaxLifetimeSeconds: value.MaxLifetimeSeconds,
	}
}
