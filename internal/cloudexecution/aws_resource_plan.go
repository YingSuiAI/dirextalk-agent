package cloudexecution

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
)

// AWSResourcePlanBuilder projects exactly the resource scope covered by the
// device signature. The first validation slice supports either an approved
// existing security group or an exclusive no-ingress security group, one
// exclusive ENI, an optional outbound-only Elastic IP, and one exclusive EC2
// instance. The no-NAT v2 path additionally materializes the exact signed S3
// Gateway and Secrets Manager Interface endpoints before the Worker. Data
// volumes are explicit EBS ledger resources and are never silently folded into
// the Worker root disk.
type AWSResourcePlanBuilder struct {
	agentInstanceID string
}

func NewAWSResourcePlanBuilder(agentInstanceID string) (*AWSResourcePlanBuilder, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || parsed == uuid.Nil {
		return nil, ErrInvalid
	}
	return &AWSResourcePlanBuilder{agentInstanceID: parsed.String()}, nil
}

func (builder *AWSResourcePlanBuilder) Build(plan cloudapproval.PlanV1, connection cloudapp.Connection, boundRecipe recipe.RecipeV1, operation Operation) ([]resource.ProvisionSpec, error) {
	if builder == nil || plan.Status != cloudapproval.PlanApproved || operation.State != StateBootstrapReady && operation.State != StateProvisioning && operation.State != StateFailedRetriable ||
		plan.AgentInstanceID != builder.agentInstanceID || plan.OwnerID != connection.OwnerID || plan.ConnectionID != connection.ConnectionID ||
		plan.ResourceScope.Region != connection.Region || operation.ConnectionID != connection.ConnectionID || operation.ApprovedPlanHash == "" || operation.Bootstrap.Reference == "" {
		return nil, ErrInvalid
	}
	if plan.ResourceScope.PurchaseOption != cloudapproval.PurchaseOnDemand || plan.ResourceScope.DiskGiB < 8 || plan.ResourceScope.DiskGiB > 1024 {
		return nil, ErrUnsupportedRecipe
	}
	// A public entry point is a separately approved, post-Worker operation. The
	// initial Worker plan must never make a network declaration that this
	// builder cannot materialize and independently read back.
	if plan.NetworkScope.EntryPoint != cloudapproval.EntryPointNone || plan.NetworkScope.PublicExposure ||
		len(plan.NetworkScope.IngressPorts) != 0 || plan.NetworkScope.Hostname != "" ||
		plan.NetworkScope.TLSRequired || plan.NetworkScope.AuthenticationRequired {
		return nil, ErrInvalid
	}
	// The exclusive Worker is always private. Public ingress is a separately
	// device-approved ALB operation after an independently read-back Worker
	// succeeds, so an initial plan can never allocate an EIP.
	if plan.NetworkScope.PublicIPv4 {
		return nil, ErrInvalid
	}
	privateEndpoints := plan.NetworkScope.PrivateConnectivity == cloudapproval.PrivateConnectivityNoNATEndpointsV1
	if plan.NetworkScope.PrivateConnectivity != "" && !privateEndpoints {
		return nil, ErrInvalid
	}
	if privateEndpoints && (plan.NetworkScope.ControlPlaneEndpoint != operation.Launch.ControlPlaneTarget ||
		plan.NetworkScope.RouteTableID == "" || !validPrivateWorkerEndpointOperations(plan.ServiceOperations)) {
		return nil, ErrInvalid
	}
	if err := cloudquote.ValidateVolumeScopesForRecipe(plan.ResourceScope.VolumeScopes, boundRecipe, cloudquote.RetentionScopeV1{
		Class: cloudquote.RetentionClass(plan.RetentionScope.Class), AutoDestroy: plan.RetentionScope.AutoDestroy,
		GracePeriodSeconds: plan.RetentionScope.GracePeriodSeconds, MaxLifetimeSeconds: plan.RetentionScope.MaxLifetimeSeconds,
	}); err != nil {
		return nil, ErrInvalid
	}
	if len(plan.ResourceScope.VolumeScopes) != 0 && len(plan.ResourceScope.AvailabilityZones) != 1 {
		return nil, ErrInvalid
	}
	installerTrust, err := resourceInstallerTrust(operation)
	if err != nil {
		return nil, err
	}
	parsedRole, err := arn.Parse(connection.ControlRoleARN)
	if err != nil || parsedRole.Service != "iam" || parsedRole.AccountID != connection.AccountID {
		return nil, ErrInvalid
	}
	foundation, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{
		AgentInstanceID: builder.agentInstanceID, Partition: parsedRole.Partition,
		AccountID: connection.AccountID, Region: connection.Region,
	})
	if err != nil {
		return nil, ErrInvalid
	}
	retention, deadline, autoDestroy, err := resourceRetention(plan, operation)
	if err != nil {
		return nil, err
	}
	common := resource.ProvisionSpec{
		AgentInstanceID: builder.agentInstanceID, OwnerID: plan.OwnerID, TaskID: operation.TaskID,
		DeploymentID: operation.DeploymentID, Region: plan.ResourceScope.Region,
		ApprovedPlanHash: operation.ApprovedPlanHash, ApprovalID: operation.Launch.ApprovalID,
		Retention: retention, DestroyDeadline: deadline, AutoDestroyApproved: autoDestroy,
	}
	result := make([]resource.ProvisionSpec, 0, 9+len(plan.ResourceScope.VolumeScopes))
	securityGroupID := plan.NetworkScope.SecurityGroupID
	securityGroupMode := plan.NetworkScope.SecurityGroupMode
	if securityGroupMode == "" && securityGroupID != "" {
		securityGroupMode = cloudapproval.SecurityGroupExisting
	}
	var eniDependencies []string
	switch securityGroupMode {
	case cloudapproval.SecurityGroupExisting:
		if securityGroupID == "" {
			return nil, ErrInvalid
		}
	case cloudapproval.SecurityGroupCreateDedicated:
		if securityGroupID != "" {
			return nil, ErrInvalid
		}
		groupID := deterministicID(operation.DeploymentID, "security-group")
		groupAWS := &resource.AWSResourceSpecV1{
			SchemaVersion: resource.AWSResourceSpecSchemaV1,
			SecurityGroup: &resource.AWSSecurityGroupSpecV1{
				VPCID: plan.NetworkScope.VPCID, Description: "Dirextalk exclusive Worker " + operation.DeploymentID,
				Egress: []resource.AWSNetworkRuleV1{
					{Protocol: "tcp", FromPort: 53, ToPort: 53, CIDRv4: "0.0.0.0/0"},
					{Protocol: "udp", FromPort: 53, ToPort: 53, CIDRv4: "0.0.0.0/0"},
					{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRv4: "0.0.0.0/0"},
				},
			},
		}
		groupDigest, digestErr := groupAWS.Digest(resource.TypeSG)
		if digestErr != nil {
			return nil, ErrInvalid
		}
		group := common
		group.ResourceID, group.Type, group.LogicalName, group.SpecDigest, group.AWS = groupID, resource.TypeSG, "worker-security-group", groupDigest, groupAWS
		result = append(result, group)
		eniDependencies = []string{groupID}
		if privateEndpoints {
			endpointGroupID := deterministicID(operation.DeploymentID, "endpoint-security-group")
			endpointGroupAWS := &resource.AWSResourceSpecV1{
				SchemaVersion: resource.AWSResourceSpecSchemaV1,
				SecurityGroup: &resource.AWSSecurityGroupSpecV1{
					VPCID:       plan.NetworkScope.VPCID,
					Description: "Dirextalk Worker private endpoints " + operation.DeploymentID,
				},
			}
			endpointGroupDigest, digestErr := endpointGroupAWS.Digest(resource.TypeSG)
			if digestErr != nil {
				return nil, ErrInvalid
			}
			endpointGroup := common
			endpointGroup.ResourceID, endpointGroup.Type, endpointGroup.LogicalName = endpointGroupID, resource.TypeSG, "worker-endpoint-security-group"
			endpointGroup.SpecDigest, endpointGroup.AWS = endpointGroupDigest, endpointGroupAWS
			result = append(result, endpointGroup)

			ruleID := deterministicID(operation.DeploymentID, "endpoint-security-group-rule")
			ruleAWS := &resource.AWSResourceSpecV1{
				SchemaVersion: resource.AWSResourceSpecSchemaV1,
				SecurityGroupRule: &resource.AWSSecurityGroupRuleSpecV1{
					Direction: resource.AWSSecurityGroupRuleDirectionIngress,
					Protocol:  "tcp", FromPort: 443, ToPort: 443,
					SourceSecurityGroupResourceID: groupID,
					TargetSecurityGroupResourceID: endpointGroupID,
				},
			}
			ruleDigest, digestErr := ruleAWS.Digest(resource.TypeSecurityGroupRule)
			if digestErr != nil {
				return nil, ErrInvalid
			}
			rule := common
			rule.ResourceID, rule.Type, rule.LogicalName = ruleID, resource.TypeSecurityGroupRule, "worker-to-private-endpoint-https"
			rule.SpecDigest, rule.DependsOn, rule.AWS = ruleDigest, []string{groupID, endpointGroupID}, ruleAWS
			result = append(result, rule)

			gatewayID := deterministicID(operation.DeploymentID, "endpoint:s3-gateway")
			gatewayAWS := &resource.AWSResourceSpecV1{
				SchemaVersion: resource.AWSResourceSpecSchemaV1,
				Endpoint: &resource.AWSVPCEndpointSpecV1{
					VPCID:         plan.NetworkScope.VPCID,
					ServiceName:   "com.amazonaws." + plan.ResourceScope.Region + ".s3",
					EndpointType:  resource.AWSVPCEndpointTypeGateway,
					RouteTableIDs: []string{plan.NetworkScope.RouteTableID},
				},
			}
			gatewayDigest, digestErr := gatewayAWS.Digest(resource.TypeEndpoint)
			if digestErr != nil {
				return nil, ErrInvalid
			}
			gateway := common
			gateway.ResourceID, gateway.Type, gateway.LogicalName = gatewayID, resource.TypeEndpoint, "worker-s3-gateway-endpoint"
			gateway.SpecDigest, gateway.AWS = gatewayDigest, gatewayAWS
			result = append(result, gateway)

			interfaceID := deterministicID(operation.DeploymentID, "endpoint:secretsmanager-interface")
			interfaceAWS := &resource.AWSResourceSpecV1{
				SchemaVersion: resource.AWSResourceSpecSchemaV1,
				Endpoint: &resource.AWSVPCEndpointSpecV1{
					VPCID:             plan.NetworkScope.VPCID,
					ServiceName:       "com.amazonaws." + plan.ResourceScope.Region + ".secretsmanager",
					EndpointType:      resource.AWSVPCEndpointTypeInterface,
					SubnetID:          plan.NetworkScope.SubnetID,
					PrivateDNSEnabled: true,
				},
			}
			interfaceDigest, digestErr := interfaceAWS.Digest(resource.TypeEndpoint)
			if digestErr != nil {
				return nil, ErrInvalid
			}
			interfaceEndpoint := common
			interfaceEndpoint.ResourceID, interfaceEndpoint.Type, interfaceEndpoint.LogicalName = interfaceID, resource.TypeEndpoint, "worker-secretsmanager-interface-endpoint"
			interfaceEndpoint.SpecDigest, interfaceEndpoint.DependsOn, interfaceEndpoint.AWS = interfaceDigest, []string{endpointGroupID}, interfaceAWS
			result = append(result, interfaceEndpoint)
		}
	default:
		return nil, ErrInvalid
	}

	eniID := deterministicID(operation.DeploymentID, "eni")
	eniAWS := &resource.AWSResourceSpecV1{
		SchemaVersion: resource.AWSResourceSpecSchemaV1,
		NetworkInterface: &resource.AWSNetworkInterfaceSpecV1{
			SubnetID: plan.NetworkScope.SubnetID, ExistingSecurityGroupID: plan.NetworkScope.SecurityGroupID,
			Description: "Dirextalk exclusive Worker " + operation.DeploymentID,
		},
	}
	eniDigest, err := eniAWS.Digest(resource.TypeENI)
	if err != nil {
		return nil, ErrInvalid
	}
	eni := common
	eni.ResourceID, eni.Type, eni.LogicalName, eni.SpecDigest, eni.AWS = eniID, resource.TypeENI, "worker-network-interface", eniDigest, eniAWS
	eni.DependsOn = eniDependencies
	result = append(result, eni)

	instanceDependencies := []string{eniID}
	if privateEndpoints {
		instanceDependencies = append(instanceDependencies,
			deterministicID(operation.DeploymentID, "endpoint:s3-gateway"),
			deterministicID(operation.DeploymentID, "endpoint:secretsmanager-interface"),
		)
	}
	attachments := make([]resource.AWSDataVolumeAttachmentV1, 0, len(plan.ResourceScope.VolumeScopes))
	for _, volume := range plan.ResourceScope.VolumeScopes {
		volumeID := deterministicID(operation.DeploymentID, "volume:"+volume.SlotID)
		disposition := resource.AWSVolumeDeleteWithDeployment
		if volume.Disposition == cloudapproval.VolumeRetainWithManagedService {
			disposition = resource.AWSVolumeRetainWithManagedService
		}
		volumeAWS := &resource.AWSResourceSpecV1{
			SchemaVersion: resource.AWSResourceSpecSchemaV1,
			Volume: &resource.AWSEBSVolumeSpecV1{
				AvailabilityZone: plan.ResourceScope.AvailabilityZones[0], SizeGiB: volume.SizeGiB,
				VolumeType: volume.VolumeType, IOPS: volume.IOPS, ThroughputMiBPS: volume.ThroughputMiBPS,
				KMSKeyID: volume.KMSKeyID, SlotID: volume.SlotID, DeviceName: volume.DeviceName,
				MountPath: volume.MountPath, ReadOnly: volume.ReadOnly, Persistent: volume.Persistent, Disposition: disposition,
			},
		}
		volumeDigest, digestErr := volumeAWS.Digest(resource.TypeEBS)
		if digestErr != nil {
			return nil, ErrInvalid
		}
		volumeSpec := common
		volumeSpec.ResourceID, volumeSpec.Type, volumeSpec.LogicalName = volumeID, resource.TypeEBS, "recipe-volume-"+volume.SlotID
		volumeSpec.SpecDigest, volumeSpec.AWS = volumeDigest, volumeAWS
		result = append(result, volumeSpec)
		instanceDependencies = append(instanceDependencies, volumeID)
		attachments = append(attachments, resource.AWSDataVolumeAttachmentV1{ResourceID: volumeID, DeviceName: volume.DeviceName})
	}

	instanceAWS := &resource.AWSResourceSpecV1{
		SchemaVersion: resource.AWSResourceSpecSchemaV1,
		Instance: &resource.AWSEC2InstanceSpecV1{
			ImageID: plan.ResourceScope.WorkerImageID, ImageDigest: plan.ResourceScope.WorkerImageDigest,
			Architecture: plan.ResourceScope.Architecture,
			InstanceType: plan.ResourceScope.InstanceType, InstanceProfileName: foundation.WorkerProfileName,
			UserDataArtifactRef:    operation.Bootstrap.Reference,
			UserDataArtifactDigest: "sha256:" + hex.EncodeToString(operation.Bootstrap.SHA256[:]),
			Bootstrap: resource.AWSWorkerBootstrapSpecV1{
				DeploymentID: operation.DeploymentID, WorkerID: deterministicID(operation.DeploymentID, "worker"),
				ControlPlaneEndpoint: operation.Launch.ControlPlaneTarget, EnrollmentExpectedRevision: 1,
				InstallerTrust: installerTrust, InstallerArtifacts: append([]installerbootstrap.ArtifactSourceV1(nil), operation.InstallerArtifacts...),
				InstallerSecrets: append([]installerbootstrap.SecretSourceV1(nil), operation.InstallerSecrets...),
			},
			RootDeviceName: "/dev/sda1", RootVolumeGiB: uint32(plan.ResourceScope.DiskGiB),
			RootKMSKeyID: "alias/" + foundation.StackName, Market: resource.AWSMarketOnDemand,
			DataVolumes: attachments, EBSOptimized: true,
		},
	}
	instanceDigest, err := instanceAWS.Digest(resource.TypeEC2)
	if err != nil {
		return nil, ErrInvalid
	}
	instance := common
	instance.ResourceID, instance.Type, instance.LogicalName = deterministicID(operation.DeploymentID, "ec2"), resource.TypeEC2, "exclusive-cloud-worker"
	instance.SpecDigest, instance.DependsOn, instance.AWS = instanceDigest, instanceDependencies, instanceAWS
	result = append(result, instance)
	return result, nil
}

func validPrivateWorkerEndpointOperations(value *cloudapproval.ServiceOperationScopeV1) bool {
	if value == nil || len(value.PrivateEndpoints) != 2 || len(value.Snapshots) != 0 {
		return false
	}
	var gateway, secrets bool
	for _, endpoint := range value.PrivateEndpoints {
		switch {
		case endpoint.Service == cloudapproval.PrivateEndpointServiceS3 && endpoint.EndpointType == cloudapproval.PrivateEndpointTypeGateway:
			gateway = endpoint.SecurityGroupSource == "" && !endpoint.PrivateDNSEnabled && endpoint.MonthlyHours == 0 && endpoint.DataMiBPerMonth == 0
		case endpoint.Service == cloudapproval.PrivateEndpointServiceSecretsManager && endpoint.EndpointType == cloudapproval.PrivateEndpointTypeInterface:
			secrets = endpoint.SecurityGroupSource == cloudapproval.EndpointSecurityGroupEndpointDedicatedFromWorker && endpoint.PrivateDNSEnabled && endpoint.MonthlyHours > 0 && endpoint.DataMiBPerMonth > 0
		default:
			return false
		}
	}
	return gateway && secrets
}

func resourceInstallerTrust(operation Operation) (*installerbootstrap.RootTrustMaterialV1, error) {
	if operation.InstallerRootTrust == nil {
		return nil, nil
	}
	value := operation.InstallerRootTrust
	trust := &installerbootstrap.RootTrustMaterialV1{
		SchemaVersion:    value.SchemaVersion,
		TrustID:          value.TrustID,
		PublicKey:        append([]byte(nil), value.PublicKey...),
		ConfigCBOR:       append([]byte(nil), value.ConfigCBOR...),
		ConfigDigest:     value.ConfigDigest,
		ArtifactManifest: value.ArtifactManifest,
	}
	trust.ArtifactManifest.Manifest.Artifacts = append([]installer.ArtifactV1(nil), value.ArtifactManifest.Manifest.Artifacts...)
	trust.ArtifactManifest.Manifest.Secrets = append([]installer.SecretV1(nil), value.ArtifactManifest.Manifest.Secrets...)
	trust.ArtifactManifest.Manifest.Volumes = append([]installer.VolumeV1(nil), value.ArtifactManifest.Manifest.Volumes...)
	trust.ArtifactManifest.Signature = append([]byte(nil), value.ArtifactManifest.Signature...)
	if _, err := installerbootstrap.ValidateTrustMaterial(*trust, operation.DeploymentID); err != nil {
		return nil, ErrInvalid
	}
	return trust, nil
}

func resourceRetention(plan cloudapproval.PlanV1, operation Operation) (task.RetentionPolicy, time.Time, bool, error) {
	switch plan.RetentionScope.Class {
	case cloudapproval.RetentionEphemeral:
		if !plan.RetentionScope.AutoDestroy || plan.RetentionScope.MaxLifetimeSeconds == 0 || operation.CreatedAt.IsZero() {
			return "", time.Time{}, false, ErrInvalid
		}
		deadline := operation.CreatedAt.UTC().Add(time.Duration(plan.RetentionScope.MaxLifetimeSeconds) * time.Second)
		if !deadline.After(operation.UpdatedAt) {
			return "", time.Time{}, false, fmt.Errorf("%w: approved resource lifetime already expired", ErrNotReady)
		}
		return task.RetentionEphemeralAutoDestroy, deadline, true, nil
	case cloudapproval.RetentionManaged:
		if plan.RetentionScope.AutoDestroy {
			return "", time.Time{}, false, ErrInvalid
		}
		return task.RetentionManaged, time.Time{}, false, nil
	default:
		return "", time.Time{}, false, ErrInvalid
	}
}
