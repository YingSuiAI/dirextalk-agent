package cloudexecution

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
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
// instance. It fails closed for Spot and persistent data volumes until their
// additional quote and lifecycle contracts are represented in PlanV1.
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
	for _, slot := range boundRecipe.VolumeSlots {
		if slot.Persistent {
			return nil, ErrUnsupportedRecipe
		}
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
	result := make([]resource.ProvisionSpec, 0, 4)
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

	if plan.NetworkScope.PublicIPv4 {
		eipAWS := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, ElasticIP: &resource.AWSElasticIPSpecV1{Domain: "vpc"}}
		eipDigest, digestErr := eipAWS.Digest(resource.TypeEIP)
		if digestErr != nil {
			return nil, ErrInvalid
		}
		eip := common
		eip.ResourceID, eip.Type, eip.LogicalName = deterministicID(operation.DeploymentID, "eip"), resource.TypeEIP, "worker-public-ipv4"
		eip.SpecDigest, eip.DependsOn, eip.AWS = eipDigest, []string{eniID}, eipAWS
		result = append(result, eip)
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
			},
			RootDeviceName: "/dev/sda1", RootVolumeGiB: uint32(plan.ResourceScope.DiskGiB),
			RootKMSKeyID: "alias/" + foundation.StackName, Market: resource.AWSMarketOnDemand,
			EBSOptimized: true,
		},
	}
	instanceDigest, err := instanceAWS.Digest(resource.TypeEC2)
	if err != nil {
		return nil, ErrInvalid
	}
	instance := common
	instance.ResourceID, instance.Type, instance.LogicalName = deterministicID(operation.DeploymentID, "ec2"), resource.TypeEC2, "exclusive-cloud-worker"
	instance.SpecDigest, instance.DependsOn, instance.AWS = instanceDigest, []string{eniID}, instanceAWS
	result = append(result, instance)
	return result, nil
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
