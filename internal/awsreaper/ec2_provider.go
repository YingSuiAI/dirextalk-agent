package awsreaper

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
)

var (
	ErrCloudReadBack       = errors.New("AWS resource read-back failed")
	ErrCloudMutation       = errors.New("AWS resource mutation failed")
	ErrOwnershipMismatch   = errors.New("AWS resource ownership does not match approved ephemeral manifest")
	ErrUnsupportedMutation = errors.New("AWS Reaper provider supports destruction only")
)

const (
	awsTagAgentInstanceID = "dirextalk:agent_instance_id"
	awsTagOwnerID         = "dirextalk:owner_id"
	awsTagTaskID          = "dirextalk:task_id"
	awsTagDeploymentID    = "dirextalk:deployment_id"
	awsTagRetention       = "dirextalk:retention"
	awsTagDestroyDeadline = "dirextalk:destroy_deadline"
	awsTagResourceID      = "dirextalk:resource_id"
	awsRetentionEphemeral = "ephemeral"
	awsRetentionManaged   = "managed"
)

type EC2API interface {
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	TerminateInstances(context.Context, *ec2.TerminateInstancesInput, ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error)
	DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	DeleteVolume(context.Context, *ec2.DeleteVolumeInput, ...func(*ec2.Options)) (*ec2.DeleteVolumeOutput, error)
	DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
	DeleteNetworkInterface(context.Context, *ec2.DeleteNetworkInterfaceInput, ...func(*ec2.Options)) (*ec2.DeleteNetworkInterfaceOutput, error)
	DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
	ReleaseAddress(context.Context, *ec2.ReleaseAddressInput, ...func(*ec2.Options)) (*ec2.ReleaseAddressOutput, error)
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DeleteSecurityGroup(context.Context, *ec2.DeleteSecurityGroupInput, ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error)
	DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
	DeleteSnapshot(context.Context, *ec2.DeleteSnapshotInput, ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error)
	DescribeVpcEndpoints(context.Context, *ec2.DescribeVpcEndpointsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error)
	DeleteVpcEndpoints(context.Context, *ec2.DeleteVpcEndpointsInput, ...func(*ec2.Options)) (*ec2.DeleteVpcEndpointsOutput, error)
}

type EC2Provider struct {
	client          EC2API
	agentInstanceID string
	region          string
	now             func() time.Time
}

func NewEC2Provider(client EC2API, agentInstanceID, region string) (*EC2Provider, error) {
	config := Config{AgentInstanceID: strings.TrimSpace(agentInstanceID), Region: strings.TrimSpace(region), ManifestTable: "placeholder"}
	if client == nil || config.Validate() != nil {
		return nil, ErrInvalidConfig
	}
	return &EC2Provider{client: client, agentInstanceID: config.AgentInstanceID, region: config.Region, now: time.Now}, nil
}

func (provider *EC2Provider) Create(context.Context, resource.ProviderCreateRequest) (resource.ProviderObservation, error) {
	return resource.ProviderObservation{}, ErrUnsupportedMutation
}

func (provider *EC2Provider) FindByClientToken(context.Context, resource.Type, string, string) (resource.ProviderObservation, bool, error) {
	return resource.ProviderObservation{}, false, ErrUnsupportedMutation
}

func (provider *EC2Provider) ListOwned(context.Context, string) ([]resource.ProviderObservation, error) {
	return nil, ErrUnsupportedMutation
}

func (provider *EC2Provider) ReadBack(ctx context.Context, kind resource.Type, providerID, region string) (resource.ProviderObservation, error) {
	if !provider.validRequest(kind, providerID, region) {
		return resource.ProviderObservation{}, resource.ErrInvalid
	}
	observation, err := provider.observe(ctx, kind, providerID)
	if err != nil {
		if isNotFound(err) {
			return absentObservation(kind, providerID, provider.now()), nil
		}
		return resource.ProviderObservation{}, ErrCloudReadBack
	}
	return resource.ProviderObservation{
		ProviderID: providerID, Type: kind, Exists: observation.exists,
		Tags: awsTagsToResourceTags(observation.tags), ObservedAt: provider.now().UTC(),
	}, nil
}

func (provider *EC2Provider) Delete(ctx context.Context, kind resource.Type, providerID, region string, expectedTags map[string]string) error {
	if !provider.validRequest(kind, providerID, region) {
		return resource.ErrInvalid
	}
	observation, err := provider.observe(ctx, kind, providerID)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return ErrCloudReadBack
	}
	if !observation.exists {
		return nil
	}
	if err := provider.verifyEphemeralOwnership(observation.tags, expectedTags); err != nil {
		return err
	}
	if err := provider.delete(ctx, kind, providerID); err != nil && !isNotFound(err) {
		return ErrCloudMutation
	}
	return nil
}

func (provider *EC2Provider) validRequest(kind resource.Type, providerID, region string) bool {
	if strings.TrimSpace(providerID) == "" || len(providerID) > 255 || region != provider.region || strings.ContainsAny(providerID, "\r\n\x00*/ ") {
		return false
	}
	switch kind {
	case resource.TypeEC2, resource.TypeEBS, resource.TypeENI, resource.TypeEIP, resource.TypeSG, resource.TypeEndpoint, resource.TypeSnapshot:
		return true
	default:
		return false
	}
}

type rawObservation struct {
	exists bool
	tags   map[string]string
}

func (provider *EC2Provider) observe(ctx context.Context, kind resource.Type, providerID string) (rawObservation, error) {
	switch kind {
	case resource.TypeEC2:
		output, err := provider.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{providerID}})
		if err != nil {
			return rawObservation{}, err
		}
		for _, reservation := range output.Reservations {
			for _, instance := range reservation.Instances {
				if aws.ToString(instance.InstanceId) == providerID {
					return rawObservation{exists: instance.State == nil || instance.State.Name != ec2types.InstanceStateNameTerminated, tags: sdkTags(instance.Tags)}, nil
				}
			}
		}
	case resource.TypeEBS:
		output, err := provider.client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{VolumeIds: []string{providerID}})
		if err != nil {
			return rawObservation{}, err
		}
		for _, value := range output.Volumes {
			if aws.ToString(value.VolumeId) == providerID {
				return rawObservation{exists: true, tags: sdkTags(value.Tags)}, nil
			}
		}
	case resource.TypeENI:
		output, err := provider.client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{NetworkInterfaceIds: []string{providerID}})
		if err != nil {
			return rawObservation{}, err
		}
		for _, value := range output.NetworkInterfaces {
			if aws.ToString(value.NetworkInterfaceId) == providerID {
				return rawObservation{exists: true, tags: sdkTags(value.TagSet)}, nil
			}
		}
	case resource.TypeEIP:
		output, err := provider.client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{AllocationIds: []string{providerID}})
		if err != nil {
			return rawObservation{}, err
		}
		for _, value := range output.Addresses {
			if aws.ToString(value.AllocationId) == providerID {
				return rawObservation{exists: true, tags: sdkTags(value.Tags)}, nil
			}
		}
	case resource.TypeSG:
		output, err := provider.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: []string{providerID}})
		if err != nil {
			return rawObservation{}, err
		}
		for _, value := range output.SecurityGroups {
			if aws.ToString(value.GroupId) == providerID {
				return rawObservation{exists: true, tags: sdkTags(value.Tags)}, nil
			}
		}
	case resource.TypeSnapshot:
		output, err := provider.client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{SnapshotIds: []string{providerID}})
		if err != nil {
			return rawObservation{}, err
		}
		for _, value := range output.Snapshots {
			if aws.ToString(value.SnapshotId) == providerID {
				return rawObservation{exists: true, tags: sdkTags(value.Tags)}, nil
			}
		}
	case resource.TypeEndpoint:
		output, err := provider.client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{VpcEndpointIds: []string{providerID}})
		if err != nil {
			return rawObservation{}, err
		}
		for _, value := range output.VpcEndpoints {
			if aws.ToString(value.VpcEndpointId) == providerID {
				return rawObservation{exists: true, tags: sdkTags(value.Tags)}, nil
			}
		}
	}
	return rawObservation{exists: false}, nil
}

func (provider *EC2Provider) delete(ctx context.Context, kind resource.Type, providerID string) error {
	switch kind {
	case resource.TypeEC2:
		_, err := provider.client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{InstanceIds: []string{providerID}})
		return err
	case resource.TypeEBS:
		_, err := provider.client.DeleteVolume(ctx, &ec2.DeleteVolumeInput{VolumeId: &providerID})
		return err
	case resource.TypeENI:
		_, err := provider.client.DeleteNetworkInterface(ctx, &ec2.DeleteNetworkInterfaceInput{NetworkInterfaceId: &providerID})
		return err
	case resource.TypeEIP:
		_, err := provider.client.ReleaseAddress(ctx, &ec2.ReleaseAddressInput{AllocationId: &providerID})
		return err
	case resource.TypeSG:
		_, err := provider.client.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{GroupId: &providerID})
		return err
	case resource.TypeSnapshot:
		_, err := provider.client.DeleteSnapshot(ctx, &ec2.DeleteSnapshotInput{SnapshotId: &providerID})
		return err
	case resource.TypeEndpoint:
		output, err := provider.client.DeleteVpcEndpoints(ctx, &ec2.DeleteVpcEndpointsInput{VpcEndpointIds: []string{providerID}})
		if err != nil {
			return err
		}
		if output == nil || len(output.Unsuccessful) != 0 {
			return ErrCloudMutation
		}
		return nil
	default:
		return ErrUnsupportedMutation
	}
}

func (provider *EC2Provider) verifyEphemeralOwnership(actual, expected map[string]string) error {
	deadline, err := time.Parse(time.RFC3339, expected[resource.TagDestroyDeadline])
	if err != nil || deadline.After(provider.now().UTC()) || expected[resource.TagAgentInstanceID] != provider.agentInstanceID ||
		expected[resource.TagRetention] != string(task.RetentionEphemeralAutoDestroy) {
		return ErrOwnershipMismatch
	}
	expectedAWS := map[string]string{
		awsTagAgentInstanceID: expected[resource.TagAgentInstanceID],
		awsTagOwnerID:         expected[resource.TagOwnerID],
		awsTagTaskID:          expected[resource.TagTaskID],
		awsTagDeploymentID:    expected[resource.TagDeploymentID],
		awsTagResourceID:      expected[resource.TagResourceID],
		awsTagRetention:       awsRetentionEphemeral,
		awsTagDestroyDeadline: deadline.UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	for key, value := range expectedAWS {
		if value == "" || actual[key] != value {
			return ErrOwnershipMismatch
		}
	}
	return nil
}

func sdkTags(tags []ec2types.Tag) map[string]string {
	result := make(map[string]string, len(tags))
	for _, tag := range tags {
		key, value := aws.ToString(tag.Key), aws.ToString(tag.Value)
		if key != "" {
			result[key] = value
		}
	}
	return result
}

func awsTagsToResourceTags(tags map[string]string) map[string]string {
	retention := ""
	switch tags[awsTagRetention] {
	case awsRetentionEphemeral:
		retention = string(task.RetentionEphemeralAutoDestroy)
	case awsRetentionManaged:
		retention = string(task.RetentionManaged)
	}
	return map[string]string{
		resource.TagAgentInstanceID: tags[awsTagAgentInstanceID], resource.TagOwnerID: tags[awsTagOwnerID],
		resource.TagTaskID: tags[awsTagTaskID], resource.TagDeploymentID: tags[awsTagDeploymentID],
		resource.TagResourceID: tags[awsTagResourceID], resource.TagRetention: retention,
		resource.TagDestroyDeadline: tags[awsTagDestroyDeadline],
	}
}

func absentObservation(kind resource.Type, providerID string, now time.Time) resource.ProviderObservation {
	return resource.ProviderObservation{ProviderID: providerID, Type: kind, Exists: false, ObservedAt: now.UTC()}
}

func isNotFound(err error) bool {
	var apiError smithy.APIError
	if !errors.As(err, &apiError) {
		return false
	}
	code := strings.ToLower(apiError.ErrorCode())
	return strings.Contains(code, "notfound") || strings.Contains(code, "not_found")
}
