package awsreaper

import (
	"context"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/google/uuid"
)

type typedFakeEC2 struct {
	EC2API
	providerID string
	tags       []ec2types.Tag
	exists     map[resource.Type]bool
	deleted    []resource.Type
}

func (fake *typedFakeEC2) markDeleted(kind resource.Type) {
	fake.exists[kind] = false
	fake.deleted = append(fake.deleted, kind)
}

func (fake *typedFakeEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	state := ec2types.InstanceStateNameTerminated
	if fake.exists[resource.TypeEC2] {
		state = ec2types.InstanceStateNameRunning
	}
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{{InstanceId: &fake.providerID, Tags: fake.tags, State: &ec2types.InstanceState{Name: state}}}}}}, nil
}
func (fake *typedFakeEC2) TerminateInstances(context.Context, *ec2.TerminateInstancesInput, ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error) {
	fake.markDeleted(resource.TypeEC2)
	return &ec2.TerminateInstancesOutput{}, nil
}
func (fake *typedFakeEC2) DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	result := &ec2.DescribeVolumesOutput{}
	if fake.exists[resource.TypeEBS] {
		result.Volumes = []ec2types.Volume{{VolumeId: &fake.providerID, Tags: fake.tags}}
	}
	return result, nil
}
func (fake *typedFakeEC2) DeleteVolume(context.Context, *ec2.DeleteVolumeInput, ...func(*ec2.Options)) (*ec2.DeleteVolumeOutput, error) {
	fake.markDeleted(resource.TypeEBS)
	return &ec2.DeleteVolumeOutput{}, nil
}
func (fake *typedFakeEC2) DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	result := &ec2.DescribeNetworkInterfacesOutput{}
	if fake.exists[resource.TypeENI] {
		result.NetworkInterfaces = []ec2types.NetworkInterface{{NetworkInterfaceId: &fake.providerID, TagSet: fake.tags}}
	}
	return result, nil
}
func (fake *typedFakeEC2) DeleteNetworkInterface(context.Context, *ec2.DeleteNetworkInterfaceInput, ...func(*ec2.Options)) (*ec2.DeleteNetworkInterfaceOutput, error) {
	fake.markDeleted(resource.TypeENI)
	return &ec2.DeleteNetworkInterfaceOutput{}, nil
}
func (fake *typedFakeEC2) DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	result := &ec2.DescribeAddressesOutput{}
	if fake.exists[resource.TypeEIP] {
		result.Addresses = []ec2types.Address{{AllocationId: &fake.providerID, Tags: fake.tags}}
	}
	return result, nil
}
func (fake *typedFakeEC2) ReleaseAddress(context.Context, *ec2.ReleaseAddressInput, ...func(*ec2.Options)) (*ec2.ReleaseAddressOutput, error) {
	fake.markDeleted(resource.TypeEIP)
	return &ec2.ReleaseAddressOutput{}, nil
}
func (fake *typedFakeEC2) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	result := &ec2.DescribeSecurityGroupsOutput{}
	if fake.exists[resource.TypeSG] {
		result.SecurityGroups = []ec2types.SecurityGroup{{GroupId: &fake.providerID, Tags: fake.tags}}
	}
	return result, nil
}
func (fake *typedFakeEC2) DeleteSecurityGroup(context.Context, *ec2.DeleteSecurityGroupInput, ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error) {
	fake.markDeleted(resource.TypeSG)
	return &ec2.DeleteSecurityGroupOutput{}, nil
}
func (fake *typedFakeEC2) DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	result := &ec2.DescribeSnapshotsOutput{}
	if fake.exists[resource.TypeSnapshot] {
		result.Snapshots = []ec2types.Snapshot{{SnapshotId: &fake.providerID, Tags: fake.tags}}
	}
	return result, nil
}
func (fake *typedFakeEC2) DeleteSnapshot(context.Context, *ec2.DeleteSnapshotInput, ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error) {
	fake.markDeleted(resource.TypeSnapshot)
	return &ec2.DeleteSnapshotOutput{}, nil
}
func (fake *typedFakeEC2) DescribeVpcEndpoints(context.Context, *ec2.DescribeVpcEndpointsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error) {
	result := &ec2.DescribeVpcEndpointsOutput{}
	if fake.exists[resource.TypeEndpoint] {
		result.VpcEndpoints = []ec2types.VpcEndpoint{{VpcEndpointId: &fake.providerID, Tags: fake.tags}}
	}
	return result, nil
}
func (fake *typedFakeEC2) DeleteVpcEndpoints(context.Context, *ec2.DeleteVpcEndpointsInput, ...func(*ec2.Options)) (*ec2.DeleteVpcEndpointsOutput, error) {
	fake.markDeleted(resource.TypeEndpoint)
	return &ec2.DeleteVpcEndpointsOutput{}, nil
}

func TestEC2ProviderDispatchesTypedDestroyAndReadBackForEveryResourceKind(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	ids := map[resource.Type]string{
		resource.TypeEC2: "i-0123456789abcdef0", resource.TypeEBS: "vol-0123456789abcdef0",
		resource.TypeENI: "eni-0123456789abcdef0", resource.TypeEIP: "eipalloc-0123456789abcdef0",
		resource.TypeSG: "sg-0123456789abcdef0", resource.TypeSnapshot: "snap-0123456789abcdef0",
		resource.TypeEndpoint: "vpce-0123456789abcdef0",
	}
	for kind, providerID := range ids {
		t.Run(string(kind), func(t *testing.T) {
			agentID, taskID, deploymentID, resourceID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
			fake := &typedFakeEC2{providerID: providerID, exists: map[resource.Type]bool{kind: true}, tags: awsResourceTags(agentID, taskID, deploymentID, resourceID, now.Add(-time.Minute), awsRetentionEphemeral)}
			provider, _ := NewEC2Provider(fake, agentID, "us-west-2")
			provider.now = func() time.Time { return now }
			if err := provider.Delete(context.Background(), kind, providerID, "us-west-2", expectedResourceTags(agentID, taskID, deploymentID, resourceID, now.Add(-time.Minute))); err != nil {
				t.Fatal(err)
			}
			if len(fake.deleted) != 1 || fake.deleted[0] != kind {
				t.Fatalf("deleted = %v", fake.deleted)
			}
			observation, err := provider.ReadBack(context.Background(), kind, providerID, "us-west-2")
			if err != nil || observation.Exists {
				t.Fatalf("read-back = %+v err=%v", observation, err)
			}
		})
	}
}
