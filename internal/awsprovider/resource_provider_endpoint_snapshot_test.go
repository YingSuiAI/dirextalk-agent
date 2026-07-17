package awsprovider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestEC2ResourceProviderRecoversPrivateEndpointAndSnapshotAndVerifiesDelete(t *testing.T) {
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	client := &endpointSnapshotEC2Fake{
		endpointID: "vpce-0123456789abcdef0", snapshotID: "snap-0123456789abcdef0",
		endpointCreateError: errors.New("endpoint response lost"), snapshotCreateError: errors.New("snapshot response lost"),
	}
	provider, err := NewEC2ResourceProvider(client, "us-east-1", func() time.Time { return now }, WithEC2ResourcePollInterval(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}

	endpointSpec := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, Endpoint: &resource.AWSVPCEndpointSpecV1{
		VPCID: "vpc-0123456789abcdef0", ServiceName: "com.amazonaws.us-east-1.s3",
		SubnetIDs: []string{"subnet-0123456789abcdef0"}, PrivateDNSEnabled: true,
	}}
	endpointRequest := endpointSnapshotRequest(t, resource.TypeEndpoint, "11111111-1111-4111-8111-111111111111", "dtx-endpoint-0123456789", endpointSpec,
		[]resource.ProviderDependency{{ResourceID: "22222222-2222-4222-8222-222222222222", Type: resource.TypeSG, ProviderID: "sg-0123456789abcdef0"}})
	endpoint, err := provider.Create(context.Background(), endpointRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !endpoint.Exists || endpoint.ProviderID != client.endpointID || client.endpointCreateCalls != 1 {
		t.Fatalf("lost endpoint response was not recovered: observation=%#v calls=%d", endpoint, client.endpointCreateCalls)
	}
	input := client.endpointInput
	if input == nil || aws.ToString(input.ClientToken) != endpointRequest.ClientToken || input.VpcEndpointType != ec2types.VpcEndpointTypeInterface ||
		input.IpAddressType != ec2types.IpAddressTypeIpv4 || len(input.SecurityGroupIds) != 1 || input.SecurityGroupIds[0] != endpointRequest.Dependencies[0].ProviderID ||
		len(input.SubnetIds) != 1 || input.SubnetIds[0] != endpointSpec.Endpoint.SubnetIDs[0] || input.PolicyDocument != nil || client.authorizeIngressCalls != 0 {
		t.Fatalf("endpoint was not a closed private-only mutation: input=%#v ingress_calls=%d", input, client.authorizeIngressCalls)
	}

	snapshotSpec := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, Snapshot: &resource.AWSEBSSnapshotSpecV1{
		Description: "checkpoint before upgrade", Disposition: resource.AWSSnapshotDeleteWithDeployment,
	}}
	snapshotRequest := endpointSnapshotRequest(t, resource.TypeSnapshot, "33333333-3333-4333-8333-333333333333", "dtx-snapshot-012345678", snapshotSpec,
		[]resource.ProviderDependency{{ResourceID: "44444444-4444-4444-8444-444444444444", Type: resource.TypeEBS, ProviderID: "vol-0123456789abcdef0"}})
	snapshot, err := provider.Create(context.Background(), snapshotRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Exists || snapshot.ProviderID != client.snapshotID || client.snapshotCreateCalls != 1 || client.snapshotInput == nil ||
		aws.ToString(client.snapshotInput.VolumeId) != snapshotRequest.Dependencies[0].ProviderID {
		t.Fatalf("lost snapshot response was not recovered: observation=%#v calls=%d input=%#v", snapshot, client.snapshotCreateCalls, client.snapshotInput)
	}
	if _, found, err := provider.FindByClientToken(context.Background(), resource.TypeSnapshot, "us-east-1", snapshotRequest.ClientToken); err != nil || !found {
		t.Fatalf("snapshot token recovery failed: found=%v err=%v", found, err)
	}
	if candidates, err := provider.FindAllByClientToken(context.Background(), resource.TypeSnapshot, "us-east-1", snapshotRequest.ClientToken); err != nil || len(candidates) != 1 || candidates[0].ProviderID != client.snapshotID {
		t.Fatalf("snapshot candidate evidence=%#v err=%v", candidates, err)
	}

	owned, err := provider.ListOwned(context.Background(), endpointRequest.Tags[resource.TagAgentInstanceID], endpointRequest.Tags[resource.TagOwnerID])
	if err != nil {
		t.Fatal(err)
	}
	if len(owned) != 2 || owned[0].Type != resource.TypeEndpoint || owned[1].Type != resource.TypeSnapshot {
		t.Fatalf("endpoint/snapshot recovery list = %#v", owned)
	}
	for _, item := range []resource.ProviderObservation{endpoint, snapshot} {
		if err := provider.Delete(context.Background(), item.Type, item.ProviderID, "us-east-1", item.Tags); err != nil {
			t.Fatalf("delete %s: %v", item.Type, err)
		}
		readBack, err := provider.ReadBack(context.Background(), item.Type, item.ProviderID, "us-east-1")
		if err != nil || readBack.Exists {
			t.Fatalf("%s delete was not independently verified: %#v err=%v", item.Type, readBack, err)
		}
	}
}

func endpointSnapshotRequest(t *testing.T, kind resource.Type, resourceID, token string, spec *resource.AWSResourceSpecV1, dependencies []resource.ProviderDependency) resource.ProviderCreateRequest {
	t.Helper()
	digest, err := spec.Digest(kind)
	if err != nil {
		t.Fatal(err)
	}
	return resource.ProviderCreateRequest{
		ResourceID: resourceID, Type: kind, LogicalName: "private-data-path", Region: "us-east-1",
		SpecDigest: digest, ClientToken: token, Tags: validResourceTags(resourceID), Dependencies: dependencies, AWS: spec,
	}
}

type endpointSnapshotEC2Fake struct {
	EC2ResourceAPI
	endpointID, snapshotID                   string
	endpointCreateError, snapshotCreateError error
	endpointCreateCalls, snapshotCreateCalls int
	authorizeIngressCalls                    int
	endpointInput                            *ec2.CreateVpcEndpointInput
	snapshotInput                            *ec2.CreateSnapshotInput
	endpoint                                 *ec2types.VpcEndpoint
	snapshot                                 *ec2types.Snapshot
}

func (fake *endpointSnapshotEC2Fake) CreateVpcEndpoint(_ context.Context, input *ec2.CreateVpcEndpointInput, _ ...func(*ec2.Options)) (*ec2.CreateVpcEndpointOutput, error) {
	fake.endpointCreateCalls++
	fake.endpointInput = input
	tags := []ec2types.Tag(nil)
	if len(input.TagSpecifications) == 1 {
		tags = append(tags, input.TagSpecifications[0].Tags...)
	}
	fake.endpoint = &ec2types.VpcEndpoint{
		VpcEndpointId: aws.String(fake.endpointID), VpcId: input.VpcId, ServiceName: input.ServiceName,
		VpcEndpointType: input.VpcEndpointType, State: ec2types.StateAvailable, SubnetIds: append([]string(nil), input.SubnetIds...),
		Groups:            []ec2types.SecurityGroupIdentifier{{GroupId: aws.String(input.SecurityGroupIds[0])}},
		PrivateDnsEnabled: input.PrivateDnsEnabled, IpAddressType: input.IpAddressType, Tags: tags,
	}
	if fake.endpointCreateError != nil {
		err := fake.endpointCreateError
		fake.endpointCreateError = nil
		return nil, err
	}
	return &ec2.CreateVpcEndpointOutput{ClientToken: input.ClientToken, VpcEndpoint: fake.endpoint}, nil
}

func (fake *endpointSnapshotEC2Fake) DescribeVpcEndpoints(_ context.Context, input *ec2.DescribeVpcEndpointsInput, _ ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error) {
	if fake.endpoint == nil {
		return &ec2.DescribeVpcEndpointsOutput{}, nil
	}
	if len(input.VpcEndpointIds) > 0 && (len(input.VpcEndpointIds) != 1 || input.VpcEndpointIds[0] != fake.endpointID) {
		return &ec2.DescribeVpcEndpointsOutput{}, nil
	}
	if len(input.Filters) > 0 && !matchesFilters(fake.endpoint.Tags, input.Filters) {
		return &ec2.DescribeVpcEndpointsOutput{}, nil
	}
	return &ec2.DescribeVpcEndpointsOutput{VpcEndpoints: []ec2types.VpcEndpoint{*fake.endpoint}}, nil
}

func (fake *endpointSnapshotEC2Fake) DeleteVpcEndpoints(_ context.Context, _ *ec2.DeleteVpcEndpointsInput, _ ...func(*ec2.Options)) (*ec2.DeleteVpcEndpointsOutput, error) {
	fake.endpoint.State = ec2types.StateDeleted
	return &ec2.DeleteVpcEndpointsOutput{}, nil
}

func (fake *endpointSnapshotEC2Fake) CreateSnapshot(_ context.Context, input *ec2.CreateSnapshotInput, _ ...func(*ec2.Options)) (*ec2.CreateSnapshotOutput, error) {
	fake.snapshotCreateCalls++
	fake.snapshotInput = input
	tags := []ec2types.Tag(nil)
	if len(input.TagSpecifications) == 1 {
		tags = append(tags, input.TagSpecifications[0].Tags...)
	}
	fake.snapshot = &ec2types.Snapshot{
		SnapshotId: aws.String(fake.snapshotID), VolumeId: input.VolumeId, Description: input.Description,
		Encrypted: aws.Bool(true), State: ec2types.SnapshotStateCompleted, Tags: tags,
	}
	if fake.snapshotCreateError != nil {
		err := fake.snapshotCreateError
		fake.snapshotCreateError = nil
		return nil, err
	}
	return &ec2.CreateSnapshotOutput{SnapshotId: fake.snapshot.SnapshotId, VolumeId: input.VolumeId, Description: input.Description, Encrypted: aws.Bool(true), State: ec2types.SnapshotStateCompleted, Tags: tags}, nil
}

func (fake *endpointSnapshotEC2Fake) DescribeSnapshots(_ context.Context, input *ec2.DescribeSnapshotsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	if fake.snapshot == nil {
		return &ec2.DescribeSnapshotsOutput{}, nil
	}
	if len(input.SnapshotIds) > 0 && (len(input.SnapshotIds) != 1 || input.SnapshotIds[0] != fake.snapshotID) {
		return &ec2.DescribeSnapshotsOutput{}, nil
	}
	if len(input.Filters) > 0 && !matchesFilters(fake.snapshot.Tags, input.Filters) {
		return &ec2.DescribeSnapshotsOutput{}, nil
	}
	return &ec2.DescribeSnapshotsOutput{Snapshots: []ec2types.Snapshot{*fake.snapshot}}, nil
}

func (fake *endpointSnapshotEC2Fake) DeleteSnapshot(_ context.Context, _ *ec2.DeleteSnapshotInput, _ ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error) {
	fake.snapshot = nil
	return &ec2.DeleteSnapshotOutput{}, nil
}

func (fake *endpointSnapshotEC2Fake) AuthorizeSecurityGroupIngress(context.Context, *ec2.AuthorizeSecurityGroupIngressInput, ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupIngressOutput, error) {
	fake.authorizeIngressCalls++
	return &ec2.AuthorizeSecurityGroupIngressOutput{}, nil
}

func (fake *endpointSnapshotEC2Fake) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{}, nil
}

func (fake *endpointSnapshotEC2Fake) DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	return &ec2.DescribeVolumesOutput{}, nil
}

func (fake *endpointSnapshotEC2Fake) DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return &ec2.DescribeNetworkInterfacesOutput{}, nil
}

func (fake *endpointSnapshotEC2Fake) DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	return &ec2.DescribeAddressesOutput{}, nil
}

func (fake *endpointSnapshotEC2Fake) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{}, nil
}
