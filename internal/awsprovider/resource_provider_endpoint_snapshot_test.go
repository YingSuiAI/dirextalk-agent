package awsprovider

import (
	"context"
	"errors"
	"slices"
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

func TestEC2ResourceProviderCreatesExactNoNATEndpointTypesAndRejectsDrift(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	t.Run("Secrets Manager Interface", func(t *testing.T) {
		client := &endpointSnapshotEC2Fake{endpointID: "vpce-0123456789abcdef0"}
		provider, err := NewEC2ResourceProvider(client, "us-east-1", func() time.Time { return now }, WithEC2ResourcePollInterval(time.Nanosecond))
		if err != nil {
			t.Fatal(err)
		}
		spec := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, Endpoint: &resource.AWSVPCEndpointSpecV1{
			VPCID: "vpc-0123456789abcdef0", ServiceName: "com.amazonaws.us-east-1.secretsmanager",
			EndpointType: resource.AWSVPCEndpointTypeInterface, SubnetID: "subnet-0123456789abcdef0", PrivateDNSEnabled: true,
		}}
		request := endpointSnapshotRequest(t, resource.TypeEndpoint, "11111111-1111-4111-8111-111111111111", "dtx-secrets-0123456789", spec,
			[]resource.ProviderDependency{{ResourceID: "22222222-2222-4222-8222-222222222222", Type: resource.TypeSG, ProviderID: "sg-0123456789abcdef0"}})
		if _, err := provider.Create(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		input := client.endpointInput
		if input.VpcEndpointType != ec2types.VpcEndpointTypeInterface || !aws.ToBool(input.PrivateDnsEnabled) ||
			!slices.Equal(input.SubnetIds, []string{spec.Endpoint.SubnetID}) || !slices.Equal(input.SecurityGroupIds, []string{request.Dependencies[0].ProviderID}) ||
			len(input.RouteTableIds) != 0 || input.PolicyDocument != nil {
			t.Fatalf("Interface endpoint input = %#v", input)
		}
		client.endpoint.SubnetIds = []string{"subnet-0bbbbbbbbbbbbbbbb"}
		if _, err := provider.VerifyCreateReadBack(context.Background(), request, client.endpointID); !errors.Is(err, resource.ErrReadBack) {
			t.Fatalf("drift error = %v, want ErrReadBack", err)
		}
	})

	t.Run("S3 Gateway", func(t *testing.T) {
		client := &endpointSnapshotEC2Fake{endpointID: "vpce-0fedcba9876543210"}
		provider, err := NewEC2ResourceProvider(client, "us-east-1", func() time.Time { return now }, WithEC2ResourcePollInterval(time.Nanosecond))
		if err != nil {
			t.Fatal(err)
		}
		spec := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, Endpoint: &resource.AWSVPCEndpointSpecV1{
			VPCID: "vpc-0123456789abcdef0", ServiceName: "com.amazonaws.us-east-1.s3",
			EndpointType: resource.AWSVPCEndpointTypeGateway, RouteTableIDs: []string{"rtb-0123456789abcdef0"},
		}}
		request := endpointSnapshotRequest(t, resource.TypeEndpoint, "33333333-3333-4333-8333-333333333333", "dtx-gateway-0123456789", spec, nil)
		observation, err := provider.Create(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		input := client.endpointInput
		if input.VpcEndpointType != ec2types.VpcEndpointTypeGateway || !slices.Equal(input.RouteTableIds, spec.Endpoint.RouteTableIDs) ||
			len(input.SubnetIds) != 0 || len(input.SecurityGroupIds) != 0 || input.PrivateDnsEnabled != nil || input.PolicyDocument != nil {
			t.Fatalf("Gateway endpoint input = %#v", input)
		}
		recovered, err := provider.Create(context.Background(), request)
		if err != nil || recovered.ProviderID != observation.ProviderID || client.endpointCreateCalls != 1 {
			t.Fatalf("Gateway token recovery = %#v error=%v create_calls=%d", recovered, err, client.endpointCreateCalls)
		}
		client.omitLocalRoute = true
		if _, err := provider.VerifyCreateReadBack(context.Background(), request, client.endpointID); !errors.Is(err, resource.ErrReadBack) {
			t.Fatalf("missing local route error = %v, want ErrReadBack", err)
		}
		client.omitLocalRoute = false
		if err := provider.Delete(context.Background(), resource.TypeEndpoint, observation.ProviderID, "us-east-1", observation.Tags); err != nil {
			t.Fatal(err)
		}
	})
}

func TestEC2ResourceProviderPreservesLegacyMultiSubnetS3InterfaceEndpoint(t *testing.T) {
	client := &endpointSnapshotEC2Fake{endpointID: "vpce-0123456789abcdef0"}
	provider, err := NewEC2ResourceProvider(client, "us-east-1", func() time.Time {
		return time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	}, WithEC2ResourcePollInterval(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	spec := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, Endpoint: &resource.AWSVPCEndpointSpecV1{
		VPCID: "vpc-0123456789abcdef0", ServiceName: "com.amazonaws.us-east-1.s3",
		SubnetIDs: []string{"subnet-0123456789abcdef0", "subnet-0fedcba9876543210"}, PrivateDNSEnabled: true,
	}}
	request := endpointSnapshotRequest(t, resource.TypeEndpoint, "11111111-1111-4111-8111-111111111111", "dtx-legacy-0123456789", spec,
		[]resource.ProviderDependency{{ResourceID: "22222222-2222-4222-8222-222222222222", Type: resource.TypeSG, ProviderID: "sg-0123456789abcdef0"}})
	if _, err := provider.Create(context.Background(), request); err != nil {
		t.Fatalf("legacy multi-subnet S3 Interface endpoint: %v", err)
	}
	if !slices.Equal(client.endpointInput.SubnetIds, spec.Endpoint.SubnetIDs) {
		t.Fatalf("legacy subnets = %v, want %v", client.endpointInput.SubnetIds, spec.Endpoint.SubnetIDs)
	}
}

func TestEC2ResourceProviderRejectsConflictingUntaggedPrivateEndpoint(t *testing.T) {
	base := &endpointSnapshotEC2Fake{endpointID: "vpce-0123456789abcdef0"}
	base.endpoint = &ec2types.VpcEndpoint{
		VpcEndpointId: aws.String(base.endpointID), VpcId: aws.String("vpc-0123456789abcdef0"),
		ServiceName: aws.String("com.amazonaws.us-east-1.secretsmanager"), VpcEndpointType: ec2types.VpcEndpointTypeInterface,
		State: ec2types.StateAvailable,
	}
	client := &endpointConflictEC2Fake{endpointSnapshotEC2Fake: base}
	provider, err := NewEC2ResourceProvider(client, "us-east-1", func() time.Time {
		return time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	}, WithEC2ResourcePollInterval(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	spec := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, Endpoint: &resource.AWSVPCEndpointSpecV1{
		VPCID: "vpc-0123456789abcdef0", ServiceName: "com.amazonaws.us-east-1.secretsmanager",
		EndpointType: resource.AWSVPCEndpointTypeInterface, SubnetID: "subnet-0123456789abcdef0", PrivateDNSEnabled: true,
	}}
	request := endpointSnapshotRequest(t, resource.TypeEndpoint, "11111111-1111-4111-8111-111111111111", "dtx-conflict-01234567", spec,
		[]resource.ProviderDependency{{ResourceID: "22222222-2222-4222-8222-222222222222", Type: resource.TypeSG, ProviderID: "sg-0123456789abcdef0"}})
	if _, err := provider.Create(context.Background(), request); !errors.Is(err, resource.ErrAlreadyExists) {
		t.Fatalf("conflict error = %v, want ErrAlreadyExists", err)
	}
	if base.endpointCreateCalls != 0 {
		t.Fatalf("conflicting endpoint triggered %d create calls", base.endpointCreateCalls)
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
	omitLocalRoute                           bool
}

type endpointConflictEC2Fake struct {
	*endpointSnapshotEC2Fake
}

func (fake *endpointConflictEC2Fake) DescribeVpcEndpoints(_ context.Context, input *ec2.DescribeVpcEndpointsInput, _ ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error) {
	if fake.endpoint == nil {
		return &ec2.DescribeVpcEndpointsOutput{}, nil
	}
	for _, filter := range input.Filters {
		name := aws.ToString(filter.Name)
		if len(filter.Values) != 1 {
			return &ec2.DescribeVpcEndpointsOutput{}, nil
		}
		switch name {
		case "vpc-id":
			if filter.Values[0] != aws.ToString(fake.endpoint.VpcId) {
				return &ec2.DescribeVpcEndpointsOutput{}, nil
			}
		case "service-name":
			if filter.Values[0] != aws.ToString(fake.endpoint.ServiceName) {
				return &ec2.DescribeVpcEndpointsOutput{}, nil
			}
		default:
			return &ec2.DescribeVpcEndpointsOutput{}, nil
		}
	}
	return &ec2.DescribeVpcEndpointsOutput{VpcEndpoints: []ec2types.VpcEndpoint{*fake.endpoint}}, nil
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
		RouteTableIds:     append([]string(nil), input.RouteTableIds...),
		PrivateDnsEnabled: input.PrivateDnsEnabled, IpAddressType: input.IpAddressType, Tags: tags,
	}
	if len(input.SecurityGroupIds) == 1 {
		fake.endpoint.Groups = []ec2types.SecurityGroupIdentifier{{GroupId: aws.String(input.SecurityGroupIds[0])}}
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

func (fake *endpointSnapshotEC2Fake) DescribeSecurityGroups(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if len(input.GroupIds) != 1 {
		return &ec2.DescribeSecurityGroupsOutput{}, nil
	}
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []ec2types.SecurityGroup{{
		GroupId: aws.String(input.GroupIds[0]), VpcId: aws.String("vpc-0123456789abcdef0"),
	}}}, nil
}

func (fake *endpointSnapshotEC2Fake) DescribeSubnets(_ context.Context, input *ec2.DescribeSubnetsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	if len(input.SubnetIds) == 0 {
		return &ec2.DescribeSubnetsOutput{}, nil
	}
	result := make([]ec2types.Subnet, 0, len(input.SubnetIds))
	for _, subnetID := range input.SubnetIds {
		result = append(result, ec2types.Subnet{
			SubnetId: aws.String(subnetID), VpcId: aws.String("vpc-0123456789abcdef0"), State: ec2types.SubnetStateAvailable,
		})
	}
	return &ec2.DescribeSubnetsOutput{Subnets: result}, nil
}

func (fake *endpointSnapshotEC2Fake) DescribeRouteTables(_ context.Context, input *ec2.DescribeRouteTablesInput, _ ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	if len(input.RouteTableIds) != 1 {
		return &ec2.DescribeRouteTablesOutput{}, nil
	}
	var routes []ec2types.Route
	if !fake.omitLocalRoute {
		routes = append(routes, ec2types.Route{DestinationCidrBlock: aws.String("10.0.0.0/16"), GatewayId: aws.String("local"), State: ec2types.RouteStateActive})
	}
	if fake.endpoint != nil && fake.endpoint.VpcEndpointType == ec2types.VpcEndpointTypeGateway && fake.endpoint.State != ec2types.StateDeleted {
		routes = append(routes, ec2types.Route{DestinationPrefixListId: aws.String("pl-0123456789abcdef0"), GatewayId: fake.endpoint.VpcEndpointId, State: ec2types.RouteStateActive})
	}
	return &ec2.DescribeRouteTablesOutput{RouteTables: []ec2types.RouteTable{{
		RouteTableId: aws.String(input.RouteTableIds[0]), VpcId: aws.String("vpc-0123456789abcdef0"), Routes: routes,
	}}}, nil
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
