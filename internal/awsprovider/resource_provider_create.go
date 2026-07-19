package awsprovider

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func (provider *EC2ResourceProvider) createSecurityGroup(ctx context.Context, request resource.ProviderCreateRequest) (resource.ProviderObservation, error) {
	spec := request.AWS.SecurityGroup
	name := deterministicResourceName(request.LogicalName, request.ResourceID)
	output, err := provider.client.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
		GroupName: aws.String(name), Description: aws.String(spec.Description), VpcId: aws.String(spec.VPCID),
		TagSpecifications: []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeSecurityGroup, Tags: ec2Tags(provider.creationTags(request))}},
	})
	groupID := ""
	if err == nil && output != nil {
		groupID = aws.ToString(output.GroupId)
	} else if apiCode(err, "InvalidGroup.Duplicate") {
		groups, describeErr := provider.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{Filters: []ec2types.Filter{
			{Name: aws.String("group-name"), Values: []string{name}}, {Name: aws.String("vpc-id"), Values: []string{spec.VPCID}},
		}})
		if describeErr != nil {
			return resource.ProviderObservation{}, providerError(ctx, describeErr)
		}
		if groups == nil || len(groups.SecurityGroups) != 1 {
			return resource.ProviderObservation{}, resource.ErrReadBack
		}
		groupID = aws.ToString(groups.SecurityGroups[0].GroupId)
		if !containsTags(tagsFromEC2(groups.SecurityGroups[0].Tags), provider.creationTags(request)) {
			return resource.ProviderObservation{}, resource.ErrReadBack
		}
	} else {
		return resource.ProviderObservation{}, providerError(ctx, err)
	}
	if groupID == "" {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	if err := provider.replaceSecurityGroupRules(ctx, groupID, spec); err != nil {
		return resource.ProviderObservation{}, err
	}
	if err := provider.markReady(ctx, groupID, request); err != nil {
		return resource.ProviderObservation{}, err
	}
	return provider.readBack(ctx, resource.TypeSG, groupID)
}

func (provider *EC2ResourceProvider) replaceSecurityGroupRules(ctx context.Context, groupID string, spec *resource.AWSSecurityGroupSpecV1) error {
	current, err := provider.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: []string{groupID}})
	if err != nil {
		return providerError(ctx, err)
	}
	if current == nil || len(current.SecurityGroups) != 1 {
		return resource.ErrReadBack
	}
	group := current.SecurityGroups[0]
	if len(group.IpPermissions) > 0 {
		_, err = provider.client.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{GroupId: aws.String(groupID), IpPermissions: group.IpPermissions})
		if err != nil && !apiCode(err, "InvalidPermission.NotFound") {
			return providerError(ctx, err)
		}
	}
	if len(group.IpPermissionsEgress) > 0 {
		_, err = provider.client.RevokeSecurityGroupEgress(ctx, &ec2.RevokeSecurityGroupEgressInput{GroupId: aws.String(groupID), IpPermissions: group.IpPermissionsEgress})
		if err != nil && !apiCode(err, "InvalidPermission.NotFound") {
			return providerError(ctx, err)
		}
	}
	if desired := networkPermissions(spec.Ingress); len(desired) > 0 {
		if _, err := provider.client.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{GroupId: aws.String(groupID), IpPermissions: desired}); err != nil {
			return providerError(ctx, err)
		}
	}
	if desired := networkPermissions(spec.Egress); len(desired) > 0 {
		if _, err := provider.client.AuthorizeSecurityGroupEgress(ctx, &ec2.AuthorizeSecurityGroupEgressInput{GroupId: aws.String(groupID), IpPermissions: desired}); err != nil {
			return providerError(ctx, err)
		}
	}
	verified, err := provider.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: []string{groupID}})
	if err != nil {
		return providerError(ctx, err)
	}
	if verified == nil || len(verified.SecurityGroups) != 1 || permissionDigest(verified.SecurityGroups[0].IpPermissions) != permissionDigest(networkPermissions(spec.Ingress)) || permissionDigest(verified.SecurityGroups[0].IpPermissionsEgress) != permissionDigest(networkPermissions(spec.Egress)) {
		return resource.ErrReadBack
	}
	return nil
}

func networkPermissions(rules []resource.AWSNetworkRuleV1) []ec2types.IpPermission {
	permissions := make([]ec2types.IpPermission, 0, len(rules))
	for _, rule := range rules {
		permissions = append(permissions, ec2types.IpPermission{
			IpProtocol: aws.String(rule.Protocol), FromPort: aws.Int32(int32(rule.FromPort)), ToPort: aws.Int32(int32(rule.ToPort)),
			IpRanges: []ec2types.IpRange{{CidrIp: aws.String(rule.CIDRv4)}},
		})
	}
	return permissions
}

func permissionDigest(permissions []ec2types.IpPermission) string {
	values := make([]string, 0)
	for _, permission := range permissions {
		for _, cidr := range permission.IpRanges {
			values = append(values, fmt.Sprintf("%s:%d:%d:%s", aws.ToString(permission.IpProtocol), aws.ToInt32(permission.FromPort), aws.ToInt32(permission.ToPort), aws.ToString(cidr.CidrIp)))
		}
		// Any IPv6, prefix-list, or group-based rule is outside the closed spec.
		if len(permission.Ipv6Ranges)+len(permission.PrefixListIds)+len(permission.UserIdGroupPairs) > 0 {
			values = append(values, "unsupported")
		}
	}
	sort.Strings(values)
	return fmt.Sprintf("%q", values)
}

func (provider *EC2ResourceProvider) createVolume(ctx context.Context, request resource.ProviderCreateRequest) (resource.ProviderObservation, error) {
	spec := request.AWS.Volume
	snapshotID := ""
	snapshotKMSKeyID := ""
	if spec.SourceSnapshotResourceID != "" {
		snapshotID = dependencyIDByResource(request.Dependencies, spec.SourceSnapshotResourceID, resource.TypeSnapshot)
		snapshot, err := provider.snapshot(ctx, snapshotID)
		if err != nil {
			return resource.ProviderObservation{}, err
		}
		snapshotKMSKeyID = aws.ToString(snapshot.KmsKeyId)
		if snapshot.State != ec2types.SnapshotStateCompleted || !aws.ToBool(snapshot.Encrypted) ||
			aws.ToInt32(snapshot.VolumeSize) != int32(spec.SizeGiB) ||
			!kmsReadBackMatches(spec.KMSKeyID, snapshotKMSKeyID) {
			return resource.ProviderObservation{}, resource.ErrReadBack
		}
	}
	output, err := provider.client.CreateVolume(ctx, &ec2.CreateVolumeInput{
		AvailabilityZone: aws.String(spec.AvailabilityZone), ClientToken: aws.String(request.ClientToken), Encrypted: aws.Bool(true),
		Iops: aws.Int32(int32(spec.IOPS)), KmsKeyId: aws.String(spec.KMSKeyID), Size: aws.Int32(int32(spec.SizeGiB)),
		SnapshotId: optionalToken(snapshotID), Throughput: aws.Int32(int32(spec.ThroughputMiBPS)), VolumeType: ec2types.VolumeTypeGp3,
		TagSpecifications: []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeVolume, Tags: ec2Tags(provider.creationTags(request))}},
	})
	if err != nil {
		return resource.ProviderObservation{}, providerError(ctx, err)
	}
	volumeID := ""
	if output != nil {
		volumeID = aws.ToString(output.VolumeId)
	}
	if volumeID == "" {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	if err := provider.wait(ctx, func(ctx context.Context) (bool, error) {
		volume, err := provider.volume(ctx, volumeID)
		if err != nil {
			return false, err
		}
		if volume.State == ec2types.VolumeStateError || volume.State == ec2types.VolumeStateDeleted {
			return false, resource.ErrReadBack
		}
		return volume.State == ec2types.VolumeStateAvailable, nil
	}); err != nil {
		return resource.ProviderObservation{}, err
	}
	volume, err := provider.volume(ctx, volumeID)
	if err != nil {
		return resource.ProviderObservation{}, err
	}
	if !aws.ToBool(volume.Encrypted) || aws.ToInt32(volume.Size) != int32(spec.SizeGiB) || volume.VolumeType != ec2types.VolumeTypeGp3 || aws.ToString(volume.AvailabilityZone) != spec.AvailabilityZone || aws.ToInt32(volume.Iops) != int32(spec.IOPS) || aws.ToInt32(volume.Throughput) != int32(spec.ThroughputMiBPS) || !kmsReadBackMatches(spec.KMSKeyID, aws.ToString(volume.KmsKeyId)) {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	if snapshotKMSKeyID != "" && aws.ToString(volume.KmsKeyId) != snapshotKMSKeyID {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	if err := provider.markReady(ctx, volumeID, request); err != nil {
		return resource.ProviderObservation{}, err
	}
	return provider.readBack(ctx, resource.TypeEBS, volumeID)
}

func (provider *EC2ResourceProvider) createNetworkInterface(ctx context.Context, request resource.ProviderCreateRequest) (resource.ProviderObservation, error) {
	spec := request.AWS.NetworkInterface
	securityGroupID := spec.ExistingSecurityGroupID
	if securityGroupID == "" {
		securityGroupID = dependencyID(request.Dependencies, resource.TypeSG)
	}
	output, err := provider.client.CreateNetworkInterface(ctx, &ec2.CreateNetworkInterfaceInput{
		SubnetId: aws.String(spec.SubnetID), Description: aws.String(spec.Description), ClientToken: aws.String(request.ClientToken),
		Groups:            []string{securityGroupID},
		TagSpecifications: []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeNetworkInterface, Tags: ec2Tags(provider.creationTags(request))}},
	})
	if err != nil {
		return resource.ProviderObservation{}, providerError(ctx, err)
	}
	interfaceID := ""
	if output != nil && output.NetworkInterface != nil {
		interfaceID = aws.ToString(output.NetworkInterface.NetworkInterfaceId)
	}
	if interfaceID == "" {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	if err := provider.wait(ctx, func(ctx context.Context) (bool, error) {
		value, err := provider.networkInterface(ctx, interfaceID)
		if err != nil {
			return false, err
		}
		return value.Status == ec2types.NetworkInterfaceStatusAvailable, nil
	}); err != nil {
		return resource.ProviderObservation{}, err
	}
	networkInterface, err := provider.networkInterface(ctx, interfaceID)
	if err != nil {
		return resource.ProviderObservation{}, err
	}
	if aws.ToString(networkInterface.SubnetId) != spec.SubnetID || len(networkInterface.Groups) != 1 || aws.ToString(networkInterface.Groups[0].GroupId) != securityGroupID {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	if err := provider.markReady(ctx, interfaceID, request); err != nil {
		return resource.ProviderObservation{}, err
	}
	return provider.readBack(ctx, resource.TypeENI, interfaceID)
}

func (provider *EC2ResourceProvider) createElasticIP(ctx context.Context, request resource.ProviderCreateRequest) (resource.ProviderObservation, error) {
	interfaceID := dependencyID(request.Dependencies, resource.TypeENI)
	filters := []ec2types.Filter{{Name: aws.String("tag:" + resourceClientTokenTag), Values: []string{request.ClientToken}}}
	addresses, err := provider.addressesByFilters(ctx, filters)
	if err != nil {
		return resource.ProviderObservation{}, err
	}
	if len(addresses) == 0 {
		output, allocateErr := provider.client.AllocateAddress(ctx, &ec2.AllocateAddressInput{
			Domain:            ec2types.DomainTypeVpc,
			TagSpecifications: []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeElasticIp, Tags: ec2Tags(provider.readyTags(request))}},
		})
		if allocateErr == nil && output != nil && aws.ToString(output.AllocationId) != "" {
			address, readErr := provider.address(ctx, aws.ToString(output.AllocationId))
			if readErr != nil {
				return resource.ProviderObservation{}, readErr
			}
			addresses = []ec2types.Address{address}
		} else {
			addresses, err = provider.addressesByFilters(ctx, filters)
			if err != nil {
				return resource.ProviderObservation{}, err
			}
			if len(addresses) == 0 {
				return resource.ProviderObservation{}, providerError(ctx, allocateErr)
			}
		}
	}
	if len(addresses) != 1 {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	address := addresses[0]
	allocationID := aws.ToString(address.AllocationId)
	if allocationID == "" || address.Domain != ec2types.DomainTypeVpc || !containsTags(tagsFromEC2(address.Tags), provider.readyTags(request)) {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	if associatedInterfaceID := aws.ToString(address.NetworkInterfaceId); associatedInterfaceID != "" && associatedInterfaceID != interfaceID {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	if aws.ToString(address.AssociationId) == "" {
		if _, err := provider.client.AssociateAddress(ctx, &ec2.AssociateAddressInput{
			AllocationId: aws.String(allocationID), NetworkInterfaceId: aws.String(interfaceID), AllowReassociation: aws.Bool(false),
		}); err != nil {
			return resource.ProviderObservation{}, providerError(ctx, err)
		}
		address, err = provider.address(ctx, allocationID)
		if err != nil {
			return resource.ProviderObservation{}, err
		}
	}
	if aws.ToString(address.AssociationId) == "" || aws.ToString(address.NetworkInterfaceId) != interfaceID {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	return provider.readBack(ctx, resource.TypeEIP, allocationID)
}

func (provider *EC2ResourceProvider) createVpcEndpoint(ctx context.Context, request resource.ProviderCreateRequest) (resource.ProviderObservation, error) {
	spec := request.AWS.Endpoint
	expectedServiceName := "com.amazonaws." + provider.region + ".s3"
	if spec.EffectiveEndpointType() == resource.AWSVPCEndpointTypeInterface {
		expectedServiceName = "com.amazonaws." + provider.region + ".secretsmanager"
		if spec.EndpointType == "" {
			expectedServiceName = spec.ServiceName
		}
		if strings.HasPrefix(spec.ServiceName, "com.amazonaws.vpce.") {
			expectedServiceName = spec.ServiceName
		}
	}
	if spec.ServiceName != expectedServiceName {
		return resource.ProviderObservation{}, resource.ErrInvalid
	}
	securityGroupID := ""
	if spec.EffectiveEndpointType() == resource.AWSVPCEndpointTypeInterface {
		securityGroupID = spec.ExistingSecurityGroupID
		if securityGroupID == "" {
			securityGroupID = dependencyID(request.Dependencies, resource.TypeSG)
		}
	}
	filters := []ec2types.Filter{{Name: aws.String("tag:" + resourceClientTokenTag), Values: []string{request.ClientToken}}}
	values, err := provider.vpcEndpointsByFilters(ctx, filters)
	if err != nil {
		return resource.ProviderObservation{}, err
	}
	if len(values) == 0 {
		if err := provider.validateVpcEndpointInputs(ctx, spec, securityGroupID); err != nil {
			return resource.ProviderObservation{}, err
		}
		conflicts, conflictErr := provider.vpcEndpointsByFilters(ctx, []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{spec.VPCID}},
			{Name: aws.String("service-name"), Values: []string{spec.ServiceName}},
		})
		if conflictErr != nil {
			return resource.ProviderObservation{}, conflictErr
		}
		if len(conflicts) != 0 {
			return resource.ProviderObservation{}, resource.ErrAlreadyExists
		}
		input := &ec2.CreateVpcEndpointInput{
			VpcId: aws.String(spec.VPCID), ServiceName: aws.String(spec.ServiceName), ClientToken: aws.String(request.ClientToken),
			TagSpecifications: []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeVpcEndpoint, Tags: ec2Tags(provider.readyTags(request))}},
		}
		switch spec.EffectiveEndpointType() {
		case resource.AWSVPCEndpointTypeGateway:
			input.VpcEndpointType = ec2types.VpcEndpointTypeGateway
			input.RouteTableIds = append([]string(nil), spec.RouteTableIDs...)
		case resource.AWSVPCEndpointTypeInterface:
			input.VpcEndpointType = ec2types.VpcEndpointTypeInterface
			input.IpAddressType = ec2types.IpAddressTypeIpv4
			input.SubnetIds = spec.EffectiveSubnetIDs()
			input.SecurityGroupIds = []string{securityGroupID}
			input.PrivateDnsEnabled = aws.Bool(spec.PrivateDNSEnabled)
		default:
			return resource.ProviderObservation{}, resource.ErrInvalid
		}
		output, createErr := provider.client.CreateVpcEndpoint(ctx, input)
		if createErr == nil && output != nil && output.VpcEndpoint != nil && aws.ToString(output.VpcEndpoint.VpcEndpointId) != "" {
			values = []ec2types.VpcEndpoint{*output.VpcEndpoint}
		} else {
			values, err = provider.vpcEndpointsByFilters(ctx, filters)
			if err != nil {
				return resource.ProviderObservation{}, err
			}
			if len(values) == 0 {
				return resource.ProviderObservation{}, providerError(ctx, createErr)
			}
		}
	}
	if len(values) != 1 || aws.ToString(values[0].VpcEndpointId) == "" {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	endpointID := aws.ToString(values[0].VpcEndpointId)
	if err := provider.waitReady(ctx, resource.TypeEndpoint, endpointID); err != nil {
		return resource.ProviderObservation{}, err
	}
	value, err := provider.vpcEndpoint(ctx, endpointID)
	if err != nil {
		return resource.ProviderObservation{}, err
	}
	if !provider.vpcEndpointMatches(value, spec, securityGroupID, provider.readyTags(request)) {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	if spec.EffectiveEndpointType() == resource.AWSVPCEndpointTypeGateway {
		if err := provider.validateGatewayEndpointRoute(ctx, spec.RouteTableIDs[0], endpointID, true); err != nil {
			return resource.ProviderObservation{}, err
		}
	}
	return provider.readBack(ctx, resource.TypeEndpoint, endpointID)
}

func (provider *EC2ResourceProvider) validateVpcEndpointInputs(ctx context.Context, spec *resource.AWSVPCEndpointSpecV1, securityGroupID string) error {
	switch spec.EffectiveEndpointType() {
	case resource.AWSVPCEndpointTypeGateway:
		output, err := provider.client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{RouteTableIds: append([]string(nil), spec.RouteTableIDs...)})
		if err != nil {
			return providerError(ctx, err)
		}
		if output == nil || len(output.RouteTables) != 1 || aws.ToString(output.RouteTables[0].RouteTableId) != spec.RouteTableIDs[0] || aws.ToString(output.RouteTables[0].VpcId) != spec.VPCID ||
			!routeTableHasOnlyLocalIPv4(output.RouteTables[0]) {
			return resource.ErrReadBack
		}
	case resource.AWSVPCEndpointTypeInterface:
		expectedSubnetIDs := spec.EffectiveSubnetIDs()
		subnets, err := provider.client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{SubnetIds: expectedSubnetIDs})
		if err != nil {
			return providerError(ctx, err)
		}
		groups, groupErr := provider.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: []string{securityGroupID}})
		if groupErr != nil {
			return providerError(ctx, groupErr)
		}
		if subnets == nil || len(subnets.Subnets) != len(expectedSubnetIDs) ||
			groups == nil || len(groups.SecurityGroups) != 1 || aws.ToString(groups.SecurityGroups[0].GroupId) != securityGroupID || aws.ToString(groups.SecurityGroups[0].VpcId) != spec.VPCID {
			return resource.ErrReadBack
		}
		seenSubnets := make(map[string]struct{}, len(subnets.Subnets))
		for _, subnet := range subnets.Subnets {
			subnetID := aws.ToString(subnet.SubnetId)
			if !slices.Contains(expectedSubnetIDs, subnetID) || aws.ToString(subnet.VpcId) != spec.VPCID || subnet.State != ec2types.SubnetStateAvailable {
				return resource.ErrReadBack
			}
			seenSubnets[subnetID] = struct{}{}
		}
		if len(seenSubnets) != len(expectedSubnetIDs) {
			return resource.ErrReadBack
		}
	default:
		return resource.ErrInvalid
	}
	return nil
}

func (provider *EC2ResourceProvider) validateGatewayEndpointRoute(ctx context.Context, routeTableID, endpointID string, expected bool) error {
	output, err := provider.client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{RouteTableIds: []string{routeTableID}})
	if err != nil {
		return providerError(ctx, err)
	}
	if output == nil || len(output.RouteTables) != 1 || aws.ToString(output.RouteTables[0].RouteTableId) != routeTableID {
		return resource.ErrReadBack
	}
	matched := 0
	hasLocal := false
	for _, route := range output.RouteTables[0].Routes {
		if aws.ToString(route.GatewayId) == "local" {
			if !routeTableHasOnlyLocalIPv4(ec2types.RouteTable{Routes: []ec2types.Route{route}}) {
				return resource.ErrReadBack
			}
			hasLocal = true
			continue
		}
		if aws.ToString(route.GatewayId) == endpointID && aws.ToString(route.DestinationPrefixListId) != "" && route.State == ec2types.RouteStateActive &&
			route.DestinationCidrBlock == nil && route.DestinationIpv6CidrBlock == nil {
			matched++
			continue
		}
		return resource.ErrReadBack
	}
	if !hasLocal || (expected && matched != 1) || (!expected && matched != 0) {
		return resource.ErrReadBack
	}
	return nil
}

func (provider *EC2ResourceProvider) vpcEndpointMatches(value ec2types.VpcEndpoint, spec *resource.AWSVPCEndpointSpecV1, securityGroupID string, tags map[string]string) bool {
	if aws.ToString(value.VpcId) != spec.VPCID || aws.ToString(value.ServiceName) != spec.ServiceName || !containsTags(tagsFromEC2(value.Tags), tags) {
		return false
	}
	switch spec.EffectiveEndpointType() {
	case resource.AWSVPCEndpointTypeGateway:
		return value.VpcEndpointType == ec2types.VpcEndpointTypeGateway && sameStringSet(value.RouteTableIds, spec.RouteTableIDs) &&
			len(value.SubnetIds) == 0 && len(value.Groups) == 0 && !aws.ToBool(value.PrivateDnsEnabled)
	case resource.AWSVPCEndpointTypeInterface:
		return value.VpcEndpointType == ec2types.VpcEndpointTypeInterface && value.IpAddressType == ec2types.IpAddressTypeIpv4 &&
			aws.ToBool(value.PrivateDnsEnabled) == spec.PrivateDNSEnabled && sameStringSet(value.SubnetIds, spec.EffectiveSubnetIDs()) &&
			len(value.RouteTableIds) == 0 && len(value.Groups) == 1 && aws.ToString(value.Groups[0].GroupId) == securityGroupID
	default:
		return false
	}
}

func (provider *EC2ResourceProvider) createSnapshot(ctx context.Context, request resource.ProviderCreateRequest) (resource.ProviderObservation, error) {
	spec := request.AWS.Snapshot
	volumeID := dependencyID(request.Dependencies, resource.TypeEBS)
	filters := []ec2types.Filter{{Name: aws.String("tag:" + resourceClientTokenTag), Values: []string{request.ClientToken}}}
	values, err := provider.snapshotsByFilters(ctx, filters)
	if err != nil {
		return resource.ProviderObservation{}, err
	}
	if len(values) == 0 {
		output, createErr := provider.client.CreateSnapshot(ctx, &ec2.CreateSnapshotInput{
			VolumeId: aws.String(volumeID), Description: aws.String(spec.Description),
			TagSpecifications: []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeSnapshot, Tags: ec2Tags(provider.readyTags(request))}},
		})
		if createErr == nil && output != nil && aws.ToString(output.SnapshotId) != "" {
			value, readErr := provider.snapshot(ctx, aws.ToString(output.SnapshotId))
			if readErr != nil {
				return resource.ProviderObservation{}, readErr
			}
			values = []ec2types.Snapshot{value}
		} else {
			values, err = provider.snapshotsByFilters(ctx, filters)
			if err != nil {
				return resource.ProviderObservation{}, err
			}
			if len(values) == 0 {
				return resource.ProviderObservation{}, providerError(ctx, createErr)
			}
		}
	}
	if len(values) != 1 || aws.ToString(values[0].SnapshotId) == "" {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	snapshotID := aws.ToString(values[0].SnapshotId)
	if err := provider.waitReady(ctx, resource.TypeSnapshot, snapshotID); err != nil {
		return resource.ProviderObservation{}, err
	}
	value, err := provider.snapshot(ctx, snapshotID)
	if err != nil {
		return resource.ProviderObservation{}, err
	}
	if aws.ToString(value.VolumeId) != volumeID || aws.ToString(value.Description) != spec.Description || !aws.ToBool(value.Encrypted) ||
		!containsTags(tagsFromEC2(value.Tags), provider.readyTags(request)) {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	return provider.readBack(ctx, resource.TypeSnapshot, snapshotID)
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	values := make(map[string]int, len(left))
	for _, value := range left {
		values[value]++
	}
	for _, value := range right {
		if values[value] == 0 {
			return false
		}
		values[value]--
	}
	return true
}

func (provider *EC2ResourceProvider) createInstance(ctx context.Context, request resource.ProviderCreateRequest) (resource.ProviderObservation, error) {
	spec := request.AWS.Instance
	if err := provider.verifyApprovedWorkerAMI(ctx, request, spec); err != nil {
		return resource.ProviderObservation{}, err
	}
	userData, err := fixedWorkerUserData(request)
	if err != nil {
		return resource.ProviderObservation{}, err
	}
	rootRequest, err := embeddedRootCreateRequest(request, spec)
	if err != nil {
		return resource.ProviderObservation{}, err
	}
	input := &ec2.RunInstancesInput{
		MinCount: aws.Int32(1), MaxCount: aws.Int32(1), ClientToken: aws.String(request.ClientToken), ImageId: aws.String(spec.ImageID),
		InstanceType: ec2types.InstanceType(spec.InstanceType), EbsOptimized: aws.Bool(spec.EBSOptimized), UserData: aws.String(userData),
		IamInstanceProfile: &ec2types.IamInstanceProfileSpecification{Name: aws.String(spec.InstanceProfileName)},
		NetworkInterfaces:  []ec2types.InstanceNetworkInterfaceSpecification{{NetworkInterfaceId: aws.String(dependencyID(request.Dependencies, resource.TypeENI)), DeviceIndex: aws.Int32(0)}},
		MetadataOptions: &ec2types.InstanceMetadataOptionsRequest{
			HttpEndpoint: ec2types.InstanceMetadataEndpointStateEnabled, HttpTokens: ec2types.HttpTokensStateRequired,
			HttpPutResponseHopLimit: aws.Int32(1), InstanceMetadataTags: ec2types.InstanceMetadataTagsStateEnabled,
		},
		InstanceInitiatedShutdownBehavior: ec2types.ShutdownBehaviorTerminate, DisableApiTermination: aws.Bool(false), DisableApiStop: aws.Bool(false),
		BlockDeviceMappings: []ec2types.BlockDeviceMapping{{DeviceName: aws.String(spec.RootDeviceName), Ebs: &ec2types.EbsBlockDevice{
			DeleteOnTermination: aws.Bool(true), Encrypted: aws.Bool(true), KmsKeyId: aws.String(spec.RootKMSKeyID),
			VolumeSize: aws.Int32(int32(spec.RootVolumeGiB)), VolumeType: ec2types.VolumeTypeGp3,
		}}},
		TagSpecifications: []ec2types.TagSpecification{
			{ResourceType: ec2types.ResourceTypeInstance, Tags: ec2Tags(provider.creationTags(request))},
			{ResourceType: ec2types.ResourceTypeVolume, Tags: ec2Tags(provider.creationTags(rootRequest))},
		},
	}
	if spec.Market == resource.AWSMarketSpot {
		input.InstanceMarketOptions = &ec2types.InstanceMarketOptionsRequest{MarketType: ec2types.MarketTypeSpot, SpotOptions: &ec2types.SpotMarketOptions{
			SpotInstanceType: ec2types.SpotInstanceTypeOneTime, InstanceInterruptionBehavior: ec2types.InstanceInterruptionBehaviorTerminate,
		}}
	}
	output, err := provider.client.RunInstances(ctx, input)
	if err != nil {
		return resource.ProviderObservation{}, providerError(ctx, err)
	}
	instanceID := ""
	if output != nil && len(output.Instances) == 1 {
		instanceID = aws.ToString(output.Instances[0].InstanceId)
	}
	if instanceID == "" {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	if err := provider.wait(ctx, func(ctx context.Context) (bool, error) {
		instance, err := provider.instance(ctx, instanceID)
		if err != nil {
			return false, err
		}
		if instance.State == nil || instance.State.Name == ec2types.InstanceStateNameShuttingDown || instance.State.Name == ec2types.InstanceStateNameTerminated {
			return false, resource.ErrReadBack
		}
		return instance.State.Name == ec2types.InstanceStateNameRunning, nil
	}); err != nil {
		return resource.ProviderObservation{}, err
	}
	instance, err := provider.instance(ctx, instanceID)
	if err != nil {
		return resource.ProviderObservation{}, err
	}
	rootVolumeID, err := provider.verifyLaunchedInstance(ctx, instance, dependencyID(request.Dependencies, resource.TypeENI), spec)
	if err != nil {
		return resource.ProviderObservation{}, err
	}
	if len(spec.Bootstrap.InstallerArtifacts) != 0 {
		if provider.workerArtifacts == nil {
			return resource.ProviderObservation{}, resource.ErrReadBack
		}
		if err := provider.workerArtifacts.Bind(ctx, WorkerArtifactBindingRequest{
			InstanceID: instanceID, RoleName: spec.InstanceProfileName, DeploymentID: spec.Bootstrap.DeploymentID,
			Artifacts: append([]installerbootstrap.ArtifactSourceV1(nil), spec.Bootstrap.InstallerArtifacts...),
		}); err != nil {
			return resource.ProviderObservation{}, err
		}
	}
	if len(spec.Bootstrap.InstallerSecrets) != 0 {
		if provider.workerSecrets == nil {
			return resource.ProviderObservation{}, resource.ErrReadBack
		}
		if err := provider.workerSecrets.Bind(ctx, WorkerSecretBindingRequest{
			InstanceID: instanceID, RoleName: spec.InstanceProfileName, DeploymentID: spec.Bootstrap.DeploymentID,
			Secrets: append([]installerbootstrap.SecretSourceV1(nil), spec.Bootstrap.InstallerSecrets...),
		}); err != nil {
			return resource.ProviderObservation{}, err
		}
	}
	if len(spec.DataVolumes) != 0 {
		for _, attachment := range spec.DataVolumes {
			volumeID := dependencyIDByResource(request.Dependencies, attachment.ResourceID, resource.TypeEBS)
			if volumeID == "" {
				return resource.ProviderObservation{}, resource.ErrInvalid
			}
			if err := provider.ensureVolumeAttachment(ctx, volumeID, instanceID, attachment.DeviceName); err != nil {
				return resource.ProviderObservation{}, err
			}
		}
	} else if volumeID := dependencyID(request.Dependencies, resource.TypeEBS); volumeID != "" {
		if err := provider.ensureVolumeAttachment(ctx, volumeID, instanceID, spec.DataDeviceName); err != nil {
			return resource.ProviderObservation{}, err
		}
	}
	// The separately owned root volume is made discoverable first. Publishing
	// the parent ready tag last prevents reconciliation from exposing a parent
	// whose child cannot yet be recovered by client token and tags.
	if err := provider.markReady(ctx, rootVolumeID, rootRequest); err != nil {
		return resource.ProviderObservation{}, err
	}
	if err := provider.markReady(ctx, instanceID, request); err != nil {
		return resource.ProviderObservation{}, err
	}
	return provider.readBack(ctx, resource.TypeEC2, instanceID)
}

func (provider *EC2ResourceProvider) verifyApprovedWorkerAMI(ctx context.Context, request resource.ProviderCreateRequest, spec *resource.AWSEC2InstanceSpecV1) error {
	if provider == nil || provider.workerAMIReader == nil || !sdkAccountPattern.MatchString(provider.workerAMIAccount) || spec == nil {
		return resource.ErrReadBack
	}
	evidence, err := provider.workerAMIReader.InspectWorkerAMI(ctx, WorkerAMIInspectionRequest{
		AMIID: spec.ImageID, AccountID: provider.workerAMIAccount, Region: request.Region,
		Architecture: spec.Architecture, RootDeviceName: spec.RootDeviceName,
		AgentInstanceID: request.Tags[resource.TagAgentInstanceID],
	})
	if err != nil {
		return err
	}
	digest, err := evidence.ImageDigest()
	if err != nil || digest != spec.ImageDigest {
		return resource.ErrReadBack
	}
	return nil
}

func embeddedRootCreateRequest(parent resource.ProviderCreateRequest, spec *resource.AWSEC2InstanceSpecV1) (resource.ProviderCreateRequest, error) {
	resourceID, specDigest, err := resource.EmbeddedRootVolumeFacts(parent.ResourceID, spec)
	if err != nil {
		return resource.ProviderCreateRequest{}, err
	}
	tags := copyStringMap(parent.Tags)
	tags[resource.TagResourceID] = resourceID
	tags[resource.TagEmbeddedParentResourceID] = parent.ResourceID
	return resource.ProviderCreateRequest{
		ResourceID: resourceID, Type: resource.TypeEBS, LogicalName: "embedded-root-volume",
		Region: parent.Region, SpecDigest: specDigest, ClientToken: parent.ClientToken, Tags: tags,
	}, nil
}

func (provider *EC2ResourceProvider) verifyLaunchedInstance(ctx context.Context, instance ec2types.Instance, interfaceID string, spec *resource.AWSEC2InstanceSpecV1) (string, error) {
	if aws.ToString(instance.ImageId) != spec.ImageID || string(instance.InstanceType) != spec.InstanceType || aws.ToBool(instance.EbsOptimized) != spec.EBSOptimized || instance.IamInstanceProfile == nil || !strings.HasSuffix(aws.ToString(instance.IamInstanceProfile.Arn), "/"+spec.InstanceProfileName) {
		return "", resource.ErrReadBack
	}
	if (spec.Market == resource.AWSMarketSpot) != (instance.InstanceLifecycle == ec2types.InstanceLifecycleTypeSpot) {
		return "", resource.ErrReadBack
	}
	if instance.MetadataOptions == nil || instance.MetadataOptions.HttpEndpoint != ec2types.InstanceMetadataEndpointStateEnabled || instance.MetadataOptions.HttpTokens != ec2types.HttpTokensStateRequired || aws.ToInt32(instance.MetadataOptions.HttpPutResponseHopLimit) != 1 || instance.MetadataOptions.InstanceMetadataTags != ec2types.InstanceMetadataTagsStateEnabled || instance.MetadataOptions.State != ec2types.InstanceMetadataOptionsStateApplied {
		return "", resource.ErrReadBack
	}
	if len(instance.NetworkInterfaces) != 1 || aws.ToString(instance.NetworkInterfaces[0].NetworkInterfaceId) != interfaceID {
		return "", resource.ErrReadBack
	}
	rootVolumeID := ""
	for _, mapping := range instance.BlockDeviceMappings {
		if aws.ToString(mapping.DeviceName) == spec.RootDeviceName && mapping.Ebs != nil && aws.ToBool(mapping.Ebs.DeleteOnTermination) {
			rootVolumeID = aws.ToString(mapping.Ebs.VolumeId)
		}
	}
	if rootVolumeID == "" {
		return "", resource.ErrReadBack
	}
	root, err := provider.volume(ctx, rootVolumeID)
	if err != nil {
		return "", err
	}
	if !aws.ToBool(root.Encrypted) || aws.ToInt32(root.Size) != int32(spec.RootVolumeGiB) || root.VolumeType != ec2types.VolumeTypeGp3 || !kmsReadBackMatches(spec.RootKMSKeyID, aws.ToString(root.KmsKeyId)) {
		return "", resource.ErrReadBack
	}
	return rootVolumeID, nil
}

func kmsReadBackMatches(expected, actual string) bool {
	if actual == "" {
		return false
	}
	if strings.HasPrefix(expected, "arn:") {
		return actual == expected
	}
	return true
}

func (provider *EC2ResourceProvider) ensureVolumeAttachment(ctx context.Context, volumeID, instanceID, device string) error {
	if device == "" {
		return resource.ErrInvalid
	}
	volume, err := provider.volume(ctx, volumeID)
	if err != nil {
		return err
	}
	attached := false
	for _, attachment := range volume.Attachments {
		if aws.ToString(attachment.InstanceId) != instanceID || aws.ToString(attachment.Device) != device {
			return resource.ErrReadBack
		}
		attached = true
	}
	if !attached {
		if _, err := provider.client.AttachVolume(ctx, &ec2.AttachVolumeInput{VolumeId: aws.String(volumeID), InstanceId: aws.String(instanceID), Device: aws.String(device)}); err != nil {
			return providerError(ctx, err)
		}
	}
	return provider.wait(ctx, func(ctx context.Context) (bool, error) {
		volume, err := provider.volume(ctx, volumeID)
		if err != nil {
			return false, err
		}
		for _, attachment := range volume.Attachments {
			if aws.ToString(attachment.InstanceId) == instanceID && aws.ToString(attachment.Device) == device && attachment.State == ec2types.VolumeAttachmentStateAttached {
				return true, nil
			}
		}
		return false, nil
	})
}
