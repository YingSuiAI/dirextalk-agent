package awsprovider

import (
	"context"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func (provider *EC2ResourceProvider) readBack(ctx context.Context, kind resource.Type, providerID string) (resource.ProviderObservation, error) {
	now := provider.now().UTC()
	switch kind {
	case resource.TypeSG:
		output, err := provider.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: []string{providerID}})
		if err != nil {
			if isNotFound(kind, err) {
				return resource.ProviderObservation{ProviderID: providerID, Type: kind, Exists: false, ObservedAt: now}, nil
			}
			return resource.ProviderObservation{}, providerError(ctx, err)
		}
		if output == nil || len(output.SecurityGroups) != 1 || aws.ToString(output.SecurityGroups[0].GroupId) != providerID {
			return resource.ProviderObservation{}, resource.ErrReadBack
		}
		return observation(providerID, kind, tagsFromEC2(output.SecurityGroups[0].Tags), now), nil
	case resource.TypeALB:
		return provider.readBackApplicationLoadBalancer(ctx, providerID, now)
	case resource.TypeTargetGroup:
		return provider.readBackTargetGroup(ctx, providerID, now)
	case resource.TypeListener:
		return provider.readBackHTTPSListener(ctx, providerID, now)
	case resource.TypeSecurityGroupRule:
		return provider.readBackSecurityGroupRule(ctx, providerID, now)
	case resource.TypeEBS:
		output, err := provider.client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{VolumeIds: []string{providerID}})
		if err != nil {
			if isNotFound(kind, err) {
				return resource.ProviderObservation{ProviderID: providerID, Type: kind, Exists: false, ObservedAt: now}, nil
			}
			return resource.ProviderObservation{}, providerError(ctx, err)
		}
		if output == nil || len(output.Volumes) != 1 || aws.ToString(output.Volumes[0].VolumeId) != providerID {
			return resource.ProviderObservation{}, resource.ErrReadBack
		}
		if output.Volumes[0].State == ec2types.VolumeStateDeleted {
			return resource.ProviderObservation{ProviderID: providerID, Type: kind, Exists: false, ObservedAt: now}, nil
		}
		return observation(providerID, kind, tagsFromEC2(output.Volumes[0].Tags), now), nil
	case resource.TypeENI:
		output, err := provider.client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{NetworkInterfaceIds: []string{providerID}})
		if err != nil {
			if isNotFound(kind, err) {
				return resource.ProviderObservation{ProviderID: providerID, Type: kind, Exists: false, ObservedAt: now}, nil
			}
			return resource.ProviderObservation{}, providerError(ctx, err)
		}
		if output == nil || len(output.NetworkInterfaces) != 1 || aws.ToString(output.NetworkInterfaces[0].NetworkInterfaceId) != providerID {
			return resource.ProviderObservation{}, resource.ErrReadBack
		}
		return observation(providerID, kind, tagsFromEC2(output.NetworkInterfaces[0].TagSet), now), nil
	case resource.TypeEIP:
		output, err := provider.client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{AllocationIds: []string{providerID}})
		if err != nil {
			if isNotFound(kind, err) {
				return resource.ProviderObservation{ProviderID: providerID, Type: kind, Exists: false, ObservedAt: now}, nil
			}
			return resource.ProviderObservation{}, providerError(ctx, err)
		}
		if output == nil || len(output.Addresses) != 1 || aws.ToString(output.Addresses[0].AllocationId) != providerID {
			return resource.ProviderObservation{}, resource.ErrReadBack
		}
		return observation(providerID, kind, tagsFromEC2(output.Addresses[0].Tags), now), nil
	case resource.TypeEndpoint:
		output, err := provider.client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{VpcEndpointIds: []string{providerID}})
		if err != nil {
			if isNotFound(kind, err) {
				return resource.ProviderObservation{ProviderID: providerID, Type: kind, Exists: false, ObservedAt: now}, nil
			}
			return resource.ProviderObservation{}, providerError(ctx, err)
		}
		if output == nil {
			return resource.ProviderObservation{}, resource.ErrReadBack
		}
		if len(output.VpcEndpoints) == 0 {
			return resource.ProviderObservation{ProviderID: providerID, Type: kind, Exists: false, ObservedAt: now}, nil
		}
		if len(output.VpcEndpoints) != 1 || aws.ToString(output.VpcEndpoints[0].VpcEndpointId) != providerID {
			return resource.ProviderObservation{}, resource.ErrReadBack
		}
		if output.VpcEndpoints[0].State == ec2types.StateDeleted {
			return resource.ProviderObservation{ProviderID: providerID, Type: kind, Exists: false, ObservedAt: now}, nil
		}
		return observation(providerID, kind, tagsFromEC2(output.VpcEndpoints[0].Tags), now), nil
	case resource.TypeSnapshot:
		output, err := provider.client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{SnapshotIds: []string{providerID}, OwnerIds: []string{"self"}})
		if err != nil {
			if isNotFound(kind, err) {
				return resource.ProviderObservation{ProviderID: providerID, Type: kind, Exists: false, ObservedAt: now}, nil
			}
			return resource.ProviderObservation{}, providerError(ctx, err)
		}
		if output == nil {
			return resource.ProviderObservation{}, resource.ErrReadBack
		}
		if len(output.Snapshots) == 0 {
			return resource.ProviderObservation{ProviderID: providerID, Type: kind, Exists: false, ObservedAt: now}, nil
		}
		if len(output.Snapshots) != 1 || aws.ToString(output.Snapshots[0].SnapshotId) != providerID {
			return resource.ProviderObservation{}, resource.ErrReadBack
		}
		return observation(providerID, kind, tagsFromEC2(output.Snapshots[0].Tags), now), nil
	case resource.TypeEC2:
		output, err := provider.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{providerID}})
		if err != nil {
			if isNotFound(kind, err) {
				return resource.ProviderObservation{ProviderID: providerID, Type: kind, Exists: false, ObservedAt: now}, nil
			}
			return resource.ProviderObservation{}, providerError(ctx, err)
		}
		instances := flattenInstances(output)
		if len(instances) != 1 || aws.ToString(instances[0].InstanceId) != providerID || instances[0].State == nil {
			return resource.ProviderObservation{}, resource.ErrReadBack
		}
		if instances[0].State.Name == ec2types.InstanceStateNameTerminated {
			return resource.ProviderObservation{ProviderID: providerID, Type: kind, Exists: false, ObservedAt: now}, nil
		}
		parent := observation(providerID, kind, tagsFromEC2(instances[0].Tags), now)
		rootResourceID, err := resource.EmbeddedRootVolumeResourceID(parent.Tags[resource.TagResourceID])
		if err != nil {
			return resource.ProviderObservation{}, resource.ErrReadBack
		}
		roots, err := provider.describeByFilters(ctx, resource.TypeEBS, []ec2types.Filter{
			{Name: aws.String("tag:" + awsResourceIDTag), Values: []string{rootResourceID}},
			{Name: aws.String("tag:" + embeddedParentTag), Values: []string{parent.Tags[resource.TagResourceID]}},
			{Name: aws.String("tag:" + TagAgentInstanceID), Values: []string{parent.Tags[resource.TagAgentInstanceID]}},
		})
		if err != nil {
			return resource.ProviderObservation{}, err
		}
		if len(roots) != 1 || roots[0].Tags[resource.TagResourceID] != rootResourceID ||
			roots[0].Tags[resource.TagEmbeddedParentResourceID] != parent.Tags[resource.TagResourceID] {
			return resource.ProviderObservation{}, resource.ErrReadBack
		}
		parent.Embedded = []resource.ProviderObservation{roots[0]}
		return parent, nil
	default:
		return resource.ProviderObservation{}, resource.ErrInvalid
	}
}

func observation(providerID string, kind resource.Type, tags map[string]string, now time.Time) resource.ProviderObservation {
	return resource.ProviderObservation{ProviderID: providerID, Type: kind, Exists: true, Tags: tags, ObservedAt: now}
}

func (provider *EC2ResourceProvider) describeByFilters(ctx context.Context, kind resource.Type, filters []ec2types.Filter) ([]resource.ProviderObservation, error) {
	now := provider.now().UTC()
	result := make([]resource.ProviderObservation, 0)
	switch kind {
	case resource.TypeSG:
		seen, next := map[string]struct{}{}, ""
		for {
			output, err := provider.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{Filters: filters, NextToken: optionalToken(next)})
			if err != nil {
				return nil, providerError(ctx, err)
			}
			if output == nil {
				return nil, resource.ErrReadBack
			}
			for _, value := range output.SecurityGroups {
				result = append(result, observation(aws.ToString(value.GroupId), kind, tagsFromEC2(value.Tags), now))
			}
			next, err = advancePage(output.NextToken, seen)
			if err != nil || next == "" {
				return result, err
			}
		}
	case resource.TypeEBS:
		seen, next := map[string]struct{}{}, ""
		for {
			output, err := provider.client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{Filters: filters, NextToken: optionalToken(next)})
			if err != nil {
				return nil, providerError(ctx, err)
			}
			if output == nil {
				return nil, resource.ErrReadBack
			}
			for _, value := range output.Volumes {
				if value.State != ec2types.VolumeStateDeleted {
					result = append(result, observation(aws.ToString(value.VolumeId), kind, tagsFromEC2(value.Tags), now))
				}
			}
			next, err = advancePage(output.NextToken, seen)
			if err != nil || next == "" {
				return result, err
			}
		}
	case resource.TypeENI:
		seen, next := map[string]struct{}{}, ""
		for {
			output, err := provider.client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{Filters: filters, NextToken: optionalToken(next)})
			if err != nil {
				return nil, providerError(ctx, err)
			}
			if output == nil {
				return nil, resource.ErrReadBack
			}
			for _, value := range output.NetworkInterfaces {
				result = append(result, observation(aws.ToString(value.NetworkInterfaceId), kind, tagsFromEC2(value.TagSet), now))
			}
			next, err = advancePage(output.NextToken, seen)
			if err != nil || next == "" {
				return result, err
			}
		}
	case resource.TypeEIP:
		addresses, err := provider.addressesByFilters(ctx, filters)
		if err != nil {
			return nil, err
		}
		for _, value := range addresses {
			result = append(result, observation(aws.ToString(value.AllocationId), kind, tagsFromEC2(value.Tags), now))
		}
		return result, nil
	case resource.TypeEndpoint:
		values, err := provider.vpcEndpointsByFilters(ctx, filters)
		if err != nil {
			return nil, err
		}
		for _, value := range values {
			if value.State != ec2types.StateDeleted {
				result = append(result, observation(aws.ToString(value.VpcEndpointId), kind, tagsFromEC2(value.Tags), now))
			}
		}
		return result, nil
	case resource.TypeSnapshot:
		values, err := provider.snapshotsByFilters(ctx, filters)
		if err != nil {
			return nil, err
		}
		for _, value := range values {
			result = append(result, observation(aws.ToString(value.SnapshotId), kind, tagsFromEC2(value.Tags), now))
		}
		return result, nil
	case resource.TypeEC2:
		seen, next := map[string]struct{}{}, ""
		for {
			output, err := provider.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{Filters: filters, NextToken: optionalToken(next)})
			if err != nil {
				return nil, providerError(ctx, err)
			}
			if output == nil {
				return nil, resource.ErrReadBack
			}
			for _, value := range flattenInstances(output) {
				if value.State != nil && value.State.Name != ec2types.InstanceStateNameTerminated {
					result = append(result, observation(aws.ToString(value.InstanceId), kind, tagsFromEC2(value.Tags), now))
				}
			}
			next, err = advancePage(output.NextToken, seen)
			if err != nil || next == "" {
				return result, err
			}
		}
	default:
		return nil, resource.ErrInvalid
	}
}

func optionalToken(value string) *string {
	if value == "" {
		return nil
	}
	return aws.String(value)
}

func advancePage(value *string, seen map[string]struct{}) (string, error) {
	next := aws.ToString(value)
	if next == "" {
		return "", nil
	}
	if _, duplicate := seen[next]; duplicate {
		return "", resource.ErrReadBack
	}
	seen[next] = struct{}{}
	return next, nil
}

func (provider *EC2ResourceProvider) volume(ctx context.Context, volumeID string) (ec2types.Volume, error) {
	output, err := provider.client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{VolumeIds: []string{volumeID}})
	if err != nil {
		return ec2types.Volume{}, providerError(ctx, err)
	}
	if output == nil || len(output.Volumes) != 1 || aws.ToString(output.Volumes[0].VolumeId) != volumeID {
		return ec2types.Volume{}, resource.ErrReadBack
	}
	return output.Volumes[0], nil
}

func (provider *EC2ResourceProvider) networkInterface(ctx context.Context, interfaceID string) (ec2types.NetworkInterface, error) {
	output, err := provider.client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{NetworkInterfaceIds: []string{interfaceID}})
	if err != nil {
		return ec2types.NetworkInterface{}, providerError(ctx, err)
	}
	if output == nil || len(output.NetworkInterfaces) != 1 || aws.ToString(output.NetworkInterfaces[0].NetworkInterfaceId) != interfaceID {
		return ec2types.NetworkInterface{}, resource.ErrReadBack
	}
	return output.NetworkInterfaces[0], nil
}

func (provider *EC2ResourceProvider) address(ctx context.Context, allocationID string) (ec2types.Address, error) {
	output, err := provider.client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{AllocationIds: []string{allocationID}})
	if err != nil {
		return ec2types.Address{}, providerError(ctx, err)
	}
	if output == nil || len(output.Addresses) != 1 || aws.ToString(output.Addresses[0].AllocationId) != allocationID {
		return ec2types.Address{}, resource.ErrReadBack
	}
	return output.Addresses[0], nil
}

func (provider *EC2ResourceProvider) addressesByFilters(ctx context.Context, filters []ec2types.Filter) ([]ec2types.Address, error) {
	output, err := provider.client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{Filters: filters})
	if err != nil {
		return nil, providerError(ctx, err)
	}
	if output == nil {
		return nil, resource.ErrReadBack
	}
	return output.Addresses, nil
}

func (provider *EC2ResourceProvider) vpcEndpoint(ctx context.Context, endpointID string) (ec2types.VpcEndpoint, error) {
	output, err := provider.client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{VpcEndpointIds: []string{endpointID}})
	if err != nil {
		return ec2types.VpcEndpoint{}, providerError(ctx, err)
	}
	if output == nil || len(output.VpcEndpoints) != 1 || aws.ToString(output.VpcEndpoints[0].VpcEndpointId) != endpointID {
		return ec2types.VpcEndpoint{}, resource.ErrReadBack
	}
	return output.VpcEndpoints[0], nil
}

func (provider *EC2ResourceProvider) vpcEndpointsByFilters(ctx context.Context, filters []ec2types.Filter) ([]ec2types.VpcEndpoint, error) {
	seen, next := map[string]struct{}{}, ""
	result := make([]ec2types.VpcEndpoint, 0)
	for {
		output, err := provider.client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{Filters: filters, NextToken: optionalToken(next)})
		if err != nil {
			return nil, providerError(ctx, err)
		}
		if output == nil {
			return nil, resource.ErrReadBack
		}
		result = append(result, output.VpcEndpoints...)
		next, err = advancePage(output.NextToken, seen)
		if err != nil || next == "" {
			return result, err
		}
	}
}

func (provider *EC2ResourceProvider) snapshot(ctx context.Context, snapshotID string) (ec2types.Snapshot, error) {
	output, err := provider.client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{SnapshotIds: []string{snapshotID}, OwnerIds: []string{"self"}})
	if err != nil {
		return ec2types.Snapshot{}, providerError(ctx, err)
	}
	if output == nil || len(output.Snapshots) != 1 || aws.ToString(output.Snapshots[0].SnapshotId) != snapshotID {
		return ec2types.Snapshot{}, resource.ErrReadBack
	}
	return output.Snapshots[0], nil
}

func (provider *EC2ResourceProvider) snapshotsByFilters(ctx context.Context, filters []ec2types.Filter) ([]ec2types.Snapshot, error) {
	seen, next := map[string]struct{}{}, ""
	result := make([]ec2types.Snapshot, 0)
	for {
		output, err := provider.client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{Filters: filters, OwnerIds: []string{"self"}, NextToken: optionalToken(next)})
		if err != nil {
			return nil, providerError(ctx, err)
		}
		if output == nil {
			return nil, resource.ErrReadBack
		}
		result = append(result, output.Snapshots...)
		next, err = advancePage(output.NextToken, seen)
		if err != nil || next == "" {
			return result, err
		}
	}
}

func (provider *EC2ResourceProvider) instance(ctx context.Context, instanceID string) (ec2types.Instance, error) {
	output, err := provider.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{instanceID}})
	if err != nil {
		return ec2types.Instance{}, providerError(ctx, err)
	}
	instances := flattenInstances(output)
	if len(instances) != 1 || aws.ToString(instances[0].InstanceId) != instanceID {
		return ec2types.Instance{}, resource.ErrReadBack
	}
	return instances[0], nil
}
