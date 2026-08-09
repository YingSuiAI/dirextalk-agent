package sdkclient

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

var errProfileTagsMissing = errors.New("instance profile identity tags are not installed")

type stackMapping struct {
	stack     cftypes.Stack
	physical  map[cloudaws.ResourceKind]string
	resources map[cloudaws.ResourceKind]cftypes.StackResource
}

var cfnResourceTypes = map[cloudaws.ResourceKind]string{
	cloudaws.ResourceSecurityGroup:   "AWS::EC2::SecurityGroup",
	cloudaws.ResourceIAMRole:         "AWS::IAM::Role",
	cloudaws.ResourceInstanceProfile: "AWS::IAM::InstanceProfile",
	cloudaws.ResourceENI:             "AWS::EC2::NetworkInterface",
	cloudaws.ResourceEIP:             "AWS::EC2::EIP",
	cloudaws.ResourceEC2:             "AWS::EC2::Instance",
}

func (client *Client) ObserveGraph(ctx context.Context, request cloudaws.ObserveGraphRequest) (cloudaws.ObservedGraph, error) {
	if err := validateGraphRequest(request); err != nil || !client.matchesConfig(request.Identity) {
		return cloudaws.ObservedGraph{}, cloudaws.ErrInvalid
	}
	if err := client.verify(ctx, request.Identity); err != nil {
		return cloudaws.ObservedGraph{}, err
	}
	stackName := deterministicStackName(request.Identity)
	nameOrARN := stackName
	if request.StackProviderID != "" {
		nameOrARN = request.StackProviderID
	}
	stack, found, err := client.describeStack(ctx, request.Identity, nameOrARN)
	if err != nil {
		return cloudaws.ObservedGraph{}, err
	}
	if !found {
		return client.observeWithoutStack(ctx, request)
	}
	if err := client.validateStack(stack, stackName, request.StackProviderID, request.ExpectedTags); err != nil {
		return cloudaws.ObservedGraph{}, err
	}
	state, err := graphState(stack.StackStatus)
	if err != nil {
		return cloudaws.ObservedGraph{}, err
	}
	mapping, err := client.readStackMapping(ctx, request.Identity, stack, request.ExpectedTags, state != cloudaws.GraphActive)
	if err != nil {
		return cloudaws.ObservedGraph{}, err
	}
	for kind, expected := range request.ExpectedResourceProviderIDs {
		if kind == cloudaws.ResourceStack {
			if expected != awssdk.ToString(stack.StackId) {
				return cloudaws.ObservedGraph{}, cloudaws.ErrOwnershipMismatch
			}
			continue
		}
		if kind == cloudaws.ResourceIAMRole || kind == cloudaws.ResourceInstanceProfile {
			expectedName := request.Plan.IAMRoleName
			if kind == cloudaws.ResourceInstanceProfile {
				expectedName = request.Plan.InstanceProfileName
			}
			if mapping.physical[kind] != "" && mapping.physical[kind] != expectedName {
				return cloudaws.ObservedGraph{}, cloudaws.ErrOwnershipMismatch
			}
			if mapping.physical[kind] == "" {
				mapping.physical[kind] = expectedName
			}
			continue
		}
		if actual := mapping.physical[kind]; actual != "" && actual != expected {
			return cloudaws.ObservedGraph{}, cloudaws.ErrOwnershipMismatch
		}
		if mapping.physical[kind] == "" {
			mapping.physical[kind] = expected
		}
	}
	observations := make([]cloudaws.ResourceObservation, 0, len(cloudaws.AllResourceKinds()))
	observedKinds := make(map[cloudaws.ResourceKind]bool, len(cloudaws.AllResourceKinds()))
	rootVolumeID := ""
	for _, kind := range []cloudaws.ResourceKind{cloudaws.ResourceSecurityGroup, cloudaws.ResourceIAMRole, cloudaws.ResourceInstanceProfile,
		cloudaws.ResourceENI, cloudaws.ResourceEIP, cloudaws.ResourceEC2} {
		providerID := mapping.physical[kind]
		if providerID == "" {
			continue
		}
		observation, rootID, observeErr := client.observePhysical(ctx, request.Identity, request.Plan, mapping, kind, providerID,
			request.ExpectedResourceProviderIDs[kind], request.ExpectedTags, request.SecurityGroupPolicy)
		if errors.Is(observeErr, errProfileTagsMissing) && kind == cloudaws.ResourceInstanceProfile {
			state = cloudaws.GraphProvisioning
			continue
		}
		if observeErr != nil {
			return cloudaws.ObservedGraph{}, observeErr
		}
		if rootID != "" {
			rootVolumeID = rootID
		}
		observations = append(observations, observation)
		observedKinds[kind] = true
	}
	if rootVolumeID == "" {
		rootVolumeID = mapping.physical[cloudaws.ResourceEBS]
	}
	if rootVolumeID != "" {
		if expected := request.ExpectedResourceProviderIDs[cloudaws.ResourceEBS]; expected != "" && expected != rootVolumeID {
			return cloudaws.ObservedGraph{}, cloudaws.ErrOwnershipMismatch
		}
		volume, _, err := client.observePhysical(ctx, request.Identity, request.Plan, mapping, cloudaws.ResourceEBS, rootVolumeID,
			request.ExpectedResourceProviderIDs[cloudaws.ResourceEBS], request.ExpectedTags, request.SecurityGroupPolicy)
		if err != nil {
			return cloudaws.ObservedGraph{}, err
		}
		observations = append(observations, volume)
		observedKinds[cloudaws.ResourceEBS] = true
	} else if state != cloudaws.GraphProvisioning {
		observations = append(observations, absentObservation(cloudaws.ResourceEBS, "", client.now().UTC()))
		observedKinds[cloudaws.ResourceEBS] = true
	}
	if state != cloudaws.GraphActive {
		for _, kind := range cloudaws.AllResourceKinds() {
			if kind == cloudaws.ResourceStack || observedKinds[kind] {
				continue
			}
			providerID := mapping.physical[kind]
			if kind == cloudaws.ResourceIAMRole || kind == cloudaws.ResourceInstanceProfile {
				providerID = request.ExpectedResourceProviderIDs[kind]
			}
			observations = append(observations, absentObservation(kind, providerID, client.now().UTC()))
		}
	}
	observations = append(observations, cloudaws.ResourceObservation{Kind: cloudaws.ResourceStack, LogicalID: cloudaws.LogicalID(cloudaws.ResourceStack),
		ProviderID: awssdk.ToString(stack.StackId), Exists: true, Tags: cfnTagMap(stack.Tags), LaunchIdentity: request.Identity.LaunchIdentity,
		Generation: request.Identity.Generation, ObservedAt: client.now().UTC()})
	if state == cloudaws.GraphActive && len(observations) != len(cloudaws.AllResourceKinds()) {
		state = cloudaws.GraphProvisioning
	}
	return cloudaws.ObservedGraph{
		Identity: request.Identity, PlanDigest: request.PlanDigest, InfrastructureDigest: request.InfrastructureDigest,
		IntentDigest: request.IntentDigest, StackProviderID: awssdk.ToString(stack.StackId), State: state, Resources: observations,
		Topology: cloudaws.TopologyProof{EC2InstanceCount: 1,
			Ingress: []cloudaws.NetworkRule{}, Egress: append([]cloudaws.NetworkRule(nil), request.SecurityGroupPolicy.Egress...), SSMEnabled: false,
			FQDNEnforcement: request.SecurityGroupPolicy.FQDNEnforcement, FQDNPolicyDigest: request.SecurityGroupPolicy.FQDNPolicyDigest},
		ObservedAt: client.now().UTC(),
	}, nil
}

// observeWithoutStack does not infer resource absence from CloudFormation
// absence. It independently inventories every EC2 resource by the complete
// immutable tag set, checks persisted provider IDs, and directly reads the
// deterministic IAM role/profile names before it can report
// verified_destroyed.
func (client *Client) observeWithoutStack(ctx context.Context, request cloudaws.ObserveGraphRequest) (cloudaws.ObservedGraph, error) {
	providerIDs := make(map[cloudaws.ResourceKind]string, len(request.ExpectedResourceProviderIDs)+2)
	for kind, providerID := range request.ExpectedResourceProviderIDs {
		providerIDs[kind] = providerID
	}
	discovered, err := client.discoverTaggedProviderIDs(ctx, request.Identity, request.ExpectedTags)
	if err != nil {
		return cloudaws.ObservedGraph{}, err
	}
	for kind, providerID := range discovered {
		if expected := providerIDs[kind]; expected != "" && expected != providerID {
			return cloudaws.ObservedGraph{}, cloudaws.ErrOwnershipMismatch
		}
		providerIDs[kind] = providerID
	}
	physical := make(map[cloudaws.ResourceKind]string, len(providerIDs)+2)
	for kind, providerID := range providerIDs {
		physical[kind] = providerID
	}
	physical[cloudaws.ResourceIAMRole] = request.Plan.IAMRoleName
	physical[cloudaws.ResourceInstanceProfile] = request.Plan.InstanceProfileName
	mapping := stackMapping{physical: physical, resources: make(map[cloudaws.ResourceKind]cftypes.StackResource)}
	ordered := []cloudaws.ResourceKind{cloudaws.ResourceSecurityGroup, cloudaws.ResourceIAMRole, cloudaws.ResourceInstanceProfile,
		cloudaws.ResourceENI, cloudaws.ResourceEIP, cloudaws.ResourceEC2, cloudaws.ResourceEBS}
	observations := make([]cloudaws.ResourceObservation, 0, len(cloudaws.AllResourceKinds()))
	exists := false
	for _, kind := range ordered {
		locator := mapping.physical[kind]
		expectedProviderID := providerIDs[kind]
		if locator == "" {
			observations = append(observations, absentObservation(kind, expectedProviderID, client.now().UTC()))
			continue
		}
		observation, rootVolumeID, observeErr := client.observePhysical(ctx, request.Identity, request.Plan, mapping, kind, locator,
			expectedProviderID, request.ExpectedTags, request.SecurityGroupPolicy)
		if observeErr != nil {
			return cloudaws.ObservedGraph{}, observeErr
		}
		if rootVolumeID != "" {
			if expected := providerIDs[cloudaws.ResourceEBS]; expected != "" && expected != rootVolumeID {
				return cloudaws.ObservedGraph{}, cloudaws.ErrOwnershipMismatch
			}
			providerIDs[cloudaws.ResourceEBS] = rootVolumeID
			mapping.physical[cloudaws.ResourceEBS] = rootVolumeID
		}
		exists = exists || observation.Exists
		observations = append(observations, observation)
	}
	stackProviderID := request.StackProviderID
	if stackProviderID == "" {
		stackProviderID = providerIDs[cloudaws.ResourceStack]
	}
	observations = append(observations, absentObservation(cloudaws.ResourceStack, stackProviderID, client.now().UTC()))
	state := cloudaws.GraphVerifiedDestroyed
	if exists {
		state = cloudaws.GraphDestroying
	}
	return cloudaws.ObservedGraph{
		Identity: request.Identity, PlanDigest: request.PlanDigest, InfrastructureDigest: request.InfrastructureDigest,
		IntentDigest: request.IntentDigest, State: state, Resources: observations, ObservedAt: client.now().UTC(),
	}, nil
}

func (client *Client) discoverTaggedProviderIDs(ctx context.Context, identity cloudaws.ExecutionIdentity, expectedTags map[string]string) (map[cloudaws.ResourceKind]string, error) {
	filters := ec2TagFilters(expectedTags)
	result := make(map[cloudaws.ResourceKind]string)
	merge := func(kind cloudaws.ResourceKind, providerID string) error {
		if providerID == "" {
			return cloudaws.ErrCloudReadback
		}
		if existing := result[kind]; existing != "" && existing != providerID {
			return cloudaws.ErrOwnershipMismatch
		}
		result[kind] = providerID
		return nil
	}

	var nextToken *string
	for {
		if err := client.verify(ctx, identity); err != nil {
			return nil, err
		}
		output, err := client.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{Filters: filters, NextToken: nextToken})
		if err != nil || output == nil {
			return nil, errors.Join(cloudaws.ErrCloudReadback, err)
		}
		for _, reservation := range output.Reservations {
			for _, instance := range reservation.Instances {
				if instance.State != nil && string(instance.State.Name) == "terminated" {
					continue
				}
				if err := merge(cloudaws.ResourceEC2, awssdk.ToString(instance.InstanceId)); err != nil {
					return nil, err
				}
			}
		}
		if output.NextToken == nil || awssdk.ToString(output.NextToken) == "" {
			break
		}
		nextToken = output.NextToken
	}

	nextToken = nil
	for {
		if err := client.verify(ctx, identity); err != nil {
			return nil, err
		}
		output, err := client.ec2.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{Filters: filters, NextToken: nextToken})
		if err != nil || output == nil {
			return nil, errors.Join(cloudaws.ErrCloudReadback, err)
		}
		for _, volume := range output.Volumes {
			if err := merge(cloudaws.ResourceEBS, awssdk.ToString(volume.VolumeId)); err != nil {
				return nil, err
			}
		}
		if output.NextToken == nil || awssdk.ToString(output.NextToken) == "" {
			break
		}
		nextToken = output.NextToken
	}

	nextToken = nil
	for {
		if err := client.verify(ctx, identity); err != nil {
			return nil, err
		}
		output, err := client.ec2.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{Filters: filters, NextToken: nextToken})
		if err != nil || output == nil {
			return nil, errors.Join(cloudaws.ErrCloudReadback, err)
		}
		for _, networkInterface := range output.NetworkInterfaces {
			if err := merge(cloudaws.ResourceENI, awssdk.ToString(networkInterface.NetworkInterfaceId)); err != nil {
				return nil, err
			}
		}
		if output.NextToken == nil || awssdk.ToString(output.NextToken) == "" {
			break
		}
		nextToken = output.NextToken
	}

	if err := client.verify(ctx, identity); err != nil {
		return nil, err
	}
	addresses, err := client.ec2.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{Filters: filters})
	if err != nil || addresses == nil {
		return nil, errors.Join(cloudaws.ErrCloudReadback, err)
	}
	for _, address := range addresses.Addresses {
		if err := merge(cloudaws.ResourceEIP, awssdk.ToString(address.AllocationId)); err != nil {
			return nil, err
		}
	}

	nextToken = nil
	for {
		if err := client.verify(ctx, identity); err != nil {
			return nil, err
		}
		output, err := client.ec2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{Filters: filters, NextToken: nextToken})
		if err != nil || output == nil {
			return nil, errors.Join(cloudaws.ErrCloudReadback, err)
		}
		for _, group := range output.SecurityGroups {
			if err := merge(cloudaws.ResourceSecurityGroup, awssdk.ToString(group.GroupId)); err != nil {
				return nil, err
			}
		}
		if output.NextToken == nil || awssdk.ToString(output.NextToken) == "" {
			break
		}
		nextToken = output.NextToken
	}
	return result, nil
}

func (client *Client) ObserveResource(ctx context.Context, request cloudaws.ObserveResourceRequest) (cloudaws.ResourceObservation, error) {
	if err := validateResourceRequest(request); err != nil || !client.matchesConfig(request.Identity) {
		return cloudaws.ResourceObservation{}, cloudaws.ErrInvalid
	}
	if err := client.verify(ctx, request.Identity); err != nil {
		return cloudaws.ResourceObservation{}, err
	}
	stackName := deterministicStackName(request.Identity)
	stackARN := request.ExpectedResourceProviderIDs[cloudaws.ResourceStack]
	stack, found, err := client.describeStack(ctx, request.Identity, stackARN)
	if err != nil {
		return cloudaws.ResourceObservation{}, err
	}
	if !found {
		graph, graphErr := client.observeWithoutStack(ctx, cloudaws.ObserveGraphRequest{
			Identity: request.Identity, Plan: request.Plan, PlanDigest: request.PlanDigest, InfrastructureDigest: request.InfrastructureDigest,
			IntentDigest: request.IntentDigest, ClientToken: "readback", ExpectedResourceProviderIDs: request.ExpectedResourceProviderIDs,
			ExpectedTags: request.ExpectedTags, SecurityGroupPolicy: request.SecurityGroupPolicy,
		})
		if graphErr != nil {
			return cloudaws.ResourceObservation{}, graphErr
		}
		for _, observation := range graph.Resources {
			if observation.Kind == request.Kind {
				return observation, nil
			}
		}
		return cloudaws.ResourceObservation{}, cloudaws.ErrCloudReadback
	}
	if err := client.validateStack(stack, stackName, stackARN, request.ExpectedTags); err != nil {
		return cloudaws.ResourceObservation{}, err
	}
	mapping, err := client.readStackMapping(ctx, request.Identity, stack, request.ExpectedTags, true)
	if err != nil {
		return cloudaws.ResourceObservation{}, err
	}
	if request.Kind == cloudaws.ResourceStack {
		if request.ResourceProviderID != awssdk.ToString(stack.StackId) {
			return cloudaws.ResourceObservation{}, cloudaws.ErrOwnershipMismatch
		}
		return cloudaws.ResourceObservation{Kind: request.Kind, LogicalID: request.LogicalID, ProviderID: request.ResourceProviderID,
			Exists: true, Tags: cfnTagMap(stack.Tags), LaunchIdentity: request.Identity.LaunchIdentity, Generation: request.Identity.Generation,
			ObservedAt: client.now().UTC()}, nil
	}
	if request.Kind != cloudaws.ResourceEBS && request.Kind != cloudaws.ResourceIAMRole && request.Kind != cloudaws.ResourceInstanceProfile &&
		mapping.physical[request.Kind] != "" && mapping.physical[request.Kind] != request.ResourceProviderID {
		return cloudaws.ResourceObservation{}, cloudaws.ErrOwnershipMismatch
	}
	locator := mapping.physical[request.Kind]
	if request.Kind == cloudaws.ResourceIAMRole && locator == "" {
		locator = request.Plan.IAMRoleName
	}
	if request.Kind == cloudaws.ResourceInstanceProfile && locator == "" {
		locator = request.Plan.InstanceProfileName
	}
	observation, _, err := client.observePhysical(ctx, request.Identity, request.Plan, mapping, request.Kind, locator,
		request.ResourceProviderID, request.ExpectedTags, request.SecurityGroupPolicy)
	return observation, err
}

func (client *Client) EnsureResourceIdentity(ctx context.Context, request cloudaws.EnsureResourceIdentityRequest) error {
	if request.Identity.Validate() != nil || request.Plan.Validate() != nil || !request.Plan.Identity.Equal(request.Identity) ||
		request.Kind != cloudaws.ResourceInstanceProfile || request.LogicalID != cloudaws.LogicalID(cloudaws.ResourceInstanceProfile) ||
		request.PlanDigest != request.Plan.Digest || request.InfrastructureDigest != request.Plan.InfrastructureDigest || request.IntentDigest == "" ||
		request.StackProviderID == "" || request.MutationToken == "" || !client.matchesConfig(request.Identity) ||
		len(request.ExpectedResourceProviderIDs) != 2 ||
		!validIAMUniqueID(request.ExpectedResourceProviderIDs[cloudaws.ResourceIAMRole]) ||
		!validIAMUniqueID(request.ExpectedResourceProviderIDs[cloudaws.ResourceInstanceProfile]) ||
		!containsTags(request.ExpectedTags, cloudaws.RequiredTags(request.Identity, request.PlanDigest, request.InfrastructureDigest, request.IntentDigest)) {
		return cloudaws.ErrInvalid
	}
	return client.ensureInstanceProfileIdentity(ctx, request)
}

func (client *Client) readStackMapping(ctx context.Context, identity cloudaws.ExecutionIdentity, stack cftypes.Stack, expectedTags map[string]string, allowPartial bool) (stackMapping, error) {
	if err := client.validateStack(stack, deterministicStackName(identity), awssdk.ToString(stack.StackId), expectedTags); err != nil {
		return stackMapping{}, err
	}
	if err := client.verify(ctx, identity); err != nil {
		return stackMapping{}, err
	}
	output, err := client.cfn.DescribeStackResources(ctx, &cloudformation.DescribeStackResourcesInput{StackName: stack.StackId})
	if err != nil || output == nil {
		return stackMapping{}, errors.Join(cloudaws.ErrCloudReadback, err)
	}
	result := stackMapping{stack: stack, physical: make(map[cloudaws.ResourceKind]string), resources: make(map[cloudaws.ResourceKind]cftypes.StackResource)}
	for _, resource := range output.StackResources {
		kind, found := kindForLogicalID(awssdk.ToString(resource.LogicalResourceId))
		if !found || awssdk.ToString(resource.ResourceType) != cfnResourceTypes[kind] || awssdk.ToString(resource.StackId) != awssdk.ToString(stack.StackId) {
			return stackMapping{}, cloudaws.ErrOwnershipMismatch
		}
		if _, duplicate := result.resources[kind]; duplicate {
			return stackMapping{}, cloudaws.ErrOwnershipMismatch
		}
		result.resources[kind] = resource
		result.physical[kind] = awssdk.ToString(resource.PhysicalResourceId)
	}
	if !allowPartial && len(result.resources) != len(cfnResourceTypes) {
		return stackMapping{}, cloudaws.ErrCloudReadback
	}
	return result, nil
}

func (client *Client) observePhysical(ctx context.Context, identity cloudaws.ExecutionIdentity, plan cloudaws.Plan, mapping stackMapping,
	kind cloudaws.ResourceKind, locator, expectedProviderID string, expectedTags map[string]string, policy cloudaws.SecurityGroupPolicy) (cloudaws.ResourceObservation, string, error) {
	if err := client.verify(ctx, identity); err != nil {
		return cloudaws.ResourceObservation{}, "", err
	}
	now := client.now().UTC()
	providerID := locator
	if kind == cloudaws.ResourceIAMRole || kind == cloudaws.ResourceInstanceProfile {
		providerID = expectedProviderID
	} else if expectedProviderID != "" && expectedProviderID != locator {
		return cloudaws.ResourceObservation{}, "", cloudaws.ErrOwnershipMismatch
	}
	observation := cloudaws.ResourceObservation{Kind: kind, LogicalID: cloudaws.LogicalID(kind), ProviderID: providerID, Exists: true,
		LaunchIdentity: identity.LaunchIdentity, Generation: identity.Generation, ObservedAt: now}
	switch kind {
	case cloudaws.ResourceEC2:
		instance, found, err := client.describeInstance(ctx, providerID)
		if err != nil || !found {
			return absentObservation(kind, providerID, now), "", err
		}
		tags := ec2TagMap(instance.Tags)
		if !containsTags(tags, expectedTags) || awssdk.ToString(instance.ImageId) != plan.AMIID || string(instance.InstanceType) != plan.InstanceType ||
			string(instance.Architecture) != expectedEC2Architecture(plan.Architecture) || instance.MetadataOptions == nil ||
			string(instance.MetadataOptions.HttpTokens) != "required" || awssdk.ToInt32(instance.MetadataOptions.HttpPutResponseHopLimit) != 1 ||
			len(instance.NetworkInterfaces) != 1 || awssdk.ToString(instance.NetworkInterfaces[0].NetworkInterfaceId) != mapping.physical[cloudaws.ResourceENI] ||
			instance.IamInstanceProfile == nil || !strings.HasSuffix(awssdk.ToString(instance.IamInstanceProfile.Arn), "/"+plan.InstanceProfileName) {
			return cloudaws.ResourceObservation{}, "", cloudaws.ErrOwnershipMismatch
		}
		rootID := ""
		for _, device := range instance.BlockDeviceMappings {
			if awssdk.ToString(device.DeviceName) == plan.RootDeviceName && device.Ebs != nil && awssdk.ToBool(device.Ebs.DeleteOnTermination) {
				rootID = awssdk.ToString(device.Ebs.VolumeId)
			}
		}
		if rootID == "" {
			return cloudaws.ResourceObservation{}, "", cloudaws.ErrCloudReadback
		}
		observation.Tags = tags
		observation.PrivateIP = awssdk.ToString(instance.PrivateIpAddress)
		return observation, rootID, nil
	case cloudaws.ResourceEBS:
		volume, found, err := client.describeVolume(ctx, providerID)
		if err != nil || !found {
			return absentObservation(kind, providerID, now), "", err
		}
		tags := ec2TagMap(volume.Tags)
		if !containsTags(tags, expectedTags) || awssdk.ToInt32(volume.Size) != int32(plan.RootVolumeGiB) || string(volume.VolumeType) != plan.RootVolumeType ||
			awssdk.ToInt32(volume.Iops) != int32(plan.RootVolumeIOPS) || awssdk.ToInt32(volume.Throughput) != int32(plan.RootVolumeThroughput) ||
			!awssdk.ToBool(volume.Encrypted) || awssdk.ToString(volume.KmsKeyId) != plan.RootKMSKeyARN || len(volume.Attachments) > 1 ||
			(len(volume.Attachments) == 1 && awssdk.ToString(volume.Attachments[0].InstanceId) != mapping.physical[cloudaws.ResourceEC2]) {
			return cloudaws.ResourceObservation{}, "", cloudaws.ErrOwnershipMismatch
		}
		observation.Tags = tags
		return observation, "", nil
	case cloudaws.ResourceENI:
		value, found, err := client.describeENI(ctx, providerID)
		if err != nil || !found {
			return absentObservation(kind, providerID, now), "", err
		}
		tags := ec2TagMap(value.TagSet)
		if !containsTags(tags, expectedTags) || awssdk.ToString(value.SubnetId) != plan.SubnetID || len(value.Groups) != 1 ||
			awssdk.ToString(value.Groups[0].GroupId) != mapping.physical[cloudaws.ResourceSecurityGroup] {
			return cloudaws.ResourceObservation{}, "", cloudaws.ErrOwnershipMismatch
		}
		observation.Tags = tags
		return observation, "", nil
	case cloudaws.ResourceEIP:
		value, found, err := client.describeEIP(ctx, providerID)
		if err != nil || !found {
			return absentObservation(kind, providerID, now), "", err
		}
		tags := ec2TagMap(value.Tags)
		if !containsTags(tags, expectedTags) || awssdk.ToString(value.NetworkInterfaceId) != mapping.physical[cloudaws.ResourceENI] {
			return cloudaws.ResourceObservation{}, "", cloudaws.ErrOwnershipMismatch
		}
		observation.Tags = tags
		observation.PublicIP = awssdk.ToString(value.PublicIp)
		return observation, "", nil
	case cloudaws.ResourceSecurityGroup:
		value, found, err := client.describeSecurityGroup(ctx, providerID)
		if err != nil || !found {
			return absentObservation(kind, providerID, now), "", err
		}
		tags := ec2TagMap(value.Tags)
		if !containsTags(tags, expectedTags) || awssdk.ToString(value.VpcId) != plan.VPCID || len(value.IpPermissions) != 0 ||
			!equalSecurityGroupEgress(value.IpPermissionsEgress, policy.Egress) {
			return cloudaws.ResourceObservation{}, "", cloudaws.ErrOwnershipMismatch
		}
		observation.Tags = tags
		return observation, "", nil
	case cloudaws.ResourceIAMRole:
		if locator != plan.IAMRoleName {
			return cloudaws.ResourceObservation{}, "", cloudaws.ErrOwnershipMismatch
		}
		role, found, err := client.getRole(ctx, identity, locator)
		if err != nil || !found {
			return absentObservation(kind, expectedProviderID, now), "", err
		}
		providerID = awssdk.ToString(role.RoleId)
		if !validIAMUniqueID(expectedProviderID) || providerID != expectedProviderID {
			return cloudaws.ResourceObservation{}, "", cloudaws.ErrOwnershipMismatch
		}
		tags, err := client.listRoleTags(ctx, identity, locator)
		if err != nil {
			return cloudaws.ResourceObservation{}, "", err
		}
		if !containsTags(tags, expectedTags) {
			return cloudaws.ResourceObservation{}, "", cloudaws.ErrOwnershipMismatch
		}
		observation.ProviderID = providerID
		observation.Tags = tags
		return observation, "", nil
	case cloudaws.ResourceInstanceProfile:
		if locator != plan.InstanceProfileName {
			return cloudaws.ResourceObservation{}, "", cloudaws.ErrOwnershipMismatch
		}
		profile, found, err := client.getInstanceProfile(ctx, identity, locator)
		if err != nil || !found {
			return absentObservation(kind, expectedProviderID, now), "", err
		}
		providerID = awssdk.ToString(profile.InstanceProfileId)
		if !validIAMUniqueID(expectedProviderID) || providerID != expectedProviderID ||
			len(profile.Roles) != 1 || awssdk.ToString(profile.Roles[0].RoleName) != mapping.physical[cloudaws.ResourceIAMRole] {
			return cloudaws.ResourceObservation{}, "", cloudaws.ErrOwnershipMismatch
		}
		if expectedRoleID := mapping.physical[cloudaws.ResourceIAMRole]; validIAMUniqueID(expectedRoleID) &&
			awssdk.ToString(profile.Roles[0].RoleId) != expectedRoleID {
			return cloudaws.ResourceObservation{}, "", cloudaws.ErrOwnershipMismatch
		}
		tags, err := client.listInstanceProfileTags(ctx, identity, locator)
		if err != nil {
			return cloudaws.ResourceObservation{}, "", err
		}
		if !containsTags(tags, expectedTags) {
			return cloudaws.ResourceObservation{}, "", errProfileTagsMissing
		}
		observation.ProviderID = providerID
		observation.Tags = tags
		return observation, "", nil
	default:
		return cloudaws.ResourceObservation{}, "", cloudaws.ErrInvalid
	}
}

func (client *Client) describeInstance(ctx context.Context, id string) (ec2types.Instance, bool, error) {
	output, err := client.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{id}})
	if err != nil {
		if resourceNotFound(err) {
			return ec2types.Instance{}, false, nil
		}
		return ec2types.Instance{}, false, errors.Join(cloudaws.ErrCloudReadback, err)
	}
	for _, reservation := range output.Reservations {
		for _, value := range reservation.Instances {
			if awssdk.ToString(value.InstanceId) == id {
				if value.State != nil && string(value.State.Name) == "terminated" {
					return ec2types.Instance{}, false, nil
				}
				return value, true, nil
			}
		}
	}
	return ec2types.Instance{}, false, nil
}

func (client *Client) describeVolume(ctx context.Context, id string) (ec2types.Volume, bool, error) {
	output, err := client.ec2.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{VolumeIds: []string{id}})
	if err != nil {
		if resourceNotFound(err) {
			return ec2types.Volume{}, false, nil
		}
		return ec2types.Volume{}, false, errors.Join(cloudaws.ErrCloudReadback, err)
	}
	for _, value := range output.Volumes {
		if awssdk.ToString(value.VolumeId) == id {
			return value, true, nil
		}
	}
	return ec2types.Volume{}, false, nil
}

func (client *Client) describeENI(ctx context.Context, id string) (ec2types.NetworkInterface, bool, error) {
	output, err := client.ec2.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{NetworkInterfaceIds: []string{id}})
	if err != nil {
		if resourceNotFound(err) {
			return ec2types.NetworkInterface{}, false, nil
		}
		return ec2types.NetworkInterface{}, false, errors.Join(cloudaws.ErrCloudReadback, err)
	}
	for _, value := range output.NetworkInterfaces {
		if awssdk.ToString(value.NetworkInterfaceId) == id {
			return value, true, nil
		}
	}
	return ec2types.NetworkInterface{}, false, nil
}

func (client *Client) describeEIP(ctx context.Context, id string) (ec2types.Address, bool, error) {
	output, err := client.ec2.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{AllocationIds: []string{id}})
	if err != nil {
		if resourceNotFound(err) {
			return ec2types.Address{}, false, nil
		}
		return ec2types.Address{}, false, errors.Join(cloudaws.ErrCloudReadback, err)
	}
	for _, value := range output.Addresses {
		if awssdk.ToString(value.AllocationId) == id {
			return value, true, nil
		}
	}
	return ec2types.Address{}, false, nil
}

func (client *Client) describeSecurityGroup(ctx context.Context, id string) (ec2types.SecurityGroup, bool, error) {
	output, err := client.ec2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: []string{id}})
	if err != nil {
		if resourceNotFound(err) {
			return ec2types.SecurityGroup{}, false, nil
		}
		return ec2types.SecurityGroup{}, false, errors.Join(cloudaws.ErrCloudReadback, err)
	}
	for _, value := range output.SecurityGroups {
		if awssdk.ToString(value.GroupId) == id {
			return value, true, nil
		}
	}
	return ec2types.SecurityGroup{}, false, nil
}

func (client *Client) getRole(ctx context.Context, identity cloudaws.ExecutionIdentity, name string) (iamtypes.Role, bool, error) {
	if err := client.verify(ctx, identity); err != nil {
		return iamtypes.Role{}, false, err
	}
	output, err := client.iam.GetRole(ctx, &iam.GetRoleInput{RoleName: awssdk.String(name)})
	if err != nil {
		if resourceNotFound(err) {
			return iamtypes.Role{}, false, nil
		}
		return iamtypes.Role{}, false, errors.Join(cloudaws.ErrCloudReadback, err)
	}
	if output == nil || output.Role == nil || awssdk.ToString(output.Role.RoleName) != name || !validIAMUniqueID(awssdk.ToString(output.Role.RoleId)) ||
		!client.validIAMARN(awssdk.ToString(output.Role.Arn), "role/"+name) {
		return iamtypes.Role{}, false, cloudaws.ErrOwnershipMismatch
	}
	return *output.Role, true, nil
}

func (client *Client) getInstanceProfile(ctx context.Context, identity cloudaws.ExecutionIdentity, name string) (iamtypes.InstanceProfile, bool, error) {
	if err := client.verify(ctx, identity); err != nil {
		return iamtypes.InstanceProfile{}, false, err
	}
	output, err := client.iam.GetInstanceProfile(ctx, &iam.GetInstanceProfileInput{InstanceProfileName: awssdk.String(name)})
	if err != nil {
		if resourceNotFound(err) {
			return iamtypes.InstanceProfile{}, false, nil
		}
		return iamtypes.InstanceProfile{}, false, errors.Join(cloudaws.ErrCloudReadback, err)
	}
	if output == nil || output.InstanceProfile == nil || awssdk.ToString(output.InstanceProfile.InstanceProfileName) != name ||
		!validIAMUniqueID(awssdk.ToString(output.InstanceProfile.InstanceProfileId)) ||
		!client.validIAMARN(awssdk.ToString(output.InstanceProfile.Arn), "instance-profile/"+name) {
		return iamtypes.InstanceProfile{}, false, cloudaws.ErrOwnershipMismatch
	}
	return *output.InstanceProfile, true, nil
}

func (client *Client) listRoleTags(ctx context.Context, identity cloudaws.ExecutionIdentity, name string) (map[string]string, error) {
	result := make(map[string]string)
	var marker *string
	for {
		if err := client.verify(ctx, identity); err != nil {
			return nil, err
		}
		output, err := client.iam.ListRoleTags(ctx, &iam.ListRoleTagsInput{RoleName: awssdk.String(name), Marker: marker})
		if err != nil || output == nil {
			return nil, errors.Join(cloudaws.ErrCloudReadback, err)
		}
		for _, tag := range output.Tags {
			result[awssdk.ToString(tag.Key)] = awssdk.ToString(tag.Value)
		}
		if !output.IsTruncated {
			break
		}
		if output.Marker == nil || awssdk.ToString(output.Marker) == "" {
			return nil, cloudaws.ErrCloudReadback
		}
		marker = output.Marker
	}
	return result, nil
}

func (client *Client) listInstanceProfileTags(ctx context.Context, identity cloudaws.ExecutionIdentity, name string) (map[string]string, error) {
	result := make(map[string]string)
	var marker *string
	for {
		if err := client.verify(ctx, identity); err != nil {
			return nil, err
		}
		output, err := client.iam.ListInstanceProfileTags(ctx, &iam.ListInstanceProfileTagsInput{InstanceProfileName: awssdk.String(name), Marker: marker})
		if err != nil || output == nil {
			return nil, errors.Join(cloudaws.ErrCloudReadback, err)
		}
		for _, tag := range output.Tags {
			result[awssdk.ToString(tag.Key)] = awssdk.ToString(tag.Value)
		}
		if !output.IsTruncated {
			break
		}
		if output.Marker == nil || awssdk.ToString(output.Marker) == "" {
			return nil, cloudaws.ErrCloudReadback
		}
		marker = output.Marker
	}
	return result, nil
}

func validateGraphRequest(request cloudaws.ObserveGraphRequest) error {
	if request.Identity.Validate() != nil || request.Plan.Validate() != nil || !request.Plan.Identity.Equal(request.Identity) ||
		request.PlanDigest != request.Plan.Digest || request.InfrastructureDigest != request.Plan.InfrastructureDigest || request.IntentDigest == "" ||
		request.ClientToken == "" || !containsTags(request.ExpectedTags, cloudaws.RequiredTags(request.Identity, request.PlanDigest, request.InfrastructureDigest, request.IntentDigest)) ||
		len(request.SecurityGroupPolicy.Ingress) != 0 || request.SecurityGroupPolicy.SecurityGroupEnforcesFQDN || request.SecurityGroupPolicy.FQDNEnforcement != "controlled_tls_proxy" {
		return cloudaws.ErrInvalid
	}
	if validateExpectedResourceProviderIDs(request.ExpectedResourceProviderIDs, "", "") != nil {
		return cloudaws.ErrInvalid
	}
	return nil
}

func validateResourceRequest(request cloudaws.ObserveResourceRequest) error {
	if request.Identity.Validate() != nil || request.Plan.Validate() != nil || !request.Plan.Identity.Equal(request.Identity) ||
		request.PlanDigest != request.Plan.Digest || request.InfrastructureDigest != request.Plan.InfrastructureDigest || request.IntentDigest == "" ||
		request.LogicalID != cloudaws.LogicalID(request.Kind) || request.ResourceProviderID == "" ||
		request.ExpectedResourceProviderIDs[cloudaws.ResourceStack] == "" ||
		!containsTags(request.ExpectedTags, cloudaws.RequiredTags(request.Identity, request.PlanDigest, request.InfrastructureDigest, request.IntentDigest)) {
		return cloudaws.ErrInvalid
	}
	if validateExpectedResourceProviderIDs(request.ExpectedResourceProviderIDs, request.Kind, request.ResourceProviderID) != nil {
		return cloudaws.ErrInvalid
	}
	return nil
}

func validateExpectedResourceProviderIDs(values map[cloudaws.ResourceKind]string, requiredKind cloudaws.ResourceKind, requiredID string) error {
	validKinds := make(map[cloudaws.ResourceKind]bool, len(cloudaws.AllResourceKinds()))
	for _, kind := range cloudaws.AllResourceKinds() {
		validKinds[kind] = true
	}
	if requiredKind != "" && values[requiredKind] != requiredID {
		return cloudaws.ErrInvalid
	}
	for kind, providerID := range values {
		if !validKinds[kind] || providerID == "" ||
			((kind == cloudaws.ResourceIAMRole || kind == cloudaws.ResourceInstanceProfile) && !validIAMUniqueID(providerID)) ||
			(kind != cloudaws.ResourceIAMRole && kind != cloudaws.ResourceInstanceProfile && !providerPattern.MatchString(providerID)) {
			return cloudaws.ErrInvalid
		}
	}
	return nil
}

func graphState(status cftypes.StackStatus) (cloudaws.GraphState, error) {
	switch status {
	case cftypes.StackStatusCreateComplete, cftypes.StackStatusUpdateComplete:
		return cloudaws.GraphActive, nil
	case cftypes.StackStatusDeleteInProgress, cftypes.StackStatusDeleteFailed:
		return cloudaws.GraphDestroying, nil
	case cftypes.StackStatusCreateInProgress, cftypes.StackStatusReviewInProgress, cftypes.StackStatusUpdateInProgress,
		cftypes.StackStatusUpdateCompleteCleanupInProgress, cftypes.StackStatusRollbackInProgress,
		cftypes.StackStatusUpdateRollbackInProgress, cftypes.StackStatusUpdateRollbackCompleteCleanupInProgress:
		return cloudaws.GraphProvisioning, nil
	case cftypes.StackStatusCreateFailed, cftypes.StackStatusRollbackFailed, cftypes.StackStatusRollbackComplete,
		cftypes.StackStatusUpdateFailed, cftypes.StackStatusUpdateRollbackFailed, cftypes.StackStatusUpdateRollbackComplete:
		return "", cloudaws.ErrCloudMutation
	default:
		return "", cloudaws.ErrCloudReadback
	}
}

func absentGraph(request cloudaws.ObserveGraphRequest, now time.Time) cloudaws.ObservedGraph {
	resources := make([]cloudaws.ResourceObservation, 0, len(cloudaws.AllResourceKinds()))
	for _, kind := range cloudaws.AllResourceKinds() {
		resources = append(resources, absentObservation(kind, "", now))
	}
	return cloudaws.ObservedGraph{Identity: request.Identity, PlanDigest: request.PlanDigest, InfrastructureDigest: request.InfrastructureDigest,
		IntentDigest: request.IntentDigest, State: cloudaws.GraphVerifiedDestroyed, Resources: resources, ObservedAt: now}
}

func absentObservation(kind cloudaws.ResourceKind, providerID string, now time.Time) cloudaws.ResourceObservation {
	return cloudaws.ResourceObservation{Kind: kind, LogicalID: cloudaws.LogicalID(kind), ProviderID: providerID, Exists: false, ObservedAt: now}
}

func kindForLogicalID(logical string) (cloudaws.ResourceKind, bool) {
	for kind := range cfnResourceTypes {
		if cloudaws.LogicalID(kind) == logical {
			return kind, true
		}
	}
	return "", false
}

func expectedEC2Architecture(value string) string {
	if value == "arm64" {
		return "arm64"
	}
	return "x86_64"
}

func ec2TagMap(tags []ec2types.Tag) map[string]string {
	result := make(map[string]string, len(tags))
	for _, tag := range tags {
		result[awssdk.ToString(tag.Key)] = awssdk.ToString(tag.Value)
	}
	return result
}

func ec2TagFilters(tags map[string]string) []ec2types.Filter {
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]ec2types.Filter, 0, len(keys))
	for _, key := range keys {
		result = append(result, ec2types.Filter{Name: awssdk.String("tag:" + key), Values: []string{tags[key]}})
	}
	return result
}

func sdkIAMTags(tags map[string]string) []iamtypes.Tag {
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]iamtypes.Tag, 0, len(keys))
	for _, key := range keys {
		result = append(result, iamtypes.Tag{Key: awssdk.String(key), Value: awssdk.String(tags[key])})
	}
	return result
}

func equalSecurityGroupEgress(actual []ec2types.IpPermission, expected []cloudaws.NetworkRule) bool {
	rules := make([]cloudaws.NetworkRule, 0)
	for _, permission := range actual {
		if len(permission.Ipv6Ranges) != 0 || len(permission.PrefixListIds) != 0 || len(permission.UserIdGroupPairs) != 0 ||
			permission.FromPort == nil || permission.ToPort == nil || len(permission.IpRanges) != 1 {
			return false
		}
		rules = append(rules, cloudaws.NetworkRule{Protocol: awssdk.ToString(permission.IpProtocol), FromPort: uint16(awssdk.ToInt32(permission.FromPort)),
			ToPort: uint16(awssdk.ToInt32(permission.ToPort)), CIDRv4: awssdk.ToString(permission.IpRanges[0].CidrIp)})
	}
	key := func(rule cloudaws.NetworkRule) string {
		return rule.Protocol + ":" + strconv.Itoa(int(rule.FromPort)) + ":" + strconv.Itoa(int(rule.ToPort)) + ":" + rule.CIDRv4
	}
	sort.Slice(rules, func(i, j int) bool { return key(rules[i]) < key(rules[j]) })
	expected = append([]cloudaws.NetworkRule(nil), expected...)
	sort.Slice(expected, func(i, j int) bool { return key(expected[i]) < key(expected[j]) })
	if len(rules) != len(expected) {
		return false
	}
	for index := range rules {
		if rules[index] != expected[index] {
			return false
		}
	}
	return true
}

func resourceNotFound(err error) bool {
	var api interface{ ErrorCode() string }
	if !errors.As(err, &api) {
		return false
	}
	code := strings.ToLower(api.ErrorCode())
	return strings.Contains(code, "notfound") || strings.Contains(code, "not_found") || strings.Contains(code, "nosuch")
}

var _ = fmt.Sprintf
