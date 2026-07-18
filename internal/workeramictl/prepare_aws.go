package workeramictl

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami/awsadapter"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

const canonicalUbuntuOwnerID = "099720109477"

type prepareCloudFormationAPI interface {
	DescribeStacks(context.Context, *cloudformation.DescribeStacksInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
}

type prepareEC2API interface {
	DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
	DescribePrefixLists(context.Context, *ec2.DescribePrefixListsInput, ...func(*ec2.Options)) (*ec2.DescribePrefixListsOutput, error)
	DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error)
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
}

type sdkPrepareResolver struct {
	cloudformation prepareCloudFormationAPI
	ec2            prepareEC2API
	region         string
}

func (resolver *sdkPrepareResolver) Resolve(ctx context.Context, request PrepareEnvironmentRequestV2) (PrepareEnvironmentV2, error) {
	if ctx == nil || resolver == nil || resolver.cloudformation == nil || resolver.ec2 == nil || resolver.region != request.Region ||
		!accountPattern.MatchString(request.AccountID) || !regionPattern.MatchString(request.Region) || strings.TrimSpace(request.AgentInstanceID) == "" {
		return PrepareEnvironmentV2{}, errInvalidInput
	}
	partition := partitionForRegion(request.Region)
	spec, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{AgentInstanceID: request.AgentInstanceID, Partition: partition, AccountID: request.AccountID, Region: request.Region})
	if err != nil {
		return PrepareEnvironmentV2{}, errCloudOperation
	}
	stacks, err := resolver.cloudformation.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: aws.String(spec.StackName)})
	if err != nil {
		return PrepareEnvironmentV2{}, errCloudOperation
	}
	if stacks == nil || len(stacks.Stacks) != 1 {
		return PrepareEnvironmentV2{}, errCloudOperation
	}
	stack := stacks.Stacks[0]
	outputs, stackID, err := validateFoundationStack(stack, request, spec.StackName, spec.ArtifactBucketName, spec.ManifestTableName, spec.WorkerProfileName, spec.SecretNamespace, spec.ReaperFunctionName)
	if err != nil {
		return PrepareEnvironmentV2{}, errCloudOperation
	}
	vpcID := outputs["ReleaseVPCId"]
	vpcs, err := resolver.ec2.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{VpcIds: []string{vpcID}})
	if err != nil || vpcs == nil || validateFoundationVPC(vpcs.Vpcs, vpcID, request.AgentInstanceID) != nil {
		return PrepareEnvironmentV2{}, errCloudOperation
	}

	subnets, err := resolver.ec2.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{SubnetIds: []string{outputs["ReleasePrivateSubnetId"]}})
	if err != nil || subnets == nil || len(subnets.Subnets) != 1 {
		return PrepareEnvironmentV2{}, errCloudOperation
	}
	subnet := subnets.Subnets[0]
	if aws.ToString(subnet.SubnetId) != outputs["ReleasePrivateSubnetId"] || aws.ToString(subnet.VpcId) != vpcID || subnet.State != ec2types.SubnetStateAvailable ||
		aws.ToBool(subnet.MapPublicIpOnLaunch) || !hasExactFoundationTags(subnet.Tags, request.AgentInstanceID) {
		return PrepareEnvironmentV2{}, errCloudOperation
	}
	groups, err := resolver.ec2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: []string{outputs["ReleaseZeroIngressSecurityGroupId"]}})
	if err != nil || groups == nil || len(groups.SecurityGroups) != 1 {
		return PrepareEnvironmentV2{}, errCloudOperation
	}
	group := groups.SecurityGroups[0]
	if aws.ToString(group.GroupId) != outputs["ReleaseZeroIngressSecurityGroupId"] || aws.ToString(group.VpcId) != vpcID || len(group.IpPermissions) != 0 ||
		!hasExactFoundationTags(group.Tags, request.AgentInstanceID) {
		return PrepareEnvironmentV2{}, errCloudOperation
	}

	routeTableID := outputs["ReleasePrivateRouteTableId"]
	routeTables, err := resolver.ec2.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{RouteTableIds: []string{routeTableID}})
	if err != nil || routeTables == nil {
		return PrepareEnvironmentV2{}, errCloudOperation
	}
	routeTableID, err = selectFoundationRouteTable(routeTables.RouteTables, routeTableID, outputs["ReleasePrivateSubnetId"], vpcID)
	if err != nil {
		return PrepareEnvironmentV2{}, errCloudOperation
	}

	prefixes, err := resolver.ec2.DescribePrefixLists(ctx, &ec2.DescribePrefixListsInput{Filters: []ec2types.Filter{{Name: aws.String("prefix-list-name"), Values: []string{"com.amazonaws." + request.Region + ".s3"}}}})
	if err != nil || prefixes == nil || len(prefixes.PrefixLists) != 1 || !prefixListIDPattern.MatchString(aws.ToString(prefixes.PrefixLists[0].PrefixListId)) ||
		aws.ToString(prefixes.PrefixLists[0].PrefixListName) != "com.amazonaws."+request.Region+".s3" {
		return PrepareEnvironmentV2{}, errCloudOperation
	}

	images, err := resolver.ec2.DescribeImages(ctx, &ec2.DescribeImagesInput{Owners: []string{canonicalUbuntuOwnerID}, Filters: []ec2types.Filter{
		{Name: aws.String("architecture"), Values: []string{"x86_64"}}, {Name: aws.String("name"), Values: []string{"ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"}},
		{Name: aws.String("root-device-type"), Values: []string{"ebs"}}, {Name: aws.String("state"), Values: []string{"available"}}, {Name: aws.String("virtualization-type"), Values: []string{"hvm"}},
	}})
	if err != nil || images == nil {
		return PrepareEnvironmentV2{}, errCloudOperation
	}
	base, err := selectCurrentCanonicalBase(images.Images)
	if err != nil {
		return PrepareEnvironmentV2{}, errCloudOperation
	}
	return PrepareEnvironmentV2{
		FoundationStackName: spec.StackName, FoundationStackID: stackID, FoundationVPCID: vpcID, FoundationRouteTableID: routeTableID,
		PrivateSubnetID: outputs["ReleasePrivateSubnetId"], ZeroIngressSecurityGroupID: outputs["ReleaseZeroIngressSecurityGroupId"],
		ArtifactBucket: outputs["ArtifactBucketName"], ArtifactKMSKeyARN: outputs["FoundationKeyArn"],
		S3PrefixListID: aws.ToString(prefixes.PrefixLists[0].PrefixListId), BaseAMIID: aws.ToString(base.ImageId), BaseAMIOwnerID: canonicalUbuntuOwnerID,
		RootDeviceName: aws.ToString(base.RootDeviceName),
	}, nil
}

func validateFoundationStack(stack cftypes.Stack, request PrepareEnvironmentRequestV2, expectedName, expectedBucket, expectedTable, expectedProfile, expectedSecretNamespace, expectedReaper string) (map[string]string, string, error) {
	if aws.ToString(stack.StackName) != expectedName || (stack.StackStatus != cftypes.StackStatusCreateComplete && stack.StackStatus != cftypes.StackStatusUpdateComplete) || stack.DeletionTime != nil {
		return nil, "", errCloudOperation
	}
	stackID := aws.ToString(stack.StackId)
	parsed, err := arn.Parse(stackID)
	if err != nil || parsed.Service != "cloudformation" || parsed.Region != request.Region || parsed.AccountID != request.AccountID || !strings.HasPrefix(parsed.Resource, "stack/"+expectedName+"/") {
		return nil, "", errCloudOperation
	}
	parameters := make(map[string]string, len(stack.Parameters))
	for _, parameter := range stack.Parameters {
		key, value := aws.ToString(parameter.ParameterKey), aws.ToString(parameter.ParameterValue)
		if key == "" || value == "" || parameters[key] != "" {
			return nil, "", errCloudOperation
		}
		parameters[key] = value
	}
	for key, value := range map[string]string{"AgentInstanceId": request.AgentInstanceID, "ArtifactBucketName": expectedBucket, "ManifestTableName": expectedTable, "WorkerProfileName": expectedProfile, "SecretNamespace": expectedSecretNamespace} {
		if parameters[key] != value {
			return nil, "", errCloudOperation
		}
	}
	outputs := make(map[string]string, len(stack.Outputs))
	for _, output := range stack.Outputs {
		key, value := aws.ToString(output.OutputKey), aws.ToString(output.OutputValue)
		if key == "" || value == "" || outputs[key] != "" {
			return nil, "", errCloudOperation
		}
		outputs[key] = value
	}
	expectedKeys := []string{"ArtifactBucketName", "FoundationKeyArn", "ManifestTableName", "ReaperFunctionArn", "ReleasePrivateRouteTableId", "ReleasePrivateSubnetId", "ReleaseVPCId", "ReleaseZeroIngressSecurityGroupId", "SecretNamespace", "WorkerInstanceProfileArn"}
	if len(outputs) != len(expectedKeys) {
		return nil, "", errCloudOperation
	}
	for _, key := range expectedKeys {
		if outputs[key] == "" {
			return nil, "", errCloudOperation
		}
	}
	if outputs["ArtifactBucketName"] != expectedBucket || outputs["ManifestTableName"] != expectedTable || outputs["SecretNamespace"] != expectedSecretNamespace ||
		!vpcIDPattern.MatchString(outputs["ReleaseVPCId"]) || !subnetIDPattern.MatchString(outputs["ReleasePrivateSubnetId"]) ||
		!routeTableIDPattern.MatchString(outputs["ReleasePrivateRouteTableId"]) || !securityGroupIDPattern.MatchString(outputs["ReleaseZeroIngressSecurityGroupId"]) ||
		outputs["WorkerInstanceProfileArn"] != "arn:"+partitionForRegion(request.Region)+":iam::"+request.AccountID+":instance-profile/"+expectedProfile ||
		outputs["ReaperFunctionArn"] != "arn:"+partitionForRegion(request.Region)+":lambda:"+request.Region+":"+request.AccountID+":function:"+expectedReaper ||
		!strings.HasPrefix(outputs["FoundationKeyArn"], "arn:"+partitionForRegion(request.Region)+":kms:"+request.Region+":"+request.AccountID+":key/") {
		return nil, "", errCloudOperation
	}
	return outputs, stackID, nil
}

func validateFoundationVPC(vpcs []ec2types.Vpc, expectedVPCID, agentInstanceID string) error {
	if len(vpcs) != 1 {
		return errCloudOperation
	}
	vpc := vpcs[0]
	if aws.ToString(vpc.VpcId) != expectedVPCID || vpc.State != ec2types.VpcStateAvailable || aws.ToString(vpc.CidrBlock) != "10.255.0.0/24" ||
		vpc.InstanceTenancy != ec2types.TenancyDefault || aws.ToBool(vpc.IsDefault) || !hasExactFoundationTags(vpc.Tags, agentInstanceID) {
		return errCloudOperation
	}
	return nil
}

func selectFoundationRouteTable(tables []ec2types.RouteTable, expectedRouteTableID, subnetID, vpcID string) (string, error) {
	if len(tables) != 1 {
		return "", errCloudOperation
	}
	table := tables[0]
	if aws.ToString(table.RouteTableId) != expectedRouteTableID || aws.ToString(table.VpcId) != vpcID || !routeTableHasOnlyLocalRoute(table) || len(table.Associations) != 1 ||
		aws.ToString(table.Associations[0].SubnetId) != subnetID || aws.ToBool(table.Associations[0].Main) {
		return "", errCloudOperation
	}
	return expectedRouteTableID, nil
}

func routeTableHasOnlyLocalRoute(table ec2types.RouteTable) bool {
	if len(table.Routes) != 1 {
		return false
	}
	route := table.Routes[0]
	return aws.ToString(route.GatewayId) == "local" && route.State == ec2types.RouteStateActive && aws.ToString(route.DestinationCidrBlock) != ""
}

func selectCurrentCanonicalBase(images []ec2types.Image) (ec2types.Image, error) {
	return selectCurrentCanonicalBaseAt(images, time.Now().UTC())
}

func selectCurrentCanonicalBaseAt(images []ec2types.Image, now time.Time) (ec2types.Image, error) {
	type candidate struct {
		image   ec2types.Image
		created time.Time
	}
	var candidates []candidate
	for _, image := range images {
		created, err := time.Parse(time.RFC3339Nano, aws.ToString(image.CreationDate))
		if err != nil || created.IsZero() || !awsadapter.ValidCanonicalNobleSourceImageAt(image, now) {
			continue
		}
		candidates = append(candidates, candidate{image: image, created: created.UTC()})
	}
	if len(candidates) == 0 {
		return ec2types.Image{}, errCloudOperation
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].created.After(candidates[j].created) })
	if len(candidates) > 1 && candidates[0].created.Equal(candidates[1].created) {
		return ec2types.Image{}, errCloudOperation
	}
	return candidates[0].image, nil
}

func hasExactFoundationTags(tags []ec2types.Tag, agentInstanceID string) bool {
	values := make(map[string]string, len(tags))
	for _, tag := range tags {
		key := aws.ToString(tag.Key)
		if key == "" || values[key] != "" {
			return false
		}
		values[key] = aws.ToString(tag.Value)
	}
	return len(values) == 2 && values["dirextalk:agent_instance_id"] == agentInstanceID && values["dirextalk:component"] == "foundation-release"
}

func partitionForRegion(region string) string {
	if strings.HasPrefix(region, "cn-") {
		return "aws-cn"
	}
	if strings.HasPrefix(region, "us-gov-") {
		return "aws-us-gov"
	}
	return "aws"
}
