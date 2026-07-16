package awsadapter

import (
	"context"

	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func (adapter *Adapter) ValidateEnvironment(ctx context.Context, input workerami.BuildEnvironmentV1) error {
	if err := adapter.validateScope(input.Region, input.AccountID); err != nil {
		return err
	}
	images, err := adapter.ec2.DescribeImages(ctx, &ec2.DescribeImagesInput{ImageIds: []string{input.BaseAMIID}, Owners: []string{input.BaseAMIOwnerID}})
	if err != nil {
		return providerError(ctx, err)
	}
	if len(images.Images) != 1 || !validBaseImage(images.Images[0], input) {
		return workerami.ErrReadBackMismatch
	}

	subnets, err := adapter.ec2.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{SubnetIds: []string{input.PrivateSubnetID}})
	if err != nil {
		return providerError(ctx, err)
	}
	if len(subnets.Subnets) != 1 || stringValue(subnets.Subnets[0].SubnetId) != input.PrivateSubnetID || stringValue(subnets.Subnets[0].VpcId) == "" ||
		subnets.Subnets[0].State != ec2types.SubnetStateAvailable || aws.ToBool(subnets.Subnets[0].MapPublicIpOnLaunch) {
		return workerami.ErrReadBackMismatch
	}

	groups, err := adapter.ec2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: []string{input.ZeroIngressSGID}})
	if err != nil {
		return providerError(ctx, err)
	}
	if len(groups.SecurityGroups) != 1 || stringValue(groups.SecurityGroups[0].GroupId) != input.ZeroIngressSGID ||
		stringValue(groups.SecurityGroups[0].VpcId) != stringValue(subnets.Subnets[0].VpcId) ||
		len(groups.SecurityGroups[0].IpPermissions) != 0 || !adapter.validHTTPSOnlyEgress(groups.SecurityGroups[0].IpPermissionsEgress) {
		return workerami.ErrReadBackMismatch
	}

	versioning, err := adapter.s3.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(input.ArtifactBucket)})
	if err != nil {
		return providerError(ctx, err)
	}
	if versioning.Status != s3types.BucketVersioningStatusEnabled {
		return workerami.ErrReadBackMismatch
	}
	encryption, err := adapter.s3.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: aws.String(input.ArtifactBucket)})
	if err != nil {
		return providerError(ctx, err)
	}
	if encryption.ServerSideEncryptionConfiguration == nil || len(encryption.ServerSideEncryptionConfiguration.Rules) != 1 {
		return workerami.ErrReadBackMismatch
	}
	rule := encryption.ServerSideEncryptionConfiguration.Rules[0]
	if rule.ApplyServerSideEncryptionByDefault == nil ||
		rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm != s3types.ServerSideEncryptionAwsKms ||
		stringValue(rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID) != input.ArtifactKMSKeyARN {
		return workerami.ErrReadBackMismatch
	}

	var token *string
	for {
		offerings, describeErr := adapter.ec2.DescribeInstanceTypeOfferings(ctx, &ec2.DescribeInstanceTypeOfferingsInput{
			Filters:      []ec2types.Filter{{Name: aws.String("instance-type"), Values: []string{input.BuilderInstanceType}}, {Name: aws.String("location"), Values: []string{input.Region}}},
			LocationType: ec2types.LocationTypeRegion, NextToken: token,
		})
		if describeErr != nil {
			return providerError(ctx, describeErr)
		}
		for _, offering := range offerings.InstanceTypeOfferings {
			if string(offering.InstanceType) == input.BuilderInstanceType && stringValue(offering.Location) == input.Region {
				return nil
			}
		}
		if stringValue(offerings.NextToken) == "" {
			return workerami.ErrReadBackMismatch
		}
		token = offerings.NextToken
	}
}

func validBaseImage(image ec2types.Image, input workerami.BuildEnvironmentV1) bool {
	wantedArch := ec2types.ArchitectureValuesX8664
	if input.Architecture == "arm64" {
		wantedArch = ec2types.ArchitectureValuesArm64
	}
	if stringValue(image.ImageId) != input.BaseAMIID || stringValue(image.OwnerId) != input.BaseAMIOwnerID ||
		image.State != ec2types.ImageStateAvailable || image.Architecture != wantedArch || image.RootDeviceType != ec2types.DeviceTypeEbs ||
		stringValue(image.RootDeviceName) != input.RootDeviceName || len(image.BlockDeviceMappings) != 1 {
		return false
	}
	mapping := image.BlockDeviceMappings[0]
	return stringValue(mapping.DeviceName) == input.RootDeviceName && mapping.Ebs != nil
}

func (adapter *Adapter) validHTTPSOnlyEgress(permissions []ec2types.IpPermission) bool {
	if len(permissions) == 0 {
		return false
	}
	for _, permission := range permissions {
		if stringValue(permission.IpProtocol) != "tcp" || aws.ToInt32(permission.FromPort) != 443 || aws.ToInt32(permission.ToPort) != 443 ||
			len(permission.UserIdGroupPairs) != 0 || len(permission.IpRanges)+len(permission.Ipv6Ranges)+len(permission.PrefixListIds) == 0 {
			return false
		}
		for _, ipRange := range permission.Ipv6Ranges {
			cidr := stringValue(ipRange.CidrIpv6)
			if cidr == "::/0" && !adapter.allowInternet {
				return false
			}
			if _, approved := adapter.cidrs[cidr]; !approved && !(adapter.allowInternet && cidr == "::/0") {
				return false
			}
		}
		for _, ipRange := range permission.IpRanges {
			cidr := stringValue(ipRange.CidrIp)
			if (cidr == "0.0.0.0/0" || cidr == "::/0") && !adapter.allowInternet {
				return false
			}
			if _, approved := adapter.cidrs[cidr]; !approved && !(adapter.allowInternet && cidr == "0.0.0.0/0") {
				return false
			}
		}
		for _, prefix := range permission.PrefixListIds {
			if _, approved := adapter.prefixes[stringValue(prefix.PrefixListId)]; !approved {
				return false
			}
		}
	}
	return true
}
