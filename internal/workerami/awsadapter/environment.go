package awsadapter

import (
	"context"
	"strings"
	"time"

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
	if input.NetworkMode == workerami.NetworkModeS3GatewayV2 {
		if err := adapter.validateFoundation(ctx, input); err != nil {
			return err
		}
	}
	images, err := adapter.ec2.DescribeImages(ctx, &ec2.DescribeImagesInput{ImageIds: []string{input.BaseAMIID}, Owners: []string{input.BaseAMIOwnerID}})
	if err != nil {
		return providerError(ctx, err)
	}
	if len(images.Images) != 1 || !validBaseImage(images.Images[0], input) {
		return workerami.ErrReadBackMismatch
	}
	if input.NetworkMode == workerami.NetworkModeS3GatewayV2 && !validCanonicalNobleImage(images.Images[0]) {
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
	if input.NetworkMode == workerami.NetworkModeS3GatewayV2 && stringValue(subnets.Subnets[0].VpcId) != input.FoundationVPCID {
		return workerami.ErrReadBackMismatch
	}

	groups, err := adapter.ec2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: []string{input.ZeroIngressSGID}})
	if err != nil {
		return providerError(ctx, err)
	}
	if len(groups.SecurityGroups) != 1 || stringValue(groups.SecurityGroups[0].GroupId) != input.ZeroIngressSGID ||
		stringValue(groups.SecurityGroups[0].VpcId) != stringValue(subnets.Subnets[0].VpcId) ||
		len(groups.SecurityGroups[0].IpPermissions) != 0 {
		return workerami.ErrReadBackMismatch
	}
	if input.NetworkMode == workerami.NetworkModeS3GatewayV2 {
		if !validS3GatewayEgress(groups.SecurityGroups[0].IpPermissionsEgress, input.S3PrefixListID) {
			return workerami.ErrReadBackMismatch
		}
		prefixes, describeErr := adapter.ec2.DescribePrefixLists(ctx, &ec2.DescribePrefixListsInput{PrefixListIds: []string{input.S3PrefixListID}})
		if describeErr != nil {
			return providerError(ctx, describeErr)
		}
		if prefixes == nil || len(prefixes.PrefixLists) != 1 || stringValue(prefixes.PrefixLists[0].PrefixListId) != input.S3PrefixListID ||
			stringValue(prefixes.PrefixLists[0].PrefixListName) != "com.amazonaws."+input.Region+".s3" {
			return workerami.ErrReadBackMismatch
		}
		routes, describeErr := adapter.ec2.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{RouteTableIds: []string{input.FoundationRouteTableID}})
		if describeErr != nil {
			return providerError(ctx, describeErr)
		}
		if routes == nil || len(routes.RouteTables) != 1 || !validFoundationRouteTable(routes.RouteTables[0], input) {
			return workerami.ErrReadBackMismatch
		}
	} else if !adapter.validHTTPSOnlyEgress(groups.SecurityGroups[0].IpPermissionsEgress) {
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
		stringValue(image.RootDeviceName) != input.RootDeviceName || !validBaseImageMappings(image, input.RootDeviceName) {
		return false
	}
	return true
}

func validCanonicalNobleImage(image ec2types.Image) bool {
	return ValidCanonicalNobleSourceImageAt(image, time.Now().UTC())
}

// ValidCanonicalNobleSourceImageAt validates the immutable public source-image
// boundary shared by read-only preparation and build-time provider read-back.
func ValidCanonicalNobleSourceImageAt(image ec2types.Image, now time.Time) bool {
	name := stringValue(image.Name)
	return stringValue(image.OwnerId) == "099720109477" && aws.ToBool(image.Public) && image.State == ec2types.ImageStateAvailable && image.VirtualizationType == ec2types.VirtualizationTypeHvm &&
		image.Architecture == ec2types.ArchitectureValuesX8664 && image.RootDeviceType == ec2types.DeviceTypeEbs && stringValue(image.PlatformDetails) == "Linux/UNIX" &&
		strings.HasPrefix(name, "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-") && !strings.Contains(name, "minimal") && !strings.Contains(name, "pro-") &&
		imageIsCurrentAt(image.DeprecationTime, now) && validBaseImageMappings(image, stringValue(image.RootDeviceName)) && validCanonicalRootStorage(image)
}

func validBaseImageMappings(image ec2types.Image, rootDeviceName string) bool {
	seenDevices := make(map[string]struct{}, len(image.BlockDeviceMappings))
	foundRoot := false
	for _, mapping := range image.BlockDeviceMappings {
		deviceName := stringValue(mapping.DeviceName)
		if deviceName == "" {
			return false
		}
		if _, duplicate := seenDevices[deviceName]; duplicate {
			return false
		}
		seenDevices[deviceName] = struct{}{}
		if deviceName == rootDeviceName {
			if foundRoot || mapping.Ebs == nil || stringValue(mapping.VirtualName) != "" || !snapshotPattern.MatchString(stringValue(mapping.Ebs.SnapshotId)) {
				return false
			}
			foundRoot = true
			continue
		}
		if mapping.Ebs != nil || !validEphemeralVirtualName(stringValue(mapping.VirtualName)) {
			return false
		}
	}
	return foundRoot
}

func validCanonicalRootStorage(image ec2types.Image) bool {
	rootDeviceName := stringValue(image.RootDeviceName)
	for _, mapping := range image.BlockDeviceMappings {
		if stringValue(mapping.DeviceName) != rootDeviceName {
			continue
		}
		return mapping.Ebs != nil && mapping.Ebs.VolumeType == ec2types.VolumeTypeGp3 && aws.ToInt32(mapping.Ebs.VolumeSize) > 0 && aws.ToBool(mapping.Ebs.DeleteOnTermination)
	}
	return false
}

func imageIsCurrentAt(deprecationTime *string, now time.Time) bool {
	if now.IsZero() {
		return false
	}
	if deprecationTime == nil {
		return true
	}
	deprecatedAt, err := time.Parse(time.RFC3339Nano, stringValue(deprecationTime))
	return err == nil && deprecatedAt.After(now)
}

func validEphemeralVirtualName(value string) bool {
	const prefix = "ephemeral"
	if !strings.HasPrefix(value, prefix) || len(value) == len(prefix) {
		return false
	}
	for _, digit := range value[len(prefix):] {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

func validS3GatewayEgress(permissions []ec2types.IpPermission, prefixListID string) bool {
	if len(permissions) < 1 || len(permissions) > 2 || !prefixPattern.MatchString(prefixListID) {
		return false
	}
	sentinel, s3Rule := 0, 0
	for _, permission := range permissions {
		if stringValue(permission.IpProtocol) == "-1" && len(permission.IpRanges) == 1 && stringValue(permission.IpRanges[0].CidrIp) == "127.0.0.1/32" &&
			len(permission.Ipv6Ranges) == 0 && len(permission.PrefixListIds) == 0 && len(permission.UserIdGroupPairs) == 0 {
			sentinel++
			continue
		}
		if stringValue(permission.IpProtocol) == "tcp" && aws.ToInt32(permission.FromPort) == 443 && aws.ToInt32(permission.ToPort) == 443 &&
			len(permission.PrefixListIds) == 1 && stringValue(permission.PrefixListIds[0].PrefixListId) == prefixListID && len(permission.IpRanges) == 0 &&
			len(permission.Ipv6Ranges) == 0 && len(permission.UserIdGroupPairs) == 0 {
			s3Rule++
			continue
		}
		return false
	}
	return sentinel == 1 && s3Rule <= 1
}

func validFoundationRouteTable(routeTable ec2types.RouteTable, input workerami.BuildEnvironmentV1) bool {
	if stringValue(routeTable.RouteTableId) != input.FoundationRouteTableID || stringValue(routeTable.VpcId) != input.FoundationVPCID {
		return false
	}
	localRoutes, s3Routes := 0, 0
	for _, route := range routeTable.Routes {
		if stringValue(route.GatewayId) == "local" && route.State == ec2types.RouteStateActive && stringValue(route.DestinationCidrBlock) != "" && stringValue(route.DestinationPrefixListId) == "" {
			localRoutes++
			continue
		}
		endpointID := stringValue(route.GatewayId)
		if stringValue(route.DestinationPrefixListId) == input.S3PrefixListID && endpointPattern.MatchString(endpointID) && route.State == ec2types.RouteStateActive &&
			(input.ExpectedVPCEndpointID == "" || endpointID == input.ExpectedVPCEndpointID) {
			s3Routes++
			continue
		}
		return false
	}
	if localRoutes != 1 || s3Routes > 1 {
		return false
	}
	// Both the absent and exact transient states are valid at preflight: a
	// response may have been lost before its ID was recorded, or a completed
	// cleanup may already have removed the recorded resource. Preparation and
	// cleanup subsequently require exact tags/IDs before any mutation.
	return true
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
