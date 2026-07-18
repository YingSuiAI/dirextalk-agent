package awsadapter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type fakeCloudFormation struct {
	output *cloudformation.DescribeStacksOutput
	err    error
}

func (fake *fakeCloudFormation) DescribeStacks(context.Context, *cloudformation.DescribeStacksInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {
	return fake.output, fake.err
}

func TestV2EnvironmentRechecksFoundationCanonicalBaseAndPrivateRoute(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*workerami.BuildEnvironmentV1, *fakeEC2, *fakeCloudFormation)
	}{
		{name: "valid"},
		{name: "recorded reachability already absent", mutate: func(environment *workerami.BuildEnvironmentV1, _ *fakeEC2, _ *fakeCloudFormation) {
			environment.ExpectedVPCEndpointID = "vpce-0123456789abcdef0"
		}},
		{name: "stack output drift", mutate: func(_ *workerami.BuildEnvironmentV1, _ *fakeEC2, cf *fakeCloudFormation) {
			cf.output.Stacks[0].Outputs[0].OutputValue = aws.String("subnet-11111111111111111")
		}},
		{name: "public internet egress even in test mode", mutate: func(_ *workerami.BuildEnvironmentV1, client *fakeEC2, _ *fakeCloudFormation) {
			client.describeSecurityGroupsFn = func(*ec2.DescribeSecurityGroupsInput) (*ec2.DescribeSecurityGroupsOutput, error) {
				return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []ec2types.SecurityGroup{{GroupId: aws.String(testSG), VpcId: aws.String("vpc-0123456789abcdef0"), IpPermissionsEgress: []ec2types.IpPermission{{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(443), ToPort: aws.Int32(443), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}}}}}}, nil
			}
		}},
		{name: "base image drift", mutate: func(_ *workerami.BuildEnvironmentV1, client *fakeEC2, _ *fakeCloudFormation) {
			client.describeImagesFn = func(*ec2.DescribeImagesInput) (*ec2.DescribeImagesOutput, error) {
				image := canonicalBaseFixture()
				image.Name = aws.String("ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-20260718")
				return &ec2.DescribeImagesOutput{Images: []ec2types.Image{image}}, nil
			}
		}},
		{name: "internet route", mutate: func(_ *workerami.BuildEnvironmentV1, client *fakeEC2, _ *fakeCloudFormation) {
			client.describeRouteTablesFn = func(*ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
				return &ec2.DescribeRouteTablesOutput{RouteTables: []ec2types.RouteTable{{RouteTableId: aws.String("rtb-0123456789abcdef0"), VpcId: aws.String("vpc-0123456789abcdef0"), Routes: []ec2types.Route{{DestinationCidrBlock: aws.String("0.0.0.0/0"), GatewayId: aws.String("igw-0123456789abcdef0"), State: ec2types.RouteStateActive}}}}}, nil
			}
		}},
		{name: "partial recovery after lost rule response", mutate: func(environment *workerami.BuildEnvironmentV1, client *fakeEC2, _ *fakeCloudFormation) {
			environment.ExpectedVPCEndpointID = "vpce-0123456789abcdef0"
			client.describeSecurityGroupsFn = func(*ec2.DescribeSecurityGroupsInput) (*ec2.DescribeSecurityGroupsOutput, error) {
				return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []ec2types.SecurityGroup{{GroupId: aws.String(testSG), VpcId: aws.String(environment.FoundationVPCID), IpPermissionsEgress: append(foundationSentinelEgress(), foundationS3Egress(environment.S3PrefixListID))}}}, nil
			}
			client.describeRouteTablesFn = func(*ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
				return &ec2.DescribeRouteTablesOutput{RouteTables: []ec2types.RouteTable{
					{RouteTableId: aws.String(environment.FoundationRouteTableID), VpcId: aws.String(environment.FoundationVPCID), Routes: []ec2types.Route{
						{DestinationCidrBlock: aws.String("10.255.0.0/24"), GatewayId: aws.String("local"), State: ec2types.RouteStateActive},
						{DestinationPrefixListId: aws.String(environment.S3PrefixListID), GatewayId: aws.String(environment.ExpectedVPCEndpointID), State: ec2types.RouteStateActive},
					}},
				}}, nil
			}
		}},
		{name: "unrecorded reachability after lost endpoint response", mutate: func(environment *workerami.BuildEnvironmentV1, client *fakeEC2, _ *fakeCloudFormation) {
			client.describeSecurityGroupsFn = func(*ec2.DescribeSecurityGroupsInput) (*ec2.DescribeSecurityGroupsOutput, error) {
				return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []ec2types.SecurityGroup{{GroupId: aws.String(testSG), VpcId: aws.String(environment.FoundationVPCID), IpPermissionsEgress: append(foundationSentinelEgress(), foundationS3Egress(environment.S3PrefixListID))}}}, nil
			}
			client.describeRouteTablesFn = func(*ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
				return &ec2.DescribeRouteTablesOutput{RouteTables: []ec2types.RouteTable{
					{RouteTableId: aws.String(environment.FoundationRouteTableID), VpcId: aws.String(environment.FoundationVPCID), Routes: []ec2types.Route{
						{DestinationCidrBlock: aws.String("10.255.0.0/24"), GatewayId: aws.String("local"), State: ec2types.RouteStateActive},
						{DestinationPrefixListId: aws.String(environment.S3PrefixListID), GatewayId: aws.String("vpce-0123456789abcdef0"), State: ec2types.RouteStateActive},
					}},
				}}, nil
			}
		}},
		{name: "ambiguous unrecorded S3 rules", mutate: func(environment *workerami.BuildEnvironmentV1, client *fakeEC2, _ *fakeCloudFormation) {
			client.describeSecurityGroupsFn = func(*ec2.DescribeSecurityGroupsInput) (*ec2.DescribeSecurityGroupsOutput, error) {
				return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []ec2types.SecurityGroup{{GroupId: aws.String(testSG), VpcId: aws.String(environment.FoundationVPCID), IpPermissionsEgress: append(foundationSentinelEgress(), foundationS3Egress(environment.S3PrefixListID), foundationS3Egress(environment.S3PrefixListID))}}}, nil
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment, ec2Client, s3Client, cfClient := validV2Environment(t)
			if test.mutate != nil {
				test.mutate(&environment, ec2Client, cfClient)
			}
			presign := &fakePresign{fn: func(*s3.GetObjectInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
				panic("unexpected presign")
			}}
			adapter, err := newAdapter(Config{Region: testRegion, AccountID: testAccount, AllowTestHTTPSInternetEgress: true}, ec2Client, s3Client, presign, cfClient)
			if err != nil {
				t.Fatal(err)
			}
			err = adapter.ValidateEnvironment(context.Background(), environment)
			if test.name == "valid" || test.name == "recorded reachability already absent" || test.name == "partial recovery after lost rule response" || test.name == "unrecorded reachability after lost endpoint response" {
				if err != nil {
					t.Fatalf("ValidateEnvironment() = %v", err)
				}
			} else if !errors.Is(err, workerami.ErrReadBackMismatch) {
				t.Fatalf("ValidateEnvironment(%s) = %v", test.name, err)
			}
		})
	}
}

func TestCanonicalNobleReadBackAcceptsScheduledDeprecationAndVirtualMappings(t *testing.T) {
	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	image := canonicalBaseFixture()
	image.DeprecationTime = aws.String("2028-07-14T11:54:30Z")
	image.BlockDeviceMappings = append(image.BlockDeviceMappings,
		ec2types.BlockDeviceMapping{DeviceName: aws.String("/dev/sdb"), VirtualName: aws.String("ephemeral0")},
		ec2types.BlockDeviceMapping{DeviceName: aws.String("/dev/sdc"), VirtualName: aws.String("ephemeral1")},
	)
	if !validBaseImage(image, validV2BuildEnvironmentForImage()) || !ValidCanonicalNobleSourceImageAt(image, now) {
		t.Fatal("current official Canonical image shape was rejected")
	}

	tests := []struct {
		name   string
		mutate func(*ec2types.Image)
	}{
		{name: "already deprecated", mutate: func(current *ec2types.Image) { current.DeprecationTime = aws.String("2026-07-18T23:59:59Z") }},
		{name: "non-root EBS", mutate: func(current *ec2types.Image) {
			current.BlockDeviceMappings[1].VirtualName = nil
			current.BlockDeviceMappings[1].Ebs = &ec2types.EbsBlockDevice{SnapshotId: aws.String("snap-11111111111111111"), VolumeType: ec2types.VolumeTypeGp3, VolumeSize: aws.Int32(8), DeleteOnTermination: aws.Bool(true)}
		}},
		{name: "wrong root snapshot", mutate: func(current *ec2types.Image) { current.BlockDeviceMappings[0].Ebs.SnapshotId = nil }},
		{name: "wrong root storage", mutate: func(current *ec2types.Image) { current.BlockDeviceMappings[0].Ebs.VolumeType = ec2types.VolumeTypeGp2 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := image
			changed.BlockDeviceMappings = append([]ec2types.BlockDeviceMapping(nil), image.BlockDeviceMappings...)
			rootEBS := *image.BlockDeviceMappings[0].Ebs
			changed.BlockDeviceMappings[0].Ebs = &rootEBS
			test.mutate(&changed)
			if validBaseImage(changed, validV2BuildEnvironmentForImage()) && ValidCanonicalNobleSourceImageAt(changed, now) {
				t.Fatal("invalid Canonical source image was accepted")
			}
		})
	}
}

func validV2BuildEnvironmentForImage() workerami.BuildEnvironmentV1 {
	return workerami.BuildEnvironmentV1{Architecture: "amd64", BaseAMIID: testAMI, BaseAMIOwnerID: testOwner, RootDeviceName: "/dev/sda1"}
}

func validV2Environment(t *testing.T) (workerami.BuildEnvironmentV1, *fakeEC2, *fakeS3, *fakeCloudFormation) {
	t.Helper()
	environment := workerami.BuildEnvironmentV1{Region: testRegion, AccountID: testAccount, AgentInstanceID: "11111111-1111-4111-8111-111111111111", Architecture: "amd64",
		BaseAMIID: testAMI, BaseAMIOwnerID: testOwner, PrivateSubnetID: testSubnet, ZeroIngressSGID: testSG, ArtifactBucket: "dtx-worker-artifacts",
		ArtifactKMSKeyARN: testKMS, BuilderInstanceType: "t3.small", RootDeviceName: "/dev/sda1", NetworkMode: workerami.NetworkModeS3GatewayV2,
		FoundationStackName: "dtx-agent-abc-foundation", FoundationStackID: "arn:aws:cloudformation:us-west-2:123456789012:stack/dtx-agent-abc-foundation/11111111-2222-4333-8444-555555555555",
		FoundationVPCID: "vpc-0123456789abcdef0", FoundationRouteTableID: "rtb-0123456789abcdef0", S3PrefixListID: "pl-0123456789abcdef0"}
	ec2Client, s3Client := validEnvironmentClients(t)
	ec2Client.describeImagesFn = func(*ec2.DescribeImagesInput) (*ec2.DescribeImagesOutput, error) {
		return &ec2.DescribeImagesOutput{Images: []ec2types.Image{canonicalBaseFixture()}}, nil
	}
	ec2Client.describeSecurityGroupsFn = func(*ec2.DescribeSecurityGroupsInput) (*ec2.DescribeSecurityGroupsOutput, error) {
		return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []ec2types.SecurityGroup{{GroupId: aws.String(testSG), VpcId: aws.String(environment.FoundationVPCID), IpPermissionsEgress: foundationSentinelEgress()}}}, nil
	}
	ec2Client.describePrefixListsFn = func(*ec2.DescribePrefixListsInput) (*ec2.DescribePrefixListsOutput, error) {
		return &ec2.DescribePrefixListsOutput{PrefixLists: []ec2types.PrefixList{{PrefixListId: aws.String(environment.S3PrefixListID), PrefixListName: aws.String("com.amazonaws." + testRegion + ".s3")}}}, nil
	}
	ec2Client.describeRouteTablesFn = func(*ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		return &ec2.DescribeRouteTablesOutput{RouteTables: []ec2types.RouteTable{{RouteTableId: aws.String(environment.FoundationRouteTableID), VpcId: aws.String(environment.FoundationVPCID), Routes: []ec2types.Route{{DestinationCidrBlock: aws.String("10.255.0.0/24"), GatewayId: aws.String("local"), State: ec2types.RouteStateActive}}}}}, nil
	}
	stack := cftypes.Stack{StackName: aws.String(environment.FoundationStackName), StackId: aws.String(environment.FoundationStackID), StackStatus: cftypes.StackStatusCreateComplete,
		Parameters: []cftypes.Parameter{{ParameterKey: aws.String("AgentInstanceId"), ParameterValue: aws.String(environment.AgentInstanceID)}}, Outputs: []cftypes.Output{
			{OutputKey: aws.String("ReleasePrivateSubnetId"), OutputValue: aws.String(environment.PrivateSubnetID)},
			{OutputKey: aws.String("ReleaseZeroIngressSecurityGroupId"), OutputValue: aws.String(environment.ZeroIngressSGID)},
			{OutputKey: aws.String("ArtifactBucketName"), OutputValue: aws.String(environment.ArtifactBucket)},
			{OutputKey: aws.String("FoundationKeyArn"), OutputValue: aws.String(environment.ArtifactKMSKeyARN)},
		}}
	return environment, ec2Client, s3Client, &fakeCloudFormation{output: &cloudformation.DescribeStacksOutput{Stacks: []cftypes.Stack{stack}}}
}

func foundationSentinelEgress() []ec2types.IpPermission {
	return []ec2types.IpPermission{{IpProtocol: aws.String("-1"), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("127.0.0.1/32")}}}}
}

func foundationS3Egress(prefixListID string) ec2types.IpPermission {
	return ec2types.IpPermission{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(443), ToPort: aws.Int32(443), PrefixListIds: []ec2types.PrefixListId{{PrefixListId: aws.String(prefixListID)}}}
}

func canonicalBaseFixture() ec2types.Image {
	image := baseImageFixture()
	image.Public = aws.Bool(true)
	image.VirtualizationType = ec2types.VirtualizationTypeHvm
	image.PlatformDetails = aws.String("Linux/UNIX")
	image.Name = aws.String("ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-20260718")
	image.BlockDeviceMappings[0].Ebs.VolumeType = ec2types.VolumeTypeGp3
	image.BlockDeviceMappings[0].Ebs.VolumeSize = aws.Int32(8)
	image.BlockDeviceMappings[0].Ebs.DeleteOnTermination = aws.Bool(true)
	return image
}
