package workeramictl

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestValidateFoundationStackRejectsAccountRegionAndOutputDrift(t *testing.T) {
	request := PrepareEnvironmentRequestV2{AccountID: "123456789012", Region: "us-east-1", AgentInstanceID: "11111111-1111-4111-8111-111111111111"}
	stack := validPrepareStack(request)
	if _, _, err := validateFoundationStack(stack, request, "dtx-agent-abc-foundation", "dtx-agent-bucket", "dtx-agent-table", "dtx-agent-worker", "dtx/11111111-1111-4111-8111-111111111111/deployments/", "dtx-agent-reaper"); err != nil {
		t.Fatalf("valid stack = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*cftypes.Stack, *PrepareEnvironmentRequestV2)
	}{
		{name: "account", mutate: func(_ *cftypes.Stack, current *PrepareEnvironmentRequestV2) { current.AccountID = "999999999999" }},
		{name: "region", mutate: func(_ *cftypes.Stack, current *PrepareEnvironmentRequestV2) { current.Region = "us-west-2" }},
		{name: "bucket output", mutate: func(current *cftypes.Stack, _ *PrepareEnvironmentRequestV2) {
			setPrepareOutput(current, "ArtifactBucketName", "different-bucket")
		}},
		{name: "vpc output", mutate: func(current *cftypes.Stack, _ *PrepareEnvironmentRequestV2) {
			setPrepareOutput(current, "ReleaseVPCId", "vpc-invalid")
		}},
		{name: "route table output", mutate: func(current *cftypes.Stack, _ *PrepareEnvironmentRequestV2) {
			setPrepareOutput(current, "ReleasePrivateRouteTableId", "rtb-invalid")
		}},
		{name: "missing route table output", mutate: func(current *cftypes.Stack, _ *PrepareEnvironmentRequestV2) {
			current.Outputs = current.Outputs[:len(current.Outputs)-1]
		}},
		{name: "duplicate output", mutate: func(current *cftypes.Stack, _ *PrepareEnvironmentRequestV2) {
			current.Outputs = append(current.Outputs, current.Outputs[0])
		}},
		{name: "unstable stack", mutate: func(current *cftypes.Stack, _ *PrepareEnvironmentRequestV2) {
			current.StackStatus = cftypes.StackStatusUpdateInProgress
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changedStack := validPrepareStack(request)
			changedRequest := request
			test.mutate(&changedStack, &changedRequest)
			if _, _, err := validateFoundationStack(changedStack, changedRequest, "dtx-agent-abc-foundation", "dtx-agent-bucket", "dtx-agent-table", "dtx-agent-worker", "dtx/11111111-1111-4111-8111-111111111111/deployments/", "dtx-agent-reaper"); err == nil {
				t.Fatal("drifted stack was accepted")
			}
		})
	}
}

func TestSelectCurrentCanonicalBaseRejectsOwnerAndNewestAmbiguity(t *testing.T) {
	older := canonicalPrepareImage("ami-0123456789abcdef0", "2026-07-17T00:00:00Z")
	newer := canonicalPrepareImage("ami-11111111111111111", "2026-07-18T00:00:00Z")
	selected, err := selectCurrentCanonicalBase([]ec2types.Image{older, newer})
	if err != nil || aws.ToString(selected.ImageId) != aws.ToString(newer.ImageId) {
		t.Fatalf("selectCurrentCanonicalBase() = %#v, %v", selected, err)
	}
	tie := canonicalPrepareImage("ami-22222222222222222", "2026-07-18T00:00:00Z")
	if _, err := selectCurrentCanonicalBase([]ec2types.Image{newer, tie}); err == nil {
		t.Fatal("same-time newest AMIs were not rejected as ambiguous")
	}
	newer.OwnerId = aws.String("999999999999")
	if _, err := selectCurrentCanonicalBase([]ec2types.Image{newer}); err == nil {
		t.Fatal("non-Canonical owner was accepted")
	}
}

func TestSelectCurrentCanonicalBaseAcceptsScheduledDeprecationAndVirtualMappings(t *testing.T) {
	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	image := canonicalPrepareImage("ami-0123456789abcdef0", "2026-07-14T11:54:30Z")
	image.DeprecationTime = aws.String("2028-07-14T11:54:30Z")
	image.BlockDeviceMappings = append(image.BlockDeviceMappings,
		ec2types.BlockDeviceMapping{DeviceName: aws.String("/dev/sdb"), VirtualName: aws.String("ephemeral0")},
		ec2types.BlockDeviceMapping{DeviceName: aws.String("/dev/sdc"), VirtualName: aws.String("ephemeral1")},
	)
	selected, err := selectCurrentCanonicalBaseAt([]ec2types.Image{image}, now)
	if err != nil || aws.ToString(selected.ImageId) != aws.ToString(image.ImageId) {
		t.Fatalf("selectCurrentCanonicalBaseAt() = %#v, %v", selected, err)
	}

	tests := []struct {
		name   string
		mutate func(*ec2types.Image)
	}{
		{name: "already deprecated", mutate: func(current *ec2types.Image) { current.DeprecationTime = aws.String("2026-07-18T23:59:59Z") }},
		{name: "invalid deprecation time", mutate: func(current *ec2types.Image) { current.DeprecationTime = aws.String("later") }},
		{name: "non-root EBS mapping", mutate: func(current *ec2types.Image) {
			current.BlockDeviceMappings[1].VirtualName = nil
			current.BlockDeviceMappings[1].Ebs = &ec2types.EbsBlockDevice{SnapshotId: aws.String("snap-11111111111111111"), VolumeType: ec2types.VolumeTypeGp3, VolumeSize: aws.Int32(8), DeleteOnTermination: aws.Bool(true)}
		}},
		{name: "root snapshot missing", mutate: func(current *ec2types.Image) { current.BlockDeviceMappings[0].Ebs.SnapshotId = nil }},
		{name: "root storage class", mutate: func(current *ec2types.Image) { current.BlockDeviceMappings[0].Ebs.VolumeType = ec2types.VolumeTypeGp2 }},
		{name: "root retained", mutate: func(current *ec2types.Image) {
			current.BlockDeviceMappings[0].Ebs.DeleteOnTermination = aws.Bool(false)
		}},
		{name: "wrong architecture", mutate: func(current *ec2types.Image) { current.Architecture = ec2types.ArchitectureValuesArm64 }},
		{name: "unavailable", mutate: func(current *ec2types.Image) { current.State = ec2types.ImageStatePending }},
		{name: "wrong product", mutate: func(current *ec2types.Image) {
			current.Name = aws.String("ubuntu/images/hvm-ssd-gp3/ubuntu-jammy-22.04-amd64-server-20260714")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := image
			changed.BlockDeviceMappings = append([]ec2types.BlockDeviceMapping(nil), image.BlockDeviceMappings...)
			rootEBS := *image.BlockDeviceMappings[0].Ebs
			changed.BlockDeviceMappings[0].Ebs = &rootEBS
			test.mutate(&changed)
			if _, err := selectCurrentCanonicalBaseAt([]ec2types.Image{changed}, now); err == nil {
				t.Fatal("invalid Canonical source image was accepted")
			}
		})
	}
}

func TestSelectFoundationRouteTableRejectsAmbiguousOrNonLocalRouting(t *testing.T) {
	subnetID, vpcID, routeTableID := "subnet-0123456789abcdef0", "vpc-0123456789abcdef0", "rtb-0123456789abcdef0"
	valid := ec2types.RouteTable{RouteTableId: aws.String("rtb-0123456789abcdef0"), VpcId: aws.String(vpcID),
		Associations: []ec2types.RouteTableAssociation{{SubnetId: aws.String(subnetID)}}, Routes: []ec2types.Route{{GatewayId: aws.String("local"), DestinationCidrBlock: aws.String("10.255.0.0/24"), State: ec2types.RouteStateActive}}}
	if selected, err := selectFoundationRouteTable([]ec2types.RouteTable{valid}, routeTableID, subnetID, vpcID); err != nil || selected != aws.ToString(valid.RouteTableId) {
		t.Fatalf("selectFoundationRouteTable() = %q, %v", selected, err)
	}
	duplicate := valid
	duplicate.RouteTableId = aws.String("rtb-11111111111111111")
	if _, err := selectFoundationRouteTable([]ec2types.RouteTable{valid, duplicate}, routeTableID, subnetID, vpcID); err == nil {
		t.Fatal("ambiguous main route tables were accepted")
	}
	public := valid
	public.Routes = append(public.Routes, ec2types.Route{GatewayId: aws.String("igw-0123456789abcdef0"), DestinationCidrBlock: aws.String("0.0.0.0/0"), State: ec2types.RouteStateActive})
	if _, err := selectFoundationRouteTable([]ec2types.RouteTable{public}, routeTableID, subnetID, vpcID); err == nil {
		t.Fatal("public route table was accepted")
	}
	valid.RouteTableId = aws.String("rtb-11111111111111111")
	if _, err := selectFoundationRouteTable([]ec2types.RouteTable{valid}, routeTableID, subnetID, vpcID); err == nil {
		t.Fatal("route table output drift was accepted")
	}
}

func TestValidateFoundationVPCRequiresExactOutputAndFoundationFacts(t *testing.T) {
	agentID, vpcID := "11111111-1111-4111-8111-111111111111", "vpc-0123456789abcdef0"
	valid := ec2types.Vpc{VpcId: aws.String(vpcID), State: ec2types.VpcStateAvailable, CidrBlock: aws.String("10.255.0.0/24"),
		InstanceTenancy: ec2types.TenancyDefault, IsDefault: aws.Bool(false), Tags: []ec2types.Tag{
			{Key: aws.String("dirextalk:agent_instance_id"), Value: aws.String(agentID)}, {Key: aws.String("dirextalk:component"), Value: aws.String("foundation-release")},
		}}
	if err := validateFoundationVPC([]ec2types.Vpc{valid}, vpcID, agentID); err != nil {
		t.Fatalf("validateFoundationVPC() = %v", err)
	}
	valid.VpcId = aws.String("vpc-11111111111111111")
	if err := validateFoundationVPC([]ec2types.Vpc{valid}, vpcID, agentID); err == nil {
		t.Fatal("VPC output drift was accepted")
	}
}

func validPrepareStack(request PrepareEnvironmentRequestV2) cftypes.Stack {
	return cftypes.Stack{StackName: aws.String("dtx-agent-abc-foundation"),
		StackId: aws.String("arn:aws:cloudformation:" + request.Region + ":" + request.AccountID + ":stack/dtx-agent-abc-foundation/11111111-2222-4333-8444-555555555555"), StackStatus: cftypes.StackStatusCreateComplete,
		Parameters: []cftypes.Parameter{
			{ParameterKey: aws.String("AgentInstanceId"), ParameterValue: aws.String(request.AgentInstanceID)}, {ParameterKey: aws.String("ArtifactBucketName"), ParameterValue: aws.String("dtx-agent-bucket")},
			{ParameterKey: aws.String("ManifestTableName"), ParameterValue: aws.String("dtx-agent-table")}, {ParameterKey: aws.String("WorkerProfileName"), ParameterValue: aws.String("dtx-agent-worker")},
			{ParameterKey: aws.String("SecretNamespace"), ParameterValue: aws.String("dtx/11111111-1111-4111-8111-111111111111/deployments/")},
		}, Outputs: []cftypes.Output{
			{OutputKey: aws.String("ReleaseVPCId"), OutputValue: aws.String("vpc-0123456789abcdef0")}, {OutputKey: aws.String("ReleasePrivateSubnetId"), OutputValue: aws.String("subnet-0123456789abcdef0")},
			{OutputKey: aws.String("ReleasePrivateRouteTableId"), OutputValue: aws.String("rtb-0123456789abcdef0")}, {OutputKey: aws.String("ReleaseZeroIngressSecurityGroupId"), OutputValue: aws.String("sg-0123456789abcdef0")},
			{OutputKey: aws.String("ArtifactBucketName"), OutputValue: aws.String("dtx-agent-bucket")}, {OutputKey: aws.String("FoundationKeyArn"), OutputValue: aws.String("arn:aws:kms:us-east-1:123456789012:key/11111111-2222-4333-8444-555555555555")},
			{OutputKey: aws.String("ManifestTableName"), OutputValue: aws.String("dtx-agent-table")}, {OutputKey: aws.String("WorkerInstanceProfileArn"), OutputValue: aws.String("arn:aws:iam::123456789012:instance-profile/dtx-agent-worker")},
			{OutputKey: aws.String("SecretNamespace"), OutputValue: aws.String("dtx/11111111-1111-4111-8111-111111111111/deployments/")}, {OutputKey: aws.String("ReaperFunctionArn"), OutputValue: aws.String("arn:aws:lambda:us-east-1:123456789012:function:dtx-agent-reaper")},
		}}
}

func setPrepareOutput(stack *cftypes.Stack, key, value string) {
	for index := range stack.Outputs {
		if aws.ToString(stack.Outputs[index].OutputKey) == key {
			stack.Outputs[index].OutputValue = aws.String(value)
			return
		}
	}
}

func canonicalPrepareImage(id, created string) ec2types.Image {
	return ec2types.Image{ImageId: aws.String(id), OwnerId: aws.String(canonicalUbuntuOwnerID), Public: aws.Bool(true), State: ec2types.ImageStateAvailable,
		Architecture: ec2types.ArchitectureValuesX8664, RootDeviceType: ec2types.DeviceTypeEbs, VirtualizationType: ec2types.VirtualizationTypeHvm,
		PlatformDetails: aws.String("Linux/UNIX"), Name: aws.String("ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-20260718"),
		CreationDate: aws.String(created), RootDeviceName: aws.String("/dev/sda1"), BlockDeviceMappings: []ec2types.BlockDeviceMapping{{DeviceName: aws.String("/dev/sda1"), Ebs: &ec2types.EbsBlockDevice{
			SnapshotId: aws.String("snap-0123456789abcdef0"), VolumeType: ec2types.VolumeTypeGp3, VolumeSize: aws.Int32(8), DeleteOnTermination: aws.Bool(true),
		}}}}
}
