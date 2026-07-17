package awsprovider

import (
	"context"
	"errors"
	"slices"
	"testing"

	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type fakePlacementEC2 struct {
	vpcPages      map[string]*ec2.DescribeVpcsOutput
	subnetPages   map[string]*ec2.DescribeSubnetsOutput
	routePages    map[string]*ec2.DescribeRouteTablesOutput
	gatewayPages  map[string]*ec2.DescribeInternetGatewaysOutput
	natPages      map[string]*ec2.DescribeNatGatewaysOutput
	typePages     map[string]*ec2.DescribeInstanceTypesOutput
	offeringPages map[string]*ec2.DescribeInstanceTypeOfferingsOutput
	zones         *ec2.DescribeAvailabilityZonesOutput
}

func (fake *fakePlacementEC2) DescribeVpcs(_ context.Context, input *ec2.DescribeVpcsInput, _ ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	return page(fake.vpcPages, input.NextToken), nil
}

func (fake *fakePlacementEC2) DescribeSubnets(_ context.Context, input *ec2.DescribeSubnetsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	return page(fake.subnetPages, input.NextToken), nil
}

func (fake *fakePlacementEC2) DescribeAvailabilityZones(_ context.Context, _ *ec2.DescribeAvailabilityZonesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAvailabilityZonesOutput, error) {
	return fake.zones, nil
}

func (fake *fakePlacementEC2) DescribeRouteTables(_ context.Context, input *ec2.DescribeRouteTablesInput, _ ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	return page(fake.routePages, input.NextToken), nil
}

func (fake *fakePlacementEC2) DescribeInternetGateways(_ context.Context, input *ec2.DescribeInternetGatewaysInput, _ ...func(*ec2.Options)) (*ec2.DescribeInternetGatewaysOutput, error) {
	return page(fake.gatewayPages, input.NextToken), nil
}

func (fake *fakePlacementEC2) DescribeNatGateways(_ context.Context, input *ec2.DescribeNatGatewaysInput, _ ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error) {
	return page(fake.natPages, input.NextToken), nil
}

func (fake *fakePlacementEC2) DescribeInstanceTypes(_ context.Context, input *ec2.DescribeInstanceTypesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error) {
	return page(fake.typePages, input.NextToken), nil
}

func (fake *fakePlacementEC2) DescribeInstanceTypeOfferings(_ context.Context, input *ec2.DescribeInstanceTypeOfferingsInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceTypeOfferingsOutput, error) {
	return page(fake.offeringPages, input.NextToken), nil
}

func page[T any](pages map[string]*T, token *string) *T {
	key := aws.ToString(token)
	return pages[key]
}

func TestPlacementResolverRequiresEffectiveIGWRoute(t *testing.T) {
	fake := placementFixture()
	fake.routePages = map[string]*ec2.DescribeRouteTablesOutput{"": {
		RouteTables: []ec2types.RouteTable{{
			VpcId: aws.String(testPlacementVPC), Associations: []ec2types.RouteTableAssociation{{SubnetId: aws.String(testPlacementSubnet)}},
			Routes: []ec2types.Route{{DestinationCidrBlock: aws.String("0.0.0.0/0"), NatGatewayId: aws.String("nat-0123456789abcdef0"), State: ec2types.RouteStateActive}},
		}},
	}}
	// MapPublicIpOnLaunch is deliberately not accepted as evidence that an
	// independently created ENI and EIP have a usable internet path.
	fake.subnetPages[""].Subnets[0].MapPublicIpOnLaunch = aws.Bool(true)

	resolver, err := newPlacementResolver(fake, testPlacementRegion)
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolver.Resolve(context.Background(), testPlacementRequest())
	if !errors.Is(err, ErrPlacementNetworkUnavailable) {
		t.Fatalf("Resolve error = %v, want ErrPlacementNetworkUnavailable", err)
	}
}

func TestPlacementResolverUsesMainRouteOnlyWhenSubnetHasNoExplicitRouteTable(t *testing.T) {
	fake := placementFixture()
	fake.routePages[""].RouteTables[0].Associations = []ec2types.RouteTableAssociation{{Main: aws.Bool(true)}}

	resolver, err := newPlacementResolver(fake, testPlacementRegion)
	if err != nil {
		t.Fatal(err)
	}
	got, err := resolver.Resolve(context.Background(), testPlacementRequest())
	if err != nil {
		t.Fatal(err)
	}
	if got.Network.SubnetID != testPlacementSubnet || !got.Network.PublicIPv4 {
		t.Fatalf("main-route placement = %#v", got.Network)
	}
}

func TestPlacementResolverRequiresPublicNATEgressForPrivateWorker(t *testing.T) {
	request := testPlacementRequest()
	request.PublicIPv4 = false

	t.Run("rejects a private subnet without an active public NAT route", func(t *testing.T) {
		fake := placementFixture()
		fake.routePages[""].RouteTables[0].Routes = []ec2types.Route{{DestinationCidrBlock: aws.String("0.0.0.0/0"), NatGatewayId: aws.String("nat-0123456789abcdef0"), State: ec2types.RouteStateActive}}
		resolver, err := newPlacementResolver(fake, testPlacementRegion)
		if err != nil {
			t.Fatal(err)
		}
		_, err = resolver.Resolve(context.Background(), request)
		if !errors.Is(err, ErrPlacementNetworkUnavailable) {
			t.Fatalf("Resolve error = %v, want ErrPlacementNetworkUnavailable", err)
		}
	})

	t.Run("accepts a private subnet only through an active public NAT with IGW egress", func(t *testing.T) {
		fake := placementFixture()
		const natSubnet = "subnet-0fedcba9876543210"
		fake.routePages[""] = &ec2.DescribeRouteTablesOutput{RouteTables: []ec2types.RouteTable{
			{VpcId: aws.String(testPlacementVPC), Associations: []ec2types.RouteTableAssociation{{SubnetId: aws.String(testPlacementSubnet)}},
				Routes: []ec2types.Route{{DestinationCidrBlock: aws.String("0.0.0.0/0"), NatGatewayId: aws.String("nat-0123456789abcdef0"), State: ec2types.RouteStateActive}}},
			{VpcId: aws.String(testPlacementVPC), Associations: []ec2types.RouteTableAssociation{{SubnetId: aws.String(natSubnet)}},
				Routes: []ec2types.Route{{DestinationCidrBlock: aws.String("0.0.0.0/0"), GatewayId: aws.String(testPlacementIGW), State: ec2types.RouteStateActive}}},
		}}
		fake.natPages = map[string]*ec2.DescribeNatGatewaysOutput{"": {NatGateways: []ec2types.NatGateway{{NatGatewayId: aws.String("nat-0123456789abcdef0"), VpcId: aws.String(testPlacementVPC), SubnetId: aws.String(natSubnet), State: ec2types.NatGatewayStateAvailable, ConnectivityType: ec2types.ConnectivityTypePublic, NatGatewayAddresses: []ec2types.NatGatewayAddress{{PublicIp: aws.String("198.51.100.10")}}}}}}
		resolver, err := newPlacementResolver(fake, testPlacementRegion)
		if err != nil {
			t.Fatal(err)
		}
		got, err := resolver.Resolve(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if got.Network.PublicIPv4 || got.Usage.PublicIPv4Hours != 0 || got.Network.SubnetID != testPlacementSubnet {
			t.Fatalf("private NAT placement = %#v usage=%#v", got.Network, got.Usage)
		}
	})
}

func TestPlacementResolverRejectsInsufficientCandidateChain(t *testing.T) {
	fake := placementFixture()
	fake.typePages = map[string]*ec2.DescribeInstanceTypesOutput{"": {InstanceTypes: []ec2types.InstanceTypeInfo{
		placementInstanceInfo("m7i.large", 2, 8192), placementInstanceInfo("m7i.xlarge", 4, 16384),
	}}}
	fake.offeringPages = map[string]*ec2.DescribeInstanceTypeOfferingsOutput{"": {InstanceTypeOfferings: []ec2types.InstanceTypeOffering{
		placementOffering("m7i.large"), placementOffering("m7i.xlarge"),
	}}}

	resolver, err := newPlacementResolver(fake, testPlacementRegion)
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolver.Resolve(context.Background(), testPlacementRequest())
	if !errors.Is(err, ErrPlacementCapacityUnavailable) {
		t.Fatalf("Resolve error = %v, want ErrPlacementCapacityUnavailable", err)
	}
}

func TestPlacementResolverDeterministicallyResolvesThreeCandidatesAcrossUnorderedPages(t *testing.T) {
	fake := placementFixture()
	// Deliberately scramble both page order and item order. The resolver must not
	// let AWS response ordering alter the signed scope later built from this fact.
	fake.vpcPages = map[string]*ec2.DescribeVpcsOutput{
		"":      {Vpcs: []ec2types.Vpc{{VpcId: aws.String("vpc-0aaaaaaaaaaaaaaaa"), State: ec2types.VpcStateAvailable}}, NextToken: aws.String("vpc-2")},
		"vpc-2": {Vpcs: []ec2types.Vpc{{VpcId: aws.String(testPlacementVPC), State: ec2types.VpcStateAvailable, IsDefault: aws.Bool(true)}}},
	}
	fake.typePages = map[string]*ec2.DescribeInstanceTypesOutput{
		"":        {InstanceTypes: []ec2types.InstanceTypeInfo{placementInstanceInfo("m7i.2xlarge", 8, 32768), placementInstanceInfo("z1d.large", 2, 16384)}, NextToken: aws.String("types-2")},
		"types-2": {InstanceTypes: []ec2types.InstanceTypeInfo{placementInstanceInfo("m7i.xlarge", 4, 16384), placementInstanceInfo("t3.small", 2, 4096)}},
	}
	fake.offeringPages = map[string]*ec2.DescribeInstanceTypeOfferingsOutput{
		"":        {InstanceTypeOfferings: []ec2types.InstanceTypeOffering{placementOffering("m7i.2xlarge"), placementOffering("z1d.large")}, NextToken: aws.String("offer-2")},
		"offer-2": {InstanceTypeOfferings: []ec2types.InstanceTypeOffering{placementOffering("t3.small"), placementOffering("m7i.xlarge")}},
	}

	resolver, err := newPlacementResolver(fake, testPlacementRegion)
	if err != nil {
		t.Fatal(err)
	}
	got, err := resolver.Resolve(context.Background(), testPlacementRequest())
	if err != nil {
		t.Fatal(err)
	}
	if got.Region != testPlacementRegion || got.AvailabilityZone != testPlacementZone || got.Network.VPCID != testPlacementVPC || got.Network.SubnetID != testPlacementSubnet {
		t.Fatalf("placement identity = %#v", got)
	}
	if got.Network.SecurityGroupMode != cloudquote.SecurityGroupCreateDedicated || got.Network.SecurityGroupID != "" || !got.Network.PublicIPv4 || got.Network.EntryPoint != cloudquote.EntryPointNone || got.Network.PublicExposure {
		t.Fatalf("network scope = %#v", got.Network)
	}
	if got.Usage.RuntimeHoursPerMonth != 730 || got.Usage.PublicIPv4Hours != 730 {
		t.Fatalf("usage = %#v", got.Usage)
	}
	wantProfiles := []cloudquote.CandidateProfile{cloudquote.CandidateEconomic, cloudquote.CandidateRecommended, cloudquote.CandidatePerformance}
	wantTypes := []string{"t3.small", "m7i.xlarge", "m7i.2xlarge"}
	if len(got.Candidates) != 3 {
		t.Fatalf("candidate count = %d", len(got.Candidates))
	}
	for index, candidate := range got.Candidates {
		if candidate.Profile != wantProfiles[index] || candidate.InstanceType != wantTypes[index] || !slices.Equal(candidate.AvailabilityZones, []string{testPlacementZone}) {
			t.Fatalf("candidate[%d] = %#v", index, candidate)
		}
		if candidate.Architecture != recipe.ArchitectureAMD64 || candidate.DiskGiB != uint64(40<<index) {
			t.Fatalf("candidate[%d] resource values = %#v", index, candidate)
		}
	}
}

const (
	testPlacementRegion = "us-east-1"
	testPlacementZone   = "us-east-1b"
	testPlacementVPC    = "vpc-0123456789abcdef0"
	testPlacementSubnet = "subnet-0123456789abcdef0"
	testPlacementIGW    = "igw-0123456789abcdef0"
)

func testPlacementRequest() PlacementRequestV1 {
	return PlacementRequestV1{
		Requirements: recipe.ResourceRequirementsV1{MinVCPU: 2, MinMemoryMiB: 4096, MinDiskGiB: 40, Architecture: recipe.ArchitectureAMD64},
		PublicIPv4:   true, RuntimeHoursPerMonth: 730,
	}
}

func placementFixture() *fakePlacementEC2 {
	return &fakePlacementEC2{
		vpcPages: map[string]*ec2.DescribeVpcsOutput{"": {Vpcs: []ec2types.Vpc{{VpcId: aws.String(testPlacementVPC), State: ec2types.VpcStateAvailable, IsDefault: aws.Bool(true)}}}},
		subnetPages: map[string]*ec2.DescribeSubnetsOutput{"": {Subnets: []ec2types.Subnet{{
			SubnetId: aws.String(testPlacementSubnet), VpcId: aws.String(testPlacementVPC), AvailabilityZone: aws.String(testPlacementZone),
			State: ec2types.SubnetStateAvailable, AvailableIpAddressCount: aws.Int32(16),
		}}}},
		zones: &ec2.DescribeAvailabilityZonesOutput{AvailabilityZones: []ec2types.AvailabilityZone{{
			RegionName: aws.String(testPlacementRegion), ZoneName: aws.String(testPlacementZone), ZoneType: aws.String("availability-zone"), State: ec2types.AvailabilityZoneStateAvailable,
		}}},
		routePages: map[string]*ec2.DescribeRouteTablesOutput{"": {RouteTables: []ec2types.RouteTable{{
			VpcId: aws.String(testPlacementVPC), Associations: []ec2types.RouteTableAssociation{{SubnetId: aws.String(testPlacementSubnet)}},
			Routes: []ec2types.Route{{DestinationCidrBlock: aws.String("0.0.0.0/0"), GatewayId: aws.String(testPlacementIGW), State: ec2types.RouteStateActive}},
		}}}},
		gatewayPages: map[string]*ec2.DescribeInternetGatewaysOutput{"": {InternetGateways: []ec2types.InternetGateway{{
			InternetGatewayId: aws.String(testPlacementIGW), Attachments: []ec2types.InternetGatewayAttachment{{VpcId: aws.String(testPlacementVPC), State: ec2types.AttachmentStatusAttached}},
		}}}},
		natPages: map[string]*ec2.DescribeNatGatewaysOutput{"": {}},
		typePages: map[string]*ec2.DescribeInstanceTypesOutput{"": {InstanceTypes: []ec2types.InstanceTypeInfo{
			placementInstanceInfo("t3.small", 2, 4096), placementInstanceInfo("m7i.xlarge", 4, 16384), placementInstanceInfo("m7i.2xlarge", 8, 32768),
		}}},
		offeringPages: map[string]*ec2.DescribeInstanceTypeOfferingsOutput{"": {InstanceTypeOfferings: []ec2types.InstanceTypeOffering{
			placementOffering("t3.small"), placementOffering("m7i.xlarge"), placementOffering("m7i.2xlarge"),
		}}},
	}
}

func placementInstanceInfo(instanceType string, vcpu int32, memoryMiB int64) ec2types.InstanceTypeInfo {
	return ec2types.InstanceTypeInfo{
		InstanceType: ec2types.InstanceType(instanceType), CurrentGeneration: aws.Bool(true), BareMetal: aws.Bool(false), SupportedInRegion: aws.Bool(true),
		ProcessorInfo: &ec2types.ProcessorInfo{SupportedArchitectures: []ec2types.ArchitectureType{ec2types.ArchitectureTypeX8664}},
		VCpuInfo:      &ec2types.VCpuInfo{DefaultVCpus: aws.Int32(vcpu)}, MemoryInfo: &ec2types.MemoryInfo{SizeInMiB: aws.Int64(memoryMiB)},
		SupportedRootDeviceTypes: []ec2types.RootDeviceType{ec2types.RootDeviceTypeEbs}, SupportedVirtualizationTypes: []ec2types.VirtualizationType{ec2types.VirtualizationTypeHvm},
		SupportedUsageClasses: []ec2types.UsageClassType{ec2types.UsageClassTypeOnDemand},
	}
}

func placementOffering(instanceType string) ec2types.InstanceTypeOffering {
	return ec2types.InstanceTypeOffering{InstanceType: ec2types.InstanceType(instanceType), Location: aws.String(testPlacementZone), LocationType: ec2types.LocationTypeAvailabilityZone}
}
