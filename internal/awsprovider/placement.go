package awsprovider

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strings"

	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

const placementPageLimit = 100

var (
	ErrPlacementNetworkUnavailable  = errors.New("no eligible AWS placement network is available")
	ErrPlacementCapacityUnavailable = errors.New("fewer than three eligible AWS instance candidates are available")
	placementRegionPattern          = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
)

// PlacementEC2ReadAPI is a closed discovery-only surface. In particular it
// has no RunInstances, CreateSecurityGroup, AllocateAddress, or other mutation.
type PlacementEC2ReadAPI interface {
	DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeAvailabilityZones(context.Context, *ec2.DescribeAvailabilityZonesInput, ...func(*ec2.Options)) (*ec2.DescribeAvailabilityZonesOutput, error)
	DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error)
	DescribeInternetGateways(context.Context, *ec2.DescribeInternetGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeInternetGatewaysOutput, error)
	DescribeNatGateways(context.Context, *ec2.DescribeNatGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error)
	DescribeInstanceTypes(context.Context, *ec2.DescribeInstanceTypesInput, ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error)
	DescribeInstanceTypeOfferings(context.Context, *ec2.DescribeInstanceTypeOfferingsInput, ...func(*ec2.Options)) (*ec2.DescribeInstanceTypeOfferingsOutput, error)
}

// PlacementRequestV1 carries only provider-neutral requirements and explicit
// usage assumptions. Identity, Recipe digest, retention, and secrets are bound
// by the application coordinator after this read-only step.
type PlacementRequestV1 struct {
	Requirements         recipe.ResourceRequirementsV1
	PublicIPv4           bool
	RuntimeHoursPerMonth uint32
}

func (request PlacementRequestV1) Validate() error {
	return validatePlacementRequest(request)
}

type PlacementCandidateV1 struct {
	Profile           cloudquote.CandidateProfile
	InstanceType      string
	Architecture      recipe.Architecture
	VCPU              uint32
	MemoryMiB         uint64
	GPUType           string
	GPUCount          uint32
	GPUMemoryMiB      uint64
	DiskGiB           uint64
	AvailabilityZones []string
}

type PlacementV1 struct {
	Region           string
	AvailabilityZone string
	Network          cloudquote.NetworkScopeV1
	Usage            cloudquote.UsageV1
	Candidates       []PlacementCandidateV1
}

type PlacementResolver struct {
	client PlacementEC2ReadAPI
	region string
}

// newPlacementResolver is the injected fake/SDK test seam. Production code
// must use NewPlacementResolverFromSource so discovery always runs through the
// fixed Control Role's short-lived STS session.
func newPlacementResolver(client PlacementEC2ReadAPI, region string) (*PlacementResolver, error) {
	if client == nil || !placementRegionPattern.MatchString(strings.TrimSpace(region)) || strings.TrimSpace(region) != region {
		return nil, ErrInvalidRequest
	}
	return &PlacementResolver{client: client, region: region}, nil
}

func NewPlacementResolverFromSource(region string, source *SourceCredentials, controlRoleARN, roleSessionName string) (*PlacementResolver, error) {
	config, err := AssumedControlAWSConfig(region, source, controlRoleARN, roleSessionName)
	if err != nil {
		return nil, err
	}
	return newPlacementResolver(ec2.NewFromConfig(config), region)
}

func (resolver *PlacementResolver) Resolve(ctx context.Context, request PlacementRequestV1) (PlacementV1, error) {
	if resolver == nil || resolver.client == nil || ctx == nil || request.Validate() != nil {
		return PlacementV1{}, ErrInvalidRequest
	}
	networks, err := resolver.readNetworks(ctx, request.PublicIPv4)
	if err != nil {
		return PlacementV1{}, err
	}
	if len(networks) == 0 {
		return PlacementV1{}, ErrPlacementNetworkUnavailable
	}
	instances, err := resolver.readInstanceTypes(ctx, request.Requirements)
	if err != nil {
		return PlacementV1{}, err
	}
	offerings, err := resolver.readOfferings(ctx, networkZones(networks))
	if err != nil {
		return PlacementV1{}, err
	}
	for _, network := range networks {
		candidates, candidateErr := selectPlacementCandidates(instances, offerings[network.zone], request.Requirements, network.zone)
		if candidateErr != nil {
			continue
		}
		usage := cloudquote.UsageV1{RuntimeHoursPerMonth: request.RuntimeHoursPerMonth}
		if request.PublicIPv4 {
			usage.PublicIPv4Hours = request.RuntimeHoursPerMonth
		}
		return PlacementV1{
			Region: resolver.region, AvailabilityZone: network.zone,
			Network: cloudquote.NetworkScopeV1{
				VPCID: network.vpcID, SubnetID: network.subnetID, SecurityGroupMode: cloudquote.SecurityGroupCreateDedicated,
				PublicIPv4: request.PublicIPv4, EntryPoint: cloudquote.EntryPointNone,
			},
			Usage: usage, Candidates: candidates,
		}, nil
	}
	return PlacementV1{}, ErrPlacementCapacityUnavailable
}

type placementNetwork struct {
	vpcID      string
	subnetID   string
	zone       string
	defaultVPC bool
}

func (resolver *PlacementResolver) readNetworks(ctx context.Context, publicIPv4 bool) ([]placementNetwork, error) {
	vpcs, err := resolver.readVPCs(ctx)
	if err != nil {
		return nil, err
	}
	subnets, err := resolver.readSubnets(ctx)
	if err != nil {
		return nil, err
	}
	zonesOutput, err := resolver.client.DescribeAvailabilityZones(ctx, &ec2.DescribeAvailabilityZonesInput{Filters: []ec2types.Filter{
		{Name: aws.String("region-name"), Values: []string{resolver.region}}, {Name: aws.String("state"), Values: []string{"available"}}, {Name: aws.String("zone-type"), Values: []string{"availability-zone"}},
	}})
	if err != nil {
		return nil, fmt.Errorf("DescribeAvailabilityZones: %w", err)
	}
	if zonesOutput == nil {
		return nil, errors.New("DescribeAvailabilityZones returned an empty response")
	}
	availableZones := make(map[string]struct{}, len(zonesOutput.AvailabilityZones))
	for _, zone := range zonesOutput.AvailabilityZones {
		name := aws.ToString(zone.ZoneName)
		if aws.ToString(zone.RegionName) == resolver.region && aws.ToString(zone.ZoneType) == "availability-zone" && zone.State == ec2types.AvailabilityZoneStateAvailable && name != "" {
			availableZones[name] = struct{}{}
		}
	}
	routes, err := resolver.readRouteTables(ctx)
	if err != nil {
		return nil, err
	}
	gateways, err := resolver.readAttachedGateways(ctx)
	if err != nil {
		return nil, err
	}
	var natGateways map[string]placementNATGateway
	if !publicIPv4 {
		natGateways, err = resolver.readPublicNATGateways(ctx, routes, gateways)
		if err != nil {
			return nil, err
		}
	}
	result := make([]placementNetwork, 0, len(subnets))
	for _, subnet := range subnets {
		vpcID, subnetID, zone := aws.ToString(subnet.VpcId), aws.ToString(subnet.SubnetId), aws.ToString(subnet.AvailabilityZone)
		isDefault, vpcOK := vpcs[vpcID]
		_, zoneOK := availableZones[zone]
		if !vpcOK || !zoneOK || subnet.State != ec2types.SubnetStateAvailable || subnetID == "" || aws.ToInt32(subnet.AvailableIpAddressCount) < 1 || aws.ToBool(subnet.Ipv6Native) {
			continue
		}
		if publicIPv4 && !subnetHasEffectiveIGWRoute(subnetID, vpcID, routes, gateways) {
			continue
		}
		if !publicIPv4 && !subnetHasEffectiveNATRoute(subnetID, vpcID, routes, natGateways) {
			continue
		}
		result = append(result, placementNetwork{vpcID: vpcID, subnetID: subnetID, zone: zone, defaultVPC: isDefault})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].defaultVPC != result[j].defaultVPC {
			return result[i].defaultVPC
		}
		if result[i].vpcID != result[j].vpcID {
			return result[i].vpcID < result[j].vpcID
		}
		if result[i].zone != result[j].zone {
			return result[i].zone < result[j].zone
		}
		return result[i].subnetID < result[j].subnetID
	})
	return result, nil
}

func (resolver *PlacementResolver) readVPCs(ctx context.Context) (map[string]bool, error) {
	result := make(map[string]bool)
	err := walkPlacementPages(func(token *string) (*string, error) {
		output, err := resolver.client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{Filters: []ec2types.Filter{{Name: aws.String("state"), Values: []string{"available"}}}, MaxResults: aws.Int32(1000), NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("DescribeVpcs: %w", err)
		}
		if output == nil {
			return nil, errors.New("DescribeVpcs returned an empty response")
		}
		for _, value := range output.Vpcs {
			id := aws.ToString(value.VpcId)
			if id != "" && value.State == ec2types.VpcStateAvailable {
				result[id] = result[id] || aws.ToBool(value.IsDefault)
			}
		}
		return output.NextToken, nil
	})
	return result, err
}

func (resolver *PlacementResolver) readSubnets(ctx context.Context) ([]ec2types.Subnet, error) {
	var result []ec2types.Subnet
	err := walkPlacementPages(func(token *string) (*string, error) {
		output, err := resolver.client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{Filters: []ec2types.Filter{{Name: aws.String("state"), Values: []string{"available"}}}, MaxResults: aws.Int32(1000), NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("DescribeSubnets: %w", err)
		}
		if output == nil {
			return nil, errors.New("DescribeSubnets returned an empty response")
		}
		result = append(result, output.Subnets...)
		return output.NextToken, nil
	})
	return result, err
}

func (resolver *PlacementResolver) readRouteTables(ctx context.Context) ([]ec2types.RouteTable, error) {
	var result []ec2types.RouteTable
	err := walkPlacementPages(func(token *string) (*string, error) {
		output, err := resolver.client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{MaxResults: aws.Int32(1000), NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("DescribeRouteTables: %w", err)
		}
		if output == nil {
			return nil, errors.New("DescribeRouteTables returned an empty response")
		}
		result = append(result, output.RouteTables...)
		return output.NextToken, nil
	})
	return result, err
}

func (resolver *PlacementResolver) readAttachedGateways(ctx context.Context) (map[string]map[string]struct{}, error) {
	result := make(map[string]map[string]struct{})
	err := walkPlacementPages(func(token *string) (*string, error) {
		output, err := resolver.client.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{Filters: []ec2types.Filter{{Name: aws.String("attachment.state"), Values: []string{"available"}}}, MaxResults: aws.Int32(1000), NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("DescribeInternetGateways: %w", err)
		}
		if output == nil {
			return nil, errors.New("DescribeInternetGateways returned an empty response")
		}
		for _, gateway := range output.InternetGateways {
			gatewayID := aws.ToString(gateway.InternetGatewayId)
			for _, attachment := range gateway.Attachments {
				vpcID := aws.ToString(attachment.VpcId)
				if gatewayID != "" && vpcID != "" && (attachment.State == ec2types.AttachmentStatusAttached || string(attachment.State) == "available") {
					if result[vpcID] == nil {
						result[vpcID] = make(map[string]struct{})
					}
					result[vpcID][gatewayID] = struct{}{}
				}
			}
		}
		return output.NextToken, nil
	})
	return result, err
}

type placementNATGateway struct {
	vpcID    string
	subnetID string
}

// readPublicNATGateways accepts only an available public NAT gateway with an
// observed EIP and an independently verified IGW route from its own subnet.
// A private Worker can therefore reach required HTTPS installation endpoints
// without acquiring a public address itself.
func (resolver *PlacementResolver) readPublicNATGateways(ctx context.Context, routes []ec2types.RouteTable, gateways map[string]map[string]struct{}) (map[string]placementNATGateway, error) {
	result := make(map[string]placementNATGateway)
	err := walkPlacementPages(func(token *string) (*string, error) {
		output, err := resolver.client.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{Filter: []ec2types.Filter{{Name: aws.String("state"), Values: []string{string(ec2types.NatGatewayStateAvailable)}}}, MaxResults: aws.Int32(1000), NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("DescribeNatGateways: %w", err)
		}
		if output == nil {
			return nil, errors.New("DescribeNatGateways returned an empty response")
		}
		for _, value := range output.NatGateways {
			id, vpcID, subnetID := aws.ToString(value.NatGatewayId), aws.ToString(value.VpcId), aws.ToString(value.SubnetId)
			if id == "" || vpcID == "" || subnetID == "" || value.State != ec2types.NatGatewayStateAvailable || value.ConnectivityType != ec2types.ConnectivityTypePublic ||
				!natGatewayHasPublicAddress(value) || !subnetHasEffectiveIGWRoute(subnetID, vpcID, routes, gateways) {
				continue
			}
			candidate := placementNATGateway{vpcID: vpcID, subnetID: subnetID}
			if existing, found := result[id]; found && existing != candidate {
				return nil, fmt.Errorf("DescribeNatGateways returned conflicting facts for %s", id)
			}
			result[id] = candidate
		}
		return output.NextToken, nil
	})
	return result, err
}

func natGatewayHasPublicAddress(value ec2types.NatGateway) bool {
	for _, address := range value.NatGatewayAddresses {
		if aws.ToString(address.PublicIp) != "" {
			return true
		}
	}
	return false
}

func subnetHasEffectiveIGWRoute(subnetID, vpcID string, tables []ec2types.RouteTable, gateways map[string]map[string]struct{}) bool {
	var explicit, main []ec2types.RouteTable
	for _, table := range tables {
		if aws.ToString(table.VpcId) != vpcID {
			continue
		}
		for _, association := range table.Associations {
			if aws.ToString(association.SubnetId) == subnetID {
				explicit = append(explicit, table)
			}
			if aws.ToBool(association.Main) {
				main = append(main, table)
			}
		}
	}
	effective := explicit
	if len(effective) == 0 {
		effective = main
	}
	for _, table := range effective {
		for _, route := range table.Routes {
			gatewayID := aws.ToString(route.GatewayId)
			if aws.ToString(route.DestinationCidrBlock) == "0.0.0.0/0" && route.State == ec2types.RouteStateActive && strings.HasPrefix(gatewayID, "igw-") {
				if _, ok := gateways[vpcID][gatewayID]; ok {
					return true
				}
			}
		}
	}
	return false
}

func subnetHasEffectiveNATRoute(subnetID, vpcID string, tables []ec2types.RouteTable, gateways map[string]placementNATGateway) bool {
	var explicit, main []ec2types.RouteTable
	for _, table := range tables {
		if aws.ToString(table.VpcId) != vpcID {
			continue
		}
		for _, association := range table.Associations {
			if aws.ToString(association.SubnetId) == subnetID {
				explicit = append(explicit, table)
			}
			if aws.ToBool(association.Main) {
				main = append(main, table)
			}
		}
	}
	effective := explicit
	if len(effective) == 0 {
		effective = main
	}
	for _, table := range effective {
		for _, route := range table.Routes {
			natID := aws.ToString(route.NatGatewayId)
			if aws.ToString(route.DestinationCidrBlock) == "0.0.0.0/0" && route.State == ec2types.RouteStateActive {
				if gateway, ok := gateways[natID]; ok && gateway.vpcID == vpcID {
					return true
				}
			}
		}
	}
	return false
}

type placementInstance struct {
	instanceType string
	architecture recipe.Architecture
	vcpu         uint32
	memoryMiB    uint64
	gpuType      string
	gpuCount     uint32
	gpuMemoryMiB uint64
}

func (resolver *PlacementResolver) readInstanceTypes(ctx context.Context, requirements recipe.ResourceRequirementsV1) (map[string]placementInstance, error) {
	result := make(map[string]placementInstance)
	wantedArchitecture := "x86_64"
	if requirements.Architecture == recipe.ArchitectureARM64 {
		wantedArchitecture = "arm64"
	}
	err := walkPlacementPages(func(token *string) (*string, error) {
		output, err := resolver.client.DescribeInstanceTypes(ctx, &ec2.DescribeInstanceTypesInput{Filters: []ec2types.Filter{
			{Name: aws.String("bare-metal"), Values: []string{"false"}}, {Name: aws.String("current-generation"), Values: []string{"true"}},
			{Name: aws.String("processor-info.supported-architecture"), Values: []string{wantedArchitecture}},
		}, MaxResults: aws.Int32(100), NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("DescribeInstanceTypes: %w", err)
		}
		if output == nil {
			return nil, errors.New("DescribeInstanceTypes returned an empty response")
		}
		for _, info := range output.InstanceTypes {
			candidate, ok := normalizePlacementInstance(info, requirements)
			if !ok {
				continue
			}
			if previous, exists := result[candidate.instanceType]; exists && previous != candidate {
				return nil, fmt.Errorf("DescribeInstanceTypes returned conflicting facts for %s", candidate.instanceType)
			}
			result[candidate.instanceType] = candidate
		}
		return output.NextToken, nil
	})
	return result, err
}

func normalizePlacementInstance(info ec2types.InstanceTypeInfo, requirements recipe.ResourceRequirementsV1) (placementInstance, bool) {
	instanceType := string(info.InstanceType)
	if instanceType == "" || strings.HasSuffix(instanceType, ".metal") || aws.ToBool(info.BareMetal) || (info.CurrentGeneration != nil && !aws.ToBool(info.CurrentGeneration)) ||
		(info.SupportedInRegion != nil && !aws.ToBool(info.SupportedInRegion)) || info.VCpuInfo == nil || info.MemoryInfo == nil || info.ProcessorInfo == nil ||
		!slices.Contains(info.SupportedRootDeviceTypes, ec2types.RootDeviceTypeEbs) || !slices.Contains(info.SupportedVirtualizationTypes, ec2types.VirtualizationTypeHvm) ||
		!slices.Contains(info.SupportedUsageClasses, ec2types.UsageClassTypeOnDemand) {
		return placementInstance{}, false
	}
	wanted := ec2types.ArchitectureTypeX8664
	if requirements.Architecture == recipe.ArchitectureARM64 {
		wanted = ec2types.ArchitectureTypeArm64
	}
	vcpu, memory := aws.ToInt32(info.VCpuInfo.DefaultVCpus), aws.ToInt64(info.MemoryInfo.SizeInMiB)
	if !slices.Contains(info.ProcessorInfo.SupportedArchitectures, wanted) || vcpu <= 0 || memory <= 0 || uint32(vcpu) < requirements.MinVCPU || uint64(memory) < requirements.MinMemoryMiB {
		return placementInstance{}, false
	}
	candidate := placementInstance{instanceType: instanceType, architecture: requirements.Architecture, vcpu: uint32(vcpu), memoryMiB: uint64(memory)}
	if requirements.GPURequired {
		if info.GpuInfo == nil || aws.ToInt32(info.GpuInfo.TotalGpuMemoryInMiB) <= 0 {
			return placementInstance{}, false
		}
		for _, gpu := range info.GpuInfo.Gpus {
			count := aws.ToInt32(gpu.Count)
			if count <= 0 || gpu.MemoryInfo == nil || !gpuMatchesFamily(gpu, requirements.GPUFamily) {
				continue
			}
			memoryPerGPU := int64(aws.ToInt32(gpu.MemoryInfo.SizeInMiB))
			if memoryPerGPU <= 0 || memoryPerGPU > math.MaxInt64/int64(count) {
				return placementInstance{}, false
			}
			candidate.gpuCount += uint32(count)
			candidate.gpuMemoryMiB += uint64(memoryPerGPU * int64(count))
			if candidate.gpuType == "" || aws.ToString(gpu.Name) < candidate.gpuType {
				candidate.gpuType = aws.ToString(gpu.Name)
			}
		}
		if candidate.gpuCount == 0 || candidate.gpuMemoryMiB < requirements.MinGPUMemoryMiB || candidate.gpuType == "" {
			return placementInstance{}, false
		}
	} else if info.GpuInfo != nil && len(info.GpuInfo.Gpus) != 0 {
		return placementInstance{}, false
	}
	return candidate, true
}

func gpuMatchesFamily(gpu ec2types.GpuDeviceInfo, family string) bool {
	return strings.EqualFold(strings.TrimSpace(family), strings.TrimSpace(aws.ToString(gpu.Name))) ||
		strings.EqualFold(strings.TrimSpace(family), strings.TrimSpace(aws.ToString(gpu.Manufacturer)))
}

func (resolver *PlacementResolver) readOfferings(ctx context.Context, zones []string) (map[string]map[string]struct{}, error) {
	result := make(map[string]map[string]struct{}, len(zones))
	err := walkPlacementPages(func(token *string) (*string, error) {
		output, err := resolver.client.DescribeInstanceTypeOfferings(ctx, &ec2.DescribeInstanceTypeOfferingsInput{
			LocationType: ec2types.LocationTypeAvailabilityZone, Filters: []ec2types.Filter{{Name: aws.String("location"), Values: zones}}, MaxResults: aws.Int32(1000), NextToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("DescribeInstanceTypeOfferings: %w", err)
		}
		if output == nil {
			return nil, errors.New("DescribeInstanceTypeOfferings returned an empty response")
		}
		for _, offering := range output.InstanceTypeOfferings {
			zone, instanceType := aws.ToString(offering.Location), string(offering.InstanceType)
			if slices.Contains(zones, zone) && instanceType != "" && offering.LocationType == ec2types.LocationTypeAvailabilityZone {
				if result[zone] == nil {
					result[zone] = make(map[string]struct{})
				}
				result[zone][instanceType] = struct{}{}
			}
		}
		return output.NextToken, nil
	})
	return result, err
}

func selectPlacementCandidates(instances map[string]placementInstance, offered map[string]struct{}, requirements recipe.ResourceRequirementsV1, zone string) ([]PlacementCandidateV1, error) {
	pool := make([]placementInstance, 0, len(offered))
	for instanceType := range offered {
		if candidate, ok := instances[instanceType]; ok {
			pool = append(pool, candidate)
		}
	}
	profiles := []cloudquote.CandidateProfile{cloudquote.CandidateEconomic, cloudquote.CandidateRecommended, cloudquote.CandidatePerformance}
	used := make(map[string]struct{}, len(profiles))
	result := make([]PlacementCandidateV1, 0, len(profiles))
	var previous placementInstance
	for index, profile := range profiles {
		multiplier := uint64(1 << index)
		targetVCPU := saturatingMultiply32(requirements.MinVCPU, uint32(multiplier))
		targetMemory := saturatingMultiply64(requirements.MinMemoryMiB, multiplier)
		eligible := make([]placementInstance, 0, len(pool))
		for _, candidate := range pool {
			_, alreadyUsed := used[candidate.instanceType]
			if alreadyUsed || candidate.vcpu < targetVCPU || candidate.memoryMiB < targetMemory || candidate.vcpu < previous.vcpu || candidate.memoryMiB < previous.memoryMiB || candidate.gpuMemoryMiB < previous.gpuMemoryMiB {
				continue
			}
			eligible = append(eligible, candidate)
		}
		sort.Slice(eligible, func(i, j int) bool {
			if eligible[i].vcpu != eligible[j].vcpu {
				return eligible[i].vcpu < eligible[j].vcpu
			}
			if eligible[i].memoryMiB != eligible[j].memoryMiB {
				return eligible[i].memoryMiB < eligible[j].memoryMiB
			}
			if eligible[i].gpuMemoryMiB != eligible[j].gpuMemoryMiB {
				return eligible[i].gpuMemoryMiB < eligible[j].gpuMemoryMiB
			}
			return eligible[i].instanceType < eligible[j].instanceType
		})
		if len(eligible) == 0 {
			return nil, ErrPlacementCapacityUnavailable
		}
		selected := eligible[0]
		used[selected.instanceType] = struct{}{}
		previous = selected
		result = append(result, PlacementCandidateV1{
			Profile: profile, InstanceType: selected.instanceType, Architecture: selected.architecture, VCPU: selected.vcpu, MemoryMiB: selected.memoryMiB,
			GPUType: selected.gpuType, GPUCount: selected.gpuCount, GPUMemoryMiB: selected.gpuMemoryMiB,
			DiskGiB: min(saturatingMultiply64(requirements.MinDiskGiB, multiplier), uint64(64*1024)), AvailabilityZones: []string{zone},
		})
	}
	return result, nil
}

func networkZones(networks []placementNetwork) []string {
	seen := make(map[string]struct{}, len(networks))
	for _, network := range networks {
		seen[network.zone] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for zone := range seen {
		result = append(result, zone)
	}
	sort.Strings(result)
	return result
}

func validatePlacementRequest(request PlacementRequestV1) error {
	requirements := request.Requirements
	if request.RuntimeHoursPerMonth == 0 || request.RuntimeHoursPerMonth > 744 || requirements.MinVCPU == 0 || requirements.MinVCPU > 1024 ||
		requirements.MinMemoryMiB == 0 || requirements.MinMemoryMiB > 64*1024*1024 || requirements.MinDiskGiB == 0 || requirements.MinDiskGiB > 64*1024 ||
		!recipe.ValidArchitecture(requirements.Architecture) {
		return ErrInvalidRequest
	}
	if requirements.GPURequired {
		if requirements.MinGPUMemoryMiB == 0 || strings.TrimSpace(requirements.GPUFamily) == "" || requirements.GPUFamily != strings.TrimSpace(requirements.GPUFamily) {
			return ErrInvalidRequest
		}
	} else if requirements.MinGPUMemoryMiB != 0 || requirements.GPUFamily != "" {
		return ErrInvalidRequest
	}
	return nil
}

func walkPlacementPages(next func(*string) (*string, error)) error {
	seen := make(map[string]struct{}, placementPageLimit)
	var token *string
	for page := 0; page < placementPageLimit; page++ {
		nextToken, err := next(token)
		if err != nil {
			return err
		}
		value := aws.ToString(nextToken)
		if value == "" {
			return nil
		}
		if _, exists := seen[value]; exists {
			return errors.New("AWS placement pagination token repeated")
		}
		seen[value] = struct{}{}
		token = aws.String(value)
	}
	return errors.New("AWS placement pagination limit exceeded")
}

func saturatingMultiply32(value, multiplier uint32) uint32 {
	if multiplier != 0 && value > math.MaxUint32/multiplier {
		return math.MaxUint32
	}
	return value * multiplier
}

func saturatingMultiply64(value, multiplier uint64) uint64 {
	if multiplier != 0 && value > math.MaxUint64/multiplier {
		return math.MaxUint64
	}
	return value * multiplier
}
