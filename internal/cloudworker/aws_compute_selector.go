package cloudworker

import (
	"context"
	"encoding/json"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"

	workaws "github.com/YingSuiAI/dirextalk-agent/internal/awscredential"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/pricing"
	pricingtypes "github.com/aws/aws-sdk-go-v2/service/pricing/types"
)

type AWSComputeSelectionAPI interface {
	DescribeInstanceTypes(context.Context, *ec2.DescribeInstanceTypesInput, ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error)
	DescribeInstanceTypeOfferings(context.Context, *ec2.DescribeInstanceTypeOfferingsInput, ...func(*ec2.Options)) (*ec2.DescribeInstanceTypeOfferingsOutput, error)
}

type AWSComputeSelectionFactory interface {
	NewEC2(workaws.CredentialHandle, string) (AWSComputeSelectionAPI, error)
	NewPricing(workaws.CredentialHandle) (AWSPriceListAPI, error)
}

type SDKAWSComputeSelectionFactory struct{}

func (SDKAWSComputeSelectionFactory) NewEC2(credential workaws.CredentialHandle, region string) (AWSComputeSelectionAPI, error) {
	if credential.Validate() != nil || strings.TrimSpace(region) == "" || strings.TrimSpace(region) != region {
		return nil, ErrStaleAuthorization
	}
	config := aws.Config{Region: region, Credentials: credentials.NewStaticCredentialsProvider(
		credential.AccessKeyID, credential.SecretAccessKey, credential.SessionToken)}
	return ec2.NewFromConfig(config), nil
}

func (SDKAWSComputeSelectionFactory) NewPricing(credential workaws.CredentialHandle) (AWSPriceListAPI, error) {
	return SDKAWSPriceListFactory{}.New(credential)
}

type AWSComputeSelector struct {
	credentials workaws.ExactCredentialResolver
	factory     AWSComputeSelectionFactory
}

func NewAWSComputeSelector(credentials workaws.ExactCredentialResolver, factory AWSComputeSelectionFactory) (*AWSComputeSelector, error) {
	if credentials == nil || factory == nil {
		return nil, ErrInvalid
	}
	return &AWSComputeSelector{credentials: credentials, factory: factory}, nil
}

type pricedInstanceShape struct {
	name, architecture string
	vcpu, memoryGiB    uint32
	hourlyMicros       uint64
}

type computeSelectionStageError struct{ stage string }

func (e computeSelectionStageError) Error() string {
	return "cloudworker: compute selection " + e.stage + " unavailable"
}

func (e computeSelectionStageError) Unwrap() error { return ErrProviderUnavailable }

func computeSelectionUnavailable(stage string) error {
	return computeSelectionStageError{stage: stage}
}

// SelectCompute reads current-generation Linux shared-tenancy on-demand
// products, intersects them with the region's actual EC2 offerings, and
// chooses the cheapest x86_64 shape satisfying the request.
func (selector *AWSComputeSelector) SelectCompute(ctx context.Context, binding AWSBinding, requirements ComputeRequirements) (ComputeSpec, error) {
	if selector == nil || ctx == nil || validateAWS(binding) != nil || requirements.validate() != nil {
		return ComputeSpec{}, ErrInvalid
	}
	credential, err := selector.credentials.ResolveCredentialRevision(ctx, binding.CredentialID, binding.CredentialRevision)
	if err != nil || credential.Validate() != nil || credential.ReferenceID != binding.CredentialID || credential.AccountID != binding.AccountID {
		return ComputeSpec{}, ErrStaleAuthorization
	}
	ec2Client, err := selector.factory.NewEC2(credential, binding.Region)
	if err != nil || ec2Client == nil {
		return ComputeSpec{}, computeSelectionUnavailable("offerings")
	}
	pricingClient, err := selector.factory.NewPricing(credential)
	if err != nil || pricingClient == nil {
		return ComputeSpec{}, computeSelectionUnavailable("pricing")
	}
	shapes, err := listPricedInstanceShapes(ctx, pricingClient, binding.Region, requirements)
	if err != nil || len(shapes) == 0 {
		return ComputeSpec{}, computeSelectionUnavailable("pricing")
	}
	names := make([]string, 0, len(shapes))
	for name := range shapes {
		names = append(names, name)
	}
	sort.Strings(names)
	offered := make(map[string]bool)
	for start := 0; start < len(names); start += 100 {
		end := start + 100
		if end > len(names) {
			end = len(names)
		}
		var next *string
		for page := 0; page < 5; page++ {
			output, callErr := ec2Client.DescribeInstanceTypeOfferings(ctx, &ec2.DescribeInstanceTypeOfferingsInput{
				// The selector needs regional availability, not one row per
				// availability zone. Querying availability-zone rows multiplies
				// every candidate by the region's AZ count and can exhaust the
				// bounded pagination window in large regions such as us-east-1.
				LocationType: ec2types.LocationTypeRegion, MaxResults: aws.Int32(100), NextToken: next,
				Filters: []ec2types.Filter{{Name: aws.String("instance-type"), Values: names[start:end]}},
			})
			if callErr != nil || output == nil {
				return ComputeSpec{}, computeSelectionUnavailable("offerings")
			}
			for _, offering := range output.InstanceTypeOfferings {
				name := string(offering.InstanceType)
				if _, ok := shapes[name]; ok && aws.ToString(offering.Location) == binding.Region {
					offered[name] = true
				}
			}
			if strings.TrimSpace(aws.ToString(output.NextToken)) == "" {
				break
			}
			if page == 4 {
				return ComputeSpec{}, computeSelectionUnavailable("offerings")
			}
			next = output.NextToken
		}
	}
	names = names[:0]
	for name := range offered {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ComputeSpec{}, computeSelectionUnavailable("offerings")
	}
	eligible := make(map[string]pricedInstanceShape)
	for start := 0; start < len(names); start += 100 {
		end := start + 100
		if end > len(names) {
			end = len(names)
		}
		types := make([]ec2types.InstanceType, 0, end-start)
		for _, name := range names[start:end] {
			types = append(types, ec2types.InstanceType(name))
		}
		output, callErr := ec2Client.DescribeInstanceTypes(ctx, &ec2.DescribeInstanceTypesInput{InstanceTypes: types})
		if callErr != nil || output == nil {
			return ComputeSpec{}, computeSelectionUnavailable("describe_types")
		}
		for _, value := range output.InstanceTypes {
			name := string(value.InstanceType)
			shape, ok := shapes[name]
			if !ok || value.VCpuInfo == nil || value.MemoryInfo == nil || value.ProcessorInfo == nil ||
				!containsX8664(value.ProcessorInfo.SupportedArchitectures) {
				continue
			}
			vcpu := uint32(aws.ToInt32(value.VCpuInfo.DefaultVCpus))
			memoryMiB := aws.ToInt64(value.MemoryInfo.SizeInMiB)
			if vcpu < requirements.MinVCPU || memoryMiB < int64(requirements.MinMemoryGiB)*1024 {
				continue
			}
			shape.vcpu = vcpu
			shape.memoryGiB = uint32((memoryMiB + 1023) / 1024)
			shape.architecture = "x86_64"
			eligible[name] = shape
		}
	}
	if len(eligible) == 0 {
		return ComputeSpec{}, computeSelectionUnavailable("describe_types")
	}
	names = names[:0]
	for name := range eligible {
		names = append(names, name)
	}
	sort.Strings(names)
	var selected pricedInstanceShape
	for _, name := range names {
		shape := eligible[name]
		if selected.name == "" || shape.hourlyMicros < selected.hourlyMicros || (shape.hourlyMicros == selected.hourlyMicros && shape.name < selected.name) {
			selected = shape
		}
	}
	if selected.name == "" {
		return ComputeSpec{}, computeSelectionUnavailable("describe_types")
	}
	return ComputeSpec{InstanceType: selected.name, Architecture: selected.architecture, VCPU: selected.vcpu, MemoryGiB: selected.memoryGiB,
		RootDeviceName: "/dev/xvda", VolumeGiB: requirements.DiskGiB, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125}, nil
}

func listPricedInstanceShapes(ctx context.Context, client AWSPriceListAPI, region string, requirements ComputeRequirements) (map[string]pricedInstanceShape, error) {
	filters := []pricingtypes.Filter{}
	for key, value := range map[string]string{"operatingSystem": "Linux", "tenancy": "Shared", "preInstalledSw": "NA", "capacitystatus": "Used", "currentGeneration": "Yes", "regionCode": region} {
		filters = append(filters, pricingtypes.Filter{Field: aws.String(key), Type: pricingtypes.FilterTypeTermMatch, Value: aws.String(value)})
	}
	sort.Slice(filters, func(i, j int) bool { return aws.ToString(filters[i].Field) < aws.ToString(filters[j].Field) })
	shapes := make(map[string]pricedInstanceShape)
	var next *string
	for page := 0; page < 20; page++ {
		output, err := client.GetProducts(ctx, &pricing.GetProductsInput{ServiceCode: aws.String("AmazonEC2"), Filters: filters,
			FormatVersion: aws.String("aws_v1"), MaxResults: aws.Int32(100), NextToken: next})
		if err != nil || output == nil {
			return nil, ErrProviderUnavailable
		}
		for _, raw := range output.PriceList {
			var document awsPriceDocument
			if json.Unmarshal([]byte(raw), &document) != nil || document.Product.ProductFamily != "Compute Instance" {
				continue
			}
			attributes := document.Product.Attributes
			name := strings.TrimSpace(attributes["instanceType"])
			if name == "" || strings.HasSuffix(name, ".metal") {
				continue
			}
			vcpu64, parseErr := strconv.ParseUint(strings.TrimSpace(attributes["vcpu"]), 10, 32)
			memory, parseErr2 := parseGiB(attributes["memory"])
			if parseErr != nil || parseErr2 != nil || uint32(vcpu64) < requirements.MinVCPU || memory < requirements.MinMemoryGiB {
				continue
			}
			price, ok := documentHourlyMicros(document)
			if !ok {
				continue
			}
			current, exists := shapes[name]
			if exists && current.hourlyMicros != price {
				return nil, ErrProviderUnavailable
			}
			shapes[name] = pricedInstanceShape{name: name, vcpu: uint32(vcpu64), memoryGiB: memory, hourlyMicros: price}
		}
		if strings.TrimSpace(aws.ToString(output.NextToken)) == "" {
			return shapes, nil
		}
		next = output.NextToken
	}
	return nil, ErrProviderUnavailable
}

func parseGiB(value string) (uint32, error) {
	value = strings.TrimSpace(strings.TrimSuffix(strings.ReplaceAll(value, ",", ""), " GiB"))
	rat, ok := new(big.Rat).SetString(value)
	if !ok || rat.Sign() <= 0 {
		return 0, ErrInvalid
	}
	quotient := new(big.Int).Quo(rat.Num(), rat.Denom())
	if new(big.Int).Mod(rat.Num(), rat.Denom()).Sign() != 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	if !quotient.IsUint64() || quotient.Uint64() > math.MaxUint32 {
		return 0, ErrInvalid
	}
	return uint32(quotient.Uint64()), nil
}

func documentHourlyMicros(document awsPriceDocument) (uint64, bool) {
	prices := map[string]*big.Rat{}
	for _, term := range document.Terms.OnDemand {
		for _, dimension := range term.PriceDimensions {
			if dimension.Unit != "Hrs" {
				continue
			}
			price, ok := new(big.Rat).SetString(strings.TrimSpace(dimension.PricePerUnit["USD"]))
			if !ok || price.Sign() <= 0 {
				return 0, false
			}
			prices[price.RatString()] = price
		}
	}
	if len(prices) != 1 {
		return 0, false
	}
	for _, price := range prices {
		price.Mul(price, big.NewRat(1_000_000, 1))
		value := new(big.Int).Quo(price.Num(), price.Denom())
		if new(big.Int).Mod(price.Num(), price.Denom()).Sign() != 0 {
			value.Add(value, big.NewInt(1))
		}
		if value.IsUint64() && value.Uint64() > 0 {
			return value.Uint64(), true
		}
	}
	return 0, false
}

func containsX8664(values []ec2types.ArchitectureType) bool {
	for _, value := range values {
		if value == ec2types.ArchitectureTypeX8664 {
			return true
		}
	}
	return false
}

var _ ComputeSelector = (*AWSComputeSelector)(nil)
