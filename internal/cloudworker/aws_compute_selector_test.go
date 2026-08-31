package cloudworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	workaws "github.com/YingSuiAI/dirextalk-agent/internal/awscredential"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/pricing"
)

type computeSelectionAWS struct {
	offeringLocationType ec2types.LocationType
	regionalLocation     string
	offeredTypes         map[string]bool
	calls                *[]string
	describedTypes       []string
	offeringsErr         error
	describeTypesErr     error
}

func (provider *computeSelectionAWS) DescribeInstanceTypes(_ context.Context, input *ec2.DescribeInstanceTypesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error) {
	if provider.calls != nil {
		*provider.calls = append(*provider.calls, "describe_types")
	}
	if provider.describeTypesErr != nil {
		return nil, provider.describeTypesErr
	}
	result := &ec2.DescribeInstanceTypesOutput{}
	for _, name := range input.InstanceTypes {
		provider.describedTypes = append(provider.describedTypes, string(name))
		vcpu, memory := int32(2), int64(2048)
		if string(name) == "m7i-flex.large" {
			memory = 8192
		}
		info := ec2types.InstanceTypeInfo{InstanceType: name,
			VCpuInfo: &ec2types.VCpuInfo{DefaultVCpus: aws.Int32(vcpu)}, MemoryInfo: &ec2types.MemoryInfo{SizeInMiB: aws.Int64(memory)},
			ProcessorInfo: &ec2types.ProcessorInfo{SupportedArchitectures: []ec2types.ArchitectureType{ec2types.ArchitectureTypeX8664}}}
		if string(name) == "g5.xlarge" {
			info.GpuInfo = &ec2types.GpuInfo{TotalGpuMemoryInMiB: aws.Int32(24 * 1024), Gpus: []ec2types.GpuDeviceInfo{{Name: aws.String("A10G")}}}
		}
		if string(name) == "g6f.2xlarge" {
			info.VCpuInfo.DefaultVCpus = aws.Int32(8)
			info.MemoryInfo.SizeInMiB = aws.Int64(32 * 1024)
			info.GpuInfo = &ec2types.GpuInfo{TotalGpuMemoryInMiB: aws.Int32(5724), Gpus: []ec2types.GpuDeviceInfo{{Name: aws.String("L4")}}}
		}
		result.InstanceTypes = append(result.InstanceTypes, info)
	}
	return result, nil
}

func (provider *computeSelectionAWS) DescribeInstanceTypeOfferings(_ context.Context, input *ec2.DescribeInstanceTypeOfferingsInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceTypeOfferingsOutput, error) {
	if provider.calls != nil {
		*provider.calls = append(*provider.calls, "offerings")
	}
	if provider.offeringsErr != nil {
		return nil, provider.offeringsErr
	}
	provider.offeringLocationType = input.LocationType
	if input.LocationType == ec2types.LocationTypeAvailabilityZone {
		// Model a large region where AZ-expanded results still have a sixth
		// page. The old five-page availability-zone query fails closed here.
		return &ec2.DescribeInstanceTypeOfferingsOutput{NextToken: aws.String("more-availability-zones")}, nil
	}
	location := provider.regionalLocation
	if location == "" {
		location = "ap-northeast-1"
	}
	result := &ec2.DescribeInstanceTypeOfferingsOutput{}
	for _, name := range input.Filters[0].Values {
		if provider.offeredTypes != nil && !provider.offeredTypes[name] {
			continue
		}
		result.InstanceTypeOfferings = append(result.InstanceTypeOfferings, ec2types.InstanceTypeOffering{InstanceType: ec2types.InstanceType(name), Location: aws.String(location)})
	}
	return result, nil
}

func TestAWSComputeSelectorRejectsRegionPrefixCollision(t *testing.T) {
	credential := &livePricingCredential{handle: workaws.CredentialHandle{ReferenceID: "11111111-1111-4111-8111-111111111111",
		Region: "ap-northeast-1", AccountID: "123456789012", PrincipalARN: "arn:aws:iam::123456789012:user/test", AccessKeyID: "access", SecretAccessKey: "secret"}}
	ec2Provider := &computeSelectionAWS{regionalLocation: "ap-northeast-10"}
	factory := &computeSelectionFactory{ec2: ec2Provider}
	selector, err := NewAWSComputeSelector(credential, factory)
	if err != nil {
		t.Fatal(err)
	}
	binding := AWSBinding{AccountID: credential.handle.AccountID, Region: "ap-northeast-2", CredentialID: credential.handle.ReferenceID, CredentialRevision: 7}
	_, err = selector.SelectCompute(context.Background(), binding, ComputeRequirements{MinVCPU: 2, MinMemoryGiB: 4, DiskGiB: 20, EstimatedRuntimeMinutes: 30})
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("prefix-collision region err=%v, want provider unavailable", err)
	}
	if factory.ec2Region != binding.Region {
		t.Fatalf("EC2 region=%q, want host region %q", factory.ec2Region, binding.Region)
	}
}

type computeSelectionPricing struct {
	calls *[]string
	err   error
}

func (provider computeSelectionPricing) GetProducts(context.Context, *pricing.GetProductsInput, ...func(*pricing.Options)) (*pricing.GetProductsOutput, error) {
	if provider.calls != nil {
		*provider.calls = append(*provider.calls, "pricing")
	}
	if provider.err != nil {
		return nil, provider.err
	}
	document := func(name, memory, hourly string) string {
		value := map[string]any{
			"product": map[string]any{"productFamily": "Compute Instance", "attributes": map[string]string{"instanceType": name, "vcpu": "2", "memory": memory}},
			"terms":   map[string]any{"OnDemand": map[string]any{"term": map[string]any{"priceDimensions": map[string]any{"rate": map[string]any{"unit": "Hrs", "pricePerUnit": map[string]string{"USD": hourly}}}}}},
		}
		raw, _ := json.Marshal(value)
		return string(raw)
	}
	return &pricing.GetProductsOutput{PriceList: []string{
		document("g3.4xlarge", "122 GiB", "0.01"),
		document("t3.small", "2 GiB", "0.03"),
		document("g5.xlarge", "16 GiB", "1.01"),
		document("g6f.2xlarge", "32 GiB", "0.50"),
		document("m7i-flex.large", "8 GiB", "0.08"),
	}}, nil
}

func TestAWSComputeSelectorHonorsGPURequirement(t *testing.T) {
	credential := &livePricingCredential{handle: workaws.CredentialHandle{ReferenceID: "11111111-1111-4111-8111-111111111111",
		Region: "ap-northeast-1", AccountID: "123456789012", PrincipalARN: "arn:aws:iam::123456789012:user/test", AccessKeyID: "access", SecretAccessKey: "secret"}}
	ec2Provider := &computeSelectionAWS{regionalLocation: "ap-northeast-2", offeredTypes: map[string]bool{
		"t3.small": true, "m7i-flex.large": true, "g5.xlarge": true, "g6f.2xlarge": true,
	}}
	selector, err := NewAWSComputeSelector(credential, &computeSelectionFactory{ec2: ec2Provider})
	if err != nil {
		t.Fatal(err)
	}
	binding := AWSBinding{AccountID: credential.handle.AccountID, Region: "ap-northeast-2", CredentialID: credential.handle.ReferenceID, CredentialRevision: 7}
	selected, err := selector.SelectCompute(context.Background(), binding, ComputeRequirements{
		MinVCPU: 2, MinMemoryGiB: 2, MinAcceleratorMemoryGiB: 20, DiskGiB: 24, EstimatedRuntimeMinutes: 30, AcceleratorType: AcceleratorGPU,
	})
	if err != nil || selected.InstanceType != "g5.xlarge" || selected.AcceleratorType != AcceleratorGPU || selected.AcceleratorName != "A10G" || selected.AcceleratorMemoryMiB != 24*1024 {
		t.Fatalf("selected=%+v err=%v", selected, err)
	}
}

type computeSelectionFactory struct {
	ec2       *computeSelectionAWS
	ec2Region string
	pricing   AWSPriceListAPI
}

func (factory *computeSelectionFactory) NewEC2(_ workaws.CredentialHandle, region string) (AWSComputeSelectionAPI, error) {
	factory.ec2Region = region
	return factory.ec2, nil
}
func (factory *computeSelectionFactory) NewPricing(workaws.CredentialHandle) (AWSPriceListAPI, error) {
	if factory.pricing != nil {
		return factory.pricing, nil
	}
	return computeSelectionPricing{}, nil
}

func TestAWSComputeSelectorChoosesCheapestAvailableShapeSatisfyingRequirements(t *testing.T) {
	credential := &livePricingCredential{handle: workaws.CredentialHandle{ReferenceID: "11111111-1111-4111-8111-111111111111",
		Region: "ap-northeast-1", AccountID: "123456789012", PrincipalARN: "arn:aws:iam::123456789012:user/test", AccessKeyID: "access", SecretAccessKey: "secret"}}
	var calls []string
	ec2Provider := &computeSelectionAWS{regionalLocation: "ap-northeast-2", offeredTypes: map[string]bool{
		"t3.small": true, "m7i-flex.large": true,
	}, calls: &calls}
	factory := &computeSelectionFactory{ec2: ec2Provider, pricing: computeSelectionPricing{calls: &calls}}
	selector, err := NewAWSComputeSelector(credential, factory)
	if err != nil {
		t.Fatal(err)
	}
	binding := AWSBinding{AccountID: credential.handle.AccountID, Region: "ap-northeast-2", CredentialID: credential.handle.ReferenceID, CredentialRevision: 7}
	cheap, err := selector.SelectCompute(context.Background(), binding, ComputeRequirements{MinVCPU: 2, MinMemoryGiB: 2, DiskGiB: 24, EstimatedRuntimeMinutes: 30})
	if err != nil || cheap.InstanceType != "t3.small" || cheap.VCPU != 2 || cheap.MemoryGiB != 2 || cheap.VolumeGiB != 24 {
		t.Fatalf("cheap=%+v err=%v", cheap, err)
	}
	larger, err := selector.SelectCompute(context.Background(), binding, ComputeRequirements{MinVCPU: 2, MinMemoryGiB: 4, DiskGiB: 40, EstimatedRuntimeMinutes: 60})
	if err != nil || larger.InstanceType != "m7i-flex.large" || larger.MemoryGiB != 8 || larger.VolumeGiB != 40 {
		t.Fatalf("larger=%+v err=%v", larger, err)
	}
	if ec2Provider.offeringLocationType != ec2types.LocationTypeRegion {
		t.Fatalf("offering location type=%q, want region", ec2Provider.offeringLocationType)
	}
	if factory.ec2Region != binding.Region {
		t.Fatalf("EC2 region=%q, want host region %q", factory.ec2Region, binding.Region)
	}
	if slices.Contains(ec2Provider.describedTypes, "g3.4xlarge") {
		t.Fatalf("DescribeInstanceTypes received retired regional type: %v", ec2Provider.describedTypes)
	}
	if len(calls) < 3 || !slices.Equal(calls[:3], []string{"pricing", "offerings", "describe_types"}) {
		t.Fatalf("AWS selection call order=%v, want pricing then offerings then describe_types", calls)
	}
}

func TestAWSComputeSelectorRedactsProviderFailuresByStage(t *testing.T) {
	credential := &livePricingCredential{handle: workaws.CredentialHandle{ReferenceID: "11111111-1111-4111-8111-111111111111",
		Region: "ap-northeast-1", AccountID: "123456789012", PrincipalARN: "arn:aws:iam::123456789012:user/test", AccessKeyID: "access", SecretAccessKey: "secret"}}
	binding := AWSBinding{AccountID: credential.handle.AccountID, Region: "ap-northeast-2", CredentialID: credential.handle.ReferenceID, CredentialRevision: 7}
	sensitive := errors.New("SignatureDoesNotMatch secret-access-key credential-body")
	tests := []struct {
		name, wantStage string
		ec2             *computeSelectionAWS
		pricing         AWSPriceListAPI
	}{
		{name: "pricing", wantStage: "pricing", ec2: &computeSelectionAWS{}, pricing: computeSelectionPricing{err: sensitive}},
		{name: "offerings", wantStage: "offerings", ec2: &computeSelectionAWS{offeringsErr: sensitive}},
		{name: "describe types", wantStage: "describe_types", ec2: &computeSelectionAWS{regionalLocation: binding.Region, describeTypesErr: sensitive}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selector, err := NewAWSComputeSelector(credential, &computeSelectionFactory{ec2: test.ec2, pricing: test.pricing})
			if err != nil {
				t.Fatal(err)
			}
			_, err = selector.SelectCompute(context.Background(), binding, ComputeRequirements{MinVCPU: 2, MinMemoryGiB: 2, DiskGiB: 20, EstimatedRuntimeMinutes: 30})
			if !errors.Is(err, ErrProviderUnavailable) {
				t.Fatalf("err=%v, want provider unavailable", err)
			}
			var stageErr computeSelectionStageError
			if !errors.As(err, &stageErr) || stageErr.stage != test.wantStage {
				t.Fatalf("err=%v stage=%q, want %q", err, stageErr.stage, test.wantStage)
			}
			for _, leaked := range []string{"SignatureDoesNotMatch", "secret-access-key", "credential-body"} {
				if strings.Contains(err.Error(), leaked) {
					t.Fatal(fmt.Errorf("provider error leaked %q: %w", leaked, err))
				}
			}
		})
	}
}
