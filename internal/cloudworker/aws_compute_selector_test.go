package cloudworker

import (
	"context"
	"encoding/json"
	"testing"

	workaws "github.com/YingSuiAI/dirextalk-agent/internal/awscredential"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/pricing"
)

type computeSelectionAWS struct{}

func (computeSelectionAWS) DescribeInstanceTypes(_ context.Context, input *ec2.DescribeInstanceTypesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error) {
	result := &ec2.DescribeInstanceTypesOutput{}
	for _, name := range input.InstanceTypes {
		vcpu, memory := int32(2), int64(2048)
		if string(name) == "m7i-flex.large" {
			memory = 8192
		}
		result.InstanceTypes = append(result.InstanceTypes, ec2types.InstanceTypeInfo{InstanceType: name,
			VCpuInfo: &ec2types.VCpuInfo{DefaultVCpus: aws.Int32(vcpu)}, MemoryInfo: &ec2types.MemoryInfo{SizeInMiB: aws.Int64(memory)},
			ProcessorInfo: &ec2types.ProcessorInfo{SupportedArchitectures: []ec2types.ArchitectureType{ec2types.ArchitectureTypeX8664}}})
	}
	return result, nil
}

func (computeSelectionAWS) DescribeInstanceTypeOfferings(_ context.Context, input *ec2.DescribeInstanceTypeOfferingsInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceTypeOfferingsOutput, error) {
	result := &ec2.DescribeInstanceTypeOfferingsOutput{}
	for _, name := range input.Filters[0].Values {
		result.InstanceTypeOfferings = append(result.InstanceTypeOfferings, ec2types.InstanceTypeOffering{InstanceType: ec2types.InstanceType(name), Location: aws.String("ap-northeast-1a")})
	}
	return result, nil
}

type computeSelectionPricing struct{}

func (computeSelectionPricing) GetProducts(context.Context, *pricing.GetProductsInput, ...func(*pricing.Options)) (*pricing.GetProductsOutput, error) {
	document := func(name, memory, hourly string) string {
		value := map[string]any{
			"product": map[string]any{"productFamily": "Compute Instance", "attributes": map[string]string{"instanceType": name, "vcpu": "2", "memory": memory}},
			"terms":   map[string]any{"OnDemand": map[string]any{"term": map[string]any{"priceDimensions": map[string]any{"rate": map[string]any{"unit": "Hrs", "pricePerUnit": map[string]string{"USD": hourly}}}}}},
		}
		raw, _ := json.Marshal(value)
		return string(raw)
	}
	return &pricing.GetProductsOutput{PriceList: []string{
		document("t3.small", "2 GiB", "0.03"),
		document("m7i-flex.large", "8 GiB", "0.08"),
	}}, nil
}

type computeSelectionFactory struct{}

func (computeSelectionFactory) NewEC2(workaws.CredentialHandle) (AWSComputeSelectionAPI, error) {
	return computeSelectionAWS{}, nil
}
func (computeSelectionFactory) NewPricing(workaws.CredentialHandle) (AWSPriceListAPI, error) {
	return computeSelectionPricing{}, nil
}

func TestAWSComputeSelectorChoosesCheapestAvailableShapeSatisfyingRequirements(t *testing.T) {
	credential := &livePricingCredential{handle: workaws.CredentialHandle{ReferenceID: "11111111-1111-4111-8111-111111111111",
		Region: "ap-northeast-1", AccountID: "123456789012", PrincipalARN: "arn:aws:iam::123456789012:user/test", AccessKeyID: "access", SecretAccessKey: "secret"}}
	selector, err := NewAWSComputeSelector(credential, computeSelectionFactory{})
	if err != nil {
		t.Fatal(err)
	}
	binding := AWSBinding{AccountID: credential.handle.AccountID, Region: credential.handle.Region, CredentialID: credential.handle.ReferenceID, CredentialRevision: 7}
	cheap, err := selector.SelectCompute(context.Background(), binding, ComputeRequirements{MinVCPU: 2, MinMemoryGiB: 2, DiskGiB: 24, EstimatedRuntimeMinutes: 30})
	if err != nil || cheap.InstanceType != "t3.small" || cheap.VCPU != 2 || cheap.MemoryGiB != 2 || cheap.VolumeGiB != 24 {
		t.Fatalf("cheap=%+v err=%v", cheap, err)
	}
	larger, err := selector.SelectCompute(context.Background(), binding, ComputeRequirements{MinVCPU: 2, MinMemoryGiB: 4, DiskGiB: 40, EstimatedRuntimeMinutes: 60})
	if err != nil || larger.InstanceType != "m7i-flex.large" || larger.MemoryGiB != 8 || larger.VolumeGiB != 40 {
		t.Fatalf("larger=%+v err=%v", larger, err)
	}
}
