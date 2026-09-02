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
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/workerimage"
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
	describeImagesInput  *ec2.DescribeImagesInput
	describeImagesErr    error
	images               []ec2types.Image
	offeringsErr         error
	describeTypesErr     error
}

func (provider *computeSelectionAWS) DescribeImages(_ context.Context, input *ec2.DescribeImagesInput, _ ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	provider.describeImagesInput = input
	if provider.describeImagesErr != nil {
		return nil, provider.describeImagesErr
	}
	return &ec2.DescribeImagesOutput{Images: provider.images}, nil
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
			info.GpuInfo = &ec2types.GpuInfo{TotalGpuMemoryInMiB: aws.Int32(24 * 1024), Gpus: []ec2types.GpuDeviceInfo{{Name: aws.String("L4")}}}
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
	selector, err := newTestAWSComputeSelector(credential, factory)
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

func TestAWSComputeSelectorDiscoversGPURootBeforeQuoteAndExcludesUnsupportedFamily(t *testing.T) {
	credential := &livePricingCredential{handle: workaws.CredentialHandle{ReferenceID: "11111111-1111-4111-8111-111111111111",
		Region: "ap-northeast-1", AccountID: "123456789012", PrincipalARN: "arn:aws:iam::123456789012:user/test", AccessKeyID: "access", SecretAccessKey: "secret"}}
	ec2Provider := &computeSelectionAWS{regionalLocation: "ap-northeast-2", offeredTypes: map[string]bool{
		"t3.small": true, "m7i-flex.large": true, "g5.xlarge": true, "g6f.2xlarge": true,
	}, images: []ec2types.Image{workerImageFixture("ami-0123456789abcdef0", workerimage.FlavorGPU, "2026-08-25T00:00:00Z", 75)}}
	selector, err := newTestAWSComputeSelector(credential, &computeSelectionFactory{ec2: ec2Provider})
	if err != nil {
		t.Fatal(err)
	}
	binding := AWSBinding{AccountID: credential.handle.AccountID, Region: "ap-northeast-2", CredentialID: credential.handle.ReferenceID, CredentialRevision: 7}
	selected, err := selector.SelectCompute(context.Background(), binding, ComputeRequirements{
		MinVCPU: 2, MinMemoryGiB: 2, MinAcceleratorMemoryGiB: 20, DiskGiB: 24, EstimatedRuntimeMinutes: 30, AcceleratorType: AcceleratorGPU,
	})
	if err != nil || selected.InstanceType != "g5.xlarge" || selected.AcceleratorType != AcceleratorGPU || selected.AcceleratorName != "A10G" || selected.AcceleratorMemoryMiB != 24*1024 || selected.RootDeviceName != "/dev/sda1" || selected.VolumeGiB != 75 {
		t.Fatalf("selected=%+v err=%v", selected, err)
	}
	if ec2Provider.describeImagesInput == nil || !slices.Equal(ec2Provider.describeImagesInput.Owners, []string{workerimage.PublisherAccountID}) ||
		!slices.Equal(ec2Provider.describeImagesInput.ImageIds, []string{"ami-0123456789abcdef0"}) {
		t.Fatalf("GPU image discovery = %#v", ec2Provider.describeImagesInput)
	}
	larger, err := selector.SelectCompute(context.Background(), binding, ComputeRequirements{
		MinVCPU: 2, MinMemoryGiB: 2, MinAcceleratorMemoryGiB: 20, DiskGiB: 120, EstimatedRuntimeMinutes: 30, AcceleratorType: AcceleratorGPU,
	})
	if err != nil || larger.VolumeGiB != 120 {
		t.Fatalf("larger GPU volume=%+v err=%v", larger, err)
	}
}

func workerImageFixture(id string, flavor workerimage.Flavor, created string, volumeGiB int32) ec2types.Image {
	return ec2types.Image{ImageId: aws.String(id), OwnerId: aws.String(workerimage.PublisherAccountID), Public: aws.Bool(true), Name: aws.String("dirextalk-worker-" + string(flavor)), CreationDate: aws.String(created), RootDeviceName: aws.String("/dev/sda1"),
		State: ec2types.ImageStateAvailable, Architecture: ec2types.ArchitectureValuesX8664, VirtualizationType: ec2types.VirtualizationTypeHvm, RootDeviceType: ec2types.DeviceTypeEbs,
		BlockDeviceMappings: []ec2types.BlockDeviceMapping{{DeviceName: aws.String("/dev/sda1"), Ebs: &ec2types.EbsBlockDevice{VolumeSize: aws.Int32(volumeGiB)}}}}
}

type computeSelectionFactory struct {
	ec2          *computeSelectionAWS
	ec2Region    string
	pricing      AWSPriceListAPI
	pricingCalls int
}

func (factory *computeSelectionFactory) NewEC2(_ workaws.CredentialHandle, region string) (AWSComputeSelectionAPI, error) {
	factory.ec2Region = region
	if len(factory.ec2.images) == 0 {
		factory.ec2.images = []ec2types.Image{workerImageFixture("ami-0123456789abcdef0", workerimage.FlavorCPU, "2026-08-25T00:00:00Z", 16)}
	}
	return factory.ec2, nil
}
func (factory *computeSelectionFactory) NewPricing(workaws.CredentialHandle) (AWSPriceListAPI, error) {
	factory.pricingCalls++
	if factory.pricing != nil {
		return factory.pricing, nil
	}
	return computeSelectionPricing{}, nil
}

func newTestAWSComputeSelector(credentials workaws.ExactCredentialResolver, factory AWSComputeSelectionFactory) (*AWSComputeSelector, error) {
	selector, err := NewAWSComputeSelector(credentials, factory)
	if err != nil {
		return nil, err
	}
	selector.imageReference = func(_ string, flavor workerimage.Flavor) (workerimage.Reference, error) {
		reference := workerimage.Reference{Flavor: flavor, OwnerID: workerimage.PublisherAccountID, ImageID: "ami-0123456789abcdef0", SchemaVersion: workerimage.SchemaVersion, ImageVersion: workerimage.ImageVersion, PiVersion: workerimage.PiVersion, Tested: true}
		if flavor == workerimage.FlavorGPU {
			reference.GPUSupportedFamilies = []string{"g4dn", "g5", "p5"}
		}
		return reference, nil
	}
	return selector, nil
}

func TestAWSComputeSelectorChoosesCheapestAvailableShapeSatisfyingRequirements(t *testing.T) {
	credential := &livePricingCredential{handle: workaws.CredentialHandle{ReferenceID: "11111111-1111-4111-8111-111111111111",
		Region: "ap-northeast-1", AccountID: "123456789012", PrincipalARN: "arn:aws:iam::123456789012:user/test", AccessKeyID: "access", SecretAccessKey: "secret"}}
	var calls []string
	ec2Provider := &computeSelectionAWS{regionalLocation: "ap-northeast-2", offeredTypes: map[string]bool{
		"t3.small": true, "m7i-flex.large": true,
	}, calls: &calls}
	factory := &computeSelectionFactory{ec2: ec2Provider, pricing: computeSelectionPricing{calls: &calls}}
	selector, err := newTestAWSComputeSelector(credential, factory)
	if err != nil {
		t.Fatal(err)
	}
	binding := AWSBinding{AccountID: credential.handle.AccountID, Region: "ap-northeast-2", CredentialID: credential.handle.ReferenceID, CredentialRevision: 7}
	cheap, err := selector.SelectCompute(context.Background(), binding, ComputeRequirements{MinVCPU: 2, MinMemoryGiB: 2, DiskGiB: 8, EstimatedRuntimeMinutes: 30})
	if err != nil || cheap.InstanceType != "t3.small" || cheap.VCPU != 2 || cheap.MemoryGiB != 2 || cheap.VolumeGiB != 16 {
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

func TestAWSComputeSelectorRejectsUnqualifiedPublicImageBeforePricing(t *testing.T) {
	credential := &livePricingCredential{handle: workaws.CredentialHandle{ReferenceID: "11111111-1111-4111-8111-111111111111", Region: "ap-northeast-1", AccountID: "123456789012", PrincipalARN: "arn:aws:iam::123456789012:user/test", AccessKeyID: "access", SecretAccessKey: "secret"}}
	binding := AWSBinding{AccountID: credential.handle.AccountID, Region: "ap-northeast-1", CredentialID: credential.handle.ReferenceID, CredentialRevision: 7}
	for _, state := range []string{"unpublished", "customer-owned", "private", "provider-failure"} {
		t.Run(state, func(t *testing.T) {
			binding := binding
			image := workerImageFixture("ami-0123456789abcdef0", workerimage.FlavorCPU, "2026-08-25T00:00:00Z", 16)
			probe := &computeSelectionAWS{images: []ec2types.Image{image}}
			factory := &computeSelectionFactory{ec2: probe}
			selector, err := newTestAWSComputeSelector(credential, factory)
			if err != nil {
				t.Fatal(err)
			}
			kind := workerimage.FailureIncompatible
			switch state {
			case "unpublished":
				kind = workerimage.FailureMissing
				selector.imageReference = workerimage.PublishedReference
				binding.Region = "unpublished-region"
			case "customer-owned":
				probe.images[0].OwnerId = aws.String(credential.handle.AccountID)
			case "private":
				probe.images[0].Public = aws.Bool(false)
			case "provider-failure":
				kind = workerimage.FailureUnavailable
				probe.describeImagesErr = errors.New("SignatureDoesNotMatch secret-access-key")
			}
			_, err = selector.SelectCompute(context.Background(), binding, ComputeRequirements{MinVCPU: 2, MinMemoryGiB: 2, DiskGiB: 16, EstimatedRuntimeMinutes: 30})
			if !workerimage.IsFailure(err, kind) || strings.Contains(err.Error(), "secret-access-key") || factory.pricingCalls != 0 {
				t.Fatalf("error=%v pricingCalls=%d", err, factory.pricingCalls)
			}
		})
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
			selector, err := newTestAWSComputeSelector(credential, &computeSelectionFactory{ec2: test.ec2, pricing: test.pricing})
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
