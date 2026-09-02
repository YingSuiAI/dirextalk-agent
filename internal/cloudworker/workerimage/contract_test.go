package workerimage

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestValidateParameterAndImageRequireExactVersionedContract(t *testing.T) {
	parameterName, err := ParameterName(FlavorCPU)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := ValidateParameter(FlavorCPU, Parameter{Name: parameterName, DataType: ParameterDataType, Value: "ami-0123456789abcdef0", Version: 7})
	if err != nil {
		t.Fatal(err)
	}
	image, err := ValidateImage("123456789012", reference, imageFixture(FlavorCPU, true))
	if err != nil {
		t.Fatal(err)
	}
	if image.ImageID != reference.ImageID || image.ParameterVersion != 7 || image.RootDeviceName != "/dev/sda1" || image.RootVolumeGiB != 24 {
		t.Fatalf("image=%+v", image)
	}
	previous := imageFixture(FlavorCPU, true)
	for index := range previous.Tags {
		if aws.ToString(previous.Tags[index].Key) == TagVersion {
			previous.Tags[index].Value = aws.String("0.9.0")
		}
	}
	if compatible, err := ValidateImage("123456789012", reference, previous); err != nil || compatible.ImageVersion != "0.9.0" {
		t.Fatalf("compatible previous image=%+v err=%v", compatible, err)
	}
	for index := range previous.Tags {
		if aws.ToString(previous.Tags[index].Key) == TagPiVersion {
			previous.Tags[index].Value = aws.String(RollbackPiVersion)
		}
	}
	if _, err := ValidateImage("123456789012", reference, previous); err != nil {
		t.Fatalf("rollback Pi version rejected: %v", err)
	}
	for index := range previous.Tags {
		if aws.ToString(previous.Tags[index].Key) == TagPiVersion {
			previous.Tags[index].Value = aws.String("0.83.0")
		}
	}
	if _, err := ValidateImage("123456789012", reference, previous); !IsFailure(err, FailureIncompatible) {
		t.Fatalf("unsupported Pi version accepted: %v", err)
	}
}

func TestValidateImageClassifiesUnverifiedAndIncompatibleWithoutProviderDetails(t *testing.T) {
	name, _ := ParameterName(FlavorGPU)
	reference, _ := ValidateParameter(FlavorGPU, Parameter{Name: name, DataType: ParameterDataType, Value: "ami-0123456789abcdef0", Version: 3})
	unverified := imageFixture(FlavorGPU, false)
	if _, err := ValidateImage("123456789012", reference, unverified); !IsFailure(err, FailureUnverified) || stringsContainAny(err.Error(), "secret", "provider detail") {
		t.Fatalf("unverified error=%v", err)
	}
	incompatible := imageFixture(FlavorGPU, true)
	incompatible.OwnerId = aws.String("999999999999")
	if _, err := ValidateImage("123456789012", reference, incompatible); !IsFailure(err, FailureIncompatible) {
		t.Fatalf("incompatible error=%v", err)
	}
	if _, err := ValidateParameter(FlavorGPU, Parameter{}); !IsFailure(err, FailureMissing) {
		t.Fatalf("missing error=%v", err)
	}
	cpuWithGPUFamilies := imageFixture(FlavorCPU, true)
	cpuWithGPUFamilies.Tags = append(cpuWithGPUFamilies.Tags, types.Tag{Key: aws.String(TagGPUSupportedFamilies), Value: aws.String("g5")})
	cpuName, _ := ParameterName(FlavorCPU)
	cpuReference, _ := ValidateParameter(FlavorCPU, Parameter{Name: cpuName, DataType: ParameterDataType, Value: "ami-0123456789abcdef0", Version: 1})
	if _, err := ValidateImage("123456789012", cpuReference, cpuWithGPUFamilies); !IsFailure(err, FailureIncompatible) {
		t.Fatalf("CPU image accepted GPU family metadata: %v", err)
	}
	for _, malformed := range []string{"g5,g4dn", "g5,g5", "G5", "-g5", "g5-", "g5, p5"} {
		gpuImage := imageFixture(FlavorGPU, true)
		for index := range gpuImage.Tags {
			if aws.ToString(gpuImage.Tags[index].Key) == TagGPUSupportedFamilies {
				gpuImage.Tags[index].Value = aws.String(malformed)
			}
		}
		if _, err := ValidateImage("123456789012", reference, gpuImage); !IsFailure(err, FailureIncompatible) {
			t.Errorf("accepted non-canonical GPU families %q: %v", malformed, err)
		}
	}
	var typed ContractError
	if !errors.As(ContractError{Kind: FailureMissing, Flavor: FlavorCPU}, &typed) {
		t.Fatal("contract error is not discoverable")
	}
}

func imageFixture(flavor Flavor, tested bool) types.Image {
	testedValue := "false"
	if tested {
		testedValue = "true"
	}
	image := types.Image{
		ImageId: aws.String("ami-0123456789abcdef0"), OwnerId: aws.String("123456789012"), Name: aws.String("dirextalk-worker"),
		State: types.ImageStateAvailable, Architecture: types.ArchitectureValuesX8664, VirtualizationType: types.VirtualizationTypeHvm,
		RootDeviceType: types.DeviceTypeEbs, RootDeviceName: aws.String("/dev/sda1"), CreationDate: aws.String("2026-09-02T00:00:00Z"),
		BlockDeviceMappings: []types.BlockDeviceMapping{{DeviceName: aws.String("/dev/sda1"), Ebs: &types.EbsBlockDevice{VolumeSize: aws.Int32(24)}}},
		Tags: []types.Tag{{Key: aws.String(TagSchema), Value: aws.String(SchemaVersion)}, {Key: aws.String(TagFlavor), Value: aws.String(string(flavor))},
			{Key: aws.String(TagVersion), Value: aws.String(ImageVersion)}, {Key: aws.String(TagPiVersion), Value: aws.String(PiVersion)},
			{Key: aws.String(TagImageTested), Value: aws.String(testedValue)}},
	}
	if flavor == FlavorGPU {
		image.Tags = append(image.Tags, types.Tag{Key: aws.String(TagGPUSupportedFamilies), Value: aws.String("g4dn,g5,p5")})
	}
	return image
}

func stringsContainAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if len(needle) > 0 && len(value) >= len(needle) {
			for i := 0; i+len(needle) <= len(value); i++ {
				if value[i:i+len(needle)] == needle {
					return true
				}
			}
		}
	}
	return false
}
