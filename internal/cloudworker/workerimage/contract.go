// Package workerimage owns the immutable Dirextalk EC2 image contract used
// before quoting and again immediately before launch.
package workerimage

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type Flavor string

const (
	FlavorCPU Flavor = "cpu"
	FlavorGPU Flavor = "gpu"

	SchemaVersion           = "1"
	ImageVersion            = "1.1.0"
	PiVersion               = "0.84.4"
	RollbackPiVersion       = "0.84.1"
	ToolBaseline            = "1"
	ParameterDataType       = "aws:ec2:image"
	TagSchema               = "DirextalkWorkerImageSchema"
	TagFlavor               = "DirextalkWorkerImageFlavor"
	TagVersion              = "DirextalkWorkerImageVersion"
	TagPiVersion            = "DirextalkPiVersion"
	TagImageTested          = "DirextalkImageTested"
	TagGPUSupportedFamilies = "DirextalkGPUSupportedFamilies"
	ManifestPath            = "/opt/dirextalk-worker/manifest.json"
	PiPath                  = "/opt/dirextalk-worker/bin/pi"
)

type FailureKind string

const (
	FailureMissing      FailureKind = "missing"
	FailureIncompatible FailureKind = "incompatible"
	FailureUnverified   FailureKind = "unverified"
	FailureUnavailable  FailureKind = "unavailable"
)

type ContractError struct {
	Kind   FailureKind
	Flavor Flavor
}

func (e ContractError) Error() string {
	path, _ := ParameterName(e.Flavor)
	switch e.Kind {
	case FailureMissing:
		return fmt.Sprintf("Dirextalk %s Worker image is not published; publish %s in the selected AWS account and Region", e.Flavor, path)
	case FailureIncompatible:
		return fmt.Sprintf("Dirextalk %s Worker image is incompatible; publish a semantic image release with schema %s and Pi %s at %s", e.Flavor, SchemaVersion, PiVersion, path)
	case FailureUnverified:
		return fmt.Sprintf("Dirextalk %s Worker image is not verified; complete the image tests and republish %s", e.Flavor, path)
	default:
		return fmt.Sprintf("Dirextalk %s Worker image metadata is temporarily unavailable", e.Flavor)
	}
}

func IsFailure(err error, kind FailureKind) bool {
	var target ContractError
	return errors.As(err, &target) && target.Kind == kind
}

func ValidFlavor(value Flavor) bool { return value == FlavorCPU || value == FlavorGPU }

func FlavorForAccelerator(accelerator string) (Flavor, error) {
	switch strings.TrimSpace(accelerator) {
	case "":
		return FlavorCPU, nil
	case "gpu":
		return FlavorGPU, nil
	default:
		return "", ContractError{Kind: FailureIncompatible}
	}
}

func ParameterName(flavor Flavor) (string, error) {
	if !ValidFlavor(flavor) {
		return "", ContractError{Kind: FailureIncompatible, Flavor: flavor}
	}
	return "/dirextalk/worker-images/v1/" + string(flavor) + "/current", nil
}

type Parameter struct {
	Name, DataType, Value string
	Version               int64
}

type Reference struct {
	Flavor           Flavor
	ParameterName    string
	ParameterVersion int64
	ImageID          string
}

var (
	imageIDPattern      = regexp.MustCompile(`^ami-[0-9a-f]{8,17}$`)
	imageVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	gpuFamilyPattern    = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)
)

func ValidImageVersion(value string) bool { return imageVersionPattern.MatchString(value) }

func CompatiblePiVersion(value string) bool { return value == PiVersion || value == RollbackPiVersion }

func ValidateParameter(flavor Flavor, value Parameter) (Reference, error) {
	name, err := ParameterName(flavor)
	if err != nil {
		return Reference{}, err
	}
	if strings.TrimSpace(value.Name) == "" || strings.TrimSpace(value.Value) == "" {
		return Reference{}, ContractError{Kind: FailureMissing, Flavor: flavor}
	}
	if value.Name != name || value.DataType != ParameterDataType || value.Version <= 0 || !imageIDPattern.MatchString(value.Value) {
		return Reference{}, ContractError{Kind: FailureIncompatible, Flavor: flavor}
	}
	return Reference{Flavor: flavor, ParameterName: name, ParameterVersion: value.Version, ImageID: value.Value}, nil
}

type Image struct {
	Flavor                           Flavor
	ImageID, ImageName, ImageVersion string
	ParameterName                    string
	ParameterVersion                 int64
	CreatedAt                        time.Time
	RootDeviceName                   string
	RootVolumeGiB                    int32
	GPUSupportedFamilies             []string
}

func ValidateImage(accountID string, reference Reference, image types.Image) (Image, error) {
	if len(accountID) != 12 || !ValidFlavor(reference.Flavor) || reference.ImageID == "" || reference.ParameterVersion <= 0 ||
		aws.ToString(image.ImageId) != reference.ImageID || aws.ToString(image.OwnerId) != accountID || image.State != types.ImageStateAvailable ||
		image.Architecture != types.ArchitectureValuesX8664 || image.VirtualizationType != types.VirtualizationTypeHvm || image.RootDeviceType != types.DeviceTypeEbs {
		return Image{}, ContractError{Kind: FailureIncompatible, Flavor: reference.Flavor}
	}
	tags := make(map[string]string, len(image.Tags))
	for _, tag := range image.Tags {
		if key := strings.TrimSpace(aws.ToString(tag.Key)); key != "" {
			tags[key] = strings.TrimSpace(aws.ToString(tag.Value))
		}
	}
	if tags[TagSchema] != SchemaVersion || tags[TagFlavor] != string(reference.Flavor) || !ValidImageVersion(tags[TagVersion]) || !CompatiblePiVersion(tags[TagPiVersion]) {
		return Image{}, ContractError{Kind: FailureIncompatible, Flavor: reference.Flavor}
	}
	if tags[TagImageTested] != "true" {
		return Image{}, ContractError{Kind: FailureUnverified, Flavor: reference.Flavor}
	}
	gpuFamilies, err := validateGPUFamilies(reference.Flavor, tags[TagGPUSupportedFamilies])
	if err != nil {
		return Image{}, err
	}
	createdAt, err := time.Parse(time.RFC3339, aws.ToString(image.CreationDate))
	rootDeviceName := strings.TrimSpace(aws.ToString(image.RootDeviceName))
	var rootVolumeGiB int32
	for _, mapping := range image.BlockDeviceMappings {
		if aws.ToString(mapping.DeviceName) == rootDeviceName && mapping.Ebs != nil {
			rootVolumeGiB = aws.ToInt32(mapping.Ebs.VolumeSize)
			break
		}
	}
	if err != nil || !strings.HasPrefix(rootDeviceName, "/dev/") || rootVolumeGiB < 8 {
		return Image{}, ContractError{Kind: FailureIncompatible, Flavor: reference.Flavor}
	}
	return Image{Flavor: reference.Flavor, ImageID: reference.ImageID, ImageName: aws.ToString(image.Name), ImageVersion: tags[TagVersion],
		ParameterName: reference.ParameterName, ParameterVersion: reference.ParameterVersion, CreatedAt: createdAt.UTC(),
		RootDeviceName: rootDeviceName, RootVolumeGiB: rootVolumeGiB, GPUSupportedFamilies: gpuFamilies}, nil
}

func validateGPUFamilies(flavor Flavor, value string) ([]string, error) {
	if flavor == FlavorCPU {
		if value != "" {
			return nil, ContractError{Kind: FailureIncompatible, Flavor: flavor}
		}
		return nil, nil
	}
	if flavor != FlavorGPU || value == "" || strings.TrimSpace(value) != value {
		return nil, ContractError{Kind: FailureIncompatible, Flavor: flavor}
	}
	families := strings.Split(value, ",")
	previous := ""
	for _, family := range families {
		if !gpuFamilyPattern.MatchString(family) || family <= previous {
			return nil, ContractError{Kind: FailureIncompatible, Flavor: flavor}
		}
		previous = family
	}
	return families, nil
}

func (image Image) SupportsInstanceType(instanceType string) bool {
	if image.Flavor != FlavorGPU {
		return image.Flavor == FlavorCPU
	}
	family, _, ok := strings.Cut(strings.ToLower(strings.TrimSpace(instanceType)), ".")
	if !ok {
		return false
	}
	for _, supported := range image.GPUSupportedFamilies {
		if family == supported {
			return true
		}
	}
	return false
}
