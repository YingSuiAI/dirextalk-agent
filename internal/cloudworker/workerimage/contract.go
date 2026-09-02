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

	SchemaVersion      = "1"
	ImageVersion       = "1.1.4"
	PiVersion          = "0.84.4"
	RollbackPiVersion  = "0.84.1"
	ToolBaseline       = "1"
	PublisherAccountID = "066107820442"
	ManifestPath       = "/opt/dirextalk-worker/manifest.json"
	PiPath             = "/opt/dirextalk-worker/bin/pi"
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
	switch e.Kind {
	case FailureMissing:
		return fmt.Sprintf("Dirextalk %s Worker image is not published for this Region; qualify a public image and update the Agent public release catalog", e.Flavor)
	case FailureIncompatible:
		return fmt.Sprintf("Dirextalk %s Worker image is incompatible; update the Agent public release catalog with a qualified image using schema %s and Pi %s", e.Flavor, SchemaVersion, PiVersion)
	case FailureUnverified:
		return fmt.Sprintf("Dirextalk %s Worker image is not verified; complete image qualification before updating the Agent public release catalog", e.Flavor)
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

type Reference struct {
	Flavor               Flavor   `json:"-"`
	OwnerID              string   `json:"-"`
	ImageID              string   `json:"image_id"`
	SchemaVersion        string   `json:"image_schema"`
	ImageVersion         string   `json:"image_version"`
	PiVersion            string   `json:"pi_version"`
	Tested               bool     `json:"tested"`
	GPUSupportedFamilies []string `json:"gpu_supported_families,omitempty"`
}

var (
	imageIDPattern      = regexp.MustCompile(`^ami-[0-9a-f]{8,17}$`)
	imageVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	gpuFamilyPattern    = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)
)

func ValidImageVersion(value string) bool { return imageVersionPattern.MatchString(value) }

func CompatiblePiVersion(value string) bool { return value == PiVersion || value == RollbackPiVersion }

// ValidProvenance also validates retained, already-qualified Workers without
// requiring their release to remain the current catalog entry.
func ValidProvenance(ownerID, imageID, version, piVersion string) bool {
	return ownerID == PublisherAccountID && imageIDPattern.MatchString(imageID) && ValidImageVersion(version) && CompatiblePiVersion(piVersion)
}

func ValidateReference(reference Reference) error {
	if !ValidFlavor(reference.Flavor) || reference.SchemaVersion != SchemaVersion ||
		!ValidProvenance(reference.OwnerID, reference.ImageID, reference.ImageVersion, reference.PiVersion) {
		return ContractError{Kind: FailureIncompatible, Flavor: reference.Flavor}
	}
	if !reference.Tested {
		return ContractError{Kind: FailureUnverified, Flavor: reference.Flavor}
	}
	return validateGPUFamilies(reference.Flavor, reference.GPUSupportedFamilies)
}

type Image struct {
	Flavor                           Flavor
	ImageID, ImageName, ImageVersion string
	OwnerID, PiVersion               string
	CreatedAt                        time.Time
	RootDeviceName                   string
	RootVolumeGiB                    int32
	GPUSupportedFamilies             []string
}

func ValidateImage(reference Reference, image types.Image) (Image, error) {
	if err := ValidateReference(reference); err != nil {
		return Image{}, err
	}
	if aws.ToString(image.ImageId) != reference.ImageID || aws.ToString(image.OwnerId) != PublisherAccountID || !aws.ToBool(image.Public) || image.State != types.ImageStateAvailable ||
		image.Architecture != types.ArchitectureValuesX8664 || image.VirtualizationType != types.VirtualizationTypeHvm || image.RootDeviceType != types.DeviceTypeEbs {
		return Image{}, ContractError{Kind: FailureIncompatible, Flavor: reference.Flavor}
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
	return Image{Flavor: reference.Flavor, ImageID: reference.ImageID, ImageName: aws.ToString(image.Name), ImageVersion: reference.ImageVersion,
		OwnerID: PublisherAccountID, PiVersion: reference.PiVersion, CreatedAt: createdAt.UTC(),
		RootDeviceName: rootDeviceName, RootVolumeGiB: rootVolumeGiB, GPUSupportedFamilies: append([]string(nil), reference.GPUSupportedFamilies...)}, nil
}

func validateGPUFamilies(flavor Flavor, families []string) error {
	if flavor == FlavorCPU {
		if len(families) != 0 {
			return ContractError{Kind: FailureIncompatible, Flavor: flavor}
		}
		return nil
	}
	if flavor != FlavorGPU || len(families) == 0 {
		return ContractError{Kind: FailureIncompatible, Flavor: flavor}
	}
	previous := ""
	for _, family := range families {
		if !gpuFamilyPattern.MatchString(family) || family <= previous {
			return ContractError{Kind: FailureIncompatible, Flavor: flavor}
		}
		previous = family
	}
	return nil
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
