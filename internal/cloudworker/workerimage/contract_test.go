package workerimage

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func referenceFixture(flavor Flavor) Reference {
	reference := Reference{Flavor: flavor, OwnerID: PublisherAccountID, ImageID: "ami-0123456789abcdef0", SchemaVersion: SchemaVersion, ImageVersion: ImageVersion, PiVersion: PiVersion, Tested: true}
	if flavor == FlavorGPU {
		reference.GPUSupportedFamilies = []string{"g4dn", "g5", "p5"}
	}
	return reference
}

func TestPublicImageIsConsumableWithoutCustomerSSMOrSharedTags(t *testing.T) {
	reference := referenceFixture(FlavorCPU)
	image, err := ValidateImage(reference, imageFixture())
	if err != nil {
		t.Fatalf("qualified public publisher image rejected without shared tags: %v", err)
	}
	if image.OwnerID != PublisherAccountID || image.ImageID != reference.ImageID || image.PiVersion != PiVersion || image.RootDeviceName != "/dev/sda1" || image.RootVolumeGiB != 24 {
		t.Fatalf("image=%+v", image)
	}
	// Image names and customer-visible tags are not catalog authority.
	tagged := imageFixture()
	tagged.Name, tagged.Tags = aws.String("untrusted-name"), []types.Tag{{Key: aws.String("DirextalkPiVersion"), Value: aws.String("invalid")}}
	if _, err := ValidateImage(reference, tagged); err != nil {
		t.Fatalf("unshared tag unexpectedly affected trusted catalog: %v", err)
	}
}

func TestValidatePublicImageRejectsDifferentIdentityOrIncompatibleLiveImage(t *testing.T) {
	for name, mutate := range map[string]func(*types.Image){
		"customer owner":     func(image *types.Image) { image.OwnerId = aws.String("123456789012") },
		"different id":       func(image *types.Image) { image.ImageId = aws.String("ami-fffffffffffffffff") },
		"private":            func(image *types.Image) { image.Public = aws.Bool(false) },
		"unknown visibility": func(image *types.Image) { image.Public = nil },
		"not available":      func(image *types.Image) { image.State = types.ImageStatePending },
		"arm":                func(image *types.Image) { image.Architecture = types.ArchitectureValuesArm64 },
		"paravirtual":        func(image *types.Image) { image.VirtualizationType = types.VirtualizationTypeParavirtual },
		"instance store":     func(image *types.Image) { image.RootDeviceType = types.DeviceTypeInstanceStore },
		"missing root":       func(image *types.Image) { image.RootDeviceName = nil },
		"wrong root mapping": func(image *types.Image) { image.BlockDeviceMappings[0].DeviceName = aws.String("/dev/sdb") },
		"small root":         func(image *types.Image) { image.BlockDeviceMappings[0].Ebs.VolumeSize = aws.Int32(1) },
		"missing creation":   func(image *types.Image) { image.CreationDate = nil },
	} {
		t.Run(name, func(t *testing.T) {
			image := imageFixture()
			mutate(&image)
			if _, err := ValidateImage(referenceFixture(FlavorCPU), image); !IsFailure(err, FailureIncompatible) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestCatalogPinsQualifiedRegionFlavorAndRejectsUnverifiedMetadata(t *testing.T) {
	catalog := func(reference Reference) []byte {
		data, err := json.Marshal(map[string]any{"schema": "dirextalk.worker-image-catalog/v1", "publisher_account_id": PublisherAccountID, "regions": map[string]any{"ap-northeast-1": map[string]Reference{"gpu": reference}}})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	data := catalog(referenceFixture(FlavorGPU))
	reference, err := catalogReference(data, "ap-northeast-1", FlavorGPU)
	if err != nil || reference.OwnerID != PublisherAccountID || reference.Flavor != FlavorGPU || strings.Join(reference.GPUSupportedFamilies, ",") != "g4dn,g5,p5" {
		t.Fatalf("reference=%+v err=%v", reference, err)
	}
	for _, request := range []struct {
		region string
		flavor Flavor
	}{{"ap-northeast-2", FlavorGPU}, {"ap-northeast-1", FlavorCPU}} {
		if _, err := catalogReference(data, request.region, request.flavor); !IsFailure(err, FailureMissing) {
			t.Fatalf("missing lookup returned %v", err)
		}
	}
	for name, mutate := range map[string]func(*Reference){
		"id":                 func(r *Reference) { r.ImageID = "not-an-ami" },
		"schema":             func(r *Reference) { r.SchemaVersion = "2" },
		"release":            func(r *Reference) { r.ImageVersion = "latest" },
		"pi":                 func(r *Reference) { r.PiVersion = "0.0.1" },
		"family absent":      func(r *Reference) { r.GPUSupportedFamilies = nil },
		"families unordered": func(r *Reference) { r.GPUSupportedFamilies = []string{"g5", "g4dn"} },
		"families duplicate": func(r *Reference) { r.GPUSupportedFamilies = []string{"g5", "g5"} },
		"families malformed": func(r *Reference) { r.GPUSupportedFamilies = []string{"G5"} },
		"families combined":  func(r *Reference) { r.GPUSupportedFamilies = []string{"g4dn,g5"} },
		"families empty":     func(r *Reference) { r.GPUSupportedFamilies = []string{""} },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := referenceFixture(FlavorGPU)
			mutate(&invalid)
			if _, err := catalogReference(catalog(invalid), "ap-northeast-1", FlavorGPU); !IsFailure(err, FailureIncompatible) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	unverified := referenceFixture(FlavorGPU)
	unverified.Tested = false
	if _, err := catalogReference(catalog(unverified), "ap-northeast-1", FlavorGPU); !IsFailure(err, FailureUnverified) {
		t.Fatalf("error=%v", err)
	}
	for _, malformed := range []string{`{}`, string(data) + `{}`, strings.Replace(string(data), PublisherAccountID, "123456789012", 1), strings.Replace(string(data), `"image_id":`, `"unknown":1,"image_id":`, 1)} {
		if _, err := catalogReference([]byte(malformed), "ap-northeast-1", FlavorGPU); !IsFailure(err, FailureIncompatible) {
			t.Fatalf("malformed catalog accepted: %v", err)
		}
	}
}

func TestPublishedCatalogIsValidAndOnlyContainsQualifiedEntries(t *testing.T) {
	var catalog struct {
		Regions map[string]map[Flavor]json.RawMessage `json:"regions"`
	}
	if err := json.Unmarshal(publishedCatalog, &catalog); err != nil {
		t.Fatal(err)
	}
	// Empty catalogs are intentionally valid while live qualification is pending.
	if _, err := PublishedReference("unpublished-region", FlavorCPU); !IsFailure(err, FailureMissing) {
		t.Fatalf("catalog header invalid: %v", err)
	}
	for region, entries := range catalog.Regions {
		for flavor := range entries {
			if _, err := PublishedReference(region, flavor); err != nil {
				t.Fatalf("%s/%s: %v", region, flavor, err)
			}
		}
	}
}

func TestRetainedProvenanceDoesNotRequireCurrentCatalogEntry(t *testing.T) {
	if !ValidProvenance(PublisherAccountID, "ami-0123456789abcdef0", "0.9.0", RollbackPiVersion) {
		t.Fatal("qualified retained release rejected")
	}
	if ValidProvenance("123456789012", "ami-0123456789abcdef0", ImageVersion, PiVersion) {
		t.Fatal("customer-owned image accepted as publisher provenance")
	}
}

func TestCPUReferenceRejectsGPUFamilyMetadata(t *testing.T) {
	for _, families := range [][]string{{"g5"}, {""}} {
		reference := referenceFixture(FlavorCPU)
		reference.GPUSupportedFamilies = families
		if err := ValidateReference(reference); !IsFailure(err, FailureIncompatible) {
			t.Fatalf("families=%q error=%v", families, err)
		}
	}
}

func imageFixture() types.Image {
	return types.Image{
		ImageId: aws.String("ami-0123456789abcdef0"), OwnerId: aws.String(PublisherAccountID), Public: aws.Bool(true), Name: aws.String("dirextalk-worker"),
		State: types.ImageStateAvailable, Architecture: types.ArchitectureValuesX8664, VirtualizationType: types.VirtualizationTypeHvm,
		RootDeviceType: types.DeviceTypeEbs, RootDeviceName: aws.String("/dev/sda1"), CreationDate: aws.String("2026-09-02T00:00:00Z"),
		BlockDeviceMappings: []types.BlockDeviceMapping{{DeviceName: aws.String("/dev/sda1"), Ebs: &types.EbsBlockDevice{VolumeSize: aws.Int32(24)}}},
	}
}
