package releaseecr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

const (
	BuildSourcePlatformOS           = "linux"
	BuildSourcePlatformArchitecture = "amd64"
	BuildSourceRegion               = "ap-northeast-3"

	buildKitSourceDigest   = "sha256:63db51c9b30208a7c2b1c40392c7ebb9ce2f85ba238a18a85420f8f5ea2d4684"
	frontendSourceDigest   = "sha256:b5f3b260a9678e1d83d2fce86eeddf79420b79147eaba2a25986f47133d73720"
	goBaseSourceDigest     = "sha256:7c6a62c80c3f15fb49aae282d7a296149889ebe39b2318f3a299f2759c1ce135"
	lambdaBaseSourceDigest = "sha256:f91e5c83528080b2e41d22536d413042e451e67968c7473c4f7e77a627c944bc"
)

const (
	buildKitSourceTag   = "buildkit-linux-amd64"
	frontendSourceTag   = "dockerfile-frontend-linux-amd64"
	goBaseSourceTag     = "go-build-base-linux-amd64"
	lambdaBaseSourceTag = "reaper-runtime-base-linux-amd64"
)

const (
	ociManifestMediaType    = "application/vnd.oci.image.manifest.v1+json"
	dockerManifestMediaType = "application/vnd.docker.distribution.manifest.v2+json"
)

type BuildSourceRole string

const (
	BuildSourceBuildKit      BuildSourceRole = "buildkit"
	BuildSourceFrontend      BuildSourceRole = "dockerfile_frontend"
	BuildSourceGoBase        BuildSourceRole = "go_build_base"
	BuildSourceLambdaRuntime BuildSourceRole = "reaper_runtime_base"
)

// BuildSourceCatalogEntry is a closed source-image binding. UpstreamHost and
// UpstreamRepository are consumed only by the explicit seed path. Release
// preparation and publication derive private references from RegistryHost.
type BuildSourceCatalogEntry struct {
	Role               BuildSourceRole
	Tag                string
	Digest             string
	UpstreamHost       string
	UpstreamAuthHost   string
	UpstreamRepository string
}

var buildSourceCatalog = []BuildSourceCatalogEntry{
	{Role: BuildSourceBuildKit, Tag: buildKitSourceTag, Digest: buildKitSourceDigest, UpstreamHost: "registry-1.docker.io", UpstreamAuthHost: "auth.docker.io", UpstreamRepository: "moby/buildkit"},
	{Role: BuildSourceFrontend, Tag: frontendSourceTag, Digest: frontendSourceDigest, UpstreamHost: "registry-1.docker.io", UpstreamAuthHost: "auth.docker.io", UpstreamRepository: "docker/dockerfile"},
	{Role: BuildSourceGoBase, Tag: goBaseSourceTag, Digest: goBaseSourceDigest, UpstreamHost: "registry-1.docker.io", UpstreamAuthHost: "auth.docker.io", UpstreamRepository: "library/golang"},
	{Role: BuildSourceLambdaRuntime, Tag: lambdaBaseSourceTag, Digest: lambdaBaseSourceDigest, UpstreamHost: "public.ecr.aws", UpstreamAuthHost: "public.ecr.aws", UpstreamRepository: "lambda/provided"},
}

func BuildSourceCatalog() []BuildSourceCatalogEntry {
	return append([]BuildSourceCatalogEntry(nil), buildSourceCatalog...)
}

type BuildSourceReferences struct {
	BuildKit      string
	Frontend      string
	GoBuildBase   string
	ReaperRuntime string
}

func PrivateBuildSourceReferences(registryHost string) (BuildSourceReferences, error) {
	suffix := ".dkr.ecr." + BuildSourceRegion + ".amazonaws.com"
	accountID := strings.TrimSuffix(registryHost, suffix)
	if registryHost == "" || strings.ContainsAny(registryHost, "/:@ \t\r\n") ||
		accountID == registryHost || !accountPattern.MatchString(accountID) {
		return BuildSourceReferences{}, ErrBuildSource
	}
	reference := func(entry BuildSourceCatalogEntry) string {
		return registryHost + "/" + RepositoryBuildSource + ":" + entry.Tag + "@" + entry.Digest
	}
	return BuildSourceReferences{
		BuildKit:      reference(buildSourceCatalog[0]),
		Frontend:      reference(buildSourceCatalog[1]),
		GoBuildBase:   reference(buildSourceCatalog[2]),
		ReaperRuntime: reference(buildSourceCatalog[3]),
	}, nil
}

type buildSourceReadAPI interface {
	DescribeRepositories(context.Context, *ecr.DescribeRepositoriesInput, ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	ListTagsForResource(context.Context, *ecr.ListTagsForResourceInput, ...func(*ecr.Options)) (*ecr.ListTagsForResourceOutput, error)
	BatchGetImage(context.Context, *ecr.BatchGetImageInput, ...func(*ecr.Options)) (*ecr.BatchGetImageOutput, error)
	DescribeImages(context.Context, *ecr.DescribeImagesInput, ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error)
}

type buildSourceManifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Config        struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	} `json:"layers"`
}

func verifyBuildSources(ctx context.Context, client buildSourceReadAPI, partition, accountID, region, registryHost string) error {
	if client == nil {
		return ErrBuildSource
	}
	spec := RepositorySpec{Component: "build-sources", Name: RepositoryBuildSource}
	output, err := client.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{
		RegistryId: aws.String(accountID), RepositoryNames: []string{RepositoryBuildSource},
	})
	if err != nil || output == nil || len(output.Repositories) != 1 {
		return ErrBuildSource
	}
	repository := output.Repositories[0]
	if validateRepository(repository, partition, accountID, region, registryHost, RepositoryBuildSource) != nil {
		return ErrBuildSourceMismatch
	}
	tags, err := client.ListTagsForResource(ctx, &ecr.ListTagsForResourceInput{ResourceArn: repository.RepositoryArn})
	if err != nil || tags == nil || !exactRepositoryTags(tags.Tags, spec) {
		return ErrBuildSourceMismatch
	}
	for _, entry := range buildSourceCatalog {
		if err := verifyBuildSourceImage(ctx, client, accountID, entry); err != nil {
			return err
		}
	}
	return nil
}

func verifyBuildSourceImage(ctx context.Context, client buildSourceReadAPI, accountID string, entry BuildSourceCatalogEntry) error {
	images, err := client.BatchGetImage(ctx, &ecr.BatchGetImageInput{
		RegistryId: aws.String(accountID), RepositoryName: aws.String(RepositoryBuildSource),
		ImageIds:           []ecrtypes.ImageIdentifier{{ImageTag: aws.String(entry.Tag)}},
		AcceptedMediaTypes: []string{ociManifestMediaType, dockerManifestMediaType},
	})
	if err != nil || images == nil {
		return ErrBuildSource
	}
	if len(images.Failures) == 1 && len(images.Images) == 0 &&
		images.Failures[0].FailureCode == ecrtypes.ImageFailureCodeImageNotFound &&
		images.Failures[0].ImageId != nil &&
		aws.ToString(images.Failures[0].ImageId.ImageTag) == entry.Tag {
		return ErrBuildSourceMissing
	}
	if len(images.Failures) != 0 || len(images.Images) != 1 {
		return ErrBuildSource
	}
	image := images.Images[0]
	raw := []byte(aws.ToString(image.ImageManifest))
	if !validDigestBytes(entry.Digest, raw) || image.ImageId == nil ||
		aws.ToString(image.ImageId.ImageDigest) != entry.Digest ||
		aws.ToString(image.ImageId.ImageTag) != entry.Tag ||
		(aws.ToString(image.ImageManifestMediaType) != ociManifestMediaType &&
			aws.ToString(image.ImageManifestMediaType) != dockerManifestMediaType) {
		return ErrBuildSourceMismatch
	}
	var manifest buildSourceManifest
	if json.Unmarshal(raw, &manifest) != nil || manifest.SchemaVersion != 2 ||
		manifest.MediaType != aws.ToString(image.ImageManifestMediaType) ||
		!validManifestDescriptors(manifest) {
		return ErrBuildSourceMismatch
	}
	details, err := client.DescribeImages(ctx, &ecr.DescribeImagesInput{
		RegistryId: aws.String(accountID), RepositoryName: aws.String(RepositoryBuildSource),
		ImageIds: []ecrtypes.ImageIdentifier{{ImageDigest: aws.String(entry.Digest)}},
	})
	if err != nil || details == nil || len(details.ImageDetails) != 1 {
		return ErrBuildSource
	}
	detail := details.ImageDetails[0]
	if aws.ToString(detail.ImageDigest) != entry.Digest ||
		aws.ToString(detail.ImageManifestMediaType) != manifest.MediaType ||
		!slices.Contains(detail.ImageTags, entry.Tag) {
		return ErrBuildSourceMismatch
	}
	return nil
}

func validManifestDescriptors(manifest buildSourceManifest) bool {
	if !validDigest(manifest.Config.Digest) || manifest.Config.Size <= 0 ||
		manifest.Config.MediaType == "" || len(manifest.Layers) == 0 {
		return false
	}
	for _, layer := range manifest.Layers {
		if !validDigest(layer.Digest) || layer.Size <= 0 || layer.MediaType == "" {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func validDigestBytes(want string, content []byte) bool {
	if !validDigest(want) {
		return false
	}
	sum := sha256.Sum256(content)
	return "sha256:"+hex.EncodeToString(sum[:]) == want
}
