package releaseecr

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type ManagedVerifier struct {
	options ManagedVerifyOptions
	clients ManagedClients
}

type releaseBinding struct {
	spec   RepositorySpec
	image  string
	digest string
}

func NewManagedVerifier(options ManagedVerifyOptions, clients ManagedClients) (*ManagedVerifier, error) {
	manifest, err := releaseartifact.Normalize(options.ReleaseManifest)
	if err != nil || !regionPattern.MatchString(options.Region) || !accountPattern.MatchString(options.ExpectedAccountID) ||
		options.Now == nil || clients.STS == nil || clients.ECR == nil {
		return nil, ErrInvalidInput
	}
	if clients.Region != options.Region {
		return nil, ErrRegionMismatch
	}
	options.ReleaseManifest = manifest
	return &ManagedVerifier{options: options, clients: clients}, nil
}

// VerifyManagedDefault resolves credentials only through the AWS SDK default
// chain and performs no mutation or registry authentication operation.
func VerifyManagedDefault(ctx context.Context, options ManagedVerifyOptions) (ManagedReceiptV1, error) {
	if options.Now == nil {
		options.Now = time.Now
	}
	if _, err := releaseartifact.Normalize(options.ReleaseManifest); err != nil ||
		!regionPattern.MatchString(options.Region) || !accountPattern.MatchString(options.ExpectedAccountID) {
		return ManagedReceiptV1{}, ErrInvalidInput
	}
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(options.Region))
	if err != nil {
		return ManagedReceiptV1{}, redactedAWSFailure(ctx)
	}
	verifier, err := NewManagedVerifier(options, ManagedClients{
		Region: awsConfig.Region,
		STS:    sts.NewFromConfig(awsConfig),
		ECR:    ecr.NewFromConfig(awsConfig),
	})
	if err != nil {
		return ManagedReceiptV1{}, err
	}
	return verifier.Verify(ctx)
}

func (verifier *ManagedVerifier) Verify(ctx context.Context) (ManagedReceiptV1, error) {
	partition, err := verifyExpectedIdentity(ctx, verifier.options.ExpectedAccountID, verifier.clients.STS)
	if err != nil {
		return ManagedReceiptV1{}, err
	}
	registryHost, err := expectedRegistryHost(partition, verifier.options.ExpectedAccountID, verifier.options.Region)
	if err != nil {
		return ManagedReceiptV1{}, err
	}
	bindings, err := managedReleaseBindings(verifier.options.ReleaseManifest, registryHost)
	if err != nil {
		return ManagedReceiptV1{}, err
	}
	manifestDigest, err := verifier.options.ReleaseManifest.Digest()
	if err != nil {
		return ManagedReceiptV1{}, ErrInvalidInput
	}

	repositories := make([]ManagedRepositoryReceiptV1, 0, len(bindings))
	for _, binding := range bindings {
		repository, err := verifier.readRepository(ctx, partition, registryHost, binding.spec)
		if err != nil {
			return ManagedReceiptV1{}, err
		}
		if err := verifier.readImageBinding(ctx, binding); err != nil {
			return ManagedReceiptV1{}, err
		}
		repositories = append(repositories, ManagedRepositoryReceiptV1{
			Component:   binding.spec.Component,
			Name:        binding.spec.Name,
			ARN:         aws.ToString(repository.RepositoryArn),
			URI:         aws.ToString(repository.RepositoryUri),
			Retention:   ManagedRetention,
			ReleaseTag:  verifier.options.ReleaseManifest.ReleaseTag,
			ImageDigest: binding.digest,
			Image:       binding.image,
		})
	}
	verifiedAt := verifier.options.Now().UTC()
	if verifiedAt.IsZero() {
		return ManagedReceiptV1{}, ErrInvalidInput
	}
	return ManagedReceiptV1{
		SchemaVersion:         ManagedReceiptSchemaV1,
		AccountID:             verifier.options.ExpectedAccountID,
		Region:                verifier.options.Region,
		RegistryHost:          registryHost,
		Retention:             ManagedRetention,
		ReleaseTag:            verifier.options.ReleaseManifest.ReleaseTag,
		ReleaseManifestDigest: manifestDigest,
		VerifiedAt:            verifiedAt.Format(time.RFC3339Nano),
		Repositories:          repositories,
	}, nil
}

func managedReleaseBindings(manifest releaseartifact.ReleaseManifestV1, registryHost string) ([]releaseBinding, error) {
	images := map[string]string{
		"agent":  manifest.AgentImage,
		"worker": manifest.WorkerImage,
		"reaper": manifest.ReaperImage,
	}
	bindings := make([]releaseBinding, 0, len(fixedRepositories))
	for _, spec := range fixedRepositories {
		image := images[spec.Component]
		nameAndTag, digest, found := strings.Cut(image, "@")
		if !found || nameAndTag != registryHost+"/"+spec.Name+":"+manifest.ReleaseTag || digest == "" {
			return nil, ErrReleaseManifestBinding
		}
		bindings = append(bindings, releaseBinding{spec: spec, image: image, digest: digest})
	}
	return bindings, nil
}

func (verifier *ManagedVerifier) readRepository(ctx context.Context, partition, registryHost string, spec RepositorySpec) (ecrtypes.Repository, error) {
	output, err := verifier.clients.ECR.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{
		RegistryId: aws.String(verifier.options.ExpectedAccountID), RepositoryNames: []string{spec.Name},
	})
	if err != nil {
		var missing *ecrtypes.RepositoryNotFoundException
		if errors.As(err, &missing) {
			return ecrtypes.Repository{}, ErrRepositoryDrift
		}
		return ecrtypes.Repository{}, redactedAWSFailure(ctx)
	}
	if output == nil || len(output.Repositories) != 1 {
		return ecrtypes.Repository{}, ErrRepositoryDrift
	}
	repository := output.Repositories[0]
	if err := validateRepository(repository, partition, verifier.options.ExpectedAccountID, verifier.options.Region, registryHost, spec.Name); err != nil {
		return ecrtypes.Repository{}, err
	}
	tags, err := verifier.clients.ECR.ListTagsForResource(ctx, &ecr.ListTagsForResourceInput{ResourceArn: repository.RepositoryArn})
	if err != nil {
		return ecrtypes.Repository{}, redactedAWSFailure(ctx)
	}
	if tags == nil || !exactRepositoryTags(tags.Tags, spec) {
		return ecrtypes.Repository{}, ErrRepositoryDrift
	}
	return repository, nil
}

func (verifier *ManagedVerifier) readImageBinding(ctx context.Context, binding releaseBinding) error {
	output, err := verifier.clients.ECR.DescribeImages(ctx, &ecr.DescribeImagesInput{
		RegistryId:     aws.String(verifier.options.ExpectedAccountID),
		RepositoryName: aws.String(binding.spec.Name),
		ImageIds:       []ecrtypes.ImageIdentifier{{ImageTag: aws.String(verifier.options.ReleaseManifest.ReleaseTag)}},
	})
	if err != nil {
		var imageMissing *ecrtypes.ImageNotFoundException
		if errors.As(err, &imageMissing) {
			return ErrReleaseImageBinding
		}
		var repositoryMissing *ecrtypes.RepositoryNotFoundException
		if errors.As(err, &repositoryMissing) {
			return ErrRepositoryDrift
		}
		return redactedAWSFailure(ctx)
	}
	if output == nil || aws.ToString(output.NextToken) != "" || len(output.ImageDetails) != 1 {
		return ErrReleaseImageBinding
	}
	detail := output.ImageDetails[0]
	if aws.ToString(detail.RegistryId) != verifier.options.ExpectedAccountID ||
		aws.ToString(detail.RepositoryName) != binding.spec.Name || aws.ToString(detail.ImageDigest) != binding.digest {
		return ErrReleaseImageBinding
	}
	tagMatches := 0
	for _, tag := range detail.ImageTags {
		if tag == verifier.options.ReleaseManifest.ReleaseTag {
			tagMatches++
		}
	}
	if tagMatches != 1 {
		return ErrReleaseImageBinding
	}
	return nil
}
