package releaseecr

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	managedTestRevision = "0123456789abcdef0123456789abcdef01234567"
	managedTestTag      = "v0.1.0-alpha.20260718.1-0123456789ab"
)

type managedECRFake struct {
	repositories  map[string]ecrtypes.Repository
	tags          map[string][]ecrtypes.Tag
	images        map[string][]ecrtypes.ImageDetail
	describeCalls []string
	tagCalls      []string
	imageCalls    []ecr.DescribeImagesInput
	err           error
}

func (client *managedECRFake) DescribeRepositories(_ context.Context, input *ecr.DescribeRepositoriesInput, _ ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	if client.err != nil {
		return nil, client.err
	}
	if input == nil || aws.ToString(input.RegistryId) != testAccount || len(input.RepositoryNames) != 1 {
		return nil, errors.New("invalid describe input with provider detail")
	}
	name := input.RepositoryNames[0]
	client.describeCalls = append(client.describeCalls, name)
	repository, found := client.repositories[name]
	if !found {
		return nil, &ecrtypes.RepositoryNotFoundException{Message: aws.String("missing repository with provider detail")}
	}
	return &ecr.DescribeRepositoriesOutput{Repositories: []ecrtypes.Repository{repository}}, nil
}

func (client *managedECRFake) ListTagsForResource(_ context.Context, input *ecr.ListTagsForResourceInput, _ ...func(*ecr.Options)) (*ecr.ListTagsForResourceOutput, error) {
	if client.err != nil {
		return nil, client.err
	}
	for name, repository := range client.repositories {
		if aws.ToString(repository.RepositoryArn) == aws.ToString(input.ResourceArn) {
			client.tagCalls = append(client.tagCalls, name)
			return &ecr.ListTagsForResourceOutput{Tags: append([]ecrtypes.Tag(nil), client.tags[name]...)}, nil
		}
	}
	return nil, errors.New("unknown ARN with provider detail")
}

func (client *managedECRFake) DescribeImages(_ context.Context, input *ecr.DescribeImagesInput, _ ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
	if client.err != nil {
		return nil, client.err
	}
	if input == nil || aws.ToString(input.RegistryId) != testAccount || len(input.ImageIds) != 1 ||
		aws.ToString(input.ImageIds[0].ImageDigest) != "" || aws.ToString(input.ImageIds[0].ImageTag) != managedTestTag {
		return nil, errors.New("invalid image input with provider detail")
	}
	client.imageCalls = append(client.imageCalls, *input)
	details, found := client.images[aws.ToString(input.RepositoryName)]
	if !found {
		return nil, &ecrtypes.ImageNotFoundException{Message: aws.String("missing image with provider detail")}
	}
	return &ecr.DescribeImagesOutput{ImageDetails: append([]ecrtypes.ImageDetail(nil), details...)}, nil
}

func TestVerifyManagedReadsOnlyFixedRepositoriesAndAttestsReleaseManifest(t *testing.T) {
	manifest := validManagedManifest()
	client := validManagedECR(manifest)
	verifier, err := NewManagedVerifier(validManagedOptions(manifest), ManagedClients{Region: testRegion, STS: validSTS(), ECR: client})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := verifier.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.SchemaVersion != ManagedReceiptSchemaV1 || receipt.AccountID != testAccount || receipt.Region != testRegion ||
		receipt.RegistryHost != registryHost(testAccount, testRegion) || receipt.Retention != ManagedRetention ||
		receipt.ReleaseTag != managedTestTag || receipt.ReleaseManifestDigest != wantDigest ||
		receipt.VerifiedAt != testNow.Format(time.RFC3339Nano) || len(receipt.Repositories) != len(FixedRepositories()) {
		t.Fatalf("managed receipt = %#v", receipt)
	}
	wantNames := []string{RepositoryAgent, RepositoryWorker, RepositoryReaper}
	if !slices.Equal(client.describeCalls, wantNames) || !slices.Equal(client.tagCalls, wantNames) || len(client.imageCalls) != len(wantNames) {
		t.Fatalf("read scope: describe=%#v tags=%#v images=%#v", client.describeCalls, client.tagCalls, client.imageCalls)
	}
	for index, repository := range receipt.Repositories {
		spec := FixedRepositories()[index]
		if repository.Component != spec.Component || repository.Name != spec.Name || repository.Retention != ManagedRetention ||
			repository.ARN != aws.ToString(client.repositories[spec.Name].RepositoryArn) ||
			repository.URI != registryHost(testAccount, testRegion)+"/"+spec.Name ||
			repository.ReleaseTag != managedTestTag || repository.Image != managedImage(manifest, spec.Component) ||
			repository.ImageDigest != strings.Split(managedImage(manifest, spec.Component), "@")[1] {
			t.Fatalf("repository receipt[%d] = %#v", index, repository)
		}
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"authorization", "password", "token", "caller_arn", "provider detail"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("managed receipt exposed %q: %s", forbidden, encoded)
		}
	}
}

func TestVerifyManagedFailsClosedOnIdentityRegionManifestRepositoryTagAndImageDrift(t *testing.T) {
	manifest := validManagedManifest()
	tests := []struct {
		name      string
		options   ManagedVerifyOptions
		region    string
		sts       *fakeSTS
		mutate    func(*managedECRFake)
		want      error
		wantNoECR bool
	}{
		{name: "SDK region mismatch", options: validManagedOptions(manifest), region: "eu-west-1", sts: validSTS(), want: ErrRegionMismatch, wantNoECR: true},
		{name: "caller account mismatch", options: validManagedOptions(manifest), region: testRegion, sts: &fakeSTS{output: &sts.GetCallerIdentityOutput{
			Account: aws.String("999999999999"), Arn: aws.String("arn:aws:iam::999999999999:role/release"), UserId: aws.String("AROATEST:release"),
		}}, want: ErrIdentityMismatch, wantNoECR: true},
		{name: "manifest account binding", options: managedOptionsWithImage(manifest, "agent", "999999999999.dkr.ecr.us-east-1.amazonaws.com/"+RepositoryAgent+":"+managedTestTag+"@"+managedDigest('a')), region: testRegion, sts: validSTS(), want: ErrReleaseManifestBinding, wantNoECR: true},
		{name: "manifest region binding", options: managedOptionsWithImage(manifest, "worker", testAccount+".dkr.ecr.eu-west-1.amazonaws.com/"+RepositoryWorker+":"+managedTestTag+"@"+managedDigest('b')), region: testRegion, sts: validSTS(), want: ErrReleaseManifestBinding, wantNoECR: true},
		{name: "manifest repository binding", options: managedOptionsWithImage(manifest, "reaper", registryHost(testAccount, testRegion)+"/unexpected-reaper:"+managedTestTag+"@"+managedDigest('c')), region: testRegion, sts: validSTS(), want: ErrReleaseManifestBinding, wantNoECR: true},
		{name: "missing retention tag", options: validManagedOptions(manifest), region: testRegion, sts: validSTS(), mutate: func(client *managedECRFake) {
			client.tags[RepositoryAgent] = client.tags[RepositoryAgent][:3]
		}, want: ErrRepositoryDrift},
		{name: "wrong retention tag", options: validManagedOptions(manifest), region: testRegion, sts: validSTS(), mutate: func(client *managedECRFake) {
			client.tags[RepositoryAgent][3].Value = aws.String("ephemeral")
		}, want: ErrRepositoryDrift},
		{name: "unexpected tag", options: validManagedOptions(manifest), region: testRegion, sts: validSTS(), mutate: func(client *managedECRFake) {
			client.tags[RepositoryAgent] = append(client.tags[RepositoryAgent], ecrtypes.Tag{Key: aws.String("adopted"), Value: aws.String("true")})
		}, want: ErrRepositoryDrift},
		{name: "repository ARN drift", options: validManagedOptions(manifest), region: testRegion, sts: validSTS(), mutate: func(client *managedECRFake) {
			repository := client.repositories[RepositoryAgent]
			repository.RepositoryArn = aws.String("arn:aws:ecr:" + testRegion + ":" + testAccount + ":repository/unexpected")
			client.repositories[RepositoryAgent] = repository
		}, want: ErrRepositoryDrift},
		{name: "repository config drift", options: validManagedOptions(manifest), region: testRegion, sts: validSTS(), mutate: func(client *managedECRFake) {
			repository := client.repositories[RepositoryWorker]
			repository.ImageTagMutability = ecrtypes.ImageTagMutabilityMutable
			client.repositories[RepositoryWorker] = repository
		}, want: ErrRepositoryDrift},
		{name: "image wrong repository", options: validManagedOptions(manifest), region: testRegion, sts: validSTS(), mutate: func(client *managedECRFake) {
			client.images[RepositoryAgent][0].RepositoryName = aws.String(RepositoryWorker)
		}, want: ErrReleaseImageBinding},
		{name: "image wrong tag", options: validManagedOptions(manifest), region: testRegion, sts: validSTS(), mutate: func(client *managedECRFake) {
			client.images[RepositoryAgent][0].ImageTags = []string{"latest"}
		}, want: ErrReleaseImageBinding},
		{name: "image wrong digest", options: validManagedOptions(manifest), region: testRegion, sts: validSTS(), mutate: func(client *managedECRFake) {
			client.images[RepositoryAgent][0].ImageDigest = aws.String(managedDigest('f'))
		}, want: ErrReleaseImageBinding},
		{name: "image missing", options: validManagedOptions(manifest), region: testRegion, sts: validSTS(), mutate: func(client *managedECRFake) {
			delete(client.images, RepositoryAgent)
		}, want: ErrReleaseImageBinding},
		{name: "image ambiguous", options: validManagedOptions(manifest), region: testRegion, sts: validSTS(), mutate: func(client *managedECRFake) {
			client.images[RepositoryAgent] = append(client.images[RepositoryAgent], client.images[RepositoryAgent][0])
		}, want: ErrReleaseImageBinding},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := validManagedECR(manifest)
			if test.mutate != nil {
				test.mutate(client)
			}
			verifier, err := NewManagedVerifier(test.options, ManagedClients{Region: test.region, STS: test.sts, ECR: client})
			if errors.Is(test.want, ErrRegionMismatch) {
				if !errors.Is(err, test.want) {
					t.Fatalf("NewManagedVerifier error = %v, want %v", err, test.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifier.Verify(context.Background()); !errors.Is(err, test.want) {
				t.Fatalf("Verify error = %v, want %v", err, test.want)
			}
			if test.wantNoECR && (len(client.describeCalls) != 0 || len(client.tagCalls) != 0 || len(client.imageCalls) != 0) {
				t.Fatalf("precondition failure reached ECR: %#v %#v %#v", client.describeCalls, client.tagCalls, client.imageCalls)
			}
		})
	}
}

func TestVerifyManagedRedactsProviderFailuresAndNeverAuthenticatesOrMutates(t *testing.T) {
	secret := "provider-secret-response-canary"
	manifest := validManagedManifest()
	client := validManagedECR(manifest)
	client.err = errors.New(secret)
	verifier, err := NewManagedVerifier(validManagedOptions(manifest), ManagedClients{Region: testRegion, STS: validSTS(), ECR: client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background()); !errors.Is(err, ErrAWSOperation) || strings.Contains(err.Error(), secret) {
		t.Fatalf("provider failure was not redacted: %v", err)
	}
	// ManagedECRAPI deliberately has no create, tag, authorization-token, image
	// put, or delete method. A verifier cannot mutate even through its injected
	// provider boundary.
}

func validManagedOptions(manifest releaseartifact.ReleaseManifestV1) ManagedVerifyOptions {
	return ManagedVerifyOptions{
		Region: testRegion, ExpectedAccountID: testAccount, ReleaseManifest: manifest,
		Now: func() time.Time { return testNow },
	}
}

func managedOptionsWithImage(manifest releaseartifact.ReleaseManifestV1, component, image string) ManagedVerifyOptions {
	switch component {
	case "agent":
		manifest.AgentImage = image
	case "worker":
		manifest.WorkerImage = image
	case "reaper":
		manifest.ReaperImage = image
	}
	return validManagedOptions(manifest)
}

func validManagedManifest() releaseartifact.ReleaseManifestV1 {
	return releaseartifact.ReleaseManifestV1{
		SchemaVersion: releaseartifact.SchemaVersionV1,
		ReleaseTag:    managedTestTag, GitRevision: managedTestRevision, OS: "linux", Architecture: "amd64",
		AgentImage:         managedReference(RepositoryAgent, managedDigest('a')),
		WorkerImage:        managedReference(RepositoryWorker, managedDigest('b')),
		ReaperImage:        managedReference(RepositoryReaper, managedDigest('c')),
		WorkerRootFSDigest: managedDigest('d'), WorkerBinaryDigest: managedDigest('e'), GeneratedAt: "2026-07-18T00:00:00Z",
	}
}

func validManagedECR(manifest releaseartifact.ReleaseManifestV1) *managedECRFake {
	client := &managedECRFake{
		repositories: make(map[string]ecrtypes.Repository), tags: make(map[string][]ecrtypes.Tag), images: make(map[string][]ecrtypes.ImageDetail),
	}
	for _, spec := range FixedRepositories() {
		client.repositories[spec.Name] = validRepository(spec.Name)
		client.tags[spec.Name] = validRepositoryTags(spec.Name)
		image := managedImage(manifest, spec.Component)
		client.images[spec.Name] = []ecrtypes.ImageDetail{{
			RegistryId: aws.String(testAccount), RepositoryName: aws.String(spec.Name), ImageDigest: aws.String(strings.Split(image, "@")[1]), ImageTags: []string{managedTestTag},
		}}
	}
	return client
}

func managedImage(manifest releaseartifact.ReleaseManifestV1, component string) string {
	switch component {
	case "agent":
		return manifest.AgentImage
	case "worker":
		return manifest.WorkerImage
	case "reaper":
		return manifest.ReaperImage
	default:
		return ""
	}
}

func managedReference(repository, digest string) string {
	return registryHost(testAccount, testRegion) + "/" + repository + ":" + managedTestTag + "@" + digest
}

func managedDigest(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}
