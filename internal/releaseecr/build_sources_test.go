package releaseecr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

func TestBuildSourceCatalogIsClosedAndSeparateFromReleaseRepositories(t *testing.T) {
	want := []struct {
		role   BuildSourceRole
		digest string
	}{
		{BuildSourceBuildKit, "sha256:63db51c9b30208a7c2b1c40392c7ebb9ce2f85ba238a18a85420f8f5ea2d4684"},
		{BuildSourceFrontend, "sha256:b5f3b260a9678e1d83d2fce86eeddf79420b79147eaba2a25986f47133d73720"},
		{BuildSourceGoBase, "sha256:7c6a62c80c3f15fb49aae282d7a296149889ebe39b2318f3a299f2759c1ce135"},
		{BuildSourceLambdaRuntime, "sha256:f91e5c83528080b2e41d22536d413042e451e67968c7473c4f7e77a627c944bc"},
	}
	catalog := BuildSourceCatalog()
	if len(catalog) != len(want) {
		t.Fatalf("catalog entries = %d", len(catalog))
	}
	seenTags := map[string]bool{}
	for index, entry := range catalog {
		if entry.Role != want[index].role || entry.Digest != want[index].digest ||
			entry.Tag == "" || seenTags[entry.Tag] || entry.UpstreamHost == "" ||
			entry.UpstreamAuthHost == "" || entry.UpstreamRepository == "" {
			t.Fatalf("catalog[%d] = %#v", index, entry)
		}
		seenTags[entry.Tag] = true
	}
	for _, repository := range FixedRepositories() {
		if repository.Name == RepositoryBuildSource {
			t.Fatal("build source repository entered the release manifest repository set")
		}
	}
	references, err := PrivateBuildSourceReferences(registryHost(testAccount, BuildSourceRegion))
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range []string{references.BuildKit, references.Frontend, references.GoBuildBase, references.ReaperRuntime} {
		if !strings.HasPrefix(reference, registryHost(testAccount, BuildSourceRegion)+"/"+RepositoryBuildSource+":") ||
			!strings.Contains(reference, "@sha256:") || strings.Contains(reference, "docker.io") ||
			strings.Contains(reference, "public.ecr.aws") {
			t.Fatalf("non-private source reference %q", reference)
		}
	}
	if _, err := PrivateBuildSourceReferences(registryHost(testAccount, "us-east-1")); !errors.Is(err, ErrBuildSource) {
		t.Fatalf("non-Osaka registry error = %v", err)
	}
	if validBuildSourceOptions(BuildSourceOptions{Region: "us-east-1", ExpectedAccountID: testAccount}) {
		t.Fatal("non-Osaka source options accepted")
	}
}

func TestVerifyBuildSourceImageRequiresRawManifestAndTagDigestReadback(t *testing.T) {
	fixture := newSourceFixture(t)
	client := &sourceReadFake{
		manifest: fixture.manifest, mediaType: fixture.mediaType, entry: fixture.entry,
		detail: ecrtypes.ImageDetail{
			ImageDigest: aws.String(fixture.entry.Digest), ImageManifestMediaType: aws.String(fixture.mediaType),
			ImageTags: []string{fixture.entry.Tag},
		},
	}
	if err := verifyBuildSourceImage(context.Background(), client, testAccount, fixture.entry); err != nil {
		t.Fatal(err)
	}
	client.manifest = append([]byte(nil), fixture.manifest...)
	client.manifest[len(client.manifest)-2] ^= 1
	if err := verifyBuildSourceImage(context.Background(), client, testAccount, fixture.entry); !errors.Is(err, ErrBuildSourceMismatch) {
		t.Fatalf("tampered manifest error = %v", err)
	}
}

func TestPrepareBuildSourcesCreatesOnlyRetainedRepositoryAndReadsBack(t *testing.T) {
	backend := &fakeECR{repositories: map[string]ecrtypes.Repository{}}
	client := &sourceSeedFake{fakeECR: backend}
	result, err := prepareBuildSources(context.Background(), BuildSourceOptions{
		Region: BuildSourceRegion, ExpectedAccountID: testAccount,
	}, buildSourceClients{Region: BuildSourceRegion, STS: validSTS(), ECR: client})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Created || result.Repository != RepositoryBuildSource || !result.RepositoryVerified || result.CatalogVerified || result.Seeded ||
		len(backend.createCalls) != 1 || aws.ToString(backend.createCalls[0].RepositoryName) != RepositoryBuildSource {
		t.Fatalf("prepare result=%#v calls=%#v", result, backend.createCalls)
	}
	input := backend.createCalls[0]
	if input.ImageTagMutability != ecrtypes.ImageTagMutabilityImmutable ||
		input.ImageScanningConfiguration == nil || !input.ImageScanningConfiguration.ScanOnPush ||
		input.EncryptionConfiguration == nil || input.EncryptionConfiguration.EncryptionType != ecrtypes.EncryptionTypeAes256 ||
		!equalRepositoryTags(input.Tags, repositoryTags(RepositorySpec{Component: "build-sources", Name: RepositoryBuildSource})) {
		t.Fatalf("source repository config = %#v", input)
	}
	if len(backend.repositories) != 1 || backend.authorizationCalls != 0 {
		t.Fatalf("prepare escaped source repository boundary: repos=%#v auth=%d", backend.repositories, backend.authorizationCalls)
	}
}

func TestDownloadBuildSourceCreatesPrivateVerifiedLinuxAMD64Layout(t *testing.T) {
	fixture := newSourceFixture(t)
	client := fixture.httpClient()
	root := t.TempDir()
	layout, err := downloadBuildSource(context.Background(), client, root, fixture.entry)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(layout.manifest, fixture.manifest) || layout.mediaType != fixture.mediaType ||
		len(layout.blobs) != 2 {
		t.Fatalf("layout = %#v", layout)
	}
	for _, name := range append([]string{layout.root, filepath.Join(layout.root, "blobs"), filepath.Join(layout.root, "blobs", "sha256")}, layout.blobs...) {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if info.IsDir() && info.Mode().Perm() != 0o700 {
			t.Fatalf("directory %s mode = %o", name, info.Mode().Perm())
		}
		if !info.IsDir() && info.Mode().Perm() != 0o600 {
			t.Fatalf("file %s mode = %o", name, info.Mode().Perm())
		}
	}
}

func TestRegistryBearerChallengeCannotEscapeClosedAuthHost(t *testing.T) {
	reader := registryReader{
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("untrusted token realm reached network")
			return nil, nil
		})},
		host: "registry.test", authHost: "auth.registry.test", repository: "closed/source",
	}
	challenge := `Bearer realm="https://attacker.invalid/token",service="registry.test",scope="repository:other/admin:*"`
	if _, err := reader.bearerToken(context.Background(), challenge); !errors.Is(err, ErrBuildSource) {
		t.Fatalf("untrusted realm error = %v", err)
	}

	scopeObserved := ""
	reader.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		scopeObserved = request.URL.Query().Get("scope")
		return response(http.StatusOK, []byte(`{"token":"closed-token","expires_in":300}`), "application/json"), nil
	})}
	challenge = `Bearer realm="https://auth.registry.test/token",service="registry.test",scope="repository:other/admin:*"`
	if token, err := reader.bearerToken(context.Background(), challenge); err != nil || token != "closed-token" {
		t.Fatalf("trusted challenge token=%q error=%v", token, err)
	}
	if scopeObserved != "repository:closed/source:pull" {
		t.Fatalf("token scope = %q", scopeObserved)
	}
}

func TestSeedBuildSourceIsConcurrentIdempotentAndReadbackAuthoritative(t *testing.T) {
	fixture := newSourceFixture(t)
	client := &memorySeedECR{fixture: fixture}
	seeder := buildSourceSeeder{accountID: testAccount, ecr: client, http: fixture.httpClient()}
	root := t.TempDir()
	errorsFound := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsFound <- seeder.seed(context.Background(), root, fixture.entry)
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	client.mutex.Lock()
	putCalls := client.putCalls
	client.mutex.Unlock()
	if putCalls != 1 {
		t.Fatalf("concurrent identical seed put calls = %d", putCalls)
	}
	if err := seeder.seed(context.Background(), root, fixture.entry); err != nil {
		t.Fatal(err)
	}
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if client.putCalls != 1 {
		t.Fatalf("idempotent seed repeated mutation: %d", client.putCalls)
	}
}

func TestSeedBuildSourceRejectsExistingMismatchWithoutMutation(t *testing.T) {
	fixture := newSourceFixture(t)
	client := &memorySeedECR{fixture: fixture, stored: true, storedManifest: []byte(`{"tampered":true}`)}
	seeder := buildSourceSeeder{accountID: testAccount, ecr: client, http: fixture.httpClient()}
	if err := seeder.seed(context.Background(), t.TempDir(), fixture.entry); !errors.Is(err, ErrBuildSourceMismatch) {
		t.Fatalf("mismatch error = %v", err)
	}
	if client.putCalls != 0 {
		t.Fatalf("mismatch caused mutation: %d", client.putCalls)
	}
}

func TestSeedBuildSourceDoesNotMutateAfterAmbiguousReadFailure(t *testing.T) {
	fixture := newSourceFixture(t)
	client := &memorySeedECR{fixture: fixture, batchErr: errors.New("provider response unavailable")}
	seeder := buildSourceSeeder{accountID: testAccount, ecr: client, http: fixture.httpClient()}
	if err := seeder.seed(context.Background(), t.TempDir(), fixture.entry); !errors.Is(err, ErrBuildSource) {
		t.Fatalf("ambiguous read error = %v", err)
	}
	if client.putCalls != 0 {
		t.Fatalf("ambiguous read caused mutation: %d", client.putCalls)
	}
}

type sourceFixture struct {
	entry     BuildSourceCatalogEntry
	manifest  []byte
	mediaType string
	config    []byte
	layer     []byte
}

func newSourceFixture(t *testing.T) sourceFixture {
	t.Helper()
	config := []byte(`{"architecture":"amd64","os":"linux"}`)
	layer := []byte("compressed-layer")
	configDigest := digestBytes(config)
	layerDigest := digestBytes(layer)
	manifest, err := json.Marshal(buildSourceManifest{
		SchemaVersion: 2,
		MediaType:     ociManifestMediaType,
		Config: struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		}{MediaType: "application/vnd.oci.image.config.v1+json", Digest: configDigest, Size: int64(len(config))},
		Layers: []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		}{{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: layerDigest, Size: int64(len(layer))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return sourceFixture{
		entry: BuildSourceCatalogEntry{
			Role: BuildSourceGoBase, Tag: "test-linux-amd64", Digest: digestBytes(manifest),
			UpstreamHost: "registry.test", UpstreamAuthHost: "auth.registry.test", UpstreamRepository: "closed/source",
		},
		manifest: manifest, mediaType: ociManifestMediaType, config: config, layer: layer,
	}
}

func (fixture sourceFixture) httpClient() *http.Client {
	blobs := map[string][]byte{
		digestBytes(fixture.config): fixture.config,
		digestBytes(fixture.layer):  fixture.layer,
	}
	return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var content []byte
		contentType := "application/octet-stream"
		switch {
		case strings.Contains(request.URL.Path, "/manifests/"):
			content = fixture.manifest
			contentType = fixture.mediaType
		case strings.Contains(request.URL.Path, "/blobs/"):
			digest := request.URL.Path[strings.LastIndex(request.URL.Path, "/")+1:]
			content = blobs[digest]
		default:
			return response(http.StatusNotFound, nil, ""), nil
		}
		if content == nil {
			return response(http.StatusNotFound, nil, ""), nil
		}
		return response(http.StatusOK, content, contentType), nil
	})}
}

func digestBytes(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func response(status int, content []byte, contentType string) *http.Response {
	header := make(http.Header)
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	return &http.Response{
		StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(content)),
	}
}

type sourceReadFake struct {
	manifest  []byte
	mediaType string
	entry     BuildSourceCatalogEntry
	detail    ecrtypes.ImageDetail
}

func (client *sourceReadFake) DescribeRepositories(context.Context, *ecr.DescribeRepositoriesInput, ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	return nil, errors.New("unexpected repository read")
}

func (client *sourceReadFake) ListTagsForResource(context.Context, *ecr.ListTagsForResourceInput, ...func(*ecr.Options)) (*ecr.ListTagsForResourceOutput, error) {
	return nil, errors.New("unexpected tag read")
}

func (client *sourceReadFake) BatchGetImage(_ context.Context, input *ecr.BatchGetImageInput, _ ...func(*ecr.Options)) (*ecr.BatchGetImageOutput, error) {
	if input == nil || aws.ToString(input.RegistryId) != testAccount ||
		aws.ToString(input.RepositoryName) != RepositoryBuildSource ||
		len(input.ImageIds) != 1 || aws.ToString(input.ImageIds[0].ImageTag) != client.entry.Tag ||
		!slices.Equal(input.AcceptedMediaTypes, []string{ociManifestMediaType, dockerManifestMediaType}) {
		return nil, errors.New("bad batch get")
	}
	return &ecr.BatchGetImageOutput{Images: []ecrtypes.Image{{
		RegistryId: aws.String(testAccount), RepositoryName: aws.String(RepositoryBuildSource),
		ImageManifest: aws.String(string(client.manifest)), ImageManifestMediaType: aws.String(client.mediaType),
		ImageId: &ecrtypes.ImageIdentifier{ImageTag: aws.String(client.entry.Tag), ImageDigest: aws.String(client.entry.Digest)},
	}}}, nil
}

func (client *sourceReadFake) DescribeImages(_ context.Context, input *ecr.DescribeImagesInput, _ ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
	if input == nil || len(input.ImageIds) != 1 ||
		aws.ToString(input.ImageIds[0].ImageTag) != "" ||
		aws.ToString(input.ImageIds[0].ImageDigest) != client.entry.Digest {
		return nil, errors.New("bad describe images")
	}
	return &ecr.DescribeImagesOutput{ImageDetails: []ecrtypes.ImageDetail{client.detail}}, nil
}

type sourceSeedFake struct {
	*fakeECR
}

func (client *sourceSeedFake) CreateRepository(_ context.Context, input *ecr.CreateRepositoryInput, _ ...func(*ecr.Options)) (*ecr.CreateRepositoryOutput, error) {
	if input == nil {
		return nil, errors.New("missing create")
	}
	client.createCalls = append(client.createCalls, *input)
	name := aws.ToString(input.RepositoryName)
	repository := validRepositoryIn(name, BuildSourceRegion)
	client.repositories[name] = repository
	if client.repositoryTags == nil {
		client.repositoryTags = make(map[string][]ecrtypes.Tag)
	}
	client.repositoryTags[name] = append([]ecrtypes.Tag(nil), input.Tags...)
	return &ecr.CreateRepositoryOutput{Repository: &repository}, nil
}

func (*sourceSeedFake) BatchCheckLayerAvailability(context.Context, *ecr.BatchCheckLayerAvailabilityInput, ...func(*ecr.Options)) (*ecr.BatchCheckLayerAvailabilityOutput, error) {
	return nil, errors.New("unexpected layer check")
}
func (*sourceSeedFake) InitiateLayerUpload(context.Context, *ecr.InitiateLayerUploadInput, ...func(*ecr.Options)) (*ecr.InitiateLayerUploadOutput, error) {
	return nil, errors.New("unexpected upload")
}
func (*sourceSeedFake) UploadLayerPart(context.Context, *ecr.UploadLayerPartInput, ...func(*ecr.Options)) (*ecr.UploadLayerPartOutput, error) {
	return nil, errors.New("unexpected upload")
}
func (*sourceSeedFake) CompleteLayerUpload(context.Context, *ecr.CompleteLayerUploadInput, ...func(*ecr.Options)) (*ecr.CompleteLayerUploadOutput, error) {
	return nil, errors.New("unexpected upload")
}
func (*sourceSeedFake) PutImage(context.Context, *ecr.PutImageInput, ...func(*ecr.Options)) (*ecr.PutImageOutput, error) {
	return nil, errors.New("unexpected put")
}

type memorySeedECR struct {
	mutex          sync.Mutex
	fixture        sourceFixture
	stored         bool
	storedManifest []byte
	putCalls       int
	batchErr       error
}

func (*memorySeedECR) DescribeRepositories(context.Context, *ecr.DescribeRepositoriesInput, ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	return nil, errors.New("unexpected repository read")
}
func (*memorySeedECR) CreateRepository(context.Context, *ecr.CreateRepositoryInput, ...func(*ecr.Options)) (*ecr.CreateRepositoryOutput, error) {
	return nil, errors.New("unexpected repository create")
}
func (*memorySeedECR) ListTagsForResource(context.Context, *ecr.ListTagsForResourceInput, ...func(*ecr.Options)) (*ecr.ListTagsForResourceOutput, error) {
	return nil, errors.New("unexpected tags read")
}
func (client *memorySeedECR) BatchGetImage(_ context.Context, input *ecr.BatchGetImageInput, _ ...func(*ecr.Options)) (*ecr.BatchGetImageOutput, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if client.batchErr != nil {
		return nil, client.batchErr
	}
	if input == nil || len(input.ImageIds) != 1 || aws.ToString(input.ImageIds[0].ImageTag) != client.fixture.entry.Tag {
		return nil, errors.New("bad batch get")
	}
	if !client.stored {
		return &ecr.BatchGetImageOutput{Failures: []ecrtypes.ImageFailure{{
			FailureCode: ecrtypes.ImageFailureCodeImageNotFound,
			ImageId:     &ecrtypes.ImageIdentifier{ImageTag: aws.String(client.fixture.entry.Tag)},
		}}}, nil
	}
	manifest := client.storedManifest
	if manifest == nil {
		manifest = client.fixture.manifest
	}
	return &ecr.BatchGetImageOutput{Images: []ecrtypes.Image{{
		ImageId:       &ecrtypes.ImageIdentifier{ImageTag: aws.String(client.fixture.entry.Tag), ImageDigest: aws.String(client.fixture.entry.Digest)},
		ImageManifest: aws.String(string(manifest)), ImageManifestMediaType: aws.String(client.fixture.mediaType),
	}}}, nil
}
func (client *memorySeedECR) DescribeImages(context.Context, *ecr.DescribeImagesInput, ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.stored {
		return &ecr.DescribeImagesOutput{}, nil
	}
	return &ecr.DescribeImagesOutput{ImageDetails: []ecrtypes.ImageDetail{{
		ImageDigest: aws.String(client.fixture.entry.Digest), ImageManifestMediaType: aws.String(client.fixture.mediaType),
		ImageTags: []string{client.fixture.entry.Tag},
	}}}, nil
}
func (client *memorySeedECR) BatchCheckLayerAvailability(_ context.Context, input *ecr.BatchCheckLayerAvailabilityInput, _ ...func(*ecr.Options)) (*ecr.BatchCheckLayerAvailabilityOutput, error) {
	if input == nil || len(input.LayerDigests) != 1 {
		return nil, errors.New("bad layer check")
	}
	return &ecr.BatchCheckLayerAvailabilityOutput{Layers: []ecrtypes.Layer{{
		LayerAvailability: ecrtypes.LayerAvailabilityAvailable, LayerDigest: aws.String(input.LayerDigests[0]),
	}}}, nil
}
func (*memorySeedECR) InitiateLayerUpload(context.Context, *ecr.InitiateLayerUploadInput, ...func(*ecr.Options)) (*ecr.InitiateLayerUploadOutput, error) {
	return nil, errors.New("unexpected upload")
}
func (*memorySeedECR) UploadLayerPart(context.Context, *ecr.UploadLayerPartInput, ...func(*ecr.Options)) (*ecr.UploadLayerPartOutput, error) {
	return nil, errors.New("unexpected upload")
}
func (*memorySeedECR) CompleteLayerUpload(context.Context, *ecr.CompleteLayerUploadInput, ...func(*ecr.Options)) (*ecr.CompleteLayerUploadOutput, error) {
	return nil, errors.New("unexpected upload")
}
func (client *memorySeedECR) PutImage(_ context.Context, input *ecr.PutImageInput, _ ...func(*ecr.Options)) (*ecr.PutImageOutput, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if input == nil || aws.ToString(input.ImageDigest) != client.fixture.entry.Digest ||
		aws.ToString(input.ImageTag) != client.fixture.entry.Tag ||
		aws.ToString(input.ImageManifest) != string(client.fixture.manifest) ||
		aws.ToString(input.ImageManifestMediaType) != client.fixture.mediaType {
		return nil, errors.New("digest-preserving put rejected")
	}
	client.putCalls++
	client.stored = true
	client.storedManifest = append([]byte(nil), client.fixture.manifest...)
	return &ecr.PutImageOutput{}, nil
}
