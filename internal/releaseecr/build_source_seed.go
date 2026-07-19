package releaseecr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	BuildSourceResultSchemaV1 = "dirextalk.agent.ecr-build-sources/v1"
	maxSourceManifestBytes    = 4 << 20
	maxSourceConfigBytes      = 16 << 20
	maxLayerUploadPartBytes   = 20 << 20
)

type BuildSourceOptions struct {
	Region            string
	ExpectedAccountID string
}

type BuildSourceResultV1 struct {
	SchemaVersion      string `json:"schema_version"`
	AccountID          string `json:"account_id"`
	Region             string `json:"region"`
	RegistryHost       string `json:"registry_host"`
	Repository         string `json:"repository"`
	Created            bool   `json:"created,omitempty"`
	RepositoryVerified bool   `json:"repository_verified"`
	CatalogVerified    bool   `json:"catalog_verified"`
	Seeded             bool   `json:"seeded,omitempty"`
}

type buildSourceSeedAPI interface {
	buildSourceReadAPI
	CreateRepository(context.Context, *ecr.CreateRepositoryInput, ...func(*ecr.Options)) (*ecr.CreateRepositoryOutput, error)
	BatchCheckLayerAvailability(context.Context, *ecr.BatchCheckLayerAvailabilityInput, ...func(*ecr.Options)) (*ecr.BatchCheckLayerAvailabilityOutput, error)
	InitiateLayerUpload(context.Context, *ecr.InitiateLayerUploadInput, ...func(*ecr.Options)) (*ecr.InitiateLayerUploadOutput, error)
	UploadLayerPart(context.Context, *ecr.UploadLayerPartInput, ...func(*ecr.Options)) (*ecr.UploadLayerPartOutput, error)
	CompleteLayerUpload(context.Context, *ecr.CompleteLayerUploadInput, ...func(*ecr.Options)) (*ecr.CompleteLayerUploadOutput, error)
	PutImage(context.Context, *ecr.PutImageInput, ...func(*ecr.Options)) (*ecr.PutImageOutput, error)
}

type buildSourceClients struct {
	Region string
	STS    STSAPI
	ECR    buildSourceSeedAPI
}

func PrepareBuildSourcesDefault(ctx context.Context, options BuildSourceOptions) (BuildSourceResultV1, error) {
	return withDefaultBuildSourceClients(ctx, options, func(ctx context.Context, options BuildSourceOptions, clients buildSourceClients) (BuildSourceResultV1, error) {
		return prepareBuildSources(ctx, options, clients)
	})
}

func VerifyBuildSourcesDefault(ctx context.Context, options BuildSourceOptions) (BuildSourceResultV1, error) {
	return withDefaultBuildSourceClients(ctx, options, func(ctx context.Context, options BuildSourceOptions, clients buildSourceClients) (BuildSourceResultV1, error) {
		partition, registryHost, err := buildSourceIdentity(ctx, options, clients)
		if err != nil {
			return BuildSourceResultV1{}, err
		}
		if err := verifyBuildSources(ctx, clients.ECR, partition, options.ExpectedAccountID, options.Region, registryHost); err != nil {
			return BuildSourceResultV1{}, err
		}
		return buildSourceResult(options, registryHost, false, true, false), nil
	})
}

func SeedBuildSourcesDefault(ctx context.Context, options BuildSourceOptions) (BuildSourceResultV1, error) {
	return withDefaultBuildSourceClients(ctx, options, func(ctx context.Context, options BuildSourceOptions, clients buildSourceClients) (BuildSourceResultV1, error) {
		partition, registryHost, err := buildSourceIdentity(ctx, options, clients)
		if err != nil {
			return BuildSourceResultV1{}, err
		}
		// Seeding never provisions implicitly. The explicit prepare surface must
		// establish and read back the retained repository first.
		if err := verifyBuildSourceRepository(ctx, clients.ECR, partition, options.ExpectedAccountID, options.Region, registryHost); err != nil {
			return BuildSourceResultV1{}, err
		}
		root, err := os.MkdirTemp("", "dirextalk-build-sources-")
		if err != nil {
			return BuildSourceResultV1{}, ErrBuildSource
		}
		if err := os.Chmod(root, 0o700); err != nil {
			_ = os.RemoveAll(root)
			return BuildSourceResultV1{}, ErrBuildSource
		}
		defer os.RemoveAll(root)
		seeder := buildSourceSeeder{accountID: options.ExpectedAccountID, ecr: clients.ECR, http: http.DefaultClient}
		for _, entry := range buildSourceCatalog {
			if err := seeder.seed(ctx, root, entry); err != nil {
				return BuildSourceResultV1{}, err
			}
		}
		if err := verifyBuildSources(ctx, clients.ECR, partition, options.ExpectedAccountID, options.Region, registryHost); err != nil {
			return BuildSourceResultV1{}, err
		}
		return buildSourceResult(options, registryHost, false, true, true), nil
	})
}

type buildSourceOperation func(context.Context, BuildSourceOptions, buildSourceClients) (BuildSourceResultV1, error)

func withDefaultBuildSourceClients(ctx context.Context, options BuildSourceOptions, operation buildSourceOperation) (BuildSourceResultV1, error) {
	if !validBuildSourceOptions(options) || operation == nil {
		return BuildSourceResultV1{}, ErrInvalidInput
	}
	config, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(options.Region))
	if err != nil {
		return BuildSourceResultV1{}, redactedAWSFailure(ctx)
	}
	client := ecr.NewFromConfig(config)
	return operation(ctx, options, buildSourceClients{
		Region: config.Region, STS: sts.NewFromConfig(config), ECR: client,
	})
}

func validBuildSourceOptions(options BuildSourceOptions) bool {
	return options.Region == BuildSourceRegion && accountPattern.MatchString(options.ExpectedAccountID)
}

func buildSourceIdentity(ctx context.Context, options BuildSourceOptions, clients buildSourceClients) (string, string, error) {
	if !validBuildSourceOptions(options) || clients.Region != options.Region || clients.STS == nil || clients.ECR == nil {
		return "", "", ErrInvalidInput
	}
	partition, err := verifyExpectedIdentity(ctx, options.ExpectedAccountID, clients.STS)
	if err != nil {
		return "", "", err
	}
	host, err := expectedRegistryHost(partition, options.ExpectedAccountID, options.Region)
	if err != nil {
		return "", "", err
	}
	return partition, host, nil
}

func prepareBuildSources(ctx context.Context, options BuildSourceOptions, clients buildSourceClients) (BuildSourceResultV1, error) {
	partition, registryHost, err := buildSourceIdentity(ctx, options, clients)
	if err != nil {
		return BuildSourceResultV1{}, err
	}
	spec := RepositorySpec{Component: "build-sources", Name: RepositoryBuildSource}
	repository, found, err := describeBuildSourceRepository(ctx, clients.ECR, options.ExpectedAccountID)
	if err != nil {
		return BuildSourceResultV1{}, err
	}
	created := false
	if !found {
		_, createErr := clients.ECR.CreateRepository(ctx, &ecr.CreateRepositoryInput{
			RepositoryName: aws.String(RepositoryBuildSource), ImageTagMutability: ecrtypes.ImageTagMutabilityImmutable,
			ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{ScanOnPush: true},
			EncryptionConfiguration:    &ecrtypes.EncryptionConfiguration{EncryptionType: ecrtypes.EncryptionTypeAes256},
			Tags:                       repositoryTags(spec),
		})
		if createErr != nil {
			var exists *ecrtypes.RepositoryAlreadyExistsException
			if !errors.As(createErr, &exists) {
				repository, found, err = describeBuildSourceRepository(ctx, clients.ECR, options.ExpectedAccountID)
				if err != nil || !found {
					return BuildSourceResultV1{}, redactedAWSFailure(ctx)
				}
			}
		} else {
			created = true
		}
		repository, found, err = describeBuildSourceRepository(ctx, clients.ECR, options.ExpectedAccountID)
		if err != nil || !found {
			return BuildSourceResultV1{}, ErrBuildSource
		}
	}
	if validateRepository(repository, partition, options.ExpectedAccountID, options.Region, registryHost, RepositoryBuildSource) != nil {
		return BuildSourceResultV1{}, ErrBuildSourceMismatch
	}
	return buildSourceResult(options, registryHost, created, false, false), nil
}

func verifyBuildSourceRepository(ctx context.Context, client buildSourceReadAPI, partition, accountID, region, registryHost string) error {
	repository, found, err := describeBuildSourceRepository(ctx, client, accountID)
	if err != nil || !found {
		return ErrBuildSource
	}
	if validateRepository(repository, partition, accountID, region, registryHost, RepositoryBuildSource) != nil {
		return ErrBuildSourceMismatch
	}
	return nil
}

func describeBuildSourceRepository(ctx context.Context, client buildSourceReadAPI, accountID string) (ecrtypes.Repository, bool, error) {
	output, err := client.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{
		RegistryId: aws.String(accountID), RepositoryNames: []string{RepositoryBuildSource},
	})
	if err != nil {
		var missing *ecrtypes.RepositoryNotFoundException
		if errors.As(err, &missing) {
			return ecrtypes.Repository{}, false, nil
		}
		return ecrtypes.Repository{}, false, redactedAWSFailure(ctx)
	}
	if output == nil || len(output.Repositories) != 1 {
		return ecrtypes.Repository{}, false, ErrBuildSourceMismatch
	}
	repository := output.Repositories[0]
	tags, err := client.ListTagsForResource(ctx, &ecr.ListTagsForResourceInput{ResourceArn: repository.RepositoryArn})
	spec := RepositorySpec{Component: "build-sources", Name: RepositoryBuildSource}
	if err != nil || tags == nil || !exactRepositoryTags(tags.Tags, spec) {
		return ecrtypes.Repository{}, false, ErrBuildSourceMismatch
	}
	return repository, true, nil
}

func buildSourceResult(options BuildSourceOptions, host string, created, catalogVerified, seeded bool) BuildSourceResultV1 {
	return BuildSourceResultV1{
		SchemaVersion: BuildSourceResultSchemaV1, AccountID: options.ExpectedAccountID, Region: options.Region,
		RegistryHost: host, Repository: RepositoryBuildSource, Created: created,
		RepositoryVerified: true, CatalogVerified: catalogVerified, Seeded: seeded,
	}
}

type buildSourceSeeder struct {
	accountID string
	ecr       buildSourceSeedAPI
	http      *http.Client
}

var buildSourceSeedLocks sync.Map

func (seeder buildSourceSeeder) seed(ctx context.Context, root string, entry BuildSourceCatalogEntry) error {
	lockValue, _ := buildSourceSeedLocks.LoadOrStore(seeder.accountID+"/"+entry.Tag, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

	if err := verifyBuildSourceImage(ctx, seeder.ecr, seeder.accountID, entry); err == nil {
		return nil
	} else if !errors.Is(err, ErrBuildSourceMissing) {
		return err
	}
	layout, err := downloadBuildSource(ctx, seeder.http, root, entry)
	if err != nil {
		return err
	}
	if err := seeder.upload(ctx, entry, layout); err != nil {
		return err
	}
	return verifyBuildSourceImage(ctx, seeder.ecr, seeder.accountID, entry)
}

type downloadedBuildSource struct {
	root      string
	manifest  []byte
	mediaType string
	blobs     []string
}

func downloadBuildSource(ctx context.Context, client *http.Client, parent string, entry BuildSourceCatalogEntry) (downloadedBuildSource, error) {
	if client == nil || !validDigest(entry.Digest) || entry.UpstreamHost == "" ||
		entry.UpstreamAuthHost == "" || entry.UpstreamRepository == "" {
		return downloadedBuildSource{}, ErrBuildSource
	}
	root := filepath.Join(parent, string(entry.Role))
	if err := os.Mkdir(root, 0o700); err != nil {
		return downloadedBuildSource{}, ErrBuildSource
	}
	blobRoot := filepath.Join(root, "blobs", "sha256")
	if err := os.MkdirAll(blobRoot, 0o700); err != nil {
		return downloadedBuildSource{}, ErrBuildSource
	}
	registry := registryReader{
		client: client, host: entry.UpstreamHost, authHost: entry.UpstreamAuthHost, repository: entry.UpstreamRepository,
	}
	manifest, mediaType, err := registry.readManifest(ctx, entry.Digest)
	if err != nil || !validDigestBytes(entry.Digest, manifest) {
		return downloadedBuildSource{}, ErrBuildSourceMismatch
	}
	var parsed buildSourceManifest
	if json.Unmarshal(manifest, &parsed) != nil || parsed.SchemaVersion != 2 || parsed.MediaType != mediaType ||
		(mediaType != ociManifestMediaType && mediaType != dockerManifestMediaType) || !validManifestDescriptors(parsed) {
		return downloadedBuildSource{}, ErrBuildSourceMismatch
	}
	manifestPath := filepath.Join(blobRoot, strings.TrimPrefix(entry.Digest, "sha256:"))
	if err := writePrivateFile(manifestPath, manifest); err != nil {
		return downloadedBuildSource{}, ErrBuildSource
	}
	descriptors := []struct {
		digest string
		size   int64
	}{
		{digest: parsed.Config.Digest, size: parsed.Config.Size},
	}
	for _, layer := range parsed.Layers {
		descriptors = append(descriptors, struct {
			digest string
			size   int64
		}{digest: layer.Digest, size: layer.Size})
	}
	paths := make([]string, 0, len(descriptors))
	for _, descriptor := range descriptors {
		path := filepath.Join(blobRoot, strings.TrimPrefix(descriptor.digest, "sha256:"))
		if err := registry.downloadBlob(ctx, descriptor.digest, descriptor.size, path); err != nil {
			return downloadedBuildSource{}, err
		}
		paths = append(paths, path)
	}
	config, err := os.ReadFile(paths[0])
	if err != nil || len(config) > maxSourceConfigBytes {
		return downloadedBuildSource{}, ErrBuildSource
	}
	var platform struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	}
	if json.Unmarshal(config, &platform) != nil || platform.OS != BuildSourcePlatformOS ||
		platform.Architecture != BuildSourcePlatformArchitecture {
		return downloadedBuildSource{}, ErrBuildSourceMismatch
	}
	index, _ := json.Marshal(struct {
		SchemaVersion int `json:"schemaVersion"`
		Manifests     []struct {
			MediaType string            `json:"mediaType"`
			Digest    string            `json:"digest"`
			Size      int               `json:"size"`
			Platform  map[string]string `json:"platform"`
		} `json:"manifests"`
	}{SchemaVersion: 2, Manifests: []struct {
		MediaType string            `json:"mediaType"`
		Digest    string            `json:"digest"`
		Size      int               `json:"size"`
		Platform  map[string]string `json:"platform"`
	}{{MediaType: mediaType, Digest: entry.Digest, Size: len(manifest), Platform: map[string]string{"os": BuildSourcePlatformOS, "architecture": BuildSourcePlatformArchitecture}}}})
	if err := writePrivateFile(filepath.Join(root, "index.json"), append(index, '\n')); err != nil ||
		writePrivateFile(filepath.Join(root, "oci-layout"), []byte("{\"imageLayoutVersion\":\"1.0.0\"}\n")) != nil {
		return downloadedBuildSource{}, ErrBuildSource
	}
	return downloadedBuildSource{root: root, manifest: manifest, mediaType: mediaType, blobs: paths}, nil
}

func (seeder buildSourceSeeder) upload(ctx context.Context, entry BuildSourceCatalogEntry, source downloadedBuildSource) error {
	for _, path := range source.blobs {
		digest := "sha256:" + filepath.Base(path)
		availability, err := seeder.ecr.BatchCheckLayerAvailability(ctx, &ecr.BatchCheckLayerAvailabilityInput{
			RegistryId: aws.String(seeder.accountID), RepositoryName: aws.String(RepositoryBuildSource), LayerDigests: []string{digest},
		})
		if err != nil || availability == nil || len(availability.Failures) != 0 {
			return redactedAWSFailure(ctx)
		}
		available := len(availability.Layers) == 1 &&
			availability.Layers[0].LayerAvailability == ecrtypes.LayerAvailabilityAvailable &&
			aws.ToString(availability.Layers[0].LayerDigest) == digest
		if !available {
			if err := seeder.uploadBlob(ctx, path, digest); err != nil {
				return err
			}
		}
	}
	_, err := seeder.ecr.PutImage(ctx, &ecr.PutImageInput{
		RegistryId: aws.String(seeder.accountID), RepositoryName: aws.String(RepositoryBuildSource),
		ImageManifest: aws.String(string(source.manifest)), ImageManifestMediaType: aws.String(source.mediaType),
		ImageDigest: aws.String(entry.Digest), ImageTag: aws.String(entry.Tag),
	})
	if err != nil {
		var exists *ecrtypes.ImageAlreadyExistsException
		var tagExists *ecrtypes.ImageTagAlreadyExistsException
		if !errors.As(err, &exists) && !errors.As(err, &tagExists) {
			return redactedAWSFailure(ctx)
		}
	}
	return nil
}

func (seeder buildSourceSeeder) uploadBlob(ctx context.Context, path, digest string) error {
	file, err := os.Open(path)
	if err != nil {
		return ErrBuildSource
	}
	defer file.Close()
	start, err := seeder.ecr.InitiateLayerUpload(ctx, &ecr.InitiateLayerUploadInput{
		RegistryId: aws.String(seeder.accountID), RepositoryName: aws.String(RepositoryBuildSource),
	})
	if err != nil || start == nil || aws.ToString(start.UploadId) == "" {
		return redactedAWSFailure(ctx)
	}
	partSize := aws.ToInt64(start.PartSize)
	if partSize <= 0 || partSize > maxLayerUploadPartBytes {
		partSize = maxLayerUploadPartBytes
	}
	buffer := make([]byte, partSize)
	defer clear(buffer)
	var offset int64
	for {
		n, readErr := io.ReadFull(file, buffer)
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return ErrBuildSource
		}
		last := offset + int64(n) - 1
		output, uploadErr := seeder.ecr.UploadLayerPart(ctx, &ecr.UploadLayerPartInput{
			RegistryId: aws.String(seeder.accountID), RepositoryName: aws.String(RepositoryBuildSource),
			UploadId: start.UploadId, PartFirstByte: aws.Int64(offset), PartLastByte: aws.Int64(last),
			LayerPartBlob: buffer[:n],
		})
		if uploadErr != nil || output == nil || aws.ToInt64(output.LastByteReceived) != last {
			return redactedAWSFailure(ctx)
		}
		offset = last + 1
		if errors.Is(readErr, io.ErrUnexpectedEOF) {
			break
		}
	}
	if offset == 0 {
		return ErrBuildSourceMismatch
	}
	complete, err := seeder.ecr.CompleteLayerUpload(ctx, &ecr.CompleteLayerUploadInput{
		RegistryId: aws.String(seeder.accountID), RepositoryName: aws.String(RepositoryBuildSource),
		UploadId: start.UploadId, LayerDigests: []string{digest},
	})
	if err != nil {
		var exists *ecrtypes.LayerAlreadyExistsException
		if !errors.As(err, &exists) {
			return redactedAWSFailure(ctx)
		}
		return nil
	}
	if complete == nil || aws.ToString(complete.LayerDigest) != digest {
		return ErrBuildSourceMismatch
	}
	return nil
}

type registryReader struct {
	client     *http.Client
	host       string
	authHost   string
	repository string
	token      string
}

func (reader *registryReader) readManifest(ctx context.Context, digest string) ([]byte, string, error) {
	response, err := reader.request(ctx, "/v2/"+reader.repository+"/manifests/"+digest, strings.Join([]string{ociManifestMediaType, dockerManifestMediaType}, ", "))
	if err != nil {
		return nil, "", err
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, maxSourceManifestBytes+1))
	mediaType := strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])
	if err != nil || len(content) == 0 || len(content) > maxSourceManifestBytes ||
		(mediaType != ociManifestMediaType && mediaType != dockerManifestMediaType) {
		return nil, "", ErrBuildSource
	}
	return content, mediaType, nil
}

func (reader *registryReader) downloadBlob(ctx context.Context, digest string, size int64, path string) error {
	if size <= 0 || !validDigest(digest) {
		return ErrBuildSourceMismatch
	}
	response, err := reader.request(ctx, "/v2/"+reader.repository+"/blobs/"+digest, "")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrBuildSource
	}
	hash := sha256.New()
	written, copyErr := io.CopyN(io.MultiWriter(file, hash), response.Body, size)
	var extra [1]byte
	extraN, extraErr := response.Body.Read(extra[:])
	closeErr := file.Close()
	if copyErr != nil || written != size || extraN != 0 || (extraErr != nil && !errors.Is(extraErr, io.EOF)) || closeErr != nil ||
		"sha256:"+hex.EncodeToString(hash.Sum(nil)) != digest {
		_ = os.Remove(path)
		return ErrBuildSourceMismatch
	}
	return nil
}

func (reader *registryReader) request(ctx context.Context, path, accept string) (*http.Response, error) {
	attempt := func(token string) (*http.Response, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+reader.host+path, nil)
		if err != nil {
			return nil, ErrBuildSource
		}
		if accept != "" {
			request.Header.Set("Accept", accept)
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		return reader.client.Do(request)
	}
	response, err := attempt(reader.token)
	if err != nil {
		return nil, ErrBuildSource
	}
	if response.StatusCode == http.StatusUnauthorized && reader.token == "" {
		challenge := response.Header.Get("WWW-Authenticate")
		response.Body.Close()
		token, tokenErr := reader.bearerToken(ctx, challenge)
		if tokenErr != nil {
			return nil, tokenErr
		}
		reader.token = token
		response, err = attempt(reader.token)
		if err != nil {
			return nil, ErrBuildSource
		}
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, ErrBuildSource
	}
	return response, nil
}

func (reader *registryReader) bearerToken(ctx context.Context, challenge string) (string, error) {
	if !strings.HasPrefix(challenge, "Bearer ") {
		return "", ErrBuildSource
	}
	parameters := make(map[string]string)
	for _, item := range strings.Split(strings.TrimPrefix(challenge, "Bearer "), ",") {
		pair := strings.SplitN(strings.TrimSpace(item), "=", 2)
		if len(pair) != 2 {
			return "", ErrBuildSource
		}
		parameters[pair[0]] = strings.Trim(pair[1], `"`)
	}
	realm, err := url.Parse(parameters["realm"])
	if err != nil || realm.Scheme != "https" || realm.Hostname() != reader.authHost ||
		realm.Port() != "" || realm.User != nil || realm.Fragment != "" {
		return "", ErrBuildSource
	}
	query := realm.Query()
	if service := parameters["service"]; service != "" {
		if strings.ContainsAny(service, " \t\r\n") {
			return "", ErrBuildSource
		}
		query.Set("service", service)
	}
	query.Set("scope", "repository:"+reader.repository+":pull")
	realm.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", ErrBuildSource
	}
	response, err := reader.client.Do(request)
	if err != nil {
		return "", ErrBuildSource
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", ErrBuildSource
	}
	var token struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	if decoder.Decode(&token) != nil {
		return "", ErrBuildSource
	}
	if token.Token == "" {
		token.Token = token.AccessToken
	}
	if token.Token == "" || strings.ContainsAny(token.Token, " \t\r\n") || (token.ExpiresIn != 0 && token.ExpiresIn < 30) {
		return "", ErrBuildSource
	}
	return token.Token, nil
}
