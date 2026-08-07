package sdkclient

import (
	"context"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type S3OutputVersionAPI interface {
	ListObjectVersions(context.Context, *s3.ListObjectVersionsInput, ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// ExactOutputVersionStoreFactory seals every inventory and exact-version
// mutation to one immutable credential/configuration revision. Construction is
// offline; each S3 call still performs its own STS account proof.
type ExactOutputVersionStoreFactory struct {
	sdkConfig awssdk.Config
	config    Config
}

func NewExactOutputVersionStoreFactory(sdkConfig awssdk.Config, config Config) (*ExactOutputVersionStoreFactory, error) {
	if config.Validate() != nil || sdkConfig.Region != config.Region || sdkConfig.Credentials == nil {
		return nil, cloudworker.ErrInvalid
	}
	sdkConfig = withoutSDKRetries(sdkConfig)
	return &ExactOutputVersionStoreFactory{sdkConfig: sdkConfig, config: config}, nil
}

func (factory *ExactOutputVersionStoreFactory) StoreForOutput(
	ctx context.Context,
	identity cloudworker.OutputExecutionIdentity,
) (cloudworker.OutputVersionStore, error) {
	if factory == nil || ctx == nil || ctx.Err() != nil || !outputIdentityMatchesConfig(identity, factory.config) {
		return nil, cloudworker.ErrStaleAuthorization
	}
	return NewS3OutputVersionStore(factory.sdkConfig, factory.config, identity)
}

// S3OutputVersionStore inventories every version and delete marker below one
// execution prefix. It never deletes by key alone and never treats an SDK
// success response as cleanup proof; the caller must perform a second complete
// inventory before marking the journal verified clean.
type S3OutputVersionStore struct {
	config   Config
	identity cloudworker.OutputExecutionIdentity
	sts      STSAPI
	s3       S3OutputVersionAPI
	now      func() time.Time
}

func NewS3OutputVersionStore(
	sdkConfig awssdk.Config,
	config Config,
	identity cloudworker.OutputExecutionIdentity,
) (*S3OutputVersionStore, error) {
	if config.Validate() != nil || sdkConfig.Region != config.Region || sdkConfig.Credentials == nil ||
		!outputIdentityMatchesConfig(identity, config) {
		return nil, cloudworker.ErrInvalid
	}
	sdkConfig = withoutSDKRetries(sdkConfig)
	return newS3OutputVersionStore(config, identity, sts.NewFromConfig(sdkConfig), s3.NewFromConfig(sdkConfig), time.Now)
}

func newS3OutputVersionStore(
	config Config,
	identity cloudworker.OutputExecutionIdentity,
	stsClient STSAPI,
	s3Client S3OutputVersionAPI,
	now func() time.Time,
) (*S3OutputVersionStore, error) {
	if config.Validate() != nil || !outputIdentityMatchesConfig(identity, config) || stsClient == nil || s3Client == nil || now == nil {
		return nil, cloudworker.ErrInvalid
	}
	return &S3OutputVersionStore{config: config, identity: identity, sts: stsClient, s3: s3Client, now: now}, nil
}

func (store *S3OutputVersionStore) InventoryPage(
	ctx context.Context,
	request cloudworker.OutputInventoryRequest,
) (cloudworker.OutputInventoryPage, error) {
	if store == nil || ctx == nil || request.Identity != store.identity || request.Identity.Validate() != nil ||
		request.Cursor.Validate() != nil || !outputIdentityMatchesConfig(request.Identity, store.config) {
		return cloudworker.OutputInventoryPage{}, cloudworker.ErrInvalid
	}
	if err := store.verifyIdentity(ctx); err != nil {
		return cloudworker.OutputInventoryPage{}, err
	}
	input := &s3.ListObjectVersionsInput{
		Bucket: awssdk.String(store.identity.Bucket), Prefix: awssdk.String(store.identity.KeyPrefix),
		ExpectedBucketOwner: awssdk.String(store.identity.AccountID), MaxKeys: awssdk.Int32(1000),
	}
	if request.Cursor.KeyMarker != "" {
		input.KeyMarker = awssdk.String(request.Cursor.KeyMarker)
	}
	if request.Cursor.VersionIDMarker != "" {
		input.VersionIdMarker = awssdk.String(request.Cursor.VersionIDMarker)
	}
	output, err := store.s3.ListObjectVersions(ctx, input)
	if err != nil || output == nil {
		return cloudworker.OutputInventoryPage{}, errors.Join(cloudworker.ErrOutputCleanupPending, err)
	}
	if awssdk.ToString(output.Name) != store.identity.Bucket || awssdk.ToString(output.Prefix) != store.identity.KeyPrefix ||
		awssdk.ToString(output.KeyMarker) != request.Cursor.KeyMarker || awssdk.ToString(output.VersionIdMarker) != request.Cursor.VersionIDMarker ||
		awssdk.ToInt32(output.MaxKeys) != 1000 || awssdk.ToString(output.Delimiter) != "" || len(output.CommonPrefixes) != 0 {
		return cloudworker.OutputInventoryPage{}, cloudworker.ErrStaleAuthorization
	}
	observedAt := store.now().UTC()
	page := cloudworker.OutputInventoryPage{
		Identity: store.identity, ObservedAt: observedAt,
		Versions: make([]cloudworker.OutputVersionObservation, 0, len(output.Versions)+len(output.DeleteMarkers)),
	}
	for _, version := range output.Versions {
		page.Versions = append(page.Versions, cloudworker.OutputVersionObservation{
			Identity: cloudworker.OutputVersionIdentity{OutputExecutionIdentity: store.identity,
				Key: awssdk.ToString(version.Key), VersionID: awssdk.ToString(version.VersionId)},
			SizeBytes: awssdk.ToInt64(version.Size), ObservedAt: observedAt,
		})
	}
	for _, marker := range output.DeleteMarkers {
		page.Versions = append(page.Versions, cloudworker.OutputVersionObservation{
			Identity: cloudworker.OutputVersionIdentity{OutputExecutionIdentity: store.identity,
				Key: awssdk.ToString(marker.Key), VersionID: awssdk.ToString(marker.VersionId), DeleteMarker: true},
			ObservedAt: observedAt,
		})
	}
	if awssdk.ToBool(output.IsTruncated) {
		page.NextCursor = cloudworker.OutputInventoryCursor{
			KeyMarker: awssdk.ToString(output.NextKeyMarker), VersionIDMarker: awssdk.ToString(output.NextVersionIdMarker),
		}
	} else if awssdk.ToString(output.NextKeyMarker) != "" || awssdk.ToString(output.NextVersionIdMarker) != "" {
		return cloudworker.OutputInventoryPage{}, cloudworker.ErrStaleAuthorization
	}
	if page.Validate(request) != nil || (awssdk.ToBool(output.IsTruncated) && page.NextCursor.KeyMarker == "") {
		return cloudworker.OutputInventoryPage{}, cloudworker.ErrStaleAuthorization
	}
	return page, nil
}

func (store *S3OutputVersionStore) ObserveExact(
	ctx context.Context,
	identity cloudworker.OutputVersionIdentity,
) (cloudworker.OutputExactObservation, error) {
	if store == nil || ctx == nil || identity.Validate() != nil || identity.OutputExecutionIdentity != store.identity ||
		identity.DeleteMarker || !outputIdentityMatchesConfig(identity.OutputExecutionIdentity, store.config) {
		return cloudworker.OutputExactObservation{}, cloudworker.ErrInvalid
	}
	if err := store.verifyIdentity(ctx); err != nil {
		return cloudworker.OutputExactObservation{}, err
	}
	output, err := store.s3.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: awssdk.String(identity.Bucket), Key: awssdk.String(identity.Key), VersionId: awssdk.String(identity.VersionID),
		ExpectedBucketOwner: awssdk.String(identity.AccountID), ChecksumMode: s3types.ChecksumModeEnabled,
	})
	observedAt := store.now().UTC()
	if err != nil {
		if stagingObjectNotFound(err) {
			return cloudworker.OutputExactObservation{Identity: identity, Exists: false, ObservedAt: observedAt}, nil
		}
		return cloudworker.OutputExactObservation{}, errors.Join(cloudworker.ErrOutputCleanupPending, err)
	}
	if output == nil || awssdk.ToBool(output.DeleteMarker) || awssdk.ToString(output.VersionId) != identity.VersionID ||
		output.ServerSideEncryption != s3types.ServerSideEncryptionAwsKms || awssdk.ToString(output.SSEKMSKeyId) != identity.KMSKeyARN ||
		awssdk.ToBool(output.BucketKeyEnabled) {
		return cloudworker.OutputExactObservation{}, cloudworker.ErrStaleAuthorization
	}
	observation := cloudworker.OutputExactObservation{
		Identity: identity, Exists: true, SizeBytes: awssdk.ToInt64(output.ContentLength),
		MediaType: awssdk.ToString(output.ContentType), SHA256: artifactDigestMetadata(output.Metadata),
		KMSKeyARN: awssdk.ToString(output.SSEKMSKeyId), BucketKeyEnabled: awssdk.ToBool(output.BucketKeyEnabled),
		ObservedAt: observedAt,
	}
	if observation.Validate(identity) != nil {
		return cloudworker.OutputExactObservation{}, cloudworker.ErrStaleAuthorization
	}
	return observation, nil
}

func (store *S3OutputVersionStore) DeleteExact(ctx context.Context, identity cloudworker.OutputVersionIdentity) error {
	if store == nil || ctx == nil || identity.Validate() != nil || identity.OutputExecutionIdentity != store.identity ||
		!outputIdentityMatchesConfig(identity.OutputExecutionIdentity, store.config) {
		return cloudworker.ErrInvalid
	}
	if err := store.verifyIdentity(ctx); err != nil {
		return err
	}
	output, err := store.s3.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: awssdk.String(identity.Bucket), Key: awssdk.String(identity.Key), VersionId: awssdk.String(identity.VersionID),
		ExpectedBucketOwner: awssdk.String(identity.AccountID),
	})
	if err != nil || output == nil || awssdk.ToString(output.VersionId) != identity.VersionID ||
		awssdk.ToBool(output.DeleteMarker) != identity.DeleteMarker {
		return errors.Join(cloudworker.ErrOutputDeleteUncertain, err)
	}
	return nil
}

func (store *S3OutputVersionStore) verifyIdentity(ctx context.Context) error {
	if store == nil || ctx == nil || !outputIdentityMatchesConfig(store.identity, store.config) {
		return cloudaws.ErrIdentityMismatch
	}
	output, err := store.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || output == nil || awssdk.ToString(output.Account) != store.identity.AccountID {
		return errors.Join(cloudaws.ErrIdentityMismatch, err)
	}
	return nil
}

func outputIdentityMatchesConfig(identity cloudworker.OutputExecutionIdentity, config Config) bool {
	return identity.Validate() == nil && identity.AccountID == config.AccountID &&
		identity.AccountGeneration == config.AccountGeneration && identity.Region == config.Region &&
		identity.ProviderID == config.ProviderID
}

var _ cloudworker.OutputVersionStoreFactory = (*ExactOutputVersionStoreFactory)(nil)
var _ cloudworker.OutputVersionStore = (*S3OutputVersionStore)(nil)
