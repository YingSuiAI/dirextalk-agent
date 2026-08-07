package sdkclient

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"maps"
	"strings"
	"time"

	cloudworker "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type S3StagingAPI interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	ListObjectVersions(context.Context, *s3.ListObjectVersionsInput, ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// S3StagingStore is the post-confirmation input upload boundary. Every SDK
// operation is immediately preceded by a fresh STS account proof. PutObject
// is attempted at most once by InputStager; an unknown response is resolved
// only through exact-key version inventory and immutable metadata.
type S3StagingStore struct {
	config Config
	sts    STSAPI
	s3     S3StagingAPI
	now    func() time.Time
}

func NewS3StagingStore(sdkConfig awssdk.Config, config Config) (*S3StagingStore, error) {
	if config.Validate() != nil || sdkConfig.Region != config.Region || sdkConfig.Credentials == nil {
		return nil, cloudworker.ErrInvalid
	}
	sdkConfig = withoutSDKRetries(sdkConfig)
	return newS3StagingStore(config, sts.NewFromConfig(sdkConfig), s3.NewFromConfig(sdkConfig), time.Now)
}

func newS3StagingStore(config Config, stsClient STSAPI, s3Client S3StagingAPI, now func() time.Time) (*S3StagingStore, error) {
	if config.Validate() != nil || stsClient == nil || s3Client == nil || now == nil {
		return nil, cloudworker.ErrInvalid
	}
	return &S3StagingStore{config: config, sts: stsClient, s3: s3Client, now: now}, nil
}

func (store *S3StagingStore) Readiness(ctx context.Context) error {
	return store.verifyIdentity(ctx)
}

func (store *S3StagingStore) PutVersion(ctx context.Context, request cloudworker.StagingPutRequest) (cloudworker.StagingObjectObservation, error) {
	if store == nil || ctx == nil || request.Identity.Validate() != nil || request.Body == nil || !store.matches(request.Identity) {
		return cloudworker.StagingObjectObservation{}, cloudworker.ErrInvalid
	}
	checksum, err := stagingChecksum(request.Identity.SourceSHA256)
	if err != nil {
		return cloudworker.StagingObjectObservation{}, cloudworker.ErrInvalid
	}
	if _, err := request.Body.Seek(0, io.SeekStart); err != nil {
		return cloudworker.StagingObjectObservation{}, cloudworker.ErrInvalid
	}
	if err := store.verifyIdentity(ctx); err != nil {
		return cloudworker.StagingObjectObservation{}, err
	}
	output, putErr := store.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: awssdk.String(request.Identity.Bucket), Key: awssdk.String(request.Identity.Key), Body: request.Body,
		ContentLength: awssdk.Int64(int64(request.Identity.SizeBytes)), ContentType: awssdk.String(request.Identity.MediaType),
		ChecksumAlgorithm: s3types.ChecksumAlgorithmSha256, ChecksumSHA256: awssdk.String(checksum),
		ExpectedBucketOwner: awssdk.String(store.config.AccountID), Metadata: request.Identity.Metadata(),
		ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: awssdk.String(request.Identity.KMSKeyARN),
		BucketKeyEnabled: awssdk.Bool(false),
	})
	if putErr != nil || output == nil || !validS3VersionID(awssdk.ToString(output.VersionId)) ||
		awssdk.ToString(output.ChecksumSHA256) != checksum || output.ServerSideEncryption != s3types.ServerSideEncryptionAwsKms ||
		awssdk.ToString(output.SSEKMSKeyId) != request.Identity.KMSKeyARN {
		return cloudworker.StagingObjectObservation{}, errors.Join(cloudworker.ErrStagingResponseUnknown, putErr)
	}
	return cloudworker.StagingObjectObservation{Identity: request.Identity, VersionID: awssdk.ToString(output.VersionId), Exists: true, ObservedAt: store.now().UTC()}, nil
}

func (store *S3StagingStore) FindVersion(ctx context.Context, identity cloudworker.StagingObjectIdentity) (cloudworker.StagingObjectObservation, bool, error) {
	if store == nil || ctx == nil || identity.Validate() != nil || !store.matches(identity) {
		return cloudworker.StagingObjectObservation{}, false, cloudworker.ErrInvalid
	}
	var keyMarker, versionMarker *string
	versions := make([]string, 0, 2)
	for page := 0; page < 1024; page++ {
		if err := store.verifyIdentity(ctx); err != nil {
			return cloudworker.StagingObjectObservation{}, false, err
		}
		output, err := store.s3.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: awssdk.String(identity.Bucket), Prefix: awssdk.String(identity.Key), ExpectedBucketOwner: awssdk.String(store.config.AccountID),
			KeyMarker: keyMarker, VersionIdMarker: versionMarker, MaxKeys: awssdk.Int32(1000),
		})
		if err != nil || output == nil {
			return cloudworker.StagingObjectObservation{}, false, errors.Join(cloudworker.ErrStagingPending, err)
		}
		for _, marker := range output.DeleteMarkers {
			if awssdk.ToString(marker.Key) == identity.Key {
				return cloudworker.StagingObjectObservation{}, false, cloudworker.ErrConflict
			}
		}
		for _, version := range output.Versions {
			if awssdk.ToString(version.Key) != identity.Key {
				continue
			}
			versionID := awssdk.ToString(version.VersionId)
			if !validS3VersionID(versionID) {
				return cloudworker.StagingObjectObservation{}, false, cloudworker.ErrConflict
			}
			versions = append(versions, versionID)
			if len(versions) > 1 {
				return cloudworker.StagingObjectObservation{}, false, cloudworker.ErrConflict
			}
		}
		if !awssdk.ToBool(output.IsTruncated) {
			break
		}
		nextKey, nextVersion := strings.TrimSpace(awssdk.ToString(output.NextKeyMarker)), strings.TrimSpace(awssdk.ToString(output.NextVersionIdMarker))
		if nextKey == "" || (keyMarker != nil && nextKey == *keyMarker && versionMarker != nil && nextVersion == *versionMarker) {
			return cloudworker.StagingObjectObservation{}, false, cloudworker.ErrConflict
		}
		keyMarker, versionMarker = awssdk.String(nextKey), awssdk.String(nextVersion)
		if page == 1023 {
			return cloudworker.StagingObjectObservation{}, false, cloudworker.ErrConflict
		}
	}
	if len(versions) == 0 {
		return cloudworker.StagingObjectObservation{}, false, nil
	}
	observation, err := store.ObserveVersion(ctx, cloudworker.StagingVersionRequest{Identity: identity, VersionID: versions[0]})
	if err != nil {
		return cloudworker.StagingObjectObservation{}, false, err
	}
	return observation, observation.Exists, nil
}

func (store *S3StagingStore) ObserveVersion(ctx context.Context, request cloudworker.StagingVersionRequest) (cloudworker.StagingObjectObservation, error) {
	if store == nil || ctx == nil || request.Identity.Validate() != nil || !validS3VersionID(request.VersionID) || !store.matches(request.Identity) {
		return cloudworker.StagingObjectObservation{}, cloudworker.ErrInvalid
	}
	if err := store.verifyIdentity(ctx); err != nil {
		return cloudworker.StagingObjectObservation{}, err
	}
	output, err := store.s3.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: awssdk.String(request.Identity.Bucket), Key: awssdk.String(request.Identity.Key), VersionId: awssdk.String(request.VersionID),
		ExpectedBucketOwner: awssdk.String(store.config.AccountID), ChecksumMode: s3types.ChecksumModeEnabled,
	})
	if err != nil {
		if stagingObjectNotFound(err) {
			return cloudworker.StagingObjectObservation{Identity: request.Identity, VersionID: request.VersionID, Exists: false, ObservedAt: store.now().UTC()}, nil
		}
		return cloudworker.StagingObjectObservation{}, errors.Join(cloudworker.ErrStagingPending, err)
	}
	if output == nil || !store.validHead(request.Identity, request.VersionID, output) {
		return cloudworker.StagingObjectObservation{}, cloudworker.ErrConflict
	}
	return cloudworker.StagingObjectObservation{Identity: request.Identity, VersionID: request.VersionID, Exists: true, ObservedAt: store.now().UTC()}, nil
}

func (store *S3StagingStore) DeleteVersion(ctx context.Context, request cloudworker.StagingVersionRequest) error {
	if store == nil || ctx == nil || request.Identity.Validate() != nil || !validS3VersionID(request.VersionID) || !store.matches(request.Identity) {
		return cloudworker.ErrInvalid
	}
	observation, err := store.ObserveVersion(ctx, request)
	if err != nil || !observation.Exists {
		return err
	}
	if err := store.verifyIdentity(ctx); err != nil {
		return err
	}
	output, deleteErr := store.s3.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: awssdk.String(request.Identity.Bucket), Key: awssdk.String(request.Identity.Key), VersionId: awssdk.String(request.VersionID),
		ExpectedBucketOwner: awssdk.String(store.config.AccountID),
	})
	if deleteErr != nil || output == nil || awssdk.ToString(output.VersionId) != request.VersionID {
		return errors.Join(cloudworker.ErrStagingResponseUnknown, deleteErr)
	}
	return nil
}

func (store *S3StagingStore) validHead(identity cloudworker.StagingObjectIdentity, versionID string, output *s3.HeadObjectOutput) bool {
	checksum, err := stagingChecksum(identity.SourceSHA256)
	return err == nil && awssdk.ToString(output.VersionId) == versionID && awssdk.ToInt64(output.ContentLength) == int64(identity.SizeBytes) &&
		awssdk.ToString(output.ContentType) == identity.MediaType && awssdk.ToString(output.ChecksumSHA256) == checksum &&
		output.ServerSideEncryption == s3types.ServerSideEncryptionAwsKms && awssdk.ToString(output.SSEKMSKeyId) == identity.KMSKeyARN &&
		maps.Equal(output.Metadata, identity.Metadata())
}

func (store *S3StagingStore) verifyIdentity(ctx context.Context) error {
	if store == nil || ctx == nil || store.config.Validate() != nil {
		return cloudaws.ErrIdentityMismatch
	}
	output, err := store.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || output == nil || awssdk.ToString(output.Account) != store.config.AccountID {
		return errors.Join(cloudaws.ErrIdentityMismatch, err)
	}
	return nil
}

func (store *S3StagingStore) matches(identity cloudworker.StagingObjectIdentity) bool {
	return store != nil && identity.AccountID == store.config.AccountID && identity.AccountGeneration == store.config.AccountGeneration &&
		identity.Region == store.config.Region && identity.ProviderID == store.config.ProviderID
}

func stagingChecksum(value string) (string, error) {
	digest, err := hex.DecodeString(value)
	if err != nil || len(digest) != 32 {
		return "", cloudworker.ErrInvalid
	}
	return base64.StdEncoding.EncodeToString(digest), nil
}

func stagingObjectNotFound(err error) bool {
	var api interface{ ErrorCode() string }
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode() {
	case "NoSuchKey", "NoSuchVersion", "NotFound", "404":
		return true
	default:
		return false
	}
}

var _ cloudworker.StagingObjectStore = (*S3StagingStore)(nil)
