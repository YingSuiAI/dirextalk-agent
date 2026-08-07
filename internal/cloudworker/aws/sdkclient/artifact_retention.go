package sdkclient

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const artifactDigestMetadataKey = "dirextalk-sha256"

type S3ArtifactRetentionAPI interface {
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// S3ArtifactRetentionStore is bound to one configured AWS owner identity. It
// disables SDK retries, proves the STS account before every request, and only
// observes or deletes an exact, centrally verified VersionId.
type S3ArtifactRetentionStore struct {
	config Config
	sts    STSAPI
	s3     S3ArtifactRetentionAPI
	now    func() time.Time
}

func NewS3ArtifactRetentionStore(sdkConfig awssdk.Config, config Config) (*S3ArtifactRetentionStore, error) {
	if config.Validate() != nil || sdkConfig.Region != config.Region || sdkConfig.Credentials == nil {
		return nil, cloudworker.ErrInvalid
	}
	sdkConfig = withoutSDKRetries(sdkConfig)
	return newS3ArtifactRetentionStore(config, sts.NewFromConfig(sdkConfig), s3.NewFromConfig(sdkConfig), time.Now)
}

func newS3ArtifactRetentionStore(config Config, stsClient STSAPI, s3Client S3ArtifactRetentionAPI, now func() time.Time) (*S3ArtifactRetentionStore, error) {
	if config.Validate() != nil || stsClient == nil || s3Client == nil || now == nil {
		return nil, cloudworker.ErrInvalid
	}
	return &S3ArtifactRetentionStore{config: config, sts: stsClient, s3: s3Client, now: now}, nil
}

func (store *S3ArtifactRetentionStore) Readiness(ctx context.Context) error {
	return store.verifyIdentity(ctx)
}

func (store *S3ArtifactRetentionStore) ObserveExactArtifact(ctx context.Context, identity cloudworker.ArtifactRetentionIdentity) (cloudworker.ArtifactObjectObservation, error) {
	if store == nil || ctx == nil || identity.Validate() != nil || !store.matches(identity) {
		return cloudworker.ArtifactObjectObservation{}, cloudworker.ErrInvalid
	}
	if err := store.verifyIdentity(ctx); err != nil {
		return cloudworker.ArtifactObjectObservation{}, err
	}
	output, err := store.s3.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: awssdk.String(identity.Claim.Bucket), Key: awssdk.String(identity.Claim.Key),
		VersionId: awssdk.String(identity.Claim.VersionID), ExpectedBucketOwner: awssdk.String(identity.AccountID),
	})
	if err != nil {
		if stagingObjectNotFound(err) {
			return cloudworker.ArtifactObjectObservation{Identity: identity, Exists: false, ObservedAt: store.now().UTC()}, nil
		}
		return cloudworker.ArtifactObjectObservation{}, errors.Join(cloudworker.ErrArtifactDeletePending, err)
	}
	if output == nil || awssdk.ToBool(output.DeleteMarker) || awssdk.ToString(output.VersionId) != identity.Claim.VersionID ||
		awssdk.ToInt64(output.ContentLength) != identity.Claim.SizeBytes || awssdk.ToString(output.ContentType) != identity.Claim.MediaType ||
		artifactDigestMetadata(output.Metadata) != identity.Claim.SHA256 ||
		output.ServerSideEncryption != s3types.ServerSideEncryptionAwsKms ||
		awssdk.ToString(output.SSEKMSKeyId) != identity.KMSKeyARN || awssdk.ToBool(output.BucketKeyEnabled) {
		return cloudworker.ArtifactObjectObservation{}, cloudworker.ErrStaleAuthorization
	}
	return cloudworker.ArtifactObjectObservation{Identity: identity, Exists: true, ObservedAt: store.now().UTC()}, nil
}

func (store *S3ArtifactRetentionStore) DeleteExactArtifact(ctx context.Context, identity cloudworker.ArtifactRetentionIdentity) error {
	if store == nil || ctx == nil || identity.Validate() != nil || !store.matches(identity) {
		return cloudworker.ErrInvalid
	}
	if err := store.verifyIdentity(ctx); err != nil {
		return err
	}
	output, err := store.s3.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: awssdk.String(identity.Claim.Bucket), Key: awssdk.String(identity.Claim.Key),
		VersionId: awssdk.String(identity.Claim.VersionID), ExpectedBucketOwner: awssdk.String(identity.AccountID),
	})
	if err != nil || output == nil || awssdk.ToString(output.VersionId) != identity.Claim.VersionID || awssdk.ToBool(output.DeleteMarker) {
		return errors.Join(cloudworker.ErrArtifactDeleteUncertain, err)
	}
	return nil
}

func (store *S3ArtifactRetentionStore) verifyIdentity(ctx context.Context) error {
	if store == nil || ctx == nil || store.config.Validate() != nil {
		return cloudaws.ErrIdentityMismatch
	}
	output, err := store.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || output == nil || awssdk.ToString(output.Account) != store.config.AccountID {
		return errors.Join(cloudaws.ErrIdentityMismatch, err)
	}
	return nil
}

func (store *S3ArtifactRetentionStore) matches(identity cloudworker.ArtifactRetentionIdentity) bool {
	return store != nil && identity.AccountID == store.config.AccountID &&
		identity.AccountGeneration == store.config.AccountGeneration && identity.Region == store.config.Region &&
		identity.ProviderID == store.config.ProviderID
}

func artifactDigestMetadata(metadata map[string]string) string {
	value := ""
	found := false
	for key, candidate := range metadata {
		if !strings.EqualFold(strings.TrimSpace(key), artifactDigestMetadataKey) {
			continue
		}
		if found || strings.TrimSpace(candidate) != candidate {
			return ""
		}
		found, value = true, candidate
	}
	if !found {
		return ""
	}
	return value
}

var _ cloudworker.ArtifactObjectStore = (*S3ArtifactRetentionStore)(nil)
