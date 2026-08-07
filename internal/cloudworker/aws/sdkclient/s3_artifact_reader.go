package sdkclient

import (
	"context"
	"errors"
	"io"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ExactArtifactReaderFactory constructs a reader sealed to one retained object.
// Construction performs no AWS call; each object read independently verifies
// the configured account through STS before issuing exact-version GetObject.
type ExactArtifactReaderFactory struct {
	sdkConfig awssdk.Config
	config    Config
}

func NewExactArtifactReaderFactory(sdkConfig awssdk.Config, config Config) (*ExactArtifactReaderFactory, error) {
	if config.Validate() != nil || sdkConfig.Region != config.Region || sdkConfig.Credentials == nil {
		return nil, cloudworker.ErrInvalid
	}
	sdkConfig = withoutSDKRetries(sdkConfig)
	return &ExactArtifactReaderFactory{sdkConfig: sdkConfig, config: config}, nil
}

func (factory *ExactArtifactReaderFactory) ReaderForArtifact(
	ctx context.Context,
	authority cloudworker.ArtifactDownloadAuthority,
) (cloudresult.ObjectReader, error) {
	if factory == nil || ctx == nil || ctx.Err() != nil || authority.Retention.Identity.Validate() != nil {
		return nil, cloudworker.ErrStaleAuthorization
	}
	return NewS3ArtifactObjectReader(factory.sdkConfig, factory.config, authority.Retention.Identity)
}

type S3ArtifactObjectReader struct {
	config   Config
	identity cloudworker.ArtifactRetentionIdentity
	sts      STSAPI
	s3       S3API
}

func NewS3ArtifactObjectReader(
	sdkConfig awssdk.Config,
	config Config,
	identity cloudworker.ArtifactRetentionIdentity,
) (*S3ArtifactObjectReader, error) {
	if config.Validate() != nil || sdkConfig.Region != config.Region || sdkConfig.Credentials == nil {
		return nil, cloudresult.ErrInvalid
	}
	sdkConfig = withoutSDKRetries(sdkConfig)
	return newS3ArtifactObjectReader(config, identity, sts.NewFromConfig(sdkConfig), s3.NewFromConfig(sdkConfig))
}

func newS3ArtifactObjectReader(
	config Config,
	identity cloudworker.ArtifactRetentionIdentity,
	stsClient STSAPI,
	s3Client S3API,
) (*S3ArtifactObjectReader, error) {
	if config.Validate() != nil || identity.Validate() != nil || stsClient == nil || s3Client == nil ||
		identity.AccountID != config.AccountID || identity.AccountGeneration != config.AccountGeneration ||
		identity.Region != config.Region || identity.ProviderID != config.ProviderID {
		return nil, cloudresult.ErrInvalid
	}
	return &S3ArtifactObjectReader{config: config, identity: identity, sts: stsClient, s3: s3Client}, nil
}

func (reader *S3ArtifactObjectReader) ReadObject(
	ctx context.Context,
	request cloudresult.ObjectRequest,
) (cloudresult.ObjectRead, error) {
	if reader == nil || ctx == nil {
		return cloudresult.ObjectRead{}, cloudresult.ErrInvalid
	}
	claim := reader.identity.Claim
	if request.Bucket != claim.Bucket || request.Key != claim.Key ||
		request.VersionID != claim.VersionID || request.MaximumBytes != claim.SizeBytes {
		return cloudresult.ObjectRead{}, cloudresult.ErrInvalid
	}
	if err := reader.verifyIdentity(ctx); err != nil {
		return cloudresult.ObjectRead{}, err
	}
	output, err := reader.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: awssdk.String(claim.Bucket), Key: awssdk.String(claim.Key),
		VersionId: awssdk.String(claim.VersionID), ExpectedBucketOwner: awssdk.String(reader.identity.AccountID),
	})
	if err != nil || output == nil || output.Body == nil {
		return cloudresult.ObjectRead{}, errors.Join(cloudresult.ErrUnavailable, err)
	}
	if awssdk.ToString(output.VersionId) != claim.VersionID || awssdk.ToInt64(output.ContentLength) != claim.SizeBytes ||
		awssdk.ToString(output.ContentType) != claim.MediaType || awssdk.ToBool(output.DeleteMarker) ||
		artifactDigestMetadata(output.Metadata) != claim.SHA256 ||
		output.ServerSideEncryption != s3types.ServerSideEncryptionAwsKms ||
		awssdk.ToString(output.SSEKMSKeyId) != reader.identity.KMSKeyARN || awssdk.ToBool(output.BucketKeyEnabled) {
		_ = output.Body.Close()
		return cloudresult.ObjectRead{}, cloudworker.ErrStaleAuthorization
	}
	return cloudresult.ObjectRead{
		Bucket: claim.Bucket, Key: claim.Key, VersionID: claim.VersionID,
		SizeBytes: claim.SizeBytes, MediaType: claim.MediaType,
		Body: &limitedReadCloser{Reader: io.LimitReader(output.Body, claim.SizeBytes+1), closer: output.Body},
	}, nil
}

func (reader *S3ArtifactObjectReader) verifyIdentity(ctx context.Context) error {
	if reader == nil || ctx == nil || reader.identity.Validate() != nil ||
		reader.identity.AccountID != reader.config.AccountID ||
		reader.identity.AccountGeneration != reader.config.AccountGeneration ||
		reader.identity.Region != reader.config.Region || reader.identity.ProviderID != reader.config.ProviderID {
		return cloudworker.ErrStaleAuthorization
	}
	output, err := reader.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || output == nil || awssdk.ToString(output.Account) != reader.identity.AccountID {
		return errors.Join(cloudworker.ErrStaleAuthorization, err)
	}
	return nil
}

var _ cloudworker.ArtifactDownloadReaderFactory = (*ExactArtifactReaderFactory)(nil)
var _ cloudresult.ObjectReader = (*S3ArtifactObjectReader)(nil)
