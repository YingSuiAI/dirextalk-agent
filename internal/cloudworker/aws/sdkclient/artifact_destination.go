package sdkclient

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	defaultArtifactDestinationReadinessAttemptTimeout = 15 * time.Second
	defaultArtifactDestinationReadinessAttempts       = 2
)

type ArtifactDestinationS3API interface {
	HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketOwnershipControls(context.Context, *s3.GetBucketOwnershipControlsInput, ...func(*s3.Options)) (*s3.GetBucketOwnershipControlsOutput, error)
}

type ArtifactDestinationKMSAPI interface {
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

// S3ArtifactDestinationReadiness is a read-only, revision-bound preflight for
// the durable artifact destination. It proves that every required safety and
// retention property still exists before a quote or AWS mutation proceeds.
type S3ArtifactDestinationReadiness struct {
	config         Config
	sts            STSAPI
	s3             ArtifactDestinationS3API
	kms            ArtifactDestinationKMSAPI
	attemptTimeout time.Duration
	attempts       int
}

func NewS3ArtifactDestinationReadiness(sdkConfig awssdk.Config, config Config) (*S3ArtifactDestinationReadiness, error) {
	if config.Validate() != nil || sdkConfig.Region != config.Region || sdkConfig.Credentials == nil {
		return nil, cloudworker.ErrInvalid
	}
	sdkConfig = withoutSDKRetries(sdkConfig)
	return newS3ArtifactDestinationReadiness(config, sts.NewFromConfig(sdkConfig), s3.NewFromConfig(sdkConfig), kms.NewFromConfig(sdkConfig))
}

func newS3ArtifactDestinationReadiness(config Config, stsClient STSAPI, s3Client ArtifactDestinationS3API, kmsClient ArtifactDestinationKMSAPI) (*S3ArtifactDestinationReadiness, error) {
	if config.Validate() != nil || stsClient == nil || s3Client == nil || kmsClient == nil {
		return nil, cloudworker.ErrInvalid
	}
	return &S3ArtifactDestinationReadiness{
		config: config, sts: stsClient, s3: s3Client, kms: kmsClient,
		attemptTimeout: defaultArtifactDestinationReadinessAttemptTimeout,
		attempts:       defaultArtifactDestinationReadinessAttempts,
	}, nil
}

func (check *S3ArtifactDestinationReadiness) Readiness(ctx context.Context, bucket, kmsKeyARN string) error {
	if check == nil || ctx == nil || check.config.Validate() != nil || strings.TrimSpace(bucket) != bucket || len(bucket) < 3 ||
		!strings.HasPrefix(kmsKeyARN, "arn:aws:kms:"+check.config.Region+":"+check.config.AccountID+":key/") ||
		check.attemptTimeout <= 0 || check.attempts <= 0 {
		return cloudworker.ErrInvalid
	}
	var lastErr error
	for attempt := 0; attempt < check.attempts; attempt++ {
		callCtx, cancel := context.WithTimeout(ctx, check.attemptTimeout)
		err := check.readinessOnce(callCtx, bucket, kmsKeyARN)
		callErr := callCtx.Err()
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return errors.Join(cloudworker.ErrArtifactDestinationUnavailable, ctx.Err(), err)
		}
		if !errors.Is(callErr, context.DeadlineExceeded) {
			return err
		}
	}
	return errors.Join(cloudworker.ErrArtifactDestinationUnavailable, context.DeadlineExceeded, lastErr)
}

func (check *S3ArtifactDestinationReadiness) readinessOnce(ctx context.Context, bucket, kmsKeyARN string) error {
	caller, err := check.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || caller == nil || awssdk.ToString(caller.Account) != check.config.AccountID {
		return errors.Join(cloudaws.ErrIdentityMismatch, err)
	}
	head, err := check.s3.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: awssdk.String(bucket), ExpectedBucketOwner: awssdk.String(check.config.AccountID)})
	if err != nil || head == nil || awssdk.ToString(head.BucketRegion) != "" && awssdk.ToString(head.BucketRegion) != check.config.Region {
		return errors.Join(cloudworker.ErrArtifactDestinationUnavailable, err)
	}
	versioning, err := check.s3.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: awssdk.String(bucket), ExpectedBucketOwner: awssdk.String(check.config.AccountID)})
	if err != nil || versioning == nil || versioning.Status != s3types.BucketVersioningStatusEnabled {
		return errors.Join(cloudworker.ErrArtifactDestinationUnavailable, err)
	}
	encryption, err := check.s3.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: awssdk.String(bucket), ExpectedBucketOwner: awssdk.String(check.config.AccountID)})
	if err != nil || !validArtifactEncryption(encryption, kmsKeyARN) {
		return errors.Join(cloudworker.ErrArtifactDestinationUnavailable, err)
	}
	publicAccess, err := check.s3.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: awssdk.String(bucket), ExpectedBucketOwner: awssdk.String(check.config.AccountID)})
	if err != nil || publicAccess == nil || publicAccess.PublicAccessBlockConfiguration == nil ||
		!awssdk.ToBool(publicAccess.PublicAccessBlockConfiguration.BlockPublicAcls) ||
		!awssdk.ToBool(publicAccess.PublicAccessBlockConfiguration.IgnorePublicAcls) ||
		!awssdk.ToBool(publicAccess.PublicAccessBlockConfiguration.BlockPublicPolicy) ||
		!awssdk.ToBool(publicAccess.PublicAccessBlockConfiguration.RestrictPublicBuckets) {
		return errors.Join(cloudworker.ErrArtifactDestinationUnavailable, err)
	}
	ownership, err := check.s3.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{Bucket: awssdk.String(bucket), ExpectedBucketOwner: awssdk.String(check.config.AccountID)})
	if err != nil || ownership == nil || ownership.OwnershipControls == nil || len(ownership.OwnershipControls.Rules) != 1 ||
		ownership.OwnershipControls.Rules[0].ObjectOwnership != s3types.ObjectOwnershipBucketOwnerEnforced {
		return errors.Join(cloudworker.ErrArtifactDestinationUnavailable, err)
	}
	key, err := check.kms.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: awssdk.String(kmsKeyARN)})
	if err != nil || key == nil || key.KeyMetadata == nil || !key.KeyMetadata.Enabled ||
		awssdk.ToString(key.KeyMetadata.Arn) != kmsKeyARN || awssdk.ToString(key.KeyMetadata.AWSAccountId) != check.config.AccountID ||
		key.KeyMetadata.KeyState != kmstypes.KeyStateEnabled || key.KeyMetadata.KeyUsage != kmstypes.KeyUsageTypeEncryptDecrypt ||
		key.KeyMetadata.KeyManager != kmstypes.KeyManagerTypeCustomer {
		return errors.Join(cloudworker.ErrArtifactDestinationUnavailable, err)
	}
	return nil
}

func validArtifactEncryption(output *s3.GetBucketEncryptionOutput, kmsKeyARN string) bool {
	if output == nil || output.ServerSideEncryptionConfiguration == nil || len(output.ServerSideEncryptionConfiguration.Rules) != 1 {
		return false
	}
	rule := output.ServerSideEncryptionConfiguration.Rules[0]
	return rule.ApplyServerSideEncryptionByDefault != nil &&
		rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm == s3types.ServerSideEncryptionAwsKms &&
		awssdk.ToString(rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID) == kmsKeyARN && !awssdk.ToBool(rule.BucketKeyEnabled)
}
