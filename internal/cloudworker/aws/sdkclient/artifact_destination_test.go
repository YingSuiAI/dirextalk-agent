package sdkclient

import (
	"context"
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type artifactDestinationS3Fake struct {
	head       *s3.HeadBucketOutput
	headErr    error
	versioning *s3.GetBucketVersioningOutput
	encryption *s3.GetBucketEncryptionOutput
	public     *s3.GetPublicAccessBlockOutput
	ownership  *s3.GetBucketOwnershipControlsOutput
}

func (fake *artifactDestinationS3Fake) HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	return fake.head, fake.headErr
}
func (fake *artifactDestinationS3Fake) GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	return fake.versioning, nil
}
func (fake *artifactDestinationS3Fake) GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	return fake.encryption, nil
}
func (fake *artifactDestinationS3Fake) GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	return fake.public, nil
}
func (fake *artifactDestinationS3Fake) GetBucketOwnershipControls(context.Context, *s3.GetBucketOwnershipControlsInput, ...func(*s3.Options)) (*s3.GetBucketOwnershipControlsOutput, error) {
	return fake.ownership, nil
}

type artifactDestinationKMSFake struct {
	output *kms.DescribeKeyOutput
}

func (fake *artifactDestinationKMSFake) DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return fake.output, nil
}

func TestS3ArtifactDestinationReadinessRequiresDurablePrivateEncryptedStorage(t *testing.T) {
	config, bucket, keyARN, s3Fake, kmsFake := artifactDestinationFixture()
	check, err := newS3ArtifactDestinationReadiness(config, &recordingSTS{account: config.AccountID}, s3Fake, kmsFake)
	if err != nil {
		t.Fatal(err)
	}
	if err = check.Readiness(context.Background(), bucket, keyARN); err != nil {
		t.Fatalf("healthy destination rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*artifactDestinationS3Fake, *artifactDestinationKMSFake)
	}{
		{name: "bucket missing", mutate: func(s3Fake *artifactDestinationS3Fake, _ *artifactDestinationKMSFake) {
			s3Fake.headErr = errors.New("NoSuchBucket")
		}},
		{name: "versioning disabled", mutate: func(s3Fake *artifactDestinationS3Fake, _ *artifactDestinationKMSFake) {
			s3Fake.versioning.Status = s3types.BucketVersioningStatusSuspended
		}},
		{name: "bucket key changes ciphertext contract", mutate: func(s3Fake *artifactDestinationS3Fake, _ *artifactDestinationKMSFake) {
			s3Fake.encryption.ServerSideEncryptionConfiguration.Rules[0].BucketKeyEnabled = awssdk.Bool(true)
		}},
		{name: "public access is not fully blocked", mutate: func(s3Fake *artifactDestinationS3Fake, _ *artifactDestinationKMSFake) {
			s3Fake.public.PublicAccessBlockConfiguration.BlockPublicPolicy = awssdk.Bool(false)
		}},
		{name: "kms key pending deletion", mutate: func(_ *artifactDestinationS3Fake, kmsFake *artifactDestinationKMSFake) {
			kmsFake.output.KeyMetadata.Enabled = false
			kmsFake.output.KeyMetadata.KeyState = kmstypes.KeyStatePendingDeletion
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, bucket, keyARN, s3Fake, kmsFake := artifactDestinationFixture()
			test.mutate(s3Fake, kmsFake)
			check, err := newS3ArtifactDestinationReadiness(config, &recordingSTS{account: config.AccountID}, s3Fake, kmsFake)
			if err != nil {
				t.Fatal(err)
			}
			if err = check.Readiness(context.Background(), bucket, keyARN); !errors.Is(err, cloudworker.ErrArtifactDestinationUnavailable) {
				t.Fatalf("unsafe destination error = %v", err)
			}
		})
	}
}

func artifactDestinationFixture() (Config, string, string, *artifactDestinationS3Fake, *artifactDestinationKMSFake) {
	config := Config{AccountID: "123456789012", AccountGeneration: 7, Region: "us-east-1", ProviderID: "credential:11111111-1111-4111-8111-111111111111:revision:3"}
	bucket := "dirextalk-worker-artifacts"
	keyARN := "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"
	allBlocked := &s3types.PublicAccessBlockConfiguration{
		BlockPublicAcls: awssdk.Bool(true), IgnorePublicAcls: awssdk.Bool(true),
		BlockPublicPolicy: awssdk.Bool(true), RestrictPublicBuckets: awssdk.Bool(true),
	}
	s3Fake := &artifactDestinationS3Fake{
		head:       &s3.HeadBucketOutput{BucketRegion: awssdk.String(config.Region)},
		versioning: &s3.GetBucketVersioningOutput{Status: s3types.BucketVersioningStatusEnabled},
		encryption: &s3.GetBucketEncryptionOutput{ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{Rules: []s3types.ServerSideEncryptionRule{{
			ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{SSEAlgorithm: s3types.ServerSideEncryptionAwsKms, KMSMasterKeyID: awssdk.String(keyARN)},
			BucketKeyEnabled:                   awssdk.Bool(false),
		}}}},
		public:    &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: allBlocked},
		ownership: &s3.GetBucketOwnershipControlsOutput{OwnershipControls: &s3types.OwnershipControls{Rules: []s3types.OwnershipControlsRule{{ObjectOwnership: s3types.ObjectOwnershipBucketOwnerEnforced}}}},
	}
	kmsFake := &artifactDestinationKMSFake{output: &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{
		Arn: awssdk.String(keyARN), AWSAccountId: awssdk.String(config.AccountID), Enabled: true,
		KeyState: kmstypes.KeyStateEnabled, KeyUsage: kmstypes.KeyUsageTypeEncryptDecrypt, KeyManager: kmstypes.KeyManagerTypeCustomer,
	}}}
	return config, bucket, keyARN, s3Fake, kmsFake
}
