package sdkclient

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestS3ArtifactRetentionUsesFreshAccountProofAndExactVersion(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	identity := artifactRetentionSDKFixture()
	events := []string{}
	fake := &stagingS3Fake{events: &events,
		headOutput: &s3.HeadObjectOutput{
			VersionId: awssdk.String(identity.Claim.VersionID), ContentLength: awssdk.Int64(identity.Claim.SizeBytes),
			ContentType: awssdk.String(identity.Claim.MediaType), Metadata: map[string]string{artifactDigestMetadataKey: identity.Claim.SHA256},
			ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: awssdk.String(identity.KMSKeyARN),
		},
		deleteOutput: &s3.DeleteObjectOutput{VersionId: awssdk.String(identity.Claim.VersionID)},
	}
	config := Config{AccountID: identity.AccountID, AccountGeneration: identity.AccountGeneration, Region: identity.Region, ProviderID: identity.ProviderID}
	store, err := newS3ArtifactRetentionStore(config, &recordingSTS{account: identity.AccountID, events: &events}, fake, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	observation, err := store.ObserveExactArtifact(context.Background(), identity)
	if err != nil || !observation.Exists || observation.Validate(identity) != nil {
		t.Fatalf("observation=%+v err=%v", observation, err)
	}
	if err = store.DeleteExactArtifact(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	want := []string{"sts", "s3.head", "sts", "s3.delete"}
	if len(events) != len(want) {
		t.Fatalf("events=%v", events)
	}
	for index := range want {
		if events[index] != want[index] {
			t.Fatalf("operation %d did not have adjacent account proof: %v", index, events)
		}
	}
	if fake.headInput == nil || fake.deleteInput == nil ||
		awssdk.ToString(fake.headInput.Bucket) != identity.Claim.Bucket ||
		awssdk.ToString(fake.headInput.Key) != identity.Claim.Key ||
		awssdk.ToString(fake.headInput.VersionId) != identity.Claim.VersionID ||
		awssdk.ToString(fake.deleteInput.VersionId) != identity.Claim.VersionID ||
		awssdk.ToString(fake.deleteInput.ExpectedBucketOwner) != identity.AccountID {
		t.Fatalf("S3 calls were not exact: head=%+v delete=%+v", fake.headInput, fake.deleteInput)
	}

	fake.deleteOutput, fake.deleteErr, events = nil, errors.New("connection reset"), nil
	fake.events = &events
	if err = store.DeleteExactArtifact(context.Background(), identity); !errors.Is(err, cloudworker.ErrArtifactDeleteUncertain) {
		t.Fatalf("ambiguous DeleteObjectVersion was classified safe: %v", err)
	}
}

func TestS3ArtifactRetentionRejectsMetadataOrProviderReplacement(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	identity := artifactRetentionSDKFixture()
	fake := &stagingS3Fake{headOutput: &s3.HeadObjectOutput{
		VersionId: awssdk.String(identity.Claim.VersionID), ContentLength: awssdk.Int64(identity.Claim.SizeBytes),
		ContentType: awssdk.String(identity.Claim.MediaType), Metadata: map[string]string{artifactDigestMetadataKey: "foreign"},
		ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: awssdk.String(identity.KMSKeyARN),
	}}
	config := Config{AccountID: identity.AccountID, AccountGeneration: identity.AccountGeneration, Region: identity.Region, ProviderID: identity.ProviderID}
	store, _ := newS3ArtifactRetentionStore(config, &recordingSTS{account: identity.AccountID}, fake, func() time.Time { return now })
	if _, err := store.ObserveExactArtifact(context.Background(), identity); !errors.Is(err, cloudworker.ErrStaleAuthorization) {
		t.Fatalf("foreign exact-version metadata was accepted: %v", err)
	}
	replacement := identity
	replacement.CredentialRevision++
	replacement.ProviderID = "credential:" + replacement.CredentialID + ":revision:4"
	if _, err := store.ObserveExactArtifact(context.Background(), replacement); !errors.Is(err, cloudworker.ErrInvalid) {
		t.Fatalf("same-name replacement provider was accepted: %v", err)
	}
}

func artifactRetentionSDKFixture() cloudworker.ArtifactRetentionIdentity {
	credentialID := "11111111-1111-4111-8111-111111111111"
	executionID := "22222222-2222-4222-8222-222222222222"
	prefix := "executions/" + executionID + "/"
	return cloudworker.ArtifactRetentionIdentity{
		ArtifactID: "33333333-3333-4333-8333-333333333333", OwnerID: "@owner:example.test",
		AccountID: "123456789012", AccountGeneration: 7, Region: "us-east-1",
		CredentialID: credentialID, CredentialRevision: 3,
		ProviderID:  "credential:" + credentialID + ":revision:3",
		ExecutionID: executionID, PlanID: "44444444-4444-4444-8444-444444444444",
		PlanDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		KeyPrefix:  prefix,
		KMSKeyARN:  "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111",
		Claim: cloudresult.ObjectClaim{
			Name: "final.json", Bucket: "dirextalk-worker-artifacts", Key: prefix + "final.json",
			VersionID: "exact-version-1", SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			SizeBytes: 128, MediaType: "application/json",
		},
		ExpiresAt: time.Date(2026, 8, 7, 11, 0, 0, 0, time.UTC),
	}
}
