package sdkclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	cloudworker "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestS3StagingPutUsesFreshIdentityVersioningKMSChecksumAndMetadata(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	identity, body := stagingSDKFixture(t)
	events := []string{}
	fake := &stagingS3Fake{events: &events}
	checksum, _ := stagingChecksum(identity.SourceSHA256)
	fake.putOutput = &s3.PutObjectOutput{VersionId: awssdk.String("version-1"), ChecksumSHA256: awssdk.String(checksum),
		ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: awssdk.String(identity.KMSKeyARN)}
	store, err := newS3StagingStore(testSDKConfigForStaging(identity), &recordingSTS{account: identity.AccountID, events: &events}, fake, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	observation, err := store.PutVersion(context.Background(), cloudworker.StagingPutRequest{Identity: identity, Body: bytes.NewReader(body)})
	if err != nil || !observation.Exists || observation.VersionID != "version-1" {
		t.Fatalf("put observation=%+v err=%v", observation, err)
	}
	if len(events) != 2 || events[0] != "sts" || events[1] != "s3.put" {
		t.Fatalf("PutObject was not immediately preceded by STS: %v", events)
	}
	input := fake.putInput
	if input == nil || awssdk.ToString(input.ExpectedBucketOwner) != identity.AccountID || awssdk.ToString(input.ChecksumSHA256) != checksum ||
		input.ChecksumAlgorithm != s3types.ChecksumAlgorithmSha256 || input.ServerSideEncryption != s3types.ServerSideEncryptionAwsKms ||
		awssdk.ToString(input.SSEKMSKeyId) != identity.KMSKeyARN || awssdk.ToBool(input.BucketKeyEnabled) ||
		awssdk.ToInt64(input.ContentLength) != int64(len(body)) || input.Metadata["staging-intent"] != identity.IntentDigest() {
		t.Fatalf("unsealed PutObject input: %+v", input)
	}

	fake.putOutput, fake.putErr, events = nil, errors.New("connection reset"), nil
	fake.events = &events
	if _, err := store.PutVersion(context.Background(), cloudworker.StagingPutRequest{Identity: identity, Body: bytes.NewReader(body)}); !errors.Is(err, cloudworker.ErrStagingResponseUnknown) {
		t.Fatalf("unknown PutObject response was classified safe: %v", err)
	}
}

func TestS3StagingFindAndObserveRequireUniqueExactOwnedVersion(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	identity, _ := stagingSDKFixture(t)
	events := []string{}
	fake := &stagingS3Fake{events: &events,
		listOutputs: []*s3.ListObjectVersionsOutput{{Versions: []s3types.ObjectVersion{{Key: awssdk.String(identity.Key), VersionId: awssdk.String("version-1")}}}},
		headOutput:  stagingHead(identity, "version-1")}
	store, _ := newS3StagingStore(testSDKConfigForStaging(identity), &recordingSTS{account: identity.AccountID, events: &events}, fake, func() time.Time { return now })
	observation, found, err := store.FindVersion(context.Background(), identity)
	if err != nil || !found || observation.VersionID != "version-1" {
		t.Fatalf("find=%+v found=%v err=%v", observation, found, err)
	}
	wantEvents := []string{"sts", "s3.list", "sts", "s3.head"}
	if len(events) != len(wantEvents) {
		t.Fatalf("events=%v", events)
	}
	for index := range wantEvents {
		if events[index] != wantEvents[index] {
			t.Fatalf("AWS call %d lacks adjacent STS: %v", index, events)
		}
	}
	if fake.listInput == nil || awssdk.ToString(fake.listInput.ExpectedBucketOwner) != identity.AccountID || awssdk.ToString(fake.listInput.Prefix) != identity.Key ||
		fake.headInput == nil || awssdk.ToString(fake.headInput.VersionId) != "version-1" || fake.headInput.ChecksumMode != s3types.ChecksumModeEnabled {
		t.Fatalf("inventory was not exact: list=%+v head=%+v", fake.listInput, fake.headInput)
	}

	t.Run("multiple versions conflict", func(t *testing.T) {
		local := &stagingS3Fake{listOutputs: []*s3.ListObjectVersionsOutput{{Versions: []s3types.ObjectVersion{
			{Key: awssdk.String(identity.Key), VersionId: awssdk.String("version-1")},
			{Key: awssdk.String(identity.Key), VersionId: awssdk.String("version-2")},
		}}}}
		candidate, _ := newS3StagingStore(testSDKConfigForStaging(identity), &recordingSTS{account: identity.AccountID}, local, func() time.Time { return now })
		if _, _, err := candidate.FindVersion(context.Background(), identity); !errors.Is(err, cloudworker.ErrConflict) || local.headCalls != 0 {
			t.Fatalf("ambiguous versions were selected: heads=%d err=%v", local.headCalls, err)
		}
	})

	t.Run("metadata drift conflicts", func(t *testing.T) {
		drift := stagingHead(identity, "version-1")
		drift.Metadata = map[string]string{"staging-intent": "foreign"}
		local := &stagingS3Fake{listOutputs: []*s3.ListObjectVersionsOutput{{Versions: []s3types.ObjectVersion{{Key: awssdk.String(identity.Key), VersionId: awssdk.String("version-1")}}}}, headOutput: drift}
		candidate, _ := newS3StagingStore(testSDKConfigForStaging(identity), &recordingSTS{account: identity.AccountID}, local, func() time.Time { return now })
		if _, _, err := candidate.FindVersion(context.Background(), identity); !errors.Is(err, cloudworker.ErrConflict) {
			t.Fatalf("foreign version was accepted: %v", err)
		}
	})
}

func TestS3StagingDeleteRevalidatesExactVersionAndUnknownIsReadbackOnly(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	identity, _ := stagingSDKFixture(t)
	events := []string{}
	fake := &stagingS3Fake{events: &events, headOutput: stagingHead(identity, "version-1"), deleteOutput: &s3.DeleteObjectOutput{VersionId: awssdk.String("version-1")}}
	store, _ := newS3StagingStore(testSDKConfigForStaging(identity), &recordingSTS{account: identity.AccountID, events: &events}, fake, func() time.Time { return now })
	request := cloudworker.StagingVersionRequest{Identity: identity, VersionID: "version-1"}
	if err := store.DeleteVersion(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	want := []string{"sts", "s3.head", "sts", "s3.delete"}
	if len(events) != len(want) {
		t.Fatalf("delete events=%v", events)
	}
	for index := range want {
		if events[index] != want[index] {
			t.Fatalf("delete call %d lacks fresh identity: %v", index, events)
		}
	}
	if fake.deleteInput == nil || awssdk.ToString(fake.deleteInput.VersionId) != "version-1" || awssdk.ToString(fake.deleteInput.ExpectedBucketOwner) != identity.AccountID {
		t.Fatalf("delete was not exact: %+v", fake.deleteInput)
	}

	fake.deleteOutput, fake.deleteErr, events = nil, errors.New("timeout"), nil
	fake.events = &events
	if err := store.DeleteVersion(context.Background(), request); !errors.Is(err, cloudworker.ErrStagingResponseUnknown) {
		t.Fatalf("unknown delete was classified safe: %v", err)
	}
}

func stagingSDKFixture(t *testing.T) (cloudworker.StagingObjectIdentity, []byte) {
	t.Helper()
	request := testCreateRequest(t)
	body := []byte("input-data")
	digest := sha256.Sum256(body)
	return cloudworker.StagingObjectIdentity{
		OwnerID: request.Identity.OwnerID, AccountID: request.Identity.AccountID, AccountGeneration: request.Identity.AccountGeneration,
		Region: request.Identity.Region, ProviderID: request.Identity.ProviderID, ExecutionID: request.Identity.ExecutionID,
		PlanDigest: request.Plan.Digest, InputID: "33333333-3333-4333-8333-333333333333", SourceRef: "44444444-4444-4444-8444-444444444444",
		SourceRevision: 3, SourceSHA256: hex.EncodeToString(digest[:]), SizeBytes: uint64(len(body)), MediaType: "text/plain",
		Bucket: "dirextalk-input", Key: "executions/11111111/inputs/33333333-3333-4333-8333-333333333333", KMSKeyARN: request.Plan.RootKMSKeyARN,
	}, body
}

func stagingHead(identity cloudworker.StagingObjectIdentity, versionID string) *s3.HeadObjectOutput {
	checksum, _ := stagingChecksum(identity.SourceSHA256)
	return &s3.HeadObjectOutput{VersionId: awssdk.String(versionID), ContentLength: awssdk.Int64(int64(identity.SizeBytes)),
		ContentType: awssdk.String(identity.MediaType), ChecksumSHA256: awssdk.String(checksum), Metadata: identity.Metadata(),
		ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: awssdk.String(identity.KMSKeyARN)}
}

func testSDKConfigForStaging(identity cloudworker.StagingObjectIdentity) Config {
	return Config{AccountID: identity.AccountID, AccountGeneration: identity.AccountGeneration, Region: identity.Region, ProviderID: identity.ProviderID}
}

type stagingS3Fake struct {
	events       *[]string
	putInput     *s3.PutObjectInput
	putOutput    *s3.PutObjectOutput
	putErr       error
	listInput    *s3.ListObjectVersionsInput
	listOutputs  []*s3.ListObjectVersionsOutput
	listErr      error
	listCalls    int
	headInput    *s3.HeadObjectInput
	headOutput   *s3.HeadObjectOutput
	headErr      error
	headCalls    int
	deleteInput  *s3.DeleteObjectInput
	deleteOutput *s3.DeleteObjectOutput
	deleteErr    error
}

func (fake *stagingS3Fake) record(event string) {
	if fake.events != nil {
		*fake.events = append(*fake.events, event)
	}
}

func (fake *stagingS3Fake) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	fake.record("s3.put")
	fake.putInput = input
	return fake.putOutput, fake.putErr
}

func (fake *stagingS3Fake) ListObjectVersions(_ context.Context, input *s3.ListObjectVersionsInput, _ ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error) {
	fake.record("s3.list")
	fake.listInput = input
	index := fake.listCalls
	fake.listCalls++
	if fake.listErr != nil || index >= len(fake.listOutputs) {
		return nil, fake.listErr
	}
	return fake.listOutputs[index], nil
}

func (fake *stagingS3Fake) HeadObject(_ context.Context, input *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	fake.record("s3.head")
	fake.headInput = input
	fake.headCalls++
	return fake.headOutput, fake.headErr
}

func (fake *stagingS3Fake) DeleteObject(_ context.Context, input *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	fake.record("s3.delete")
	fake.deleteInput = input
	return fake.deleteOutput, fake.deleteErr
}

var _ S3StagingAPI = (*stagingS3Fake)(nil)
var _ = cloudaws.ErrInvalid
