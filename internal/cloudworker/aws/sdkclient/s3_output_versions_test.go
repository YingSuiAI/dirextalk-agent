package sdkclient

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
)

func TestS3OutputVersionStoreInventoriesEveryVersionAndDeletesOnlyExactIdentity(t *testing.T) {
	identity := outputStoreIdentity()
	config := outputStoreConfig(identity)
	now := time.Date(2026, 8, 8, 9, 0, 0, 0, time.UTC)
	events := make([]string, 0, 10)
	api := &outputS3Fake{events: &events, lists: []*s3.ListObjectVersionsOutput{
		outputListPage(identity, "", "", true,
			[]s3types.ObjectVersion{{Key: awssdk.String(identity.KeyPrefix + "result.json"), VersionId: awssdk.String("result-version-1"), Size: awssdk.Int64(128)}},
			[]s3types.DeleteMarkerEntry{{Key: awssdk.String(identity.KeyPrefix + "failed.json"), VersionId: awssdk.String("delete-version-1")}},
			identity.KeyPrefix+"result.json", "result-version-1"),
		outputListPage(identity, identity.KeyPrefix+"result.json", "result-version-1", false,
			[]s3types.ObjectVersion{{Key: awssdk.String(identity.KeyPrefix + "final.patch"), VersionId: awssdk.String("artifact-version-1"), Size: awssdk.Int64(64)}}, nil, "", ""),
	}, head: &s3.HeadObjectOutput{
		VersionId: awssdk.String("artifact-version-1"), ContentLength: awssdk.Int64(64), ContentType: awssdk.String("text/x-diff"),
		Metadata:             map[string]string{artifactDigestMetadataKey: cloudDigest("artifact")},
		ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: awssdk.String(identity.KMSKeyARN),
		BucketKeyEnabled: awssdk.Bool(false),
	}}
	store, err := newS3OutputVersionStore(config, identity, &recordingSTS{account: identity.AccountID, events: &events}, api, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	firstRequest := cloudworker.OutputInventoryRequest{Identity: identity}
	first, err := store.InventoryPage(t.Context(), firstRequest)
	if err != nil || len(first.Versions) != 2 || first.NextCursor.KeyMarker == "" || !first.Versions[1].Identity.DeleteMarker {
		t.Fatalf("first inventory=%+v err=%v", first, err)
	}
	secondRequest := cloudworker.OutputInventoryRequest{Identity: identity, Cursor: first.NextCursor}
	second, err := store.InventoryPage(t.Context(), secondRequest)
	if err != nil || len(second.Versions) != 1 || second.Versions[0].Identity.Key != identity.KeyPrefix+"final.patch" || second.NextCursor.KeyMarker != "" {
		t.Fatalf("second inventory=%+v err=%v", second, err)
	}
	exact, err := store.ObserveExact(t.Context(), second.Versions[0].Identity)
	if err != nil || !exact.Exists || exact.SHA256 != cloudDigest("artifact") || exact.KMSKeyARN != identity.KMSKeyARN {
		t.Fatalf("exact observation=%+v err=%v", exact, err)
	}
	api.deletes = []*s3.DeleteObjectOutput{
		{VersionId: awssdk.String("result-version-1"), DeleteMarker: awssdk.Bool(false)},
		{VersionId: awssdk.String("delete-version-1"), DeleteMarker: awssdk.Bool(true)},
	}
	if err = store.DeleteExact(t.Context(), first.Versions[0].Identity); err != nil {
		t.Fatal(err)
	}
	if err = store.DeleteExact(t.Context(), first.Versions[1].Identity); err != nil {
		t.Fatal(err)
	}
	if len(api.deleteInputs) != 2 || awssdk.ToString(api.deleteInputs[0].VersionId) != "result-version-1" ||
		awssdk.ToString(api.deleteInputs[1].VersionId) != "delete-version-1" ||
		awssdk.ToString(api.deleteInputs[0].ExpectedBucketOwner) != identity.AccountID {
		t.Fatalf("delete inputs=%+v", api.deleteInputs)
	}
	wantEvents := []string{"sts", "s3.list", "sts", "s3.list", "sts", "s3.head", "sts", "s3.delete", "sts", "s3.delete"}
	if len(events) != len(wantEvents) {
		t.Fatalf("events=%v want=%v", events, wantEvents)
	}
	for index := range wantEvents {
		if events[index] != wantEvents[index] {
			t.Fatalf("events=%v want=%v", events, wantEvents)
		}
	}
}

func TestS3OutputVersionStoreFailsClosedOnForeignOrAmbiguousResponses(t *testing.T) {
	identity := outputStoreIdentity()
	config := outputStoreConfig(identity)
	now := time.Date(2026, 8, 8, 9, 0, 0, 0, time.UTC)
	t.Run("foreign inventory", func(t *testing.T) {
		page := outputListPage(identity, "", "", false, nil, nil, "", "")
		page.Name = awssdk.String("replacement-bucket")
		store, _ := newS3OutputVersionStore(config, identity, &recordingSTS{account: identity.AccountID}, &outputS3Fake{lists: []*s3.ListObjectVersionsOutput{page}}, func() time.Time { return now })
		if _, err := store.InventoryPage(t.Context(), cloudworker.OutputInventoryRequest{Identity: identity}); !errors.Is(err, cloudworker.ErrStaleAuthorization) {
			t.Fatalf("foreign inventory err=%v", err)
		}
	})
	t.Run("non advancing cursor", func(t *testing.T) {
		page := outputListPage(identity, "cursor", "version", true, nil, nil, "cursor", "version")
		store, _ := newS3OutputVersionStore(config, identity, &recordingSTS{account: identity.AccountID}, &outputS3Fake{lists: []*s3.ListObjectVersionsOutput{page}}, func() time.Time { return now })
		request := cloudworker.OutputInventoryRequest{Identity: identity, Cursor: cloudworker.OutputInventoryCursor{KeyMarker: "cursor", VersionIDMarker: "version"}}
		if _, err := store.InventoryPage(t.Context(), request); !errors.Is(err, cloudworker.ErrStaleAuthorization) {
			t.Fatalf("same cursor err=%v", err)
		}
	})
	t.Run("head identity drift", func(t *testing.T) {
		version := cloudworker.OutputVersionIdentity{OutputExecutionIdentity: identity, Key: identity.KeyPrefix + "final.patch", VersionID: "artifact-version-1"}
		api := &outputS3Fake{head: &s3.HeadObjectOutput{
			VersionId: awssdk.String(version.VersionID), ContentLength: awssdk.Int64(64), ContentType: awssdk.String("text/x-diff"),
			Metadata: map[string]string{artifactDigestMetadataKey: cloudDigest("artifact")}, ServerSideEncryption: s3types.ServerSideEncryptionAwsKms,
			SSEKMSKeyId: awssdk.String("arn:aws:kms:us-east-1:123456789012:key/22222222-2222-4222-8222-222222222222"),
		}}
		store, _ := newS3OutputVersionStore(config, identity, &recordingSTS{account: identity.AccountID}, api, func() time.Time { return now })
		if _, err := store.ObserveExact(t.Context(), version); !errors.Is(err, cloudworker.ErrStaleAuthorization) {
			t.Fatalf("foreign head err=%v", err)
		}
	})
	t.Run("delete response unknown", func(t *testing.T) {
		version := cloudworker.OutputVersionIdentity{OutputExecutionIdentity: identity, Key: identity.KeyPrefix + "result.json", VersionID: "result-version-1"}
		api := &outputS3Fake{deletes: []*s3.DeleteObjectOutput{{VersionId: awssdk.String("replacement-version")}}}
		store, _ := newS3OutputVersionStore(config, identity, &recordingSTS{account: identity.AccountID}, api, func() time.Time { return now })
		if err := store.DeleteExact(t.Context(), version); !errors.Is(err, cloudworker.ErrOutputDeleteUncertain) {
			t.Fatalf("ambiguous delete err=%v", err)
		}
	})
	t.Run("account changed", func(t *testing.T) {
		api := &outputS3Fake{lists: []*s3.ListObjectVersionsOutput{outputListPage(identity, "", "", false, nil, nil, "", "")}}
		store, _ := newS3OutputVersionStore(config, identity, &recordingSTS{account: "999999999999"}, api, func() time.Time { return now })
		if _, err := store.InventoryPage(t.Context(), cloudworker.OutputInventoryRequest{Identity: identity}); err == nil || len(api.listInputs) != 0 {
			t.Fatalf("account drift err=%v list_calls=%d", err, len(api.listInputs))
		}
	})
}

func outputStoreIdentity() cloudworker.OutputExecutionIdentity {
	executionID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("output-execution")).String()
	return cloudworker.OutputExecutionIdentity{
		OwnerID: "@owner:example.test", AccountID: "123456789012", AccountGeneration: 7,
		Region: "us-east-1", CredentialID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("output-credential")).String(),
		CredentialRevision: 3, ProviderID: "credential:" + uuid.NewSHA1(uuid.NameSpaceOID, []byte("output-credential")).String() + ":revision:3",
		ExecutionID: executionID, PlanID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("output-plan")).String(),
		PlanDigest: cloudDigest("output-plan"), TaskID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("output-task")).String(),
		Bucket: "dirextalk-worker-artifacts", KeyPrefix: "executions/" + executionID + "/",
		KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111",
	}
}

func outputStoreConfig(identity cloudworker.OutputExecutionIdentity) Config {
	return Config{AccountID: identity.AccountID, AccountGeneration: identity.AccountGeneration, Region: identity.Region, ProviderID: identity.ProviderID}
}

func outputListPage(
	identity cloudworker.OutputExecutionIdentity,
	keyMarker, versionMarker string,
	truncated bool,
	versions []s3types.ObjectVersion,
	markers []s3types.DeleteMarkerEntry,
	nextKey, nextVersion string,
) *s3.ListObjectVersionsOutput {
	return &s3.ListObjectVersionsOutput{
		Name: awssdk.String(identity.Bucket), Prefix: awssdk.String(identity.KeyPrefix), MaxKeys: awssdk.Int32(1000),
		KeyMarker: awssdk.String(keyMarker), VersionIdMarker: awssdk.String(versionMarker), IsTruncated: awssdk.Bool(truncated),
		NextKeyMarker: awssdk.String(nextKey), NextVersionIdMarker: awssdk.String(nextVersion),
		Versions: versions, DeleteMarkers: markers,
	}
}

type outputS3Fake struct {
	events       *[]string
	lists        []*s3.ListObjectVersionsOutput
	listInputs   []*s3.ListObjectVersionsInput
	head         *s3.HeadObjectOutput
	deletes      []*s3.DeleteObjectOutput
	deleteInputs []*s3.DeleteObjectInput
}

func (fake *outputS3Fake) ListObjectVersions(_ context.Context, input *s3.ListObjectVersionsInput, _ ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error) {
	fake.record("s3.list")
	fake.listInputs = append(fake.listInputs, input)
	if len(fake.lists) == 0 {
		return nil, errors.New("unexpected list")
	}
	output := fake.lists[0]
	fake.lists = fake.lists[1:]
	return output, nil
}

func (fake *outputS3Fake) HeadObject(_ context.Context, _ *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	fake.record("s3.head")
	return fake.head, nil
}

func (fake *outputS3Fake) DeleteObject(_ context.Context, input *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	fake.record("s3.delete")
	fake.deleteInputs = append(fake.deleteInputs, input)
	if len(fake.deletes) == 0 {
		return nil, errors.New("unexpected delete")
	}
	output := fake.deletes[0]
	fake.deletes = fake.deletes[1:]
	return output, nil
}

func (fake *outputS3Fake) record(event string) {
	if fake.events != nil {
		*fake.events = append(*fake.events, event)
	}
}

var _ S3OutputVersionAPI = (*outputS3Fake)(nil)
