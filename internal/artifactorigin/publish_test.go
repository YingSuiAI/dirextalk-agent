package artifactorigin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	assets "github.com/YingSuiAI/dirextalk-agent/deploy/awsartifactorigin"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

type fakeOriginS3 struct {
	exists       bool
	historical   bool
	putCalls     int
	put          *s3.PutObjectInput
	putErr       error
	payload      []byte
	headMutation func(*s3.HeadObjectOutput)
}

func (fake *fakeOriginS3) ListObjectVersions(_ context.Context, input *s3.ListObjectVersionsInput, _ ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error) {
	output := &s3.ListObjectVersionsOutput{}
	if fake.exists {
		output.Versions = []s3types.ObjectVersion{{Key: input.Prefix, VersionId: aws.String("version-1")}}
	}
	if fake.historical {
		output.DeleteMarkers = []s3types.DeleteMarkerEntry{{Key: input.Prefix, VersionId: aws.String("delete-marker-1")}}
	}
	return output, nil
}

func (fake *fakeOriginS3) HeadObject(_ context.Context, _ *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if !fake.exists {
		return nil, &smithy.GenericAPIError{Code: "NotFound", Message: "not found"}
	}
	digest := sha256.Sum256(fake.payload)
	output := &s3.HeadObjectOutput{
		BucketKeyEnabled: aws.Bool(true), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(digest[:])),
		ContentLength: aws.Int64(int64(len(fake.payload))), ContentType: aws.String("application/octet-stream"),
		Metadata:             map[string]string{"sha256": hexDigest(digest), "artifact-id": "fixture", "source-url": "https://example.com/fixture/v1", "source-revision": "v1", "license": "MIT"},
		ServerSideEncryption: s3types.ServerSideEncryptionAwsKms,
		SSEKMSKeyId:          aws.String("arn:aws:kms:ap-northeast-3:123456789012:key/11111111-2222-4333-8444-555555555555"),
		VersionId:            aws.String("version-1"), CacheControl: aws.String(ImmutableCacheControl),
	}
	if fake.headMutation != nil {
		fake.headMutation(output)
	}
	return output, nil
}

func (fake *fakeOriginS3) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	fake.putCalls++
	fake.put = input
	if fake.putErr != nil {
		return nil, fake.putErr
	}
	payload, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	fake.payload = payload
	fake.exists = true
	return &s3.PutObjectOutput{VersionId: aws.String("version-1")}, nil
}

type fakeHTTP struct {
	calls    int
	status   int
	payload  []byte
	location string
	request  *http.Request
}

func (fake *fakeHTTP) Do(request *http.Request) (*http.Response, error) {
	fake.calls++
	fake.request = request
	status := fake.status
	if status == 0 {
		status = http.StatusOK
	}
	response := &http.Response{
		StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(fake.payload)),
		ContentLength: int64(len(fake.payload)), Request: request,
	}
	response.Header.Set("Content-Length", int64String(int64(len(fake.payload))))
	if fake.location != "" {
		response.Header.Set("Location", fake.location)
	}
	return response, nil
}

func TestPublishRefusesExistingObjectWithoutPut(t *testing.T) {
	payload := []byte("immutable fixture")
	artifact, name := fixtureArtifact(t, payload)
	defer os.Remove(name)
	store := &fakeOriginS3{exists: true, payload: payload}
	client := &fakeHTTP{payload: payload}
	_, err := Publish(context.Background(), validOriginReceipt(), artifact, name, store, client, testNow)
	if !errors.Is(err, ErrImmutableConflict) || store.putCalls != 0 || client.calls != 0 {
		t.Fatalf("Publish existing error=%v put=%d http=%d", err, store.putCalls, client.calls)
	}
}

func TestPublishRefusesHistoricalDeleteMarkerWithoutPut(t *testing.T) {
	payload := []byte("immutable fixture")
	artifact, name := fixtureArtifact(t, payload)
	defer os.Remove(name)
	store := &fakeOriginS3{historical: true}
	client := &fakeHTTP{payload: payload}
	_, err := Publish(context.Background(), validOriginReceipt(), artifact, name, store, client, testNow)
	if !errors.Is(err, ErrImmutableConflict) || store.putCalls != 0 || client.calls != 0 {
		t.Fatalf("Publish historical error=%v put=%d http=%d", err, store.putCalls, client.calls)
	}
}

func TestPublishRefusesConcurrentConditionalPutConflict(t *testing.T) {
	payload := []byte("immutable fixture")
	artifact, name := fixtureArtifact(t, payload)
	defer os.Remove(name)
	store := &fakeOriginS3{putErr: &smithy.GenericAPIError{Code: "PreconditionFailed", Message: "object now exists"}}
	client := &fakeHTTP{payload: payload}
	_, err := Publish(context.Background(), validOriginReceipt(), artifact, name, store, client, testNow)
	if !errors.Is(err, ErrImmutableConflict) || store.putCalls != 1 || client.calls != 0 {
		t.Fatalf("Publish raced error=%v put=%d http=%d", err, store.putCalls, client.calls)
	}
}

func TestPublishUsesConditionalKMSPutThenVerifiesS3AndCloudFront(t *testing.T) {
	payload := []byte("immutable fixture")
	artifact, name := fixtureArtifact(t, payload)
	defer os.Remove(name)
	store := &fakeOriginS3{}
	client := &fakeHTTP{payload: payload}
	receipt, err := Publish(context.Background(), validOriginReceipt(), artifact, name, store, client, testNow)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	digest := mustDigest(payload)
	if store.putCalls != 1 || aws.ToString(store.put.IfNoneMatch) != "*" || store.put.ServerSideEncryption != s3types.ServerSideEncryptionAwsKms ||
		aws.ToString(store.put.SSEKMSKeyId) != validOriginReceipt().KMSKeyARN || !aws.ToBool(store.put.BucketKeyEnabled) ||
		aws.ToString(store.put.ChecksumSHA256) != base64.StdEncoding.EncodeToString(digest[:]) {
		t.Fatalf("conditional put = %#v", store.put)
	}
	if client.calls != 1 || client.request.URL.RawQuery != "" || client.request.URL.Fragment != "" || client.request.Method != http.MethodGet ||
		client.request.URL.String() != receipt.URL || receipt.S3VersionID != "version-1" {
		t.Fatalf("edge verification/receipt = request %#v receipt %#v", client.request, receipt)
	}
}

func TestPublishFailsClosedOnS3OrEdgeDrift(t *testing.T) {
	payload := []byte("immutable fixture")
	artifact, name := fixtureArtifact(t, payload)
	defer os.Remove(name)
	for _, test := range []struct {
		name   string
		mutate func(*s3.HeadObjectOutput)
		http   *fakeHTTP
	}{
		{name: "s3 metadata", mutate: func(output *s3.HeadObjectOutput) { output.Metadata["sha256"] = "bad" }, http: &fakeHTTP{payload: payload}},
		{name: "edge redirect", http: &fakeHTTP{status: http.StatusFound, location: "https://elsewhere.example", payload: payload}},
		{name: "edge digest", http: &fakeHTTP{payload: bytes.Repeat([]byte{'x'}, len(payload))}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeOriginS3{headMutation: test.mutate}
			if _, err := Publish(context.Background(), validOriginReceipt(), artifact, name, store, test.http, testNow); err == nil {
				t.Fatal("Publish accepted drift")
			}
		})
	}
}

func TestVerifyPublishedRecoversLostWriteResponseWithoutPut(t *testing.T) {
	payload := []byte("immutable fixture")
	artifact, name := fixtureArtifact(t, payload)
	defer os.Remove(name)
	store := &fakeOriginS3{exists: true, payload: payload}
	client := &fakeHTTP{payload: payload}
	receipt, err := VerifyPublished(context.Background(), validOriginReceipt(), artifact, name, store, client, testNow)
	if err != nil || store.putCalls != 0 || receipt.S3VersionID != "version-1" || client.calls != 1 {
		t.Fatalf("VerifyPublished() receipt=%#v error=%v put=%d http=%d", receipt, err, store.putCalls, client.calls)
	}
}

func fixtureArtifact(t *testing.T, payload []byte) (Artifact, string) {
	t.Helper()
	digest := sha256.Sum256(payload)
	directory := t.TempDir()
	name := filepath.Join(directory, "fixture.bin")
	if err := os.WriteFile(name, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return Artifact{
		ID: "fixture", Name: "fixture.bin", SHA256: hexDigest(digest), SizeBytes: int64(len(payload)),
		MediaType: "application/octet-stream", SourceURL: "https://example.com/fixture/v1", SourceRevision: "v1", License: "MIT",
	}, name
}

func validOriginReceipt() OriginReceipt {
	return OriginReceipt{
		SchemaVersion: OriginReceiptSchemaV1, AccountID: "123456789012", StorageRegion: StorageRegion, Domain: DomainName,
		StorageStackID: stackARN(StorageRegion, StorageStackName), EdgeStackID: stackARN(EdgeRegion, EdgeStackName),
		BucketName: bucketName(), KMSKeyARN: "arn:aws:kms:ap-northeast-3:123456789012:key/11111111-2222-4333-8444-555555555555",
		DistributionID: "E1234567890ABC", DistributionARN: validEdgeOutputs()["DistributionArn"], DistributionDomainName: "d111111abcdef8.cloudfront.net",
		StorageTemplateSHA256: templateDigest(assets.StorageTemplate()), EdgeTemplateSHA256: templateDigest(assets.EdgeTemplate()), PreparedAt: testNow(),
	}
}

func mustDigest(payload []byte) [32]byte { return sha256.Sum256(payload) }

func hexDigest(digest [32]byte) string { return hex.EncodeToString(digest[:]) }

func int64String(value int64) string { return strconv.FormatInt(value, 10) }

func testNow() time.Time { return time.Date(2026, 7, 19, 2, 3, 4, 0, time.UTC) }
