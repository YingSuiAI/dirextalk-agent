package workerrunner

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type scopedS3Fake struct {
	put         *s3.PutObjectInput
	head        *s3.HeadObjectInput
	body        []byte
	putErr      error
	corruptHead bool
}

func (*scopedS3Fake) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return nil, errors.New("not implemented")
}

func (fake *scopedS3Fake) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	fake.put = input
	body, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	fake.body = body
	if fake.putErr != nil {
		return nil, fake.putErr
	}
	return &s3.PutObjectOutput{}, nil
}

func (fake *scopedS3Fake) HeadObject(_ context.Context, input *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	fake.head = input
	if fake.put == nil || aws.ToString(input.Bucket) != aws.ToString(fake.put.Bucket) || aws.ToString(input.Key) != aws.ToString(fake.put.Key) {
		return nil, errors.New("object not found")
	}
	checksum := aws.ToString(fake.put.ChecksumSHA256)
	if fake.corruptHead {
		checksum = base64.StdEncoding.EncodeToString(make([]byte, 32))
	}
	return &s3.HeadObjectOutput{
		ContentLength: aws.Int64(int64(len(fake.body))), ChecksumSHA256: aws.String(checksum),
		ContentType: fake.put.ContentType, Metadata: fake.put.Metadata,
		ServerSideEncryption: s3types.ServerSideEncryptionAwsKms,
		SSEKMSKeyId:          aws.String("arn:aws:kms:us-east-1:123456789012:key/test"), BucketKeyEnabled: aws.Bool(true),
	}, nil
}

func TestS3ObjectStoreReturnsDigestBoundClaimAfterEncryptedReadBack(t *testing.T) {
	fake := &scopedS3Fake{putErr: errors.New("response lost after accepted write")}
	store, err := NewS3ObjectStore(fake)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"schema_version":1,"status":"succeeded"}`)
	claim, err := store.Put(context.Background(), "s3://worker-bucket/workers/principal/deployment/artifacts/result.json", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Ref != "s3://worker-bucket/workers/principal/deployment/artifacts/result.json" || claim.SizeBytes != int64(len(body)) ||
		claim.MediaType != "application/json" || claim.Digest() == "" {
		t.Fatalf("claim=%+v", claim)
	}
	if fake.put == nil || fake.put.ChecksumAlgorithm != s3types.ChecksumAlgorithmSha256 || aws.ToString(fake.put.ChecksumSHA256) == "" ||
		fake.put.ServerSideEncryption != s3types.ServerSideEncryptionAwsKms || !aws.ToBool(fake.put.BucketKeyEnabled) ||
		aws.ToString(fake.put.IfNoneMatch) != "*" || fake.put.Metadata["schema"] != workerObjectSchemaV1 || fake.put.Metadata["sha256"] == "" {
		t.Fatalf("PutObject input=%+v", fake.put)
	}
	if fake.head == nil || fake.head.ChecksumMode != s3types.ChecksumModeEnabled {
		t.Fatalf("HeadObject input=%+v", fake.head)
	}
}

func TestS3ObjectStoreRejectsSecretCanaryAndCorruptReadBack(t *testing.T) {
	fake := &scopedS3Fake{}
	store, err := NewS3ObjectStore(fake)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), "s3://worker-bucket/workers/p/d/artifacts/result.json", "application/json", []byte(`{"token":"sk-abcdefghijklmnopqrstuvwxyz012345"}`)); err == nil || fake.put != nil {
		t.Fatalf("secret canary reached S3: err=%v put=%+v", err, fake.put)
	}
	fake.corruptHead = true
	if _, err := store.Put(context.Background(), "s3://worker-bucket/workers/p/d/artifacts/result.json", "application/json", []byte(`{"safe":true}`)); err == nil {
		t.Fatal("corrupt encrypted read-back was accepted")
	}
}
