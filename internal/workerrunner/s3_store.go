package workerrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const workerObjectSchemaV1 = "dirextalk-worker-object-v1"

var (
	ErrWorkerObjectInvalid     = errors.New("Worker output object is invalid")
	ErrWorkerObjectUnavailable = errors.New("Worker output object is unavailable")
)

type S3API interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

type S3ObjectStore struct{ client S3API }

func NewS3ObjectStore(client S3API) (*S3ObjectStore, error) {
	if client == nil {
		return nil, errors.New("S3 Worker object client is required")
	}
	return &S3ObjectStore{client: client}, nil
}

func (store *S3ObjectStore) Get(ctx context.Context, reference string) ([]byte, error) {
	bucket, key, err := splitS3Object(reference)
	if err != nil {
		return nil, err
	}
	output, err := store.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return nil, ErrWorkerObjectUnavailable
	}
	defer output.Body.Close()
	content, err := io.ReadAll(io.LimitReader(output.Body, maxBundleBytes+1))
	if err != nil {
		wipe(content)
		return nil, ErrWorkerObjectUnavailable
	}
	if len(content) > maxBundleBytes {
		wipe(content)
		return nil, ErrInvalidBundle
	}
	return content, nil
}

func (store *S3ObjectStore) Put(ctx context.Context, reference, contentType string, content []byte) (worker.ObjectClaim, error) {
	bucket, key, err := splitS3Object(reference)
	if err != nil {
		return worker.ObjectClaim{}, err
	}
	digest := sha256.Sum256(content)
	claim := worker.ObjectClaim{Ref: reference, SHA256: digest, SizeBytes: int64(len(content)), MediaType: contentType}
	if claim.Validate() != nil || int64(len(content)) > worker.MaximumObjectClaimBytes || security.ContainsLikelySecret(string(content)) {
		return worker.ObjectClaim{}, ErrWorkerObjectInvalid
	}
	hexDigest := hex.EncodeToString(digest[:])
	base64Digest := base64.StdEncoding.EncodeToString(digest[:])
	_, _ = store.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key), ContentType: aws.String(contentType), Body: bytes.NewReader(content),
		ContentLength: aws.Int64(int64(len(content))), ChecksumAlgorithm: s3types.ChecksumAlgorithmSha256,
		ChecksumSHA256: aws.String(base64Digest), ServerSideEncryption: s3types.ServerSideEncryptionAwsKms,
		BucketKeyEnabled: aws.Bool(true), IfNoneMatch: aws.String("*"), Metadata: map[string]string{"schema": workerObjectSchemaV1, "sha256": hexDigest},
	})
	head, headErr := store.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key), ChecksumMode: s3types.ChecksumModeEnabled,
	})
	if headErr == nil && exactWorkerObjectHead(head, claim, base64Digest, hexDigest) {
		return claim, nil
	}
	return worker.ObjectClaim{}, ErrWorkerObjectUnavailable
}

func exactWorkerObjectHead(head *s3.HeadObjectOutput, claim worker.ObjectClaim, base64Digest, hexDigest string) bool {
	return head != nil && aws.ToInt64(head.ContentLength) == claim.SizeBytes && aws.ToString(head.ChecksumSHA256) == base64Digest &&
		aws.ToString(head.ContentType) == claim.MediaType && head.ServerSideEncryption == s3types.ServerSideEncryptionAwsKms &&
		aws.ToString(head.SSEKMSKeyId) != "" && aws.ToBool(head.BucketKeyEnabled) && head.Metadata["schema"] == workerObjectSchemaV1 &&
		head.Metadata["sha256"] == hexDigest
}

func splitS3Object(reference string) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(reference))
	if err != nil || parsed.Scheme != "s3" || parsed.Host == "" || parsed.Path == "" || strings.HasSuffix(parsed.Path, "/") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", errors.New("scoped S3 object reference is invalid")
	}
	return parsed.Host, strings.TrimPrefix(parsed.Path, "/"), nil
}
