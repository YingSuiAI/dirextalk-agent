package artifactorigin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	assets "github.com/YingSuiAI/dirextalk-agent/deploy/awsartifactorigin"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

type OriginS3API interface {
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	ListObjectVersions(context.Context, *s3.ListObjectVersionsInput, ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func PublishDefault(ctx context.Context, origin OriginReceipt, artifact Artifact, localPath string, now func() time.Time) (ArtifactReceipt, error) {
	configuration, err := loadPublisherConfig(ctx, origin)
	if err != nil {
		return ArtifactReceipt{}, err
	}
	client := &http.Client{
		Timeout:       15 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return Publish(ctx, origin, artifact, localPath, s3.NewFromConfig(configuration), client, now)
}

func VerifyPublishedDefault(ctx context.Context, origin OriginReceipt, artifact Artifact, localPath string, now func() time.Time) (ArtifactReceipt, error) {
	configuration, err := loadPublisherConfig(ctx, origin)
	if err != nil {
		return ArtifactReceipt{}, err
	}
	client := &http.Client{
		Timeout:       15 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return VerifyPublished(ctx, origin, artifact, localPath, s3.NewFromConfig(configuration), client, now)
}

func loadPublisherConfig(ctx context.Context, origin OriginReceipt) (aws.Config, error) {
	if ctx == nil || validateCurrentOrigin(origin) != nil {
		return aws.Config{}, ErrInvalid
	}
	configuration, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(StorageRegion))
	if err != nil {
		return aws.Config{}, ErrArtifactUnavailable
	}
	identity, err := sts.NewFromConfig(configuration).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || aws.ToString(identity.Account) != origin.AccountID {
		return aws.Config{}, ErrArtifactUnavailable
	}
	return configuration, nil
}

func Publish(
	ctx context.Context,
	origin OriginReceipt,
	artifact Artifact,
	localPath string,
	store OriginS3API,
	edge HTTPDoer,
	now func() time.Time,
) (ArtifactReceipt, error) {
	if ctx == nil {
		return ArtifactReceipt{}, ErrInvalid
	}
	file, digest, err := openVerifiedArtifact(origin, artifact, localPath, store, edge, now)
	if err != nil {
		return ArtifactReceipt{}, err
	}
	defer file.Close()
	key := artifact.ObjectKey()
	if exists, err := objectVersionExists(ctx, store, origin.BucketName, key); err != nil {
		return ArtifactReceipt{}, err
	} else if exists {
		return ArtifactReceipt{}, ErrImmutableConflict
	}
	_, err = store.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(origin.BucketName), Key: aws.String(key), ChecksumMode: s3types.ChecksumModeEnabled,
	})
	if err == nil {
		return ArtifactReceipt{}, ErrImmutableConflict
	}
	if !objectNotFound(err) {
		return ArtifactReceipt{}, ErrArtifactUnavailable
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return ArtifactReceipt{}, ErrArtifactUnavailable
	}
	metadata := artifactMetadata(artifact)
	_, err = store.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(origin.BucketName), Key: aws.String(key), Body: file, ContentLength: aws.Int64(artifact.SizeBytes),
		ContentType: aws.String(artifact.MediaType), CacheControl: aws.String(ImmutableCacheControl),
		ChecksumAlgorithm: s3types.ChecksumAlgorithmSha256, ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(digest[:])),
		ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(origin.KMSKeyARN), BucketKeyEnabled: aws.Bool(true),
		IfNoneMatch: aws.String("*"), Metadata: metadata,
	})
	if err != nil {
		if immutablePutConflict(err) {
			return ArtifactReceipt{}, ErrImmutableConflict
		}
		return ArtifactReceipt{}, ErrArtifactUnavailable
	}
	return verifyPublished(ctx, origin, artifact, digest, store, edge, now)
}

func objectVersionExists(ctx context.Context, store OriginS3API, bucket, key string) (bool, error) {
	output, err := store.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
		Bucket: aws.String(bucket), Prefix: aws.String(key), MaxKeys: aws.Int32(1000),
	})
	if err != nil || output == nil || aws.ToBool(output.IsTruncated) {
		return false, ErrArtifactUnavailable
	}
	for _, version := range output.Versions {
		if aws.ToString(version.Key) == key {
			return true, nil
		}
	}
	for _, marker := range output.DeleteMarkers {
		if aws.ToString(marker.Key) == key {
			return true, nil
		}
	}
	return false, nil
}

func VerifyPublished(
	ctx context.Context,
	origin OriginReceipt,
	artifact Artifact,
	localPath string,
	store OriginS3API,
	edge HTTPDoer,
	now func() time.Time,
) (ArtifactReceipt, error) {
	if ctx == nil {
		return ArtifactReceipt{}, ErrInvalid
	}
	file, digest, err := openVerifiedArtifact(origin, artifact, localPath, store, edge, now)
	if err != nil {
		return ArtifactReceipt{}, err
	}
	if err := file.Close(); err != nil {
		return ArtifactReceipt{}, ErrArtifactUnavailable
	}
	return verifyPublished(ctx, origin, artifact, digest, store, edge, now)
}

func openVerifiedArtifact(origin OriginReceipt, artifact Artifact, localPath string, store OriginS3API, edge HTTPDoer, now func() time.Time) (*os.File, [32]byte, error) {
	if validateCurrentOrigin(origin) != nil || artifact.Validate() != nil || strings.TrimSpace(localPath) == "" || store == nil || edge == nil || now == nil {
		return nil, [32]byte{}, ErrInvalid
	}
	before, err := os.Lstat(localPath)
	if err != nil || !before.Mode().IsRegular() || before.Size() != artifact.SizeBytes {
		return nil, [32]byte{}, ErrInvalid
	}
	file, err := os.Open(localPath)
	if err != nil {
		return nil, [32]byte{}, ErrInvalid
	}
	ok := false
	defer func() {
		if !ok {
			_ = file.Close()
		}
	}()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() != artifact.SizeBytes {
		return nil, [32]byte{}, ErrInvalid
	}
	hash := sha256.New()
	written, err := io.CopyBuffer(hash, file, make([]byte, 128<<10))
	if err != nil || written != artifact.SizeBytes {
		return nil, [32]byte{}, ErrInvalid
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	if hex.EncodeToString(digest[:]) != artifact.SHA256 {
		return nil, [32]byte{}, ErrInvalid
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, [32]byte{}, ErrInvalid
	}
	ok = true
	return file, digest, nil
}

func verifyPublished(ctx context.Context, origin OriginReceipt, artifact Artifact, digest [32]byte, store OriginS3API, edge HTTPDoer, now func() time.Time) (ArtifactReceipt, error) {
	key := artifact.ObjectKey()
	head, err := store.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(origin.BucketName), Key: aws.String(key), ChecksumMode: s3types.ChecksumModeEnabled,
	})
	if err != nil || head == nil || aws.ToInt64(head.ContentLength) != artifact.SizeBytes || aws.ToString(head.ContentType) != artifact.MediaType ||
		aws.ToString(head.CacheControl) != ImmutableCacheControl || head.ServerSideEncryption != s3types.ServerSideEncryptionAwsKms ||
		aws.ToString(head.SSEKMSKeyId) != origin.KMSKeyARN || !aws.ToBool(head.BucketKeyEnabled) || aws.ToString(head.VersionId) == "" ||
		aws.ToString(head.ChecksumSHA256) != base64.StdEncoding.EncodeToString(digest[:]) || !sameMap(head.Metadata, artifactMetadata(artifact)) {
		return ArtifactReceipt{}, ErrS3Verification
	}
	publicURL := "https://" + DomainName + "/" + key
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, publicURL, nil)
	if err != nil {
		return ArtifactReceipt{}, ErrInvalid
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := edge.Do(request)
	if err != nil || response == nil {
		return ArtifactReceipt{}, ErrEdgeVerification
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Location") != "" || response.ContentLength != artifact.SizeBytes ||
		response.Header.Get("Content-Length") != strconv.FormatInt(artifact.SizeBytes, 10) ||
		(response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity") ||
		response.Request == nil || response.Request.URL == nil || response.Request.URL.String() != publicURL ||
		response.Request.URL.RawQuery != "" || response.Request.URL.Fragment != "" {
		return ArtifactReceipt{}, ErrEdgeVerification
	}
	hash := sha256.New()
	written, err := io.CopyBuffer(hash, io.LimitReader(response.Body, artifact.SizeBytes+1), make([]byte, 128<<10))
	if err != nil || written != artifact.SizeBytes || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), artifact.SHA256) {
		return ArtifactReceipt{}, ErrEdgeVerification
	}
	verifiedAt := now().UTC()
	if verifiedAt.IsZero() {
		return ArtifactReceipt{}, ErrInvalid
	}
	return ArtifactReceipt{
		SchemaVersion: ArtifactReceiptSchemaV1, AccountID: origin.AccountID, Region: StorageRegion, Domain: DomainName,
		ArtifactID: artifact.ID, Name: artifact.Name, SHA256: artifact.SHA256, SizeBytes: artifact.SizeBytes,
		S3Bucket: origin.BucketName, S3Key: key, S3VersionID: aws.ToString(head.VersionId), URL: publicURL, VerifiedAt: verifiedAt,
	}, nil
}

func artifactMetadata(artifact Artifact) map[string]string {
	return map[string]string{
		"artifact-id": artifact.ID, "sha256": artifact.SHA256, "source-url": artifact.SourceURL,
		"source-revision": artifact.SourceRevision, "license": artifact.License,
	}
}

func validateCurrentOrigin(receipt OriginReceipt) error {
	if receipt.Validate() != nil || receipt.StorageTemplateSHA256 != templateDigest(assets.StorageTemplate()) ||
		receipt.EdgeTemplateSHA256 != templateDigest(assets.EdgeTemplate()) {
		return ErrInvalid
	}
	return nil
}

func objectNotFound(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "NotFound", "NoSuchKey", "404":
		return true
	default:
		return false
	}
}

func immutablePutConflict(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "PreconditionFailed", "ConditionalRequestConflict", "412":
		return true
	default:
		return false
	}
}
