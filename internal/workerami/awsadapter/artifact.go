package awsadapter

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func (adapter *Adapter) FindArtifact(ctx context.Context, object workerami.ArtifactObjectV1) (workerami.ArtifactVersionV1, bool, error) {
	if !validObject(object) {
		return workerami.ArtifactVersionV1{}, false, workerami.ErrInvalidInput
	}
	var keyMarker, versionMarker *string
	matches := make([]string, 0, 1)
	for {
		output, err := adapter.s3.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: aws.String(object.Bucket), Prefix: aws.String(object.Key), KeyMarker: keyMarker, VersionIdMarker: versionMarker,
		})
		if err != nil {
			return workerami.ArtifactVersionV1{}, false, providerError(ctx, err)
		}
		for _, version := range output.Versions {
			if stringValue(version.Key) != object.Key || stringValue(version.VersionId) == "" {
				continue
			}
			match, headErr := adapter.headArtifact(ctx, object, stringValue(version.VersionId))
			if headErr != nil {
				return workerami.ArtifactVersionV1{}, false, headErr
			}
			if !match {
				return workerami.ArtifactVersionV1{}, false, workerami.ErrReadBackMismatch
			}
			matches = append(matches, stringValue(version.VersionId))
			if len(matches) > 1 {
				return workerami.ArtifactVersionV1{}, false, workerami.ErrReadBackMismatch
			}
		}
		if !aws.ToBool(output.IsTruncated) {
			break
		}
		if stringValue(output.NextKeyMarker) == "" || stringValue(output.NextVersionIdMarker) == "" {
			return workerami.ArtifactVersionV1{}, false, workerami.ErrReadBackMismatch
		}
		keyMarker, versionMarker = output.NextKeyMarker, output.NextVersionIdMarker
	}
	if len(matches) == 0 {
		return workerami.ArtifactVersionV1{}, false, nil
	}
	return workerami.ArtifactVersionV1{VersionID: matches[0]}, true, nil
}

func (adapter *Adapter) PutArtifact(ctx context.Context, object workerami.ArtifactObjectV1, body io.Reader) (workerami.ArtifactVersionV1, error) {
	if !validObject(object) || body == nil {
		return workerami.ArtifactVersionV1{}, workerami.ErrInvalidInput
	}
	checksum := checksumBase64(object.Digest)
	output, err := adapter.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(object.Bucket), Key: aws.String(object.Key), Body: body, ContentLength: aws.Int64(object.Size),
		ChecksumAlgorithm: s3types.ChecksumAlgorithmSha256, ChecksumSHA256: aws.String(checksum),
		ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(object.KMSKeyARN),
		Metadata: artifactMetadata(object),
	})
	if err != nil {
		recovered, found, recoverErr := adapter.FindArtifact(ctx, object)
		if recoverErr == nil && found {
			return recovered, nil
		}
		if recoverErr != nil {
			return workerami.ArtifactVersionV1{}, recoverErr
		}
		return workerami.ArtifactVersionV1{}, providerError(ctx, err)
	}
	versionID := stringValue(output.VersionId)
	if versionID == "" {
		return workerami.ArtifactVersionV1{}, workerami.ErrReadBackMismatch
	}
	match, headErr := adapter.headArtifact(ctx, object, versionID)
	if headErr != nil {
		return workerami.ArtifactVersionV1{}, headErr
	}
	if !match {
		return workerami.ArtifactVersionV1{}, workerami.ErrReadBackMismatch
	}
	return workerami.ArtifactVersionV1{VersionID: versionID}, nil
}

func (adapter *Adapter) PresignArtifactGET(ctx context.Context, object workerami.ArtifactObjectV1, versionID string, ttl time.Duration) (string, error) {
	if !validObject(object) || strings.TrimSpace(versionID) == "" || ttl <= 0 || ttl > maxPresignTTL {
		return "", workerami.ErrInvalidInput
	}
	request, err := adapter.presign.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(object.Bucket), Key: aws.String(object.Key), VersionId: aws.String(versionID), ChecksumMode: s3types.ChecksumModeEnabled,
	}, func(options *s3.PresignOptions) { options.Expires = ttl })
	if err != nil {
		return "", providerError(ctx, err)
	}
	if request == nil || request.URL == "" {
		return "", workerami.ErrReadBackMismatch
	}
	parsed, parseErr := url.Parse(request.URL)
	if parseErr != nil || parsed.Query().Get("versionId") != versionID {
		return "", workerami.ErrReadBackMismatch
	}
	return request.URL, nil
}

func (adapter *Adapter) ObserveArtifactVersion(ctx context.Context, object workerami.ArtifactObjectV1, versionID string) (bool, error) {
	if !validObject(object) || strings.TrimSpace(versionID) == "" {
		return false, workerami.ErrInvalidInput
	}
	return adapter.headArtifact(ctx, object, versionID)
}

func (adapter *Adapter) DeleteArtifactVersion(ctx context.Context, object workerami.ArtifactObjectV1, versionID string) error {
	if !validObject(object) || strings.TrimSpace(versionID) == "" {
		return workerami.ErrInvalidInput
	}
	_, err := adapter.s3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(object.Bucket), Key: aws.String(object.Key), VersionId: aws.String(versionID)})
	return providerError(ctx, err)
}

func (adapter *Adapter) headArtifact(ctx context.Context, object workerami.ArtifactObjectV1, versionID string) (bool, error) {
	output, err := adapter.s3.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(object.Bucket), Key: aws.String(object.Key), VersionId: aws.String(versionID), ChecksumMode: s3types.ChecksumModeEnabled,
	})
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, providerError(ctx, err)
	}
	if output == nil || stringValue(output.VersionId) != versionID || output.ServerSideEncryption != s3types.ServerSideEncryptionAwsKms ||
		stringValue(output.SSEKMSKeyId) != object.KMSKeyARN || aws.ToInt64(output.ContentLength) != object.Size ||
		stringValue(output.ChecksumSHA256) != checksumBase64(object.Digest) || !equalMetadata(output.Metadata, artifactMetadata(object)) {
		return false, workerami.ErrReadBackMismatch
	}
	return true, nil
}

func validObject(object workerami.ArtifactObjectV1) bool {
	return object.Bucket != "" && object.Key != "" && object.KMSKeyARN != "" && digestPattern.MatchString(object.Digest) && object.Size > 0
}

func artifactMetadata(object workerami.ArtifactObjectV1) map[string]string {
	return map[string]string{"schema": ArtifactMetadataSchemaV1, "digest": object.Digest, "size": strconv.FormatInt(object.Size, 10)}
}

func equalMetadata(actual, expected map[string]string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func checksumBase64(digest string) string {
	raw, _ := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	return base64.StdEncoding.EncodeToString(raw)
}
