package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type S3API interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

type S3ArtifactDownloader struct {
	client S3API
	retry  accessDeniedRetry
}

func NewS3ArtifactDownloader(client S3API) (*S3ArtifactDownloader, error) {
	return newS3ArtifactDownloaderWithRetry(client, defaultAccessDeniedRetry())
}

func newS3ArtifactDownloaderWithRetry(client S3API, retry accessDeniedRetry) (*S3ArtifactDownloader, error) {
	if client == nil || !retry.valid() {
		return nil, ErrInvalidInput
	}
	return &S3ArtifactDownloader{client: client, retry: retry}, nil
}

// Open uses an exact object version and asks S3 to return its stored checksum.
// The local materializer hashes the body again while writing, so both S3
// metadata tampering and a corrupted/interrupted response fail closed.
func (downloader *S3ArtifactDownloader) Open(ctx context.Context, source ArtifactSourceV1) (ArtifactDownload, error) {
	if downloader == nil || downloader.client == nil || ctx == nil || source.SchemaVersion != ArtifactSourceSchemaV1 ||
		!bucketPattern.MatchString(source.Bucket) || source.Key == "" || !versionPattern.MatchString(source.VersionID) || len(source.VersionID) > 1024 ||
		!digestPattern.MatchString(source.SHA256) || source.SizeBytes < 1 || source.TargetPath == "" || source.KMSKeyARN == "" {
		return ArtifactDownload{}, ErrArtifactSource
	}
	output, err := retryAccessDenied(ctx, downloader.retry, func() (*s3.GetObjectOutput, error) {
		return downloader.client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(source.Bucket), Key: aws.String(source.Key), VersionId: aws.String(source.VersionID),
			ChecksumMode: s3types.ChecksumModeEnabled,
		})
	})
	if err != nil || output == nil || output.Body == nil {
		return ArtifactDownload{}, ErrArtifactSource
	}
	expectedRaw, err := hex.DecodeString(strings.TrimPrefix(source.SHA256, "sha256:"))
	if err != nil || len(expectedRaw) != 32 || aws.ToInt64(output.ContentLength) != source.SizeBytes ||
		aws.ToString(output.VersionId) != source.VersionID || aws.ToString(output.ChecksumSHA256) != base64.StdEncoding.EncodeToString(expectedRaw) ||
		output.ServerSideEncryption != s3types.ServerSideEncryptionAwsKms || aws.ToString(output.SSEKMSKeyId) != source.KMSKeyARN || !aws.ToBool(output.BucketKeyEnabled) {
		clear(expectedRaw)
		_ = output.Body.Close()
		return ArtifactDownload{}, ErrArtifactSource
	}
	clear(expectedRaw)
	return ArtifactDownload{Body: &exactLengthReadCloser{reader: io.LimitReader(output.Body, source.SizeBytes+1), closer: output.Body}}, nil
}

type exactLengthReadCloser struct {
	reader io.Reader
	closer io.Closer
}

func (reader *exactLengthReadCloser) Read(buffer []byte) (int, error) {
	return reader.reader.Read(buffer)
}
func (reader *exactLengthReadCloser) Close() error { return reader.closer.Close() }
