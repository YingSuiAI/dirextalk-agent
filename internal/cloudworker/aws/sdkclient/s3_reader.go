package sdkclient

import (
	"context"
	"errors"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type S3API interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// S3ObjectReader is bound to one immutable execution and one exact artifact
// prefix. Construction is offline; each ReadObject performs a fresh STS
// account proof and always sends a non-empty VersionId.
type S3ObjectReader struct {
	config   Config
	identity cloudaws.ExecutionIdentity
	scope    cloudresult.Scope
	sts      STSAPI
	s3       S3API
}

func NewS3ObjectReader(sdkConfig awssdk.Config, config Config, identity cloudaws.ExecutionIdentity, scope cloudresult.Scope) (*S3ObjectReader, error) {
	if config.Validate() != nil || identity.Validate() != nil || scope.Validate() != nil || sdkConfig.Region != config.Region || sdkConfig.Credentials == nil {
		return nil, cloudresult.ErrInvalid
	}
	sdkConfig = withoutSDKRetries(sdkConfig)
	return newS3ObjectReader(config, identity, scope, sts.NewFromConfig(sdkConfig), s3.NewFromConfig(sdkConfig))
}

func newS3ObjectReader(config Config, identity cloudaws.ExecutionIdentity, scope cloudresult.Scope, stsClient STSAPI, s3Client S3API) (*S3ObjectReader, error) {
	if config.Validate() != nil || identity.Validate() != nil || !identityMatchesConfig(identity, config) || scope.Validate() != nil || stsClient == nil || s3Client == nil {
		return nil, cloudresult.ErrInvalid
	}
	return &S3ObjectReader{config: config, identity: identity, scope: scope, sts: stsClient, s3: s3Client}, nil
}

func (reader *S3ObjectReader) Readiness(ctx context.Context) error {
	return reader.verifyIdentity(ctx)
}

func (reader *S3ObjectReader) ReadObject(ctx context.Context, request cloudresult.ObjectRequest) (cloudresult.ObjectRead, error) {
	if reader == nil || ctx == nil || !reader.validRequest(request) {
		return cloudresult.ObjectRead{}, cloudresult.ErrInvalid
	}
	if err := reader.verifyIdentity(ctx); err != nil {
		return cloudresult.ObjectRead{}, err
	}
	output, err := reader.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: awssdk.String(request.Bucket), Key: awssdk.String(request.Key), VersionId: awssdk.String(request.VersionID),
		ExpectedBucketOwner: awssdk.String(reader.config.AccountID),
	})
	if err != nil || output == nil || output.Body == nil {
		return cloudresult.ObjectRead{}, errors.Join(cloudresult.ErrUnavailable, err)
	}
	size := awssdk.ToInt64(output.ContentLength)
	versionID := awssdk.ToString(output.VersionId)
	mediaType := awssdk.ToString(output.ContentType)
	if versionID != request.VersionID || size < 1 || size > request.MaximumBytes || size > cloudresult.MaxObjectBytes || mediaType == "" ||
		awssdk.ToBool(output.DeleteMarker) {
		_ = output.Body.Close()
		return cloudresult.ObjectRead{}, cloudresult.ErrInvalid
	}
	return cloudresult.ObjectRead{
		Bucket: request.Bucket, Key: request.Key, VersionID: versionID, SizeBytes: size, MediaType: mediaType,
		Body: &limitedReadCloser{Reader: io.LimitReader(output.Body, request.MaximumBytes+1), closer: output.Body},
	}, nil
}

func (reader *S3ObjectReader) validRequest(request cloudresult.ObjectRequest) bool {
	if reader == nil || request.Bucket != reader.scope.Bucket || request.MaximumBytes < 1 || request.MaximumBytes > cloudresult.MaxObjectBytes ||
		request.Key == "" || !strings.HasPrefix(request.Key, reader.scope.KeyPrefix) || !validS3VersionID(request.VersionID) {
		return false
	}
	relative := strings.TrimPrefix(request.Key, reader.scope.KeyPrefix)
	return relative != "" && !strings.Contains(relative, "..") && !strings.HasPrefix(request.Key, "/") && !strings.ContainsAny(request.Key, "\\\r\n\x00")
}

func (reader *S3ObjectReader) verifyIdentity(ctx context.Context) error {
	if reader == nil || ctx == nil || !identityMatchesConfig(reader.identity, reader.config) {
		return cloudaws.ErrIdentityMismatch
	}
	output, err := reader.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || output == nil || awssdk.ToString(output.Account) != reader.config.AccountID {
		return errors.Join(cloudaws.ErrIdentityMismatch, err)
	}
	return nil
}

func identityMatchesConfig(identity cloudaws.ExecutionIdentity, config Config) bool {
	return identity.AccountID == config.AccountID && identity.AccountGeneration == config.AccountGeneration && identity.Region == config.Region && identity.ProviderID == config.ProviderID
}

func validS3VersionID(value string) bool {
	if value == "" || value == "null" || len(value) > 1024 || value != strings.TrimSpace(value) || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

type limitedReadCloser struct {
	io.Reader
	closer io.Closer
}

func (reader *limitedReadCloser) Close() error { return reader.closer.Close() }

var _ cloudresult.ObjectReader = (*S3ObjectReader)(nil)
