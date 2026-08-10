package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	s3DigestMetadataHeader = "X-Amz-Meta-Dirextalk-Sha256"
	s3SSEHeader            = "X-Amz-Server-Side-Encryption"
	s3SSEKMSKeyIDHeader    = "X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id"
	s3SSEBucketKeyHeader   = "X-Amz-Server-Side-Encryption-Bucket-Key-Enabled"
	s3SSEKMSAlgorithm      = "aws:kms"
	s3SSEBucketKeyDisabled = "false"
)

type S3HTTPWriter struct {
	credentials       aws.CredentialsProvider
	identity          IdentitySource
	signer            HTTPSigner
	http              httpDoer
	now               func() time.Time
	artifactKMSKeyARN string
}

func NewS3HTTPWriter(
	credentials aws.CredentialsProvider,
	identity IdentitySource,
	proxy *OutboundProxy,
	artifactKMSKeyARN string,
) (*S3HTTPWriter, error) {
	if credentials == nil || identity == nil || proxy == nil ||
		!kmsKeyARNPattern.MatchString(artifactKMSKeyARN) {
		return nil, ErrInvalid
	}
	transport, err := proxy.HTTPTransport()
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout:       30 * time.Second,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrUploadUncertain },
	}
	return newS3HTTPWriter(credentials, identity, v4.NewSigner(), client, func() time.Time {
		return time.Now().UTC()
	}, artifactKMSKeyARN)
}

func newS3HTTPWriter(
	credentials aws.CredentialsProvider,
	identity IdentitySource,
	signer HTTPSigner,
	doer httpDoer,
	now func() time.Time,
	artifactKMSKeyARN string,
) (*S3HTTPWriter, error) {
	if credentials == nil || identity == nil || signer == nil || doer == nil || now == nil ||
		(artifactKMSKeyARN != "" && !kmsKeyARNPattern.MatchString(artifactKMSKeyARN)) {
		return nil, ErrInvalid
	}
	return &S3HTTPWriter{
		credentials: credentials, identity: identity,
		signer: signer, http: doer, now: now,
		artifactKMSKeyARN: artifactKMSKeyARN,
	}, nil
}

func (writer *S3HTTPWriter) Put(
	ctx context.Context,
	binding Binding,
	scope cloudresult.Scope,
	spec PutObject,
) (cloudresult.ObjectClaim, error) {
	probe := cloudresult.ObjectClaim{
		Name: spec.Name, Bucket: spec.Bucket, Key: spec.Key, VersionID: "version-probe",
		SHA256: spec.SHA256, SizeBytes: spec.SizeBytes, MediaType: spec.MediaType,
	}
	if writer == nil || ctx == nil || binding.Validate() != nil ||
		scope.Validate() != nil || probe.Validate() != nil || !scope.Contains(probe) ||
		int64(len(spec.Content)) != spec.SizeBytes ||
		strings.Contains(spec.Bucket, ".") ||
		!validArtifactKMSKeyARN(writer.artifactKMSKeyARN, binding.Region, binding.AccountID) {
		return cloudresult.ObjectClaim{}, ErrInvalid
	}
	digest := sha256.Sum256(spec.Content)
	if hex.EncodeToString(digest[:]) != spec.SHA256 {
		return cloudresult.ObjectClaim{}, ErrInvalid
	}
	endpoint, err := s3ObjectURL(binding.Region, spec.Bucket, spec.Key, "")
	if err != nil {
		return cloudresult.ObjectClaim{}, err
	}
	if err := writer.revalidate(ctx, binding); err != nil {
		return cloudresult.ObjectClaim{}, err
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPut, endpoint, bytes.NewReader(spec.Content),
	)
	if err != nil {
		return cloudresult.ObjectClaim{}, ErrInvalid
	}
	request.ContentLength = spec.SizeBytes
	request.Header.Set("Content-Type", spec.MediaType)
	request.Header.Set("X-Amz-Content-Sha256", spec.SHA256)
	request.Header.Set(s3DigestMetadataHeader, spec.SHA256)
	request.Header.Set(s3SSEHeader, s3SSEKMSAlgorithm)
	request.Header.Set(s3SSEKMSKeyIDHeader, writer.artifactKMSKeyARN)
	request.Header.Set(s3SSEBucketKeyHeader, s3SSEBucketKeyDisabled)
	if err := writer.sign(ctx, request, spec.SHA256, binding.Region); err != nil {
		return cloudresult.ObjectClaim{}, err
	}
	response, err := writer.http.Do(request)
	request.Header.Del("Authorization")
	request.Header.Del("X-Amz-Security-Token")
	if err != nil || response == nil || response.Body == nil {
		logS3Failure("put", "transport", 0)
		return cloudresult.ObjectClaim{}, ErrUploadUncertain
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	closeErr := response.Body.Close()
	versionID := strings.TrimSpace(response.Header.Get("X-Amz-Version-Id"))
	if closeErr != nil {
		logS3Failure("put", "response_body", response.StatusCode)
		return cloudresult.ObjectClaim{}, ErrUploadUncertain
	}
	if response.StatusCode != http.StatusOK {
		logS3Failure("put", "response_status", response.StatusCode)
		return cloudresult.ObjectClaim{}, ErrUploadUncertain
	}
	if versionID == "" || versionID == "null" {
		logS3Failure("put", "version_missing", response.StatusCode)
		return cloudresult.ObjectClaim{}, ErrUploadUncertain
	}
	claim := cloudresult.ObjectClaim{
		Name: spec.Name, Bucket: spec.Bucket, Key: spec.Key, VersionID: versionID,
		SHA256: spec.SHA256, SizeBytes: spec.SizeBytes, MediaType: spec.MediaType,
	}
	if claim.Validate() != nil {
		return cloudresult.ObjectClaim{}, ErrUploadUncertain
	}
	if err := writer.verifyHead(ctx, binding, claim); err != nil {
		return cloudresult.ObjectClaim{}, err
	}
	return claim, nil
}

func (writer *S3HTTPWriter) verifyHead(
	ctx context.Context,
	binding Binding,
	claim cloudresult.ObjectClaim,
) error {
	if err := writer.revalidate(ctx, binding); err != nil {
		return err
	}
	endpoint, err := s3ObjectURL(binding.Region, claim.Bucket, claim.Key, claim.VersionID)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, nil)
	if err != nil {
		return ErrInvalid
	}
	emptyDigest := sha256.Sum256(nil)
	emptyDigestText := hex.EncodeToString(emptyDigest[:])
	request.Header.Set("X-Amz-Content-Sha256", emptyDigestText)
	if err := writer.sign(ctx, request, emptyDigestText, binding.Region); err != nil {
		return err
	}
	response, err := writer.http.Do(request)
	request.Header.Del("Authorization")
	request.Header.Del("X-Amz-Security-Token")
	if err != nil || response == nil || response.Body == nil {
		logS3Failure("head", "transport", 0)
		return ErrUploadUncertain
	}
	closeErr := response.Body.Close()
	contentLength := response.ContentLength
	if contentLength < 0 {
		contentLength, _ = strconv.ParseInt(response.Header.Get("Content-Length"), 10, 64)
	}
	if closeErr != nil {
		logS3Failure("head", "response_body", response.StatusCode)
		return ErrUploadUncertain
	}
	if response.StatusCode != http.StatusOK {
		logS3Failure("head", "response_status", response.StatusCode)
		return ErrUploadUncertain
	}
	if strings.TrimSpace(response.Header.Get("X-Amz-Version-Id")) != claim.VersionID ||
		contentLength != claim.SizeBytes || response.Header.Get("Content-Type") != claim.MediaType ||
		response.Header.Get(s3DigestMetadataHeader) != claim.SHA256 ||
		response.Header.Get(s3SSEHeader) != s3SSEKMSAlgorithm ||
		response.Header.Get(s3SSEKMSKeyIDHeader) != writer.artifactKMSKeyARN ||
		!bucketKeyDisabledResponse(response.Header) {
		logS3Failure("head", "metadata_mismatch", response.StatusCode)
		return ErrUploadUncertain
	}
	return nil
}

// S3 omits x-amz-server-side-encryption-bucket-key-enabled when the effective
// value is false. An explicit false is also accepted; true or any other value
// would violate the launch plan's exact encryption contract.
func bucketKeyDisabledResponse(header http.Header) bool {
	value := strings.TrimSpace(header.Get(s3SSEBucketKeyHeader))
	return value == "" || value == s3SSEBucketKeyDisabled
}

func logS3Failure(operation, phase string, statusCode int) {
	if statusCode > 0 {
		slog.Error("[cloud-worker.s3] outcome=failed", "operation", operation, "phase", phase, "http_status", statusCode)
		return
	}
	slog.Error("[cloud-worker.s3] outcome=failed", "operation", operation, "phase", phase)
}

func (writer *S3HTTPWriter) revalidate(ctx context.Context, binding Binding) error {
	identity, err := writer.identity.ReadIdentity(ctx)
	if err != nil {
		identity.Destroy()
		return ErrUnavailable
	}
	defer identity.Destroy()
	if identity.AccountID != binding.AccountID || identity.Region != binding.Region ||
		identity.InstanceID != binding.InstanceID || len(identity.Document) == 0 ||
		len(identity.PKCS7) == 0 {
		return ErrIdentityChanged
	}
	return nil
}

func (writer *S3HTTPWriter) sign(
	ctx context.Context,
	request *http.Request,
	payloadDigest string,
	region string,
) error {
	credentials, err := writer.credentials.Retrieve(ctx)
	now := writer.now().UTC()
	if err != nil || !credentials.CanExpire ||
		!credentials.Expires.After(now.Add(minimumProofLifetime)) ||
		!temporaryAccessKeyPattern.MatchString(credentials.AccessKeyID) ||
		credentials.SecretAccessKey == "" || credentials.SessionToken == "" {
		credentials = aws.Credentials{}
		return ErrIdentityChanged
	}
	err = writer.signer.SignHTTP(
		ctx, credentials, request, payloadDigest, "s3", region, now,
	)
	credentials = aws.Credentials{}
	if err != nil {
		return ErrUploadUncertain
	}
	return nil
}

func s3ObjectURL(region, bucket, key, versionID string) (string, error) {
	if !regionPattern.MatchString(region) || bucket == "" || key == "" ||
		strings.ContainsAny(bucket+key, "\r\n\x00") {
		return "", ErrInvalid
	}
	suffix := "amazonaws.com"
	if strings.HasPrefix(region, "cn-") {
		suffix = "amazonaws.com.cn"
	}
	value := &url.URL{
		Scheme: "https", Host: bucket + ".s3." + region + "." + suffix,
		Path: "/" + key,
	}
	if versionID != "" {
		query := url.Values{}
		query.Set("versionId", versionID)
		value.RawQuery = query.Encode()
	}
	return value.String(), nil
}
