package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

type S3HTTPInputReader struct{ transport *S3HTTPWriter }

func NewS3HTTPInputReader(
	credentials aws.CredentialsProvider,
	identity IdentitySource,
	proxy *OutboundProxy,
) (*S3HTTPInputReader, error) {
	if credentials == nil || identity == nil || proxy == nil {
		return nil, ErrInvalid
	}
	httpTransport, err := proxy.HTTPTransport()
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout:       30 * time.Second,
		Transport:     httpTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrUnavailable },
	}
	transport, err := newS3HTTPWriter(
		credentials, identity, v4.NewSigner(), client,
		func() time.Time { return time.Now().UTC() }, "",
	)
	if err != nil {
		return nil, err
	}
	return &S3HTTPInputReader{transport: transport}, nil
}

func newS3HTTPInputReader(
	credentials aws.CredentialsProvider,
	identity IdentitySource,
	signer HTTPSigner,
	doer httpDoer,
	now func() time.Time,
) (*S3HTTPInputReader, error) {
	transport, err := newS3HTTPWriter(credentials, identity, signer, doer, now, "")
	if err != nil {
		return nil, err
	}
	return &S3HTTPInputReader{transport: transport}, nil
}

func (reader *S3HTTPInputReader) ReadExact(
	ctx context.Context,
	binding Binding,
	request InputObjectRequest,
) (InputObjectRead, error) {
	if reader == nil || reader.transport == nil || ctx == nil || binding.Validate() != nil {
		return InputObjectRead{}, ErrInvalid
	}
	if !validInputBucket(request.Bucket) || strings.Contains(request.Bucket, ".") ||
		!validInputKey(request.Key) || !validInputVersion(request.VersionID) ||
		request.SizeBytes < 1 || request.SizeBytes > MaxInputObjectBytes ||
		!validInputText(request.MediaType, 255) {
		return InputObjectRead{}, ErrInvalid
	}
	if err := reader.transport.revalidate(ctx, binding); err != nil {
		return InputObjectRead{}, err
	}
	endpoint, err := s3ObjectURL(
		binding.Region, request.Bucket, request.Key, request.VersionID,
	)
	if err != nil {
		return InputObjectRead{}, err
	}
	emptyDigest := sha256.Sum256(nil)
	digestText := hex.EncodeToString(emptyDigest[:])
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return InputObjectRead{}, ErrInvalid
	}
	httpRequest.Header.Set("X-Amz-Content-Sha256", digestText)
	if err := reader.transport.sign(ctx, httpRequest, digestText, binding.Region); err != nil {
		return InputObjectRead{}, err
	}
	response, err := reader.transport.http.Do(httpRequest)
	httpRequest.Header.Del("Authorization")
	httpRequest.Header.Del("X-Amz-Security-Token")
	if err != nil || response == nil || response.Body == nil {
		return InputObjectRead{}, ErrUnavailable
	}
	contentLength := response.ContentLength
	if contentLength < 0 {
		contentLength, _ = strconv.ParseInt(response.Header.Get("Content-Length"), 10, 64)
	}
	if response.StatusCode != http.StatusOK ||
		strings.TrimSpace(response.Header.Get("X-Amz-Version-Id")) != request.VersionID ||
		contentLength != request.SizeBytes || response.Header.Get("Content-Type") != request.MediaType {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		_ = response.Body.Close()
		return InputObjectRead{}, ErrInvalid
	}
	return InputObjectRead{
		Bucket: request.Bucket, Key: request.Key, VersionID: request.VersionID,
		SizeBytes: contentLength, MediaType: response.Header.Get("Content-Type"),
		Body: response.Body,
	}, nil
}

var _ ExactInputObjectReader = (*S3HTTPInputReader)(nil)
