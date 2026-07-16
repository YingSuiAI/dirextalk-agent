package workerrunner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3API interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
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
		return nil, fmt.Errorf("get scoped S3 object: %w", err)
	}
	defer output.Body.Close()
	content, err := io.ReadAll(io.LimitReader(output.Body, maxBundleBytes+1))
	if err != nil {
		wipe(content)
		return nil, fmt.Errorf("read scoped S3 object: %w", err)
	}
	if len(content) > maxBundleBytes {
		wipe(content)
		return nil, ErrInvalidBundle
	}
	return content, nil
}

func (store *S3ObjectStore) Put(ctx context.Context, reference, contentType string, content []byte) error {
	bucket, key, err := splitS3Object(reference)
	if err != nil {
		return err
	}
	if len(content) == 0 || len(content) > maxBundleBytes || contentType != "application/json" {
		return errors.New("Worker output object is invalid")
	}
	_, err = store.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key), ContentType: aws.String(contentType), Body: bytes.NewReader(content),
	})
	if err != nil {
		return fmt.Errorf("put scoped S3 object: %w", err)
	}
	return nil
}

func splitS3Object(reference string) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(reference))
	if err != nil || parsed.Scheme != "s3" || parsed.Host == "" || parsed.Path == "" || strings.HasSuffix(parsed.Path, "/") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", errors.New("scoped S3 object reference is invalid")
	}
	return parsed.Host, strings.TrimPrefix(parsed.Path, "/"), nil
}
