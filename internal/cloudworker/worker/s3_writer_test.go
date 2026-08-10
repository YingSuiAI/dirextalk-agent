package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

type staticS3Identity struct{ value InstanceIdentity }

func (identity staticS3Identity) ReadIdentity(context.Context) (InstanceIdentity, error) {
	return InstanceIdentity{
		AccountID: identity.value.AccountID, Region: identity.value.Region,
		InstanceID: identity.value.InstanceID,
		Document:   bytes.Clone(identity.value.Document), PKCS7: bytes.Clone(identity.value.PKCS7),
	}, nil
}

type staticS3Credentials struct{ value aws.Credentials }

func (credentials staticS3Credentials) Retrieve(context.Context) (aws.Credentials, error) {
	return credentials.value, nil
}

type recordingS3Signer struct{}

func (recordingS3Signer) SignHTTP(
	_ context.Context,
	_ aws.Credentials,
	request *http.Request,
	_ string,
	service string,
	region string,
	_ time.Time,
	_ ...func(*v4.SignerOptions),
) error {
	request.Header.Set("Authorization", "signed-"+service+"-"+region)
	return nil
}

type rewriteS3Transport struct {
	server *url.URL
	base   http.RoundTripper
}

type s3DoerFunc func(*http.Request) (*http.Response, error)

func (do s3DoerFunc) Do(request *http.Request) (*http.Response, error) {
	return do(request)
}

func (transport rewriteS3Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	endpoint := *request.URL
	originalHost := endpoint.Host
	endpoint.Scheme = transport.server.Scheme
	endpoint.Host = transport.server.Host
	clone.URL = &endpoint
	clone.Host = originalHost
	return transport.base.RoundTrip(clone)
}

func TestS3HTTPWriterPutsExactSSEKMSAndConsumesExactVersionHEAD(t *testing.T) {
	content := []byte(`{"status":"completed"}`)
	digest := sha256.Sum256(content)
	digestText := hex.EncodeToString(digest[:])
	kmsARN := "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"
	const (
		bucket    = "dirextalk-worker-artifacts"
		key       = "executions/11111111/result.json"
		versionID = "exact-version-1"
		mediaType = "application/json"
	)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Host != bucket+".s3.us-east-1.amazonaws.com" ||
			request.URL.Path != "/"+key ||
			request.Header.Get("Authorization") != "signed-s3-us-east-1" {
			t.Errorf("unexpected S3 request: method=%s host=%s url=%s headers=%v", request.Method, request.Host, request.URL, request.Header)
			response.WriteHeader(http.StatusForbidden)
			return
		}
		switch request.Method {
		case http.MethodPut:
			body, _ := io.ReadAll(request.Body)
			if request.URL.Query().Get("versionId") != "" || !bytes.Equal(body, content) ||
				request.Header.Get(s3SSEHeader) != s3SSEKMSAlgorithm ||
				request.Header.Get(s3SSEKMSKeyIDHeader) != kmsARN ||
				request.Header.Get(s3SSEBucketKeyHeader) != s3SSEBucketKeyDisabled ||
				request.Header.Get(s3DigestMetadataHeader) != digestText {
				t.Errorf("PUT escaped exact SSE-KMS contract: query=%v headers=%v body=%q", request.URL.Query(), request.Header, body)
				response.WriteHeader(http.StatusForbidden)
				return
			}
			response.Header().Set("X-Amz-Version-Id", versionID)
			response.WriteHeader(http.StatusOK)
		case http.MethodHead:
			if request.URL.Query().Get("versionId") != versionID {
				t.Errorf("HEAD did not pin exact version: %v", request.URL.Query())
				response.WriteHeader(http.StatusForbidden)
				return
			}
			response.Header().Set("X-Amz-Version-Id", versionID)
			response.Header().Set("Content-Length", strconv.Itoa(len(content)))
			response.Header().Set("Content-Type", mediaType)
			response.Header().Set(s3DigestMetadataHeader, digestText)
			response.Header().Set(s3SSEHeader, s3SSEKMSAlgorithm)
			response.Header().Set(s3SSEKMSKeyIDHeader, kmsARN)
			// Real S3 omits the bucket-key response header when its effective
			// value is false, even when PUT explicitly requested false.
			response.WriteHeader(http.StatusOK)
		default:
			response.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	binding := testS3Binding()
	writer, err := newS3HTTPWriter(
		staticS3Credentials{value: aws.Credentials{
			AccessKeyID: "ASIAABCDEFGHIJKLMNOP", SecretAccessKey: "secret",
			SessionToken: "session", CanExpire: true, Expires: now.Add(time.Hour),
		}},
		staticS3Identity{value: InstanceIdentity{
			AccountID: binding.AccountID, Region: binding.Region, InstanceID: binding.InstanceID,
			Document: []byte("document"), PKCS7: []byte("pkcs7"),
		}},
		recordingS3Signer{},
		&http.Client{Transport: rewriteS3Transport{server: serverURL, base: http.DefaultTransport}},
		func() time.Time { return now }, kmsARN,
	)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := writer.Put(
		t.Context(), binding,
		cloudresult.Scope{Bucket: bucket, KeyPrefix: "executions/11111111/"},
		PutObject{Name: "result.json", Bucket: bucket, Key: key, SHA256: digestText,
			SizeBytes: int64(len(content)), MediaType: mediaType, Content: content},
	)
	if err != nil {
		t.Fatal(err)
	}
	if claim.VersionID != versionID || requests.Load() != 2 {
		t.Fatalf("claim=%+v request count=%d", claim, requests.Load())
	}
}

func TestS3HTTPWriterRejectsKMSAccountOrRegionDriftBeforeHTTP(t *testing.T) {
	binding := testS3Binding()
	writer, err := newS3HTTPWriter(
		staticS3Credentials{}, staticS3Identity{}, recordingS3Signer{},
		http.DefaultClient, time.Now,
		"arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
	)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("x")
	digest := sha256.Sum256(content)
	_, err = writer.Put(
		t.Context(), binding,
		cloudresult.Scope{Bucket: "dirextalk-worker-artifacts", KeyPrefix: "executions/11111111/"},
		PutObject{Name: "result.json", Bucket: "dirextalk-worker-artifacts",
			Key: "executions/11111111/result.json", SHA256: hex.EncodeToString(digest[:]),
			SizeBytes: 1, MediaType: "application/json", Content: content},
	)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("KMS drift error = %v", err)
	}
}

func TestS3HTTPWriterRejectsHEADEncryptionDrift(t *testing.T) {
	binding := testS3Binding()
	kmsARN := "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"
	claim := cloudresult.ObjectClaim{
		Name: "result.json", Bucket: "dirextalk-worker-artifacts",
		Key: "executions/11111111/result.json", VersionID: "exact-version-1",
		SHA256: strings.Repeat("a", 64), SizeBytes: 1, MediaType: "application/json",
	}
	for name, mutate := range map[string]func(http.Header){
		"missing_sse": func(header http.Header) { header.Del(s3SSEHeader) },
		"wrong_kms": func(header http.Header) {
			header.Set(s3SSEKMSKeyIDHeader, strings.Replace(kmsARN, "11111111", "22222222", 1))
		},
		"bucket_key": func(header http.Header) { header.Set(s3SSEBucketKeyHeader, "true") },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC()
			doer := s3DoerFunc(func(*http.Request) (*http.Response, error) {
				header := make(http.Header)
				header.Set("X-Amz-Version-Id", claim.VersionID)
				header.Set("Content-Length", "1")
				header.Set("Content-Type", claim.MediaType)
				header.Set(s3DigestMetadataHeader, claim.SHA256)
				header.Set(s3SSEHeader, s3SSEKMSAlgorithm)
				header.Set(s3SSEKMSKeyIDHeader, kmsARN)
				header.Set(s3SSEBucketKeyHeader, s3SSEBucketKeyDisabled)
				mutate(header)
				return &http.Response{
					StatusCode: http.StatusOK, Header: header, Body: http.NoBody,
					ContentLength: claim.SizeBytes,
				}, nil
			})
			writer, err := newS3HTTPWriter(
				staticS3Credentials{value: aws.Credentials{
					AccessKeyID: "ASIAABCDEFGHIJKLMNOP", SecretAccessKey: "secret",
					SessionToken: "session", CanExpire: true, Expires: now.Add(time.Hour),
				}},
				staticS3Identity{value: InstanceIdentity{
					AccountID: binding.AccountID, Region: binding.Region, InstanceID: binding.InstanceID,
					Document: []byte("document"), PKCS7: []byte("pkcs7"),
				}},
				recordingS3Signer{}, doer, func() time.Time { return now }, kmsARN,
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.verifyHead(t.Context(), binding, claim); !errors.Is(err, ErrUploadUncertain) {
				t.Fatalf("HEAD drift error = %v", err)
			}
		})
	}
}

func TestBucketKeyDisabledResponseMatchesS3Semantics(t *testing.T) {
	for name, value := range map[string]string{
		"omitted":        "",
		"explicit_false": s3SSEBucketKeyDisabled,
	} {
		t.Run(name, func(t *testing.T) {
			header := make(http.Header)
			if value != "" {
				header.Set(s3SSEBucketKeyHeader, value)
			}
			if !bucketKeyDisabledResponse(header) {
				t.Fatalf("bucketKeyDisabledResponse(%q) = false", value)
			}
		})
	}
	for _, value := range []string{"true", "invalid"} {
		header := make(http.Header)
		header.Set(s3SSEBucketKeyHeader, value)
		if bucketKeyDisabledResponse(header) {
			t.Fatalf("bucketKeyDisabledResponse(%q) = true", value)
		}
	}
}

func testS3Binding() Binding {
	return Binding{BootstrapBinding: BootstrapBinding{
		OwnerID: "owner-1", AccountID: "123456789012", AccountGeneration: 1,
		Region: "us-east-1", InstanceID: "i-0123456789abcdef0",
		LaunchIdentity: strings.Repeat("1", 64),
		ExecutionID:    "11111111-1111-4111-8111-111111111111", ExecutionSHA256: strings.Repeat("2", 64),
		TaskID: "22222222-2222-4222-8222-222222222222", TaskSHA256: strings.Repeat("3", 64),
		InputManifestSHA256: strings.Repeat("4", 64), ModelBindingSHA256: strings.Repeat("5", 64),
	}, Attempt: 1, LeaseEpoch: 1}
}
