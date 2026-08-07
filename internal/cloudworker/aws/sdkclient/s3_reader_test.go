package sdkclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestS3ObjectReaderAlwaysUsesExactVersionAndFreshIdentity(t *testing.T) {
	request := testCreateRequest(t)
	events := []string{}
	stsClient := &recordingSTS{account: request.Identity.AccountID, events: &events}
	body := &trackedBody{Reader: bytes.NewReader([]byte("hello"))}
	s3Client := &recordingS3{events: &events, output: &s3.GetObjectOutput{Body: body, ContentLength: awssdk.Int64(5),
		ContentType: awssdk.String("application/json"), VersionId: awssdk.String("version-7")}}
	reader, err := newS3ObjectReader(testSDKConfig(request.Identity), request.Identity,
		cloudresult.Scope{Bucket: "dirextalk-output", KeyPrefix: "executions/11111111/"}, stsClient, s3Client)
	if err != nil {
		t.Fatal(err)
	}
	read, err := reader.ReadObject(context.Background(), cloudresult.ObjectRequest{Bucket: "dirextalk-output", Key: "executions/11111111/final.json", VersionID: "version-7", MaximumBytes: 5})
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(read.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = read.Body.Close()
	if string(content) != "hello" || read.Bucket != "dirextalk-output" || read.Key != "executions/11111111/final.json" ||
		read.VersionID != "version-7" || read.SizeBytes != 5 || read.MediaType != "application/json" {
		t.Fatalf("unexpected exact-version read: %+v content=%q", read, content)
	}
	if s3Client.input == nil || awssdk.ToString(s3Client.input.VersionId) != "version-7" || awssdk.ToString(s3Client.input.ExpectedBucketOwner) != request.Identity.AccountID {
		t.Fatalf("S3 request was not version/owner pinned: %+v", s3Client.input)
	}
	if len(events) != 2 || events[0] != "sts" || events[1] != "s3.get" {
		t.Fatalf("GetObject was not immediately preceded by STS: %v", events)
	}
	if !body.closed {
		t.Fatal("S3 response body was not closed")
	}
}

func TestS3ObjectReaderRejectsLatestForeignAndOversizedResponses(t *testing.T) {
	request := testCreateRequest(t)
	scope := cloudresult.Scope{Bucket: "dirextalk-output", KeyPrefix: "executions/11111111/"}
	baseRequest := cloudresult.ObjectRequest{Bucket: scope.Bucket, Key: scope.KeyPrefix + "final.json", VersionID: "version-7", MaximumBytes: 5}

	t.Run("latest version", func(t *testing.T) {
		s3Client := &recordingS3{}
		reader, _ := newS3ObjectReader(testSDKConfig(request.Identity), request.Identity, scope,
			&recordingSTS{account: request.Identity.AccountID}, s3Client)
		invalid := baseRequest
		invalid.VersionID = ""
		if _, err := reader.ReadObject(context.Background(), invalid); !errors.Is(err, cloudresult.ErrInvalid) || s3Client.calls != 0 {
			t.Fatalf("latest read was attempted: calls=%d err=%v", s3Client.calls, err)
		}
	})

	t.Run("foreign caller account", func(t *testing.T) {
		s3Client := &recordingS3{}
		reader, _ := newS3ObjectReader(testSDKConfig(request.Identity), request.Identity, scope,
			&recordingSTS{account: "999999999999"}, s3Client)
		if _, err := reader.ReadObject(context.Background(), baseRequest); !errors.Is(err, cloudaws.ErrIdentityMismatch) || s3Client.calls != 0 {
			t.Fatalf("foreign account crossed S3 boundary: calls=%d err=%v", s3Client.calls, err)
		}
	})

	t.Run("version drift closes body", func(t *testing.T) {
		body := &trackedBody{Reader: bytes.NewReader([]byte("hello"))}
		s3Client := &recordingS3{output: &s3.GetObjectOutput{Body: body, ContentLength: awssdk.Int64(5),
			ContentType: awssdk.String("application/json"), VersionId: awssdk.String("replacement")}}
		reader, _ := newS3ObjectReader(testSDKConfig(request.Identity), request.Identity, scope,
			&recordingSTS{account: request.Identity.AccountID}, s3Client)
		if _, err := reader.ReadObject(context.Background(), baseRequest); !errors.Is(err, cloudresult.ErrInvalid) || !body.closed {
			t.Fatalf("version drift was accepted or leaked body: closed=%v err=%v", body.closed, err)
		}
	})

	t.Run("body is bounded", func(t *testing.T) {
		body := &trackedBody{Reader: bytes.NewReader(bytes.Repeat([]byte("x"), 100))}
		s3Client := &recordingS3{output: &s3.GetObjectOutput{Body: body, ContentLength: awssdk.Int64(5),
			ContentType: awssdk.String("application/json"), VersionId: awssdk.String("version-7")}}
		reader, _ := newS3ObjectReader(testSDKConfig(request.Identity), request.Identity, scope,
			&recordingSTS{account: request.Identity.AccountID}, s3Client)
		read, err := reader.ReadObject(context.Background(), baseRequest)
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(read.Body)
		_ = read.Body.Close()
		if err != nil || len(content) != int(baseRequest.MaximumBytes+1) {
			t.Fatalf("body limit = %d bytes err=%v", len(content), err)
		}
	})
}

func testSDKConfig(identity cloudaws.ExecutionIdentity) Config {
	return Config{AccountID: identity.AccountID, AccountGeneration: identity.AccountGeneration, Region: identity.Region, ProviderID: identity.ProviderID}
}

type recordingSTS struct {
	account string
	err     error
	events  *[]string
}

func (client *recordingSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if client.events != nil {
		*client.events = append(*client.events, "sts")
	}
	if client.err != nil {
		return nil, client.err
	}
	return &sts.GetCallerIdentityOutput{Account: awssdk.String(client.account)}, nil
}

type recordingS3 struct {
	output *s3.GetObjectOutput
	err    error
	input  *s3.GetObjectInput
	calls  int
	events *[]string
}

func (client *recordingS3) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	client.calls++
	client.input = input
	if client.events != nil {
		*client.events = append(*client.events, "s3.get")
	}
	return client.output, client.err
}

type trackedBody struct {
	io.Reader
	closed bool
}

func (body *trackedBody) Close() error {
	body.closed = true
	return nil
}
