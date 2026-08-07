package sdkclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestS3ArtifactObjectReaderRequiresExactVersionKMSAndMetadata(t *testing.T) {
	identity := artifactRetentionSDKFixture()
	content := bytes.Repeat([]byte("x"), int(identity.Claim.SizeBytes))
	events := []string{}
	body := &trackedBody{Reader: bytes.NewReader(content)}
	s3Client := &recordingS3{events: &events, output: artifactGetOutput(identity, body)}
	config := Config{AccountID: identity.AccountID, AccountGeneration: identity.AccountGeneration, Region: identity.Region, ProviderID: identity.ProviderID}
	reader, err := newS3ArtifactObjectReader(config, identity, &recordingSTS{account: identity.AccountID, events: &events}, s3Client)
	if err != nil {
		t.Fatal(err)
	}
	read, err := reader.ReadObject(context.Background(), cloudresult.ObjectRequest{
		Bucket: identity.Claim.Bucket, Key: identity.Claim.Key, VersionID: identity.Claim.VersionID,
		MaximumBytes: identity.Claim.SizeBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(read.Body)
	_ = read.Body.Close()
	if err != nil || !bytes.Equal(actual, content) || !body.closed {
		t.Fatalf("content=%d closed=%t err=%v", len(actual), body.closed, err)
	}
	if len(events) != 2 || events[0] != "sts" || events[1] != "s3.get" ||
		s3Client.input == nil || awssdk.ToString(s3Client.input.Bucket) != identity.Claim.Bucket ||
		awssdk.ToString(s3Client.input.Key) != identity.Claim.Key ||
		awssdk.ToString(s3Client.input.VersionId) != identity.Claim.VersionID ||
		awssdk.ToString(s3Client.input.ExpectedBucketOwner) != identity.AccountID {
		t.Fatalf("events=%v input=%+v", events, s3Client.input)
	}
}

func TestS3ArtifactObjectReaderRejectsIdentityOrEncryptionDrift(t *testing.T) {
	identity := artifactRetentionSDKFixture()
	config := Config{AccountID: identity.AccountID, AccountGeneration: identity.AccountGeneration, Region: identity.Region, ProviderID: identity.ProviderID}
	request := cloudresult.ObjectRequest{Bucket: identity.Claim.Bucket, Key: identity.Claim.Key, VersionID: identity.Claim.VersionID, MaximumBytes: identity.Claim.SizeBytes}

	tests := []struct {
		name   string
		mutate func(*s3.GetObjectOutput)
	}{
		{"digest metadata", func(output *s3.GetObjectOutput) { output.Metadata[artifactDigestMetadataKey] = "foreign" }},
		{"kms key", func(output *s3.GetObjectOutput) {
			output.SSEKMSKeyId = awssdk.String("arn:aws:kms:us-east-1:123456789012:key/replacement")
		}},
		{"bucket key", func(output *s3.GetObjectOutput) { output.BucketKeyEnabled = awssdk.Bool(true) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := &trackedBody{Reader: bytes.NewReader(bytes.Repeat([]byte("x"), int(identity.Claim.SizeBytes)))}
			output := artifactGetOutput(identity, body)
			test.mutate(output)
			reader, _ := newS3ArtifactObjectReader(config, identity, &recordingSTS{account: identity.AccountID}, &recordingS3{output: output})
			if _, err := reader.ReadObject(context.Background(), request); !errors.Is(err, cloudworker.ErrStaleAuthorization) || !body.closed {
				t.Fatalf("err=%v closed=%t", err, body.closed)
			}
		})
	}
}

func artifactGetOutput(identity cloudworker.ArtifactRetentionIdentity, body io.ReadCloser) *s3.GetObjectOutput {
	return &s3.GetObjectOutput{
		Body: body, VersionId: awssdk.String(identity.Claim.VersionID),
		ContentLength: awssdk.Int64(identity.Claim.SizeBytes), ContentType: awssdk.String(identity.Claim.MediaType),
		Metadata:             map[string]string{artifactDigestMetadataKey: identity.Claim.SHA256},
		ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: awssdk.String(identity.KMSKeyARN),
	}
}
