package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestS3ArtifactDownloaderRequiresExactVersionChecksumAndKMSReadback(t *testing.T) {
	payload := []byte("digest-bound installer")
	digest := sha256.Sum256(payload)
	source := ArtifactSourceV1{
		SchemaVersion: ArtifactSourceSchemaV1, Name: "installer", Bucket: "dtx-artifacts",
		Key: "deployments/22222222-2222-4222-8222-222222222222/artifacts/installer", VersionID: "version-1",
		KMSKeyARN: "arn:aws:kms:ap-south-1:123456789012:key/11111111-2222-4333-8444-555555555555",
		SHA256: "sha256:" + hex.EncodeToString(digest[:]), SizeBytes: int64(len(payload)),
		TargetPath: "/usr/local/share/dirextalk-worker/artifacts/installer", RecipeDigest: "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
	}
	exact := &s3.GetObjectOutput{
		Body: io.NopCloser(bytes.NewReader(payload)), ContentLength: aws.Int64(int64(len(payload))), VersionId: aws.String(source.VersionID),
		ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(digest[:])), ServerSideEncryption: s3types.ServerSideEncryptionAwsKms,
		SSEKMSKeyId: aws.String(source.KMSKeyARN), BucketKeyEnabled: aws.Bool(true),
	}
	client := &artifactS3Fake{output: exact}
	downloader, err := NewS3ArtifactDownloader(client)
	if err != nil {
		t.Fatal(err)
	}
	download, err := downloader.Open(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(download.Body)
	closeErr := download.Body.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, payload) || client.input == nil ||
		aws.ToString(client.input.Bucket) != source.Bucket || aws.ToString(client.input.Key) != source.Key ||
		aws.ToString(client.input.VersionId) != source.VersionID || client.input.ChecksumMode != s3types.ChecksumModeEnabled {
		t.Fatalf("versioned S3 read = %q input=%+v read=%v close=%v", got, client.input, readErr, closeErr)
	}

	tests := []struct {
		name string
		edit func(*s3.GetObjectOutput)
	}{
		{name: "missing", edit: func(output *s3.GetObjectOutput) { output.Body = nil }},
		{name: "size", edit: func(output *s3.GetObjectOutput) { output.ContentLength = aws.Int64(int64(len(payload) + 1)) }},
		{name: "version", edit: func(output *s3.GetObjectOutput) { output.VersionId = aws.String("other") }},
		{name: "checksum", edit: func(output *s3.GetObjectOutput) { output.ChecksumSHA256 = aws.String(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32))) }},
		{name: "encryption", edit: func(output *s3.GetObjectOutput) { output.ServerSideEncryption = s3types.ServerSideEncryptionAes256 }},
		{name: "kms key", edit: func(output *s3.GetObjectOutput) { output.SSEKMSKeyId = aws.String(source.KMSKeyARN + "-other") }},
		{name: "bucket key", edit: func(output *s3.GetObjectOutput) { output.BucketKeyEnabled = aws.Bool(false) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := *exact
			output.Body = io.NopCloser(bytes.NewReader(payload))
			test.edit(&output)
			rejected, _ := NewS3ArtifactDownloader(&artifactS3Fake{output: &output})
			if _, err := rejected.Open(context.Background(), source); !errors.Is(err, ErrArtifactSource) {
				t.Fatalf("tampered S3 output error = %v", err)
			}
		})
	}
}

type artifactS3Fake struct {
	input  *s3.GetObjectInput
	output *s3.GetObjectOutput
	err    error
}

func (fake *artifactS3Fake) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	fake.input = input
	return fake.output, fake.err
}
