package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamartifact"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestAWSTeamArtifactContentReaderVerifiesRetainedObject(t *testing.T) {
	t.Parallel()
	content := []byte("verified report")
	digest := sha256.Sum256(content)
	now := time.Date(2026, 8, 9, 1, 2, 3, 0, time.UTC)
	artifact, err := teamartifact.NewVerified(teamartifact.BuildRequest{
		AgentInstanceID:  "11111111-1111-4111-8111-111111111111",
		OwnerID:          "owner-1",
		ExecutionID:      "22222222-2222-4222-8222-222222222222",
		OperationID:      "33333333-3333-4333-8333-333333333333",
		TaskID:           "44444444-4444-4444-8444-444444444444",
		PlanID:           "55555555-5555-4555-8555-555555555555",
		PlanRevision:     1,
		ConnectionID:     "66666666-6666-4666-8666-666666666666",
		RoleID:           "researcher",
		ActionID:         "deliver",
		DeploymentID:     "77777777-7777-4777-8777-777777777777",
		Name:             "report.md",
		MediaType:        "text/plain; charset=utf-8",
		SizeBytes:        int64(len(content)),
		SHA256:           "sha256:" + hex.EncodeToString(digest[:]),
		ObjectRef:        "s3://artifact-bucket/workers/principal/77777777-7777-4777-8777-777777777777/artifacts/report.txt",
		CreatedAt:        now,
		RetentionExpires: now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := newAWSTeamArtifactContentReader(
		teamArtifactConnectionLoaderFake{},
		teamArtifactConfigProviderFake{},
	)
	if err != nil {
		t.Fatal(err)
	}
	reader.newClient = func(aws.Config) teamResultS3API {
		return &teamArtifactS3Fake{content: content, mediaType: artifact.MediaType}
	}

	read, err := reader.ReadTeamArtifactContent(
		context.Background(),
		artifact,
		artifact.SizeBytes,
	)
	if err != nil || !bytes.Equal(read, content) {
		t.Fatalf("content=%q error=%v", read, err)
	}
}

type teamArtifactConnectionLoaderFake struct{}

func (teamArtifactConnectionLoaderFake) LoadConnection(
	context.Context,
	string,
	string,
) (cloudapp.Connection, error) {
	return cloudapp.Connection{}, nil
}

type teamArtifactConfigProviderFake struct{}

func (teamArtifactConfigProviderFake) controlConfig(
	context.Context,
	cloudapp.Connection,
) (aws.Config, awsprovider.BootstrapIdentitySpec, error) {
	return aws.Config{}, awsprovider.BootstrapIdentitySpec{
		ArtifactBucketName: "artifact-bucket",
	}, nil
}

type teamArtifactS3Fake struct {
	content   []byte
	mediaType string
}

func (fake *teamArtifactS3Fake) GetObject(
	context.Context,
	*s3.GetObjectInput,
	...func(*s3.Options),
) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(fake.content)),
		ContentLength: aws.Int64(int64(len(fake.content))),
		ContentType:   aws.String(fake.mediaType),
	}, nil
}
