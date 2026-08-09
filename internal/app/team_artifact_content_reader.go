package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamartifact"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type teamArtifactConnectionLoader interface {
	LoadConnection(context.Context, string, string) (cloudapp.Connection, error)
}

type teamArtifactControlConfigProvider interface {
	controlConfig(
		context.Context,
		cloudapp.Connection,
	) (aws.Config, awsprovider.BootstrapIdentitySpec, error)
}

type awsTeamArtifactContentReader struct {
	connections teamArtifactConnectionLoader
	configs     teamArtifactControlConfigProvider
	newClient   func(aws.Config) teamResultS3API
}

func newAWSTeamArtifactContentReader(
	connections teamArtifactConnectionLoader,
	configs teamArtifactControlConfigProvider,
) (*awsTeamArtifactContentReader, error) {
	if connections == nil || configs == nil {
		return nil, cloudapp.ErrInvalid
	}
	return &awsTeamArtifactContentReader{
		connections: connections,
		configs:     configs,
		newClient: func(config aws.Config) teamResultS3API {
			return s3.NewFromConfig(config)
		},
	}, nil
}

func (reader *awsTeamArtifactContentReader) ReadTeamArtifactContent(
	ctx context.Context,
	artifact teamartifact.ArtifactV1,
	maximum int64,
) ([]byte, error) {
	if reader == nil || reader.connections == nil || reader.configs == nil ||
		reader.newClient == nil || ctx == nil || artifact.Validate() != nil ||
		maximum < 1 || maximum != artifact.SizeBytes ||
		maximum > teamartifact.MaximumArtifactBytes {
		return nil, cloudapp.ErrInvalid
	}
	connection, err := reader.connections.LoadConnection(
		ctx,
		artifact.OwnerID,
		artifact.ConnectionID,
	)
	if err != nil {
		return nil, cloudapp.ErrUnavailable
	}
	configuration, foundation, err := reader.configs.controlConfig(
		ctx,
		connection,
	)
	if err != nil {
		return nil, cloudapp.ErrUnavailable
	}
	bucket, key, err := splitTeamResultObject(artifact.ObjectRef)
	if err != nil || bucket != foundation.ArtifactBucketName ||
		!validRetainedTeamArtifactKey(key, artifact.DeploymentID) {
		return nil, cloudapp.ErrInvalid
	}
	output, err := reader.newClient(configuration).GetObject(
		ctx,
		&s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		},
	)
	if err != nil || output == nil || output.Body == nil {
		return nil, cloudapp.ErrUnavailable
	}
	defer output.Body.Close()
	if aws.ToInt64(output.ContentLength) != artifact.SizeBytes ||
		aws.ToString(output.ContentType) != artifact.MediaType {
		return nil, cloudapp.ErrInvalid
	}
	content, err := io.ReadAll(io.LimitReader(output.Body, maximum+1))
	if err != nil {
		clear(content)
		return nil, cloudapp.ErrUnavailable
	}
	digest := sha256.Sum256(content)
	if int64(len(content)) != artifact.SizeBytes ||
		fmt.Sprintf("sha256:%x", digest) != artifact.SHA256 {
		clear(content)
		return nil, cloudapp.ErrInvalid
	}
	return content, nil
}

func validRetainedTeamArtifactKey(key, deploymentID string) bool {
	segments := strings.Split(key, "/")
	return len(segments) == 5 &&
		segments[0] == "workers" &&
		segments[1] != "" &&
		segments[2] == deploymentID &&
		segments[3] == "artifacts" &&
		segments[4] != ""
}
