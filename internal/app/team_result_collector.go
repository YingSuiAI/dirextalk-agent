package app

import (
	"context"
	"io"
	"net/url"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerresult"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type teamResultS3API interface {
	GetObject(
		context.Context,
		*s3.GetObjectInput,
		...func(*s3.Options),
	) (*s3.GetObjectOutput, error)
}

type awsTeamResultCollector struct {
	agentInstanceID string
	runtimes        *awsResourceRuntimeFactory
}

func newAWSTeamResultCollector(
	agentInstanceID string,
	runtimes *awsResourceRuntimeFactory,
) (*awsTeamResultCollector, error) {
	if strings.TrimSpace(agentInstanceID) == "" ||
		runtimes == nil ||
		runtimes.agentInstanceID != agentInstanceID {
		return nil, cloudapp.ErrInvalid
	}
	return &awsTeamResultCollector{
		agentInstanceID: agentInstanceID,
		runtimes:        runtimes,
	}, nil
}

func (collector *awsTeamResultCollector) Collect(
	ctx context.Context,
	connection cloudapp.Connection,
	deployment worker.Deployment,
) (workerresult.Collected, error) {
	if collector == nil ||
		collector.runtimes == nil ||
		ctx == nil ||
		deployment.DeploymentID == "" ||
		deployment.OwnerID != connection.OwnerID {
		return workerresult.Collected{}, workerresult.ErrInvalid
	}
	configuration, foundation, err :=
		collector.runtimes.controlConfig(ctx, connection)
	if err != nil {
		return workerresult.Collected{}, err
	}
	bucket, prefix, err := teamResultPrefix(
		deployment.Access.ArtifactPrefix,
		deployment.DeploymentID,
	)
	if err != nil || bucket != foundation.ArtifactBucketName {
		return workerresult.Collected{}, workerresult.ErrInvalid
	}
	reader := &teamResultObjectReader{
		client: s3.NewFromConfig(configuration),
		bucket: bucket,
		prefix: prefix,
	}
	verified, err := workerresult.NewCollector(reader)
	if err != nil {
		return workerresult.Collected{}, err
	}
	return verified.Collect(ctx, deployment)
}

type teamResultObjectReader struct {
	client teamResultS3API
	bucket string
	prefix string
}

func (reader *teamResultObjectReader) Get(
	ctx context.Context,
	reference string,
	maximum int64,
) ([]byte, error) {
	bucket, key, err := splitTeamResultObject(reference)
	if reader == nil ||
		reader.client == nil ||
		ctx == nil ||
		maximum < 1 ||
		maximum > worker.MaximumObjectClaimBytes ||
		err != nil ||
		bucket != reader.bucket ||
		!strings.HasPrefix(key, reader.prefix) ||
		strings.Contains(
			strings.TrimPrefix(key, reader.prefix),
			"/",
		) {
		return nil, workerresult.ErrInvalid
	}
	output, err := reader.client.GetObject(
		ctx,
		&s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		},
	)
	if err != nil || output == nil || output.Body == nil {
		return nil, workerresult.ErrUnavailable
	}
	defer output.Body.Close()
	if aws.ToInt64(output.ContentLength) != maximum {
		return nil, workerresult.ErrInvalid
	}
	content, err := io.ReadAll(
		io.LimitReader(output.Body, maximum+1),
	)
	if err != nil {
		clear(content)
		return nil, workerresult.ErrUnavailable
	}
	if int64(len(content)) != maximum {
		clear(content)
		return nil, workerresult.ErrInvalid
	}
	return content, nil
}

func teamResultPrefix(
	reference string,
	deploymentID string,
) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(reference))
	expected := "deployments/" + deploymentID + "/artifacts/"
	if err != nil ||
		parsed.Scheme != "s3" ||
		parsed.Host == "" ||
		strings.TrimPrefix(parsed.Path, "/") != expected ||
		parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return "", "", workerresult.ErrInvalid
	}
	return parsed.Host, expected, nil
}

func splitTeamResultObject(
	reference string,
) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(reference))
	if err != nil ||
		parsed.Scheme != "s3" ||
		parsed.Host == "" ||
		parsed.Path == "" ||
		strings.HasSuffix(parsed.Path, "/") ||
		parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return "", "", workerresult.ErrInvalid
	}
	return parsed.Host, strings.TrimPrefix(parsed.Path, "/"), nil
}
