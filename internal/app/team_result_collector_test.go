package app

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/workerresult"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestTeamResultObjectReaderRestrictsExactDeploymentPrefix(
	t *testing.T,
) {
	t.Parallel()
	client := &teamResultS3Stub{
		content: []byte(`{"safe":true}`),
	}
	reader := &teamResultObjectReader{
		client: client,
		bucket: "agent-artifacts",
		prefix: "deployments/11111111-1111-4111-8111-111111111111/" +
			"artifacts/",
	}
	reference := "s3://agent-artifacts/" +
		reader.prefix + "result.json"
	content, err := reader.Get(
		context.Background(),
		reference,
		int64(len(client.content)),
	)
	if err != nil ||
		!bytes.Equal(content, client.content) ||
		aws.ToString(client.input.Bucket) != "agent-artifacts" ||
		aws.ToString(client.input.Key) !=
			reader.prefix+"result.json" {
		t.Fatalf(
			"Team result read content=%q input=%#v error=%v",
			content,
			client.input,
			err,
		)
	}
	for _, invalid := range []string{
		"s3://other-bucket/" + reader.prefix + "result.json",
		"s3://agent-artifacts/deployments/other/artifacts/result.json",
		"s3://agent-artifacts/" + reader.prefix + "nested/result.json",
	} {
		if _, err := reader.Get(
			context.Background(),
			invalid,
			int64(len(client.content)),
		); err != workerresult.ErrInvalid {
			t.Fatalf("out-of-scope reference %q error=%v", invalid, err)
		}
	}
}

func TestTeamResultPrefixRequiresCanonicalDeploymentPath(
	t *testing.T,
) {
	t.Parallel()
	deploymentID := "11111111-1111-4111-8111-111111111111"
	bucket, prefix, err := teamResultPrefix(
		"s3://agent-artifacts/deployments/"+
			deploymentID+"/artifacts/",
		deploymentID,
	)
	if err != nil ||
		bucket != "agent-artifacts" ||
		prefix != "deployments/"+deploymentID+"/artifacts/" {
		t.Fatalf(
			"Team result prefix bucket=%q prefix=%q error=%v",
			bucket,
			prefix,
			err,
		)
	}
	if _, _, err := teamResultPrefix(
		"s3://agent-artifacts/deployments/other/artifacts/",
		deploymentID,
	); err != workerresult.ErrInvalid {
		t.Fatalf("mismatched deployment prefix error=%v", err)
	}
}

type teamResultS3Stub struct {
	content []byte
	input   *s3.GetObjectInput
}

func (stub *teamResultS3Stub) GetObject(
	_ context.Context,
	input *s3.GetObjectInput,
	_ ...func(*s3.Options),
) (*s3.GetObjectOutput, error) {
	stub.input = input
	return &s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(stub.content)),
		ContentLength: aws.Int64(int64(len(stub.content))),
	}, nil
}
