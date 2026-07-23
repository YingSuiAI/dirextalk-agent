package releaseecr

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

const reaperLambdaPolicySID = "LambdaECRImageRetrievalPolicy"

type repositoryPolicyReadAPI interface {
	GetRepositoryPolicy(context.Context, *ecr.GetRepositoryPolicyInput, ...func(*ecr.Options)) (*ecr.GetRepositoryPolicyOutput, error)
}

type repositoryPolicyWriteAPI interface {
	repositoryPolicyReadAPI
	SetRepositoryPolicy(context.Context, *ecr.SetRepositoryPolicyInput, ...func(*ecr.Options)) (*ecr.SetRepositoryPolicyOutput, error)
}

func ensureReaperLambdaRepositoryPolicy(ctx context.Context, client repositoryPolicyWriteAPI, partition, accountID, region string) error {
	document, statements, found, err := readRepositoryPolicy(ctx, client, accountID)
	if err != nil {
		return err
	}
	expected := reaperLambdaPolicyStatement(partition, accountID, region)
	if found && exactlyOneExpectedPolicy(statements, expected) {
		return nil
	}
	filtered := make([]any, 0, len(statements)+1)
	for _, statement := range statements {
		current, ok := statement.(map[string]any)
		if ok && current["Sid"] == reaperLambdaPolicySID {
			continue
		}
		filtered = append(filtered, statement)
	}
	filtered = append(filtered, expected)
	if document == nil {
		document = make(map[string]any)
	}
	document["Version"] = "2012-10-17"
	document["Statement"] = filtered
	encoded, err := json.Marshal(document)
	if err != nil {
		return ErrRepositoryDrift
	}
	if _, err := client.SetRepositoryPolicy(ctx, &ecr.SetRepositoryPolicyInput{
		RegistryId: aws.String(accountID), RepositoryName: aws.String(RepositoryReaper), PolicyText: aws.String(string(encoded)),
	}); err != nil {
		return redactedAWSFailure(ctx)
	}
	_, readBack, readBackFound, err := readRepositoryPolicy(ctx, client, accountID)
	if err != nil {
		return err
	}
	if !readBackFound || !exactlyOneExpectedPolicy(readBack, expected) {
		return ErrRepositoryDrift
	}
	return nil
}

func verifyReaperLambdaRepositoryPolicy(ctx context.Context, client repositoryPolicyReadAPI, partition, accountID, region string) error {
	_, statements, found, err := readRepositoryPolicy(ctx, client, accountID)
	if err != nil {
		return err
	}
	if !found || !exactlyOneExpectedPolicy(statements, reaperLambdaPolicyStatement(partition, accountID, region)) {
		return ErrRepositoryDrift
	}
	return nil
}

func readRepositoryPolicy(ctx context.Context, client repositoryPolicyReadAPI, accountID string) (map[string]any, []any, bool, error) {
	output, err := client.GetRepositoryPolicy(ctx, &ecr.GetRepositoryPolicyInput{
		RegistryId: aws.String(accountID), RepositoryName: aws.String(RepositoryReaper),
	})
	if err != nil {
		var missing *ecrtypes.RepositoryPolicyNotFoundException
		if errors.As(err, &missing) {
			return nil, nil, false, nil
		}
		return nil, nil, false, redactedAWSFailure(ctx)
	}
	if output == nil || aws.ToString(output.RegistryId) != accountID || aws.ToString(output.RepositoryName) != RepositoryReaper ||
		aws.ToString(output.PolicyText) == "" {
		return nil, nil, false, ErrRepositoryDrift
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(aws.ToString(output.PolicyText)), &document); err != nil {
		return nil, nil, false, ErrRepositoryDrift
	}
	statements, ok := document["Statement"].([]any)
	if !ok {
		if single, singleOK := document["Statement"].(map[string]any); singleOK {
			statements = []any{single}
		} else {
			return nil, nil, false, ErrRepositoryDrift
		}
	}
	return document, statements, true, nil
}

func reaperLambdaPolicyStatement(partition, accountID, region string) map[string]any {
	return map[string]any{
		"Sid":    reaperLambdaPolicySID,
		"Effect": "Allow",
		"Principal": map[string]any{
			"Service": "lambda.amazonaws.com",
		},
		"Action": []any{"ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"},
		"Condition": map[string]any{
			"StringEquals": map[string]any{"aws:SourceAccount": accountID},
			"ArnLike": map[string]any{
				"aws:SourceArn": "arn:" + partition + ":lambda:" + region + ":" + accountID + ":function:dtx-agent-*-reaper",
			},
		},
	}
}

func exactlyOneExpectedPolicy(statements []any, expected map[string]any) bool {
	matches := 0
	for _, statement := range statements {
		current, ok := statement.(map[string]any)
		if !ok || current["Sid"] != reaperLambdaPolicySID {
			continue
		}
		if !reflect.DeepEqual(current, expected) {
			return false
		}
		matches++
	}
	return matches == 1
}
