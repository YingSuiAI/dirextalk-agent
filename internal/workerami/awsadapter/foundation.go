package awsadapter

import (
	"context"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

func (adapter *Adapter) validateFoundation(ctx context.Context, input workerami.BuildEnvironmentV1) error {
	if adapter.cloudformation == nil || input.NetworkMode != workerami.NetworkModeS3GatewayV2 {
		return workerami.ErrReadBackMismatch
	}
	output, err := adapter.cloudformation.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: aws.String(input.FoundationStackName)})
	if err != nil {
		return providerError(ctx, err)
	}
	if output == nil || len(output.Stacks) != 1 {
		return workerami.ErrReadBackMismatch
	}
	stack := output.Stacks[0]
	if aws.ToString(stack.StackName) != input.FoundationStackName || aws.ToString(stack.StackId) != input.FoundationStackID ||
		(stack.StackStatus != cftypes.StackStatusCreateComplete && stack.StackStatus != cftypes.StackStatusUpdateComplete) || stack.DeletionTime != nil {
		return workerami.ErrReadBackMismatch
	}
	agentMatched := false
	for _, parameter := range stack.Parameters {
		if aws.ToString(parameter.ParameterKey) == "AgentInstanceId" {
			if agentMatched || aws.ToString(parameter.ParameterValue) != input.AgentInstanceID {
				return workerami.ErrReadBackMismatch
			}
			agentMatched = true
		}
	}
	if !agentMatched {
		return workerami.ErrReadBackMismatch
	}
	wanted := map[string]string{"ReleasePrivateSubnetId": input.PrivateSubnetID, "ReleaseZeroIngressSecurityGroupId": input.ZeroIngressSGID,
		"ArtifactBucketName": input.ArtifactBucket, "FoundationKeyArn": input.ArtifactKMSKeyARN}
	seen := make(map[string]struct{}, len(wanted))
	for _, current := range stack.Outputs {
		key := aws.ToString(current.OutputKey)
		expected, relevant := wanted[key]
		if !relevant {
			continue
		}
		if _, duplicate := seen[key]; duplicate || aws.ToString(current.OutputValue) != expected {
			return workerami.ErrReadBackMismatch
		}
		seen[key] = struct{}{}
	}
	if len(seen) != len(wanted) || !strings.Contains(input.FoundationStackID, ":stack/"+input.FoundationStackName+"/") {
		return workerami.ErrReadBackMismatch
	}
	return nil
}
