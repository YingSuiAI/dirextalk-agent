package artifactorigin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/smithy-go"
)

type describeResult struct {
	output *cloudformation.DescribeStacksOutput
	err    error
}

type fakeCloudFormation struct {
	describes []describeResult
	create    *cloudformation.CreateStackInput
	update    *cloudformation.UpdateStackInput
	updateErr error
}

func (fake *fakeCloudFormation) DescribeStacks(context.Context, *cloudformation.DescribeStacksInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {
	if len(fake.describes) == 0 {
		return nil, &smithy.GenericAPIError{Code: "InternalError", Message: "unexpected describe"}
	}
	result := fake.describes[0]
	fake.describes = fake.describes[1:]
	return result.output, result.err
}

func (fake *fakeCloudFormation) CreateStack(_ context.Context, input *cloudformation.CreateStackInput, _ ...func(*cloudformation.Options)) (*cloudformation.CreateStackOutput, error) {
	fake.create = input
	return &cloudformation.CreateStackOutput{StackId: aws.String(stackARN(StorageRegion, StorageStackName))}, nil
}

func (fake *fakeCloudFormation) UpdateStack(_ context.Context, input *cloudformation.UpdateStackInput, _ ...func(*cloudformation.Options)) (*cloudformation.UpdateStackOutput, error) {
	fake.update = input
	return &cloudformation.UpdateStackOutput{StackId: aws.String(stackARN(StorageRegion, StorageStackName))}, fake.updateErr
}

func TestSDKStackDriverCreatesWithDeterministicRequestThenWaits(t *testing.T) {
	request := StackRequest{
		Name: StorageStackName, Template: []byte("template"),
		Parameters: map[string]string{"B": "2", "A": "1"}, Tags: map[string]string{"managed_by": "dirextalk-agent", "component": "artifact-origin-storage"},
	}
	complete := cloudFormationStack(request, cftypes.StackStatusCreateComplete)
	fake := &fakeCloudFormation{describes: []describeResult{
		{err: &smithy.GenericAPIError{Code: "ValidationError", Message: "Stack with id dtx does not exist"}},
		{output: &cloudformation.DescribeStacksOutput{Stacks: []cftypes.Stack{cloudFormationStack(request, cftypes.StackStatusCreateInProgress)}}},
		{output: &cloudformation.DescribeStacksOutput{Stacks: []cftypes.Stack{complete}}},
	}}
	driver := &sdkStackDriver{client: fake, region: StorageRegion, pollInterval: time.Nanosecond}
	result, err := driver.Apply(context.Background(), request)
	if err != nil || result.Status != "CREATE_COMPLETE" || fake.create == nil || fake.update != nil {
		t.Fatalf("Apply() result=%#v error=%v create=%#v update=%#v", result, err, fake.create, fake.update)
	}
	if aws.ToString(fake.create.ClientRequestToken) != stackRequestToken(request) || fake.create.OnFailure != cftypes.OnFailureRollback ||
		aws.ToString(fake.create.Parameters[0].ParameterKey) != "A" || aws.ToString(fake.create.Parameters[1].ParameterKey) != "B" {
		t.Fatalf("CreateStack input = %#v", fake.create)
	}
}

func TestSDKStackDriverTreatsOnlyExactNoUpdateAsRecoverable(t *testing.T) {
	request := StackRequest{Name: StorageStackName, Template: []byte("template"), Parameters: map[string]string{"A": "1"}, Tags: map[string]string{"component": "artifact-origin-storage"}}
	complete := cloudFormationStack(request, cftypes.StackStatusUpdateComplete)
	fake := &fakeCloudFormation{
		describes: []describeResult{{output: &cloudformation.DescribeStacksOutput{Stacks: []cftypes.Stack{complete}}}},
		updateErr: &smithy.GenericAPIError{Code: "ValidationError", Message: "No updates are to be performed."},
	}
	driver := &sdkStackDriver{client: fake, region: StorageRegion, pollInterval: time.Nanosecond}
	if _, err := driver.Apply(context.Background(), request); err != nil || fake.create != nil || fake.update == nil {
		t.Fatalf("Apply no-op error=%v create=%#v update=%#v", err, fake.create, fake.update)
	}
}

func TestSDKStackDriverDoesNotClaimRolledBackTemplateUpdate(t *testing.T) {
	request := StackRequest{Name: StorageStackName, Template: []byte("template"), Parameters: map[string]string{"A": "1"}, Tags: map[string]string{"component": "artifact-origin-storage"}}
	before := cloudFormationStack(request, cftypes.StackStatusUpdateComplete)
	rolledBack := cloudFormationStack(request, cftypes.StackStatusUpdateRollbackComplete)
	rolledBackAt := time.Date(2026, 7, 19, 0, 1, 0, 0, time.UTC)
	rolledBack.LastUpdatedTime = aws.Time(rolledBackAt)
	fake := &fakeCloudFormation{describes: []describeResult{
		{output: &cloudformation.DescribeStacksOutput{Stacks: []cftypes.Stack{before}}},
		{output: &cloudformation.DescribeStacksOutput{Stacks: []cftypes.Stack{rolledBack}}},
	}}
	driver := &sdkStackDriver{client: fake, region: StorageRegion, pollInterval: time.Nanosecond}
	if _, err := driver.Apply(context.Background(), request); !errors.Is(err, ErrCloudOperation) {
		t.Fatalf("Apply rollback error = %v, want ErrCloudOperation", err)
	}
}

func cloudFormationStack(request StackRequest, status cftypes.StackStatus) cftypes.Stack {
	parameters := cloudFormationParameters(request.Parameters)
	tags := cloudFormationTags(request.Tags)
	created := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	return cftypes.Stack{
		StackName: aws.String(request.Name), StackId: aws.String(stackARN(StorageRegion, request.Name)), StackStatus: status,
		CreationTime: aws.Time(created), Parameters: parameters, Tags: tags,
	}
}
