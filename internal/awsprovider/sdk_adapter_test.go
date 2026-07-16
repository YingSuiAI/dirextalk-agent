package awsprovider_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cloudformationtypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

func TestStaticAWSConfigUsesOnlyUploadedCredentials(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAENVIRONMENTKEY00")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "environment-secret-that-must-not-be-used")
	credentials := &awsprovider.Credentials{AccessKeyID: []byte("AKIAABCDEFGHIJKLMNOP"), SecretAccessKey: []byte("uploaded-secret-access-key-value-123456"), SessionToken: []byte("uploaded-session-token")}
	config, err := awsprovider.StaticAWSConfig("us-east-1", credentials)
	if err != nil {
		t.Fatalf("static config: %v", err)
	}
	retrieved, err := config.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("retrieve: %v", err)
	}
	if retrieved.AccessKeyID != string(credentials.AccessKeyID) || retrieved.SecretAccessKey != string(credentials.SecretAccessKey) || retrieved.SessionToken != string(credentials.SessionToken) || config.Region != "us-east-1" {
		t.Fatalf("retrieved unexpected static credentials")
	}
}

func TestSDKProviderCreatesOnlyDeterministicBootstrapIdentity(t *testing.T) {
	clients, fakeIAM, _ := completeFakeClients()
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	provider, err := awsprovider.NewSDKProvider(clients, "us-east-1", func() time.Time { return now }, awsprovider.WithFoundationStackPollInterval(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{AgentInstanceID: "agent-01", Partition: "aws", AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := provider.EnsureBootstrapIdentity(context.Background(), spec)
	if err != nil {
		t.Fatalf("ensure identity: %v", err)
	}
	defer credential.Wipe()
	if len(fakeIAM.createRoleInputs) != 2 || len(fakeIAM.putRolePolicyInputs) != 2 || len(fakeIAM.createUserInputs) != 1 || len(fakeIAM.putUserPolicyInputs) != 1 || len(fakeIAM.deleteAccessKeyInputs) != 0 || len(fakeIAM.createAccessKeyInputs) != 1 {
		t.Fatalf("unexpected IAM calls: roles=%d rolePolicies=%d users=%d userPolicies=%d deleteKeys=%d createKeys=%d", len(fakeIAM.createRoleInputs), len(fakeIAM.putRolePolicyInputs), len(fakeIAM.createUserInputs), len(fakeIAM.putUserPolicyInputs), len(fakeIAM.deleteAccessKeyInputs), len(fakeIAM.createAccessKeyInputs))
	}
	if got := aws.ToString(fakeIAM.createUserInputs[0].UserName); got != spec.SourceUserName {
		t.Fatalf("source user = %q", got)
	}
	policy := aws.ToString(fakeIAM.putUserPolicyInputs[0].PolicyDocument)
	if strings.Contains(policy, "ec2:") || strings.Contains(policy, `"Resource":["*"]`) || !strings.Contains(policy, "sts:AssumeRole") {
		t.Fatalf("source user policy is broader than AssumeRole: %s", policy)
	}
	if string(credential.AccessKeyID) != "AKIAABCDEFGHIJKLMNOP" || string(credential.SecretAccessKey) != "generated-source-secret-value-123456" {
		t.Fatal("generated source credential missing")
	}
}

func TestSDKProviderExistingSourceKeyRequiresRemediationWithoutMutation(t *testing.T) {
	clients, fakeIAM, _ := completeFakeClients()
	oldKeyID := "AKIAOLDOLDOLDOLDOLD0"
	fakeIAM.listOutput.AccessKeyMetadata = []iamtypes.AccessKeyMetadata{{AccessKeyId: aws.String(oldKeyID)}}
	provider, err := awsprovider.NewSDKProvider(clients, "us-east-1", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{AgentInstanceID: "agent-01", Partition: "aws", AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.EnsureBootstrapIdentity(context.Background(), spec); !errors.Is(err, awsprovider.ErrSourceCredentialRemediationRequired) || strings.Contains(err.Error(), oldKeyID) {
		t.Fatalf("existing-key error=%v", err)
	}
	if len(fakeIAM.createAccessKeyInputs) != 0 || len(fakeIAM.deleteAccessKeyInputs) != 0 || aws.ToString(fakeIAM.listOutput.AccessKeyMetadata[0].AccessKeyId) != oldKeyID {
		t.Fatalf("existing key was mutated: create=%d delete=%d", len(fakeIAM.createAccessKeyInputs), len(fakeIAM.deleteAccessKeyInputs))
	}
}

func TestSDKProviderTwoSourceKeysFailClosedWithoutDeletion(t *testing.T) {
	clients, fakeIAM, _ := completeFakeClients()
	fakeIAM.listOutput.AccessKeyMetadata = []iamtypes.AccessKeyMetadata{
		{AccessKeyId: aws.String("AKIAOLDOLDOLDOLDOLD0")},
		{AccessKeyId: aws.String("AKIAOLDOLDOLDOLDOLD1")},
	}
	provider, err := awsprovider.NewSDKProvider(clients, "us-east-1", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{AgentInstanceID: "agent-01", Partition: "aws", AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.EnsureBootstrapIdentity(context.Background(), spec); !errors.Is(err, awsprovider.ErrSourceCredentialRemediationRequired) {
		t.Fatalf("two-key error=%v", err)
	}
	if len(fakeIAM.createAccessKeyInputs) != 0 || len(fakeIAM.deleteAccessKeyInputs) != 0 || len(fakeIAM.listOutput.AccessKeyMetadata) != 2 {
		t.Fatalf("two-key limit mutated IAM: create=%d delete=%d keys=%d", len(fakeIAM.createAccessKeyInputs), len(fakeIAM.deleteAccessKeyInputs), len(fakeIAM.listOutput.AccessKeyMetadata))
	}
}

func TestSDKProviderLostCreateResponseDoesNotDeleteKeyOrRepeatCreate(t *testing.T) {
	clients, fakeIAM, _ := completeFakeClients()
	secretCanary := "generated-source-secret-must-not-leak"
	createdKeyID := "AKIALOSTRESPONSE00001"
	fakeIAM.createAccessKeyErr = &smithy.GenericAPIError{Code: "InternalFailure", Message: "response lost after creating " + secretCanary}
	fakeIAM.createdKeyOnError = createdKeyID
	provider, err := awsprovider.NewSDKProvider(clients, "us-east-1", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{AgentInstanceID: "agent-01", Partition: "aws", AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.EnsureBootstrapIdentity(context.Background(), spec); !errors.Is(err, awsprovider.ErrProviderUnavailable) || strings.Contains(err.Error(), secretCanary) {
		t.Fatalf("lost-create error=%v", err)
	}
	if len(fakeIAM.deleteAccessKeyInputs) != 0 || len(fakeIAM.createAccessKeyInputs) != 1 || len(fakeIAM.listOutput.AccessKeyMetadata) != 1 {
		t.Fatalf("lost create was not retained safely: create=%d delete=%d keys=%d", len(fakeIAM.createAccessKeyInputs), len(fakeIAM.deleteAccessKeyInputs), len(fakeIAM.listOutput.AccessKeyMetadata))
	}
	fakeIAM.createAccessKeyErr = nil
	if _, err := provider.EnsureBootstrapIdentity(context.Background(), spec); !errors.Is(err, awsprovider.ErrSourceCredentialRemediationRequired) || strings.Contains(err.Error(), createdKeyID) {
		t.Fatalf("lost-create retry error=%v", err)
	}
	if len(fakeIAM.createAccessKeyInputs) != 1 || len(fakeIAM.deleteAccessKeyInputs) != 0 {
		t.Fatalf("lost-create retry repeated mutation: create=%d delete=%d", len(fakeIAM.createAccessKeyInputs), len(fakeIAM.deleteAccessKeyInputs))
	}
}

func TestSDKProviderRecoversLostCreateStackResponseByExactReadBack(t *testing.T) {
	clients, _, fakeCFN := completeFakeClients()
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	provider, err := awsprovider.NewSDKProvider(clients, "us-east-1", func() time.Time { return now }, awsprovider.WithFoundationStackPollInterval(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile("../../deploy/awsfoundation/foundation.yaml")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(template)
	request := awsprovider.FoundationStackRequest{
		StackName: "dtx-agent-0123456789ab-foundation", Region: "us-east-1", AccountID: "123456789012",
		FoundationRoleARN: "arn:aws:iam::123456789012:role/dtx-agent-0123456789ab-foundation",
		ClientToken:       "dtx-0123456789abcdef", TemplateBody: string(template), TemplateSHA256: "sha256:" + hex.EncodeToString(sum[:]),
		Parameters: map[string]string{"AgentInstanceId": "agent-01", "ReaperImageUri": "repo/reaper@sha256:" + strings.Repeat("a", 64)},
		Tags:       []awsprovider.Tag{{Key: awsprovider.TagAgentInstanceID, Value: "agent-01"}}, TerminationProtect: true,
	}
	fakeCFN.createErr = errors.New("connection closed after AWS accepted request")
	inProgress := &cloudformation.DescribeStacksOutput{Stacks: []cloudformationtypes.Stack{{
		StackId:   aws.String("arn:aws:cloudformation:us-east-1:123456789012:stack/dtx-agent-0123456789ab-foundation/stack-id"),
		StackName: aws.String(request.StackName), RoleARN: aws.String(request.FoundationRoleARN), StackStatus: cloudformationtypes.StackStatusCreateInProgress,
		Parameters: []cloudformationtypes.Parameter{{ParameterKey: aws.String("AgentInstanceId"), ParameterValue: aws.String("agent-01")}, {ParameterKey: aws.String("ReaperImageUri"), ParameterValue: aws.String(request.Parameters["ReaperImageUri"])}},
		Tags:       []cloudformationtypes.Tag{{Key: aws.String(awsprovider.TagAgentInstanceID), Value: aws.String("agent-01")}},
	}}}
	complete := *inProgress
	complete.Stacks = append([]cloudformationtypes.Stack(nil), inProgress.Stacks...)
	complete.Stacks[0].StackStatus = cloudformationtypes.StackStatusCreateComplete
	fakeCFN.describeOutputs = []*cloudformation.DescribeStacksOutput{inProgress, &complete}
	fakeCFN.templateOutput = &cloudformation.GetTemplateOutput{TemplateBody: aws.String(string(template))}
	receipt, err := provider.CreateFoundationStack(context.Background(), request)
	if err != nil {
		t.Fatalf("recover stack: %v", err)
	}
	if receipt.StackID == "" || receipt.Status != awsprovider.FoundationStackReadyStatus || !receipt.ObservedAt.Equal(now) {
		t.Fatalf("receipt = %#v", receipt)
	}
	if fakeCFN.createInput == nil || fakeCFN.createInput.RoleARN == nil || !aws.ToBool(fakeCFN.createInput.EnableTerminationProtection) || fakeCFN.createInput.OnFailure != cloudformationtypes.OnFailureDoNothing {
		t.Fatalf("unsafe CreateStack shape = %#v", fakeCFN.createInput)
	}

	complete.Stacks[0].RoleARN = aws.String("arn:aws:iam::123456789012:role/other")
	fakeCFN.describeOutputs = nil
	fakeCFN.describeOutput = &complete
	if _, err := provider.CreateFoundationStack(context.Background(), request); !errors.Is(err, awsprovider.ErrReadBackMismatch) {
		t.Fatalf("mismatch error = %v", err)
	}
}

func TestSDKProviderRejectsFoundationFailureAndReturnsContextTimeoutForRetry(t *testing.T) {
	clients, _, fakeCFN := completeFakeClients()
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	provider, err := awsprovider.NewSDKProvider(clients, "us-east-1", func() time.Time { return now }, awsprovider.WithFoundationStackPollInterval(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	template, _ := os.ReadFile("../../deploy/awsfoundation/foundation.yaml")
	sum := sha256.Sum256(template)
	request := awsprovider.FoundationStackRequest{
		StackName: "dtx-agent-0123456789ab-foundation", Region: "us-east-1", AccountID: "123456789012",
		FoundationRoleARN: "arn:aws:iam::123456789012:role/dtx-agent-0123456789ab-foundation", ClientToken: "dtx-0123456789abcdef",
		TemplateBody: string(template), TemplateSHA256: "sha256:" + hex.EncodeToString(sum[:]), Parameters: map[string]string{"AgentInstanceId": "agent-01"},
		Tags: []awsprovider.Tag{{Key: awsprovider.TagAgentInstanceID, Value: "agent-01"}}, TerminationProtect: true,
	}
	fakeCFN.createErr = errors.New("response lost")
	fakeCFN.templateOutput = &cloudformation.GetTemplateOutput{TemplateBody: aws.String(string(template))}
	fakeCFN.describeOutput = stackReadBack(request, cloudformationtypes.StackStatusRollbackComplete)
	if _, err := provider.CreateFoundationStack(context.Background(), request); !errors.Is(err, awsprovider.ErrFoundationStackFailed) {
		t.Fatalf("terminal failure error = %v", err)
	}

	fakeCFN.describeOutput = stackReadBack(request, cloudformationtypes.StackStatusCreateInProgress)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.CreateFoundationStack(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("retryable context error = %v", err)
	}
}

func stackReadBack(request awsprovider.FoundationStackRequest, status cloudformationtypes.StackStatus) *cloudformation.DescribeStacksOutput {
	parameters := make([]cloudformationtypes.Parameter, 0, len(request.Parameters))
	for key, value := range request.Parameters {
		parameters = append(parameters, cloudformationtypes.Parameter{ParameterKey: aws.String(key), ParameterValue: aws.String(value)})
	}
	return &cloudformation.DescribeStacksOutput{Stacks: []cloudformationtypes.Stack{{
		StackId: aws.String("arn:aws:cloudformation:us-east-1:123456789012:stack/dtx-agent-0123456789ab-foundation/stack-id"), StackName: aws.String(request.StackName),
		RoleARN: aws.String(request.FoundationRoleARN), StackStatus: status, Parameters: parameters,
		Tags: []cloudformationtypes.Tag{{Key: aws.String(awsprovider.TagAgentInstanceID), Value: aws.String("agent-01")}},
	}}}
}

func TestSDKProviderRedactsAWSAccessDeniedDetails(t *testing.T) {
	clients, _, _ := completeFakeClients()
	secret := "must-not-leak-provider-detail"
	clients.STS = fakeSTS{err: &smithy.GenericAPIError{Code: "AccessDenied", Message: secret}}
	provider, err := awsprovider.NewSDKProvider(clients, "us-east-1", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.GetCallerIdentity(context.Background())
	if !errors.Is(err, awsprovider.ErrPermissionDenied) || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe provider error = %v", err)
	}
}

func TestSDKProviderAcceptsTemporaryAdminSessionIdentity(t *testing.T) {
	clients, _, _ := completeFakeClients()
	clients.STS = fakeSTS{output: &sts.GetCallerIdentityOutput{
		Account: aws.String("123456789012"), Arn: aws.String("arn:aws:sts::123456789012:assumed-role/FoundationAdmin/bootstrap-session"), UserId: aws.String("AROATEST:bootstrap-session"),
	}}
	provider, err := awsprovider.NewSDKProvider(clients, "us-east-1", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := provider.GetCallerIdentity(context.Background())
	if err != nil {
		t.Fatalf("temporary identity: %v", err)
	}
	if identity.Partition != "aws" || identity.AccountID != "123456789012" || identity.Region != "us-east-1" {
		t.Fatalf("identity = %#v", identity)
	}
}

func completeFakeClients() (awsprovider.SDKClients, *fakeIAM, *fakeCFN) {
	iamClient := &fakeIAM{
		listOutput:            &iam.ListAccessKeysOutput{},
		createAccessKeyOutput: &iam.CreateAccessKeyOutput{AccessKey: &iamtypes.AccessKey{AccessKeyId: aws.String("AKIAABCDEFGHIJKLMNOP"), SecretAccessKey: aws.String("generated-source-secret-value-123456")}},
	}
	formation := &fakeCFN{}
	return awsprovider.SDKClients{
		STS: fakeSTS{output: &sts.GetCallerIdentityOutput{Account: aws.String("123456789012"), Arn: aws.String("arn:aws:iam::123456789012:root"), UserId: aws.String("123456789012")}},
		IAM: iamClient, CloudFormation: formation, S3: fakeS3{}, KMS: fakeKMS{}, SecretsManager: fakeSecrets{}, DynamoDB: fakeDynamo{}, CloudWatch: fakeCloudWatch{}, CloudWatchLogs: fakeLogs{}, EC2: fakeEC2{},
	}, iamClient, formation
}

type fakeSTS struct {
	output *sts.GetCallerIdentityOutput
	err    error
}

func (client fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return client.output, client.err
}

type fakeIAM struct {
	createRoleInputs      []*iam.CreateRoleInput
	putRolePolicyInputs   []*iam.PutRolePolicyInput
	createUserInputs      []*iam.CreateUserInput
	putUserPolicyInputs   []*iam.PutUserPolicyInput
	deleteAccessKeyInputs []*iam.DeleteAccessKeyInput
	createAccessKeyInputs []*iam.CreateAccessKeyInput
	listOutput            *iam.ListAccessKeysOutput
	createAccessKeyOutput *iam.CreateAccessKeyOutput
	createAccessKeyErr    error
	createdKeyOnError     string
}

func (client *fakeIAM) CreateUser(_ context.Context, input *iam.CreateUserInput, _ ...func(*iam.Options)) (*iam.CreateUserOutput, error) {
	client.createUserInputs = append(client.createUserInputs, input)
	return &iam.CreateUserOutput{}, nil
}
func (client *fakeIAM) TagUser(context.Context, *iam.TagUserInput, ...func(*iam.Options)) (*iam.TagUserOutput, error) {
	return &iam.TagUserOutput{}, nil
}
func (client *fakeIAM) PutUserPolicy(_ context.Context, input *iam.PutUserPolicyInput, _ ...func(*iam.Options)) (*iam.PutUserPolicyOutput, error) {
	client.putUserPolicyInputs = append(client.putUserPolicyInputs, input)
	return &iam.PutUserPolicyOutput{}, nil
}
func (client *fakeIAM) CreateRole(_ context.Context, input *iam.CreateRoleInput, _ ...func(*iam.Options)) (*iam.CreateRoleOutput, error) {
	client.createRoleInputs = append(client.createRoleInputs, input)
	return &iam.CreateRoleOutput{}, nil
}
func (client *fakeIAM) UpdateAssumeRolePolicy(context.Context, *iam.UpdateAssumeRolePolicyInput, ...func(*iam.Options)) (*iam.UpdateAssumeRolePolicyOutput, error) {
	return &iam.UpdateAssumeRolePolicyOutput{}, nil
}
func (client *fakeIAM) TagRole(context.Context, *iam.TagRoleInput, ...func(*iam.Options)) (*iam.TagRoleOutput, error) {
	return &iam.TagRoleOutput{}, nil
}
func (client *fakeIAM) PutRolePolicy(_ context.Context, input *iam.PutRolePolicyInput, _ ...func(*iam.Options)) (*iam.PutRolePolicyOutput, error) {
	client.putRolePolicyInputs = append(client.putRolePolicyInputs, input)
	return &iam.PutRolePolicyOutput{}, nil
}
func (client *fakeIAM) ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return client.listOutput, nil
}
func (client *fakeIAM) DeleteAccessKey(_ context.Context, input *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	client.deleteAccessKeyInputs = append(client.deleteAccessKeyInputs, input)
	return &iam.DeleteAccessKeyOutput{}, nil
}
func (client *fakeIAM) CreateAccessKey(_ context.Context, input *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	client.createAccessKeyInputs = append(client.createAccessKeyInputs, input)
	if client.createAccessKeyErr != nil {
		if client.createdKeyOnError != "" {
			client.listOutput.AccessKeyMetadata = append(client.listOutput.AccessKeyMetadata, iamtypes.AccessKeyMetadata{AccessKeyId: aws.String(client.createdKeyOnError)})
		}
		return nil, client.createAccessKeyErr
	}
	return client.createAccessKeyOutput, nil
}

type fakeCFN struct {
	createInput     *cloudformation.CreateStackInput
	createOutput    *cloudformation.CreateStackOutput
	createErr       error
	describeOutput  *cloudformation.DescribeStacksOutput
	describeOutputs []*cloudformation.DescribeStacksOutput
	describeCalls   int
	templateOutput  *cloudformation.GetTemplateOutput
}

func (client *fakeCFN) CreateStack(_ context.Context, input *cloudformation.CreateStackInput, _ ...func(*cloudformation.Options)) (*cloudformation.CreateStackOutput, error) {
	client.createInput = input
	return client.createOutput, client.createErr
}

func (client *fakeCFN) DescribeStacks(context.Context, *cloudformation.DescribeStacksInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {
	if len(client.describeOutputs) > 0 {
		index := client.describeCalls
		if index >= len(client.describeOutputs) {
			index = len(client.describeOutputs) - 1
		}
		client.describeCalls++
		return client.describeOutputs[index], nil
	}
	return client.describeOutput, nil
}
func (client *fakeCFN) GetTemplate(context.Context, *cloudformation.GetTemplateInput, ...func(*cloudformation.Options)) (*cloudformation.GetTemplateOutput, error) {
	return client.templateOutput, nil
}

type fakeS3 struct{}

func (fakeS3) HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	return &s3.HeadBucketOutput{}, nil
}

type fakeKMS struct{}

func (fakeKMS) DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return &kms.DescribeKeyOutput{}, nil
}

type fakeSecrets struct{}

func (fakeSecrets) DescribeSecret(context.Context, *secretsmanager.DescribeSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	return &secretsmanager.DescribeSecretOutput{}, nil
}

type fakeDynamo struct{}

func (fakeDynamo) DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	return &dynamodb.DescribeTableOutput{}, nil
}

type fakeCloudWatch struct{}

func (fakeCloudWatch) DescribeAlarms(context.Context, *cloudwatch.DescribeAlarmsInput, ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) {
	return &cloudwatch.DescribeAlarmsOutput{}, nil
}

type fakeLogs struct{}

func (fakeLogs) DescribeLogGroups(context.Context, *cloudwatchlogs.DescribeLogGroupsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
	return &cloudwatchlogs.DescribeLogGroupsOutput{}, nil
}

type fakeEC2 struct{}

func (fakeEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{}, nil
}
