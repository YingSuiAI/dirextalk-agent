package awsprovider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/credentials"
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

var (
	sdkRegionPattern  = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$`)
	sdkAccountPattern = regexp.MustCompile(`^[0-9]{12}$`)
	sdkNamePattern    = regexp.MustCompile(`^dtx-agent-[a-z0-9-]{1,54}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

type STSAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type IAMAPI interface {
	CreateUser(context.Context, *iam.CreateUserInput, ...func(*iam.Options)) (*iam.CreateUserOutput, error)
	TagUser(context.Context, *iam.TagUserInput, ...func(*iam.Options)) (*iam.TagUserOutput, error)
	PutUserPolicy(context.Context, *iam.PutUserPolicyInput, ...func(*iam.Options)) (*iam.PutUserPolicyOutput, error)
	CreateRole(context.Context, *iam.CreateRoleInput, ...func(*iam.Options)) (*iam.CreateRoleOutput, error)
	UpdateAssumeRolePolicy(context.Context, *iam.UpdateAssumeRolePolicyInput, ...func(*iam.Options)) (*iam.UpdateAssumeRolePolicyOutput, error)
	TagRole(context.Context, *iam.TagRoleInput, ...func(*iam.Options)) (*iam.TagRoleOutput, error)
	PutRolePolicy(context.Context, *iam.PutRolePolicyInput, ...func(*iam.Options)) (*iam.PutRolePolicyOutput, error)
	ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	DeleteAccessKey(context.Context, *iam.DeleteAccessKeyInput, ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error)
	CreateAccessKey(context.Context, *iam.CreateAccessKeyInput, ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error)
}

type CloudFormationAPI interface {
	CreateStack(context.Context, *cloudformation.CreateStackInput, ...func(*cloudformation.Options)) (*cloudformation.CreateStackOutput, error)
	DescribeStacks(context.Context, *cloudformation.DescribeStacksInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
	GetTemplate(context.Context, *cloudformation.GetTemplateInput, ...func(*cloudformation.Options)) (*cloudformation.GetTemplateOutput, error)
}

type S3API interface {
	HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
}

type KMSAPI interface {
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

type SecretsManagerAPI interface {
	DescribeSecret(context.Context, *secretsmanager.DescribeSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
}

type DynamoDBAPI interface {
	DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
}

type CloudWatchAPI interface {
	DescribeAlarms(context.Context, *cloudwatch.DescribeAlarmsInput, ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error)
}

type CloudWatchLogsAPI interface {
	DescribeLogGroups(context.Context, *cloudwatchlogs.DescribeLogGroupsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error)
}

type EC2API interface {
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

type SDKClients struct {
	STS            STSAPI
	IAM            IAMAPI
	CloudFormation CloudFormationAPI
	S3             S3API
	KMS            KMSAPI
	SecretsManager SecretsManagerAPI
	DynamoDB       DynamoDBAPI
	CloudWatch     CloudWatchAPI
	CloudWatchLogs CloudWatchLogsAPI
	EC2            EC2API
}

func NewSDKClients(config aws.Config) SDKClients {
	return SDKClients{
		STS: sts.NewFromConfig(config), IAM: iam.NewFromConfig(config), CloudFormation: cloudformation.NewFromConfig(config),
		S3: s3.NewFromConfig(config), KMS: kms.NewFromConfig(config), SecretsManager: secretsmanager.NewFromConfig(config),
		DynamoDB: dynamodb.NewFromConfig(config), CloudWatch: cloudwatch.NewFromConfig(config), CloudWatchLogs: cloudwatchlogs.NewFromConfig(config),
		EC2: ec2.NewFromConfig(config),
	}
}

func (clients SDKClients) valid() bool {
	return clients.STS != nil && clients.IAM != nil && clients.CloudFormation != nil && clients.S3 != nil && clients.KMS != nil && clients.SecretsManager != nil && clients.DynamoDB != nil && clients.CloudWatch != nil && clients.CloudWatchLogs != nil && clients.EC2 != nil
}

type SDKFactory struct {
	now func() time.Time
}

func NewSDKFactory() *SDKFactory {
	return &SDKFactory{now: time.Now}
}

func (factory *SDKFactory) NewBootstrapProvider(_ context.Context, region string, value *Credentials) (BootstrapProvider, error) {
	if factory == nil || factory.now == nil {
		return nil, ErrInvalidRequest
	}
	config, err := StaticAWSConfig(region, value)
	if err != nil {
		return nil, err
	}
	return NewSDKProvider(NewSDKClients(config), region, factory.now)
}

// StaticAWSConfig deliberately does not invoke config.LoadDefaultConfig: a
// root/admin bootstrap must never inherit environment, shared-file, metadata,
// or workload credentials from the Agent host.
func StaticAWSConfig(region string, value *Credentials) (aws.Config, error) {
	if !sdkRegionPattern.MatchString(region) || value == nil || !value.valid() {
		return aws.Config{}, ErrInvalidCredentials
	}
	provider := credentials.NewStaticCredentialsProvider(string(value.AccessKeyID), string(value.SecretAccessKey), string(value.SessionToken))
	return aws.Config{Region: region, Credentials: aws.NewCredentialsCache(provider), RetryMode: aws.RetryModeStandard, RetryMaxAttempts: 3}, nil
}

type SDKProvider struct {
	clients           SDKClients
	region            string
	now               func() time.Time
	stackPollInterval time.Duration
}

type SDKProviderOption func(*SDKProvider) error

func WithFoundationStackPollInterval(interval time.Duration) SDKProviderOption {
	return func(provider *SDKProvider) error {
		if interval <= 0 || interval > time.Minute {
			return ErrInvalidRequest
		}
		provider.stackPollInterval = interval
		return nil
	}
}

func NewSDKProvider(clients SDKClients, region string, now func() time.Time, options ...SDKProviderOption) (*SDKProvider, error) {
	if !clients.valid() || !sdkRegionPattern.MatchString(region) || now == nil {
		return nil, ErrInvalidRequest
	}
	provider := &SDKProvider{clients: clients, region: region, now: now, stackPollInterval: 5 * time.Second}
	for _, option := range options {
		if option == nil || option(provider) != nil {
			return nil, ErrInvalidRequest
		}
	}
	return provider, nil
}

func (provider *SDKProvider) GetCallerIdentity(ctx context.Context) (CallerIdentity, error) {
	output, err := provider.clients.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return CallerIdentity{}, providerError(ctx, err)
	}
	if output == nil {
		return CallerIdentity{}, ErrReadBackMismatch
	}
	parsed, err := arn.Parse(aws.ToString(output.Arn))
	if err != nil || (parsed.Service != "iam" && parsed.Service != "sts") || !sdkAccountPattern.MatchString(aws.ToString(output.Account)) || parsed.AccountID != aws.ToString(output.Account) || aws.ToString(output.UserId) == "" {
		return CallerIdentity{}, ErrReadBackMismatch
	}
	return CallerIdentity{Partition: parsed.Partition, AccountID: parsed.AccountID, ARN: parsed.String(), UserID: aws.ToString(output.UserId), Region: provider.region}, nil
}

func (provider *SDKProvider) EnsureBootstrapIdentity(ctx context.Context, spec BootstrapIdentitySpec) (SourceCredentials, error) {
	if err := validateBootstrapSpec(spec, provider.region); err != nil {
		return SourceCredentials{}, err
	}
	controlTrust, err := json.Marshal(spec.ControlTrustPolicy)
	if err != nil {
		return SourceCredentials{}, ErrInvalidRequest
	}
	controlPolicy, err := json.Marshal(spec.ControlBaselinePolicy)
	if err != nil {
		return SourceCredentials{}, ErrInvalidRequest
	}
	foundationTrust, err := json.Marshal(spec.FoundationTrustPolicy)
	if err != nil {
		return SourceCredentials{}, ErrInvalidRequest
	}
	foundationPolicy, err := json.Marshal(spec.FoundationExecutionPolicy)
	if err != nil {
		return SourceCredentials{}, ErrInvalidRequest
	}
	sourcePolicy, err := json.Marshal(spec.SourceUserPolicy)
	if err != nil {
		return SourceCredentials{}, ErrInvalidRequest
	}
	roleTags := iamTagSet(spec.Tags)
	if err := provider.ensureRole(ctx, spec.ControlRoleName, "Dirextalk Agent typed control role", string(controlTrust), "control-baseline-v1", string(controlPolicy), roleTags); err != nil {
		return SourceCredentials{}, err
	}
	if err := provider.ensureRole(ctx, spec.FoundationRoleName, "Dirextalk Agent CloudFormation execution role", string(foundationTrust), "foundation-execution-v1", string(foundationPolicy), roleTags); err != nil {
		return SourceCredentials{}, err
	}
	if err := provider.ensureSourceUser(ctx, spec.SourceUserName, string(sourcePolicy), roleTags); err != nil {
		return SourceCredentials{}, err
	}
	return provider.createInitialSourceAccessKey(ctx, spec.SourceUserName)
}

func (provider *SDKProvider) ensureRole(ctx context.Context, roleName, description, trustPolicy, policyName, policy string, tags []iamtypes.Tag) error {
	_, err := provider.clients.IAM.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String(roleName), Description: aws.String(description), AssumeRolePolicyDocument: aws.String(trustPolicy), MaxSessionDuration: aws.Int32(3600), Tags: tags})
	if err != nil && !apiCode(err, "EntityAlreadyExists") {
		return providerError(ctx, err)
	}
	if _, err := provider.clients.IAM.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{RoleName: aws.String(roleName), PolicyDocument: aws.String(trustPolicy)}); err != nil {
		return providerError(ctx, err)
	}
	if _, err := provider.clients.IAM.TagRole(ctx, &iam.TagRoleInput{RoleName: aws.String(roleName), Tags: tags}); err != nil {
		return providerError(ctx, err)
	}
	if _, err := provider.clients.IAM.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: aws.String(roleName), PolicyName: aws.String(policyName), PolicyDocument: aws.String(policy)}); err != nil {
		return providerError(ctx, err)
	}
	return nil
}

func (provider *SDKProvider) ensureSourceUser(ctx context.Context, userName, policy string, tags []iamtypes.Tag) error {
	_, err := provider.clients.IAM.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String(userName), Tags: tags})
	if err != nil && !apiCode(err, "EntityAlreadyExists") {
		return providerError(ctx, err)
	}
	if _, err := provider.clients.IAM.TagUser(ctx, &iam.TagUserInput{UserName: aws.String(userName), Tags: tags}); err != nil {
		return providerError(ctx, err)
	}
	if _, err := provider.clients.IAM.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: aws.String(userName), PolicyName: aws.String("assume-control-only-v1"), PolicyDocument: aws.String(policy)}); err != nil {
		return providerError(ctx, err)
	}
	return nil
}

// createInitialSourceAccessKey creates credentials only for a source user that
// has no access keys. Existing keys are never deleted or automatically
// rotated: the current BootstrapProvider/Vault contract cannot atomically
// persist a new secret and promote it before revoking the old credential.
//
// A CreateAccessKey response loss is deterministic on retry: ListAccessKeys
// observes the newly-created-but-unrecoverable key and this method fails closed
// with ErrSourceCredentialRemediationRequired instead of creating or deleting
// another key.
func (provider *SDKProvider) createInitialSourceAccessKey(ctx context.Context, userName string) (SourceCredentials, error) {
	var marker *string
	keyCount := 0
	for {
		output, err := provider.clients.IAM.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(userName), Marker: marker})
		if err != nil {
			return SourceCredentials{}, providerError(ctx, err)
		}
		if output == nil {
			return SourceCredentials{}, ErrReadBackMismatch
		}
		for _, metadata := range output.AccessKeyMetadata {
			keyID := aws.ToString(metadata.AccessKeyId)
			if keyID == "" {
				return SourceCredentials{}, ErrReadBackMismatch
			}
			keyCount++
			if keyCount > 2 {
				return SourceCredentials{}, ErrReadBackMismatch
			}
		}
		if !output.IsTruncated {
			break
		}
		if output.Marker == nil || aws.ToString(output.Marker) == "" {
			return SourceCredentials{}, ErrReadBackMismatch
		}
		marker = output.Marker
	}
	if keyCount != 0 {
		return SourceCredentials{}, ErrSourceCredentialRemediationRequired
	}
	output, err := provider.clients.IAM.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: aws.String(userName)})
	if err != nil {
		return SourceCredentials{}, providerError(ctx, err)
	}
	if output == nil || output.AccessKey == nil || aws.ToString(output.AccessKey.AccessKeyId) == "" || aws.ToString(output.AccessKey.SecretAccessKey) == "" {
		return SourceCredentials{}, ErrReadBackMismatch
	}
	return SourceCredentials{AccessKeyID: []byte(aws.ToString(output.AccessKey.AccessKeyId)), SecretAccessKey: []byte(aws.ToString(output.AccessKey.SecretAccessKey))}, nil
}

func (provider *SDKProvider) CreateFoundationStack(ctx context.Context, request FoundationStackRequest) (FoundationStackReceipt, error) {
	if err := validateStackRequest(request, provider.region); err != nil {
		return FoundationStackReceipt{}, err
	}
	parameters := make([]cloudformationtypes.Parameter, 0, len(request.Parameters))
	keys := sortedMapKeys(request.Parameters)
	for _, key := range keys {
		parameters = append(parameters, cloudformationtypes.Parameter{ParameterKey: aws.String(key), ParameterValue: aws.String(request.Parameters[key])})
	}
	output, err := provider.clients.CloudFormation.CreateStack(ctx, &cloudformation.CreateStackInput{
		StackName: aws.String(request.StackName), TemplateBody: aws.String(request.TemplateBody), ClientRequestToken: aws.String(request.ClientToken),
		Capabilities: []cloudformationtypes.Capability{cloudformationtypes.CapabilityCapabilityNamedIam}, RoleARN: aws.String(request.FoundationRoleARN),
		OnFailure: cloudformationtypes.OnFailureDoNothing, EnableTerminationProtection: aws.Bool(request.TerminationProtect), Parameters: parameters, Tags: cloudFormationTagSet(request.Tags),
	})
	if err == nil && output != nil && aws.ToString(output.StackId) != "" && !validStackARN(aws.ToString(output.StackId), request) {
		return FoundationStackReceipt{}, ErrReadBackMismatch
	}
	if err != nil {
		classified := providerError(ctx, err)
		if errors.Is(classified, ErrPermissionDenied) || errors.Is(classified, context.Canceled) || errors.Is(classified, context.DeadlineExceeded) {
			return FoundationStackReceipt{}, classified
		}
	}
	return provider.waitForFoundationStack(ctx, request)
}

func (provider *SDKProvider) waitForFoundationStack(ctx context.Context, request FoundationStackRequest) (FoundationStackReceipt, error) {
	for {
		receipt, err := provider.recoverFoundationStack(ctx, request)
		if err == nil {
			switch cloudformationtypes.StackStatus(receipt.Status) {
			case cloudformationtypes.StackStatusCreateComplete:
				return receipt, nil
			case cloudformationtypes.StackStatusCreateInProgress, cloudformationtypes.StackStatusReviewInProgress:
				// Keep polling the independently observed CloudFormation state.
			default:
				return FoundationStackReceipt{}, ErrFoundationStackFailed
			}
		} else if errors.Is(err, ErrReadBackMismatch) {
			return FoundationStackReceipt{}, err
		}
		if err := waitForContext(ctx, provider.stackPollInterval); err != nil {
			return FoundationStackReceipt{}, err
		}
	}
}

func waitForContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (provider *SDKProvider) recoverFoundationStack(ctx context.Context, request FoundationStackRequest) (FoundationStackReceipt, error) {
	output, err := provider.clients.CloudFormation.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: aws.String(request.StackName)})
	if err != nil || output == nil || len(output.Stacks) != 1 {
		return FoundationStackReceipt{}, ErrProviderUnavailable
	}
	stack := output.Stacks[0]
	stackID := aws.ToString(stack.StackId)
	if !validStackARN(stackID, request) || aws.ToString(stack.RoleARN) != request.FoundationRoleARN || !sameParameters(request.Parameters, stack.Parameters) || !sameTags(request.Tags, stack.Tags) {
		return FoundationStackReceipt{}, ErrReadBackMismatch
	}
	template, err := provider.clients.CloudFormation.GetTemplate(ctx, &cloudformation.GetTemplateInput{StackName: aws.String(stackID), TemplateStage: cloudformationtypes.TemplateStageOriginal})
	if err != nil || template == nil || template.TemplateBody == nil {
		return FoundationStackReceipt{}, ErrProviderUnavailable
	}
	sum := sha256.Sum256([]byte(aws.ToString(template.TemplateBody)))
	if "sha256:"+hex.EncodeToString(sum[:]) != request.TemplateSHA256 {
		return FoundationStackReceipt{}, ErrReadBackMismatch
	}
	return FoundationStackReceipt{StackID: stackID, Status: string(stack.StackStatus), ObservedAt: provider.now().UTC()}, nil
}

func validateBootstrapSpec(spec BootstrapIdentitySpec, region string) error {
	if spec.Region != region || !sdkRegionPattern.MatchString(spec.Region) || !sdkAccountPattern.MatchString(spec.AccountID) || spec.AgentInstanceID == "" {
		return ErrInvalidRequest
	}
	for _, name := range []string{spec.SourceUserName, spec.ControlRoleName, spec.FoundationRoleName, spec.WorkerRoleName, spec.WorkerProfileName, spec.ReaperRoleName, spec.StackName, spec.ReaperAlarmName} {
		if !sdkNamePattern.MatchString(name) {
			return ErrInvalidRequest
		}
	}
	if len(spec.Tags) == 0 || len(spec.SourceUserPolicy.Statement) == 0 || len(spec.ControlTrustPolicy.Statement) == 0 || len(spec.ControlBaselinePolicy.Statement) == 0 || len(spec.FoundationTrustPolicy.Statement) == 0 || len(spec.FoundationExecutionPolicy.Statement) == 0 {
		return ErrInvalidRequest
	}
	return nil
}

func validateStackRequest(request FoundationStackRequest, region string) error {
	if request.Region != region || !sdkRegionPattern.MatchString(request.Region) || !sdkAccountPattern.MatchString(request.AccountID) || !sdkNamePattern.MatchString(request.StackName) || !strings.HasPrefix(request.ClientToken, "dtx-") || len(request.ClientToken) > 128 || !digestPattern.MatchString(request.TemplateSHA256) || request.TemplateBody == "" || len(request.TemplateBody) > 512*1024 || !request.TerminationProtect {
		return ErrInvalidRequest
	}
	sum := sha256.Sum256([]byte(request.TemplateBody))
	if request.TemplateSHA256 != "sha256:"+hex.EncodeToString(sum[:]) {
		return ErrInvalidRequest
	}
	role, err := arn.Parse(request.FoundationRoleARN)
	if err != nil || role.Service != "iam" || role.AccountID != request.AccountID || role.Resource != "role/"+request.StackName || role.Partition == "" {
		return ErrInvalidRequest
	}
	if len(request.Parameters) == 0 || len(request.Tags) == 0 {
		return ErrInvalidRequest
	}
	for key, value := range request.Parameters {
		if key == "" || value == "" || strings.ContainsAny(key+value, "\x00\r\n") || strings.Contains(strings.ToLower(key), "secretaccesskey") {
			return ErrInvalidRequest
		}
	}
	return nil
}

func validStackARN(value string, request FoundationStackRequest) bool {
	parsed, err := arn.Parse(value)
	if err != nil || parsed.Service != "cloudformation" || parsed.Region != request.Region || parsed.AccountID != request.AccountID || parsed.Partition == "" {
		return false
	}
	parts := strings.Split(parsed.Resource, "/")
	return len(parts) == 3 && parts[0] == "stack" && parts[1] == request.StackName && parts[2] != ""
}

func sameParameters(expected map[string]string, observed []cloudformationtypes.Parameter) bool {
	if len(expected) != len(observed) {
		return false
	}
	actual := make(map[string]string, len(observed))
	for _, value := range observed {
		key := aws.ToString(value.ParameterKey)
		if key == "" || value.ParameterValue == nil {
			return false
		}
		if _, duplicate := actual[key]; duplicate {
			return false
		}
		actual[key] = aws.ToString(value.ParameterValue)
	}
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func sameTags(expected []Tag, observed []cloudformationtypes.Tag) bool {
	actual := make(map[string]string, len(observed))
	for _, tag := range observed {
		key := aws.ToString(tag.Key)
		if strings.HasPrefix(strings.ToLower(key), "aws:") {
			continue
		}
		if key == "" || tag.Value == nil {
			return false
		}
		actual[key] = aws.ToString(tag.Value)
	}
	if len(expected) != len(actual) {
		return false
	}
	for _, tag := range expected {
		if actual[tag.Key] != tag.Value {
			return false
		}
	}
	return true
}

func iamTagSet(tags []Tag) []iamtypes.Tag {
	result := make([]iamtypes.Tag, 0, len(tags))
	for _, tag := range sortedTags(tags) {
		result = append(result, iamtypes.Tag{Key: aws.String(tag.Key), Value: aws.String(tag.Value)})
	}
	return result
}

func cloudFormationTagSet(tags []Tag) []cloudformationtypes.Tag {
	result := make([]cloudformationtypes.Tag, 0, len(tags))
	for _, tag := range sortedTags(tags) {
		result = append(result, cloudformationtypes.Tag{Key: aws.String(tag.Key), Value: aws.String(tag.Value)})
	}
	return result
}

func sortedTags(tags []Tag) []Tag {
	result := append([]Tag(nil), tags...)
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func apiCode(err error, code string) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == code
}

func providerError(ctx context.Context, err error) error {
	if err == nil {
		return ErrProviderUnavailable
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnrecognizedClientException", "InvalidClientTokenId", "SignatureDoesNotMatch":
			return ErrPermissionDenied
		}
	}
	return ErrProviderUnavailable
}
