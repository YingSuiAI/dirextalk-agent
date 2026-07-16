package awsprovider

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const controlSessionDuration = 15 * time.Minute

var roleSessionPattern = regexp.MustCompile(`^dtx-[A-Za-z0-9+=,.@_-]{1,60}$`)

type AssumeRoleAPI interface {
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

// AssumedControlAWSConfig creates the daily SDK configuration. The persisted
// source IAM key can do only sts:AssumeRole; every AWS service client receives
// a cached 15-minute Control Role session rather than the long-lived key.
func AssumedControlAWSConfig(region string, source *SourceCredentials, controlRoleARN, roleSessionName string) (aws.Config, error) {
	base, err := sourceAWSConfig(region, source)
	if err != nil {
		return aws.Config{}, err
	}
	return assumedControlAWSConfigWithSTS(base, controlRoleARN, roleSessionName, sts.NewFromConfig(base))
}

// AssumedControlAWSConfigWithSTS is the injected AWS SDK seam used by contract
// tests. It remains internal to this Go module and does not expose a raw STS
// operation to RuntimeService, Eino, MCP, or Skills.
func AssumedControlAWSConfigWithSTS(region string, source *SourceCredentials, controlRoleARN, roleSessionName string, client AssumeRoleAPI) (aws.Config, error) {
	base, err := sourceAWSConfig(region, source)
	if err != nil {
		return aws.Config{}, err
	}
	return assumedControlAWSConfigWithSTS(base, controlRoleARN, roleSessionName, client)
}

func sourceAWSConfig(region string, source *SourceCredentials) (aws.Config, error) {
	if !sdkRegionPattern.MatchString(region) || source == nil || !accessKeyPattern.Match(source.AccessKeyID) || len(source.SecretAccessKey) < 20 || len(source.SecretAccessKey) > 128 {
		return aws.Config{}, ErrInvalidCredentials
	}
	provider := credentials.NewStaticCredentialsProvider(string(source.AccessKeyID), string(source.SecretAccessKey), "")
	return aws.Config{Region: region, Credentials: aws.NewCredentialsCache(provider), RetryMode: aws.RetryModeStandard, RetryMaxAttempts: 3}, nil
}

func assumedControlAWSConfigWithSTS(base aws.Config, controlRoleARN, roleSessionName string, client AssumeRoleAPI) (aws.Config, error) {
	parsed, err := arn.Parse(controlRoleARN)
	if err != nil || client == nil || parsed.Service != "iam" || !sdkAccountPattern.MatchString(parsed.AccountID) || !strings.HasPrefix(parsed.Resource, "role/dtx-agent-") || !strings.HasSuffix(parsed.Resource, "-control") || !roleSessionPattern.MatchString(roleSessionName) {
		return aws.Config{}, ErrInvalidRequest
	}
	provider := stscreds.NewAssumeRoleProvider(client, controlRoleARN, func(options *stscreds.AssumeRoleOptions) {
		options.Duration = controlSessionDuration
		options.RoleSessionName = roleSessionName
	})
	base.Credentials = aws.NewCredentialsCache(redactingCredentialsProvider{inner: provider})
	return base, nil
}

type redactingCredentialsProvider struct {
	inner aws.CredentialsProvider
}

func (provider redactingCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	credentials, err := provider.inner.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, providerError(ctx, err)
	}
	if credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" || !credentials.CanExpire || credentials.Expires.IsZero() {
		return aws.Credentials{}, ErrReadBackMismatch
	}
	return credentials, nil
}
