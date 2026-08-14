package coreaws

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type STSClient interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type STSClientFactory interface {
	NewSTS(CredentialHandle) (STSClient, error)
}

type SDKClients struct{ STS STSClient }

func (clients SDKClients) NewSTS(CredentialHandle) (STSClient, error) {
	if clients.STS == nil {
		return nil, ErrInvalid
	}
	return clients.STS, nil
}

type SDKFactory struct{}

func NewSDKFactory() *SDKFactory { return &SDKFactory{} }

func (*SDKFactory) NewSTS(handle CredentialHandle) (STSClient, error) {
	cfg, err := staticAWSConfig(handle)
	if err != nil {
		return nil, err
	}
	return sts.NewFromConfig(cfg), nil
}

func staticAWSConfig(handle CredentialHandle) (aws.Config, error) {
	if handle.credential == nil || !validRegion(handle.Region) || strings.TrimSpace(handle.credential.accessKeyID) == "" || strings.TrimSpace(handle.credential.secretAccessKey) == "" {
		return aws.Config{}, ErrInvalid
	}
	provider := credentials.NewStaticCredentialsProvider(handle.credential.accessKeyID, handle.credential.secretAccessKey, handle.credential.sessionToken)
	return aws.Config{Region: handle.Region, Credentials: aws.NewCredentialsCache(provider), Retryer: func() aws.Retryer { return aws.NopRetryer{} }}, nil
}

func StaticAWSConfig(handle CredentialHandle) (aws.Config, error) { return staticAWSConfig(handle) }

type SDKProvider struct {
	factory STSClientFactory
	timeout time.Duration
}

func NewSDKProvider(factory STSClientFactory) (*SDKProvider, error) {
	if factory == nil {
		return nil, ErrInvalid
	}
	return &SDKProvider{factory: factory, timeout: 30 * time.Second}, nil
}

func (provider *SDKProvider) GetCallerIdentity(ctx context.Context, handle CredentialHandle) (Identity, error) {
	if provider == nil || provider.factory == nil || !validRegion(handle.Region) || handle.credential == nil {
		return Identity{}, ErrInvalid
	}
	client, err := provider.factory.NewSTS(handle)
	if err != nil {
		return Identity{}, ErrInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}
	callCtx, cancel := context.WithTimeout(ctx, provider.timeout)
	defer cancel()
	out, err := client.GetCallerIdentity(callCtx, &sts.GetCallerIdentityInput{})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return Identity{}, context.Canceled
		}
		return Identity{}, ErrProvider
	}
	if out == nil || out.Account == nil || out.Arn == nil || out.UserId == nil {
		return Identity{}, ErrProvider
	}
	parsed, err := arn.Parse(aws.ToString(out.Arn))
	if err != nil || (parsed.Service != "iam" && parsed.Service != "sts") || !accountIDValid(aws.ToString(out.Account)) || parsed.AccountID != aws.ToString(out.Account) || aws.ToString(out.UserId) == "" || handle.AccountID != "" && handle.AccountID != parsed.AccountID || handle.UserARN != "" && handle.UserARN != parsed.String() {
		return Identity{}, ErrProvider
	}
	return Identity{AccountID: parsed.AccountID, UserARN: parsed.String(), PrincipalID: aws.ToString(out.UserId)}, nil
}

func accountIDValid(account string) bool {
	if len(account) != 12 {
		return false
	}
	for _, value := range account {
		if value < '0' || value > '9' {
			return false
		}
	}
	return true
}
