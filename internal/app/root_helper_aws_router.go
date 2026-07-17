package app

import (
	"context"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type rootHelperSecretsAPI interface {
	awsprovider.RootHelperKeySecretsAPI
	awsprovider.RootHelperKeyPolicyAPI
}

type rootHelperSecretsFactory interface {
	NewRootHelperSecrets(aws.Config) rootHelperSecretsAPI
}

type sdkRootHelperSecretsFactory struct{}

func (sdkRootHelperSecretsFactory) NewRootHelperSecrets(config aws.Config) rootHelperSecretsAPI {
	return secretsmanager.NewFromConfig(config)
}

type rootHelperAWSRouter struct {
	agentInstanceID string
	current         cloudstatus.Reader
	vault           *awsfoundation.CredentialVault
	factory         rootHelperSecretsFactory
}

func (router *rootHelperAWSRouter) CreateRootHelperKey(ctx context.Context, binding helperkey.DeviceBinding,
	privateKey []byte) (helperkey.SecretCoordinate, error) {
	client, err := router.client(ctx, binding)
	if err != nil {
		return helperkey.SecretCoordinate{}, err
	}
	publisher, err := awsprovider.NewRootHelperKeyPublisher(client, binding.SecretPlan.KMSKeyARN)
	if err != nil {
		return helperkey.SecretCoordinate{}, helperkey.ErrUnavailable
	}
	return publisher.CreateRootHelperKey(ctx, binding, privateKey)
}

func (router *rootHelperAWSRouter) GrantRootHelperKey(ctx context.Context, binding helperkey.DeviceBinding) error {
	client, err := router.client(ctx, binding)
	if err != nil {
		return err
	}
	publisher, err := awsprovider.NewRootHelperKeyPublisher(client, binding.SecretPlan.KMSKeyARN)
	if err != nil {
		return helperkey.ErrUnavailable
	}
	return publisher.GrantRootHelperKey(ctx, binding)
}

func (router *rootHelperAWSRouter) DenyRootHelperKey(ctx context.Context, binding helperkey.DeviceBinding) error {
	client, err := router.client(ctx, binding)
	if err != nil {
		return err
	}
	revoker, err := awsprovider.NewRootHelperKeyRevoker(client)
	if err != nil {
		return helperkey.ErrUnavailable
	}
	return revoker.DenyRootHelperKey(ctx, binding)
}

func (router *rootHelperAWSRouter) ReadBackRootHelperKeyDenied(ctx context.Context, binding helperkey.DeviceBinding) (bool, error) {
	client, err := router.client(ctx, binding)
	if err != nil {
		return false, err
	}
	revoker, err := awsprovider.NewRootHelperKeyRevoker(client)
	if err != nil {
		return false, helperkey.ErrUnavailable
	}
	return revoker.ReadBackRootHelperKeyDenied(ctx, binding)
}

func (router *rootHelperAWSRouter) client(ctx context.Context, binding helperkey.DeviceBinding) (rootHelperSecretsAPI, error) {
	if router == nil || router.current == nil || router.vault == nil || router.factory == nil ||
		binding.AgentInstanceID != router.agentInstanceID {
		return nil, helperkey.ErrUnavailable
	}
	deployment, err := router.current.GetDeployment(ctx, binding.OwnerID, binding.DeploymentID)
	if err != nil || deployment.Worker.Revision != binding.BindingRevision || deployment.ConnectionID == "" {
		return nil, helperkey.ErrConflict
	}
	connection, err := router.current.GetConnection(ctx, binding.OwnerID, deployment.ConnectionID)
	if err != nil || connection.Status != "active" || connection.AccountID != binding.SecretPlan.AccountID ||
		connection.Region != binding.SecretPlan.Region {
		return nil, helperkey.ErrConflict
	}
	source, err := router.vault.Open(ctx, awsfoundation.SourceCredentialBinding{
		AgentInstanceID: router.agentInstanceID, AccountID: connection.AccountID, Region: connection.Region,
	})
	if err != nil {
		return nil, helperkey.ErrUnavailable
	}
	config, configErr := awsprovider.AssumedControlAWSConfig(connection.Region, &source, connection.ControlRoleARN,
		"dtx-helper-"+strings.ReplaceAll(binding.DeliveryID, "-", "")[:12])
	source.Wipe()
	if configErr != nil {
		return nil, helperkey.ErrUnavailable
	}
	client := router.factory.NewRootHelperSecrets(config)
	if client == nil {
		return nil, helperkey.ErrUnavailable
	}
	return client, nil
}

var _ helperkey.SecretPublisher = (*rootHelperAWSRouter)(nil)
var _ helperkey.SecretRevoker = (*rootHelperAWSRouter)(nil)
