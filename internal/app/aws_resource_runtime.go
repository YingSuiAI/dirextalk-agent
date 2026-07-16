package app

import (
	"context"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsreaper"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/google/uuid"
)

type awsResourceRuntimeFactory struct {
	agentInstanceID string
	vault           *awsfoundation.CredentialVault
	resourceStore   *postgres.ResourceStore
}

type awsLifecycleFactory struct {
	repository resource.Repository
	runtimes   interface {
		Runtime(context.Context, cloudapp.Connection) (resource.Provider, resource.ManifestMirror, error)
	}
}

func newAWSResourceRuntimeFactory(agentInstanceID string, vault *awsfoundation.CredentialVault, resourceStore *postgres.ResourceStore) (*awsResourceRuntimeFactory, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || parsed == uuid.Nil || vault == nil || resourceStore == nil {
		return nil, cloudapp.ErrInvalid
	}
	return &awsResourceRuntimeFactory{agentInstanceID: parsed.String(), vault: vault, resourceStore: resourceStore}, nil
}

func (factory *awsResourceRuntimeFactory) Runtime(ctx context.Context, connection cloudapp.Connection) (resource.Provider, resource.ManifestMirror, error) {
	role, err := arn.Parse(connection.ControlRoleARN)
	if factory == nil || err != nil || role.Service != "iam" || role.AccountID != connection.AccountID || connection.Status != "active" {
		return nil, nil, cloudapp.ErrInvalid
	}
	foundation, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{
		AgentInstanceID: factory.agentInstanceID, Partition: role.Partition,
		AccountID: connection.AccountID, Region: connection.Region,
	})
	if err != nil || role.Resource != "role/"+foundation.ControlRoleName {
		return nil, nil, cloudapp.ErrInvalid
	}
	source, err := factory.vault.Open(ctx, awsfoundation.SourceCredentialBinding{
		AgentInstanceID: factory.agentInstanceID, AccountID: connection.AccountID, Region: connection.Region,
	})
	if err != nil {
		return nil, nil, cloudapp.ErrUnavailable
	}
	config, configErr := awsprovider.AssumedControlAWSConfig(
		connection.Region, &source, connection.ControlRoleARN,
		"dtx-resource-"+strings.ReplaceAll(uuid.NewString(), "-", "")[:20],
	)
	source.Wipe()
	if configErr != nil {
		return nil, nil, cloudapp.ErrUnavailable
	}
	provider, err := awsprovider.NewEC2ResourceProviderFromConfig(config)
	if err != nil {
		return nil, nil, cloudapp.ErrUnavailable
	}
	remoteMirror, err := awsreaper.NewDynamoManifestStore(dynamodb.NewFromConfig(config), foundation.ManifestTableName, factory.agentInstanceID)
	if err != nil {
		return nil, nil, cloudapp.ErrUnavailable
	}
	mirror, err := postgres.NewTrackedResourceManifestMirror(factory.resourceStore, remoteMirror)
	if err != nil {
		return nil, nil, cloudapp.ErrUnavailable
	}
	return provider, mirror, nil
}

func (factory *awsResourceRuntimeFactory) WorkerIdentityVerifier(ctx context.Context, connection cloudapp.Connection) (awsprovider.WorkerInstanceIdentityVerifier, error) {
	provider, _, err := factory.Runtime(ctx, connection)
	if err != nil {
		return nil, err
	}
	verifier, ok := provider.(awsprovider.WorkerInstanceIdentityVerifier)
	if !ok {
		return nil, cloudapp.ErrUnavailable
	}
	return verifier, nil
}

func (factory awsLifecycleFactory) ForConnection(ctx context.Context, connection cloudapp.Connection) (cloudexecution.ResourceLifecycle, error) {
	if factory.repository == nil || factory.runtimes == nil {
		return nil, cloudapp.ErrUnavailable
	}
	provider, mirror, err := factory.runtimes.Runtime(ctx, connection)
	if err != nil {
		return nil, err
	}
	service, err := resource.NewService(factory.repository, provider, mirror)
	if err != nil {
		return nil, cloudapp.ErrUnavailable
	}
	return service, nil
}
