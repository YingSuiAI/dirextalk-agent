package awsartifact

import (
	"context"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
)

type DeploymentSecretLifecycle struct {
	agentInstanceID string
	vault           *awsfoundation.CredentialVault
	factory         SecretsFactory
}

func NewDeploymentSecretLifecycle(agentInstanceID string, vault *awsfoundation.CredentialVault, factory SecretsFactory) (*DeploymentSecretLifecycle, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || parsed == uuid.Nil || vault == nil || factory == nil {
		return nil, ErrInvalidRequest
	}
	return &DeploymentSecretLifecycle{agentInstanceID: parsed.String(), vault: vault, factory: factory}, nil
}

func (lifecycle *DeploymentSecretLifecycle) Destroy(ctx context.Context, connection cloudapp.Connection, operation cloudexecution.Operation) error {
	if len(operation.InstallerSecrets) == 0 {
		return nil
	}
	if lifecycle == nil || ctx == nil || operation.DeploymentID == "" || operation.Launch.OwnerID != connection.OwnerID || operation.ConnectionID != connection.ConnectionID {
		return cloudexecution.ErrUnavailable
	}
	role, err := arn.Parse(connection.ControlRoleARN)
	if err != nil || role.AccountID != connection.AccountID || role.Region != "" {
		return cloudexecution.ErrUnavailable
	}
	source, err := lifecycle.vault.Open(ctx, awsfoundation.SourceCredentialBinding{
		AgentInstanceID: lifecycle.agentInstanceID, AccountID: connection.AccountID, Region: connection.Region,
	})
	if err != nil {
		return cloudexecution.ErrUnavailable
	}
	config, configErr := awsprovider.AssumedControlAWSConfig(connection.Region, &source, connection.ControlRoleARN, artifactRoleSession(operation.DeploymentID))
	source.Wipe()
	if configErr != nil {
		return cloudexecution.ErrUnavailable
	}
	client := lifecycle.factory.NewSecrets(config)
	if client == nil {
		return cloudexecution.ErrUnavailable
	}
	return destroyDeploymentSecrets(ctx, client, lifecycle.agentInstanceID, connection, operation)
}

func destroyDeploymentSecrets(ctx context.Context, client SecretsAPI, agentInstanceID string, connection cloudapp.Connection, operation cloudexecution.Operation) error {
	if ctx == nil || client == nil {
		return cloudexecution.ErrUnavailable
	}
	for _, secret := range operation.InstallerSecrets {
		secretARN, parseErr := arn.Parse(secret.SecretARN)
		if parseErr != nil || secretARN.AccountID != connection.AccountID || secretARN.Region != connection.Region || secretARN.Service != "secretsmanager" ||
			secret.SecretName != "dtx/"+agentInstanceID+"/deployments/"+operation.DeploymentID+"/"+secret.SlotID {
			return cloudexecution.ErrUnavailable
		}
		_, deleteErr := client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
			SecretId: aws.String(secret.SecretARN), ForceDeleteWithoutRecovery: aws.Bool(true),
		})
		if deleteErr != nil && !isSecretMissing(deleteErr) {
			// A previous force-delete may be pending. Only the independent read
			// below can turn that ambiguous response into success.
		}
		if _, readErr := client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(secret.SecretARN)}); !isSecretMissing(readErr) {
			return cloudexecution.ErrUnavailable
		}
	}
	return nil
}

func isSecretMissing(err error) bool {
	var apiErr smithy.APIError
	return err != nil && errors.As(err, &apiErr) && apiErr.ErrorCode() == "ResourceNotFoundException"
}

var _ cloudexecution.DeploymentSecretLifecycle = (*DeploymentSecretLifecycle)(nil)
