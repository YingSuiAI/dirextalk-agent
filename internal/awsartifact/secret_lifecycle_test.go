package awsartifact

import (
	"context"
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go"
)

func TestDeploymentSecretDestroyRequiresResourceNotFoundReadBack(t *testing.T) {
	agentID, operation, connection := secretDestroyFixture()
	client := &destroySecretsFake{describeErr: &smithy.GenericAPIError{Code: "ResourceNotFoundException", Message: "missing"}}
	if err := destroyDeploymentSecrets(context.Background(), client, agentID, connection, operation); err != nil {
		t.Fatal(err)
	}
	if client.deletedARN != operation.InstallerSecrets[0].SecretARN || !client.forceDelete {
		t.Fatalf("delete request was not exact: arn=%q force=%v", client.deletedARN, client.forceDelete)
	}

	client = &destroySecretsFake{description: &secretsmanager.DescribeSecretOutput{ARN: aws.String(operation.InstallerSecrets[0].SecretARN)}}
	if err := destroyDeploymentSecrets(context.Background(), client, agentID, connection, operation); !errors.Is(err, cloudexecution.ErrUnavailable) {
		t.Fatalf("still-existing secret read-back = %v", err)
	}
}

func secretDestroyFixture() (string, cloudexecution.Operation, cloudapp.Connection) {
	agentID, deploymentID := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	name := "dtx/" + agentID + "/deployments/" + deploymentID + "/model-token"
	connection := cloudapp.Connection{ConnectionID: "33333333-3333-4333-8333-333333333333", OwnerID: "owner-1", AccountID: "123456789012", Region: "ap-south-1"}
	operation := cloudexecution.Operation{Intent: cloudexecution.Intent{
		DeploymentID: deploymentID, ConnectionID: connection.ConnectionID, Launch: cloudexecution.LaunchRequest{OwnerID: connection.OwnerID},
	}, InstallerSecrets: []installerbootstrap.SecretSourceV1{{
		SchemaVersion: installerbootstrap.SecretSourceSchemaV1, SlotID: "model-token", SecretName: name,
		SecretARN: "arn:aws:secretsmanager:ap-south-1:123456789012:secret:" + name + "-Ab12Cd",
	}}}
	return agentID, operation, connection
}

type destroySecretsFake struct {
	deletedARN  string
	forceDelete bool
	description *secretsmanager.DescribeSecretOutput
	describeErr error
}

func (*destroySecretsFake) CreateSecret(context.Context, *secretsmanager.CreateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	return nil, errors.New("unexpected create")
}

func (fake *destroySecretsFake) DeleteSecret(_ context.Context, input *secretsmanager.DeleteSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error) {
	fake.deletedARN, fake.forceDelete = aws.ToString(input.SecretId), aws.ToBool(input.ForceDeleteWithoutRecovery)
	return &secretsmanager.DeleteSecretOutput{ARN: input.SecretId}, nil
}

func (fake *destroySecretsFake) DescribeSecret(context.Context, *secretsmanager.DescribeSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	return fake.description, fake.describeErr
}

func (*destroySecretsFake) GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return nil, errors.New("unexpected get")
}
