package awsprovider

import (
	"context"
	"strings"
	"testing"

	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func TestWorkerSecretBinderUsesRoleReadBackAndExactInstanceResourcePolicy(t *testing.T) {
	const (
		roleName     = "dtx-agent-test-worker"
		roleID       = "AROATESTROLEIDENTIFIER"
		instanceID   = "i-0123456789abcdef0"
		deploymentID = "22222222-2222-4222-8222-222222222222"
	)
	roleARN := "arn:aws:iam::123456789012:role/" + roleName
	secretName := "dtx/11111111-1111-4111-8111-111111111111/deployments/" + deploymentID + "/model-token"
	secretARN := "arn:aws:secretsmanager:ap-south-1:123456789012:secret:" + secretName + "-Ab12Cd"
	client := &secretPolicyFake{role: &iam.GetRoleOutput{Role: &iamtypes.Role{Arn: aws.String(roleARN), RoleId: aws.String(roleID), RoleName: aws.String(roleName)}}}
	binder, err := NewWorkerSecretSessionBinder(client, client, "11111111-1111-4111-8111-111111111111", "aws", "123456789012", "ap-south-1", roleName)
	if err != nil {
		t.Fatal(err)
	}
	err = binder.Bind(context.Background(), WorkerSecretBindingRequest{
		InstanceID: instanceID, RoleName: roleName, DeploymentID: deploymentID,
		Secrets: []installerbootstrap.SecretSourceV1{{SchemaVersion: installerbootstrap.SecretSourceSchemaV1, SlotID: "model-token", SecretName: secretName, SecretARN: secretARN}},
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedUserID := roleID + ":" + instanceID
	if client.getRoleName != roleName || client.putSecret != secretARN || !client.blockPublic ||
		!strings.Contains(client.policy, `"StringEquals":{"aws:userid":"`+expectedUserID+`"}`) ||
		!strings.Contains(client.policy, `"StringNotEquals":{"aws:userid":"`+expectedUserID+`"}`) ||
		strings.Contains(client.policy, "deployments/*") {
		t.Fatalf("resource policy was not exact: role=%q secret=%q policy=%s", client.getRoleName, client.putSecret, client.policy)
	}
}

func TestWorkerSecretBinderFailsClosedOnPolicyReadBackDrift(t *testing.T) {
	roleName := "dtx-agent-test-worker"
	client := &secretPolicyFake{
		role: &iam.GetRoleOutput{Role: &iamtypes.Role{
			Arn: aws.String("arn:aws:iam::123456789012:role/" + roleName), RoleId: aws.String("AROATESTROLEIDENTIFIER"), RoleName: aws.String(roleName),
		}},
		readbackDrift: true,
	}
	binder, _ := NewWorkerSecretSessionBinder(client, client, "11111111-1111-4111-8111-111111111111", "aws", "123456789012", "ap-south-1", roleName)
	deploymentID := "22222222-2222-4222-8222-222222222222"
	name := "dtx/11111111-1111-4111-8111-111111111111/deployments/" + deploymentID + "/model-token"
	if err := binder.Bind(context.Background(), WorkerSecretBindingRequest{
		InstanceID: "i-0123456789abcdef0", RoleName: roleName, DeploymentID: deploymentID,
		Secrets: []installerbootstrap.SecretSourceV1{{SchemaVersion: installerbootstrap.SecretSourceSchemaV1, SlotID: "model-token", SecretName: name,
			SecretARN: "arn:aws:secretsmanager:ap-south-1:123456789012:secret:" + name + "-Ab12Cd"}},
	}); err == nil {
		t.Fatal("resource-policy read-back drift was accepted")
	}
}

type secretPolicyFake struct {
	role          *iam.GetRoleOutput
	getRoleName   string
	putSecret     string
	policy        string
	blockPublic   bool
	readbackDrift bool
}

func (fake *secretPolicyFake) GetRole(_ context.Context, input *iam.GetRoleInput, _ ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	fake.getRoleName = aws.ToString(input.RoleName)
	return fake.role, nil
}

func (fake *secretPolicyFake) PutResourcePolicy(_ context.Context, input *secretsmanager.PutResourcePolicyInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutResourcePolicyOutput, error) {
	fake.putSecret, fake.policy, fake.blockPublic = aws.ToString(input.SecretId), aws.ToString(input.ResourcePolicy), aws.ToBool(input.BlockPublicPolicy)
	return &secretsmanager.PutResourcePolicyOutput{ARN: input.SecretId, Name: aws.String("secret")}, nil
}

func (fake *secretPolicyFake) GetResourcePolicy(context.Context, *secretsmanager.GetResourcePolicyInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error) {
	policy := fake.policy
	if fake.readbackDrift {
		policy = `{"Version":"2012-10-17","Statement":[]}`
	}
	return &secretsmanager.GetResourcePolicyOutput{ARN: aws.String(fake.putSecret), ResourcePolicy: aws.String(policy)}, nil
}

func (fake *secretPolicyFake) DescribeSecret(context.Context, *secretsmanager.DescribeSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	resource := strings.TrimPrefix(fake.putSecret, "arn:aws:secretsmanager:ap-south-1:123456789012:secret:")
	name := resource[:len(resource)-7]
	return &secretsmanager.DescribeSecretOutput{ARN: aws.String(fake.putSecret), Name: aws.String(name)}, nil
}
