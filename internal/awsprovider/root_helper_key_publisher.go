package awsprovider

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretstypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"
)

type RootHelperKeySecretsAPI interface {
	WorkerSecretPolicyAPI
	CreateSecret(context.Context, *secretsmanager.CreateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type RootHelperKeyPublisher struct {
	secrets   RootHelperKeySecretsAPI
	kmsKeyARN string
}

func NewRootHelperKeyPublisher(secrets RootHelperKeySecretsAPI, kmsKeyARN string) (*RootHelperKeyPublisher, error) {
	if secrets == nil || kmsKeyARN == "" {
		return nil, ErrInvalidRequest
	}
	return &RootHelperKeyPublisher{secrets: secrets, kmsKeyARN: kmsKeyARN}, nil
}

func (p *RootHelperKeyPublisher) CreateRootHelperKey(ctx context.Context, binding helperkey.DeviceBinding, privateKey []byte) (helperkey.SecretCoordinate, error) {
	if p == nil || len(privateKey) != 64 || binding.Secret != (helperkey.SecretCoordinate{}) {
		return helperkey.SecretCoordinate{}, resource.ErrInvalid
	}
	plan := binding.SecretPlan
	if helperkey.ValidateApprovalBinding(binding, privateKey[32:]) != nil || plan.KMSKeyARN != p.kmsKeyARN {
		return helperkey.SecretCoordinate{}, resource.ErrInvalid
	}
	name := plan.Name
	tags := []secretstypes.Tag{
		{Key: aws.String("dirextalk:agent_instance_id"), Value: aws.String(binding.AgentInstanceID)},
		{Key: aws.String("dirextalk:deployment_id"), Value: aws.String(binding.DeploymentID)},
		{Key: aws.String("dirextalk:secret_slot"), Value: aws.String(helperkey.SecretSlot)},
		{Key: aws.String("dirextalk:component"), Value: aws.String("root-helper-key")},
	}
	input := bytes.Clone(privateKey)
	defer clear(input)
	_, createErr := p.secrets.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name: aws.String(name), KmsKeyId: aws.String(plan.KMSKeyARN), ClientRequestToken: aws.String(plan.VersionID),
		SecretBinary: input, Tags: tags,
	})
	if createErr != nil && !rootHelperResourceExists(createErr) {
		// A lost successful response is reconciled by exact read-back below.
	}
	description, err := p.secrets.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(name)})
	if err != nil || description == nil || aws.ToString(description.Name) != name || aws.ToString(description.KmsKeyId) != plan.KMSKeyARN ||
		!rootHelperVersion(description.VersionIdsToStages, plan.VersionID) || !rootHelperTags(description.Tags, binding) {
		return helperkey.SecretCoordinate{}, resource.ErrReadBack
	}
	secretARN := aws.ToString(description.ARN)
	wantARNPrefix := "arn:" + plan.Partition + ":secretsmanager:" + plan.Region + ":" + plan.AccountID + ":secret:" + name + "-"
	if !strings.HasPrefix(secretARN, wantARNPrefix) {
		return helperkey.SecretCoordinate{}, resource.ErrReadBack
	}
	value, err := p.secrets.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(secretARN), VersionId: aws.String(plan.VersionID)})
	if err != nil || value == nil || aws.ToString(value.ARN) != secretARN || aws.ToString(value.VersionId) != plan.VersionID ||
		value.SecretString != nil || !bytes.Equal(value.SecretBinary, privateKey) {
		if value != nil {
			clear(value.SecretBinary)
		}
		return helperkey.SecretCoordinate{}, resource.ErrReadBack
	}
	clear(value.SecretBinary)
	return helperkey.SecretCoordinate{ARN: secretARN, Name: name, VersionID: plan.VersionID, KMSKeyARN: plan.KMSKeyARN}, nil
}

func (p *RootHelperKeyPublisher) GrantRootHelperKey(ctx context.Context, binding helperkey.DeviceBinding) error {
	if p == nil {
		return resource.ErrInvalid
	}
	policy, err := exactWorkerSessionPolicy(binding.WorkerRoleARN, binding.WorkerPrincipalID, binding.Secret.ARN)
	if err != nil {
		return resource.ErrInvalid
	}
	if _, err = p.secrets.PutResourcePolicy(ctx, &secretsmanager.PutResourcePolicyInput{
		SecretId: aws.String(binding.Secret.ARN), ResourcePolicy: aws.String(policy), BlockPublicPolicy: aws.Bool(true),
	}); err != nil {
		// Reconcile response loss below.
	}
	output, err := p.secrets.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{SecretId: aws.String(binding.Secret.ARN)})
	if err != nil || output == nil || aws.ToString(output.ARN) != binding.Secret.ARN ||
		!sameJSONPolicy(policy, aws.ToString(output.ResourcePolicy)) {
		return resource.ErrReadBack
	}
	return nil
}

func rootHelperResourceExists(err error) bool {
	var api smithy.APIError
	return err != nil && errors.As(err, &api) && api.ErrorCode() == "ResourceExistsException"
}

func rootHelperVersion(values map[string][]string, id string) bool {
	stages, ok := values[id]
	return ok && len(stages) > 0
}

func rootHelperTags(tags []secretstypes.Tag, binding helperkey.DeviceBinding) bool {
	expected := map[string]string{
		"dirextalk:agent_instance_id": binding.AgentInstanceID,
		"dirextalk:deployment_id":     binding.DeploymentID,
		"dirextalk:secret_slot":       helperkey.SecretSlot,
		"dirextalk:component":         "root-helper-key",
	}
	for _, tag := range tags {
		key, value := aws.ToString(tag.Key), aws.ToString(tag.Value)
		if expected[key] == value {
			delete(expected, key)
		}
	}
	return len(expected) == 0
}

var _ helperkey.SecretPublisher = (*RootHelperKeyPublisher)(nil)
