package roothelper

import (
	"context"

	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type SecretsAPI interface {
	DescribeSecret(context.Context, *secretsmanager.DescribeSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type ExactSecretsAccess struct{ client SecretsAPI }

func NewExactSecretsAccess(client SecretsAPI) (*ExactSecretsAccess, error) {
	if client == nil {
		return nil, ErrInvalid
	}
	return &ExactSecretsAccess{client: client}, nil
}

func (access *ExactSecretsAccess) ReadRootHelperKey(ctx context.Context, binding helperkey.DeviceBinding) ([]byte, error) {
	if access == nil || access.client == nil || ctx == nil {
		return nil, ErrUnavailable
	}
	coordinate := binding.Secret
	description, err := access.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(coordinate.ARN)})
	if err != nil || description == nil || aws.ToString(description.ARN) != coordinate.ARN ||
		aws.ToString(description.Name) != coordinate.Name || aws.ToString(description.KmsKeyId) != coordinate.KMSKeyARN ||
		!versionPresent(description.VersionIdsToStages, coordinate.VersionID) {
		return nil, ErrUnavailable
	}
	output, err := access.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(coordinate.ARN), VersionId: aws.String(coordinate.VersionID),
	})
	if err != nil || output == nil || aws.ToString(output.ARN) != coordinate.ARN ||
		aws.ToString(output.Name) != coordinate.Name || aws.ToString(output.VersionId) != coordinate.VersionID ||
		len(output.SecretBinary) != 64 || output.SecretString != nil {
		if output != nil {
			clear(output.SecretBinary)
		}
		return nil, ErrUnavailable
	}
	value := append([]byte(nil), output.SecretBinary...)
	clear(output.SecretBinary)
	return value, nil
}

// CanaryRootHelperKey deliberately performs the real GetSecretValue request.
// The handler, not this adapter, decides whether the returned AWS error is the
// exact AccessDenied condition required to activate the key.
func (access *ExactSecretsAccess) CanaryRootHelperKey(ctx context.Context, binding helperkey.DeviceBinding) error {
	if access == nil || access.client == nil || ctx == nil {
		return ErrUnavailable
	}
	output, err := access.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(binding.Secret.ARN), VersionId: aws.String(binding.Secret.VersionID),
	})
	if output != nil {
		clear(output.SecretBinary)
	}
	return err
}

func versionPresent(versions map[string][]string, versionID string) bool {
	stages, ok := versions[versionID]
	return ok && len(stages) != 0
}
