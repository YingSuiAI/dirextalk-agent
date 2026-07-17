package bootstrap

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type HelperKeySecretsAccess struct {
	client SecretsAPI
	retry  accessDeniedRetry
}

func NewHelperKeySecretsAccess(client SecretsAPI) (*HelperKeySecretsAccess, error) {
	if client == nil {
		return nil, ErrInvalidInput
	}
	return &HelperKeySecretsAccess{client: client, retry: defaultAccessDeniedRetry()}, nil
}

func (a *HelperKeySecretsAccess) ReadRootHelperKey(ctx context.Context, source RootHelperKeySourceV1) ([]byte, error) {
	if a == nil || a.client == nil || ctx == nil {
		return nil, ErrArtifactSource
	}
	var value []byte
	_, err := retryAccessDenied(ctx, a.retry, func() (struct{}, error) {
		output, err := a.get(ctx, source)
		if err != nil {
			return struct{}{}, err
		}
		value = append([]byte(nil), output.SecretBinary...)
		clear(output.SecretBinary)
		return struct{}{}, nil
	})
	if err != nil {
		clear(value)
		return nil, ErrArtifactSource
	}
	return value, nil
}

// CanaryRootHelperKey deliberately performs the real GetSecretValue call with
// the same SDK credential provider used for bootstrap. Callers must accept
// only an AWS AccessDenied code; a policy read-back or a locally fabricated
// result can never satisfy this boundary.
func (a *HelperKeySecretsAccess) CanaryRootHelperKey(ctx context.Context, source RootHelperKeySourceV1) error {
	if a == nil || a.client == nil || ctx == nil {
		return ErrArtifactSource
	}
	output, err := a.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(source.SecretARN), VersionId: aws.String(source.VersionID),
	})
	if output != nil {
		clear(output.SecretBinary)
	}
	if err != nil {
		return err
	}
	return nil
}

func (a *HelperKeySecretsAccess) get(ctx context.Context, source RootHelperKeySourceV1) (*secretsmanager.GetSecretValueOutput, error) {
	description, err := a.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(source.SecretARN)})
	if err != nil {
		return nil, err
	}
	if description == nil || aws.ToString(description.ARN) != source.SecretARN ||
		aws.ToString(description.Name) != source.SecretName || aws.ToString(description.KmsKeyId) != source.KMSKeyARN ||
		!secretVersionPresent(description.VersionIdsToStages, source.VersionID) {
		return nil, ErrArtifactSource
	}
	output, err := a.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(source.SecretARN), VersionId: aws.String(source.VersionID),
	})
	if err != nil {
		return nil, err
	}
	if output == nil || aws.ToString(output.ARN) != source.SecretARN || aws.ToString(output.Name) != source.SecretName ||
		aws.ToString(output.VersionId) != source.VersionID || len(output.SecretBinary) != 64 || output.SecretString != nil {
		if output != nil {
			clear(output.SecretBinary)
		}
		return nil, ErrArtifactSource
	}
	return output, nil
}
