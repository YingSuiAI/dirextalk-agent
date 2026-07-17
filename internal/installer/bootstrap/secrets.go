package bootstrap

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretstypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

const maxSecretBytes = 64 << 10

type SecretsAPI interface {
	DescribeSecret(context.Context, *secretsmanager.DescribeSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type SecretsDownloader struct {
	client SecretsAPI
	retry  accessDeniedRetry
}

func NewSecretsDownloader(client SecretsAPI) (*SecretsDownloader, error) {
	return newSecretsDownloaderWithRetry(client, defaultAccessDeniedRetry())
}

func newSecretsDownloaderWithRetry(client SecretsAPI, retry accessDeniedRetry) (*SecretsDownloader, error) {
	if client == nil || !retry.valid() {
		return nil, ErrInvalidInput
	}
	return &SecretsDownloader{client: client, retry: retry}, nil
}

func (downloader *SecretsDownloader) Read(ctx context.Context, source SecretSourceV1) (SecretDownload, error) {
	if downloader == nil || downloader.client == nil || ctx == nil || source.SchemaVersion != SecretSourceSchemaV1 ||
		source.SecretARN == "" || source.SecretName == "" || source.VersionID == "" || source.KMSKeyARN == "" || source.TargetPath == "" {
		return SecretDownload{}, ErrArtifactSource
	}
	download, err := retryAccessDenied(ctx, downloader.retry, func() (SecretDownload, error) {
		return downloader.readOnce(ctx, source)
	})
	if err != nil {
		clear(download.Value)
		return SecretDownload{}, ErrArtifactSource
	}
	return download, nil
}

func (downloader *SecretsDownloader) readOnce(ctx context.Context, source SecretSourceV1) (SecretDownload, error) {
	description, err := downloader.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(source.SecretARN)})
	if err != nil {
		return SecretDownload{}, err
	}
	if description == nil || aws.ToString(description.ARN) != source.SecretARN || aws.ToString(description.Name) != source.SecretName ||
		aws.ToString(description.KmsKeyId) != source.KMSKeyARN || !secretVersionPresent(description.VersionIdsToStages, source.VersionID) ||
		!exactSecretTags(description.Tags, source) {
		return SecretDownload{}, ErrArtifactSource
	}
	output, err := downloader.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(source.SecretARN), VersionId: aws.String(source.VersionID),
	})
	if err != nil {
		return SecretDownload{}, err
	}
	if output == nil || aws.ToString(output.ARN) != source.SecretARN || aws.ToString(output.Name) != source.SecretName ||
		aws.ToString(output.VersionId) != source.VersionID || len(output.SecretBinary) == 0 || len(output.SecretBinary) > maxSecretBytes || output.SecretString != nil {
		if output != nil {
			clear(output.SecretBinary)
		}
		return SecretDownload{}, ErrArtifactSource
	}
	value := append([]byte(nil), output.SecretBinary...)
	clear(output.SecretBinary)
	return SecretDownload{Value: value}, nil
}

func secretVersionPresent(versions map[string][]string, versionID string) bool {
	stages, ok := versions[versionID]
	return ok && len(stages) != 0
}

func exactSecretTags(tags []secretstypes.Tag, source SecretSourceV1) bool {
	expected := map[string]string{
		"dirextalk:agent_instance_id": strings.Split(strings.TrimPrefix(source.SecretName, "dtx/"), "/")[0],
		"dirextalk:deployment_id":     secretDeploymentID(source.SecretName),
		"dirextalk:secret_slot":       source.SlotID,
	}
	actual := make(map[string]string, len(tags))
	for _, tag := range tags {
		actual[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	for key, value := range expected {
		if value == "" || actual[key] != value {
			return false
		}
	}
	return true
}

func secretDeploymentID(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) != 5 || parts[0] != "dtx" || parts[2] != "deployments" {
		return ""
	}
	return parts[3]
}
