package awsartifact

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretstypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"
)

const maximumDeploymentSecretBytes = 64 << 10

type SecretsAPI interface {
	CreateSecret(context.Context, *secretsmanager.CreateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	DeleteSecret(context.Context, *secretsmanager.DeleteSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error)
	DescribeSecret(context.Context, *secretsmanager.DescribeSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type KMSAPI interface {
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

type SecretsFactory interface {
	NewSecrets(aws.Config) SecretsAPI
	NewKMS(aws.Config) KMSAPI
}

type secretPublicationRequest struct {
	AgentInstanceID string
	OwnerID         string
	AccountID       string
	Region          string
	DeploymentID    string
	KMSAlias        string
	Staging         []cloudexecution.InstallerSecretStagingInput
}

func validateInstallerSecretStaging(compiled cloudexecution.CompiledBundles, requested []string, deploymentID string) (map[string]string, []string, error) {
	if len(requested) == 0 && len(compiled.InstallerSecrets) == 0 {
		return map[string]string{}, []string{}, nil
	}
	if compiled.InstallerRootTrust == nil || len(requested) != len(compiled.InstallerSecrets) ||
		len(compiled.InstallerSecrets) != len(compiled.InstallerRootTrust.ArtifactManifest.Manifest.Secrets) {
		return nil, nil, ErrSecretReferencesUnsupported
	}
	expected := make(map[string]struct{}, len(requested))
	for _, reference := range requested {
		if strings.TrimSpace(reference) == "" {
			return nil, nil, ErrInvalidRequest
		}
		expected[reference] = struct{}{}
	}
	if len(expected) != len(requested) {
		return nil, nil, ErrInvalidRequest
	}
	manifest := make(map[string]struct {
		name, version, target string
		mode, uid, gid        uint32
	}, len(compiled.InstallerRootTrust.ArtifactManifest.Manifest.Secrets))
	for _, declaration := range compiled.InstallerRootTrust.ArtifactManifest.Manifest.Secrets {
		manifest[declaration.SecretRef] = struct {
			name, version, target string
			mode, uid, gid        uint32
		}{declaration.SecretName, declaration.VersionID, declaration.TargetPath, declaration.FileMode, declaration.OwnerUID, declaration.OwnerGID}
	}
	bindings := make(map[string]string, len(requested))
	bound := make([]string, 0, len(requested))
	seenSlots := make(map[string]struct{}, len(requested))
	for _, staging := range compiled.InstallerSecrets {
		declaration, ok := manifest[staging.SecretRef]
		_, approved := expected[staging.SecretRef]
		if !ok || !approved || staging.Content == nil || staging.SecretName != declaration.name || staging.VersionID != declaration.version ||
			staging.TargetPath != declaration.target || staging.FileMode != declaration.mode || staging.OwnerUID != declaration.uid || staging.OwnerGID != declaration.gid ||
			staging.RecipeDigest != compiled.InstallerRootTrust.ArtifactManifest.Manifest.Binding.RecipeDigest {
			return nil, nil, ErrInvalidRequest
		}
		if _, duplicate := seenSlots[staging.SlotID]; duplicate {
			return nil, nil, ErrInvalidRequest
		}
		seenSlots[staging.SlotID] = struct{}{}
		resolved := "secret://aws/deployments/" + deploymentID + "/" + staging.SlotID + "/" + staging.VersionID
		bindings[staging.SecretRef] = resolved
		bound = append(bound, resolved)
	}
	sort.Strings(bound)
	return bindings, bound, nil
}

func publishInstallerSecrets(ctx context.Context, secretsClient SecretsAPI, kmsClient KMSAPI, request secretPublicationRequest) ([]installerbootstrap.SecretSourceV1, error) {
	if len(request.Staging) == 0 {
		return nil, nil
	}
	if ctx == nil || secretsClient == nil || kmsClient == nil {
		return nil, ErrArtifactUnavailable
	}
	key, err := kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(request.KMSAlias)})
	if err != nil || key == nil || key.KeyMetadata == nil || aws.ToString(key.KeyMetadata.Arn) == "" {
		return nil, ErrArtifactUnavailable
	}
	keyARN := aws.ToString(key.KeyMetadata.Arn)
	parsedKey, err := arn.Parse(keyARN)
	if err != nil || parsedKey.Service != "kms" || parsedKey.Region != request.Region || parsedKey.AccountID != request.AccountID || !strings.HasPrefix(parsedKey.Resource, "key/") {
		return nil, ErrArtifactUnavailable
	}
	result := make([]installerbootstrap.SecretSourceV1, 0, len(request.Staging))
	for _, staging := range request.Staging {
		tags := []secretstypes.Tag{
			{Key: aws.String("dirextalk:agent_instance_id"), Value: aws.String(request.AgentInstanceID)},
			{Key: aws.String("dirextalk:owner_id"), Value: aws.String(request.OwnerID)},
			{Key: aws.String("dirextalk:deployment_id"), Value: aws.String(request.DeploymentID)},
			{Key: aws.String("dirextalk:secret_slot"), Value: aws.String(staging.SlotID)},
			{Key: aws.String("dirextalk:component"), Value: aws.String("deployment-secret")},
		}
		var source installerbootstrap.SecretSourceV1
		if err := staging.Content.Materialize(ctx, func(plaintext []byte) error {
			if len(plaintext) == 0 || len(plaintext) > maximumDeploymentSecretBytes {
				return ErrSecretMaterial
			}
			inputValue := bytes.Clone(plaintext)
			defer clear(inputValue)
			_, createErr := secretsClient.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
				Name: aws.String(staging.SecretName), KmsKeyId: aws.String(keyARN), ClientRequestToken: aws.String(staging.VersionID),
				SecretBinary: inputValue, Tags: tags,
			})
			if createErr != nil && !resourceExists(createErr) {
				// A lost response is reconciled below. Any mismatch remains fatal.
			}
			var verifyErr error
			source, verifyErr = readBackPublishedSecret(ctx, secretsClient, request, staging, keyARN, plaintext, true)
			return verifyErr
		}); err != nil {
			return nil, ErrArtifactUnavailable
		}
		if source.SecretARN == "" {
			source, err = readBackPublishedSecret(ctx, secretsClient, request, staging, keyARN, nil, false)
			if err != nil {
				return nil, ErrArtifactUnavailable
			}
		}
		if err := staging.Content.Commit(ctx, func() error {
			_, verifyErr := readBackPublishedSecret(ctx, secretsClient, request, staging, keyARN, nil, false)
			return verifyErr
		}); err != nil {
			return nil, ErrArtifactUnavailable
		}
		result = append(result, source)
	}
	return result, nil
}

func readBackPublishedSecret(ctx context.Context, client SecretsAPI, request secretPublicationRequest, staging cloudexecution.InstallerSecretStagingInput, keyARN string, expected []byte, compareValue bool) (installerbootstrap.SecretSourceV1, error) {
	description, err := client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(staging.SecretName)})
	if err != nil || description == nil || aws.ToString(description.Name) != staging.SecretName || aws.ToString(description.KmsKeyId) != keyARN ||
		!secretVersionExists(description.VersionIdsToStages, staging.VersionID) || !publishedSecretTags(description.Tags, request, staging) {
		return installerbootstrap.SecretSourceV1{}, ErrArtifactUnavailable
	}
	secretARN := aws.ToString(description.ARN)
	parsed, parseErr := arn.Parse(secretARN)
	if parseErr != nil || parsed.Service != "secretsmanager" || parsed.Region != request.Region || parsed.AccountID != request.AccountID ||
		!strings.HasPrefix(parsed.Resource, "secret:"+staging.SecretName+"-") {
		return installerbootstrap.SecretSourceV1{}, ErrArtifactUnavailable
	}
	if compareValue {
		value, valueErr := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(secretARN), VersionId: aws.String(staging.VersionID)})
		if valueErr != nil || value == nil || aws.ToString(value.ARN) != secretARN || aws.ToString(value.VersionId) != staging.VersionID ||
			value.SecretString != nil || !bytes.Equal(value.SecretBinary, expected) {
			if value != nil {
				clear(value.SecretBinary)
			}
			return installerbootstrap.SecretSourceV1{}, ErrArtifactUnavailable
		}
		clear(value.SecretBinary)
	}
	return installerbootstrap.SecretSourceV1{
		SchemaVersion: installerbootstrap.SecretSourceSchemaV1, SlotID: staging.SlotID, SecretRef: staging.SecretRef,
		SecretARN: secretARN, SecretName: staging.SecretName, VersionID: staging.VersionID, KMSKeyARN: keyARN,
		TargetPath: staging.TargetPath, FileMode: staging.FileMode, OwnerUID: staging.OwnerUID, OwnerGID: staging.OwnerGID,
		RecipeDigest: staging.RecipeDigest,
	}, nil
}

func secretVersionExists(versions map[string][]string, versionID string) bool {
	stages, ok := versions[versionID]
	return ok && len(stages) != 0
}

func publishedSecretTags(tags []secretstypes.Tag, request secretPublicationRequest, staging cloudexecution.InstallerSecretStagingInput) bool {
	expected := map[string]string{
		"dirextalk:agent_instance_id": request.AgentInstanceID, "dirextalk:owner_id": request.OwnerID,
		"dirextalk:deployment_id": request.DeploymentID, "dirextalk:secret_slot": staging.SlotID,
		"dirextalk:component": "deployment-secret",
	}
	actual := make(map[string]string, len(tags))
	for _, tag := range tags {
		actual[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func resourceExists(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "ResourceExistsException"
}
