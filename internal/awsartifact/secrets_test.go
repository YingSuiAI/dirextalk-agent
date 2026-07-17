package awsartifact

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretstypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/google/uuid"
)

func TestPublishInstallerSecretUsesExactVersionReadBackAndClearsSDKBuffers(t *testing.T) {
	request, staging := secretPublicationFixture()
	client := &memorySecrets{}
	keyARN := "arn:aws:kms:ap-south-1:123456789012:key/11111111-2222-4333-8444-555555555555"
	result, err := publishInstallerSecrets(context.Background(), client, staticKMS{arn: keyARN}, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].VersionID != staging.VersionID || result[0].SecretARN == "" || result[0].KMSKeyARN != keyARN {
		t.Fatalf("published secret source = %+v", result)
	}
	if client.createVersion != staging.VersionID || client.getVersion != staging.VersionID || client.createName != staging.SecretName {
		t.Fatalf("AWS secret mutation was not exact: name=%q create=%q get=%q", client.createName, client.createVersion, client.getVersion)
	}
	if !allBytesZero(client.createBuffer) || !allBytesZero(client.getBuffer) {
		t.Fatal("AWS SDK input/output retained deployment secret plaintext")
	}
	content := staging.Content.(*memorySecretContent)
	if content.materializeCalls != 1 || content.commitCalls != 1 {
		t.Fatalf("one-use lifecycle calls = %d/%d", content.materializeCalls, content.commitCalls)
	}
}

func TestPublishInstallerSecretDoesNotConsumeWhenExactReadBackFails(t *testing.T) {
	request, staging := secretPublicationFixture()
	client := &memorySecrets{wrongVersion: true}
	_, err := publishInstallerSecrets(context.Background(), client, staticKMS{arn: "arn:aws:kms:ap-south-1:123456789012:key/11111111-2222-4333-8444-555555555555"}, request)
	if !errors.Is(err, ErrArtifactUnavailable) {
		t.Fatalf("read-back failure = %v", err)
	}
	if staging.Content.(*memorySecretContent).commitCalls != 0 {
		t.Fatal("bootstrap session was consumed after failed AWS read-back")
	}
}

func TestInstallerSecretStagingRequiresApprovedManifestExactMatch(t *testing.T) {
	request, staging := secretPublicationFixture()
	root := &installerbootstrap.RootTrustMaterialV1{ArtifactManifest: installer.SignedArtifactManifestV1{Manifest: installer.ArtifactManifestV1{
		Binding: installer.BindingV1{DeploymentID: request.DeploymentID, RecipeDigest: staging.RecipeDigest},
		Secrets: []installer.SecretV1{{
			SlotID: staging.SlotID, SecretRef: staging.SecretRef, SecretName: staging.SecretName, VersionID: staging.VersionID,
			TargetPath: staging.TargetPath, FileMode: staging.FileMode, OwnerUID: staging.OwnerUID, OwnerGID: staging.OwnerGID,
		}},
	}}}
	compiled := cloudexecution.CompiledBundles{InstallerRootTrust: root, InstallerSecrets: request.Staging}
	bindings, refs, err := validateInstallerSecretStaging(compiled, []string{staging.SecretRef}, request.DeploymentID)
	if err != nil || len(refs) != 1 || bindings[staging.SecretRef] != refs[0] {
		t.Fatalf("valid staging rejected: bindings=%v refs=%v error=%v", bindings, refs, err)
	}
	compiled.InstallerSecrets[0].VersionID = uuid.NewString()
	if _, _, err := validateInstallerSecretStaging(compiled, []string{staging.SecretRef}, request.DeploymentID); err == nil {
		t.Fatal("version drift from signed installer manifest was accepted")
	}
}

func secretPublicationFixture() (secretPublicationRequest, cloudexecution.InstallerSecretStagingInput) {
	deploymentID := "22222222-2222-4222-8222-222222222222"
	staging := cloudexecution.InstallerSecretStagingInput{
		SlotID: "model-token", SecretRef: "secret_ref:bootstrap/77777777-7777-4777-8777-777777777777",
		SecretName: "dtx/11111111-1111-4111-8111-111111111111/deployments/" + deploymentID + "/model-token",
		VersionID:  uuid.NewString(), TargetPath: "/etc/dirextalk-service-secrets/model-token", FileMode: 0o400,
		RecipeDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Content:      &memorySecretContent{plaintext: []byte("deployment-secret-canary")},
	}
	request := secretPublicationRequest{
		AgentInstanceID: "11111111-1111-4111-8111-111111111111", OwnerID: "owner-1", AccountID: "123456789012",
		Region: "ap-south-1", DeploymentID: deploymentID, KMSAlias: "alias/foundation", Staging: []cloudexecution.InstallerSecretStagingInput{staging},
	}
	return request, staging
}

type memorySecretContent struct {
	plaintext        []byte
	materializeCalls int
	commitCalls      int
}

func (content *memorySecretContent) Materialize(_ context.Context, write func([]byte) error) error {
	content.materializeCalls++
	return write(content.plaintext)
}

func (content *memorySecretContent) Commit(_ context.Context, verify func() error) error {
	content.commitCalls++
	return verify()
}

type staticKMS struct{ arn string }

func (client staticKMS) DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{Arn: aws.String(client.arn)}}, nil
}

type memorySecrets struct {
	description   *secretsmanager.DescribeSecretOutput
	value         []byte
	createBuffer  []byte
	getBuffer     []byte
	createName    string
	createVersion string
	getVersion    string
	wrongVersion  bool
}

func (client *memorySecrets) CreateSecret(_ context.Context, input *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	client.createName = aws.ToString(input.Name)
	client.createVersion = aws.ToString(input.ClientRequestToken)
	client.createBuffer = input.SecretBinary
	client.value = bytes.Clone(input.SecretBinary)
	secretARN := "arn:aws:secretsmanager:ap-south-1:123456789012:secret:" + client.createName + "-Ab12Cd"
	version := client.createVersion
	if client.wrongVersion {
		version = uuid.NewString()
	}
	client.description = &secretsmanager.DescribeSecretOutput{
		ARN: aws.String(secretARN), Name: input.Name, KmsKeyId: input.KmsKeyId, VersionIdsToStages: map[string][]string{version: {"AWSCURRENT"}}, Tags: input.Tags,
	}
	return &secretsmanager.CreateSecretOutput{ARN: aws.String(secretARN), Name: input.Name, VersionId: input.ClientRequestToken}, nil
}

func (client *memorySecrets) DeleteSecret(context.Context, *secretsmanager.DeleteSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error) {
	return &secretsmanager.DeleteSecretOutput{}, nil
}

func (client *memorySecrets) DescribeSecret(context.Context, *secretsmanager.DescribeSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	return client.description, nil
}

func (client *memorySecrets) GetSecretValue(_ context.Context, input *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	client.getVersion = aws.ToString(input.VersionId)
	client.getBuffer = bytes.Clone(client.value)
	return &secretsmanager.GetSecretValueOutput{
		ARN: client.description.ARN, Name: client.description.Name, VersionId: input.VersionId, SecretBinary: client.getBuffer,
	}, nil
}

func allBytesZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

var _ = secretstypes.Tag{}
