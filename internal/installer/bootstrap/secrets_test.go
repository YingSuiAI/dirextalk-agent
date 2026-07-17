package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretstypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"
)

func TestSecretsDownloaderReadsOnlyTheBoundBinaryVersionAndClearsSDKBuffer(t *testing.T) {
	source := testSecretSource()
	canary := []byte("deployment-only-secret-canary")
	client := &recordingSecretsClient{
		description: validSecretDescription(source),
		value: &secretsmanager.GetSecretValueOutput{
			ARN: aws.String(source.SecretARN), Name: aws.String(source.SecretName), VersionId: aws.String(source.VersionID),
			SecretBinary: bytes.Clone(canary),
		},
	}
	downloader, err := NewSecretsDownloader(client)
	if err != nil {
		t.Fatal(err)
	}
	download, err := downloader.Read(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(download.Value, canary) {
		t.Fatal("downloaded secret did not match the exact bound version")
	}
	if client.describeID != source.SecretARN || client.getID != source.SecretARN || client.getVersion != source.VersionID {
		t.Fatalf("AWS reads were not exact: describe=%q get=%q version=%q", client.describeID, client.getID, client.getVersion)
	}
	if !allZero(client.value.SecretBinary) {
		t.Fatal("AWS SDK response retained plaintext after the call")
	}
	clear(download.Value)
}

func TestSecretsDownloaderRetriesOnlyBoundedAccessDeniedPropagation(t *testing.T) {
	source := testSecretSource()
	client := &recordingSecretsClient{
		description: validSecretDescription(source),
		value: &secretsmanager.GetSecretValueOutput{
			ARN: aws.String(source.SecretARN), Name: aws.String(source.SecretName), VersionId: aws.String(source.VersionID), SecretBinary: []byte("canary"),
		},
		describeErrors: []error{&smithy.GenericAPIError{Code: "AccessDeniedException", Message: "policy propagation"}},
	}
	waits := 0
	downloader, err := newSecretsDownloaderWithRetry(client, accessDeniedRetry{attempts: 3, wait: func(context.Context, time.Duration) error { waits++; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	download, err := downloader.Read(context.Background(), source)
	if err != nil || !bytes.Equal(download.Value, []byte("canary")) || client.describeCalls != 2 || client.getCalls != 1 || waits != 1 {
		clear(download.Value)
		t.Fatalf("AccessDenied secret retry result=%v describe=%d get=%d waits=%d", err, client.describeCalls, client.getCalls, waits)
	}
	clear(download.Value)

	nonRetry := &recordingSecretsClient{description: validSecretDescription(source), describeErrors: []error{errors.New("network unavailable")}}
	downloader, _ = newSecretsDownloaderWithRetry(nonRetry, accessDeniedRetry{attempts: 3, wait: func(context.Context, time.Duration) error { t.Fatal("non-AccessDenied was retried"); return nil }})
	if _, err := downloader.Read(context.Background(), source); !errors.Is(err, ErrArtifactSource) || nonRetry.describeCalls != 1 {
		t.Fatalf("non-AccessDenied secret result=%v calls=%d", err, nonRetry.describeCalls)
	}
}

func TestSecretsDownloaderFailsClosedOnMutatedCoordinateOrMetadata(t *testing.T) {
	tests := map[string]func(SecretSourceV1, *secretsmanager.DescribeSecretOutput, *secretsmanager.GetSecretValueOutput){
		"different kms key": func(_ SecretSourceV1, description *secretsmanager.DescribeSecretOutput, _ *secretsmanager.GetSecretValueOutput) {
			description.KmsKeyId = aws.String("arn:aws:kms:ap-south-1:123456789012:key/other")
		},
		"missing exact version": func(source SecretSourceV1, description *secretsmanager.DescribeSecretOutput, _ *secretsmanager.GetSecretValueOutput) {
			delete(description.VersionIdsToStages, source.VersionID)
		},
		"different deployment tag": func(_ SecretSourceV1, description *secretsmanager.DescribeSecretOutput, _ *secretsmanager.GetSecretValueOutput) {
			description.Tags[1].Value = aws.String("99999999-9999-4999-8999-999999999999")
		},
		"different returned version": func(_ SecretSourceV1, _ *secretsmanager.DescribeSecretOutput, value *secretsmanager.GetSecretValueOutput) {
			value.VersionId = aws.String("99999999-9999-4999-8999-999999999999")
		},
		"secret string": func(_ SecretSourceV1, _ *secretsmanager.DescribeSecretOutput, value *secretsmanager.GetSecretValueOutput) {
			value.SecretString = aws.String("forbidden")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			source := testSecretSource()
			description := validSecretDescription(source)
			value := &secretsmanager.GetSecretValueOutput{
				ARN: aws.String(source.SecretARN), Name: aws.String(source.SecretName), VersionId: aws.String(source.VersionID), SecretBinary: []byte("canary"),
			}
			mutate(source, description, value)
			client := &recordingSecretsClient{description: description, value: value}
			downloader, _ := NewSecretsDownloader(client)
			if _, err := downloader.Read(context.Background(), source); err == nil {
				t.Fatal("mutated secret coordinate or metadata was accepted")
			}
		})
	}
}

func testSecretSource() SecretSourceV1 {
	name := "dtx/11111111-1111-4111-8111-111111111111/deployments/22222222-2222-4222-8222-222222222222/model-token"
	return SecretSourceV1{
		SchemaVersion: SecretSourceSchemaV1, SlotID: "model-token", SecretRef: "secret_ref:bootstrap/77777777-7777-4777-8777-777777777777",
		SecretARN: "arn:aws:secretsmanager:ap-south-1:123456789012:secret:" + name + "-Ab12Cd", SecretName: name,
		VersionID: "88888888-8888-4888-8888-888888888888", KMSKeyARN: "arn:aws:kms:ap-south-1:123456789012:key/11111111-2222-4333-8444-555555555555",
		TargetPath: "/etc/dirextalk-service-secrets/model-token", FileMode: 0o400,
		RecipeDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
}

func validSecretDescription(source SecretSourceV1) *secretsmanager.DescribeSecretOutput {
	return &secretsmanager.DescribeSecretOutput{
		ARN: aws.String(source.SecretARN), Name: aws.String(source.SecretName), KmsKeyId: aws.String(source.KMSKeyARN),
		VersionIdsToStages: map[string][]string{source.VersionID: {"AWSCURRENT"}},
		Tags: []secretstypes.Tag{
			{Key: aws.String("dirextalk:agent_instance_id"), Value: aws.String("11111111-1111-4111-8111-111111111111")},
			{Key: aws.String("dirextalk:deployment_id"), Value: aws.String("22222222-2222-4222-8222-222222222222")},
			{Key: aws.String("dirextalk:secret_slot"), Value: aws.String(source.SlotID)},
		},
	}
}

type recordingSecretsClient struct {
	description    *secretsmanager.DescribeSecretOutput
	value          *secretsmanager.GetSecretValueOutput
	describeID     string
	getID          string
	getVersion     string
	describeCalls  int
	getCalls       int
	describeErrors []error
	getErrors      []error
}

func (client *recordingSecretsClient) DescribeSecret(_ context.Context, input *secretsmanager.DescribeSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	client.describeCalls++
	client.describeID = aws.ToString(input.SecretId)
	if len(client.describeErrors) != 0 {
		err := client.describeErrors[0]
		client.describeErrors = client.describeErrors[1:]
		return nil, err
	}
	return client.description, nil
}

func (client *recordingSecretsClient) GetSecretValue(_ context.Context, input *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	client.getCalls++
	client.getID = aws.ToString(input.SecretId)
	client.getVersion = aws.ToString(input.VersionId)
	if len(client.getErrors) != 0 {
		err := client.getErrors[0]
		client.getErrors = client.getErrors[1:]
		return nil, err
	}
	return client.value, nil
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
