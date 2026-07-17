package awsprovider

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretstypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
)

func TestRootHelperKeyPublisherReconcilesCreateResponseLossAndExactVersion(t *testing.T) {
	client := &rootHelperSecretsFake{loseCreateResponse: true}
	publisher, _ := NewRootHelperKeyPublisher(client, "arn:aws:kms:us-west-2:123456789012:key/key")
	binding := providerHelperBinding()
	public, private, _ := ed25519.GenerateKey(nil)
	binding.PublicKeyDigest = helperProviderDigest(public)
	binding.NonceDigest = helperProviderDigest(bytes.Repeat([]byte{0x31}, 32))
	coordinate, err := publisher.CreateRootHelperKey(context.Background(), binding, private)
	if err != nil || coordinate.VersionID != binding.DeliveryID || client.getVersion != binding.DeliveryID ||
		!allBytesZero(client.createInput) || !allBytesZero(client.getOutput) {
		t.Fatalf("coordinate=%+v err=%v version=%q buffers create=%v get=%v", coordinate, err, client.getVersion, client.createInput, client.getOutput)
	}
	binding.Secret = coordinate
	if err := publisher.GrantRootHelperKey(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(client.policy, binding.WorkerPrincipalID) {
		t.Fatalf("grant policy was not instance exact: %s", client.policy)
	}
}

func TestRootHelperKeyRevokerRequiresExactDenyReadBackAndDeleteReadBack(t *testing.T) {
	client := &rootHelperSecretsFake{}
	binding := providerHelperBinding()
	name := "dtx/" + binding.AgentInstanceID + "/deployments/" + binding.DeploymentID + "/" + helperkey.SecretSlot
	binding.Secret = helperkey.SecretCoordinate{ARN: "arn:aws:secretsmanager:us-west-2:123456789012:secret:" + name + "-Ab12Cd", Name: name, VersionID: binding.DeliveryID, KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/key"}
	client.arn = binding.Secret.ARN
	revoker, _ := NewRootHelperKeyRevoker(client)
	client.readbackDrift = true
	if err := revoker.DenyRootHelperKey(context.Background(), binding); !errors.Is(err, resource.ErrReadBack) {
		t.Fatalf("drift err=%v", err)
	}
	client.readbackDrift = false
	if err := revoker.DenyRootHelperKey(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(client.policy, `"Effect":"Deny"`) || strings.Contains(client.policy, `"Effect":"Allow"`) {
		t.Fatalf("not deny-only: %s", client.policy)
	}
	if err := revoker.DeleteRootHelperKeyPolicy(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
}

type rootHelperSecretsFake struct {
	name, arn, kms, version           string
	value                             []byte
	createInput, getOutput            []byte
	tags                              []secretstypes.Tag
	policy                            string
	loseCreateResponse, readbackDrift bool
	deleted                           bool
	getVersion                        string
}

func (f *rootHelperSecretsFake) CreateSecret(_ context.Context, input *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	f.name, f.kms, f.version = aws.ToString(input.Name), aws.ToString(input.KmsKeyId), aws.ToString(input.ClientRequestToken)
	f.arn = "arn:aws:secretsmanager:us-west-2:123456789012:secret:" + f.name + "-Ab12Cd"
	f.value = bytes.Clone(input.SecretBinary)
	f.createInput = input.SecretBinary
	f.tags = input.Tags
	output := &secretsmanager.CreateSecretOutput{ARN: aws.String(f.arn), Name: aws.String(f.name), VersionId: aws.String(f.version)}
	if f.loseCreateResponse {
		return output, &smithy.GenericAPIError{Code: "InternalServiceError", Message: "lost response"}
	}
	return output, nil
}
func (f *rootHelperSecretsFake) DescribeSecret(context.Context, *secretsmanager.DescribeSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	return &secretsmanager.DescribeSecretOutput{ARN: aws.String(f.arn), Name: aws.String(f.name), KmsKeyId: aws.String(f.kms), VersionIdsToStages: map[string][]string{f.version: {"AWSCURRENT"}}, Tags: f.tags}, nil
}
func (f *rootHelperSecretsFake) GetSecretValue(_ context.Context, input *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.getVersion = aws.ToString(input.VersionId)
	f.getOutput = bytes.Clone(f.value)
	return &secretsmanager.GetSecretValueOutput{ARN: aws.String(f.arn), Name: aws.String(f.name), VersionId: input.VersionId, SecretBinary: f.getOutput}, nil
}
func (f *rootHelperSecretsFake) PutResourcePolicy(_ context.Context, input *secretsmanager.PutResourcePolicyInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutResourcePolicyOutput, error) {
	f.policy = aws.ToString(input.ResourcePolicy)
	f.deleted = false
	return &secretsmanager.PutResourcePolicyOutput{ARN: input.SecretId}, nil
}
func (f *rootHelperSecretsFake) GetResourcePolicy(context.Context, *secretsmanager.GetResourcePolicyInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error) {
	policy := f.policy
	if f.readbackDrift {
		policy = `{"Version":"2012-10-17","Statement":[]}`
	}
	if f.deleted {
		policy = ""
	}
	return &secretsmanager.GetResourcePolicyOutput{ARN: aws.String(f.arn), ResourcePolicy: aws.String(policy)}, nil
}
func (f *rootHelperSecretsFake) DeleteResourcePolicy(context.Context, *secretsmanager.DeleteResourcePolicyInput, ...func(*secretsmanager.Options)) (*secretsmanager.DeleteResourcePolicyOutput, error) {
	f.deleted = true
	return &secretsmanager.DeleteResourcePolicyOutput{ARN: aws.String(f.arn)}, nil
}
func (*rootHelperSecretsFake) GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	return nil, nil
}

func providerHelperBinding() helperkey.DeviceBinding {
	instance := "i-0123456789abcdef0"
	agentID, deploymentID, deliveryID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	return helperkey.DeviceBinding{SchemaVersion: helperkey.SchemaV1, AgentInstanceID: agentID, OwnerID: "owner-helper",
		DeliveryID: deliveryID, DeploymentID: deploymentID, BindingRevision: 1,
		InstanceID: instance, WorkerRoleARN: "arn:aws:iam::123456789012:role/worker", WorkerPrincipalID: "AROATESTROLEIDENTIFIER:" + instance,
		HelperID: "root-helper", SignerKeyID: "root-helper-1",
		SecretPlan: helperkey.SecretPlan{Partition: "aws", AccountID: "123456789012", Region: "us-west-2",
			Name: "dtx/" + agentID + "/deployments/" + deploymentID + "/" + helperkey.SecretSlot, VersionID: deliveryID,
			KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/key", TargetPath: helperkey.SecretTarget, FileMode: helperkey.SecretMode}}
}
func allBytesZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func helperProviderDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
