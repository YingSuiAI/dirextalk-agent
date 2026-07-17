package roothelper

import (
	"bytes"
	"context"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func TestExactSecretsAccessReadsAndCanariesOnlyApprovedCoordinate(t *testing.T) {
	binding := helperkey.DeviceBinding{Secret: helperkey.SecretCoordinate{
		ARN:  "arn:aws:secretsmanager:us-west-2:123456789012:secret:exact-Ab12Cd",
		Name: "exact", VersionID: "version-exact",
		KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/exact",
	}}
	privateKey := bytes.Repeat([]byte{0x41}, 64)
	client := &secretsFake{binding: binding, privateKey: privateKey}
	access, err := NewExactSecretsAccess(client)
	if err != nil {
		t.Fatal(err)
	}
	value, err := access.ReadRootHelperKey(context.Background(), binding)
	if err != nil || !bytes.Equal(value, privateKey) || client.describeCalls != 1 || client.getCalls != 1 {
		t.Fatalf("exact read failed: err=%v describes=%d gets=%d", err, client.describeCalls, client.getCalls)
	}
	client.canary = true
	client.canaryErr = deniedError{code: "AccessDeniedException"}
	if err := access.CanaryRootHelperKey(context.Background(), binding); err == nil || client.getCalls != 2 {
		t.Fatalf("real canary did not return provider denial: err=%v gets=%d", err, client.getCalls)
	}
}

type secretsFake struct {
	binding       helperkey.DeviceBinding
	privateKey    []byte
	canary        bool
	canaryErr     error
	describeCalls int
	getCalls      int
}

func (fake *secretsFake) DescribeSecret(_ context.Context, input *secretsmanager.DescribeSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	fake.describeCalls++
	if aws.ToString(input.SecretId) != fake.binding.Secret.ARN {
		return nil, ErrUnavailable
	}
	return &secretsmanager.DescribeSecretOutput{
		ARN: aws.String(fake.binding.Secret.ARN), Name: aws.String(fake.binding.Secret.Name),
		KmsKeyId:           aws.String(fake.binding.Secret.KMSKeyARN),
		VersionIdsToStages: map[string][]string{fake.binding.Secret.VersionID: {"AWSCURRENT"}},
	}, nil
}

func (fake *secretsFake) GetSecretValue(_ context.Context, input *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	fake.getCalls++
	if aws.ToString(input.SecretId) != fake.binding.Secret.ARN ||
		aws.ToString(input.VersionId) != fake.binding.Secret.VersionID {
		return nil, ErrUnavailable
	}
	if fake.canary {
		return nil, fake.canaryErr
	}
	return &secretsmanager.GetSecretValueOutput{
		ARN: aws.String(fake.binding.Secret.ARN), Name: aws.String(fake.binding.Secret.Name),
		VersionId: aws.String(fake.binding.Secret.VersionID), SecretBinary: bytes.Clone(fake.privateKey),
	}, nil
}
