package awsprovider

import (
	"context"
	"encoding/json"

	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// RootHelperKeyRevoker replaces the one-instance grant with an explicit deny
// for the entire Worker role. Policy read-back is necessary but deliberately
// not sufficient for readiness: the root bootstrap must subsequently execute
// the same-principal GetSecretValue canary and report AccessDenied.
type RootHelperKeyRevoker struct {
	secrets RootHelperKeyPolicyAPI
}

type RootHelperKeyPolicyAPI interface {
	WorkerSecretPolicyAPI
	DeleteResourcePolicy(context.Context, *secretsmanager.DeleteResourcePolicyInput, ...func(*secretsmanager.Options)) (*secretsmanager.DeleteResourcePolicyOutput, error)
}

func NewRootHelperKeyRevoker(secrets RootHelperKeyPolicyAPI) (*RootHelperKeyRevoker, error) {
	if secrets == nil {
		return nil, ErrInvalidRequest
	}
	return &RootHelperKeyRevoker{secrets: secrets}, nil
}

func (r *RootHelperKeyRevoker) DeleteRootHelperKeyPolicy(ctx context.Context, binding helperkey.DeviceBinding) error {
	if r == nil || binding.Secret.ARN == "" {
		return resource.ErrInvalid
	}
	if _, err := r.secrets.DeleteResourcePolicy(ctx, &secretsmanager.DeleteResourcePolicyInput{SecretId: aws.String(binding.Secret.ARN)}); err != nil {
		// Reconcile response loss below.
	}
	output, err := r.secrets.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{SecretId: aws.String(binding.Secret.ARN)})
	if err != nil || output == nil || aws.ToString(output.ARN) != binding.Secret.ARN || aws.ToString(output.ResourcePolicy) != "" {
		return resource.ErrReadBack
	}
	return nil
}

func (r *RootHelperKeyRevoker) DenyRootHelperKey(ctx context.Context, binding helperkey.DeviceBinding) error {
	if r == nil || binding.Secret.ARN == "" || binding.WorkerRoleARN == "" {
		return resource.ErrInvalid
	}
	policy, err := exactDeniedWorkerRolePolicy(binding.WorkerRoleARN, binding.Secret.ARN)
	if err != nil {
		return resource.ErrInvalid
	}
	if _, err := r.secrets.PutResourcePolicy(ctx, &secretsmanager.PutResourcePolicyInput{
		SecretId: aws.String(binding.Secret.ARN), ResourcePolicy: aws.String(policy), BlockPublicPolicy: aws.Bool(true),
	}); err != nil {
		// A response may be lost after AWS committed the policy. The separate
		// read-back method is the only operation allowed to reconcile it.
	}
	denied, readErr := r.ReadBackRootHelperKeyDenied(ctx, binding)
	if readErr != nil || !denied {
		return resource.ErrReadBack
	}
	return nil
}

func (r *RootHelperKeyRevoker) ReadBackRootHelperKeyDenied(ctx context.Context, binding helperkey.DeviceBinding) (bool, error) {
	if r == nil || binding.Secret.ARN == "" || binding.WorkerRoleARN == "" {
		return false, resource.ErrInvalid
	}
	expected, err := exactDeniedWorkerRolePolicy(binding.WorkerRoleARN, binding.Secret.ARN)
	if err != nil {
		return false, resource.ErrInvalid
	}
	output, err := r.secrets.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{SecretId: aws.String(binding.Secret.ARN)})
	if err != nil || output == nil || aws.ToString(output.ARN) != binding.Secret.ARN ||
		!sameJSONPolicy(expected, aws.ToString(output.ResourcePolicy)) {
		return false, resource.ErrReadBack
	}
	return true, nil
}

func exactDeniedWorkerRolePolicy(roleARN, secretARN string) (string, error) {
	value := struct {
		Version   string `json:"Version"`
		Statement []struct {
			Sid       string            `json:"Sid"`
			Effect    string            `json:"Effect"`
			Principal map[string]string `json:"Principal"`
			Action    []string          `json:"Action"`
			Resource  string            `json:"Resource"`
		} `json:"Statement"`
	}{Version: "2012-10-17"}
	value.Statement = append(value.Statement, struct {
		Sid       string            `json:"Sid"`
		Effect    string            `json:"Effect"`
		Principal map[string]string `json:"Principal"`
		Action    []string          `json:"Action"`
		Resource  string            `json:"Resource"`
	}{
		Sid: "DenyWorkerRoleAfterRootHelperBootstrap", Effect: "Deny",
		Principal: map[string]string{"AWS": roleARN},
		Action:    []string{"secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"}, Resource: secretARN,
	})
	raw, err := json.Marshal(value)
	return string(raw), err
}

var _ helperkey.SecretRevoker = (*RootHelperKeyRevoker)(nil)
