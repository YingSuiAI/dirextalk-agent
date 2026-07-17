package awsprovider

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

var workerRoleIdentifierPattern = regexp.MustCompile(`^AROA[A-Z0-9]{12,124}$`)

type WorkerSecretBindingRequest struct {
	InstanceID   string
	RoleName     string
	DeploymentID string
	Secrets      []installerbootstrap.SecretSourceV1
}

type WorkerSecretBinder interface {
	Bind(context.Context, WorkerSecretBindingRequest) error
}

type WorkerSecretIAMAPI interface {
	GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error)
}

type WorkerSecretPolicyAPI interface {
	PutResourcePolicy(context.Context, *secretsmanager.PutResourcePolicyInput, ...func(*secretsmanager.Options)) (*secretsmanager.PutResourcePolicyOutput, error)
	GetResourcePolicy(context.Context, *secretsmanager.GetResourcePolicyInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error)
	DescribeSecret(context.Context, *secretsmanager.DescribeSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
}

type WorkerSecretSessionBinder struct {
	iam             WorkerSecretIAMAPI
	secrets         WorkerSecretPolicyAPI
	agentInstanceID string
	partition       string
	accountID       string
	region          string
	workerRoleName  string
}

func NewWorkerSecretSessionBinder(iamClient WorkerSecretIAMAPI, secretsClient WorkerSecretPolicyAPI, agentInstanceID, partition, accountID, region, workerRoleName string) (*WorkerSecretSessionBinder, error) {
	if iamClient == nil || secretsClient == nil || !sdkAccountPattern.MatchString(accountID) || !sdkRegionPattern.MatchString(region) ||
		strings.TrimSpace(agentInstanceID) == "" || strings.TrimSpace(workerRoleName) == "" {
		return nil, ErrInvalidRequest
	}
	switch partition {
	case "aws", "aws-cn", "aws-us-gov":
	default:
		return nil, ErrInvalidRequest
	}
	return &WorkerSecretSessionBinder{
		iam: iamClient, secrets: secretsClient, agentInstanceID: agentInstanceID, partition: partition,
		accountID: accountID, region: region, workerRoleName: workerRoleName,
	}, nil
}

func (binder *WorkerSecretSessionBinder) Bind(ctx context.Context, request WorkerSecretBindingRequest) error {
	if binder == nil || ctx == nil || !workerInstanceIDPattern.MatchString(request.InstanceID) || request.RoleName != binder.workerRoleName ||
		strings.TrimSpace(request.DeploymentID) == "" || len(request.Secrets) == 0 || len(request.Secrets) > 32 {
		return resource.ErrInvalid
	}
	roleOutput, err := binder.iam.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(binder.workerRoleName)})
	expectedRoleARN := "arn:" + binder.partition + ":iam::" + binder.accountID + ":role/" + binder.workerRoleName
	if err != nil || roleOutput == nil || roleOutput.Role == nil || aws.ToString(roleOutput.Role.Arn) != expectedRoleARN ||
		!workerRoleIdentifierPattern.MatchString(aws.ToString(roleOutput.Role.RoleId)) {
		return resource.ErrReadBack
	}
	expectedUserID := aws.ToString(roleOutput.Role.RoleId) + ":" + request.InstanceID
	seen := make(map[string]struct{}, len(request.Secrets))
	for _, source := range request.Secrets {
		if source.SchemaVersion != installerbootstrap.SecretSourceSchemaV1 || source.SecretName != "dtx/"+binder.agentInstanceID+"/deployments/"+request.DeploymentID+"/"+source.SlotID {
			return resource.ErrInvalid
		}
		secretARN, parseErr := arn.Parse(source.SecretARN)
		if parseErr != nil || secretARN.Partition != binder.partition || secretARN.Service != "secretsmanager" || secretARN.Region != binder.region || secretARN.AccountID != binder.accountID {
			return resource.ErrInvalid
		}
		if _, duplicate := seen[source.SecretARN]; duplicate {
			return resource.ErrInvalid
		}
		seen[source.SecretARN] = struct{}{}
		policy, policyErr := exactWorkerSessionPolicy(expectedRoleARN, expectedUserID, source.SecretARN)
		if policyErr != nil {
			return resource.ErrInvalid
		}
		if _, err := binder.secrets.PutResourcePolicy(ctx, &secretsmanager.PutResourcePolicyInput{
			SecretId: aws.String(source.SecretARN), ResourcePolicy: aws.String(policy), BlockPublicPolicy: aws.Bool(true),
		}); err != nil {
			return resource.ErrReadBack
		}
		readBack, err := binder.secrets.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{SecretId: aws.String(source.SecretARN)})
		if err != nil || readBack == nil || aws.ToString(readBack.ARN) != source.SecretARN || !sameJSONPolicy(policy, aws.ToString(readBack.ResourcePolicy)) {
			return resource.ErrReadBack
		}
		description, err := binder.secrets.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(source.SecretARN)})
		if err != nil || description == nil || aws.ToString(description.ARN) != source.SecretARN || aws.ToString(description.Name) != source.SecretName {
			return resource.ErrReadBack
		}
	}
	return nil
}

func exactWorkerSessionPolicy(roleARN, userID, secretARN string) (string, error) {
	type condition map[string]map[string]string
	type statement struct {
		Sid       string            `json:"Sid"`
		Effect    string            `json:"Effect"`
		Principal map[string]string `json:"Principal"`
		Action    []string          `json:"Action"`
		Resource  string            `json:"Resource"`
		Condition condition         `json:"Condition"`
	}
	value := struct {
		Version   string      `json:"Version"`
		Statement []statement `json:"Statement"`
	}{Version: "2012-10-17", Statement: []statement{
		{Sid: "AllowExactWorkerSession", Effect: "Allow", Principal: map[string]string{"AWS": roleARN},
			Action: []string{"secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"}, Resource: secretARN,
			Condition: condition{"StringEquals": {"aws:userid": userID}}},
		{Sid: "DenyOtherWorkerSessions", Effect: "Deny", Principal: map[string]string{"AWS": roleARN},
			Action: []string{"secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"}, Resource: secretARN,
			Condition: condition{"StringNotEquals": {"aws:userid": userID}}},
	}}
	encoded, err := json.Marshal(value)
	return string(encoded), err
}

func sameJSONPolicy(expected, actual string) bool {
	var left, right any
	return json.Unmarshal([]byte(expected), &left) == nil && json.Unmarshal([]byte(actual), &right) == nil && jsonEqual(left, right)
}

func jsonEqual(left, right any) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftBytes) == string(rightBytes)
}

var _ WorkerSecretBinder = (*WorkerSecretSessionBinder)(nil)
