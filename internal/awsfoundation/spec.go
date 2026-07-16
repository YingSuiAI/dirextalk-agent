// Package awsfoundation owns deterministic IAM bootstrap specifications,
// source-credential envelope storage, and the trusted Foundation template.
package awsfoundation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
)

const policyVersion = "2012-10-17"

var (
	ErrInvalidSpec = errors.New("invalid AWS foundation specification")
	accountPattern = regexp.MustCompile(`^[0-9]{12}$`)
	regionPattern  = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$`)
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type SpecInput struct {
	AgentInstanceID string
	Partition       string
	AccountID       string
	Region          string
}

func BuildSpec(input SpecInput) (awsprovider.BootstrapIdentitySpec, error) {
	if !idPattern.MatchString(input.AgentInstanceID) || !accountPattern.MatchString(input.AccountID) || !regionPattern.MatchString(input.Region) {
		return awsprovider.BootstrapIdentitySpec{}, ErrInvalidSpec
	}
	switch input.Partition {
	case "aws", "aws-cn", "aws-us-gov":
	default:
		return awsprovider.BootstrapIdentitySpec{}, ErrInvalidSpec
	}
	digest := sha256.Sum256([]byte(input.AgentInstanceID))
	suffix := hex.EncodeToString(digest[:6])
	prefix := "dtx-agent-" + suffix
	spec := awsprovider.BootstrapIdentitySpec{
		AgentInstanceID:    input.AgentInstanceID,
		AccountID:          input.AccountID,
		Partition:          input.Partition,
		Region:             input.Region,
		SourceUserName:     prefix + "-source",
		ControlRoleName:    prefix + "-control",
		FoundationRoleName: prefix + "-foundation",
		WorkerRoleName:     prefix + "-worker",
		WorkerProfileName:  prefix + "-worker",
		ReaperRoleName:     prefix + "-reaper",
		StackName:          prefix + "-foundation",
		ArtifactBucketName: fmt.Sprintf("dtx-agent-%s-%s-%s", input.AccountID, input.Region, suffix),
		ManifestTableName:  prefix + "-resources",
		WorkerLogGroupName: "/dirextalk/agent/" + suffix + "/worker",
		ReaperFunctionName: prefix + "-reaper",
		ReaperScheduleName: prefix + "-reaper",
		ReaperAlarmName:    prefix + "-reaper-errors",
		SecretNamespace:    "dtx/" + input.AgentInstanceID + "/deployments/",
		Tags:               []awsprovider.Tag{{Key: awsprovider.TagAgentInstanceID, Value: input.AgentInstanceID}, {Key: "dirextalk:component", Value: "foundation"}},
	}
	spec.ReaperLogGroupName = "/aws/lambda/" + spec.ReaperFunctionName
	controlARN := iamARN(input, "role/"+spec.ControlRoleName)
	sourceARN := iamARN(input, "user/"+spec.SourceUserName)
	stackARN := fmt.Sprintf("arn:%s:cloudformation:%s:%s:stack/%s/*", input.Partition, input.Region, input.AccountID, spec.StackName)

	spec.SourceUserPolicy = identityPolicy(statement("AssumeOnlyAgentControlRole", []string{"sts:AssumeRole"}, []string{controlARN}, nil))
	spec.ControlTrustPolicy = trustPolicy("TrustOnlySourceUser", map[string][]string{"AWS": {sourceARN}}, nil)
	spec.ControlBaselinePolicy = identityPolicy(
		statement("ObserveOnlyFoundationStack", []string{"cloudformation:DescribeStacks", "cloudformation:GetTemplate"}, []string{stackARN}, nil),
	)
	spec.FoundationTrustPolicy = trustPolicy("TrustCloudFormation", map[string][]string{"Service": {"cloudformation.amazonaws.com"}}, nil)
	spec.FoundationExecutionPolicy = foundationExecutionPolicy(input, spec)
	return spec, nil
}

func iamARN(input SpecInput, resource string) string {
	return fmt.Sprintf("arn:%s:iam::%s:%s", input.Partition, input.AccountID, resource)
}

func identityPolicy(statements ...awsprovider.PolicyStatement) awsprovider.PolicyDocument {
	return awsprovider.PolicyDocument{Version: policyVersion, Statement: statements}
}

func trustPolicy(sid string, principal map[string][]string, condition map[string]map[string]string) awsprovider.PolicyDocument {
	return awsprovider.PolicyDocument{Version: policyVersion, Statement: []awsprovider.PolicyStatement{{SID: sid, Effect: "Allow", Action: []string{"sts:AssumeRole"}, Principal: principal, Condition: condition}}}
}

func statement(sid string, actions, resources []string, condition map[string]map[string]string) awsprovider.PolicyStatement {
	return awsprovider.PolicyStatement{SID: sid, Effect: "Allow", Action: actions, Resource: resources, Condition: condition}
}

func foundationExecutionPolicy(input SpecInput, spec awsprovider.BootstrapIdentitySpec) awsprovider.PolicyDocument {
	account := input.AccountID
	partition := input.Partition
	region := input.Region
	requestTag := map[string]map[string]string{"StringEquals": {"aws:RequestTag/" + awsprovider.TagAgentInstanceID: input.AgentInstanceID}}
	return identityPolicy(
		statement("FoundationIAM", []string{"iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:TagRole", "iam:UntagRole", "iam:UpdateAssumeRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile", "iam:GetInstanceProfile", "iam:ListInstanceProfilesForRole", "iam:AddRoleToInstanceProfile", "iam:RemoveRoleFromInstanceProfile", "iam:PassRole"}, []string{
			iamARN(input, "role/"+spec.ControlRoleName), iamARN(input, "role/"+spec.WorkerRoleName), iamARN(input, "role/"+spec.ReaperRoleName),
			iamARN(input, "instance-profile/"+spec.WorkerProfileName),
		}, nil),
		statement("FoundationS3", []string{"s3:CreateBucket", "s3:DeleteBucket", "s3:GetBucketLocation", "s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:GetBucketTagging", "s3:PutBucketTagging", "s3:GetEncryptionConfiguration", "s3:PutEncryptionConfiguration", "s3:GetLifecycleConfiguration", "s3:PutLifecycleConfiguration", "s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock", "s3:ListBucket", "s3:DeleteObject", "s3:GetObject", "s3:PutObject"}, []string{
			fmt.Sprintf("arn:%s:s3:::%s", partition, spec.ArtifactBucketName), fmt.Sprintf("arn:%s:s3:::%s/*", partition, spec.ArtifactBucketName),
		}, nil),
		statement("FoundationKMSCreate", []string{"kms:CreateKey"}, []string{"*"}, requestTag),
		statement("FoundationKMSKeys", []string{"kms:DescribeKey", "kms:EnableKeyRotation", "kms:GetKeyPolicy", "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "kms:TagResource", "kms:UntagResource"}, []string{fmt.Sprintf("arn:%s:kms:%s:%s:key/*", partition, region, account)}, map[string]map[string]string{"StringEquals": {"aws:ResourceTag/" + awsprovider.TagAgentInstanceID: input.AgentInstanceID}}),
		statement("FoundationKMSGrants", []string{"kms:CreateGrant"}, []string{fmt.Sprintf("arn:%s:kms:%s:%s:key/*", partition, region, account)}, map[string]map[string]string{"Bool": {"kms:GrantIsForAWSResource": "true"}, "StringEquals": {"aws:ResourceTag/" + awsprovider.TagAgentInstanceID: input.AgentInstanceID}}),
		statement("FoundationKMSAlias", []string{"kms:CreateAlias", "kms:DeleteAlias"}, []string{fmt.Sprintf("arn:%s:kms:%s:%s:alias/%s", partition, region, account, spec.StackName), fmt.Sprintf("arn:%s:kms:%s:%s:key/*", partition, region, account)}, nil),
		statement("FoundationDynamoDB", []string{"dynamodb:CreateTable", "dynamodb:DeleteTable", "dynamodb:DescribeTable", "dynamodb:DescribeContinuousBackups", "dynamodb:UpdateContinuousBackups", "dynamodb:TagResource", "dynamodb:UntagResource"}, []string{fmt.Sprintf("arn:%s:dynamodb:%s:%s:table/%s", partition, region, account, spec.ManifestTableName)}, nil),
		statement("FoundationLogs", []string{"logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy", "logs:DeleteRetentionPolicy", "logs:TagResource", "logs:UntagResource"}, []string{fmt.Sprintf("arn:%s:logs:%s:%s:log-group:%s*", partition, region, account, spec.WorkerLogGroupName), fmt.Sprintf("arn:%s:logs:%s:%s:log-group:%s*", partition, region, account, spec.ReaperLogGroupName)}, nil),
		statement("FoundationLogsRead", []string{"logs:DescribeLogGroups"}, []string{"*"}, nil),
		statement("FoundationLambda", []string{"lambda:CreateFunction", "lambda:DeleteFunction", "lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:AddPermission", "lambda:RemovePermission", "lambda:TagResource", "lambda:UntagResource"}, []string{fmt.Sprintf("arn:%s:lambda:%s:%s:function:%s", partition, region, account, spec.ReaperFunctionName)}, nil),
		statement("FoundationEvents", []string{"events:PutRule", "events:DeleteRule", "events:DescribeRule", "events:EnableRule", "events:DisableRule", "events:PutTargets", "events:RemoveTargets", "events:TagResource", "events:UntagResource"}, []string{fmt.Sprintf("arn:%s:events:%s:%s:rule/%s", partition, region, account, spec.ReaperScheduleName)}, nil),
		statement("FoundationAlarm", []string{"cloudwatch:PutMetricAlarm", "cloudwatch:DeleteAlarms"}, []string{fmt.Sprintf("arn:%s:cloudwatch:%s:%s:alarm:%s", partition, region, account, spec.ReaperAlarmName)}, nil),
		statement("FoundationAlarmRead", []string{"cloudwatch:DescribeAlarms"}, []string{"*"}, nil),
		statement("FoundationSecretsCreate", []string{"secretsmanager:CreateSecret"}, []string{fmt.Sprintf("arn:%s:secretsmanager:%s:%s:secret:%s*", partition, region, account, spec.SecretNamespace)}, requestTag),
		statement("FoundationSecretsManage", []string{"secretsmanager:DeleteSecret", "secretsmanager:DescribeSecret", "secretsmanager:GetResourcePolicy", "secretsmanager:PutResourcePolicy", "secretsmanager:TagResource", "secretsmanager:UntagResource"}, []string{fmt.Sprintf("arn:%s:secretsmanager:%s:%s:secret:%s*", partition, region, account, spec.SecretNamespace)}, map[string]map[string]string{"StringEquals": {"aws:ResourceTag/" + awsprovider.TagAgentInstanceID: input.AgentInstanceID}}),
	)
}

var accountReadActions = map[string]struct{}{
	"ec2:DescribeInstances": {}, "ec2:DescribeVolumes": {}, "ec2:DescribeNetworkInterfaces": {},
	"ec2:DescribeAddresses": {}, "ec2:DescribeSecurityGroups": {}, "ec2:DescribeSnapshots": {}, "ec2:DescribeVpcEndpoints": {},
	"logs:DescribeLogGroups":    {},
	"cloudwatch:DescribeAlarms": {},
}

// ValidatePolicy rejects wildcard actions and unbounded resources. AWS KMS
// CreateKey is the sole mutation exception because IAM does not support a key
// ARN before creation; it remains bound by an exact action and mandatory
// agent-instance request tag. Account-level Describe actions may use Resource
// "*" only when every action is explicitly allowlisted.
func ValidatePolicy(policy awsprovider.PolicyDocument) error {
	if policy.Version != policyVersion || len(policy.Statement) == 0 {
		return ErrInvalidSpec
	}
	for _, current := range policy.Statement {
		if current.Effect != "Allow" || len(current.Action) == 0 {
			return ErrInvalidSpec
		}
		for _, action := range current.Action {
			if action == "" || strings.Contains(action, "*") || !strings.Contains(action, ":") {
				return ErrInvalidSpec
			}
		}
		for _, principals := range current.Principal {
			for _, principal := range principals {
				if principal == "" || strings.Contains(principal, "*") {
					return ErrInvalidSpec
				}
			}
		}
		if len(current.Principal) == 0 && len(current.Resource) == 0 {
			return ErrInvalidSpec
		}
		for _, resource := range current.Resource {
			if resource != "*" {
				if !strings.HasPrefix(resource, "arn:") {
					return ErrInvalidSpec
				}
				continue
			}
			if kmsCreateKeyException(current) || accountReadException(current) {
				continue
			}
			return ErrInvalidSpec
		}
	}
	return nil
}

func kmsCreateKeyException(statement awsprovider.PolicyStatement) bool {
	if len(statement.Action) != 1 || statement.Action[0] != "kms:CreateKey" {
		return false
	}
	for _, values := range statement.Condition {
		for key, value := range values {
			if key == "aws:RequestTag/"+awsprovider.TagAgentInstanceID && value != "" {
				return true
			}
		}
	}
	return false
}

func accountReadException(statement awsprovider.PolicyStatement) bool {
	if len(statement.Action) == 0 {
		return false
	}
	for _, action := range statement.Action {
		if _, ok := accountReadActions[action]; !ok {
			return false
		}
	}
	return true
}

func SortedPolicyActions(policy awsprovider.PolicyDocument) []string {
	actions := make([]string, 0)
	for _, statement := range policy.Statement {
		actions = append(actions, statement.Action...)
	}
	sort.Strings(actions)
	return actions
}
