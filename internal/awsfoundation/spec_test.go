package awsfoundation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
)

func TestBuildSpecIsDeterministicAndLeastPrivilege(t *testing.T) {
	input := SpecInput{
		AgentInstanceID: "019f5e2d-5350-7073-87d9-3ba4fdbc6818",
		Partition:       "aws",
		AccountID:       "123456789012",
		Region:          "us-east-1",
	}
	first, err := BuildSpec(input)
	if err != nil {
		t.Fatalf("build first spec: %v", err)
	}
	second, err := BuildSpec(input)
	if err != nil {
		t.Fatalf("build second spec: %v", err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("specification is not deterministic")
	}
	for name, value := range map[string]string{
		"source user":     first.SourceUserName,
		"control role":    first.ControlRoleName,
		"foundation role": first.FoundationRoleName,
		"worker role":     first.WorkerRoleName,
		"worker profile":  first.WorkerProfileName,
		"reaper role":     first.ReaperRoleName,
		"stack":           first.StackName,
	} {
		if !strings.HasPrefix(value, "dtx-agent-") || len(value) > 64 {
			t.Fatalf("%s name = %q", name, value)
		}
	}
	if first.WorkerLogGroupName != first.StackName {
		t.Fatalf("Worker log group %q is not the assignment-safe stack scope %q", first.WorkerLogGroupName, first.StackName)
	}

	policies := []awsprovider.PolicyDocument{
		first.SourceUserPolicy,
		first.ControlTrustPolicy,
		first.ControlBaselinePolicy,
		first.FoundationTrustPolicy,
		first.FoundationExecutionPolicy,
	}
	for index, policy := range policies {
		if err := ValidatePolicy(policy); err != nil {
			t.Fatalf("policy %d: %v", index, err)
		}
	}
	executionJSON, err := json.Marshal(first.FoundationExecutionPolicy)
	if err != nil || len(executionJSON) > 10_240 {
		t.Fatalf("Foundation execution policy exceeds IAM inline-role quota: bytes=%d error=%v", len(executionJSON), err)
	}
	if len(first.SourceUserPolicy.Statement) != 1 || len(first.SourceUserPolicy.Statement[0].Action) != 1 || first.SourceUserPolicy.Statement[0].Action[0] != "sts:AssumeRole" {
		t.Fatalf("source policy = %#v", first.SourceUserPolicy)
	}
	wantControlARN := "arn:aws:iam::123456789012:role/" + first.ControlRoleName
	if got := first.SourceUserPolicy.Statement[0].Resource; len(got) != 1 || got[0] != wantControlARN {
		t.Fatalf("source role resource = %#v", got)
	}
	for _, action := range SortedPolicyActions(first.ControlBaselinePolicy) {
		if action == "iam:PassRole" || action == "cloudformation:CreateStack" || action == "cloudformation:UpdateStack" || action == "cloudformation:DeleteStack" {
			t.Fatalf("daily Control Role can mutate Foundation: %s", action)
		}
	}
}

func TestBuildSpecRejectsInvalidIdentityScope(t *testing.T) {
	tests := []SpecInput{
		{AgentInstanceID: "", Partition: "aws", AccountID: "123456789012", Region: "us-east-1"},
		{AgentInstanceID: "agent", Partition: "aws", AccountID: "root", Region: "us-east-1"},
		{AgentInstanceID: "agent", Partition: "other", AccountID: "123456789012", Region: "us-east-1"},
		{AgentInstanceID: "agent", Partition: "aws", AccountID: "123456789012", Region: "not a region"},
	}
	for _, input := range tests {
		if _, err := BuildSpec(input); err == nil {
			t.Fatalf("BuildSpec(%#v) succeeded", input)
		}
	}
}

func TestFoundationExecutionPolicyOwnsOnlyTaggedReleaseNetwork(t *testing.T) {
	spec, err := BuildSpec(SpecInput{AgentInstanceID: "019f5e2d-5350-7073-87d9-3ba4fdbc6818", Partition: "aws", AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{
		"FoundationReleaseVPCCreate":          false,
		"FoundationReleaseNetworkCreate":      false,
		"FoundationReleaseNetworkCreateInVPC": false,
		"FoundationReleaseNetworkTag":         false,
		"FoundationReleaseNetworkConfigure":   false,
		"FoundationReleaseNetworkDelete":      false,
	}
	for _, statement := range spec.FoundationExecutionPolicy.Statement {
		if _, ok := wanted[statement.SID]; !ok {
			continue
		}
		wanted[statement.SID] = true
		if len(statement.Condition) == 0 {
			t.Fatalf("%s has no ownership condition", statement.SID)
		}
		for _, resource := range statement.Resource {
			if resource == "*" || !strings.HasPrefix(resource, "arn:aws:ec2:us-east-1:123456789012:") {
				t.Fatalf("%s resource = %q", statement.SID, resource)
			}
		}
	}
	for sid, found := range wanted {
		if !found {
			t.Fatalf("missing %s", sid)
		}
	}
	var create, parent *awsprovider.PolicyStatement
	for index := range spec.FoundationExecutionPolicy.Statement {
		statement := &spec.FoundationExecutionPolicy.Statement[index]
		switch statement.SID {
		case "FoundationReleaseNetworkCreate":
			create = statement
		case "FoundationReleaseNetworkCreateInVPC":
			parent = statement
		}
	}
	ownershipKey := awsprovider.TagAgentInstanceID
	if create == nil || create.Condition["StringEquals"]["aws:RequestTag/"+ownershipKey] == "" ||
		parent == nil || parent.Condition["StringEquals"]["aws:ResourceTag/"+ownershipKey] == "" ||
		!sameStringSet(create.Action, []string{"ec2:CreateSubnet", "ec2:CreateSecurityGroup", "ec2:CreateRouteTable"}) ||
		!sameStringSet(parent.Resource, []string{"arn:aws:ec2:us-east-1:123456789012:vpc/*"}) {
		t.Fatalf("release network create boundary is invalid: create=%#v parent=%#v", create, parent)
	}
}

func TestFoundationExecutionPolicyManagesOnlyExactControlManagedPolicies(t *testing.T) {
	input := SpecInput{
		AgentInstanceID: "019f5e2d-5350-7073-87d9-3ba4fdbc6818",
		Partition:       "aws",
		AccountID:       "123456789012",
		Region:          "us-east-1",
	}
	spec, err := BuildSpec(input)
	if err != nil {
		t.Fatal(err)
	}
	artifactTagPolicyARN := "arn:aws:iam::123456789012:policy/" + spec.StackName + "-control-artifact-tags"
	entrypointPolicyARN := "arn:aws:iam::123456789012:policy/" + spec.StackName + "-control-entrypoint"
	controlARN := "arn:aws:iam::123456789012:role/" + spec.ControlRoleName
	var policyStatement, attachmentStatement *awsprovider.PolicyStatement
	for index := range spec.FoundationExecutionPolicy.Statement {
		statement := &spec.FoundationExecutionPolicy.Statement[index]
		switch statement.SID {
		case "FoundationControlManagedPolicies":
			policyStatement = statement
		case "FoundationAttachControlManagedPolicies":
			attachmentStatement = statement
		}
	}
	if policyStatement == nil || !sameStringSet(policyStatement.Action, []string{
		"iam:CreatePolicy", "iam:DeletePolicy", "iam:CreatePolicyVersion", "iam:DeletePolicyVersion", "iam:SetDefaultPolicyVersion",
		"iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions", "iam:ListEntitiesForPolicy",
	}) || !sameStringSet(policyStatement.Resource, []string{artifactTagPolicyARN, entrypointPolicyARN}) {
		t.Fatalf("managed policy authority = %#v", policyStatement)
	}
	if attachmentStatement == nil || !sameStringSet(attachmentStatement.Action, []string{"iam:AttachRolePolicy", "iam:DetachRolePolicy"}) ||
		!sameStringSet(attachmentStatement.Resource, []string{artifactTagPolicyARN, controlARN, entrypointPolicyARN}) {
		t.Fatalf("managed policy attachment authority = %#v", attachmentStatement)
	}
	for _, statement := range spec.FoundationExecutionPolicy.Statement {
		for _, action := range statement.Action {
			if action == "iam:TagPolicy" || action == "iam:UntagPolicy" || strings.Contains(action, "*") {
				t.Fatalf("unexpected managed-policy authority %s", action)
			}
		}
	}
}

func TestFoundationExecutionPolicyScopesSecretsKMSValidation(t *testing.T) {
	input := SpecInput{
		AgentInstanceID: "019f5e2d-5350-7073-87d9-3ba4fdbc6818",
		Partition:       "aws",
		AccountID:       "123456789012",
		Region:          "us-east-1",
	}
	spec, err := BuildSpec(input)
	if err != nil {
		t.Fatal(err)
	}
	var secretKMS *awsprovider.PolicyStatement
	for index := range spec.FoundationExecutionPolicy.Statement {
		if spec.FoundationExecutionPolicy.Statement[index].SID == "FoundationSecretsKMS" {
			secretKMS = &spec.FoundationExecutionPolicy.Statement[index]
			break
		}
	}
	if secretKMS == nil ||
		!sameStringSet(secretKMS.Action, []string{"kms:Decrypt", "kms:GenerateDataKey"}) ||
		!sameStringSet(secretKMS.Resource, []string{"arn:aws:kms:us-east-1:123456789012:key/*"}) {
		t.Fatalf("Secrets Manager KMS authority = %#v", secretKMS)
	}
	stringEquals := secretKMS.Condition["StringEquals"]
	arnLike := secretKMS.Condition["ArnLike"]
	if stringEquals["aws:ResourceTag/"+awsprovider.TagAgentInstanceID] != input.AgentInstanceID ||
		stringEquals["kms:ViaService"] != "secretsmanager.us-east-1.amazonaws.com" ||
		arnLike["kms:EncryptionContext:SecretARN"] != "arn:aws:secretsmanager:us-east-1:123456789012:secret:"+spec.SecretNamespace+"*" {
		t.Fatalf("Secrets Manager KMS conditions = %#v", secretKMS.Condition)
	}
}

func TestFoundationExecutionPolicyIncludesConfiguredResourceProviderActions(t *testing.T) {
	spec, err := BuildSpec(SpecInput{
		AgentInstanceID: "019f5e2d-5350-7073-87d9-3ba4fdbc6818",
		Partition:       "aws",
		AccountID:       "123456789012",
		Region:          "us-east-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	actions := make(map[string]bool)
	for _, action := range SortedPolicyActions(spec.FoundationExecutionPolicy) {
		actions[action] = true
	}
	required := []string{
		"cloudwatch:ListTagsForResource",
		"dynamodb:ListTagsOfResource",
		"ec2:ReplaceRouteTableAssociation",
		"events:ListTargetsByRule",
		"iam:ListAttachedRolePolicies",
		"kms:GetKeyRotationStatus",
		"kms:ListAliases",
		"lambda:GetPolicy",
		"logs:ListTagsForResource",
		"s3:GetBucketOwnershipControls",
		"s3:GetBucketVersioning",
		"s3:PutBucketOwnershipControls",
		"s3:PutBucketVersioning",
	}
	for _, action := range required {
		if !actions[action] {
			t.Fatalf("Foundation resource-provider action is missing: %s", action)
		}
	}
}

func TestValidatePolicyRejectsBroadPrivilege(t *testing.T) {
	tests := []awsprovider.PolicyDocument{
		{Version: policyVersion, Statement: []awsprovider.PolicyStatement{{Effect: "Allow", Action: []string{"*"}, Resource: []string{"*"}}}},
		{Version: policyVersion, Statement: []awsprovider.PolicyStatement{{Effect: "Allow", Action: []string{"ec2:*"}, Resource: []string{"arn:aws:ec2:us-east-1:123456789012:instance/*"}}}},
		{Version: policyVersion, Statement: []awsprovider.PolicyStatement{{Effect: "Allow", Action: []string{"ec2:TerminateInstances"}, Resource: []string{"*"}}}},
		{Version: policyVersion, Statement: []awsprovider.PolicyStatement{{Effect: "Allow", Action: []string{"sts:AssumeRole"}, Principal: map[string][]string{"AWS": {"*"}}}}},
	}
	for _, policy := range tests {
		if err := ValidatePolicy(policy); err == nil {
			t.Fatalf("broad policy accepted: %#v", policy)
		}
	}
}
