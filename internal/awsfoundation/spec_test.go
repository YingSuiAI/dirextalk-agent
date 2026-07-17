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
