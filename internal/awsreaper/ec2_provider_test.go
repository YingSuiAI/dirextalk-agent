package awsreaper

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/google/uuid"
)

type fakeEC2Reaper struct {
	EC2API
	instance       ec2types.Instance
	terminateCalls int
}

const (
	reaperTestPlanHash   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	reaperTestApprovalID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
)

func (fake *fakeEC2Reaper) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{fake.instance}}}}, nil
}

func (fake *fakeEC2Reaper) TerminateInstances(context.Context, *ec2.TerminateInstancesInput, ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error) {
	fake.terminateCalls++
	fake.instance.State = &ec2types.InstanceState{Name: ec2types.InstanceStateNameTerminated}
	return &ec2.TerminateInstancesOutput{}, nil
}

func TestEC2ProviderDeletesOnlyExpiredExactlyOwnedEphemeralResource(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	agentID, taskID, deploymentID, resourceID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	providerID := "i-0123456789abcdef0"
	fake := &fakeEC2Reaper{instance: ec2types.Instance{
		InstanceId: &providerID, State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
		Tags: awsResourceTags(agentID, taskID, deploymentID, resourceID, now.Add(-time.Minute), awsRetentionEphemeral),
	}}
	provider, err := NewEC2Provider(fake, agentID, "us-west-2")
	if err != nil {
		t.Fatal(err)
	}
	provider.now = func() time.Time { return now }
	expected := expectedResourceTags(agentID, taskID, deploymentID, resourceID, now.Add(-time.Minute))
	if err := provider.Delete(context.Background(), resource.TypeEC2, providerID, "us-west-2", expected); err != nil {
		t.Fatal(err)
	}
	if fake.terminateCalls != 1 {
		t.Fatalf("terminate calls = %d", fake.terminateCalls)
	}
	observation, err := provider.ReadBack(context.Background(), resource.TypeEC2, providerID, "us-west-2")
	if err != nil || observation.Exists {
		t.Fatalf("read-back = %+v, err=%v", observation, err)
	}
}

func TestEC2ProviderFailsClosedForManagedOrMismatchedTags(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	agentID, taskID, deploymentID, resourceID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	providerID := "i-0123456789abcdef0"
	tests := map[string][]ec2types.Tag{
		"managed":             awsResourceTags(agentID, taskID, deploymentID, resourceID, time.Time{}, awsRetentionManaged),
		"other agent":         awsResourceTags(uuid.NewString(), taskID, deploymentID, resourceID, now.Add(-time.Minute), awsRetentionEphemeral),
		"missing resource id": withoutAWSTag(awsResourceTags(agentID, taskID, deploymentID, resourceID, now.Add(-time.Minute), awsRetentionEphemeral), awsTagResourceID),
		"missing approval id": withoutAWSTag(awsResourceTags(agentID, taskID, deploymentID, resourceID, now.Add(-time.Minute), awsRetentionEphemeral), awsTagApprovalID),
		"wrong resource id":   awsResourceTags(agentID, taskID, deploymentID, uuid.NewString(), now.Add(-time.Minute), awsRetentionEphemeral),
	}
	for name, tags := range tests {
		t.Run(name, func(t *testing.T) {
			fake := &fakeEC2Reaper{instance: ec2types.Instance{InstanceId: &providerID, Tags: tags}}
			provider, _ := NewEC2Provider(fake, agentID, "us-west-2")
			provider.now = func() time.Time { return now }
			err := provider.Delete(context.Background(), resource.TypeEC2, providerID, "us-west-2", expectedResourceTags(agentID, taskID, deploymentID, resourceID, now.Add(-time.Minute)))
			if !errors.Is(err, ErrOwnershipMismatch) || fake.terminateCalls != 0 {
				t.Fatalf("Delete error=%v calls=%d", err, fake.terminateCalls)
			}
		})
	}
}

func withoutAWSTag(tags []ec2types.Tag, key string) []ec2types.Tag {
	result := make([]ec2types.Tag, 0, len(tags))
	for _, tag := range tags {
		if aws.ToString(tag.Key) != key {
			result = append(result, tag)
		}
	}
	return result
}

func awsResourceTags(agentID, taskID, deploymentID, resourceID string, deadline time.Time, retention string) []ec2types.Tag {
	deadlineText := "none"
	if !deadline.IsZero() {
		deadlineText = deadline.UTC().Format(time.RFC3339)
	}
	values := map[string]string{
		awsTagAgentInstanceID: agentID, awsTagOwnerID: "owner-1", awsTagTaskID: taskID,
		awsTagDeploymentID: deploymentID, awsTagRetention: retention,
		awsTagDestroyDeadline: deadlineText, awsTagResourceID: resourceID,
		awsTagApprovedPlanHash: reaperTestPlanHash, awsTagApprovalID: reaperTestApprovalID,
	}
	result := make([]ec2types.Tag, 0, len(values))
	for key, value := range values {
		result = append(result, ec2types.Tag{Key: aws.String(key), Value: aws.String(value)})
	}
	return result
}

func expectedResourceTags(agentID, taskID, deploymentID, resourceID string, deadline time.Time) map[string]string {
	return map[string]string{
		resource.TagAgentInstanceID: agentID, resource.TagOwnerID: "owner-1", resource.TagTaskID: taskID,
		resource.TagDeploymentID: deploymentID, resource.TagResourceID: resourceID,
		resource.TagRetention: string(task.RetentionEphemeralAutoDestroy), resource.TagDestroyDeadline: deadline.UTC().Format(time.RFC3339),
		resource.TagApprovedPlanHash: reaperTestPlanHash, resource.TagApprovalID: reaperTestApprovalID,
	}
}
