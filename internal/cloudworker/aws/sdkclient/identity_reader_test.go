package sdkclient

import (
	"context"
	"errors"
	"testing"
	"time"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func TestReadWorkerIdentityFreshlyRevalidatesEveryReadAndReturnsNoCredentials(t *testing.T) {
	request := testCreateRequest(t)
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	events := []string{}
	instance := workerIdentityInstance(request, now)
	ec2Client := &identityEC2{events: &events, outputs: []ec2types.Instance{instance, instance}}
	iamClient := &identityIAM{events: &events, output: workerIdentityProfile(request)}
	client := &Client{config: testSDKConfig(request.Identity), sts: &recordingSTS{account: request.Identity.AccountID, events: &events}, ec2: ec2Client, iam: iamClient, now: func() time.Time { return now }}

	identity, err := client.ReadWorkerIdentity(context.Background(), request.Identity.AccountID, request.Identity.Region, request.Identity.ProviderID, "i-0123456789abcdef0")
	if err != nil || !identity.Exists || identity.InstanceID != "i-0123456789abcdef0" || identity.AccountID != request.Identity.AccountID ||
		identity.Region != request.Identity.Region || identity.LaunchIdentity != request.Identity.LaunchIdentity ||
		identity.RoleARN != "arn:aws:iam::123456789012:role/"+request.Plan.IAMRoleName || !identity.LaunchTime.Equal(now.Add(-time.Minute)) ||
		identity.RoleID != "AROA1234567890ABCDEFG" || identity.InstanceProfileID != "AIPA1234567890ABCDEFG" ||
		identity.Tags[cloudaws.TagIntentDigest] != request.Intent.IntentDigest {
		t.Fatalf("identity=%+v err=%v", identity, err)
	}
	wantEvents := []string{"sts", "ec2.describe", "sts", "iam.get_profile", "sts", "ec2.describe", "sts", "iam.get_profile"}
	if len(events) != len(wantEvents) {
		t.Fatalf("events=%v", events)
	}
	for index := range wantEvents {
		if events[index] != wantEvents[index] {
			t.Fatalf("read %d was not immediately preceded by STS: %v", index, events)
		}
	}
}

func TestReadWorkerIdentityRejectsForeignAccountAndPostconditionDrift(t *testing.T) {
	request := testCreateRequest(t)
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	instance := workerIdentityInstance(request, now)
	drifted := instance
	drifted.LaunchTime = awssdk.Time(now.Add(-2 * time.Minute))
	ec2Client := &identityEC2{outputs: []ec2types.Instance{instance, drifted}}
	client := &Client{config: testSDKConfig(request.Identity), sts: &recordingSTS{account: request.Identity.AccountID}, ec2: ec2Client,
		iam: &identityIAM{output: workerIdentityProfile(request)}, now: func() time.Time { return now }}
	if _, err := client.ReadWorkerIdentity(context.Background(), request.Identity.AccountID, request.Identity.Region, request.Identity.ProviderID, "i-0123456789abcdef0"); !errors.Is(err, cloudaws.ErrIdentityMismatch) {
		t.Fatalf("launch replacement accepted: %v", err)
	}

	ec2Client = &identityEC2{outputs: []ec2types.Instance{instance}}
	client = &Client{config: testSDKConfig(request.Identity), sts: &recordingSTS{account: "999999999999"}, ec2: ec2Client,
		iam: &identityIAM{output: workerIdentityProfile(request)}, now: func() time.Time { return now }}
	if _, err := client.ReadWorkerIdentity(context.Background(), request.Identity.AccountID, request.Identity.Region, request.Identity.ProviderID, "i-0123456789abcdef0"); !errors.Is(err, cloudaws.ErrIdentityMismatch) || ec2Client.calls != 0 {
		t.Fatalf("foreign account crossed EC2 boundary: calls=%d err=%v", ec2Client.calls, err)
	}
}

func TestReadWorkerIdentityRejectsImmutableIAMReplacementBetweenReads(t *testing.T) {
	request := testCreateRequest(t)
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	instance := workerIdentityInstance(request, now)
	first := workerIdentityProfile(request)
	second := workerIdentityProfile(request)
	second.InstanceProfile.InstanceProfileId = awssdk.String("AIPAQRSTUVWXYZ1234567")
	second.InstanceProfile.Roles[0].RoleId = awssdk.String("AROAQRSTUVWXYZ1234567")
	client := &Client{
		config: testSDKConfig(request.Identity), sts: &recordingSTS{account: request.Identity.AccountID},
		ec2: &identityEC2{outputs: []ec2types.Instance{instance, instance}},
		iam: &identityIAM{outputs: []*iam.GetInstanceProfileOutput{first, second}}, now: func() time.Time { return now },
	}
	if _, err := client.ReadWorkerIdentity(context.Background(), request.Identity.AccountID, request.Identity.Region, request.Identity.ProviderID, "i-0123456789abcdef0"); !errors.Is(err, cloudaws.ErrIdentityMismatch) {
		t.Fatalf("same-name IAM replacement accepted: %v", err)
	}
}

type identityEC2 struct {
	EC2API
	events  *[]string
	outputs []ec2types.Instance
	calls   int
}

func (client *identityEC2) DescribeInstances(_ context.Context, _ *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	client.calls++
	if client.events != nil {
		*client.events = append(*client.events, "ec2.describe")
	}
	if len(client.outputs) == 0 {
		return &ec2.DescribeInstancesOutput{}, nil
	}
	index := client.calls - 1
	if index >= len(client.outputs) {
		index = len(client.outputs) - 1
	}
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{client.outputs[index]}}}}, nil
}

type identityIAM struct {
	IAMAPI
	events  *[]string
	output  *iam.GetInstanceProfileOutput
	outputs []*iam.GetInstanceProfileOutput
	calls   int
}

func (client *identityIAM) GetInstanceProfile(_ context.Context, _ *iam.GetInstanceProfileInput, _ ...func(*iam.Options)) (*iam.GetInstanceProfileOutput, error) {
	if client.events != nil {
		*client.events = append(*client.events, "iam.get_profile")
	}
	client.calls++
	if len(client.outputs) != 0 {
		index := client.calls - 1
		if index >= len(client.outputs) {
			index = len(client.outputs) - 1
		}
		return client.outputs[index], nil
	}
	return client.output, nil
}

func workerIdentityInstance(request cloudaws.CreateStackRequest, now time.Time) ec2types.Instance {
	tags := request.ResourceTags
	resultTags := make([]ec2types.Tag, 0, len(tags))
	for key, value := range tags {
		resultTags = append(resultTags, ec2types.Tag{Key: awssdk.String(key), Value: awssdk.String(value)})
	}
	return ec2types.Instance{InstanceId: awssdk.String("i-0123456789abcdef0"), LaunchTime: awssdk.Time(now.Add(-time.Minute)), Tags: resultTags,
		State:              &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
		IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: awssdk.String("arn:aws:iam::123456789012:instance-profile/" + request.Plan.InstanceProfileName)}}
}

func workerIdentityProfile(request cloudaws.CreateStackRequest) *iam.GetInstanceProfileOutput {
	return &iam.GetInstanceProfileOutput{InstanceProfile: &iamtypes.InstanceProfile{
		Arn:                 awssdk.String("arn:aws:iam::123456789012:instance-profile/" + request.Plan.InstanceProfileName),
		InstanceProfileName: awssdk.String(request.Plan.InstanceProfileName),
		InstanceProfileId:   awssdk.String("AIPA1234567890ABCDEFG"),
		Roles: []iamtypes.Role{{Arn: awssdk.String("arn:aws:iam::123456789012:role/" + request.Plan.IAMRoleName),
			RoleName: awssdk.String(request.Plan.IAMRoleName), RoleId: awssdk.String("AROA1234567890ABCDEFG")}},
	}}
}
