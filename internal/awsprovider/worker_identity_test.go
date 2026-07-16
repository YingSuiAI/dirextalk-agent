package awsprovider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestVerifyWorkerInstanceIdentityReturnsBoundReadBackEvidence(t *testing.T) {
	now := time.Date(2026, 7, 16, 15, 0, 0, 0, time.UTC)
	profile := "dtx-agent-example-worker"
	tags := validResourceTags("11111111-1111-4111-8111-111111111111")
	client := &workerIdentityEC2Fake{instance: validWorkerIdentityInstance(profile, tags)}
	provider, err := NewEC2ResourceProvider(client, "us-east-1", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := provider.VerifyWorkerInstanceIdentity(context.Background(), WorkerInstanceIdentityRequest{
		InstanceID: "i-0123456789abcdef0", Region: "us-east-1", WorkerProfileName: profile, ExpectedOwnershipTags: tags,
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.calls != 1 || client.input == nil || len(client.input.InstanceIds) != 1 || client.input.InstanceIds[0] != evidence.InstanceID || len(client.input.Filters) != 0 {
		t.Fatalf("identity verification was not an exact instance read: %#v", client.input)
	}
	if evidence.InstanceID != "i-0123456789abcdef0" || evidence.AccountID != "123456789012" || evidence.Region != "us-east-1" || evidence.WorkerProfileName != profile || evidence.PrimaryNetworkInterfaceID != "eni-0123456789abcdef0" || evidence.ObservedAt != now || !digestPattern.MatchString(evidence.TagDigest) {
		t.Fatalf("unexpected evidence: %#v", evidence)
	}
}

func TestVerifyWorkerInstanceIdentityFailsClosedOnIdentityMismatch(t *testing.T) {
	profile := "dtx-agent-example-worker"
	tags := validResourceTags("11111111-1111-4111-8111-111111111111")
	tests := []struct {
		name   string
		mutate func(*ec2types.Instance)
	}{
		{name: "not running", mutate: func(value *ec2types.Instance) { value.State.Name = ec2types.InstanceStateNameStopped }},
		{name: "wrong profile", mutate: func(value *ec2types.Instance) {
			value.IamInstanceProfile.Arn = aws.String("arn:aws:iam::123456789012:instance-profile/dtx-agent-other-worker")
		}},
		{name: "IMDSv1 permitted", mutate: func(value *ec2types.Instance) { value.MetadataOptions.HttpTokens = ec2types.HttpTokensStateOptional }},
		{name: "IMDS change pending", mutate: func(value *ec2types.Instance) {
			value.MetadataOptions.State = ec2types.InstanceMetadataOptionsStatePending
		}},
		{name: "second ENI", mutate: func(value *ec2types.Instance) {
			value.NetworkInterfaces = append(value.NetworkInterfaces, value.NetworkInterfaces[0])
		}},
		{name: "primary ENI not attached", mutate: func(value *ec2types.Instance) {
			value.NetworkInterfaces[0].Attachment.Status = ec2types.AttachmentStatusDetached
		}},
		{name: "ownership mismatch", mutate: func(value *ec2types.Instance) {
			actual := tagsFromEC2(value.Tags)
			actual[resource.TagOwnerID] = "another-owner"
			value.Tags = ec2Tags(actual)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instance := validWorkerIdentityInstance(profile, tags)
			test.mutate(&instance)
			client := &workerIdentityEC2Fake{instance: instance}
			provider, err := NewEC2ResourceProvider(client, "us-east-1", time.Now)
			if err != nil {
				t.Fatal(err)
			}
			_, err = provider.VerifyWorkerInstanceIdentity(context.Background(), WorkerInstanceIdentityRequest{
				InstanceID: "i-0123456789abcdef0", Region: "us-east-1", WorkerProfileName: profile, ExpectedOwnershipTags: tags,
			})
			if !errors.Is(err, ErrReadBackMismatch) {
				t.Fatalf("identity mismatch did not fail closed: %v", err)
			}
		})
	}
}

func TestVerifyWorkerInstanceIdentityRejectsUnscopedRequestBeforeAWS(t *testing.T) {
	tags := validResourceTags("11111111-1111-4111-8111-111111111111")
	delete(tags, resource.TagTaskID)
	client := &workerIdentityEC2Fake{instance: validWorkerIdentityInstance("dtx-agent-example-worker", tags)}
	provider, err := NewEC2ResourceProvider(client, "us-east-1", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.VerifyWorkerInstanceIdentity(context.Background(), WorkerInstanceIdentityRequest{
		InstanceID: "i-0123456789abcdef0", Region: "us-east-1", WorkerProfileName: "dtx-agent-example-worker", ExpectedOwnershipTags: tags,
	})
	if !errors.Is(err, ErrInvalidRequest) || client.calls != 0 {
		t.Fatalf("unscoped request reached AWS: calls=%d err=%v", client.calls, err)
	}
}

func TestVerifyWorkerInstanceIdentityRejectsAccountDisagreement(t *testing.T) {
	profile := "dtx-agent-example-worker"
	tags := validResourceTags("11111111-1111-4111-8111-111111111111")
	client := &workerIdentityEC2Fake{instance: validWorkerIdentityInstance(profile, tags), ownerID: "210987654321"}
	provider, err := NewEC2ResourceProvider(client, "us-east-1", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.VerifyWorkerInstanceIdentity(context.Background(), WorkerInstanceIdentityRequest{
		InstanceID: "i-0123456789abcdef0", Region: "us-east-1", WorkerProfileName: profile, ExpectedOwnershipTags: tags,
	})
	if !errors.Is(err, ErrReadBackMismatch) {
		t.Fatalf("reservation/profile account disagreement was accepted: %v", err)
	}
}

func validWorkerIdentityInstance(profile string, tags map[string]string) ec2types.Instance {
	return ec2types.Instance{
		InstanceId: aws.String("i-0123456789abcdef0"), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
		IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: aws.String("arn:aws:iam::123456789012:instance-profile/" + profile)},
		MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
			HttpEndpoint: ec2types.InstanceMetadataEndpointStateEnabled, HttpTokens: ec2types.HttpTokensStateRequired,
			HttpPutResponseHopLimit: aws.Int32(1), InstanceMetadataTags: ec2types.InstanceMetadataTagsStateEnabled, State: ec2types.InstanceMetadataOptionsStateApplied,
		},
		NetworkInterfaces: []ec2types.InstanceNetworkInterface{{
			NetworkInterfaceId: aws.String("eni-0123456789abcdef0"), Status: ec2types.NetworkInterfaceStatusInUse,
			Attachment: &ec2types.InstanceNetworkInterfaceAttachment{DeviceIndex: aws.Int32(0), NetworkCardIndex: aws.Int32(0), Status: ec2types.AttachmentStatusAttached},
		}},
		Tags: ec2Tags(tags),
	}
}

type workerIdentityEC2Fake struct {
	EC2ResourceAPI
	instance ec2types.Instance
	input    *ec2.DescribeInstancesInput
	calls    int
	ownerID  string
}

func (fake *workerIdentityEC2Fake) DescribeInstances(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	fake.calls++
	fake.input = input
	ownerID := fake.ownerID
	if ownerID == "" {
		ownerID = "123456789012"
	}
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{OwnerId: aws.String(ownerID), Instances: []ec2types.Instance{fake.instance}}}}, nil
}
