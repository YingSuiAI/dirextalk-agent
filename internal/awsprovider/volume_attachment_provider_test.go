package awsprovider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestVolumeAttachmentProviderRecoversExactAttachAndDetachAfterResponseLoss(t *testing.T) {
	now := time.Date(2026, 7, 17, 9, 0, 0, 0, time.UTC)
	client := &volumeAttachmentFake{
		volumeID: "vol-0123456789abcdef0", state: ec2types.VolumeStateAvailable,
		loseAttachResponse: true, loseDetachResponse: true,
	}
	provider, err := NewVolumeAttachmentProvider(client, "us-east-1", func() time.Time { return now }, WithVolumeAttachmentPollInterval(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	spec := VolumeAttachmentSpecV1{
		IntentID: "11111111-1111-4111-8111-111111111111", Region: "us-east-1", InstanceID: "i-0123456789abcdef0",
		VolumeID: client.volumeID, DeviceName: "/dev/sdf",
	}
	attached, err := provider.AttachVolume(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !attached.Exists || attached.InstanceID != spec.InstanceID || attached.VolumeID != spec.VolumeID ||
		attached.DeviceName != spec.DeviceName || attached.State != VolumeAttachmentStateAttached || client.attachCalls != 1 {
		t.Fatalf("attach response-loss recovery = %+v calls=%d", attached, client.attachCalls)
	}
	detached, err := provider.DetachVolume(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if detached.Exists || detached.InstanceID != spec.InstanceID || detached.VolumeID != spec.VolumeID ||
		detached.DeviceName != spec.DeviceName || detached.State != VolumeAttachmentStateDetached || client.detachCalls != 1 {
		t.Fatalf("detach response-loss recovery = %+v calls=%d", detached, client.detachCalls)
	}
}

func TestVolumeAttachmentProviderRejectsAnyNonExactAttachment(t *testing.T) {
	base := VolumeAttachmentSpecV1{
		IntentID: "11111111-1111-4111-8111-111111111111", Region: "us-east-1", InstanceID: "i-0123456789abcdef0",
		VolumeID: "vol-0123456789abcdef0", DeviceName: "/dev/sdf",
	}
	tests := []struct {
		name       string
		attachment ec2types.VolumeAttachment
	}{
		{name: "wrong instance", attachment: ec2types.VolumeAttachment{
			InstanceId: aws.String("i-0fedcba9876543210"), Device: aws.String(base.DeviceName), State: ec2types.VolumeAttachmentStateAttached,
		}},
		{name: "wrong device", attachment: ec2types.VolumeAttachment{
			InstanceId: aws.String(base.InstanceID), Device: aws.String("/dev/sdg"), State: ec2types.VolumeAttachmentStateAttached,
		}},
		{name: "wrong state", attachment: ec2types.VolumeAttachment{
			InstanceId: aws.String(base.InstanceID), Device: aws.String(base.DeviceName), State: ec2types.VolumeAttachmentStateBusy,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &volumeAttachmentFake{
				volumeID: base.VolumeID, state: ec2types.VolumeStateInUse, attachments: []ec2types.VolumeAttachment{test.attachment},
			}
			provider, err := NewVolumeAttachmentProvider(client, base.Region, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.ReadBackVolumeAttachment(context.Background(), base); !errors.Is(err, ErrReadBackMismatch) {
				t.Fatalf("read-back error = %v", err)
			}
			if _, err := provider.AttachVolume(context.Background(), base); !errors.Is(err, ErrReadBackMismatch) {
				t.Fatalf("attach error = %v", err)
			}
			if _, err := provider.DetachVolume(context.Background(), base); !errors.Is(err, ErrReadBackMismatch) {
				t.Fatalf("detach error = %v", err)
			}
			if client.attachCalls != 0 || client.detachCalls != 0 {
				t.Fatalf("mismatch reached mutation: attach=%d detach=%d", client.attachCalls, client.detachCalls)
			}
		})
	}
}

type volumeAttachmentFake struct {
	volumeID           string
	state              ec2types.VolumeState
	attachments        []ec2types.VolumeAttachment
	loseAttachResponse bool
	loseDetachResponse bool
	attachCalls        int
	detachCalls        int
}

func (fake *volumeAttachmentFake) DescribeVolumes(_ context.Context, input *ec2.DescribeVolumesInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	if len(input.VolumeIds) != 1 || input.VolumeIds[0] != fake.volumeID {
		return nil, errors.New("unexpected volume read")
	}
	return &ec2.DescribeVolumesOutput{Volumes: []ec2types.Volume{{
		VolumeId: aws.String(fake.volumeID), State: fake.state, Attachments: append([]ec2types.VolumeAttachment(nil), fake.attachments...),
	}}}, nil
}

func (fake *volumeAttachmentFake) AttachVolume(_ context.Context, input *ec2.AttachVolumeInput, _ ...func(*ec2.Options)) (*ec2.AttachVolumeOutput, error) {
	fake.attachCalls++
	fake.state = ec2types.VolumeStateInUse
	fake.attachments = []ec2types.VolumeAttachment{{
		InstanceId: input.InstanceId, VolumeId: input.VolumeId, Device: input.Device, State: ec2types.VolumeAttachmentStateAttached,
	}}
	if fake.loseAttachResponse {
		fake.loseAttachResponse = false
		return nil, errors.New("simulated AttachVolume response loss")
	}
	return &ec2.AttachVolumeOutput{}, nil
}

func (fake *volumeAttachmentFake) DetachVolume(_ context.Context, _ *ec2.DetachVolumeInput, _ ...func(*ec2.Options)) (*ec2.DetachVolumeOutput, error) {
	fake.detachCalls++
	fake.state = ec2types.VolumeStateAvailable
	fake.attachments = nil
	if fake.loseDetachResponse {
		fake.loseDetachResponse = false
		return nil, errors.New("simulated DetachVolume response loss")
	}
	return &ec2.DetachVolumeOutput{}, nil
}
