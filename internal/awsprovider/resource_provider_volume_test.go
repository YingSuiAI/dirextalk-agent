package awsprovider

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestWorkerUserDataBindsProviderEBSIDToSignedVolumeScope(t *testing.T) {
	bootstrap := testWorkerBootstrap()
	volume := installer.VolumeV1{
		Name: "knowledge", DeviceName: "/dev/sdf", MountPath: "/srv/knowledge", Persistent: true,
		Disposition: "delete_with_deployment", SizeGiB: 40,
	}
	bootstrap.InstallerTrust = testProviderInstallerTrust(t, bootstrap.DeploymentID, volume)
	bootstrap.InstallerArtifacts = providerInstallerSources(bootstrap.InstallerTrust, bootstrap.DeploymentID)
	volumeResourceID := "77777777-7777-4777-8777-777777777777"
	request := resource.ProviderCreateRequest{
		ResourceID: "11111111-1111-4111-8111-111111111111", Region: "us-east-1", SpecDigest: digestOf('a'),
		Dependencies: []resource.ProviderDependency{{ResourceID: volumeResourceID, Type: resource.TypeEBS, ProviderID: "vol-0123456789abcdef0"}},
		AWS: &resource.AWSResourceSpecV1{Instance: &resource.AWSEC2InstanceSpecV1{
			UserDataArtifactRef:    "s3://dtx-artifacts/deployments/" + bootstrap.DeploymentID + "/launch/config.json",
			UserDataArtifactDigest: digestOf('b'), Bootstrap: bootstrap,
			DataVolumes: []resource.AWSDataVolumeAttachmentV1{{ResourceID: volumeResourceID, DeviceName: "/dev/sdf"}},
		}},
	}
	encoded, err := fixedWorkerUserData(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := installerbootstrap.ParseUserData(raw, installerbootstrap.InstanceIdentityV1{
		AccountID: "123456789012", Region: request.Region, InstanceID: "i-0123456789abcdef0",
	})
	if err != nil || len(parsed.InstallerVolumes) != 1 || parsed.InstallerVolumes[0].VolumeID != "vol-0123456789abcdef0" ||
		parsed.InstallerVolumes[0].DeviceName != volume.DeviceName || parsed.InstallerVolumes[0].Name != volume.Name {
		t.Fatalf("provider volume binding = %+v err=%v", parsed.InstallerVolumes, err)
	}
	request.Dependencies = nil
	if _, err := fixedWorkerUserData(request); !errors.Is(err, resource.ErrInvalid) {
		t.Fatalf("missing EBS dependency error = %v", err)
	}
}

func TestEBSCreateRetriesSameClientTokenAfterResponseLossWithoutDuplicate(t *testing.T) {
	now := time.Date(2026, 7, 17, 8, 0, 0, 0, time.UTC)
	client := &volumeLifecycleFake{
		loseFirstCreateResponse: true,
		snapshot: ec2types.Snapshot{
			SnapshotId: aws.String("snap-0123456789abcdef0"), State: ec2types.SnapshotStateCompleted,
			Encrypted: aws.Bool(true), KmsKeyId: aws.String(testVolumeKMSKeyARN), VolumeSize: aws.Int32(80),
		},
	}
	provider, err := NewEC2ResourceProvider(client, "us-east-1", func() time.Time { return now }, WithEC2ResourcePollInterval(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	request := replacementVolumeCreateRequest(t)
	if _, err := provider.Create(context.Background(), request); err == nil {
		t.Fatal("simulated response loss was not reported")
	}
	observed, err := provider.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !observed.Exists || observed.ProviderID != client.volumeID || client.actualCreates != 1 || client.createCalls != 2 {
		t.Fatalf("response-loss recovery duplicated EBS: observed=%+v actualCreates=%d calls=%d", observed, client.actualCreates, client.createCalls)
	}
	if client.createInput == nil || aws.ToString(client.createInput.SnapshotId) != client.snapshotID() {
		t.Fatalf("replacement volume did not bind the exact completed snapshot: %#v", client.createInput)
	}
}

func TestEBSReplacementRejectsInvalidSourceSnapshotBeforeCreate(t *testing.T) {
	request := replacementVolumeCreateRequest(t)
	wrongProviderID := request
	wrongProviderID.Dependencies = append([]resource.ProviderDependency(nil), request.Dependencies...)
	wrongProviderID.Dependencies[0].ProviderID = "vol-0123456789abcdef0"
	wrongProviderClient := &volumeLifecycleFake{}
	wrongProvider, err := NewEC2ResourceProvider(wrongProviderClient, request.Region, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongProvider.Create(context.Background(), wrongProviderID); !errors.Is(err, resource.ErrInvalid) {
		t.Fatalf("wrong typed snapshot provider ID error = %v", err)
	}
	if wrongProviderClient.createCalls != 0 {
		t.Fatal("wrong typed snapshot provider ID reached CreateVolume")
	}

	tests := []struct {
		name     string
		snapshot ec2types.Snapshot
	}{
		{name: "pending", snapshot: ec2types.Snapshot{
			SnapshotId: aws.String("snap-0123456789abcdef0"), State: ec2types.SnapshotStatePending,
			Encrypted: aws.Bool(true), KmsKeyId: aws.String(testVolumeKMSKeyARN), VolumeSize: aws.Int32(80),
		}},
		{name: "unencrypted", snapshot: ec2types.Snapshot{
			SnapshotId: aws.String("snap-0123456789abcdef0"), State: ec2types.SnapshotStateCompleted,
			Encrypted: aws.Bool(false), KmsKeyId: aws.String(testVolumeKMSKeyARN), VolumeSize: aws.Int32(80),
		}},
		{name: "wrong kms", snapshot: ec2types.Snapshot{
			SnapshotId: aws.String("snap-0123456789abcdef0"), State: ec2types.SnapshotStateCompleted,
			Encrypted: aws.Bool(true), KmsKeyId: aws.String("alias/other"), VolumeSize: aws.Int32(80),
		}},
		{name: "larger source", snapshot: ec2types.Snapshot{
			SnapshotId: aws.String("snap-0123456789abcdef0"), State: ec2types.SnapshotStateCompleted,
			Encrypted: aws.Bool(true), KmsKeyId: aws.String(testVolumeKMSKeyARN), VolumeSize: aws.Int32(81),
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &volumeLifecycleFake{snapshot: test.snapshot}
			provider, err := NewEC2ResourceProvider(client, request.Region, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.Create(context.Background(), request); !errors.Is(err, resource.ErrReadBack) {
				t.Fatalf("invalid snapshot error = %v", err)
			}
			if client.createCalls != 0 {
				t.Fatalf("CreateVolume called %d times for an invalid source snapshot", client.createCalls)
			}
		})
	}
}

func TestEBSDeleteDetachesOnlyFromSameOwnedDeploymentAndReadsBackMissing(t *testing.T) {
	request := volumeCreateRequest(t)
	expected := request.Tags
	client := &volumeLifecycleFake{
		volumeID: "vol-0123456789abcdef0", instanceID: "i-0123456789abcdef0", created: true,
		volume: ec2types.Volume{
			VolumeId: aws.String("vol-0123456789abcdef0"), State: ec2types.VolumeStateInUse,
			Tags: ec2Tags(expected), Attachments: []ec2types.VolumeAttachment{{
				InstanceId: aws.String("i-0123456789abcdef0"), Device: aws.String("/dev/sdf"), State: ec2types.VolumeAttachmentStateAttached,
			}},
		},
		instanceTags: ec2Tags(validResourceTags("dddddddd-dddd-4ddd-8ddd-dddddddddddd")),
	}
	provider, err := NewEC2ResourceProvider(client, request.Region, time.Now, WithEC2ResourcePollInterval(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Delete(context.Background(), resource.TypeEBS, client.volumeID, request.Region, expected); err != nil {
		t.Fatal(err)
	}
	if client.detachCalls != 1 || client.deleteCalls != 1 || !client.deleted {
		t.Fatalf("typed detach/delete lifecycle incomplete: detach=%d delete=%d deleted=%v", client.detachCalls, client.deleteCalls, client.deleted)
	}
	observed, err := provider.ReadBack(context.Background(), resource.TypeEBS, client.volumeID, request.Region)
	if err != nil || observed.Exists {
		t.Fatalf("destroy read-back did not prove EBS missing: observed=%+v err=%v", observed, err)
	}

	blocked := *client
	blocked.deleted, blocked.detachCalls, blocked.deleteCalls = false, 0, 0
	blocked.volume.State = ec2types.VolumeStateInUse
	blocked.volume.Attachments = []ec2types.VolumeAttachment{{InstanceId: aws.String(blocked.instanceID), Device: aws.String("/dev/sdf"), State: ec2types.VolumeAttachmentStateAttached}}
	blocked.instanceTags = ec2Tags(validResourceTags("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"))
	for index := range blocked.instanceTags {
		if aws.ToString(blocked.instanceTags[index].Key) == TagOwnerID {
			blocked.instanceTags[index].Value = aws.String("other-owner")
		}
	}
	blockedProvider, _ := NewEC2ResourceProvider(&blocked, request.Region, time.Now, WithEC2ResourcePollInterval(time.Nanosecond))
	if err := blockedProvider.Delete(context.Background(), resource.TypeEBS, blocked.volumeID, request.Region, expected); !errors.Is(err, resource.ErrReadBack) || blocked.detachCalls != 0 {
		t.Fatalf("cross-owner attachment was not blocked before detach: err=%v detach=%d", err, blocked.detachCalls)
	}
}

func volumeCreateRequest(t *testing.T) resource.ProviderCreateRequest {
	t.Helper()
	resourceID := "11111111-1111-4111-8111-111111111111"
	spec := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, Volume: &resource.AWSEBSVolumeSpecV1{
		AvailabilityZone: "us-east-1a", SizeGiB: 80, VolumeType: "gp3", IOPS: 3_000, ThroughputMiBPS: 125,
		KMSKeyID: "alias/dtx-agent-test-foundation", SlotID: "knowledge", DeviceName: "/dev/sdf", MountPath: "/srv/knowledge",
		Persistent: true, Disposition: resource.AWSVolumeDeleteWithDeployment,
	}}
	digest, err := spec.Digest(resource.TypeEBS)
	if err != nil {
		t.Fatal(err)
	}
	return resource.ProviderCreateRequest{
		ResourceID: resourceID, Type: resource.TypeEBS, LogicalName: "knowledge", Region: "us-east-1", SpecDigest: digest,
		ClientToken: "dtx-volume-0123456789", Tags: validResourceTags(resourceID), AWS: spec,
	}
}

func replacementVolumeCreateRequest(t *testing.T) resource.ProviderCreateRequest {
	t.Helper()
	request := volumeCreateRequest(t)
	request.AWS.Volume.KMSKeyID = testVolumeKMSKeyARN
	request.AWS.Volume.SourceSnapshotResourceID = "33333333-3333-4333-8333-333333333333"
	request.Dependencies = []resource.ProviderDependency{{
		ResourceID: request.AWS.Volume.SourceSnapshotResourceID, Type: resource.TypeSnapshot, ProviderID: "snap-0123456789abcdef0",
	}}
	digest, err := request.AWS.Digest(resource.TypeEBS)
	if err != nil {
		t.Fatal(err)
	}
	request.SpecDigest = digest
	return request
}

const testVolumeKMSKeyARN = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"

type volumeLifecycleFake struct {
	EC2ResourceAPI
	volumeID                string
	instanceID              string
	volume                  ec2types.Volume
	snapshot                ec2types.Snapshot
	createInput             *ec2.CreateVolumeInput
	instanceTags            []ec2types.Tag
	created                 bool
	deleted                 bool
	loseFirstCreateResponse bool
	clientToken             string
	createCalls             int
	actualCreates           int
	detachCalls             int
	deleteCalls             int
}

func (fake *volumeLifecycleFake) CreateVolume(_ context.Context, input *ec2.CreateVolumeInput, _ ...func(*ec2.Options)) (*ec2.CreateVolumeOutput, error) {
	fake.createCalls++
	fake.createInput = input
	token := aws.ToString(input.ClientToken)
	if !fake.created {
		fake.created, fake.actualCreates, fake.clientToken = true, 1, token
		fake.volumeID = "vol-0123456789abcdef0"
		fake.volume = ec2types.Volume{
			VolumeId: fake.string(fake.volumeID), AvailabilityZone: input.AvailabilityZone, Size: input.Size, Iops: input.Iops,
			Throughput: input.Throughput, KmsKeyId: input.KmsKeyId, Encrypted: aws.Bool(true), VolumeType: input.VolumeType,
			State: ec2types.VolumeStateAvailable, Tags: append([]ec2types.Tag(nil), input.TagSpecifications[0].Tags...),
		}
	} else if token != fake.clientToken {
		fake.actualCreates++
		return nil, errors.New("different client token would duplicate volume")
	}
	if fake.loseFirstCreateResponse {
		fake.loseFirstCreateResponse = false
		return nil, errors.New("simulated CreateVolume response loss")
	}
	return &ec2.CreateVolumeOutput{VolumeId: fake.string(fake.volumeID)}, nil
}

func (fake *volumeLifecycleFake) DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	if aws.ToString(fake.snapshot.SnapshotId) == "" {
		return &ec2.DescribeSnapshotsOutput{}, nil
	}
	return &ec2.DescribeSnapshotsOutput{Snapshots: []ec2types.Snapshot{fake.snapshot}}, nil
}

func (fake *volumeLifecycleFake) snapshotID() string {
	return aws.ToString(fake.snapshot.SnapshotId)
}

func (fake *volumeLifecycleFake) DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	if !fake.created {
		return &ec2.DescribeVolumesOutput{}, nil
	}
	value := fake.volume
	if fake.deleted {
		value.State = ec2types.VolumeStateDeleted
	}
	return &ec2.DescribeVolumesOutput{Volumes: []ec2types.Volume{value}}, nil
}

func (fake *volumeLifecycleFake) CreateTags(_ context.Context, input *ec2.CreateTagsInput, _ ...func(*ec2.Options)) (*ec2.CreateTagsOutput, error) {
	fake.volume.Tags = mergeTags(fake.volume.Tags, input.Tags)
	return &ec2.CreateTagsOutput{}, nil
}

func (fake *volumeLifecycleFake) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{{
		InstanceId: fake.string(fake.instanceID), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}, Tags: fake.instanceTags,
	}}}}}, nil
}

func (fake *volumeLifecycleFake) DetachVolume(context.Context, *ec2.DetachVolumeInput, ...func(*ec2.Options)) (*ec2.DetachVolumeOutput, error) {
	fake.detachCalls++
	fake.volume.Attachments = nil
	fake.volume.State = ec2types.VolumeStateAvailable
	return &ec2.DetachVolumeOutput{}, nil
}

func (fake *volumeLifecycleFake) DeleteVolume(context.Context, *ec2.DeleteVolumeInput, ...func(*ec2.Options)) (*ec2.DeleteVolumeOutput, error) {
	fake.deleteCalls++
	fake.deleted = true
	return &ec2.DeleteVolumeOutput{}, nil
}

func (*volumeLifecycleFake) string(value string) *string { return aws.String(value) }
