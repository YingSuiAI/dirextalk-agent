package awsprovider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestAttestWorkerAMIReturnsCanonicalBoundEvidence(t *testing.T) {
	now := time.Date(2026, 7, 17, 3, 4, 5, 0, time.UTC)
	request := newValidWorkerAMIAttestationRequest()
	client := validWorkerAMIAttestationFake(request)
	attestor, err := NewWorkerAMIAttestor(client, request.Region, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}

	evidence, err := attestor.AttestWorkerAMI(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if client.imageCalls != 1 || client.snapshotCalls != 1 || client.imageInput == nil || client.snapshotInput == nil {
		t.Fatalf("expected one exact AMI and snapshot read: image=%d snapshot=%d", client.imageCalls, client.snapshotCalls)
	}
	if len(client.imageInput.ImageIds) != 1 || client.imageInput.ImageIds[0] != request.AMIID || len(client.imageInput.Owners) != 1 || client.imageInput.Owners[0] != request.AccountID || len(client.imageInput.Filters) != 0 {
		t.Fatalf("DescribeImages was not narrowly scoped: %#v", client.imageInput)
	}
	if len(client.snapshotInput.SnapshotIds) != 1 || client.snapshotInput.SnapshotIds[0] != "snap-0123456789abcdef0" || len(client.snapshotInput.OwnerIds) != 1 || client.snapshotInput.OwnerIds[0] != request.AccountID || len(client.snapshotInput.Filters) != 0 {
		t.Fatalf("DescribeSnapshots was not narrowly scoped: %#v", client.snapshotInput)
	}
	if evidence.SchemaVersion != WorkerAMIAttestationSchemaV1 || evidence.AgentInstanceID != request.AgentInstanceID ||
		evidence.AMIID != request.AMIID || evidence.RootSnapshotID != "snap-0123456789abcdef0" ||
		evidence.AccountID != request.AccountID || evidence.Region != request.Region || evidence.Architecture != request.Architecture ||
		evidence.ReleaseManifestDigest != request.ReleaseManifestDigest || evidence.WorkerRootFSDigest != request.WorkerRootFSDigest ||
		evidence.WorkerBinaryDigest != request.WorkerBinaryDigest || !evidence.ObservedAt.Equal(now) {
		t.Fatalf("unexpected AMI evidence: %#v", evidence)
	}
	digest, err := evidence.Digest()
	if err != nil || !digestPattern.MatchString(digest) {
		t.Fatalf("canonical attestation digest = %q, err=%v", digest, err)
	}
	imageDigest, err := evidence.ImageDigest()
	if err != nil || !digestPattern.MatchString(imageDigest) {
		t.Fatalf("canonical image digest = %q, err=%v", imageDigest, err)
	}
	if imageDigest != "sha256:7e4a999877917727b1de25ab7a387c22d094de1fea4b265ba0a74915da8d7681" ||
		digest != "sha256:4ffd00f5983035ad459530ad4b12e165c7b05b30a766ed5e5146cea0433173c1" {
		t.Fatalf("canonical digest golden changed: image=%q attestation=%q", imageDigest, digest)
	}
	again, err := evidence.Digest()
	if err != nil || again != digest {
		t.Fatalf("attestation digest is not deterministic: first=%q second=%q err=%v", digest, again, err)
	}
	later := evidence
	later.ObservedAt = later.ObservedAt.Add(time.Minute)
	laterImageDigest, err := later.ImageDigest()
	if err != nil || laterImageDigest != imageDigest {
		t.Fatalf("observation time changed stable image digest: first=%q second=%q err=%v", imageDigest, laterImageDigest, err)
	}
	laterDigest, err := later.Digest()
	if err != nil || laterDigest == digest {
		t.Fatalf("complete attestation digest did not bind observed_at: got=%q err=%v", laterDigest, err)
	}
	changed := evidence
	changed.RootSnapshotID = "snap-11111111111111111"
	changedDigest, err := changed.Digest()
	if err != nil || changedDigest == digest {
		t.Fatalf("canonical digest did not bind root snapshot: got=%q err=%v", changedDigest, err)
	}
	changedImageDigest, err := changed.ImageDigest()
	if err != nil || changedImageDigest == imageDigest {
		t.Fatalf("image digest did not bind root snapshot: got=%q err=%v", changedImageDigest, err)
	}
}

func TestWorkerAMIAttestationRequestFromManifestBindsPublisherOutput(t *testing.T) {
	request := newValidWorkerAMIAttestationRequest()
	manifest := workerami.ImageManifestV1{
		SchemaVersion: workerami.ImageManifestSchemaV1, AgentInstanceID: request.AgentInstanceID,
		ImageID: request.AMIID, ImageName: "dtx-worker-ami-0123456789abcdefabcd",
		RootSnapshotID: "snap-0123456789abcdef0", AccountID: request.AccountID, Region: request.Region,
		Architecture: string(request.Architecture), BaseAMIID: "ami-0fedcba9876543210", BaseAMIOwnerID: "099720109477",
		RootDeviceName: request.RootDeviceName, ReleaseManifestDigest: request.ReleaseManifestDigest,
		WorkerRootFSDigest: request.WorkerRootFSDigest, WorkerBinaryDigest: request.WorkerBinaryDigest,
		CreatedAt: time.Date(2026, 7, 16, 8, 30, 0, 0, time.UTC).Format(time.RFC3339),
	}

	converted, err := WorkerAMIAttestationRequestFromManifest(manifest)
	if err != nil {
		t.Fatalf("convert published manifest: %v", err)
	}
	if converted != request {
		t.Fatalf("publication handoff mismatch: %#v", converted)
	}

	manifest.WorkerBinaryDigest = "sha256:invalid"
	if _, err := WorkerAMIAttestationRequestFromManifest(manifest); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected invalid publisher output rejection, got %v", err)
	}
}

func TestInspectWorkerAMIDerivesArtifactBindingFromMatchingAWSFacts(t *testing.T) {
	request := newValidWorkerAMIAttestationRequest()
	client := validWorkerAMIAttestationFake(request)
	attestor, err := NewWorkerAMIAttestor(client, request.Region, func() time.Time {
		return time.Date(2026, 7, 17, 5, 6, 7, 0, time.UTC)
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := attestor.InspectWorkerAMI(context.Background(), WorkerAMIInspectionRequest{
		AMIID: request.AMIID, AccountID: request.AccountID, Region: request.Region,
		Architecture: request.Architecture, RootDeviceName: request.RootDeviceName, AgentInstanceID: request.AgentInstanceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if evidence.ReleaseManifestDigest != request.ReleaseManifestDigest || evidence.WorkerRootFSDigest != request.WorkerRootFSDigest ||
		evidence.WorkerBinaryDigest != request.WorkerBinaryDigest {
		t.Fatalf("inspection did not derive exact artifact binding: %#v", evidence)
	}
	digest, err := evidence.ImageDigest()
	if err != nil || !digestPattern.MatchString(digest) {
		t.Fatalf("derived image digest = %q, err=%v", digest, err)
	}

	client.snapshots.Snapshots[0].Tags = newWorkerAMIAttestationTags(WorkerAMIAttestationRequest{
		AgentInstanceID: request.AgentInstanceID, ReleaseManifestDigest: request.ReleaseManifestDigest,
		WorkerRootFSDigest: request.WorkerRootFSDigest, WorkerBinaryDigest: differentDigest(request.WorkerBinaryDigest),
	})
	if _, err := attestor.InspectWorkerAMI(context.Background(), WorkerAMIInspectionRequest{
		AMIID: request.AMIID, AccountID: request.AccountID, Region: request.Region,
		Architecture: request.Architecture, RootDeviceName: request.RootDeviceName, AgentInstanceID: request.AgentInstanceID,
	}); !errors.Is(err, ErrReadBackMismatch) {
		t.Fatalf("inspection accepted an AMI/snapshot artifact mismatch: %v", err)
	}
}

func TestAttestWorkerAMIFailsClosedOnReplacedOrInvalidImage(t *testing.T) {
	tests := []struct {
		name              string
		wantSnapshotCalls int
		mutate            func(*workerAMIAttestationEC2Fake, WorkerAMIAttestationRequest)
	}{
		{name: "replaced AMI", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.images.Images[0].ImageId = aws.String("ami-11111111111111111")
		}},
		{name: "wrong owner", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.images.Images[0].OwnerId = aws.String("210987654321")
		}},
		{name: "not available", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.images.Images[0].State = ec2types.ImageStatePending
		}},
		{name: "wrong architecture", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.images.Images[0].Architecture = ec2types.ArchitectureValuesArm64
		}},
		{name: "wrong root device", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.images.Images[0].RootDeviceName = aws.String("/dev/xvda")
		}},
		{name: "instance store", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.images.Images[0].RootDeviceType = ec2types.DeviceTypeInstanceStore
			fake.images.Images[0].BlockDeviceMappings[0].Ebs = nil
			fake.images.Images[0].BlockDeviceMappings[0].VirtualName = aws.String("ephemeral0")
		}},
		{name: "duplicate root mapping", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.images.Images[0].BlockDeviceMappings = append(fake.images.Images[0].BlockDeviceMappings, fake.images.Images[0].BlockDeviceMappings[0])
		}},
		{name: "additional non-root mapping", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.images.Images[0].BlockDeviceMappings = append(fake.images.Images[0].BlockDeviceMappings, ec2types.BlockDeviceMapping{
				DeviceName: aws.String("/dev/sdb"), Ebs: &ec2types.EbsBlockDevice{SnapshotId: aws.String("snap-22222222222222222"), Encrypted: aws.Bool(true)},
			})
		}},
		{name: "unencrypted root mapping", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.images.Images[0].BlockDeviceMappings[0].Ebs.Encrypted = aws.Bool(false)
		}},
		{name: "wrong release tag", wantSnapshotCalls: 1, mutate: func(fake *workerAMIAttestationEC2Fake, request WorkerAMIAttestationRequest) {
			setEC2Tag(fake.images.Images[0].Tags, TagReleaseManifestDigest, differentDigest(request.ReleaseManifestDigest))
		}},
		{name: "missing agent tag", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.images.Images[0].Tags = removeEC2Tag(fake.images.Images[0].Tags, TagAgentInstanceID)
		}},
		{name: "duplicate required tag", mutate: func(fake *workerAMIAttestationEC2Fake, request WorkerAMIAttestationRequest) {
			fake.images.Images[0].Tags = append(fake.images.Images[0].Tags, ec2types.Tag{Key: aws.String(TagAgentInstanceID), Value: aws.String(request.AgentInstanceID)})
		}},
		{name: "missing image", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.images.Images = nil
		}},
		{name: "ambiguous images", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.images.Images = append(fake.images.Images, fake.images.Images[0])
		}},
		{name: "paginated images", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.images.NextToken = aws.String("more")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newValidWorkerAMIAttestationRequest()
			client := validWorkerAMIAttestationFake(request)
			test.mutate(client, request)
			attestor, err := NewWorkerAMIAttestor(client, request.Region, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			_, err = attestor.AttestWorkerAMI(context.Background(), request)
			if !errors.Is(err, ErrReadBackMismatch) || client.snapshotCalls != test.wantSnapshotCalls {
				t.Fatalf("invalid AMI did not fail before snapshot read: calls=%d err=%v", client.snapshotCalls, err)
			}
		})
	}
}

func TestAttestWorkerAMIFailsClosedOnWrongOrInvalidSnapshot(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*workerAMIAttestationEC2Fake, WorkerAMIAttestationRequest)
	}{
		{name: "wrong snapshot", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.snapshots.Snapshots[0].SnapshotId = aws.String("snap-11111111111111111")
		}},
		{name: "wrong owner", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.snapshots.Snapshots[0].OwnerId = aws.String("210987654321")
		}},
		{name: "not completed", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.snapshots.Snapshots[0].State = ec2types.SnapshotStatePending
		}},
		{name: "not encrypted", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.snapshots.Snapshots[0].Encrypted = aws.Bool(false)
		}},
		{name: "wrong binary tag", mutate: func(fake *workerAMIAttestationEC2Fake, request WorkerAMIAttestationRequest) {
			setEC2Tag(fake.snapshots.Snapshots[0].Tags, TagWorkerBinaryDigest, differentDigest(request.WorkerBinaryDigest))
		}},
		{name: "missing rootfs tag", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.snapshots.Snapshots[0].Tags = removeEC2Tag(fake.snapshots.Snapshots[0].Tags, TagWorkerRootFSDigest)
		}},
		{name: "missing snapshot", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.snapshots.Snapshots = nil
		}},
		{name: "ambiguous snapshots", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.snapshots.Snapshots = append(fake.snapshots.Snapshots, fake.snapshots.Snapshots[0])
		}},
		{name: "paginated snapshots", mutate: func(fake *workerAMIAttestationEC2Fake, _ WorkerAMIAttestationRequest) {
			fake.snapshots.NextToken = aws.String("more")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newValidWorkerAMIAttestationRequest()
			client := validWorkerAMIAttestationFake(request)
			test.mutate(client, request)
			attestor, err := NewWorkerAMIAttestor(client, request.Region, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			_, err = attestor.AttestWorkerAMI(context.Background(), request)
			if !errors.Is(err, ErrReadBackMismatch) {
				t.Fatalf("invalid snapshot did not fail closed: %v", err)
			}
		})
	}
}

func TestAttestWorkerAMIAcceptsApprovedARM64(t *testing.T) {
	request := newValidWorkerAMIAttestationRequest()
	request.Architecture = recipe.ArchitectureARM64
	client := validWorkerAMIAttestationFake(request)
	client.images.Images[0].Architecture = ec2types.ArchitectureValuesArm64
	attestor, err := NewWorkerAMIAttestor(client, request.Region, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := attestor.AttestWorkerAMI(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Architecture != recipe.ArchitectureARM64 {
		t.Fatalf("architecture = %q, want arm64", evidence.Architecture)
	}
}

func TestAttestWorkerAMIRejectsInvalidApprovalBeforeAWS(t *testing.T) {
	request := newValidWorkerAMIAttestationRequest()
	request.ReleaseManifestDigest = "latest"
	client := validWorkerAMIAttestationFake(newValidWorkerAMIAttestationRequest())
	attestor, err := NewWorkerAMIAttestor(client, request.Region, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = attestor.AttestWorkerAMI(context.Background(), request)
	if !errors.Is(err, ErrInvalidRequest) || client.imageCalls != 0 || client.snapshotCalls != 0 {
		t.Fatalf("invalid approval reached AWS: image=%d snapshot=%d err=%v", client.imageCalls, client.snapshotCalls, err)
	}
}

func newValidWorkerAMIAttestationRequest() WorkerAMIAttestationRequest {
	return WorkerAMIAttestationRequest{
		AMIID: "ami-0123456789abcdef0", AccountID: "123456789012", Region: "us-east-1",
		Architecture: recipe.ArchitectureAMD64, RootDeviceName: "/dev/sda1",
		AgentInstanceID:       "11111111-1111-4111-8111-111111111111",
		ReleaseManifestDigest: "sha256:" + repeatHex("1"),
		WorkerRootFSDigest:    "sha256:" + repeatHex("2"),
		WorkerBinaryDigest:    "sha256:" + repeatHex("3"),
	}
}

func validWorkerAMIAttestationFake(request WorkerAMIAttestationRequest) *workerAMIAttestationEC2Fake {
	tags := newWorkerAMIAttestationTags(request)
	snapshotID := "snap-0123456789abcdef0"
	return &workerAMIAttestationEC2Fake{
		images: ec2.DescribeImagesOutput{Images: []ec2types.Image{{
			ImageId: aws.String(request.AMIID), OwnerId: aws.String(request.AccountID), State: ec2types.ImageStateAvailable,
			Architecture: ec2types.ArchitectureValuesX8664, RootDeviceName: aws.String(request.RootDeviceName), RootDeviceType: ec2types.DeviceTypeEbs,
			BlockDeviceMappings: []ec2types.BlockDeviceMapping{{DeviceName: aws.String(request.RootDeviceName), Ebs: &ec2types.EbsBlockDevice{SnapshotId: aws.String(snapshotID), Encrypted: aws.Bool(true)}}},
			Tags:                tags,
		}}},
		snapshots: ec2.DescribeSnapshotsOutput{Snapshots: []ec2types.Snapshot{{
			SnapshotId: aws.String(snapshotID), OwnerId: aws.String(request.AccountID), State: ec2types.SnapshotStateCompleted,
			Encrypted: aws.Bool(true), Tags: tags,
		}}},
	}
}

func newWorkerAMIAttestationTags(request WorkerAMIAttestationRequest) []ec2types.Tag {
	return []ec2types.Tag{
		{Key: aws.String(TagAgentInstanceID), Value: aws.String(request.AgentInstanceID)},
		{Key: aws.String(TagReleaseManifestDigest), Value: aws.String(request.ReleaseManifestDigest)},
		{Key: aws.String(TagWorkerRootFSDigest), Value: aws.String(request.WorkerRootFSDigest)},
		{Key: aws.String(TagWorkerBinaryDigest), Value: aws.String(request.WorkerBinaryDigest)},
	}
}

func setEC2Tag(tags []ec2types.Tag, key, value string) {
	for index := range tags {
		if aws.ToString(tags[index].Key) == key {
			tags[index].Value = aws.String(value)
			return
		}
	}
}

func removeEC2Tag(tags []ec2types.Tag, key string) []ec2types.Tag {
	result := make([]ec2types.Tag, 0, len(tags))
	for _, tag := range tags {
		if aws.ToString(tag.Key) != key {
			result = append(result, tag)
		}
	}
	return result
}

func repeatHex(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result
}

func differentDigest(value string) string {
	if value == "sha256:"+repeatHex("f") {
		return "sha256:" + repeatHex("e")
	}
	return "sha256:" + repeatHex("f")
}

type workerAMIAttestationEC2Fake struct {
	images        ec2.DescribeImagesOutput
	snapshots     ec2.DescribeSnapshotsOutput
	imageInput    *ec2.DescribeImagesInput
	snapshotInput *ec2.DescribeSnapshotsInput
	imageCalls    int
	snapshotCalls int
}

func (fake *workerAMIAttestationEC2Fake) DescribeImages(_ context.Context, input *ec2.DescribeImagesInput, _ ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	fake.imageCalls++
	fake.imageInput = input
	return &fake.images, nil
}

func (fake *workerAMIAttestationEC2Fake) DescribeSnapshots(_ context.Context, input *ec2.DescribeSnapshotsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	fake.snapshotCalls++
	fake.snapshotInput = input
	return &fake.snapshots, nil
}
