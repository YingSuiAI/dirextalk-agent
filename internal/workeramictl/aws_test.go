package workeramictl

import (
	"context"
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

func TestSDKIdentityReaderRequiresExactAccountBoundARN(t *testing.T) {
	reader := &sdkIdentityReader{client: fakeSTSIdentity{output: &sts.GetCallerIdentityOutput{
		Account: aws.String("123456789012"), Arn: aws.String("arn:aws:sts::123456789012:assumed-role/control/release"), UserId: aws.String("AROATEST:release"),
	}}, region: "us-east-1"}
	identity, err := reader.Read(context.Background())
	if err != nil || identity != (CallerIdentityV1{AccountID: "123456789012", Region: "us-east-1"}) {
		t.Fatalf("Read() = %#v, %v", identity, err)
	}

	reader.client = fakeSTSIdentity{output: &sts.GetCallerIdentityOutput{
		Account: aws.String("123456789012"), Arn: aws.String("arn:aws:sts::999999999999:assumed-role/control/release"), UserId: aws.String("AROATEST:release"),
	}}
	if _, err := reader.Read(context.Background()); !errors.Is(err, errIdentityMismatch) {
		t.Fatalf("Read(mismatched ARN) error = %v", err)
	}
}

func TestSDKAbsenceVerifierRequiresBothResourcesAbsent(t *testing.T) {
	manifest := validAbsenceManifest()
	client := &fakeEC2Absence{images: &ec2.DescribeImagesOutput{}, snapshots: &ec2.DescribeSnapshotsOutput{}}
	verifier := &sdkAbsenceVerifier{client: client, region: manifest.Region}
	if err := verifier.VerifyAbsent(context.Background(), manifest); err != nil {
		t.Fatalf("VerifyAbsent() error = %v", err)
	}
	if client.imageCalls != 1 || client.snapshotCalls != 1 {
		t.Fatalf("absence calls = images %d snapshots %d", client.imageCalls, client.snapshotCalls)
	}

	client.images = &ec2.DescribeImagesOutput{Images: []ec2types.Image{{ImageId: aws.String(manifest.ImageID)}}}
	if err := verifier.VerifyAbsent(context.Background(), manifest); !errors.Is(err, errCloudOperation) {
		t.Fatalf("VerifyAbsent(present image) error = %v", err)
	}

	client.images = nil
	client.imageErr = &smithy.GenericAPIError{Code: "InvalidAMIID.NotFound", Message: "not found"}
	client.snapshots = nil
	client.snapshotErr = &smithy.GenericAPIError{Code: "InvalidSnapshot.NotFound", Message: "not found"}
	if err := verifier.VerifyAbsent(context.Background(), manifest); err != nil {
		t.Fatalf("VerifyAbsent(not-found responses) error = %v", err)
	}
}

type fakeSTSIdentity struct {
	output *sts.GetCallerIdentityOutput
	err    error
}

func (fake fakeSTSIdentity) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return fake.output, fake.err
}

type fakeEC2Absence struct {
	images        *ec2.DescribeImagesOutput
	imageErr      error
	snapshots     *ec2.DescribeSnapshotsOutput
	snapshotErr   error
	imageCalls    int
	snapshotCalls int
}

func (fake *fakeEC2Absence) DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	fake.imageCalls++
	return fake.images, fake.imageErr
}

func (fake *fakeEC2Absence) DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	fake.snapshotCalls++
	return fake.snapshots, fake.snapshotErr
}

func validAbsenceManifest() workerami.ImageManifestV1 {
	return workerami.ImageManifestV1{
		SchemaVersion: workerami.ImageManifestSchemaV1, AgentInstanceID: "11111111-1111-4111-8111-111111111111",
		ImageID: "ami-11111111111111111", ImageName: "dtx-worker-ami-11111111111111111111", RootSnapshotID: "snap-11111111111111111",
		AccountID: "123456789012", Region: "us-east-1", Architecture: "amd64", BaseAMIID: "ami-0123456789abcdef0",
		BaseAMIOwnerID: "099720109477", RootDeviceName: "/dev/sda1",
		ReleaseManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		WorkerRootFSDigest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		WorkerBinaryDigest:    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		CreatedAt:             "2026-07-17T01:02:03Z",
	}
}
