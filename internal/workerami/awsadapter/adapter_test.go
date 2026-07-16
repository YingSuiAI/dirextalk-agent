package awsadapter

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	testRegion  = "us-west-2"
	testAccount = "123456789012"
	testOwner   = "099720109477"
	testAMI     = "ami-0123456789abcdef0"
	testSubnet  = "subnet-0123456789abcdef0"
	testSG      = "sg-0123456789abcdef0"
	testKMS     = "arn:aws:kms:us-west-2:123456789012:key/11111111-2222-4333-8444-555555555555"
	testDigest  = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

type fakeEC2 struct {
	describeImagesFn                func(*ec2.DescribeImagesInput) (*ec2.DescribeImagesOutput, error)
	describeSnapshotsFn             func(*ec2.DescribeSnapshotsInput) (*ec2.DescribeSnapshotsOutput, error)
	describeSubnetsFn               func(*ec2.DescribeSubnetsInput) (*ec2.DescribeSubnetsOutput, error)
	describeSecurityGroupsFn        func(*ec2.DescribeSecurityGroupsInput) (*ec2.DescribeSecurityGroupsOutput, error)
	describeInstanceTypeOfferingsFn func(*ec2.DescribeInstanceTypeOfferingsInput) (*ec2.DescribeInstanceTypeOfferingsOutput, error)
	runInstancesFn                  func(*ec2.RunInstancesInput) (*ec2.RunInstancesOutput, error)
	describeInstancesFn             func(*ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error)
	describeNetworkInterfacesFn     func(*ec2.DescribeNetworkInterfacesInput) (*ec2.DescribeNetworkInterfacesOutput, error)
	describeInstanceAttributeFn     func(*ec2.DescribeInstanceAttributeInput) (*ec2.DescribeInstanceAttributeOutput, error)
	describeVolumesFn               func(*ec2.DescribeVolumesInput) (*ec2.DescribeVolumesOutput, error)
	terminateInstancesFn            func(*ec2.TerminateInstancesInput) (*ec2.TerminateInstancesOutput, error)
	createImageFn                   func(*ec2.CreateImageInput) (*ec2.CreateImageOutput, error)
	deregisterImageFn               func(*ec2.DeregisterImageInput) (*ec2.DeregisterImageOutput, error)
	deleteSnapshotFn                func(*ec2.DeleteSnapshotInput) (*ec2.DeleteSnapshotOutput, error)
}

func (f *fakeEC2) DescribeImages(_ context.Context, in *ec2.DescribeImagesInput, _ ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	return f.describeImagesFn(in)
}
func (f *fakeEC2) DescribeSnapshots(_ context.Context, in *ec2.DescribeSnapshotsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	return f.describeSnapshotsFn(in)
}
func (f *fakeEC2) DescribeSubnets(_ context.Context, in *ec2.DescribeSubnetsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	return f.describeSubnetsFn(in)
}
func (f *fakeEC2) DescribeSecurityGroups(_ context.Context, in *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return f.describeSecurityGroupsFn(in)
}
func (f *fakeEC2) DescribeInstanceTypeOfferings(_ context.Context, in *ec2.DescribeInstanceTypeOfferingsInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceTypeOfferingsOutput, error) {
	return f.describeInstanceTypeOfferingsFn(in)
}
func (f *fakeEC2) RunInstances(_ context.Context, in *ec2.RunInstancesInput, _ ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error) {
	return f.runInstancesFn(in)
}
func (f *fakeEC2) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return f.describeInstancesFn(in)
}
func (f *fakeEC2) DescribeNetworkInterfaces(_ context.Context, in *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return f.describeNetworkInterfacesFn(in)
}
func (f *fakeEC2) DescribeInstanceAttribute(_ context.Context, in *ec2.DescribeInstanceAttributeInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceAttributeOutput, error) {
	return f.describeInstanceAttributeFn(in)
}
func (f *fakeEC2) DescribeVolumes(_ context.Context, in *ec2.DescribeVolumesInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	return f.describeVolumesFn(in)
}
func (f *fakeEC2) TerminateInstances(_ context.Context, in *ec2.TerminateInstancesInput, _ ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error) {
	return f.terminateInstancesFn(in)
}
func (f *fakeEC2) CreateImage(_ context.Context, in *ec2.CreateImageInput, _ ...func(*ec2.Options)) (*ec2.CreateImageOutput, error) {
	return f.createImageFn(in)
}
func (f *fakeEC2) DeregisterImage(_ context.Context, in *ec2.DeregisterImageInput, _ ...func(*ec2.Options)) (*ec2.DeregisterImageOutput, error) {
	return f.deregisterImageFn(in)
}
func (f *fakeEC2) DeleteSnapshot(_ context.Context, in *ec2.DeleteSnapshotInput, _ ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error) {
	return f.deleteSnapshotFn(in)
}

type fakeS3 struct {
	getBucketVersioningFn func(*s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error)
	getBucketEncryptionFn func(*s3.GetBucketEncryptionInput) (*s3.GetBucketEncryptionOutput, error)
	listObjectVersionsFn  func(*s3.ListObjectVersionsInput) (*s3.ListObjectVersionsOutput, error)
	putObjectFn           func(*s3.PutObjectInput) (*s3.PutObjectOutput, error)
	headObjectFn          func(*s3.HeadObjectInput) (*s3.HeadObjectOutput, error)
	deleteObjectFn        func(*s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error)
}

func (f *fakeS3) GetBucketVersioning(_ context.Context, in *s3.GetBucketVersioningInput, _ ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	return f.getBucketVersioningFn(in)
}
func (f *fakeS3) GetBucketEncryption(_ context.Context, in *s3.GetBucketEncryptionInput, _ ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	return f.getBucketEncryptionFn(in)
}
func (f *fakeS3) ListObjectVersions(_ context.Context, in *s3.ListObjectVersionsInput, _ ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error) {
	return f.listObjectVersionsFn(in)
}
func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return f.putObjectFn(in)
}
func (f *fakeS3) HeadObject(_ context.Context, in *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	return f.headObjectFn(in)
}
func (f *fakeS3) DeleteObject(_ context.Context, in *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	return f.deleteObjectFn(in)
}

type fakePresign struct {
	fn func(*s3.GetObjectInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}

func (f *fakePresign) PresignGetObject(_ context.Context, in *s3.GetObjectInput, options ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	return f.fn(in, options...)
}

func TestValidateEnvironmentUsesClosedReadOnlyPreflight(t *testing.T) {
	ec2Client, s3Client := validEnvironmentClients(t)
	page := 0
	ec2Client.describeInstanceTypeOfferingsFn = func(in *ec2.DescribeInstanceTypeOfferingsInput) (*ec2.DescribeInstanceTypeOfferingsOutput, error) {
		if in.LocationType != ec2types.LocationTypeRegion || len(in.Filters) != 2 {
			t.Fatalf("unexpected offering input: %#v", in)
		}
		page++
		if page == 1 {
			return &ec2.DescribeInstanceTypeOfferingsOutput{NextToken: aws.String("page-2")}, nil
		}
		if aws.ToString(in.NextToken) != "page-2" {
			t.Fatalf("next token = %q", aws.ToString(in.NextToken))
		}
		return &ec2.DescribeInstanceTypeOfferingsOutput{InstanceTypeOfferings: []ec2types.InstanceTypeOffering{{InstanceType: ec2types.InstanceTypeT3Small, Location: aws.String(testRegion)}}}, nil
	}
	adapter := newTestAdapter(t, ec2Client, s3Client, nil)
	if err := adapter.ValidateEnvironment(context.Background(), validEnvironment()); err != nil {
		t.Fatalf("ValidateEnvironment() = %v", err)
	}
	if page != 2 {
		t.Fatalf("offering pages = %d", page)
	}
}

func TestNewFromConfigRequiresCallerOwnedRegionalCredentials(t *testing.T) {
	settings := Config{Region: testRegion, AccountID: testAccount, ApprovedHTTPSCIDRs: []string{"10.0.0.0/8"}}
	if _, err := NewFromConfig(aws.Config{Region: testRegion}, settings); !errors.Is(err, workerami.ErrInvalidInput) {
		t.Fatalf("missing credentials = %v", err)
	}
	if _, err := NewFromConfig(aws.Config{Region: "eu-west-1", Credentials: aws.AnonymousCredentials{}}, settings); !errors.Is(err, workerami.ErrInvalidInput) {
		t.Fatalf("region mismatch = %v", err)
	}
	adapter, err := NewFromConfig(aws.Config{Region: testRegion, Credentials: aws.AnonymousCredentials{}}, settings)
	if err != nil || adapter == nil {
		t.Fatalf("caller-owned config = %#v, %v", adapter, err)
	}
}

func TestValidateEnvironmentRejectsUnsafeNetworkAndTamperedOwnership(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeEC2, *fakeS3)
	}{
		{"public subnet", func(ec2Client *fakeEC2, _ *fakeS3) {
			ec2Client.describeSubnetsFn = func(*ec2.DescribeSubnetsInput) (*ec2.DescribeSubnetsOutput, error) {
				return &ec2.DescribeSubnetsOutput{Subnets: []ec2types.Subnet{{SubnetId: aws.String(testSubnet), MapPublicIpOnLaunch: aws.Bool(true)}}}, nil
			}
		}},
		{"ingress", func(ec2Client *fakeEC2, _ *fakeS3) {
			ec2Client.describeSecurityGroupsFn = func(*ec2.DescribeSecurityGroupsInput) (*ec2.DescribeSecurityGroupsOutput, error) {
				return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []ec2types.SecurityGroup{{GroupId: aws.String(testSG), IpPermissions: []ec2types.IpPermission{{IpProtocol: aws.String("tcp")}}, IpPermissionsEgress: validEgress()}}}, nil
			}
		}},
		{"broad egress ports", func(ec2Client *fakeEC2, _ *fakeS3) {
			ec2Client.describeSecurityGroupsFn = func(*ec2.DescribeSecurityGroupsInput) (*ec2.DescribeSecurityGroupsOutput, error) {
				return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []ec2types.SecurityGroup{{GroupId: aws.String(testSG), IpPermissionsEgress: []ec2types.IpPermission{{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(0), ToPort: aws.Int32(65535), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("10.0.0.0/8")}}}}}}}, nil
			}
		}},
		{"wrong AMI owner", func(ec2Client *fakeEC2, _ *fakeS3) {
			ec2Client.describeImagesFn = func(*ec2.DescribeImagesInput) (*ec2.DescribeImagesOutput, error) {
				image := baseImageFixture()
				image.OwnerId = aws.String("210987654321")
				return &ec2.DescribeImagesOutput{Images: []ec2types.Image{image}}, nil
			}
		}},
		{"suspended versioning", func(_ *fakeEC2, s3Client *fakeS3) {
			s3Client.getBucketVersioningFn = func(*s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error) {
				return &s3.GetBucketVersioningOutput{Status: s3types.BucketVersioningStatusSuspended}, nil
			}
		}},
		{"wrong KMS", func(_ *fakeEC2, s3Client *fakeS3) {
			s3Client.getBucketEncryptionFn = func(*s3.GetBucketEncryptionInput) (*s3.GetBucketEncryptionOutput, error) {
				output := validEncryption()
				output.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID = aws.String("wrong")
				return output, nil
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ec2Client, s3Client := validEnvironmentClients(t)
			test.mutate(ec2Client, s3Client)
			adapter := newTestAdapter(t, ec2Client, s3Client, nil)
			if err := adapter.ValidateEnvironment(context.Background(), validEnvironment()); !errors.Is(err, workerami.ErrReadBackMismatch) {
				t.Fatalf("ValidateEnvironment() = %v", err)
			}
		})
	}
}

func TestArtifactPutReadBackFindAndPresignBindImmutableVersion(t *testing.T) {
	object := validObjectFixture()
	versionID := "version-1"
	var putSeen bool
	s3Client := &fakeS3{}
	s3Client.putObjectFn = func(in *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
		putSeen = true
		if aws.ToString(in.Bucket) != object.Bucket || aws.ToString(in.Key) != object.Key || aws.ToInt64(in.ContentLength) != object.Size || in.ChecksumAlgorithm != s3types.ChecksumAlgorithmSha256 || aws.ToString(in.ChecksumSHA256) != checksumBase64(object.Digest) || in.ServerSideEncryption != s3types.ServerSideEncryptionAwsKms || aws.ToString(in.SSEKMSKeyId) != object.KMSKeyARN || !equalMetadata(in.Metadata, artifactMetadata(object)) {
			t.Fatalf("unsafe PutObject: %#v", in)
		}
		body, err := io.ReadAll(in.Body)
		if err != nil || string(body) != "rootfs" {
			t.Fatalf("body = %q, %v", body, err)
		}
		return &s3.PutObjectOutput{VersionId: aws.String(versionID)}, nil
	}
	s3Client.headObjectFn = validHeadFn(t, object, versionID)
	s3Client.listObjectVersionsFn = func(in *s3.ListObjectVersionsInput) (*s3.ListObjectVersionsOutput, error) {
		if aws.ToString(in.Prefix) != object.Key {
			t.Fatalf("prefix = %q", aws.ToString(in.Prefix))
		}
		return &s3.ListObjectVersionsOutput{Versions: []s3types.ObjectVersion{{Key: aws.String(object.Key), VersionId: aws.String(versionID)}}}, nil
	}
	presignClient := &fakePresign{fn: func(in *s3.GetObjectInput, options ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
		settings := s3.PresignOptions{}
		for _, option := range options {
			option(&settings)
		}
		if aws.ToString(in.VersionId) != versionID || in.ChecksumMode != s3types.ChecksumModeEnabled || settings.Expires != 15*time.Minute {
			t.Fatalf("presign input = %#v, ttl=%s", in, settings.Expires)
		}
		return &v4.PresignedHTTPRequest{URL: "https://bucket.s3.us-west-2.amazonaws.com/rootfs?versionId=version-1&X-Amz-Signature=redacted"}, nil
	}}
	adapter := newTestAdapter(t, &fakeEC2{}, s3Client, presignClient)
	version, err := adapter.PutArtifact(context.Background(), object, strings.NewReader("rootfs"))
	if err != nil || version.VersionID != versionID || !putSeen {
		t.Fatalf("PutArtifact() = %#v, %v", version, err)
	}
	foundVersion, found, err := adapter.FindArtifact(context.Background(), object)
	if err != nil || !found || foundVersion.VersionID != versionID {
		t.Fatalf("FindArtifact() = %#v, %v, %v", foundVersion, found, err)
	}
	url, err := adapter.PresignArtifactGET(context.Background(), object, versionID, 15*time.Minute)
	if err != nil || !strings.Contains(url, "versionId=version-1") {
		t.Fatalf("PresignArtifactGET() = %q, %v", url, err)
	}
}

func TestFindArtifactRejectsMultipleVersionsAndTamperedReadBack(t *testing.T) {
	object := validObjectFixture()
	t.Run("multiple", func(t *testing.T) {
		s3Client := &fakeS3{listObjectVersionsFn: func(*s3.ListObjectVersionsInput) (*s3.ListObjectVersionsOutput, error) {
			return &s3.ListObjectVersionsOutput{Versions: []s3types.ObjectVersion{{Key: aws.String(object.Key), VersionId: aws.String("v1")}, {Key: aws.String(object.Key), VersionId: aws.String("v2")}}}, nil
		}, headObjectFn: func(in *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
			return validHead(object, aws.ToString(in.VersionId)), nil
		}}
		adapter := newTestAdapter(t, &fakeEC2{}, s3Client, nil)
		if _, _, err := adapter.FindArtifact(context.Background(), object); !errors.Is(err, workerami.ErrReadBackMismatch) {
			t.Fatalf("FindArtifact() = %v", err)
		}
	})
	t.Run("tampered", func(t *testing.T) {
		s3Client := &fakeS3{listObjectVersionsFn: func(*s3.ListObjectVersionsInput) (*s3.ListObjectVersionsOutput, error) {
			return &s3.ListObjectVersionsOutput{Versions: []s3types.ObjectVersion{{Key: aws.String(object.Key), VersionId: aws.String("v1")}}}, nil
		}, headObjectFn: func(*s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
			output := validHead(object, "v1")
			output.Metadata["digest"] = testDigest[:len(testDigest)-1] + "b"
			return output, nil
		}}
		adapter := newTestAdapter(t, &fakeEC2{}, s3Client, nil)
		if _, _, err := adapter.FindArtifact(context.Background(), object); !errors.Is(err, workerami.ErrReadBackMismatch) {
			t.Fatalf("FindArtifact() = %v", err)
		}
	})
}

func TestLaunchBuilderProducesSinglePrivateHardenedInstance(t *testing.T) {
	launch := validLaunchFixture()
	ec2Client := &fakeEC2{runInstancesFn: func(in *ec2.RunInstancesInput) (*ec2.RunInstancesOutput, error) {
		if aws.ToInt32(in.MinCount) != 1 || aws.ToInt32(in.MaxCount) != 1 || aws.ToString(in.ClientToken) != launch.ClientToken || in.IamInstanceProfile != nil || in.KeyName != nil || len(in.NetworkInterfaces) != 1 || aws.ToBool(in.NetworkInterfaces[0].AssociatePublicIpAddress) || len(in.NetworkInterfaces[0].Groups) != 1 || len(in.BlockDeviceMappings) != 1 || in.BlockDeviceMappings[0].Ebs == nil || !aws.ToBool(in.BlockDeviceMappings[0].Ebs.Encrypted) || !aws.ToBool(in.BlockDeviceMappings[0].Ebs.DeleteOnTermination) || in.MetadataOptions == nil || in.MetadataOptions.HttpTokens != ec2types.HttpTokensStateRequired || in.InstanceInitiatedShutdownBehavior != ec2types.ShutdownBehaviorStop || len(in.TagSpecifications) != 3 || in.TagSpecifications[2].ResourceType != ec2types.ResourceTypeNetworkInterface {
			t.Fatalf("unsafe RunInstances: %#v", in)
		}
		if _, err := base64Decode(aws.ToString(in.UserData)); err != nil {
			t.Fatalf("user data base64: %v", err)
		}
		return &ec2.RunInstancesOutput{Instances: []ec2types.Instance{launchResponseInstance(launch)}}, nil
	}}
	adapter := newTestAdapter(t, ec2Client, &fakeS3{}, nil)
	observation, err := adapter.LaunchBuilder(context.Background(), launch)
	if err != nil || observation.InstanceID == "" || observation.Name != launch.Name || !equalTags(observation.Tags, launch.Tags) {
		t.Fatalf("LaunchBuilder() = %#v, %v", observation, err)
	}
}

func TestEC2MutationsRecoverLostResponsesFromExactReadBack(t *testing.T) {
	secretError := errors.New("transport response lost credential=SHOULD_NOT_ESCAPE")
	t.Run("builder", func(t *testing.T) {
		launch := validLaunchFixture()
		instance := observedInstance(launch)
		ec2Client := observedBuilderEC2(launch, instance)
		ec2Client.runInstancesFn = func(*ec2.RunInstancesInput) (*ec2.RunInstancesOutput, error) { return nil, secretError }
		adapter := newTestAdapter(t, ec2Client, &fakeS3{}, nil)
		observation, err := adapter.LaunchBuilder(context.Background(), launch)
		if err != nil || observation.InstanceID != aws.ToString(instance.InstanceId) {
			t.Fatalf("LaunchBuilder recovery = %#v, %v", observation, err)
		}
	})
	t.Run("image", func(t *testing.T) {
		create := validCreateFixture()
		image := validPublishedImage(create)
		ec2Client := &fakeEC2{
			createImageFn: func(*ec2.CreateImageInput) (*ec2.CreateImageOutput, error) { return nil, secretError },
			describeImagesFn: func(*ec2.DescribeImagesInput) (*ec2.DescribeImagesOutput, error) {
				return &ec2.DescribeImagesOutput{Images: []ec2types.Image{image}}, nil
			},
		}
		adapter := newTestAdapter(t, ec2Client, &fakeS3{}, nil)
		observation, err := adapter.CreateImage(context.Background(), create)
		if err != nil || observation.ImageID != aws.ToString(image.ImageId) {
			t.Fatalf("CreateImage recovery = %#v, %v", observation, err)
		}
	})
}

func TestFindBuilderPaginatesAndRejectsAmbiguousOrUnsafeReadBack(t *testing.T) {
	launch := validLaunchFixture()
	instance := observedInstance(launch)
	t.Run("pagination", func(t *testing.T) {
		page := 0
		ec2Client := observedBuilderEC2(launch, instance)
		ec2Client.describeInstancesFn = func(in *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			if len(in.Filters) != 3 || !hasFilter(in.Filters, "tag:"+tagBuildDigest, launch.Tags[tagBuildDigest]) {
				t.Fatalf("FindBuilder filters = %#v", in.Filters)
			}
			page++
			if page == 1 {
				return &ec2.DescribeInstancesOutput{NextToken: aws.String("two")}, nil
			}
			return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{instance}}}}, nil
		}
		adapter := newTestAdapter(t, ec2Client, &fakeS3{}, nil)
		_, found, err := adapter.FindBuilder(context.Background(), workerami.BuilderLookupV1{Name: launch.Name, BuildDigest: launch.Tags[tagBuildDigest], AccountID: testAccount, Region: testRegion})
		if err != nil || !found || page != 2 {
			t.Fatalf("FindBuilder() found=%v pages=%d err=%v", found, page, err)
		}
	})
	t.Run("multiple", func(t *testing.T) {
		ec2Client := observedBuilderEC2(launch, instance)
		ec2Client.describeInstancesFn = func(*ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{instance, instance}}}}, nil
		}
		adapter := newTestAdapter(t, ec2Client, &fakeS3{}, nil)
		if _, _, err := adapter.FindBuilder(context.Background(), workerami.BuilderLookupV1{Name: launch.Name, BuildDigest: launch.Tags[tagBuildDigest], AccountID: testAccount, Region: testRegion}); !errors.Is(err, workerami.ErrReadBackMismatch) {
			t.Fatalf("FindBuilder() = %v", err)
		}
	})
	t.Run("public address", func(t *testing.T) {
		unsafe := instance
		unsafe.PublicIpAddress = aws.String("198.51.100.1")
		ec2Client := observedBuilderEC2(launch, unsafe)
		adapter := newTestAdapter(t, ec2Client, &fakeS3{}, nil)
		if _, _, err := adapter.ObserveBuilder(context.Background(), aws.ToString(unsafe.InstanceId)); !errors.Is(err, workerami.ErrReadBackMismatch) {
			t.Fatalf("ObserveBuilder() = %v", err)
		}
	})
}

func TestCreateAndObserveImageBindImageAndEncryptedSnapshot(t *testing.T) {
	create := validCreateFixture()
	image := validPublishedImage(create)
	ec2Client := &fakeEC2{}
	ec2Client.createImageFn = func(in *ec2.CreateImageInput) (*ec2.CreateImageOutput, error) {
		if aws.ToString(in.InstanceId) != create.BuilderInstanceID || aws.ToString(in.Name) != create.Name || !aws.ToBool(in.NoReboot) || len(in.TagSpecifications) != 2 || in.TagSpecifications[0].ResourceType != ec2types.ResourceTypeImage || in.TagSpecifications[1].ResourceType != ec2types.ResourceTypeSnapshot {
			t.Fatalf("CreateImage input = %#v", in)
		}
		return &ec2.CreateImageOutput{ImageId: image.ImageId}, nil
	}
	ec2Client.describeImagesFn = func(in *ec2.DescribeImagesInput) (*ec2.DescribeImagesOutput, error) {
		return &ec2.DescribeImagesOutput{Images: []ec2types.Image{image}}, nil
	}
	ec2Client.describeSnapshotsFn = func(in *ec2.DescribeSnapshotsInput) (*ec2.DescribeSnapshotsOutput, error) {
		return &ec2.DescribeSnapshotsOutput{Snapshots: []ec2types.Snapshot{{SnapshotId: image.BlockDeviceMappings[0].Ebs.SnapshotId, OwnerId: aws.String(testAccount), Encrypted: aws.Bool(true), State: ec2types.SnapshotStateCompleted, Tags: toTags(create.SnapshotTags)}}}, nil
	}
	adapter := newTestAdapter(t, ec2Client, &fakeS3{}, nil)
	observation, err := adapter.CreateImage(context.Background(), create)
	if err != nil || observation.RootSnapshotID == "" || !equalTags(observation.Tags, create.ImageTags) {
		t.Fatalf("CreateImage() = %#v, %v", observation, err)
	}
	snapshot, found, err := adapter.ObserveSnapshot(context.Background(), observation.RootSnapshotID)
	if err != nil || !found || !snapshot.Encrypted {
		t.Fatalf("ObserveSnapshot() = %#v, %v, %v", snapshot, found, err)
	}
}

func TestProviderErrorsAreRedactedAndRecoveryReadsExactFacts(t *testing.T) {
	secretError := errors.New("AccessDenied credential=SHOULD_NOT_ESCAPE")
	object := validObjectFixture()
	t.Run("response loss", func(t *testing.T) {
		s3Client := &fakeS3{putObjectFn: func(*s3.PutObjectInput) (*s3.PutObjectOutput, error) { return nil, secretError }, listObjectVersionsFn: func(*s3.ListObjectVersionsInput) (*s3.ListObjectVersionsOutput, error) {
			return &s3.ListObjectVersionsOutput{Versions: []s3types.ObjectVersion{{Key: aws.String(object.Key), VersionId: aws.String("recovered")}}}, nil
		}, headObjectFn: validHeadFn(t, object, "recovered")}
		adapter := newTestAdapter(t, &fakeEC2{}, s3Client, nil)
		version, err := adapter.PutArtifact(context.Background(), object, strings.NewReader("rootfs"))
		if err != nil || version.VersionID != "recovered" {
			t.Fatalf("PutArtifact recovery = %#v, %v", version, err)
		}
	})
	t.Run("redaction", func(t *testing.T) {
		s3Client := &fakeS3{putObjectFn: func(*s3.PutObjectInput) (*s3.PutObjectOutput, error) { return nil, secretError }, listObjectVersionsFn: func(*s3.ListObjectVersionsInput) (*s3.ListObjectVersionsOutput, error) {
			return &s3.ListObjectVersionsOutput{}, nil
		}}
		adapter := newTestAdapter(t, &fakeEC2{}, s3Client, nil)
		_, err := adapter.PutArtifact(context.Background(), object, strings.NewReader("rootfs"))
		if !errors.Is(err, workerami.ErrProviderOperation) || strings.Contains(err.Error(), "SHOULD_NOT_ESCAPE") {
			t.Fatalf("PutArtifact error = %v", err)
		}
	})
}

func newTestAdapter(t *testing.T, ec2Client *fakeEC2, s3Client *fakeS3, presignClient *fakePresign) *Adapter {
	t.Helper()
	if presignClient == nil {
		presignClient = &fakePresign{fn: func(*s3.GetObjectInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
			panic("unexpected presign")
		}}
	}
	adapter, err := New(Config{Region: testRegion, AccountID: testAccount, ApprovedHTTPSCIDRs: []string{"10.0.0.0/8"}, ApprovedHTTPSPrefixListIDs: []string{"pl-0123456789abcdef0"}}, ec2Client, s3Client, presignClient)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func validEnvironmentClients(t *testing.T) (*fakeEC2, *fakeS3) {
	t.Helper()
	ec2Client := &fakeEC2{}
	ec2Client.describeImagesFn = func(in *ec2.DescribeImagesInput) (*ec2.DescribeImagesOutput, error) {
		if len(in.ImageIds) != 1 || in.ImageIds[0] != testAMI || len(in.Owners) != 1 || in.Owners[0] != testOwner {
			t.Fatalf("DescribeImages input = %#v", in)
		}
		return &ec2.DescribeImagesOutput{Images: []ec2types.Image{baseImageFixture()}}, nil
	}
	ec2Client.describeSubnetsFn = func(in *ec2.DescribeSubnetsInput) (*ec2.DescribeSubnetsOutput, error) {
		return &ec2.DescribeSubnetsOutput{Subnets: []ec2types.Subnet{{SubnetId: aws.String(testSubnet), VpcId: aws.String("vpc-0123456789abcdef0"), State: ec2types.SubnetStateAvailable, MapPublicIpOnLaunch: aws.Bool(false)}}}, nil
	}
	ec2Client.describeSecurityGroupsFn = func(in *ec2.DescribeSecurityGroupsInput) (*ec2.DescribeSecurityGroupsOutput, error) {
		return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []ec2types.SecurityGroup{{GroupId: aws.String(testSG), VpcId: aws.String("vpc-0123456789abcdef0"), IpPermissionsEgress: validEgress()}}}, nil
	}
	ec2Client.describeInstanceTypeOfferingsFn = func(*ec2.DescribeInstanceTypeOfferingsInput) (*ec2.DescribeInstanceTypeOfferingsOutput, error) {
		return &ec2.DescribeInstanceTypeOfferingsOutput{InstanceTypeOfferings: []ec2types.InstanceTypeOffering{{InstanceType: ec2types.InstanceTypeT3Small, Location: aws.String(testRegion)}}}, nil
	}
	s3Client := &fakeS3{}
	s3Client.getBucketVersioningFn = func(*s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error) {
		return &s3.GetBucketVersioningOutput{Status: s3types.BucketVersioningStatusEnabled}, nil
	}
	s3Client.getBucketEncryptionFn = func(*s3.GetBucketEncryptionInput) (*s3.GetBucketEncryptionOutput, error) {
		return validEncryption(), nil
	}
	return ec2Client, s3Client
}

func validEnvironment() workerami.BuildEnvironmentV1 {
	return workerami.BuildEnvironmentV1{Region: testRegion, AccountID: testAccount, Architecture: "amd64", BaseAMIID: testAMI, BaseAMIOwnerID: testOwner, PrivateSubnetID: testSubnet, ZeroIngressSGID: testSG, ArtifactBucket: "dtx-worker-artifacts", ArtifactKMSKeyARN: testKMS, BuilderInstanceType: "t3.small", RootDeviceName: "/dev/sda1"}
}
func baseImageFixture() ec2types.Image {
	return ec2types.Image{ImageId: aws.String(testAMI), OwnerId: aws.String(testOwner), State: ec2types.ImageStateAvailable, Architecture: ec2types.ArchitectureValuesX8664, RootDeviceType: ec2types.DeviceTypeEbs, RootDeviceName: aws.String("/dev/sda1"), BlockDeviceMappings: []ec2types.BlockDeviceMapping{{DeviceName: aws.String("/dev/sda1"), Ebs: &ec2types.EbsBlockDevice{SnapshotId: aws.String("snap-0123456789abcdef0")}}}}
}
func validEgress() []ec2types.IpPermission {
	return []ec2types.IpPermission{{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(443), ToPort: aws.Int32(443), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("10.0.0.0/8")}}, PrefixListIds: []ec2types.PrefixListId{{PrefixListId: aws.String("pl-0123456789abcdef0")}}}}
}
func validEncryption() *s3.GetBucketEncryptionOutput {
	return &s3.GetBucketEncryptionOutput{ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{Rules: []s3types.ServerSideEncryptionRule{{ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{SSEAlgorithm: s3types.ServerSideEncryptionAwsKms, KMSMasterKeyID: aws.String(testKMS)}}}}}
}
func validObjectFixture() workerami.ArtifactObjectV1 {
	return workerami.ArtifactObjectV1{Bucket: "dtx-worker-artifacts", Key: "releases/rootfs.tar", KMSKeyARN: testKMS, Digest: testDigest, Size: 6}
}
func validHead(object workerami.ArtifactObjectV1, version string) *s3.HeadObjectOutput {
	return &s3.HeadObjectOutput{VersionId: aws.String(version), ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(object.KMSKeyARN), ContentLength: aws.Int64(object.Size), ChecksumSHA256: aws.String(checksumBase64(object.Digest)), Metadata: artifactMetadata(object)}
}
func validHeadFn(t *testing.T, object workerami.ArtifactObjectV1, version string) func(*s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	return func(in *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
		if aws.ToString(in.VersionId) != version || in.ChecksumMode != s3types.ChecksumModeEnabled {
			t.Fatalf("HeadObject input = %#v", in)
		}
		return validHead(object, version), nil
	}
}

func validLaunchFixture() workerami.LaunchBuilderV1 {
	buildDigest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	name := "dtx-worker-ami-builder-" + strings.TrimPrefix(buildDigest, "sha256:")[:20]
	return workerami.LaunchBuilderV1{Name: name, ClientToken: "dtx-worker-ami-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", BaseAMIID: testAMI, PrivateSubnetID: testSubnet, ZeroIngressSGID: testSG, InstanceType: "t3.small", RootDeviceName: "/dev/sda1", UserData: "#!/bin/bash\nset -euo pipefail\n", Tags: map[string]string{workerami.TagAgentInstanceID: "11111111-1111-4111-8111-111111111111", workerami.TagReleaseManifestDigest: testDigest, workerami.TagWorkerRootFSDigest: testDigest, workerami.TagWorkerBinaryDigest: testDigest, tagBuildDigest: buildDigest, tagComponent: "worker-ami-builder"}, EncryptedRootVolumeRequired: true, DeleteRootVolumeOnTermination: true, IMDSv2Required: true, InstanceInitiatedStop: true}
}
func launchResponseInstance(launch workerami.LaunchBuilderV1) ec2types.Instance {
	tags := append(toTags(launch.Tags), ec2types.Tag{Key: aws.String("Name"), Value: aws.String(launch.Name)})
	return ec2types.Instance{
		InstanceId: aws.String("i-0123456789abcdef0"), ImageId: aws.String(launch.BaseAMIID),
		SubnetId: aws.String(launch.PrivateSubnetID), InstanceType: ec2types.InstanceType(launch.InstanceType),
		RootDeviceName: aws.String(launch.RootDeviceName), SecurityGroups: []ec2types.GroupIdentifier{{GroupId: aws.String(launch.ZeroIngressSGID)}},
		State: &ec2types.InstanceState{Name: ec2types.InstanceStateNamePending}, Tags: tags,
	}
}
func observedInstance(launch workerami.LaunchBuilderV1) ec2types.Instance {
	instance := launchResponseInstance(launch)
	instance.State.Name = ec2types.InstanceStateNameStopped
	instance.MetadataOptions = &ec2types.InstanceMetadataOptionsResponse{HttpTokens: ec2types.HttpTokensStateRequired, HttpEndpoint: ec2types.InstanceMetadataEndpointStateEnabled}
	instance.NetworkInterfaces = []ec2types.InstanceNetworkInterface{{NetworkInterfaceId: aws.String("eni-0123456789abcdef0"), SubnetId: aws.String(testSubnet), Attachment: &ec2types.InstanceNetworkInterfaceAttachment{DeviceIndex: aws.Int32(0), DeleteOnTermination: aws.Bool(true)}, Groups: []ec2types.GroupIdentifier{{GroupId: aws.String(testSG)}}}}
	instance.RootDeviceName = aws.String("/dev/sda1")
	instance.RootDeviceType = ec2types.DeviceTypeEbs
	instance.BlockDeviceMappings = []ec2types.InstanceBlockDeviceMapping{{DeviceName: aws.String("/dev/sda1"), Ebs: &ec2types.EbsInstanceBlockDevice{DeleteOnTermination: aws.Bool(true), VolumeId: aws.String("vol-0123456789abcdef0")}}}
	return instance
}
func observedBuilderEC2(launch workerami.LaunchBuilderV1, instance ec2types.Instance) *fakeEC2 {
	resourceTags := append(toTags(launch.Tags), ec2types.Tag{Key: aws.String("Name"), Value: aws.String(launch.Name)})
	return &fakeEC2{describeInstancesFn: func(*ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
		return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{instance}}}}, nil
	}, describeNetworkInterfacesFn: func(*ec2.DescribeNetworkInterfacesInput) (*ec2.DescribeNetworkInterfacesOutput, error) {
		return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: []ec2types.NetworkInterface{{NetworkInterfaceId: aws.String("eni-0123456789abcdef0"), SubnetId: aws.String(testSubnet), TagSet: resourceTags}}}, nil
	}, describeVolumesFn: func(*ec2.DescribeVolumesInput) (*ec2.DescribeVolumesOutput, error) {
		return &ec2.DescribeVolumesOutput{Volumes: []ec2types.Volume{{VolumeId: aws.String("vol-0123456789abcdef0"), Encrypted: aws.Bool(true), Tags: resourceTags}}}, nil
	}, describeInstanceAttributeFn: func(*ec2.DescribeInstanceAttributeInput) (*ec2.DescribeInstanceAttributeOutput, error) {
		return &ec2.DescribeInstanceAttributeOutput{InstanceInitiatedShutdownBehavior: &ec2types.AttributeValue{Value: aws.String("stop")}}, nil
	}}
}

func validCreateFixture() workerami.CreateImageV1 {
	tags := map[string]string{workerami.TagAgentInstanceID: "11111111-1111-4111-8111-111111111111", workerami.TagReleaseManifestDigest: testDigest, workerami.TagWorkerRootFSDigest: testDigest, workerami.TagWorkerBinaryDigest: testDigest}
	return workerami.CreateImageV1{Name: "dtx-worker-ami-aaaaaaaaaaaaaaaaaaaa", BuilderInstanceID: "i-0123456789abcdef0", RootDeviceName: "/dev/sda1", ImageTags: tags, SnapshotTags: cloneMap(tags), NoReboot: true, EncryptedRootRequired: true, SingleRootSnapshotOnly: true}
}
func validPublishedImage(create workerami.CreateImageV1) ec2types.Image {
	return ec2types.Image{ImageId: aws.String("ami-0fedcba9876543210"), Name: aws.String(create.Name), OwnerId: aws.String(testAccount), Architecture: ec2types.ArchitectureValuesX8664, RootDeviceType: ec2types.DeviceTypeEbs, RootDeviceName: aws.String(create.RootDeviceName), State: ec2types.ImageStatePending, CreationDate: aws.String("2026-07-17T00:00:00Z"), Tags: toTags(create.ImageTags), BlockDeviceMappings: []ec2types.BlockDeviceMapping{{DeviceName: aws.String(create.RootDeviceName), Ebs: &ec2types.EbsBlockDevice{SnapshotId: aws.String("snap-0fedcba9876543210")}}}}
}
func cloneMap(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func hasFilter(filters []ec2types.Filter, name, value string) bool {
	for _, filter := range filters {
		if aws.ToString(filter.Name) == name && len(filter.Values) == 1 && filter.Values[0] == value {
			return true
		}
	}
	return false
}
func base64Decode(input string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(input)
}
