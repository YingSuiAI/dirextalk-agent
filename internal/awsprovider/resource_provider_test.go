package awsprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestEC2ResourceProviderLaunchesHardenedWorkerFromImmutableArtifactReference(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	client := &workerEC2Fake{instanceID: "i-0123456789abcdef0", state: ec2types.InstanceStateNameRunning}
	amiReader := &workerAMIInspectionFake{evidence: validWorkerAMIInspectionEvidence(now)}
	artifactBinder := &workerArtifactBinderFake{onBind: func(WorkerArtifactBindingRequest) {
		if client.tagCalls != 0 {
			t.Fatal("Worker installer artifact binding occurred after a resource was exposed ready")
		}
	}}
	provider, err := NewEC2ResourceProvider(client, "us-east-1", func() time.Time { return now }, WithEC2ResourcePollInterval(time.Nanosecond), WithWorkerAMIInspection("123456789012", amiReader), WithWorkerArtifactBinder(artifactBinder))
	if err != nil {
		t.Fatal(err)
	}
	imageDigest, err := amiReader.evidence.ImageDigest()
	if err != nil {
		t.Fatal(err)
	}
	spec := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, Instance: &resource.AWSEC2InstanceSpecV1{
		ImageID: "ami-0123456789abcdef0", ImageDigest: imageDigest, Architecture: recipe.ArchitectureAMD64, InstanceType: "t3.large",
		InstanceProfileName: "dtx-agent-example-worker", UserDataArtifactRef: "s3://dtx-artifacts/deployments/33333333-3333-4333-8333-333333333333/launch/config.json",
		UserDataArtifactDigest: digestOf('b'), Bootstrap: testWorkerBootstrap(),
		RootDeviceName: "/dev/sda1", RootVolumeGiB: 24, RootKMSKeyID: "alias/dtx-worker",
		Market: resource.AWSMarketOnDemand, EBSOptimized: true,
	}}
	spec.Instance.Bootstrap.InstallerTrust = testProviderInstallerTrust(t, spec.Instance.Bootstrap.DeploymentID)
	spec.Instance.Bootstrap.InstallerArtifacts = providerInstallerSources(spec.Instance.Bootstrap.InstallerTrust, spec.Instance.Bootstrap.DeploymentID)
	specDigest, err := spec.Digest(resource.TypeEC2)
	if err != nil {
		t.Fatal(err)
	}
	request := resource.ProviderCreateRequest{
		ResourceID: "11111111-1111-4111-8111-111111111111", Type: resource.TypeEC2, LogicalName: "Worker Compile", Region: "us-east-1",
		SpecDigest: specDigest, ClientToken: "dtx-create-0123456789abcdef", Tags: validResourceTags("11111111-1111-4111-8111-111111111111"),
		Dependencies: []resource.ProviderDependency{{ResourceID: "22222222-2222-4222-8222-222222222222", Type: resource.TypeENI, ProviderID: "eni-0123456789abcdef0"}}, AWS: spec,
	}
	rootResourceID, _, err := resource.EmbeddedRootVolumeFacts(request.ResourceID, spec.Instance)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := provider.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !observed.Exists || observed.ProviderID != client.instanceID || observed.Tags[resourceClientTokenTag] != request.ClientToken {
		t.Fatalf("unexpected observation: %#v", observed)
	}
	if amiReader.calls != 1 || amiReader.request.AMIID != spec.Instance.ImageID || amiReader.request.AccountID != "123456789012" ||
		amiReader.request.AgentInstanceID != request.Tags[resource.TagAgentInstanceID] || amiReader.request.Architecture != spec.Instance.Architecture {
		t.Fatalf("approved AMI was not independently inspected before launch: %#v", amiReader.request)
	}
	if len(artifactBinder.requests) != 1 || artifactBinder.requests[0].InstanceID != client.instanceID ||
		artifactBinder.requests[0].DeploymentID != spec.Instance.Bootstrap.DeploymentID ||
		len(artifactBinder.requests[0].Artifacts) != len(spec.Instance.Bootstrap.InstallerArtifacts) {
		t.Fatalf("installer artifacts were not principal-bound before ready: %#v", artifactBinder.requests)
	}
	if len(observed.Embedded) != 1 || observed.Embedded[0].Type != resource.TypeEBS || observed.Embedded[0].ProviderID != "vol-0123456789abcdef0" ||
		observed.Embedded[0].Tags[resource.TagResourceID] != rootResourceID || observed.Embedded[0].Tags[resource.TagEmbeddedParentResourceID] != request.ResourceID {
		t.Fatalf("root EBS was not independently observable: %#v", observed.Embedded)
	}
	input := client.runInput
	if input == nil || aws.ToInt32(input.MinCount) != 1 || aws.ToInt32(input.MaxCount) != 1 || aws.ToString(input.ClientToken) != request.ClientToken {
		t.Fatalf("RunInstances was not typed and idempotent: %#v", input)
	}
	if len(input.NetworkInterfaces) != 1 || aws.ToString(input.NetworkInterfaces[0].NetworkInterfaceId) != "eni-0123456789abcdef0" || aws.ToInt32(input.NetworkInterfaces[0].DeviceIndex) != 0 {
		t.Fatalf("exclusive ENI was not bound: %#v", input.NetworkInterfaces)
	}
	if input.MetadataOptions == nil || input.MetadataOptions.HttpTokens != ec2types.HttpTokensStateRequired || aws.ToInt32(input.MetadataOptions.HttpPutResponseHopLimit) != 1 || input.MetadataOptions.InstanceMetadataTags != ec2types.InstanceMetadataTagsStateEnabled {
		t.Fatalf("IMDSv2 hardening is missing: %#v", input.MetadataOptions)
	}
	if len(input.BlockDeviceMappings) != 1 || input.BlockDeviceMappings[0].Ebs == nil || !aws.ToBool(input.BlockDeviceMappings[0].Ebs.Encrypted) || !aws.ToBool(input.BlockDeviceMappings[0].Ebs.DeleteOnTermination) || aws.ToString(input.BlockDeviceMappings[0].Ebs.KmsKeyId) != "alias/dtx-worker" {
		t.Fatalf("encrypted root volume is missing: %#v", input.BlockDeviceMappings)
	}
	rawTags, rawRootTags := map[string]string{}, map[string]string{}
	for _, specification := range input.TagSpecifications {
		for _, tag := range specification.Tags {
			switch specification.ResourceType {
			case ec2types.ResourceTypeInstance:
				rawTags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			case ec2types.ResourceTypeVolume:
				rawRootTags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
		}
	}
	if rawTags[TagAgentInstanceID] != request.Tags[resource.TagAgentInstanceID] || rawTags[awsResourceIDTag] != request.ResourceID || rawTags[resource.TagAgentInstanceID] != "" || rawTags[TagRetention] != RetentionEphemeral {
		t.Fatalf("AWS ownership tags do not match Foundation policy: %#v", rawTags)
	}
	if rawRootTags[awsResourceIDTag] != rootResourceID || rawRootTags[embeddedParentTag] != request.ResourceID || rawRootTags[TagRetention] != RetentionEphemeral {
		t.Fatalf("root EBS ownership tags do not bind its ledger: %#v", rawRootTags)
	}
	decoded, err := base64.StdEncoding.DecodeString(aws.ToString(input.UserData))
	if err != nil {
		t.Fatal(err)
	}
	userData := string(decoded)
	if !strings.Contains(userData, spec.Instance.UserDataArtifactRef) || !strings.Contains(userData, spec.Instance.UserDataArtifactDigest) ||
		!strings.Contains(userData, spec.Instance.Bootstrap.DeploymentID) || !strings.Contains(userData, spec.Instance.Bootstrap.WorkerID) ||
		!strings.Contains(userData, spec.Instance.Bootstrap.ControlPlaneEndpoint) || !strings.Contains(userData, `"enrollment_method":"aws_sts_sigv4"`) ||
		strings.Contains(userData, request.ClientToken) || strings.Contains(strings.ToLower(userData), "token") || strings.Contains(userData, "#!/") {
		t.Fatalf("user-data must be a secret-free immutable reference document: %s", userData)
	}
	parsed, trust, err := installerbootstrap.ParseUserData(decoded, installerbootstrap.InstanceIdentityV1{
		AccountID: "123456789012", Region: request.Region, InstanceID: client.instanceID,
	})
	if err != nil || trust == nil || parsed.InstallerTrust == nil || trust.TrustID != spec.Instance.Bootstrap.InstallerTrust.TrustID ||
		trust.Config.Binding.PlanHash == "" || trust.Config.Binding.RecipeDigest == "" {
		t.Fatalf("provider user-data lost installer approval trust: parsed=%+v trust=%+v err=%v", parsed, trust, err)
	}
	wrongOwner := validResourceTags(request.ResourceID)
	wrongOwner[resource.TagOwnerID] = "another-owner"
	if err := provider.Delete(context.Background(), resource.TypeEC2, client.instanceID, request.Region, wrongOwner); !errors.Is(err, resource.ErrReadBack) {
		t.Fatalf("destruction with mismatched ownership tags was not rejected: %v", err)
	}
}

func TestEC2ResourceProviderDoesNotReconcileHalfConfiguredWorkerAsReady(t *testing.T) {
	client := &workerEC2Fake{instanceID: "i-0123456789abcdef0", state: ec2types.InstanceStateNameRunning, tagError: errors.New("tag write lost")}
	amiReader := &workerAMIInspectionFake{evidence: validWorkerAMIInspectionEvidence(time.Now())}
	provider, err := NewEC2ResourceProvider(client, "us-east-1", time.Now, WithEC2ResourcePollInterval(time.Nanosecond), WithWorkerAMIInspection("123456789012", amiReader))
	if err != nil {
		t.Fatal(err)
	}
	imageDigest, err := amiReader.evidence.ImageDigest()
	if err != nil {
		t.Fatal(err)
	}
	spec := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, Instance: &resource.AWSEC2InstanceSpecV1{
		ImageID: "ami-0123456789abcdef0", ImageDigest: imageDigest, Architecture: recipe.ArchitectureAMD64, InstanceType: "t3.large", InstanceProfileName: "dtx-agent-example-worker",
		UserDataArtifactRef: "s3://dtx-artifacts/deployments/33333333-3333-4333-8333-333333333333/launch/config.json", UserDataArtifactDigest: digestOf('b'), Bootstrap: testWorkerBootstrap(),
		RootDeviceName: "/dev/sda1", RootVolumeGiB: 24, RootKMSKeyID: "alias/dtx-worker", Market: resource.AWSMarketOnDemand,
	}}
	digest, err := spec.Digest(resource.TypeEC2)
	if err != nil {
		t.Fatal(err)
	}
	request := resource.ProviderCreateRequest{
		ResourceID: "11111111-1111-4111-8111-111111111111", Type: resource.TypeEC2, LogicalName: "worker", Region: "us-east-1", SpecDigest: digest,
		ClientToken: "dtx-create-0123456789abcdef", Tags: validResourceTags("11111111-1111-4111-8111-111111111111"),
		Dependencies: []resource.ProviderDependency{{ResourceID: "22222222-2222-4222-8222-222222222222", Type: resource.TypeENI, ProviderID: "eni-0123456789abcdef0"}}, AWS: spec,
	}
	if _, err := provider.Create(context.Background(), request); err == nil {
		t.Fatal("ready tag failure must fail create")
	}
	if _, found, err := provider.FindByClientToken(context.Background(), resource.TypeEC2, request.Region, request.ClientToken); err != nil || found {
		t.Fatalf("half-configured Worker was exposed as ready: found=%v err=%v", found, err)
	}
}

func testWorkerBootstrap() resource.AWSWorkerBootstrapSpecV1 {
	return resource.AWSWorkerBootstrapSpecV1{
		DeploymentID: "33333333-3333-4333-8333-333333333333", WorkerID: "44444444-4444-4444-8444-444444444444",
		ControlPlaneEndpoint: "grpcs://agent.example.com:7443", EnrollmentExpectedRevision: 1,
	}
}

func testProviderInstallerTrust(t *testing.T, deploymentID string, volumes ...installer.VolumeV1) *installerbootstrap.RootTrustMaterialV1 {
	t.Helper()
	config := installer.DaemonConfigV1{
		SchemaVersion: installer.DaemonConfigSchema,
		Binding: installer.BindingV1{
			AgentInstanceID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", DeploymentID: deploymentID,
			TaskID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", PlanHash: digestOf('c'),
			ApprovalID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", RecipeDigest: digestOf('e'),
		},
		TargetRoot: installer.PreinstalledArtifactRoot,
	}
	payload := []byte("provider installer")
	digest := sha256.Sum256(payload)
	plan := installer.InstallerPlanV1{
		SchemaVersion: installer.PlanSchemaV1, Binding: config.Binding,
		Artifacts: []installer.ArtifactV1{{Name: "installer", SHA256: "sha256:" + hex.EncodeToString(digest[:]), SizeBytes: int64(len(payload)), TargetPath: installer.PreinstalledArtifactRoot + "/installer"}},
		Volumes:   append([]installer.VolumeV1(nil), volumes...),
		Commands:  []installer.CommandV1{{CommandID: "install", Argv: []string{installer.PreinstalledArtifactRoot + "/installer"}, WorkingDirectory: installer.PreinstalledArtifactRoot, TimeoutSeconds: 30, ArtifactRefs: []string{"installer"}}},
		ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
	}
	issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	delivery, err := issuer.Issue(plan, config, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	root, err := delivery.RootTrustMaterial(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	material, err := installerbootstrap.NewRootTrustMaterial(root)
	if err != nil {
		t.Fatal(err)
	}
	return &material
}

func providerInstallerSources(trust *installerbootstrap.RootTrustMaterialV1, deploymentID string) []installerbootstrap.ArtifactSourceV1 {
	artifact := trust.ArtifactManifest.Manifest.Artifacts[0]
	return []installerbootstrap.ArtifactSourceV1{{
		SchemaVersion: installerbootstrap.ArtifactSourceSchemaV1, Name: artifact.Name, Bucket: "dtx-artifacts",
		Key: "deployments/" + deploymentID + "/artifacts/" + artifact.Name, VersionID: "version-1",
		KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-4333-8444-555555555555",
		SHA256:    artifact.SHA256, SizeBytes: artifact.SizeBytes, TargetPath: artifact.TargetPath,
		RecipeDigest: trust.ArtifactManifest.Manifest.Binding.RecipeDigest,
	}}
}

func TestEC2ResourceProviderFailsClosedBeforeLaunchWithoutExactAMIInspection(t *testing.T) {
	client := &workerEC2Fake{}
	provider, err := NewEC2ResourceProvider(client, "us-east-1", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	spec := &resource.AWSEC2InstanceSpecV1{
		ImageID: "ami-0123456789abcdef0", ImageDigest: digestOf('a'), Architecture: recipe.ArchitectureAMD64, RootDeviceName: "/dev/sda1",
	}
	request := resource.ProviderCreateRequest{Region: "us-east-1", Tags: validResourceTags("11111111-1111-4111-8111-111111111111")}
	if err := provider.verifyApprovedWorkerAMI(context.Background(), request, spec); !errors.Is(err, resource.ErrReadBack) {
		t.Fatalf("missing AMI reader did not fail closed: %v", err)
	}

	reader := &workerAMIInspectionFake{evidence: validWorkerAMIInspectionEvidence(time.Now())}
	provider, err = NewEC2ResourceProvider(client, "us-east-1", time.Now, WithWorkerAMIInspection("123456789012", reader))
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.verifyApprovedWorkerAMI(context.Background(), request, spec); !errors.Is(err, resource.ErrReadBack) || reader.calls != 1 {
		t.Fatalf("mismatched approved image digest did not fail closed: calls=%d err=%v", reader.calls, err)
	}
	if client.runInput != nil {
		t.Fatal("AMI preflight reached RunInstances")
	}
}

func TestEC2ResourceProviderUsesApprovedExistingSecurityGroupWithoutOwningIt(t *testing.T) {
	client := &networkInterfaceEC2Fake{interfaceID: "eni-0123456789abcdef0"}
	provider, err := NewEC2ResourceProvider(client, "us-east-1", time.Now, WithEC2ResourcePollInterval(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	spec := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, NetworkInterface: &resource.AWSNetworkInterfaceSpecV1{
		SubnetID: "subnet-0123456789abcdef0", Description: "exclusive worker interface", ExistingSecurityGroupID: "sg-0123456789abcdef0",
	}}
	digest, err := spec.Digest(resource.TypeENI)
	if err != nil {
		t.Fatal(err)
	}
	request := resource.ProviderCreateRequest{
		ResourceID: "11111111-1111-4111-8111-111111111111", Type: resource.TypeENI, LogicalName: "worker-eni", Region: "us-east-1",
		SpecDigest: digest, ClientToken: "dtx-eni-0123456789", Tags: validResourceTags("11111111-1111-4111-8111-111111111111"), AWS: spec,
	}
	if _, err := provider.Create(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if client.createInput == nil || len(client.createInput.Groups) != 1 || client.createInput.Groups[0] != spec.NetworkInterface.ExistingSecurityGroupID {
		t.Fatalf("approved existing security group was not used: %#v", client.createInput)
	}
	request.Dependencies = []resource.ProviderDependency{{ResourceID: "22222222-2222-4222-8222-222222222222", Type: resource.TypeSG, ProviderID: "sg-0fedcba9876543210"}}
	if _, err := provider.Create(context.Background(), request); !errors.Is(err, resource.ErrInvalid) {
		t.Fatalf("existing and owned security groups must be mutually exclusive, got %v", err)
	}
}

func TestEC2ResourceProviderListsEveryOwnedPage(t *testing.T) {
	agentID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	rootTags := validResourceTags("33333333-3333-4333-8333-333333333333")
	rootTags[resource.TagEmbeddedParentResourceID] = "11111111-1111-4111-8111-111111111111"
	client := &paginatedEC2Fake{
		tags:       ec2Tags(validResourceTags("11111111-1111-4111-8111-111111111111")),
		volumeTags: ec2Tags(rootTags),
	}
	provider, err := NewEC2ResourceProvider(client, "us-east-1", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := provider.ListOwned(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(observed) != 3 || observed[0].ProviderID != "vol-03333333333333333" ||
		observed[0].Tags[resource.TagEmbeddedParentResourceID] == "" ||
		observed[1].ProviderID != "i-01111111111111111" || observed[2].ProviderID != "i-02222222222222222" || client.instancePages != 2 {
		t.Fatalf("owned pagination was incomplete: pages=%d resources=%#v", client.instancePages, observed)
	}
}

type workerEC2Fake struct {
	EC2ResourceAPI
	instanceID string
	state      ec2types.InstanceStateName
	tags       []ec2types.Tag
	volumeTags []ec2types.Tag
	runInput   *ec2.RunInstancesInput
	tagError   error
	tagCalls   int
}

func (fake *workerEC2Fake) RunInstances(_ context.Context, input *ec2.RunInstancesInput, _ ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error) {
	fake.runInput = input
	for _, specification := range input.TagSpecifications {
		switch specification.ResourceType {
		case ec2types.ResourceTypeInstance:
			fake.tags = append([]ec2types.Tag(nil), specification.Tags...)
		case ec2types.ResourceTypeVolume:
			fake.volumeTags = append([]ec2types.Tag(nil), specification.Tags...)
		}
	}
	return &ec2.RunInstancesOutput{Instances: []ec2types.Instance{{InstanceId: aws.String(fake.instanceID)}}}, nil
}

func (fake *workerEC2Fake) DescribeInstances(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if len(input.Filters) > 0 && !matchesFilters(fake.tags, input.Filters) {
		return &ec2.DescribeInstancesOutput{}, nil
	}
	instance := ec2types.Instance{
		InstanceId: aws.String(fake.instanceID), State: &ec2types.InstanceState{Name: fake.state}, Tags: append([]ec2types.Tag(nil), fake.tags...),
		ImageId: fake.runInput.ImageId, InstanceType: fake.runInput.InstanceType, EbsOptimized: fake.runInput.EbsOptimized,
		IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: aws.String("arn:aws:iam::123456789012:instance-profile/" + aws.ToString(fake.runInput.IamInstanceProfile.Name))},
		MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
			HttpEndpoint: fake.runInput.MetadataOptions.HttpEndpoint, HttpTokens: fake.runInput.MetadataOptions.HttpTokens,
			HttpPutResponseHopLimit: fake.runInput.MetadataOptions.HttpPutResponseHopLimit, InstanceMetadataTags: fake.runInput.MetadataOptions.InstanceMetadataTags,
			State: ec2types.InstanceMetadataOptionsStateApplied,
		},
		NetworkInterfaces: []ec2types.InstanceNetworkInterface{{NetworkInterfaceId: fake.runInput.NetworkInterfaces[0].NetworkInterfaceId}},
		BlockDeviceMappings: []ec2types.InstanceBlockDeviceMapping{{DeviceName: fake.runInput.BlockDeviceMappings[0].DeviceName, Ebs: &ec2types.EbsInstanceBlockDevice{
			VolumeId: aws.String("vol-0123456789abcdef0"), DeleteOnTermination: aws.Bool(true),
		}}},
	}
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{instance}}}}, nil
}

func (fake *workerEC2Fake) DescribeVolumes(_ context.Context, input *ec2.DescribeVolumesInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	if len(input.Filters) > 0 && !matchesFilters(fake.volumeTags, input.Filters) {
		return &ec2.DescribeVolumesOutput{}, nil
	}
	if len(input.VolumeIds) > 0 && (len(input.VolumeIds) != 1 || input.VolumeIds[0] != "vol-0123456789abcdef0") {
		return &ec2.DescribeVolumesOutput{}, nil
	}
	ebs := fake.runInput.BlockDeviceMappings[0].Ebs
	return &ec2.DescribeVolumesOutput{Volumes: []ec2types.Volume{{
		VolumeId: aws.String("vol-0123456789abcdef0"), Encrypted: aws.Bool(true), Size: ebs.VolumeSize,
		VolumeType: ec2types.VolumeTypeGp3, KmsKeyId: aws.String("arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"),
		Tags: append([]ec2types.Tag(nil), fake.volumeTags...),
	}}}, nil
}

func (fake *workerEC2Fake) CreateTags(_ context.Context, input *ec2.CreateTagsInput, _ ...func(*ec2.Options)) (*ec2.CreateTagsOutput, error) {
	fake.tagCalls++
	if fake.tagError != nil {
		return nil, fake.tagError
	}
	if len(input.Resources) == 1 && strings.HasPrefix(input.Resources[0], "vol-") {
		fake.volumeTags = mergeTags(fake.volumeTags, input.Tags)
	} else {
		fake.tags = mergeTags(fake.tags, input.Tags)
	}
	return &ec2.CreateTagsOutput{}, nil
}

type networkInterfaceEC2Fake struct {
	EC2ResourceAPI
	interfaceID string
	tags        []ec2types.Tag
	createInput *ec2.CreateNetworkInterfaceInput
}

type paginatedEC2Fake struct {
	EC2ResourceAPI
	tags          []ec2types.Tag
	volumeTags    []ec2types.Tag
	instancePages int
}

func (fake *paginatedEC2Fake) DescribeInstances(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	fake.instancePages++
	id, next := "i-01111111111111111", aws.String("second")
	if aws.ToString(input.NextToken) == "second" {
		id, next = "i-02222222222222222", nil
	}
	instance := ec2types.Instance{InstanceId: aws.String(id), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}, Tags: fake.tags}
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{instance}}}, NextToken: next}, nil
}

func (fake *paginatedEC2Fake) DescribeVolumes(_ context.Context, input *ec2.DescribeVolumesInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	if len(fake.volumeTags) == 0 || !matchesFilters(fake.volumeTags, input.Filters) {
		return &ec2.DescribeVolumesOutput{}, nil
	}
	return &ec2.DescribeVolumesOutput{Volumes: []ec2types.Volume{{
		VolumeId: aws.String("vol-03333333333333333"), State: ec2types.VolumeStateAvailable,
		Tags: append([]ec2types.Tag(nil), fake.volumeTags...),
	}}}, nil
}

func (fake *paginatedEC2Fake) DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return &ec2.DescribeNetworkInterfacesOutput{}, nil
}

func (fake *paginatedEC2Fake) DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	return &ec2.DescribeAddressesOutput{}, nil
}

func (fake *paginatedEC2Fake) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{}, nil
}

func (fake *paginatedEC2Fake) DescribeVpcEndpoints(context.Context, *ec2.DescribeVpcEndpointsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error) {
	return &ec2.DescribeVpcEndpointsOutput{}, nil
}

func (fake *paginatedEC2Fake) DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	return &ec2.DescribeSnapshotsOutput{}, nil
}

func (fake *networkInterfaceEC2Fake) CreateNetworkInterface(_ context.Context, input *ec2.CreateNetworkInterfaceInput, _ ...func(*ec2.Options)) (*ec2.CreateNetworkInterfaceOutput, error) {
	fake.createInput = input
	if len(input.TagSpecifications) == 1 {
		fake.tags = append([]ec2types.Tag(nil), input.TagSpecifications[0].Tags...)
	}
	return &ec2.CreateNetworkInterfaceOutput{NetworkInterface: &ec2types.NetworkInterface{NetworkInterfaceId: aws.String(fake.interfaceID), Status: ec2types.NetworkInterfaceStatusAvailable}}, nil
}

func (fake *networkInterfaceEC2Fake) DescribeNetworkInterfaces(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	if len(input.Filters) > 0 && !matchesFilters(fake.tags, input.Filters) {
		return &ec2.DescribeNetworkInterfacesOutput{}, nil
	}
	value := ec2types.NetworkInterface{
		NetworkInterfaceId: aws.String(fake.interfaceID), Status: ec2types.NetworkInterfaceStatusAvailable, TagSet: append([]ec2types.Tag(nil), fake.tags...),
		SubnetId: fake.createInput.SubnetId, Groups: []ec2types.GroupIdentifier{{GroupId: aws.String(fake.createInput.Groups[0])}},
	}
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: []ec2types.NetworkInterface{value}}, nil
}

func (fake *networkInterfaceEC2Fake) CreateTags(_ context.Context, input *ec2.CreateTagsInput, _ ...func(*ec2.Options)) (*ec2.CreateTagsOutput, error) {
	fake.tags = mergeTags(fake.tags, input.Tags)
	return &ec2.CreateTagsOutput{}, nil
}

func matchesFilters(tags []ec2types.Tag, filters []ec2types.Filter) bool {
	values := make(map[string]string, len(tags))
	for _, tag := range tags {
		values[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	for _, filter := range filters {
		name := aws.ToString(filter.Name)
		if !strings.HasPrefix(name, "tag:") || len(filter.Values) != 1 || values[strings.TrimPrefix(name, "tag:")] != filter.Values[0] {
			return false
		}
	}
	return true
}

func mergeTags(current, additions []ec2types.Tag) []ec2types.Tag {
	values := tagsFromEC2(current)
	for _, tag := range additions {
		values[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return ec2Tags(values)
}

func validResourceTags(resourceID string) map[string]string {
	return map[string]string{
		resource.TagAgentInstanceID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", resource.TagOwnerID: "owner-1",
		resource.TagTaskID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", resource.TagDeploymentID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		resource.TagResourceID: resourceID, resource.TagRetention: "ephemeral_auto_destroy", resource.TagDestroyDeadline: "2026-07-16T13:00:00Z",
	}
}

func digestOf(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}

type workerAMIInspectionFake struct {
	evidence WorkerAMIAttestationV1
	err      error
	request  WorkerAMIInspectionRequest
	calls    int
}

func (fake *workerAMIInspectionFake) InspectWorkerAMI(_ context.Context, request WorkerAMIInspectionRequest) (WorkerAMIAttestationV1, error) {
	fake.calls++
	fake.request = request
	return fake.evidence, fake.err
}

func validWorkerAMIInspectionEvidence(observedAt time.Time) WorkerAMIAttestationV1 {
	return WorkerAMIAttestationV1{
		SchemaVersion: WorkerAMIAttestationSchemaV1, AgentInstanceID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		AMIID: "ami-0123456789abcdef0", RootSnapshotID: "snap-0123456789abcdef0", AccountID: "123456789012",
		Region: "us-east-1", Architecture: recipe.ArchitectureAMD64,
		ReleaseManifestDigest: digestOf('c'), WorkerRootFSDigest: digestOf('d'), WorkerBinaryDigest: digestOf('e'),
		ObservedAt: observedAt,
	}
}
