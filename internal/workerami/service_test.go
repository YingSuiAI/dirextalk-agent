package workerami

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrootfs"
)

func TestBuildPublishesFixedAMIAndRecoversIdempotently(t *testing.T) {
	request := validBuildRequest(t)
	provider := newFakeProvider(request)
	service := newTestService(t, provider)

	manifest, err := service.Build(context.Background(), request)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if err := manifest.Validate(); err != nil {
		t.Fatalf("manifest.Validate() = %v", err)
	}
	if manifest.ImageID != provider.image.ImageID || manifest.RootSnapshotID != provider.snapshot.SnapshotID ||
		manifest.BaseAMIID != request.BaseAMIID || manifest.BaseAMIOwnerID != request.BaseAMIOwnerID ||
		manifest.ReleaseManifestDigest != request.ReleaseManifestDigest || manifest.WorkerRootFSDigest != request.RootFS.Manifest.RootFSDigest ||
		manifest.WorkerBinaryDigest != request.RootFS.Manifest.BinaryDigest {
		t.Fatalf("manifest binding mismatch: %#v", manifest)
	}
	if provider.artifactFound || provider.builder.State != BuilderTerminated {
		t.Fatalf("temporary resources survived: artifact=%v builder=%s", provider.artifactFound, provider.builder.State)
	}
	if provider.launchCalls != 1 || provider.createCalls != 1 || provider.deleteArtifactCalls != 1 || provider.terminateCalls != 1 {
		t.Fatalf("unexpected calls: %#v", provider.calls)
	}
	assertSafeLaunch(t, provider, request)

	firstCalls := append([]string(nil), provider.calls...)
	replayed, err := service.Build(context.Background(), request)
	if err != nil {
		t.Fatalf("replayed Build() error = %v", err)
	}
	if !reflect.DeepEqual(replayed, manifest) {
		t.Fatalf("replayed manifest changed:\nfirst=%#v\nsecond=%#v", manifest, replayed)
	}
	if provider.launchCalls != 1 || provider.createCalls != 1 || len(provider.calls) <= len(firstCalls) {
		t.Fatalf("idempotent read-back mutated resources: %#v", provider.calls)
	}
	if err := service.Verify(context.Background(), manifest); err != nil {
		t.Fatalf("Verify() = %v", err)
	}
}

func TestBuildRecoversLostMutationResponses(t *testing.T) {
	for _, test := range []struct {
		name string
		set  func(*fakeProvider)
	}{
		{name: "put artifact", set: func(provider *fakeProvider) { provider.losePutResponse = true }},
		{name: "launch builder", set: func(provider *fakeProvider) { provider.loseLaunchResponse = true }},
		{name: "create image", set: func(provider *fakeProvider) { provider.loseCreateResponse = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := validBuildRequest(t)
			provider := newFakeProvider(request)
			test.set(provider)
			service := newTestService(t, provider)
			manifest, err := service.Build(context.Background(), request)
			if err != nil || manifest.ImageID == "" {
				t.Fatalf("Build() = %#v, %v", manifest, err)
			}
			if provider.artifactFound || provider.builder.State != BuilderTerminated {
				t.Fatalf("response-loss cleanup failed: %#v", provider.calls)
			}
		})
	}
}

func TestBuildReconcilesDelayedCreateImageVisibilityAndCleansFailure(t *testing.T) {
	t.Run("delayed response-loss visibility", func(t *testing.T) {
		request := validBuildRequest(t)
		provider := newFakeProvider(request)
		provider.loseCreateResponse = true
		// Call 1 is the pre-create lookup; calls 2 and 3 model eventual
		// consistency after the lost CreateImage response.
		provider.findImageMissAt = map[int]bool{2: true, 3: true}
		manifest, err := newTestService(t, provider).Build(context.Background(), request)
		if err != nil || manifest.ImageID == "" {
			t.Fatalf("Build() = %#v, %v", manifest, err)
		}
		if provider.findImageCalls < 4 || provider.createCalls != 1 {
			t.Fatalf("CreateImage was not reconciled by deterministic name: %#v", provider.calls)
		}
	})

	t.Run("failed reconcile performs delayed cleanup", func(t *testing.T) {
		request := validBuildRequest(t)
		provider := newFakeProvider(request)
		provider.loseCreateResponse = true
		provider.findImageErrorAt = map[int]bool{3: true}
		provider.findImageMissAt = map[int]bool{4: true}
		manifest, err := newTestService(t, provider).Build(context.Background(), request)
		if !errors.Is(err, ErrProviderOperation) || errors.Is(err, ErrCleanupFailed) || manifest != (ImageManifestV1{}) {
			t.Fatalf("Build() = %#v, %v", manifest, err)
		}
		if provider.imageFound || provider.snapshotFound || provider.deregisterCalls != 1 || provider.deleteSnapshotCalls != 1 {
			t.Fatalf("failed CreateImage reconcile left resources: %#v calls=%#v", provider, provider.calls)
		}
	})
}

func TestDeferredCleanupReconcilesBillingResourcesAfterDoubleAmbiguity(t *testing.T) {
	t.Run("versioned artifact", func(t *testing.T) {
		request := validBuildRequest(t)
		provider := newFakeProvider(request)
		provider.losePutResponse = true
		provider.findArtifactErrorAt = map[int]bool{2: true}
		service := newTestService(t, provider)

		manifest, err := service.Build(context.Background(), request)
		if !errors.Is(err, ErrProviderOperation) || errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("Build() = %#v, %v", manifest, err)
		}
		if manifest != (ImageManifestV1{}) || provider.artifactFound || provider.deleteArtifactCalls != 1 || provider.findArtifactCalls < 3 {
			t.Fatalf("deferred artifact reconciliation failed: %#v calls=%#v", provider, provider.calls)
		}
	})

	t.Run("builder", func(t *testing.T) {
		request := validBuildRequest(t)
		provider := newFakeProvider(request)
		provider.loseLaunchResponse = true
		provider.findBuilderMissAt = map[int]bool{2: true}
		service := newTestService(t, provider)

		manifest, err := service.Build(context.Background(), request)
		if !errors.Is(err, ErrProviderOperation) || errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("Build() = %#v, %v", manifest, err)
		}
		if manifest != (ImageManifestV1{}) || provider.builder.State != BuilderTerminated || provider.terminateCalls != 1 ||
			provider.artifactFound || provider.deleteArtifactCalls != 1 || provider.findBuilderCalls < 3 {
			t.Fatalf("deferred builder reconciliation failed: %#v calls=%#v", provider, provider.calls)
		}
	})
}

func TestBuildRejectsTamperBeforeUnsafeMutation(t *testing.T) {
	t.Run("local bytes", func(t *testing.T) {
		request := validBuildRequest(t)
		if err := os.WriteFile(request.RootFS.ArchivePath, []byte("tampered"), 0o600); err != nil {
			t.Fatal(err)
		}
		provider := newFakeProvider(request)
		service := newTestService(t, provider)
		if _, err := service.Build(context.Background(), request); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("Build() error = %v", err)
		}
		if len(provider.calls) != 0 {
			t.Fatalf("provider called before file validation: %#v", provider.calls)
		}
	})

	t.Run("builder ownership tags", func(t *testing.T) {
		request := validBuildRequest(t)
		provider := newFakeProvider(request)
		validated, err := validateBuildRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		provider.builderFound = true
		provider.builder = provider.validBuilder(validated)
		provider.builder.State = BuilderRunning
		provider.builder.Tags[TagAgentInstanceID] = "22222222-2222-4222-8222-222222222222"
		service := newTestService(t, provider)
		if _, err := service.Build(context.Background(), request); !errors.Is(err, ErrOwnershipMismatch) {
			t.Fatalf("Build() error = %v", err)
		}
		if provider.terminateCalls != 0 {
			t.Fatal("unowned builder was terminated")
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*BuilderObservationV1)
	}{
		{name: "builder base AMI", mutate: func(value *BuilderObservationV1) { value.BaseAMIID = "ami-00000000000000000" }},
		{name: "builder subnet", mutate: func(value *BuilderObservationV1) { value.PrivateSubnetID = "subnet-00000000000000000" }},
		{name: "builder security group", mutate: func(value *BuilderObservationV1) { value.ZeroIngressSGID = "sg-00000000000000000" }},
		{name: "builder instance type", mutate: func(value *BuilderObservationV1) { value.InstanceType = "t3.micro" }},
		{name: "builder root device", mutate: func(value *BuilderObservationV1) { value.RootDeviceName = "/dev/xvda" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := validBuildRequest(t)
			provider := newFakeProvider(request)
			validated, err := validateBuildRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			provider.builderFound = true
			provider.builder = provider.validBuilder(validated)
			test.mutate(&provider.builder)
			service := newTestService(t, provider)
			if _, err := service.Build(context.Background(), request); !errors.Is(err, ErrOwnershipMismatch) {
				t.Fatalf("Build() error = %v", err)
			}
			if provider.terminateCalls != 0 {
				t.Fatal("mismatched builder was terminated")
			}
		})
	}

	t.Run("foreign artifact version", func(t *testing.T) {
		request := validBuildRequest(t)
		provider := newFakeProvider(request)
		provider.artifactFound = true
		provider.artifact.VersionID = "X-Amz-Credential=foreign"
		service := newTestService(t, provider)
		if _, err := service.Build(context.Background(), request); !errors.Is(err, ErrReadBackMismatch) || !errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("Build() error = %v", err)
		}
		if provider.deleteArtifactCalls != 0 {
			t.Fatal("unvalidated artifact version was deleted")
		}
	})

	t.Run("presigned URL injection", func(t *testing.T) {
		request := validBuildRequest(t)
		provider := newFakeProvider(request)
		provider.presignedURL += "'\nshutdown -h now"
		service := newTestService(t, provider)
		if _, err := service.Build(context.Background(), request); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("Build() error = %v", err)
		}
		if provider.launchCalls != 0 || provider.artifactFound {
			t.Fatalf("unsafe launch/failed cleanup: %#v", provider.calls)
		}
	})
}

func TestBuildWithholdsManifestWhenCleanupCannotBeVerified(t *testing.T) {
	request := validBuildRequest(t)
	provider := newFakeProvider(request)
	provider.failBuilderObserveDuringCleanup = true
	service := newTestService(t, provider)

	manifest, err := service.Build(context.Background(), request)
	if !errors.Is(err, ErrCleanupFailed) {
		t.Fatalf("Build() error = %v", err)
	}
	if manifest != (ImageManifestV1{}) {
		t.Fatalf("manifest escaped failed cleanup: %#v", manifest)
	}
	if provider.deleteArtifactCalls != 1 {
		t.Fatal("artifact cleanup was skipped after builder cleanup failure")
	}
}

func TestVerifyAndDestroyRequireExactOwnedImageAndSnapshot(t *testing.T) {
	request := validBuildRequest(t)
	provider := newFakeProvider(request)
	service := newTestService(t, provider)
	manifest, err := service.Build(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}

	provider.snapshot.Tags[TagWorkerBinaryDigest] = digestOf("tampered")
	if err := service.Verify(context.Background(), manifest); !errors.Is(err, ErrReadBackMismatch) {
		t.Fatalf("Verify(tampered) = %v", err)
	}
	provider.snapshot.Tags = manifestTags(manifest)
	provider.image.Tags[TagAgentInstanceID] = "22222222-2222-4222-8222-222222222222"
	if err := service.Destroy(context.Background(), manifest); !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("Destroy(tampered) = %v", err)
	}
	if provider.deregisterCalls != 0 || provider.deleteSnapshotCalls != 0 {
		t.Fatalf("unowned resources mutated: %#v", provider.calls)
	}

	provider.image.Tags = manifestTags(manifest)
	if err := service.Destroy(context.Background(), manifest); err != nil {
		t.Fatalf("Destroy() = %v", err)
	}
	if provider.imageFound || provider.snapshotFound || provider.deregisterCalls != 1 || provider.deleteSnapshotCalls != 1 {
		t.Fatalf("destroy did not verify absence: %#v", provider.calls)
	}
	deregisterIndex, deleteIndex := callIndex(provider.calls, "deregister-image"), callIndex(provider.calls, "delete-snapshot")
	if deregisterIndex < 0 || deleteIndex <= deregisterIndex {
		t.Fatalf("destruction order changed: %#v", provider.calls)
	}
	if err := service.Destroy(context.Background(), manifest); err != nil {
		t.Fatalf("replayed Destroy() = %v", err)
	}
	if provider.deregisterCalls != 1 || provider.deleteSnapshotCalls != 1 {
		t.Fatal("replayed destruction issued duplicate mutations")
	}
}

func TestImageManifestRejectsSecretLikePersistentValues(t *testing.T) {
	request := validBuildRequest(t)
	provider := newFakeProvider(request)
	manifest, err := newTestService(t, provider).Build(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ImageName = "dtx-worker-ami-latest"
	if err := manifest.Validate(); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Validate(latest) = %v", err)
	}
	manifest.ImageName = "dtx-worker-ami-token=abc"
	if err := manifest.Validate(); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Validate(secret-like) = %v", err)
	}
}

func TestBaseAMIIdentityIsRequiredAndDigestBound(t *testing.T) {
	request := validBuildRequest(t)
	provider := newFakeProvider(request)
	manifest, err := newTestService(t, provider).Build(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	tampered := manifest
	tampered.BaseAMIID = "ami-22222222222222222"
	tamperedDigest, err := tampered.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if tamperedDigest == digest {
		t.Fatal("manifest digest did not bind base AMI ID")
	}
	tampered = manifest
	tampered.BaseAMIOwnerID = "210987654321"
	tamperedDigest, err = tampered.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if tamperedDigest == digest {
		t.Fatal("manifest digest did not bind base AMI owner")
	}

	invalid := request
	invalid.BaseAMIOwnerID = ""
	if _, err := newTestService(t, newFakeProvider(invalid)).Build(context.Background(), invalid); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Build(missing base owner) = %v", err)
	}
}

func assertSafeLaunch(t *testing.T, provider *fakeProvider, request BuildRequestV1) {
	t.Helper()
	launch := provider.launch
	if launch.AssociatePublicIPAddress || launch.AttachIAMInstanceProfile || !launch.EncryptedRootVolumeRequired ||
		!launch.DeleteRootVolumeOnTermination || !launch.IMDSv2Required || !launch.InstanceInitiatedStop ||
		launch.PrivateSubnetID != request.PrivateSubnetID || launch.ZeroIngressSGID != request.ZeroIngressSGID {
		t.Fatalf("unsafe launch specification: %#v", launch)
	}
	for _, required := range []string{
		"sha256sum --check --strict", "--numeric-owner --same-owner --same-permissions",
		"readonly expected_worker_sha256='" + strings.TrimPrefix(request.RootFS.Manifest.BinaryDigest, "sha256:") + "'",
		"test \"$(cat \"${worker_digest_file}\")\" = \"${expected_worker_sha256}\"",
		"systemctl disable dirextalk-worker-installer.socket", "systemctl enable dirextalk-cloud-worker.service",
		"systemd-sysusers", "systemd-tmpfiles", "apt-get purge -y curl",
		"dnf remove -y curl curl-minimal", "forbidden_runtime in aws node npm docker dockerd containerd",
		"forbidden_unit in docker.service docker.socket containerd.service", "forbidden_socket in /var/run/docker.sock",
		"cloud-init clean", "systemctl poweroff",
	} {
		if !strings.Contains(launch.UserData, required) {
			t.Fatalf("user-data missing fixed operation %q", required)
		}
	}
	for _, forbidden := range []string{
		request.BaseAMIID, request.PrivateSubnetID, request.ZeroIngressSGID, request.ArtifactKMSKeyARN,
		request.BuilderInstanceType, request.ReleaseManifest.ReleaseTag, "aws_access_key_id", "aws_secret_access_key",
		"systemctl enable dirextalk-worker-installer.socket", "eval ", "bash -c", "sh -c", "docker run", "podman run", "aws s3", "latest", "v1.0.3",
	} {
		if strings.Contains(strings.ToLower(launch.UserData), strings.ToLower(forbidden)) {
			t.Fatalf("user-data contains forbidden input %q", forbidden)
		}
	}
	if !strings.Contains(launch.UserData, "X-Amz-Signature=") {
		t.Fatal("fake presigned URL was not handed to the closed builder boundary")
	}
	manifestText := strings.Join([]string{provider.image.Name, provider.image.ImageID, provider.snapshot.SnapshotID}, "\n")
	if strings.Contains(manifestText, "X-Amz-") {
		t.Fatal("presigned URL entered persistent identity")
	}
	if !exactTags(provider.create.ImageTags, provider.create.SnapshotTags) || len(provider.create.ImageTags) != 4 {
		t.Fatalf("attestation tags differ: image=%#v snapshot=%#v", provider.create.ImageTags, provider.create.SnapshotTags)
	}
}

func validBuildRequest(t *testing.T) BuildRequestV1 {
	t.Helper()
	rootfs := []byte("deterministic fixed worker rootfs archive\n")
	rootfsDigest := digestOfBytes(rootfs)
	binaryDigest := digestOf("worker-binary")
	revision := strings.Repeat("a", 40)
	releaseTag := "v0.1.0-alpha.20260717.1-" + revision[:12]
	manifest := releaseartifact.ReleaseManifestV1{
		SchemaVersion: releaseartifact.SchemaVersionV1, ReleaseTag: releaseTag, GitRevision: revision,
		OS: "linux", Architecture: "amd64",
		AgentImage:         "ghcr.io/yingsuiai/dirextalk-agent:" + releaseTag + "@" + digestOf("agent-image"),
		WorkerImage:        "ghcr.io/yingsuiai/dirextalk-worker:" + releaseTag + "@" + digestOf("worker-image"),
		ReaperImage:        "ghcr.io/yingsuiai/dirextalk-reaper:" + releaseTag + "@" + digestOf("reaper-image"),
		WorkerRootFSDigest: rootfsDigest, WorkerBinaryDigest: binaryDigest, GeneratedAt: "2026-07-17T00:00:00Z",
	}
	normalized, err := releaseartifact.Normalize(manifest)
	if err != nil {
		t.Fatalf("release manifest: %v", err)
	}
	manifestDigest, err := normalized.Digest()
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "worker-rootfs.tar")
	if err := os.WriteFile(archive, rootfs, 0o600); err != nil {
		t.Fatal(err)
	}
	return BuildRequestV1{
		ReleaseManifest: normalized, ReleaseManifestDigest: manifestDigest,
		RootFS: RootFSArtifactV1{ArchivePath: archive, Manifest: workerrootfs.ManifestV1{
			Schema: workerrootfs.SchemaV1, RootFSDigest: rootfsDigest, BinaryDigest: binaryDigest, Size: int64(len(rootfs)),
		}},
		Region: "us-west-2", AccountID: "123456789012", AgentInstanceID: "11111111-1111-4111-8111-111111111111",
		BaseAMIID: "ami-0123456789abcdef0", BaseAMIOwnerID: "099720109477",
		PrivateSubnetID: "subnet-0123456789abcdef0", ZeroIngressSGID: "sg-0123456789abcdef0",
		ArtifactBucket: "dtx-agent-worker-artifacts", ArtifactKey: "worker-ami/releases/rootfs.tar",
		ArtifactKMSKeyARN:   "arn:aws:kms:us-west-2:123456789012:key/11111111-2222-4333-8444-555555555555",
		BuilderInstanceType: "m7i.large", RootDeviceName: "/dev/sda1", Timeout: 5 * time.Minute,
	}
}

func newTestService(t *testing.T, provider Provider) *Service {
	t.Helper()
	service, err := New(provider, WithPollInterval(time.Nanosecond), WithDestroyTimeout(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func digestOf(value string) string { return digestOfBytes([]byte(value)) }

func digestOfBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func callIndex(calls []string, target string) int {
	for index, call := range calls {
		if call == target {
			return index
		}
	}
	return -1
}

type fakeProvider struct {
	request BuildRequestV1
	calls   []string

	artifact      ArtifactVersionV1
	artifactFound bool
	builder       BuilderObservationV1
	builderFound  bool
	image         ImageObservationV1
	imageFound    bool
	snapshot      SnapshotObservationV1
	snapshotFound bool
	presignedURL  string
	launch        LaunchBuilderV1
	create        CreateImageV1

	losePutResponse                 bool
	loseLaunchResponse              bool
	loseCreateResponse              bool
	failBuilderObserveDuringCleanup bool
	findArtifactErrorAt             map[int]bool
	findBuilderMissAt               map[int]bool
	findImageMissAt                 map[int]bool
	findImageErrorAt                map[int]bool

	findArtifactCalls   int
	findBuilderCalls    int
	findImageCalls      int
	launchCalls         int
	createCalls         int
	terminateCalls      int
	deleteArtifactCalls int
	deregisterCalls     int
	deleteSnapshotCalls int
}

func newFakeProvider(request BuildRequestV1) *fakeProvider {
	return &fakeProvider{
		request: request, artifact: ArtifactVersionV1{VersionID: "s3-version-0001"},
		presignedURL: "https://dtx-agent-worker-artifacts.s3.us-west-2.amazonaws.com/worker-ami/releases/rootfs.tar?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=redacted&X-Amz-Date=20260717T000000Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host&X-Amz-Signature=redacted",
	}
}

func (provider *fakeProvider) ValidateEnvironment(_ context.Context, input BuildEnvironmentV1) error {
	provider.calls = append(provider.calls, "validate-environment")
	if input.Region != provider.request.Region || input.AccountID != provider.request.AccountID ||
		input.BaseAMIID != provider.request.BaseAMIID || input.BaseAMIOwnerID != provider.request.BaseAMIOwnerID ||
		input.Architecture != provider.request.ReleaseManifest.Architecture || input.RootDeviceName != provider.request.RootDeviceName ||
		input.PrivateSubnetID != provider.request.PrivateSubnetID || input.ZeroIngressSGID != provider.request.ZeroIngressSGID {
		return errors.New("environment mismatch")
	}
	return nil
}

func (provider *fakeProvider) FindArtifact(_ context.Context, _ ArtifactObjectV1) (ArtifactVersionV1, bool, error) {
	provider.calls = append(provider.calls, "find-artifact")
	provider.findArtifactCalls++
	if provider.findArtifactErrorAt[provider.findArtifactCalls] {
		return ArtifactVersionV1{}, false, errors.New("ambiguous artifact lookup")
	}
	return provider.artifact, provider.artifactFound, nil
}

func (provider *fakeProvider) PutArtifact(_ context.Context, object ArtifactObjectV1, body io.Reader) (ArtifactVersionV1, error) {
	provider.calls = append(provider.calls, "put-artifact")
	content, err := io.ReadAll(body)
	if err != nil || int64(len(content)) != object.Size || digestOfBytes(content) != object.Digest {
		return ArtifactVersionV1{}, errors.New("body mismatch")
	}
	provider.artifactFound = true
	if provider.losePutResponse {
		return ArtifactVersionV1{}, errors.New("lost put response")
	}
	return provider.artifact, nil
}

func (provider *fakeProvider) PresignArtifactGET(_ context.Context, _ ArtifactObjectV1, versionID string, _ time.Duration) (string, error) {
	provider.calls = append(provider.calls, "presign-artifact")
	if versionID != provider.artifact.VersionID {
		return "", errors.New("version mismatch")
	}
	return provider.presignedURL, nil
}

func (provider *fakeProvider) ObserveArtifactVersion(_ context.Context, _ ArtifactObjectV1, versionID string) (bool, error) {
	provider.calls = append(provider.calls, "observe-artifact")
	return provider.artifactFound && versionID == provider.artifact.VersionID, nil
}

func (provider *fakeProvider) DeleteArtifactVersion(_ context.Context, _ ArtifactObjectV1, versionID string) error {
	provider.calls = append(provider.calls, "delete-artifact")
	provider.deleteArtifactCalls++
	if versionID != provider.artifact.VersionID {
		return errors.New("version mismatch")
	}
	provider.artifactFound = false
	return nil
}

func (provider *fakeProvider) FindBuilder(_ context.Context, lookup BuilderLookupV1) (BuilderObservationV1, bool, error) {
	provider.calls = append(provider.calls, "find-builder")
	provider.findBuilderCalls++
	if provider.findBuilderMissAt[provider.findBuilderCalls] {
		return BuilderObservationV1{}, false, nil
	}
	if provider.builderFound && lookup.Name != provider.builder.Name {
		return BuilderObservationV1{}, false, errors.New("lookup mismatch")
	}
	return provider.builder, provider.builderFound, nil
}

func (provider *fakeProvider) LaunchBuilder(_ context.Context, launch LaunchBuilderV1) (BuilderObservationV1, error) {
	provider.calls = append(provider.calls, "launch-builder")
	provider.launchCalls++
	provider.launch = launch
	provider.builderFound = true
	provider.builder = BuilderObservationV1{
		InstanceID: "i-0123456789abcdef0", Name: launch.Name, State: BuilderRunning,
		BaseAMIID: launch.BaseAMIID, PrivateSubnetID: launch.PrivateSubnetID, ZeroIngressSGID: launch.ZeroIngressSGID,
		InstanceType: launch.InstanceType, RootDeviceName: launch.RootDeviceName, Tags: cloneTags(launch.Tags),
	}
	if provider.loseLaunchResponse {
		return BuilderObservationV1{}, errors.New("lost launch response")
	}
	return provider.builder, nil
}

func (provider *fakeProvider) ObserveBuilder(_ context.Context, instanceID string) (BuilderObservationV1, bool, error) {
	provider.calls = append(provider.calls, "observe-builder")
	if provider.failBuilderObserveDuringCleanup && provider.imageFound {
		return BuilderObservationV1{}, false, errors.New("observe failure")
	}
	if !provider.builderFound || instanceID != provider.builder.InstanceID {
		return BuilderObservationV1{}, false, nil
	}
	if provider.builder.State == BuilderRunning {
		provider.builder.State = BuilderStopped
	}
	return provider.builder, true, nil
}

func (provider *fakeProvider) TerminateBuilder(_ context.Context, instanceID string) error {
	provider.calls = append(provider.calls, "terminate-builder")
	provider.terminateCalls++
	if instanceID != provider.builder.InstanceID {
		return errors.New("instance mismatch")
	}
	provider.builder.State = BuilderTerminated
	return nil
}

func (provider *fakeProvider) FindImage(_ context.Context, lookup ImageLookupV1) (ImageObservationV1, bool, error) {
	provider.calls = append(provider.calls, "find-image")
	provider.findImageCalls++
	if provider.findImageErrorAt[provider.findImageCalls] {
		return ImageObservationV1{}, false, errors.New("delayed image read-back failure")
	}
	if provider.findImageMissAt[provider.findImageCalls] {
		return ImageObservationV1{}, false, nil
	}
	if provider.imageFound && lookup.Name != provider.image.Name {
		return ImageObservationV1{}, false, errors.New("lookup mismatch")
	}
	return provider.image, provider.imageFound, nil
}

func (provider *fakeProvider) CreateImage(_ context.Context, create CreateImageV1) (ImageObservationV1, error) {
	provider.calls = append(provider.calls, "create-image")
	provider.createCalls++
	provider.create = create
	provider.imageFound = true
	provider.snapshotFound = true
	provider.image = ImageObservationV1{
		ImageID: "ami-11111111111111111", Name: create.Name, AccountID: provider.request.AccountID, Region: provider.request.Region,
		Architecture: provider.request.ReleaseManifest.Architecture, RootDeviceName: provider.request.RootDeviceName,
		RootSnapshotID: "snap-11111111111111111", State: ImagePending, Tags: cloneTags(create.ImageTags),
		CreatedAt: time.Date(2026, 7, 17, 1, 2, 3, 0, time.UTC),
	}
	provider.snapshot = SnapshotObservationV1{
		SnapshotID: provider.image.RootSnapshotID, AccountID: provider.request.AccountID, Region: provider.request.Region,
		State: SnapshotCompleted, Encrypted: true, Tags: cloneTags(create.SnapshotTags),
	}
	if provider.loseCreateResponse {
		return ImageObservationV1{}, errors.New("lost create response")
	}
	return provider.image, nil
}

func (provider *fakeProvider) ObserveImage(_ context.Context, imageID string) (ImageObservationV1, bool, error) {
	provider.calls = append(provider.calls, "observe-image")
	if !provider.imageFound || imageID != provider.image.ImageID {
		return ImageObservationV1{}, false, nil
	}
	if provider.image.State == ImagePending {
		provider.image.State = ImageAvailable
	}
	return provider.image, true, nil
}

func (provider *fakeProvider) ObserveSnapshot(_ context.Context, snapshotID string) (SnapshotObservationV1, bool, error) {
	provider.calls = append(provider.calls, "observe-snapshot")
	if !provider.snapshotFound || snapshotID != provider.snapshot.SnapshotID {
		return SnapshotObservationV1{}, false, nil
	}
	return provider.snapshot, true, nil
}

func (provider *fakeProvider) DeregisterImage(_ context.Context, imageID string) error {
	provider.calls = append(provider.calls, "deregister-image")
	provider.deregisterCalls++
	if !provider.imageFound || imageID != provider.image.ImageID {
		return errors.New("image mismatch")
	}
	provider.imageFound = false
	return nil
}

func (provider *fakeProvider) DeleteSnapshot(_ context.Context, snapshotID string) error {
	provider.calls = append(provider.calls, "delete-snapshot")
	provider.deleteSnapshotCalls++
	if !provider.snapshotFound || snapshotID != provider.snapshot.SnapshotID {
		return errors.New("snapshot mismatch")
	}
	provider.snapshotFound = false
	return nil
}

func (provider *fakeProvider) validBuilder(validated validatedBuild) BuilderObservationV1 {
	return BuilderObservationV1{
		InstanceID: "i-0123456789abcdef0", Name: validated.builderName, State: BuilderRunning,
		BaseAMIID: validated.request.BaseAMIID, PrivateSubnetID: validated.request.PrivateSubnetID,
		ZeroIngressSGID: validated.request.ZeroIngressSGID, InstanceType: validated.request.BuilderInstanceType,
		RootDeviceName: validated.request.RootDeviceName, Tags: cloneTags(validated.builderTags),
	}
}

var _ Provider = (*fakeProvider)(nil)
