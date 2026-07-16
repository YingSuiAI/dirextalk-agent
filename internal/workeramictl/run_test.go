package workeramictl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami/awsadapter"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrootfs"
	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestRunBuildAttestsAndWritesExclusiveCanonicalManifest(t *testing.T) {
	fixture := newBuildFixture(t)
	cloud := newFakeCloud(fixture.image, fixture.evidence)
	output := filepath.Join(t.TempDir(), "publication.json")
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{"build", "--request", fixture.requestPath, "--output", output}, &stdout, &stderr, cloud.dependencies())
	if code != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("Run(build) = %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if cloud.identityReads != 1 || cloud.buildCalls != 1 || cloud.attestCalls != 1 || cloud.destroyCalls != 0 {
		t.Fatalf("unexpected cloud calls: %#v", cloud)
	}
	publication, err := readPublicationManifest(output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if publication.ImageManifest != fixture.image || publication.ImageDigest == "" || publication.Attestation.AMIID != fixture.image.ImageID {
		t.Fatalf("publication = %#v", publication)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalPublicationJSON(publication)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, append(canonical, '\n')) {
		t.Fatalf("output is not canonical: %q", raw)
	}
	if _, err := os.Stat(buildIntentPath(output)); !os.IsNotExist(err) {
		t.Fatalf("successful build left intent behind: %v", err)
	}

	cloud = newFakeCloud(fixture.image, fixture.evidence)
	stderr.Reset()
	if code := Run(context.Background(), []string{"build", "--request", fixture.requestPath, "--output", output}, ioDiscardBuffer{}, &stderr, cloud.dependencies()); code != 0 {
		t.Fatalf("exact final replay failed: %q", stderr.String())
	}
	if cloud.buildCalls != 0 || cloud.verifyCalls != 1 || cloud.attestCalls != 1 || cloud.destroyCalls != 0 {
		t.Fatalf("existing output was not verified as an exact replay: %#v", cloud)
	}
	afterReplay, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(afterReplay, raw) {
		t.Fatal("exact replay replaced the O_EXCL publication")
	}
}

func TestRunBuildRecoversSameIntentAfterProcessCrash(t *testing.T) {
	fixture := newBuildFixture(t)
	prepared, err := parseBuildRequest(fixture.requestPath)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "publication.json")
	if err := ensureBuildIntent(output, prepared.intent); err != nil {
		t.Fatal(err)
	}
	intentBytes, err := os.ReadFile(buildIntentPath(output))
	if err != nil {
		t.Fatal(err)
	}
	canonicalIntent, err := canonicalBuildIntentJSON(prepared.intent)
	if err != nil || !bytes.Equal(intentBytes, append(canonicalIntent, '\n')) {
		t.Fatal("crash-recovery intent is not canonical")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(buildIntentPath(output))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("build intent permissions = %v, want 0600", info)
		}
	}

	cloud := newFakeCloud(fixture.image, fixture.evidence)
	var stderr bytes.Buffer
	if code := Run(context.Background(), []string{"build", "--request", fixture.requestPath, "--output", output}, ioDiscardBuffer{}, &stderr, cloud.dependencies()); code != 0 {
		t.Fatalf("same-intent recovery failed: %q", stderr.String())
	}
	if cloud.buildCalls != 1 || cloud.attestCalls != 1 {
		t.Fatalf("deterministic recovery did not resume build: %#v", cloud)
	}
	if _, err := os.Stat(buildIntentPath(output)); !os.IsNotExist(err) {
		t.Fatalf("recovery did not clean intent: %v", err)
	}
	if _, err := readPublicationManifest(output); err != nil {
		t.Fatalf("recovery did not persist final publication: %v", err)
	}
}

func TestRunBuildRejectsDifferentRequestForExistingIntent(t *testing.T) {
	fixture := newBuildFixture(t)
	prepared, err := parseBuildRequest(fixture.requestPath)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "publication.json")
	if err := ensureBuildIntent(output, prepared.intent); err != nil {
		t.Fatal(err)
	}
	input, err := os.ReadFile(fixture.requestPath)
	if err != nil {
		t.Fatal(err)
	}
	var changed BuildRequestFileV1
	if err := json.Unmarshal(input, &changed); err != nil {
		t.Fatal(err)
	}
	changed.BuilderInstanceType = "t3.small"
	changedPath := writeJSON(t, "changed-build.json", changed)
	cloud := newFakeCloud(fixture.image, fixture.evidence)
	var stderr bytes.Buffer
	if code := Run(context.Background(), []string{"build", "--request", changedPath, "--output", output}, ioDiscardBuffer{}, &stderr, cloud.dependencies()); code == 0 {
		t.Fatal("different request reused an existing build intent")
	}
	if cloud.loadCalls != 0 || cloud.buildCalls != 0 {
		t.Fatalf("different request reached AWS: %#v", cloud)
	}
}

func TestRunBuildVerifiesFinalThenRemovesCrashLeftIntent(t *testing.T) {
	fixture := newBuildFixture(t)
	prepared, err := parseBuildRequest(fixture.requestPath)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := newPublicationManifest(fixture.image, fixture.evidence)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "publication.json")
	if err := ensureBuildIntent(output, prepared.intent); err != nil {
		t.Fatal(err)
	}
	if err := writeFinalPublication(output, publication); err != nil {
		t.Fatal(err)
	}
	cloud := newFakeCloud(fixture.image, fixture.evidence)
	var stderr bytes.Buffer
	if code := Run(context.Background(), []string{"build", "--request", fixture.requestPath, "--output", output}, ioDiscardBuffer{}, &stderr, cloud.dependencies()); code != 0 {
		t.Fatalf("final+intent replay failed: %q", stderr.String())
	}
	if cloud.buildCalls != 0 || cloud.verifyCalls != 1 || cloud.attestCalls != 1 {
		t.Fatalf("final replay was not independently verified: %#v", cloud)
	}
	if _, err := os.Stat(buildIntentPath(output)); !os.IsNotExist(err) {
		t.Fatalf("verified final replay did not remove intent: %v", err)
	}
}

func TestRunBuildRejectsRootFSDigestOrStrictJSONBeforeAWS(t *testing.T) {
	fixture := newBuildFixture(t)
	cloud := newFakeCloud(fixture.image, fixture.evidence)

	requestBytes, err := os.ReadFile(fixture.requestPath)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(requestBytes, []byte(`"account_id":"123456789012"`), []byte(`"account_id":"123456789012","account_id":"123456789012"`), 1)
	duplicatePath := writeBytes(t, "duplicate.json", duplicate)
	var stderr bytes.Buffer
	if code := Run(context.Background(), []string{"build", "--request", duplicatePath, "--output", filepath.Join(t.TempDir(), "out.json")}, ioDiscardBuffer{}, &stderr, cloud.dependencies()); code == 0 {
		t.Fatal("build accepted a duplicate JSON field")
	}
	if cloud.loadCalls != 0 || cloud.buildCalls != 0 {
		t.Fatalf("AWS reached for invalid JSON: %#v", cloud)
	}

	if err := os.WriteFile(fixture.archivePath, []byte("changed-rootfs"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := Run(context.Background(), []string{"build", "--request", fixture.requestPath, "--output", filepath.Join(t.TempDir(), "out.json")}, ioDiscardBuffer{}, &stderr, cloud.dependencies()); code == 0 {
		t.Fatal("build accepted changed rootfs bytes")
	}
	if cloud.loadCalls != 0 || cloud.buildCalls != 0 {
		t.Fatalf("AWS reached for mismatched rootfs: %#v", cloud)
	}
}

func TestRunBuildRejectsReleaseWorkerDigestNotBoundToArchive(t *testing.T) {
	fixture := newBuildFixture(t)
	releaseInput, err := os.ReadFile(fixture.releasePath)
	if err != nil {
		t.Fatal(err)
	}
	release, err := releaseartifact.ParseJSON(releaseInput)
	if err != nil {
		t.Fatal(err)
	}
	release.WorkerBinaryDigest = "sha256:" + strings.Repeat("a", 64)
	encoded, err := json.Marshal(release)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.releasePath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	cloud := newFakeCloud(fixture.image, fixture.evidence)
	var stderr bytes.Buffer
	if code := Run(context.Background(), []string{"build", "--request", fixture.requestPath, "--output", filepath.Join(t.TempDir(), "out.json")}, ioDiscardBuffer{}, &stderr, cloud.dependencies()); code == 0 {
		t.Fatal("build accepted a release Worker digest not present in the rootfs archive")
	}
	if cloud.loadCalls != 0 || cloud.buildCalls != 0 {
		t.Fatalf("AWS reached for an unbound Worker binary: %#v", cloud)
	}
}

func TestRunRejectsCallerAccountMismatchBeforeMutation(t *testing.T) {
	fixture := newBuildFixture(t)
	cloud := newFakeCloud(fixture.image, fixture.evidence)
	cloud.identity = CallerIdentityV1{AccountID: "999999999999", Region: fixture.image.Region}
	var stderr bytes.Buffer
	if code := Run(context.Background(), []string{"build", "--request", fixture.requestPath, "--output", filepath.Join(t.TempDir(), "out.json")}, ioDiscardBuffer{}, &stderr, cloud.dependencies()); code == 0 {
		t.Fatal("build accepted mismatched caller account")
	}
	if cloud.buildCalls != 0 || cloud.attestCalls != 0 {
		t.Fatalf("mutation happened before account confirmation: %#v", cloud)
	}
}

func TestRunVerifyPerformsServiceAndIndependentAttestationReadBack(t *testing.T) {
	fixture := newBuildFixture(t)
	publicationPath := writePublication(t, fixture.image, fixture.evidence)
	cloud := newFakeCloud(fixture.image, fixture.evidence)
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"verify", "--manifest", publicationPath}, &stdout, &stderr, cloud.dependencies())
	if code != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("Run(verify) = %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if cloud.verifyCalls != 1 || cloud.attestCalls != 1 {
		t.Fatalf("verify did not perform both read-backs: %#v", cloud)
	}
}

func TestRunDestroyRequiresExactAccountAndImageDigestThenReadsAbsence(t *testing.T) {
	fixture := newBuildFixture(t)
	publicationPath := writePublication(t, fixture.image, fixture.evidence)
	publication, err := readPublicationManifest(publicationPath)
	if err != nil {
		t.Fatal(err)
	}
	cloud := newFakeCloud(fixture.image, fixture.evidence)

	bad := DestroyRequestFileV1{
		SchemaVersion: DestroyRequestSchemaV1, PublicationManifestPath: publicationPath,
		ConfirmAccountID: fixture.image.AccountID, ConfirmImageDigest: "sha256:" + strings.Repeat("f", 64),
	}
	badPath := writeJSON(t, "destroy-bad.json", bad)
	var stderr bytes.Buffer
	if code := Run(context.Background(), []string{"destroy", "--request", badPath}, ioDiscardBuffer{}, &stderr, cloud.dependencies()); code == 0 {
		t.Fatal("destroy accepted the wrong image digest")
	}
	if cloud.loadCalls != 0 || cloud.destroyCalls != 0 {
		t.Fatalf("AWS reached before destroy confirmation: %#v", cloud)
	}

	good := bad
	good.ConfirmImageDigest = publication.ImageDigest
	goodPath := writeJSON(t, "destroy-good.json", good)
	stderr.Reset()
	if code := Run(context.Background(), []string{"destroy", "--request", goodPath}, ioDiscardBuffer{}, &stderr, cloud.dependencies()); code != 0 {
		t.Fatalf("destroy failed: %q", stderr.String())
	}
	if cloud.destroyCalls != 1 || cloud.absenceCalls != 1 {
		t.Fatalf("destroy did not independently confirm absence: %#v", cloud)
	}
}

func TestRunNeverEchoesSecretCanariesOrProviderErrors(t *testing.T) {
	const canary = "secret-canary-do-not-print"
	fixture := newBuildFixture(t)
	input, err := os.ReadFile(fixture.requestPath)
	if err != nil {
		t.Fatal(err)
	}
	input = bytes.Replace(input, []byte("}"), []byte(`,"aws_secret_access_key":"`+canary+`"}`), 1)
	secretPath := writeBytes(t, "secret.json", input)
	cloud := newFakeCloud(fixture.image, fixture.evidence)
	var stdout, stderr bytes.Buffer
	_ = Run(context.Background(), []string{"build", "--request", secretPath, "--output", filepath.Join(t.TempDir(), "out.json")}, &stdout, &stderr, cloud.dependencies())
	if strings.Contains(stdout.String()+stderr.String(), canary) || strings.Contains(stdout.String()+stderr.String(), "aws_secret_access_key") {
		t.Fatalf("input secret leaked: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	cloud = newFakeCloud(fixture.image, fixture.evidence)
	cloud.loadErr = errors.New("provider raw error contains " + canary)
	stdout.Reset()
	stderr.Reset()
	_ = Run(context.Background(), []string{"build", "--request", fixture.requestPath, "--output", filepath.Join(t.TempDir(), "out.json")}, &stdout, &stderr, cloud.dependencies())
	if strings.Contains(stdout.String()+stderr.String(), canary) {
		t.Fatalf("provider error leaked: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

type ioDiscardBuffer struct{}

func (ioDiscardBuffer) Write(input []byte) (int, error) { return len(input), nil }

type buildFixture struct {
	requestPath string
	releasePath string
	archivePath string
	image       workerami.ImageManifestV1
	evidence    awsprovider.WorkerAMIAttestationV1
}

func newBuildFixture(t *testing.T) buildFixture {
	t.Helper()
	directory := t.TempDir()
	root := filepath.Join(directory, "rootfs")
	populateBuildRootFS(t, root)
	archivePath := filepath.Join(directory, "worker-rootfs.tar")
	rootFSManifest, err := workerrootfs.Pack(root, archivePath)
	if err != nil {
		t.Fatal(err)
	}
	archiveDigest := rootFSManifest.RootFSDigest
	binaryDigest := rootFSManifest.BinaryDigest
	revision := "0123456789abcdef0123456789abcdef01234567"
	tag := "v0.1.0-alpha.20260717.1-" + revision[:12]
	release := releaseartifact.ReleaseManifestV1{
		SchemaVersion: releaseartifact.SchemaVersionV1, ReleaseTag: tag, GitRevision: revision, OS: "linux", Architecture: "amd64",
		AgentImage: releaseImage("agent", tag, "a"), WorkerImage: releaseImage("worker", tag, "c"), ReaperImage: releaseImage("reaper", tag, "d"),
		WorkerRootFSDigest: archiveDigest, WorkerBinaryDigest: binaryDigest, GeneratedAt: "2026-07-17T00:00:00Z",
	}
	releasePath := writeJSONIn(t, directory, "release.json", release)
	releaseDigest, err := release.Digest()
	if err != nil {
		t.Fatal(err)
	}
	request := BuildRequestFileV1{
		SchemaVersion: BuildRequestSchemaV1, AccountID: "123456789012", Region: "us-east-1",
		AgentInstanceID: "11111111-1111-4111-8111-111111111111", ReleaseManifestPath: releasePath,
		RootFSArchivePath: archivePath,
		BaseAMIID:         "ami-0123456789abcdef0", BaseAMIOwnerID: "099720109477", PrivateSubnetID: "subnet-0123456789abcdef0",
		ZeroIngressSecurityGroupID: "sg-0123456789abcdef0", ArtifactBucket: "dtx-worker-artifacts-test",
		ArtifactKey: "worker/rootfs.tar", ArtifactKMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111",
		BuilderInstanceType: "t3.micro", RootDeviceName: "/dev/sda1", TimeoutSeconds: 300,
		ApprovedHTTPSCIDRs: []string{"0.0.0.0/0"}, AllowTestHTTPSInternetEgress: true,
	}
	requestPath := writeJSONIn(t, directory, "build.json", request)
	image := workerami.ImageManifestV1{
		SchemaVersion: workerami.ImageManifestSchemaV1, AgentInstanceID: request.AgentInstanceID,
		ImageID: "ami-11111111111111111", ImageName: "dtx-worker-ami-11111111111111111111", RootSnapshotID: "snap-11111111111111111",
		AccountID: request.AccountID, Region: request.Region, Architecture: "amd64", BaseAMIID: request.BaseAMIID,
		BaseAMIOwnerID: request.BaseAMIOwnerID, RootDeviceName: request.RootDeviceName,
		ReleaseManifestDigest: releaseDigest, WorkerRootFSDigest: archiveDigest, WorkerBinaryDigest: binaryDigest,
		CreatedAt: "2026-07-17T01:02:03Z",
	}
	evidence := awsprovider.WorkerAMIAttestationV1{
		SchemaVersion: awsprovider.WorkerAMIAttestationSchemaV1, AgentInstanceID: image.AgentInstanceID,
		AMIID: image.ImageID, RootSnapshotID: image.RootSnapshotID, AccountID: image.AccountID, Region: image.Region,
		Architecture: recipe.ArchitectureAMD64, ReleaseManifestDigest: image.ReleaseManifestDigest,
		WorkerRootFSDigest: image.WorkerRootFSDigest, WorkerBinaryDigest: image.WorkerBinaryDigest,
		ObservedAt: time.Date(2026, 7, 17, 1, 3, 0, 0, time.UTC),
	}
	return buildFixture{requestPath: requestPath, releasePath: releasePath, archivePath: archivePath, image: image, evidence: evidence}
}

func populateBuildRootFS(t *testing.T, root string) {
	t.Helper()
	worker := []byte("deterministic-cloud-worker-binary")
	installer := []byte("deterministic-worker-installer-binary")
	workerSum := sha256.Sum256(worker)
	installerSum := sha256.Sum256(installer)
	files := map[string][]byte{
		"etc/ssl/certs/ca-certificates.crt":                                       worker,
		"usr/local/bin/dirextalk-cloud-worker":                                    worker,
		"usr/local/bin/dirextalk-worker-installer":                                installer,
		"usr/local/share/dirextalk-worker/ami/dirextalk-cloud-worker.service":     []byte("fixed cloud Worker service\n"),
		"usr/local/share/dirextalk-worker/ami/dirextalk-installer.tmpfiles":       []byte("fixed installer tmpfiles\n"),
		"usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer.service": []byte("fixed installer service\n"),
		"usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer.socket":  []byte("fixed installer socket\n"),
		"usr/local/share/dirextalk-worker/ami/dirextalk-worker.sysusers":          []byte("fixed Worker sysusers\n"),
		"usr/local/share/dirextalk-worker/ami/dirextalk-worker.tmpfiles":          []byte("fixed Worker tmpfiles\n"),
		"usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256":          []byte(hex.EncodeToString(workerSum[:]) + "\n"),
		"usr/local/share/dirextalk-worker/dirextalk-worker-installer.sha256":      []byte(hex.EncodeToString(installerSum[:]) + "\n"),
	}
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "var", "lib", "dirextalk-worker"), 0o700); err != nil {
		t.Fatal(err)
	}
}

func releaseImage(component, tag, digestCharacter string) string {
	return "registry.example/dirextalk-" + component + ":" + tag + "@sha256:" + strings.Repeat(digestCharacter, 64)
}

func writeJSON(t *testing.T, name string, value any) string {
	t.Helper()
	return writeJSONIn(t, t.TempDir(), name, value)
}

func writeJSONIn(t *testing.T, directory, name string, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return writeBytesIn(t, directory, name, encoded)
}

func writeBytes(t *testing.T, name string, input []byte) string {
	t.Helper()
	return writeBytesIn(t, t.TempDir(), name, input)
}

func writeBytesIn(t *testing.T, directory, name string, input []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, input, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writePublication(t *testing.T, image workerami.ImageManifestV1, evidence awsprovider.WorkerAMIAttestationV1) string {
	t.Helper()
	publication, err := newPublicationManifest(image, evidence)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := canonicalPublicationJSON(publication)
	if err != nil {
		t.Fatal(err)
	}
	return writeBytes(t, "publication.json", encoded)
}

type fakeCloud struct {
	identity      CallerIdentityV1
	loadErr       error
	image         workerami.ImageManifestV1
	evidence      awsprovider.WorkerAMIAttestationV1
	loadCalls     int
	identityReads int
	buildCalls    int
	verifyCalls   int
	destroyCalls  int
	attestCalls   int
	absenceCalls  int
}

func newFakeCloud(image workerami.ImageManifestV1, evidence awsprovider.WorkerAMIAttestationV1) *fakeCloud {
	return &fakeCloud{identity: CallerIdentityV1{AccountID: image.AccountID, Region: image.Region}, image: image, evidence: evidence}
}

func (cloud *fakeCloud) dependencies() Dependencies {
	return Dependencies{
		LoadConfig: func(_ context.Context, region string) (aws.Config, error) {
			cloud.loadCalls++
			if cloud.loadErr != nil {
				return aws.Config{}, cloud.loadErr
			}
			return aws.Config{Region: region, Credentials: aws.AnonymousCredentials{}}, nil
		},
		NewIdentityReader:  func(aws.Config) (IdentityReader, error) { return fakeIdentityReader{cloud: cloud}, nil },
		NewService:         func(aws.Config, awsadapter.Config) (AMIService, error) { return fakeAMIService{cloud: cloud}, nil },
		NewAttestor:        func(aws.Config) (AMIAttestor, error) { return fakeAttestor{cloud: cloud}, nil },
		NewAbsenceVerifier: func(aws.Config) (AMIAbsenceVerifier, error) { return fakeAbsenceVerifier{cloud: cloud}, nil },
	}
}

type fakeIdentityReader struct{ cloud *fakeCloud }

func (reader fakeIdentityReader) Read(context.Context) (CallerIdentityV1, error) {
	reader.cloud.identityReads++
	return reader.cloud.identity, nil
}

type fakeAMIService struct{ cloud *fakeCloud }

func (service fakeAMIService) Build(_ context.Context, _ workerami.BuildRequestV1) (workerami.ImageManifestV1, error) {
	service.cloud.buildCalls++
	return service.cloud.image, nil
}

func (service fakeAMIService) Verify(_ context.Context, manifest workerami.ImageManifestV1) error {
	service.cloud.verifyCalls++
	if manifest != service.cloud.image {
		return errors.New("unexpected image")
	}
	return nil
}

func (service fakeAMIService) Destroy(_ context.Context, manifest workerami.ImageManifestV1) error {
	service.cloud.destroyCalls++
	if manifest != service.cloud.image {
		return errors.New("unexpected image")
	}
	return nil
}

type fakeAttestor struct{ cloud *fakeCloud }

func (attestor fakeAttestor) AttestWorkerAMI(_ context.Context, _ awsprovider.WorkerAMIAttestationRequest) (awsprovider.WorkerAMIAttestationV1, error) {
	attestor.cloud.attestCalls++
	return attestor.cloud.evidence, nil
}

type fakeAbsenceVerifier struct{ cloud *fakeCloud }

func (verifier fakeAbsenceVerifier) VerifyAbsent(_ context.Context, manifest workerami.ImageManifestV1) error {
	verifier.cloud.absenceCalls++
	if manifest != verifier.cloud.image {
		return errors.New("unexpected image")
	}
	return nil
}
