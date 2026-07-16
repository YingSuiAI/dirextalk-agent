package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

var bootstrapNow = time.Date(2026, time.July, 17, 8, 0, 0, 0, time.UTC)

func TestBootstrapMaterializesOneAtomicRootTrustFileBeforeSocketActivation(t *testing.T) {
	fixture := newBootstrapFixture(t, 'a')
	if err := fixture.service.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fixture.socket.disabled || !fixture.socket.enabled || fixture.socket.calls[0] != "disable" || fixture.socket.calls[len(fixture.socket.calls)-1] != "enable" {
		t.Fatalf("socket sequence = %#v", fixture.socket.calls)
	}
	if fixture.materializer.changes != 1 || fixture.materializer.spec != (TrustFileSpec{Path: DefaultTrustFile, Mode: 0o400, UID: 0, GID: 0}) {
		t.Fatalf("materialization = changes:%d spec:%+v", fixture.materializer.changes, fixture.materializer.spec)
	}
	if fixture.artifacts.calls != 1 || fixture.downloader.calls != 1 || fixture.artifacts.spec.Path != installer.PreinstalledArtifactRoot+"/service" {
		t.Fatalf("installer artifact was not materialized before activation: downloads=%d writes=%d spec=%+v", fixture.downloader.calls, fixture.artifacts.calls, fixture.artifacts.spec)
	}
	trust, err := DecodeTrustFile(fixture.materializer.content)
	if err != nil {
		t.Fatal(err)
	}
	if trust.TrustID != fixture.userData.InstallerTrust.TrustID || trust.Config.Binding.DeploymentID != fixture.userData.DeploymentID ||
		trust.Config.Binding.PlanHash == "" || trust.Config.Binding.RecipeDigest == "" {
		t.Fatalf("persisted trust lost approval binding: %+v", trust)
	}
}

func TestBootstrapRejectsTamperingAndLeavesSocketDisabled(t *testing.T) {
	tests := []struct {
		name string
		edit func(*UserDataV1)
	}{
		{name: "path escape", edit: func(value *UserDataV1) {
			value.ArtifactRef = "s3://dtx-artifacts/deployments/../foreign/launch/config.json"
		}},
		{name: "wrong deployment", edit: func(value *UserDataV1) { value.DeploymentID = "99999999-9999-4999-8999-999999999999" }},
		{name: "trust ID", edit: func(value *UserDataV1) { value.InstallerTrust.TrustID = "sha256:invalid" }},
		{name: "public key", edit: func(value *UserDataV1) { value.InstallerTrust.PublicKey = value.InstallerTrust.PublicKey[:31] }},
		{name: "config digest", edit: func(value *UserDataV1) { value.InstallerTrust.ConfigDigest = digestFor('e') }},
		{name: "config bytes", edit: func(value *UserDataV1) { value.InstallerTrust.ConfigCBOR[len(value.InstallerTrust.ConfigCBOR)-1] ^= 1 }},
		{name: "artifact digest", edit: func(value *UserDataV1) { value.InstallerArtifacts[0].SHA256 = digestFor('e') }},
		{name: "artifact size", edit: func(value *UserDataV1) { value.InstallerArtifacts[0].SizeBytes++ }},
		{name: "artifact path escape", edit: func(value *UserDataV1) { value.InstallerArtifacts[0].TargetPath = "/tmp/service" }},
		{name: "artifact key escape", edit: func(value *UserDataV1) { value.InstallerArtifacts[0].Key = "deployments/other/artifacts/service" }},
		{name: "artifact version", edit: func(value *UserDataV1) { value.InstallerArtifacts[0].VersionID = "null" }},
		{name: "artifact kms", edit: func(value *UserDataV1) {
			value.InstallerArtifacts[0].KMSKeyARN = "arn:aws:kms:us-east-1:123456789012:key/other"
		}},
		{name: "manifest signature", edit: func(value *UserDataV1) { value.InstallerTrust.ArtifactManifest.Signature[0] ^= 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBootstrapFixture(t, 'a')
			test.edit(&fixture.userData)
			fixture.source.raw = mustJSON(t, fixture.userData)
			if err := fixture.service.Run(context.Background()); err == nil {
				t.Fatal("tampered bootstrap succeeded")
			}
			if !fixture.socket.disabled || fixture.socket.enabled || fixture.materializer.calls != 0 || fixture.artifacts.calls != 0 {
				t.Fatalf("failure exposed socket or wrote trust: socket=%#v writes=%d", fixture.socket, fixture.materializer.calls)
			}
		})
	}
}

func TestBootstrapReplayIsIdempotentAndNewTrustAtomicallyReplacesOld(t *testing.T) {
	fixture := newBootstrapFixture(t, 'a')
	if err := fixture.service.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := bytes.Clone(fixture.materializer.content)
	if err := fixture.service.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fixture.materializer.calls != 2 || fixture.materializer.changes != 1 || !bytes.Equal(first, fixture.materializer.content) {
		t.Fatalf("exact replay rewrote trust: calls=%d changes=%d", fixture.materializer.calls, fixture.materializer.changes)
	}

	replacement := newBootstrapFixture(t, 'b')
	replacement.materializer = fixture.materializer
	replacement.service, _ = NewArtifactService(replacement.source, replacement.materializer, replacement.downloader, replacement.artifacts, replacement.socket, DefaultTrustFile)
	if err := replacement.service.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if replacement.materializer.changes != 2 || bytes.Equal(first, replacement.materializer.content) {
		t.Fatal("rotated approval trust did not replace the old atomic file")
	}
	decoded, err := DecodeTrustFile(replacement.materializer.content)
	if err != nil || decoded.TrustID != replacement.userData.InstallerTrust.TrustID {
		t.Fatalf("replacement trust = %+v error=%v", decoded, err)
	}
}

func TestBootstrapFailuresNeverEnableSocket(t *testing.T) {
	t.Run("metadata", func(t *testing.T) {
		fixture := newBootstrapFixture(t, 'a')
		fixture.source.err = errors.New("metadata unavailable")
		if err := fixture.service.Run(context.Background()); err == nil || fixture.socket.enabled || !fixture.socket.disabled {
			t.Fatalf("metadata failure = %v socket=%#v", err, fixture.socket)
		}
	})
	t.Run("materialize", func(t *testing.T) {
		fixture := newBootstrapFixture(t, 'a')
		fixture.materializer.err = errors.New("fsync failed")
		if err := fixture.service.Run(context.Background()); !errors.Is(err, ErrMaterialize) || fixture.socket.enabled || !fixture.socket.disabled {
			t.Fatalf("materialize failure = %v socket=%#v", err, fixture.socket)
		}
	})
	t.Run("artifact response", func(t *testing.T) {
		fixture := newBootstrapFixture(t, 'a')
		fixture.downloader.err = errors.New("S3 response lost")
		if err := fixture.service.Run(context.Background()); !errors.Is(err, ErrMaterialize) || fixture.socket.enabled || !fixture.socket.disabled || fixture.materializer.calls != 0 {
			t.Fatalf("artifact response failure = %v socket=%#v trust_writes=%d", err, fixture.socket, fixture.materializer.calls)
		}
	})
	t.Run("artifact atomic replace", func(t *testing.T) {
		fixture := newBootstrapFixture(t, 'a')
		fixture.artifacts.err = errors.New("rename response lost")
		if err := fixture.service.Run(context.Background()); !errors.Is(err, ErrMaterialize) || fixture.socket.enabled || !fixture.socket.disabled || fixture.materializer.calls != 0 {
			t.Fatalf("artifact write failure = %v socket=%#v trust_writes=%d", err, fixture.socket, fixture.materializer.calls)
		}
	})
	t.Run("activate", func(t *testing.T) {
		fixture := newBootstrapFixture(t, 'a')
		fixture.socket.enableErr = errors.New("socket start failed")
		if err := fixture.service.Run(context.Background()); !errors.Is(err, ErrSocketActivation) || fixture.socket.enabled || !fixture.socket.disabled {
			t.Fatalf("activation failure = %v socket=%#v", err, fixture.socket)
		}
	})
}

func TestBootstrapWithoutInstallerCapabilityLeavesSocketDisabledAndStartsWorkerPath(t *testing.T) {
	fixture := newBootstrapFixture(t, 'a')
	fixture.userData.InstallerTrust = nil
	fixture.userData.InstallerArtifacts = nil
	fixture.source.raw = mustJSON(t, fixture.userData)
	if err := fixture.service.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !fixture.socket.disabled || fixture.socket.enabled || !reflect.DeepEqual(fixture.socket.calls, []string{"disable"}) || fixture.materializer.calls != 0 {
		t.Fatalf("noop bootstrap touched installer trust/socket: socket=%#v writes=%d", fixture.socket, fixture.materializer.calls)
	}
}

func TestSystemdControllerCompensatesPartialActivationWithFixedCommands(t *testing.T) {
	runner := &recordingCommands{failAt: 2}
	controller, err := newSystemdSocketController(runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Enable(context.Background()); !errors.Is(err, ErrSocketActivation) {
		t.Fatalf("enable error = %v", err)
	}
	want := [][]string{
		{"/usr/bin/systemctl", "enable", installerSocketUnit},
		{"/usr/bin/systemctl", "start", installerSocketUnit},
		{"/usr/bin/systemctl", "disable", "--now", installerSocketUnit},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("systemd commands = %#v, want %#v", runner.calls, want)
	}
}

func TestIMDSSourceReadsIdentityAndBoundedUserDataOnly(t *testing.T) {
	raw := []byte(`{"schema_version":"test"}`)
	client := &fakeMetadata{
		identity: &imds.GetInstanceIdentityDocumentOutput{InstanceIdentityDocument: imds.InstanceIdentityDocument{
			AccountID: "123456789012", Region: "ap-south-1", InstanceID: "i-0123456789abcdef0",
		}},
		userData: &imds.GetUserDataOutput{Content: io.NopCloser(bytes.NewReader(raw))},
	}
	source, err := NewIMDSSource(client)
	if err != nil {
		t.Fatal(err)
	}
	got, identity, err := source.Read(context.Background())
	if err != nil || !bytes.Equal(got, raw) || identity.AccountID != "123456789012" || client.identityCalls != 1 || client.userDataCalls != 1 {
		t.Fatalf("IMDS read = %q identity=%+v calls=%d/%d error=%v", got, identity, client.identityCalls, client.userDataCalls, err)
	}
}

type bootstrapFixture struct {
	userData     UserDataV1
	source       *fakeSource
	materializer *memoryMaterializer
	downloader   *memoryDownloader
	artifacts    *memoryArtifactMaterializer
	socket       *fakeSocket
	service      *Service
}

func newBootstrapFixture(t *testing.T, recipeByte byte) *bootstrapFixture {
	t.Helper()
	binding := installer.BindingV1{
		AgentInstanceID: "11111111-1111-4111-8111-111111111111", DeploymentID: "22222222-2222-4222-8222-222222222222",
		TaskID: "33333333-3333-4333-8333-333333333333", PlanHash: digestFor('c'),
		ApprovalID: "44444444-4444-4444-8444-444444444444", RecipeDigest: digestFor(recipeByte),
	}
	config := installer.DaemonConfigV1{SchemaVersion: installer.DaemonConfigSchema, Binding: binding, TargetRoot: installer.PreinstalledArtifactRoot}
	artifactBytes := []byte("safe")
	artifactDigest := sha256.Sum256(artifactBytes)
	plan := installer.InstallerPlanV1{
		SchemaVersion: installer.PlanSchemaV1, Binding: binding,
		Artifacts: []installer.ArtifactV1{{Name: "service", SHA256: "sha256:" + hex.EncodeToString(artifactDigest[:]), SizeBytes: int64(len(artifactBytes)), TargetPath: installer.PreinstalledArtifactRoot + "/service"}},
		Network:   installer.NetworkV1{}, Commands: []installer.CommandV1{{
			CommandID: "install", Argv: []string{installer.PreinstalledArtifactRoot + "/service"}, WorkingDirectory: installer.PreinstalledArtifactRoot,
			TimeoutSeconds: 30, ArtifactRefs: []string{"service"},
		}}, ExpiresAt: bootstrapNow.Add(time.Hour).Format(time.RFC3339Nano),
	}
	issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{recipeByte}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	delivery, err := issuer.Issue(plan, config, bootstrapNow)
	if err != nil {
		t.Fatal(err)
	}
	rootMaterial, err := delivery.RootTrustMaterial(bootstrapNow)
	if err != nil {
		t.Fatal(err)
	}
	material, err := NewRootTrustMaterial(rootMaterial)
	if err != nil {
		t.Fatal(err)
	}
	userData := UserDataV1{
		SchemaVersion: UserDataSchemaV1, ResourceID: "55555555-5555-4555-8555-555555555555", SpecDigest: digestFor('e'),
		ArtifactRef: "s3://dtx-artifacts/deployments/" + binding.DeploymentID + "/launch/config.json", ArtifactDigest: digestFor('f'),
		Region: "ap-south-1", DeploymentID: binding.DeploymentID, WorkerID: "66666666-6666-4666-8666-666666666666",
		ControlPlaneEndpoint: "grpcs://agent.example.test:8443", EnrollmentExpectedRevision: 1, EnrollmentMethod: "aws_sts_sigv4",
		InstallerTrust: &material,
		InstallerArtifacts: []ArtifactSourceV1{{
			SchemaVersion: ArtifactSourceSchemaV1, Name: "service", Bucket: "dtx-artifacts",
			Key: "deployments/" + binding.DeploymentID + "/artifacts/service", VersionID: "v-immutable-1",
			KMSKeyARN: "arn:aws:kms:ap-south-1:123456789012:key/11111111-2222-4333-8444-555555555555",
			SHA256:    "sha256:" + hex.EncodeToString(artifactDigest[:]), SizeBytes: int64(len(artifactBytes)), TargetPath: installer.PreinstalledArtifactRoot + "/service",
			RecipeDigest: binding.RecipeDigest,
		}},
	}
	source := &fakeSource{raw: mustJSON(t, userData), identity: InstanceIdentityV1{AccountID: "123456789012", Region: "ap-south-1", InstanceID: "i-0123456789abcdef0"}}
	materializer := &memoryMaterializer{}
	downloader := &memoryDownloader{content: artifactBytes}
	artifacts := &memoryArtifactMaterializer{}
	socket := &fakeSocket{}
	service, err := NewArtifactService(source, materializer, downloader, artifacts, socket, DefaultTrustFile)
	if err != nil {
		t.Fatal(err)
	}
	return &bootstrapFixture{userData: userData, source: source, materializer: materializer, downloader: downloader, artifacts: artifacts, socket: socket, service: service}
}

type fakeSource struct {
	raw      []byte
	identity InstanceIdentityV1
	err      error
}

func (source *fakeSource) Read(context.Context) ([]byte, InstanceIdentityV1, error) {
	return bytes.Clone(source.raw), source.identity, source.err
}

type memoryMaterializer struct {
	spec    TrustFileSpec
	content []byte
	calls   int
	changes int
	err     error
}

type memoryDownloader struct {
	content []byte
	calls   int
	err     error
}

func (downloader *memoryDownloader) Open(_ context.Context, _ ArtifactSourceV1) (ArtifactDownload, error) {
	downloader.calls++
	if downloader.err != nil {
		return ArtifactDownload{}, downloader.err
	}
	return ArtifactDownload{Body: io.NopCloser(bytes.NewReader(downloader.content))}, nil
}

type memoryArtifactMaterializer struct {
	spec    ArtifactFileSpec
	content []byte
	calls   int
	err     error
}

func (materializer *memoryArtifactMaterializer) Replace(_ context.Context, spec ArtifactFileSpec, source io.Reader) (bool, error) {
	materializer.calls++
	materializer.spec = spec
	content, readErr := io.ReadAll(source)
	if readErr != nil || materializer.err != nil {
		return false, errors.Join(readErr, materializer.err)
	}
	materializer.content = content
	return true, nil
}

func (materializer *memoryMaterializer) Replace(_ context.Context, spec TrustFileSpec, content []byte) (bool, error) {
	materializer.calls++
	materializer.spec = spec
	if materializer.err != nil {
		return false, materializer.err
	}
	if bytes.Equal(materializer.content, content) {
		return false, nil
	}
	materializer.content = bytes.Clone(content)
	materializer.changes++
	return true, nil
}

type fakeSocket struct {
	disabled   bool
	enabled    bool
	calls      []string
	disableErr error
	enableErr  error
}

func (socket *fakeSocket) Disable(context.Context) error {
	socket.calls = append(socket.calls, "disable")
	socket.enabled = false
	socket.disabled = true
	return socket.disableErr
}

func (socket *fakeSocket) Enable(context.Context) error {
	socket.calls = append(socket.calls, "enable")
	if socket.enableErr != nil {
		socket.enabled = false
		socket.disabled = true
		return socket.enableErr
	}
	socket.enabled = true
	socket.disabled = false
	return nil
}

type recordingCommands struct {
	calls  [][]string
	failAt int
}

func (runner *recordingCommands) Run(_ context.Context, name string, args ...string) error {
	call := append([]string{name}, args...)
	runner.calls = append(runner.calls, call)
	if len(runner.calls) == runner.failAt {
		return errors.New("fixed command failed")
	}
	return nil
}

type fakeMetadata struct {
	identity      *imds.GetInstanceIdentityDocumentOutput
	userData      *imds.GetUserDataOutput
	identityCalls int
	userDataCalls int
}

func (metadata *fakeMetadata) GetInstanceIdentityDocument(context.Context, *imds.GetInstanceIdentityDocumentInput, ...func(*imds.Options)) (*imds.GetInstanceIdentityDocumentOutput, error) {
	metadata.identityCalls++
	return metadata.identity, nil
}

func (metadata *fakeMetadata) GetUserData(context.Context, *imds.GetUserDataInput, ...func(*imds.Options)) (*imds.GetUserDataOutput, error) {
	metadata.userDataCalls++
	return metadata.userData, nil
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func digestFor(value byte) string {
	return fmt.Sprintf("sha256:%s", strings.Repeat(string(value), sha256.Size*2))
}
