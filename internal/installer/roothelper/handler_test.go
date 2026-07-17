package roothelper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
)

func TestRootHelperBoundaryBootstrapsCanariesRestartsAndReplays(t *testing.T) {
	fixture := newFixture(t)
	bootstrap, err := fixture.issuer.IssueRootHelperBootstrapCapability(
		fixture.delivery, fixture.binding, fixture.publicKey, fixture.nonce, 4,
		fixture.now.Add(10*time.Minute), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := fixture.handler.Bootstrap(context.Background(), bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	replayedProof, err := fixture.handler.Bootstrap(context.Background(), bootstrap)
	if err != nil || !bytes.Equal(proof.Signature, replayedProof.Signature) ||
		fixture.secrets.readCalls != 1 || fixture.keys.writeCalls != 1 {
		t.Fatalf("bootstrap replay was not exact: err=%v reads=%d writes=%d", err, fixture.secrets.readCalls, fixture.keys.writeCalls)
	}
	possessionPayload, _ := helperkey.PossessionPayload(fixture.binding, fixture.nonce)
	if !ed25519.Verify(fixture.publicKey, possessionPayload, proof.Signature) {
		t.Fatal("possession proof was not signed by delivered helper key")
	}

	canary, err := fixture.handler.Canary(context.Background(), bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	replayedCanary, err := fixture.handler.Canary(context.Background(), bootstrap)
	if err != nil || !bytes.Equal(canary.Signature, replayedCanary.Signature) || fixture.secrets.canaryCalls != 1 {
		t.Fatalf("canary replay was not exact: err=%v calls=%d", err, fixture.secrets.canaryCalls)
	}
	canaryPayload, _ := helperkey.CanaryPayload(fixture.binding, canary.ObservedAt)
	if canary.ErrorCode != "AccessDeniedException" ||
		!ed25519.Verify(fixture.publicKey, canaryPayload, canary.Signature) {
		t.Fatal("canary did not prove exact AccessDenied with the delivered key")
	}

	restart, err := fixture.issuer.IssueRootHelperRestartCapability(
		fixture.delivery, fixture.binding, installer.RootHelperRestartGrantV1{
			OperationID: uuid.NewString(), DeploymentID: fixture.binding.DeploymentID, OwnerID: fixture.binding.OwnerID,
			LifecycleRestartRef: "restart-service", ExecutionBundleDigest: digest('a'),
			ExpectedInstalledManifestDigest: fixture.observer.installed, WorkerLeaseEpoch: 9,
			LeaseExpiresAt: fixture.now.Add(5 * time.Minute),
		}, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if restart.Capability.HelperPublicKeyDigest != bytesDigest(fixture.keys.value[ed25519.PublicKeySize:]) {
		t.Fatalf("restart key digest mismatch: capability=%s file=%s", restart.Capability.HelperPublicKeyDigest, bytesDigest(fixture.keys.value[ed25519.PublicKeySize:]))
	}
	receipt, err := fixture.handler.Restart(context.Background(), restart)
	if err != nil {
		t.Fatal(err)
	}
	replayedReceipt, err := fixture.handler.Restart(context.Background(), restart)
	if err != nil || !bytes.Equal(receipt.Signature, replayedReceipt.Signature) || fixture.runner.calls != 1 {
		t.Fatalf("restart response-loss replay reran command: err=%v calls=%d", err, fixture.runner.calls)
	}
	reissued, err := fixture.issuer.IssueRootHelperRestartCapability(
		fixture.delivery, fixture.binding, installer.RootHelperRestartGrantV1{
			OperationID: restart.Capability.OperationID, DeploymentID: fixture.binding.DeploymentID, OwnerID: fixture.binding.OwnerID,
			LifecycleRestartRef: "restart-service", ExecutionBundleDigest: digest('a'),
			ExpectedInstalledManifestDigest: fixture.observer.installed, WorkerLeaseEpoch: 9,
			LeaseExpiresAt: fixture.now.Add(4 * time.Minute),
		}, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	reissuedReceipt, err := fixture.handler.Restart(context.Background(), reissued)
	if err != nil || !bytes.Equal(receipt.Signature, reissuedReceipt.Signature) || fixture.runner.calls != 1 {
		t.Fatalf("fresh capability after response loss reran command: err=%v calls=%d", err, fixture.runner.calls)
	}
	if len(fixture.runner.last.Argv) != 2 || fixture.runner.last.Argv[0] != installer.PreinstalledArtifactRoot+"/service-control" ||
		fixture.runner.last.Argv[1] != "restart" ||
		len(fixture.runner.last.Environment) != 1 || fixture.runner.last.Environment[0] != installer.SafePathEnvironment {
		t.Fatalf("root executed fields outside original delivery: %#v", fixture.runner.last)
	}
	if err := (workeroperation.Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{
		fixture.binding.SignerKeyID: fixture.publicKey,
	}}).Verify(context.Background(), receipt); err != nil {
		t.Fatalf("restart receipt signature: %v", err)
	}
	if receipt.InstallManifestDigest != fixture.observer.installed ||
		receipt.RestartObservationDigest != fixture.observer.observation ||
		receipt.LeaseEpoch != 9 {
		t.Fatalf("restart receipt did not bind independent observations: %#v", receipt)
	}
}

func TestRootHelperBoundaryRejectsTamperingCrossBindingAndNonDeniedCanary(t *testing.T) {
	fixture := newFixture(t)
	bootstrap, err := fixture.issuer.IssueRootHelperBootstrapCapability(
		fixture.delivery, fixture.binding, fixture.publicKey, fixture.nonce, 1,
		fixture.now.Add(time.Minute), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bootstrap
	tampered.Capability.HelperBinding.WorkerPrincipalID = "AROACROSS:" + fixture.binding.InstanceID
	if _, err := fixture.handler.Bootstrap(context.Background(), tampered); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-principal tamper error = %v", err)
	}
	tampered = bootstrap
	tampered.Capability.HelperBinding.DeploymentID = uuid.NewString()
	if _, err := fixture.handler.Bootstrap(context.Background(), tampered); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-deployment tamper error = %v", err)
	}
	tampered = bootstrap
	tampered.Signature = bytes.Clone(tampered.Signature)
	tampered.Signature[0] ^= 0xff
	if _, err := fixture.handler.Bootstrap(context.Background(), tampered); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("signature tamper error = %v", err)
	}

	if _, err := fixture.handler.Bootstrap(context.Background(), bootstrap); err != nil {
		t.Fatal(err)
	}
	fixture.secrets.canaryErr = errors.New("still readable")
	if _, err := fixture.handler.Canary(context.Background(), bootstrap); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("non-AccessDenied canary error = %v", err)
	}
}

func TestRootHelperBoundaryRejectsUnreadyKeyAndExpiredLease(t *testing.T) {
	fixture := newFixture(t)
	if _, err := fixture.issuer.IssueRootHelperRestartCapability(
		fixture.delivery, fixture.binding, installer.RootHelperRestartGrantV1{
			OperationID: "not-an-operation", DeploymentID: fixture.binding.DeploymentID, OwnerID: fixture.binding.OwnerID,
			LifecycleRestartRef: "restart-service", ExecutionBundleDigest: digest('b'),
			ExpectedInstalledManifestDigest: fixture.observer.installed, WorkerLeaseEpoch: 3,
			LeaseExpiresAt: fixture.now.Add(time.Minute),
		}, fixture.now,
	); err == nil {
		t.Fatal("malformed operation identity was signed")
	}
	restart, err := fixture.issuer.IssueRootHelperRestartCapability(
		fixture.delivery, fixture.binding, installer.RootHelperRestartGrantV1{
			OperationID: uuid.NewString(), DeploymentID: fixture.binding.DeploymentID, OwnerID: fixture.binding.OwnerID,
			LifecycleRestartRef: "restart-service", ExecutionBundleDigest: digest('b'),
			ExpectedInstalledManifestDigest: fixture.observer.installed, WorkerLeaseEpoch: 3,
			LeaseExpiresAt: fixture.now.Add(time.Minute),
		}, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.handler.Restart(context.Background(), restart); !errors.Is(err, ErrNotReady) {
		t.Fatalf("unready key error = %v", err)
	}

	bootstrap, _ := fixture.issuer.IssueRootHelperBootstrapCapability(
		fixture.delivery, fixture.binding, fixture.publicKey, fixture.nonce, 1,
		fixture.now.Add(time.Minute), fixture.now,
	)
	fixture.clock = fixture.now.Add(2 * time.Minute)
	if _, err := fixture.handler.Bootstrap(context.Background(), bootstrap); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired bootstrap lease error = %v", err)
	}
	if fixture.secrets.readCalls != 0 || fixture.runner.calls != 0 {
		t.Fatal("expired capability reached a privileged dependency")
	}
}

func TestRootHelperMaintenanceUsesFreshCapabilityAfterInstallerPlanExpiry(t *testing.T) {
	fixture := newFixture(t)
	maintenanceAt := fixture.now.Add(48 * time.Hour)
	fixture.clock = maintenanceAt
	installerLease, err := fixture.issuer.IssueLeaseGrant(
		fixture.delivery, "restart-service", 1, fixture.now.Add(time.Minute), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.delivery.ExecuteRequest("restart-service", installerLease, maintenanceAt); !errors.Is(err, installer.Error(installer.CodePlanExpired)) {
		t.Fatalf("ordinary installer.execute remained usable after expiry: %v", err)
	}
	bootstrap, err := fixture.issuer.IssueRootHelperBootstrapCapability(
		fixture.delivery, fixture.binding, fixture.publicKey, fixture.nonce, 12,
		maintenanceAt.Add(5*time.Minute), maintenanceAt,
	)
	if err != nil {
		t.Fatalf("fresh maintenance capability could not reuse immutable delivery trust: %v", err)
	}
	if _, err := fixture.handler.Bootstrap(context.Background(), bootstrap); err != nil {
		t.Fatalf("fresh maintenance capability was rejected after original plan expiry: %v", err)
	}
	tampered := bootstrap
	tampered.Capability.HelperBinding.WorkerPrincipalID = "AROATAMPERED:" + fixture.binding.InstanceID
	if _, err := fixture.handler.Bootstrap(context.Background(), tampered); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired-plan trust accepted tampered maintenance capability: %v", err)
	}
}

func TestRootHelperDaemonRestartRecoversFromRootTrustCapabilityAndFixedKey(t *testing.T) {
	fixture := newFixture(t)
	material, err := fixture.delivery.RootTrustMaterial(fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := installer.ValidateDeliveryAgainstRootTrust(fixture.delivery, material); err != nil {
		t.Fatalf("full delivery did not match installed compact trust: %v", err)
	}
	tamperedMaterial := material
	tamperedMaterial.ConfigCBOR = bytes.Clone(material.ConfigCBOR)
	tamperedMaterial.ConfigCBOR[len(tamperedMaterial.ConfigCBOR)-1] ^= 0xff
	if err := installer.ValidateDeliveryAgainstRootTrust(fixture.delivery, tamperedMaterial); err == nil {
		t.Fatal("tampered compact trust accepted a full delivery")
	}

	bootstrap, err := fixture.issuer.IssueRootHelperBootstrapCapability(
		fixture.delivery, fixture.binding, fixture.publicKey, fixture.nonce, 5,
		fixture.now.Add(10*time.Minute), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.handler.Bootstrap(context.Background(), bootstrap); err != nil {
		t.Fatal(err)
	}

	afterBootstrapFence, err := openDeliveryFence(fixture.fencePath, false)
	if err != nil {
		t.Fatal(err)
	}
	afterBootstrapRestart, err := New(
		fixture.delivery, fixture.secrets, fixture.keys, fixture.runner, fixture.observer,
		fixture.journal, afterBootstrapFence,
		func() time.Time { return fixture.clock },
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := afterBootstrapRestart.Canary(context.Background(), bootstrap); err != nil {
		t.Fatalf("daemon restart lost recoverable canary authority: %v", err)
	}

	restart, err := fixture.issuer.IssueRootHelperRestartCapability(
		fixture.delivery, fixture.binding, installer.RootHelperRestartGrantV1{
			OperationID: uuid.NewString(), DeploymentID: fixture.binding.DeploymentID, OwnerID: fixture.binding.OwnerID,
			LifecycleRestartRef: "restart-service", ExecutionBundleDigest: digest('f'),
			ExpectedInstalledManifestDigest: fixture.observer.installed, WorkerLeaseEpoch: 11,
			LeaseExpiresAt: fixture.now.Add(5 * time.Minute),
		}, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	afterCanaryJournal, err := openRestartJournal(fixture.journalPath, false)
	if err != nil {
		t.Fatal(err)
	}
	afterCanaryFence, err := openDeliveryFence(fixture.fencePath, false)
	if err != nil {
		t.Fatal(err)
	}
	afterCanaryRestart, err := New(
		fixture.delivery, fixture.secrets, fixture.keys, fixture.runner, fixture.observer,
		afterCanaryJournal, afterCanaryFence,
		func() time.Time { return fixture.clock },
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := afterCanaryRestart.Restart(context.Background(), restart); err != nil {
		t.Fatalf("daemon restart lost fixed-key restart authority: %v", err)
	}
	terminalJournal, err := openRestartJournal(fixture.journalPath, false)
	if err != nil {
		t.Fatal(err)
	}
	afterResponseLoss, err := New(
		fixture.delivery, fixture.secrets, fixture.keys, fixture.runner, fixture.observer,
		terminalJournal, fixture.fence, func() time.Time { return fixture.clock },
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := afterResponseLoss.Restart(context.Background(), restart); err != nil || fixture.runner.calls != 1 {
		t.Fatalf("terminal journal replay reran restart: err=%v calls=%d", err, fixture.runner.calls)
	}

	interrupted, err := fixture.issuer.IssueRootHelperRestartCapability(
		fixture.delivery, fixture.binding, installer.RootHelperRestartGrantV1{
			OperationID: uuid.NewString(), DeploymentID: fixture.binding.DeploymentID, OwnerID: fixture.binding.OwnerID,
			LifecycleRestartRef: "restart-service", ExecutionBundleDigest: digest('9'),
			ExpectedInstalledManifestDigest: fixture.observer.installed, WorkerLeaseEpoch: 12,
			LeaseExpiresAt: fixture.now.Add(5 * time.Minute),
		}, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	interruptedDigest, _ := restartJournalDigest(interrupted.Capability)
	if _, _, err := terminalJournal.Begin(interrupted.Capability.OperationID, interruptedDigest); err != nil {
		t.Fatal(err)
	}
	runningJournal, err := openRestartJournal(fixture.journalPath, false)
	if err != nil {
		t.Fatal(err)
	}
	afterInterruptedRestart, err := New(
		fixture.delivery, fixture.secrets, fixture.keys, fixture.runner, fixture.observer,
		runningJournal, fixture.fence, func() time.Time { return fixture.clock },
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := afterInterruptedRestart.Restart(context.Background(), interrupted); !errors.Is(err, ErrUnavailable) ||
		fixture.runner.calls != 1 {
		t.Fatalf("running journal automatically repeated command: err=%v calls=%d", err, fixture.runner.calls)
	}

	tamperedRestart := restart
	tamperedRestart.Capability.HelperPublicKeyDigest = digest('0')
	if _, err := afterCanaryRestart.Restart(context.Background(), tamperedRestart); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("tampered helper key digest was accepted: %v", err)
	}
}

func TestDeliveryFenceAllowsFreshCapabilityAndRejectsBindingRollbackAfterRestart(t *testing.T) {
	fixture := newFixture(t)
	first, err := fixture.issuer.IssueRootHelperBootstrapCapability(
		fixture.delivery, fixture.binding, fixture.publicKey, fixture.nonce, 9,
		fixture.now.Add(10*time.Minute), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.handler.Bootstrap(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	fresh, err := fixture.issuer.IssueRootHelperBootstrapCapability(
		fixture.delivery, fixture.binding, fixture.publicKey, fixture.nonce, 10,
		fixture.now.Add(11*time.Minute), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.handler.Canary(context.Background(), fresh); err != nil {
		t.Fatalf("freshly signed capability did not match stable delivery fence: %v", err)
	}

	advancedBinding := fixture.binding
	advancedBinding.BindingRevision++
	advancedBinding.DeliveryID = uuid.NewString()
	advancedBinding.SecretPlan.VersionID = advancedBinding.DeliveryID
	advancedBinding.Secret.VersionID = advancedBinding.DeliveryID
	advanced, err := fixture.issuer.IssueRootHelperBootstrapCapability(
		fixture.delivery, advancedBinding, fixture.publicKey, fixture.nonce, 1,
		fixture.now.Add(12*time.Minute), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.handler.Bootstrap(context.Background(), advanced); err != nil {
		t.Fatal(err)
	}
	reads := fixture.secrets.readCalls
	if _, err := fixture.handler.Bootstrap(context.Background(), first); !errors.Is(err, ErrUnauthorized) ||
		fixture.secrets.readCalls != reads {
		t.Fatalf("old unexpired capability reached secret after advance: err=%v reads=%d", err, fixture.secrets.readCalls)
	}
	reopened, err := openDeliveryFence(fixture.fencePath, false)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := New(
		fixture.delivery, fixture.secrets, fixture.keys, fixture.runner, fixture.observer,
		fixture.journal, reopened, func() time.Time { return fixture.clock },
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Bootstrap(context.Background(), first); !errors.Is(err, ErrUnauthorized) ||
		fixture.secrets.readCalls != reads {
		t.Fatalf("daemon restart lost delivery rollback fence: err=%v reads=%d", err, fixture.secrets.readCalls)
	}
}

func TestDeliveryFenceCrashWindowAllowsFreshRetryForStableBinding(t *testing.T) {
	fixture := newFixture(t)
	fixture.keys.failWrites = 1
	capability, err := fixture.issuer.IssueRootHelperBootstrapCapability(
		fixture.delivery, fixture.binding, fixture.publicKey, fixture.nonce, 3,
		fixture.now.Add(10*time.Minute), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.handler.Bootstrap(context.Background(), capability); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("accept-before-key crash window error = %v", err)
	}
	reopened, err := openDeliveryFence(fixture.fencePath, false)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := New(
		fixture.delivery, fixture.secrets, fixture.keys, fixture.runner, fixture.observer,
		fixture.journal, reopened, func() time.Time { return fixture.clock },
	)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := fixture.issuer.IssueRootHelperBootstrapCapability(
		fixture.delivery, fixture.binding, fixture.publicKey, fixture.nonce, 4,
		fixture.now.Add(12*time.Minute), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Bootstrap(context.Background(), fresh); err != nil {
		t.Fatalf("fresh retry after accept-before-key crash failed: %v", err)
	}
}

type fixture struct {
	now         time.Time
	clock       time.Time
	issuer      *installer.TrustIssuer
	delivery    installer.DeliveryV1
	binding     helperkey.DeviceBinding
	publicKey   ed25519.PublicKey
	nonce       []byte
	secrets     *secretFake
	keys        *keyStoreFake
	runner      *runnerFake
	observer    *observerFake
	journal     RestartJournal
	journalPath string
	fence       DeliveryFence
	fencePath   string
	handler     *Handler
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	now := time.Date(2026, 7, 17, 8, 0, 0, 0, time.UTC)
	installerBinding := installer.BindingV1{
		AgentInstanceID: uuid.NewString(), DeploymentID: uuid.NewString(), TaskID: uuid.NewString(),
		PlanHash: digest('1'), ApprovalID: uuid.NewString(), RecipeDigest: digest('2'),
	}
	artifactContent := []byte("root reviewed service control")
	artifactSum := sha256.Sum256(artifactContent)
	artifactDigest := "sha256:" + strings.ToLower(fmtHex(artifactSum[:]))
	plan := installer.InstallerPlanV1{
		SchemaVersion: installer.PlanSchemaV1, Binding: installerBinding,
		Artifacts: []installer.ArtifactV1{{
			Name: "service-control", SHA256: artifactDigest, SizeBytes: int64(len(artifactContent)),
			TargetPath: installer.PreinstalledArtifactRoot + "/service-control",
		}},
		Network: installer.NetworkV1{OutboundHTTPSHosts: []string{"api.example.com"}},
		Commands: []installer.CommandV1{{
			CommandID: "restart-service", Argv: []string{installer.PreinstalledArtifactRoot + "/service-control", "restart"},
			WorkingDirectory: installer.PreinstalledArtifactRoot, TimeoutSeconds: 120,
			ArtifactRefs: []string{"service-control"},
		}},
		ExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339Nano),
	}
	config := installer.DaemonConfigV1{
		SchemaVersion: installer.DaemonConfigSchema, Binding: installerBinding, TargetRoot: installer.PreinstalledArtifactRoot,
	}
	issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := issuer.Issue(plan, config, now)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	nonce := bytes.Repeat([]byte{0x35}, 32)
	binding := helperkey.DeviceBinding{
		SchemaVersion: helperkey.SchemaV1, AgentInstanceID: installerBinding.AgentInstanceID,
		OwnerID: "owner-root-helper", DeliveryID: uuid.NewString(), DeploymentID: installerBinding.DeploymentID,
		BindingRevision: 2, InstanceID: "i-0123456789abcdef0",
		WorkerRoleARN:     "arn:aws:iam::123456789012:role/dtx-worker",
		WorkerPrincipalID: "AROAEXAMPLE:i-0123456789abcdef0", HelperID: helperkey.DefaultHelperID,
		SignerKeyID: "root-key-1", PublicKeyDigest: bytesDigest(publicKey),
		SecretPlan: helperkey.SecretPlan{
			Partition: "aws", AccountID: "123456789012", Region: "us-west-2",
			Name:      "dtx/" + installerBinding.AgentInstanceID + "/deployments/" + installerBinding.DeploymentID + "/" + helperkey.SecretSlot,
			VersionID: "", KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/helper-key",
			TargetPath: helperkey.SecretTarget, FileMode: helperkey.SecretMode,
		},
		NonceDigest: bytesDigest(nonce),
	}
	binding.SecretPlan.VersionID = binding.DeliveryID
	binding.Secret = helperkey.SecretCoordinate{
		ARN:  "arn:aws:secretsmanager:us-west-2:123456789012:secret:" + binding.SecretPlan.Name + "-Ab12Cd",
		Name: binding.SecretPlan.Name, VersionID: binding.DeliveryID, KMSKeyARN: binding.SecretPlan.KMSKeyARN,
	}
	secrets := &secretFake{privateKey: bytes.Clone(privateKey), canaryErr: deniedError{code: "AccessDeniedException"}}
	keys := &keyStoreFake{}
	runner := &runnerFake{}
	observer := &observerFake{installed: digest('d'), observation: digest('e')}
	journalPath := filepath.Join(t.TempDir(), "root-helper-restart.journal")
	journal, err := openRestartJournal(journalPath, false)
	if err != nil {
		t.Fatal(err)
	}
	fencePath := filepath.Join(t.TempDir(), "root-helper-delivery-fence.cbor")
	fence, err := openDeliveryFence(fencePath, false)
	if err != nil {
		t.Fatal(err)
	}
	value := &fixture{
		now: now, clock: now, issuer: issuer, delivery: delivery, binding: binding, publicKey: publicKey,
		nonce: nonce, secrets: secrets, keys: keys, runner: runner, observer: observer,
		journal: journal, journalPath: journalPath, fence: fence, fencePath: fencePath,
	}
	handler, err := New(delivery, secrets, keys, runner, observer, journal, fence, func() time.Time { return value.clock })
	if err != nil {
		t.Fatal(err)
	}
	value.handler = handler
	t.Cleanup(issuer.Close)
	return value
}

type secretFake struct {
	privateKey  []byte
	canaryErr   error
	readCalls   int
	canaryCalls int
}

func (fake *secretFake) ReadRootHelperKey(_ context.Context, _ helperkey.DeviceBinding) ([]byte, error) {
	fake.readCalls++
	return bytes.Clone(fake.privateKey), nil
}

func (fake *secretFake) CanaryRootHelperKey(_ context.Context, _ helperkey.DeviceBinding) error {
	fake.canaryCalls++
	return fake.canaryErr
}

type keyStoreFake struct {
	value      []byte
	writeCalls int
	failWrites int
}

func (fake *keyStoreFake) ReplaceRootHelperSigningKey(_ context.Context, value []byte) error {
	fake.writeCalls++
	if fake.failWrites > 0 {
		fake.failWrites--
		return ErrUnavailable
	}
	fake.value = bytes.Clone(value)
	return nil
}

func (fake *keyStoreFake) ReadRootHelperSigningKey(context.Context) ([]byte, error) {
	if len(fake.value) == 0 {
		return nil, errors.New("not found")
	}
	return bytes.Clone(fake.value), nil
}

type runnerFake struct {
	calls int
	last  installer.CommandExecution
}

func (fake *runnerFake) Run(_ context.Context, execution installer.CommandExecution) error {
	fake.calls++
	fake.last = execution
	return nil
}

type observerFake struct {
	installed   string
	observation string
}

func (fake *observerFake) InstalledManifestDigest(context.Context, installer.DeliveryV1) (string, error) {
	return fake.installed, nil
}

func (fake *observerFake) RestartObservationDigest(context.Context, installer.DeliveryV1, installer.CommandV1) (string, error) {
	return fake.observation, nil
}

type deniedError struct{ code string }

func (value deniedError) Error() string     { return value.code }
func (value deniedError) ErrorCode() string { return value.code }

func digest(char byte) string { return "sha256:" + strings.Repeat(string(char), 64) }

func bytesDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + fmtHex(sum[:])
}

func fmtHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2] = alphabet[item>>4]
		result[index*2+1] = alphabet[item&0xf]
	}
	return string(result)
}
