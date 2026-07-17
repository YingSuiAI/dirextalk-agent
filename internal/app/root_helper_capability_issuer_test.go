package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
)

type capabilityWorkerReaderFake struct{ deployment worker.Deployment }

func (fake capabilityWorkerReaderFake) Get(context.Context, string) (worker.Deployment, error) {
	return fake.deployment, nil
}

type capabilityHelperReaderFake struct {
	current helperkey.Record
	ready   helperkey.Record
}

func (fake capabilityHelperReaderFake) Get(context.Context, string) (helperkey.Record, error) {
	return fake.current.Clone(), nil
}

func (fake capabilityHelperReaderFake) CurrentReadyRootHelper(context.Context, string, string) (helperkey.Record, error) {
	return fake.ready.Clone(), nil
}

func TestProductionRootHelperCapabilityIssuerRecoversExactResponsesAndFencesDrift(t *testing.T) {
	fixture := newRootHelperCapabilityIssuerFixture(t)
	issuer, err := newProductionRootHelperCapabilityIssuer(
		capabilityWorkerReaderFake{fixture.deployment},
		capabilityHelperReaderFake{current: fixture.grant, ready: fixture.ready},
		fixture.trust, func() time.Time { return fixture.now },
	)
	if err != nil {
		t.Fatal(err)
	}
	session := worker.Assignment{
		DeploymentID: fixture.deployment.DeploymentID, OwnerID: fixture.deployment.OwnerID,
		WorkerID: fixture.deployment.WorkerID,
	}
	firstDelivery, firstBootstrap, err := issuer.IssueBootstrapCapability(context.Background(), session, fixture.grant)
	if err != nil {
		t.Fatal(err)
	}
	secondDelivery, secondBootstrap, err := issuer.IssueBootstrapCapability(context.Background(), session, fixture.grant)
	if err != nil {
		t.Fatal(err)
	}
	firstDeliveryCBOR, _ := canonical.Marshal(firstDelivery)
	secondDeliveryCBOR, _ := canonical.Marshal(secondDelivery)
	firstCapabilityCBOR, _ := canonical.Marshal(firstBootstrap)
	secondCapabilityCBOR, _ := canonical.Marshal(secondBootstrap)
	if !bytes.Equal(firstDeliveryCBOR, secondDeliveryCBOR) ||
		!bytes.Equal(firstCapabilityCBOR, secondCapabilityCBOR) ||
		firstBootstrap.Capability.DeliveryRevision != fixture.grant.Revision {
		t.Fatal("bootstrap response-loss retry changed authoritative capability")
	}

	manifestDigest, _ := canonical.Digest(fixture.delivery.ArtifactManifest.Manifest)
	operation := workeroperation.Assignment{
		OperationID: uuid.NewString(), DeploymentID: fixture.deployment.DeploymentID,
		OwnerID: fixture.deployment.OwnerID, Action: workeroperation.ActionRestart,
		LifecycleRestartRef: "restart-service", ExecutionBundleDigest: workerDigest(fixture.deployment.ExecutionBundle.SHA256),
		ExpectedInstalledManifestDigest: manifestDigest, WorkerID: fixture.deployment.WorkerID,
		LeaseEpoch: 3, LeaseExpiresAt: fixture.now.Add(time.Minute), Revision: 2,
	}
	_, firstRestart, err := issuer.IssueRestartCapability(context.Background(), session, operation)
	if err != nil {
		t.Fatal(err)
	}
	_, secondRestart, err := issuer.IssueRestartCapability(context.Background(), session, operation)
	if err != nil {
		t.Fatal(err)
	}
	firstRestartCBOR, _ := canonical.Marshal(firstRestart)
	secondRestartCBOR, _ := canonical.Marshal(secondRestart)
	if !bytes.Equal(firstRestartCBOR, secondRestartCBOR) ||
		firstRestart.Capability.ExpectedInstalledManifestDigest != manifestDigest ||
		firstRestart.Capability.HelperPublicKeyDigest != fixture.ready.Binding.PublicKeyDigest {
		t.Fatal("restart response-loss retry changed its installed-manifest or helper trust fence")
	}

	crossDeployment := operation
	crossDeployment.DeploymentID = uuid.NewString()
	if _, _, err := issuer.IssueRestartCapability(context.Background(), session, crossDeployment); !errors.Is(err, workeroperation.ErrInvalid) {
		t.Fatalf("cross-deployment restart err=%v", err)
	}
	drifted := operation
	drifted.ExpectedInstalledManifestDigest = appCapabilityDigest('f')
	if _, _, err := issuer.IssueRestartCapability(context.Background(), session, drifted); !errors.Is(err, workeroperation.ErrInvalid) {
		t.Fatalf("manifest drift err=%v", err)
	}
	expired := operation
	expired.LeaseExpiresAt = fixture.now
	if _, _, err := issuer.IssueRestartCapability(context.Background(), session, expired); !errors.Is(err, workeroperation.ErrInvalid) {
		t.Fatalf("expired restart lease err=%v", err)
	}
}

func TestProductionRootHelperBootstrapRejectsCrossDeploymentAndStaleRecord(t *testing.T) {
	fixture := newRootHelperCapabilityIssuerFixture(t)
	issuer, _ := newProductionRootHelperCapabilityIssuer(
		capabilityWorkerReaderFake{fixture.deployment},
		capabilityHelperReaderFake{current: fixture.grant, ready: fixture.ready},
		fixture.trust, func() time.Time { return fixture.now },
	)
	session := worker.Assignment{
		DeploymentID: fixture.deployment.DeploymentID, OwnerID: fixture.deployment.OwnerID,
		WorkerID: fixture.deployment.WorkerID,
	}
	cross := session
	cross.DeploymentID = uuid.NewString()
	if _, _, err := issuer.IssueBootstrapCapability(context.Background(), cross, fixture.grant); !errors.Is(err, helperkey.ErrConflict) {
		t.Fatalf("cross-deployment bootstrap err=%v", err)
	}
	stale := fixture.grant.Clone()
	stale.Revision--
	if _, _, err := issuer.IssueBootstrapCapability(context.Background(), session, stale); !errors.Is(err, helperkey.ErrConflict) {
		t.Fatalf("stale helper revision err=%v", err)
	}
}

type rootHelperCapabilityIssuerFixture struct {
	now        time.Time
	trust      *installer.TrustIssuer
	delivery   installer.DeliveryV1
	deployment worker.Deployment
	grant      helperkey.Record
	ready      helperkey.Record
}

func newRootHelperCapabilityIssuerFixture(t *testing.T) rootHelperCapabilityIssuerFixture {
	t.Helper()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	agentID, deploymentID, taskID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	binding := installer.BindingV1{
		AgentInstanceID: agentID, DeploymentID: deploymentID, TaskID: taskID,
		PlanHash: appCapabilityDigest('1'), ApprovalID: uuid.NewString(), RecipeDigest: appCapabilityDigest('2'),
	}
	content := []byte("root reviewed service control")
	contentSum := sha256.Sum256(content)
	plan := installer.InstallerPlanV1{
		SchemaVersion: installer.PlanSchemaV1, Binding: binding,
		Artifacts: []installer.ArtifactV1{{
			Name: "service-control", SHA256: workerDigest(contentSum), SizeBytes: int64(len(content)),
			TargetPath: installer.PreinstalledArtifactRoot + "/service-control",
		}},
		Commands: []installer.CommandV1{{
			CommandID:        "restart-service",
			Argv:             []string{installer.PreinstalledArtifactRoot + "/service-control", "restart"},
			WorkingDirectory: installer.PreinstalledArtifactRoot, TimeoutSeconds: 60,
			ArtifactRefs: []string{"service-control"},
		}},
		Network:   installer.NetworkV1{OutboundHTTPSHosts: []string{"api.example.com"}},
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	trust, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := trust.Issue(plan, installer.DaemonConfigV1{
		SchemaVersion: installer.DaemonConfigSchema, Binding: binding,
		TargetRoot: installer.PreinstalledArtifactRoot,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	helperPublic, _, _ := ed25519.GenerateKey(nil)
	nonce := bytes.Repeat([]byte{0x35}, 32)
	deliveryID, instanceID := uuid.NewString(), "i-0123456789abcdef0"
	secretName := "dtx/" + agentID + "/deployments/" + deploymentID + "/" + helperkey.SecretSlot
	helperBinding := helperkey.DeviceBinding{
		SchemaVersion: helperkey.SchemaV1, AgentInstanceID: agentID, OwnerID: "owner-capability",
		DeliveryID: deliveryID, DeploymentID: deploymentID, BindingRevision: 7, InstanceID: instanceID,
		WorkerRoleARN:     "arn:aws:iam::123456789012:role/dtx-worker",
		WorkerPrincipalID: "AROAEXAMPLE:" + instanceID, HelperID: helperkey.DefaultHelperID,
		SignerKeyID: "root-key-1", PublicKeyDigest: bytesDigestForCapability(helperPublic),
		NonceDigest: bytesDigestForCapability(nonce),
		SecretPlan: helperkey.SecretPlan{
			Partition: "aws", AccountID: "123456789012", Region: "us-west-2",
			Name: secretName, VersionID: deliveryID, KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/helper",
			TargetPath: helperkey.SecretTarget, FileMode: helperkey.SecretMode,
		},
	}
	helperBinding.Secret = helperkey.SecretCoordinate{
		ARN:  "arn:aws:secretsmanager:us-west-2:123456789012:secret:" + secretName + "-Ab12Cd",
		Name: secretName, VersionID: deliveryID, KMSKeyARN: helperBinding.SecretPlan.KMSKeyARN,
	}
	grant := helperkey.Record{
		Binding: helperBinding, PublicKey: helperPublic, Nonce: nonce,
		State: helperkey.StateGrant, Revision: 4, CreatedAt: now.Add(-time.Minute), UpdatedAt: now,
	}
	ready := grant.Clone()
	ready.State, ready.Revision = helperkey.StateReady, 7
	ready.ProofObservedAt, ready.RevokedAt, ready.ReadyAt = now, now, now
	executionDigest := sha256.Sum256([]byte("execution bundle"))
	deployment := worker.Deployment{
		DeploymentID: deploymentID, OwnerID: helperBinding.OwnerID, TaskID: taskID,
		ExecutionBundle:   worker.BundleRef{S3Ref: "s3://agent-artifacts/execution.cbor", SHA256: executionDigest},
		InstallerDelivery: &delivery, WorkerID: uuid.NewString(), ProviderInstanceID: instanceID,
		State: worker.StateLeased, Revision: 9, CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	return rootHelperCapabilityIssuerFixture{
		now: now, trust: trust, delivery: delivery, deployment: deployment, grant: grant, ready: ready,
	}
}

func workerDigest(sum [sha256.Size]byte) string {
	return "sha256:" + hex.EncodeToString(sum[:])
}

func bytesDigestForCapability(value []byte) string {
	sum := sha256.Sum256(value)
	return workerDigest(sum)
}

func appCapabilityDigest(value byte) string {
	return "sha256:" + string(bytes.Repeat([]byte{value}, 64))
}
