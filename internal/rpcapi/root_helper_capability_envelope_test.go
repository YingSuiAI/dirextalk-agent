package rpcapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
)

type capabilityIssuerStub struct {
	issuer     *installer.TrustIssuer
	delivery   installer.DeliveryV1
	now        time.Time
	restartErr error
}

func newCapabilityIssuerStub(t *testing.T, agentID, deploymentID string, now time.Time) *capabilityIssuerStub {
	t.Helper()
	binding := installer.BindingV1{
		AgentInstanceID: agentID, DeploymentID: deploymentID, TaskID: uuid.NewString(),
		PlanHash: workerOperationTestDigest('1'), ApprovalID: uuid.NewString(), RecipeDigest: workerOperationTestDigest('2'),
	}
	content := []byte("reviewed service control")
	sum := sha256.Sum256(content)
	artifactDigest := "sha256:" + hex.EncodeToString(sum[:])
	plan := installer.InstallerPlanV1{
		SchemaVersion: installer.PlanSchemaV1, Binding: binding,
		Artifacts: []installer.ArtifactV1{{
			Name: "service-control", SHA256: artifactDigest, SizeBytes: int64(len(content)),
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
	issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := issuer.Issue(plan, installer.DaemonConfigV1{
		SchemaVersion: installer.DaemonConfigSchema, Binding: binding,
		TargetRoot: installer.PreinstalledArtifactRoot,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	return &capabilityIssuerStub{issuer: issuer, delivery: delivery, now: now}
}

func (stub *capabilityIssuerStub) IssueBootstrapCapability(_ context.Context, _ worker.Assignment,
	record helperkey.Record) (installer.DeliveryV1, installer.SignedRootHelperBootstrapCapabilityV1, error) {
	signed, err := stub.issuer.IssueRootHelperBootstrapCapability(
		stub.delivery, record.Binding, record.PublicKey, record.Nonce, record.Revision,
		stub.now.Add(time.Minute), stub.now,
	)
	return stub.delivery, signed, err
}

func (stub *capabilityIssuerStub) IssueRestartCapability(_ context.Context, _ worker.Assignment,
	operation workeroperation.Assignment) (installer.DeliveryV1, installer.SignedRootHelperRestartCapabilityV1, error) {
	if stub.restartErr != nil {
		return installer.DeliveryV1{}, installer.SignedRootHelperRestartCapabilityV1{}, stub.restartErr
	}
	signed, err := stub.issuer.IssueRootHelperRestartCapability(stub.delivery, helperkey.DeviceBinding{
		AgentInstanceID: stub.delivery.Config.Binding.AgentInstanceID, DeploymentID: operation.DeploymentID,
		DeliveryID: uuid.NewString(), HelperID: helperkey.DefaultHelperID, SignerKeyID: "root-key-1",
		InstanceID: "i-0123456789abcdef0", WorkerPrincipalID: "AROAEXAMPLE:i-0123456789abcdef0",
		PublicKeyDigest: workerOperationTestDigest('c'),
	}, installer.RootHelperRestartGrantV1{
		OperationID: operation.OperationID, DeploymentID: operation.DeploymentID, OwnerID: operation.OwnerID,
		LifecycleRestartRef: operation.LifecycleRestartRef, ExecutionBundleDigest: operation.ExecutionBundleDigest,
		ExpectedInstalledManifestDigest: operation.ExpectedInstalledManifestDigest,
		WorkerLeaseEpoch:                operation.LeaseEpoch, LeaseExpiresAt: stub.now.Add(time.Minute),
	}, stub.now)
	return stub.delivery, signed, err
}

func TestRestartCapabilityStubIsValid(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	deploymentID := uuid.NewString()
	stub := newCapabilityIssuerStub(t, uuid.NewString(), deploymentID, now)
	assignment := workeroperation.Assignment{
		OperationID: uuid.NewString(), DeploymentID: deploymentID, OwnerID: "owner-a",
		Action: workeroperation.ActionRestart, LifecycleRestartRef: "restart-service",
		ExecutionBundleDigest:           workerOperationTestDigest('a'),
		ExpectedInstalledManifestDigest: workerOperationTestDigest('b'),
		WorkerID:                        uuid.NewString(), LeaseEpoch: 1, LeaseExpiresAt: now.Add(time.Minute), Revision: 2,
	}
	delivery, signed, err := stub.IssueRestartCapability(context.Background(), worker.Assignment{}, assignment)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := encodeRestartCapabilityEnvelope(delivery, signed, now); err != nil {
		t.Fatal(err)
	}
}

func TestCapabilityEnvelopesAreCanonicalAndContainNoPrivateKey(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	agentID, deploymentID := uuid.NewString(), uuid.NewString()
	stub := newCapabilityIssuerStub(t, agentID, deploymentID, now)
	record := rootHelperDiscoveryRecord()
	record.Binding.AgentInstanceID, record.Binding.DeploymentID = agentID, deploymentID
	record.Binding.SecretPlan.Name = "dtx/" + agentID + "/deployments/" + deploymentID + "/" + helperkey.SecretSlot
	record.Binding.Secret.Name = record.Binding.SecretPlan.Name
	record.Binding.Secret.ARN = "arn:aws:secretsmanager:us-west-2:123456789012:secret:" + record.Binding.SecretPlan.Name + "-Ab12Cd"
	delivery, bootstrap, err := stub.IssueBootstrapCapability(context.Background(), worker.Assignment{}, record)
	if err != nil {
		t.Fatal(err)
	}
	deliveryCBOR, bootstrapCBOR, err := encodeBootstrapCapabilityEnvelope(delivery, bootstrap, now)
	if err != nil {
		t.Fatal(err)
	}
	var decodedDelivery installer.DeliveryV1
	var decodedBootstrap installer.SignedRootHelperBootstrapCapabilityV1
	if installer.DecodeCanonical(deliveryCBOR, &decodedDelivery) != nil ||
		installer.DecodeCanonical(bootstrapCBOR, &decodedBootstrap) != nil ||
		decodedBootstrap.Capability.DeliveryRevision != record.Revision {
		t.Fatal("bootstrap envelope did not round-trip exact authoritative revision")
	}
	privateMarker := bytes.Repeat([]byte{0x71}, 32)
	if bytes.Contains(deliveryCBOR, privateMarker) || bytes.Contains(bootstrapCBOR, privateMarker) {
		t.Fatal("capability envelope exposed issuer private material")
	}
	if digest, _ := canonical.Digest(decodedDelivery.ArtifactManifest.Manifest); digest == "" {
		t.Fatal("decoded installer manifest is not canonical")
	}
}
