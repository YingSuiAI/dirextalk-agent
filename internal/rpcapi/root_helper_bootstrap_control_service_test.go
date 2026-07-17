package rpcapi

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
)

type rootHelperDiscoveryStub struct {
	value helperkey.Record
	scope helperkey.DiscoveryScope
}

func (stub *rootHelperDiscoveryStub) DiscoverCurrent(_ context.Context, scope helperkey.DiscoveryScope) (helperkey.Record, error) {
	stub.scope = scope
	return stub.value.Clone(), nil
}
func (stub *rootHelperDiscoveryStub) Get(context.Context, string) (helperkey.Record, error) {
	return stub.value.Clone(), nil
}
func (stub *rootHelperDiscoveryStub) SubmitProof(context.Context, helperkey.ProofRequest, []byte) (helperkey.Record, error) {
	return helperkey.Record{}, helperkey.ErrUnavailable
}
func (stub *rootHelperDiscoveryStub) ReconcileRevocation(context.Context, string, string) (helperkey.Record, error) {
	return helperkey.Record{}, helperkey.ErrUnavailable
}
func (stub *rootHelperDiscoveryStub) ConfirmCanary(context.Context, helperkey.CanaryRequest) (helperkey.Record, error) {
	return helperkey.Record{}, helperkey.ErrUnavailable
}

func TestRootHelperAcquirePendingUsesAuthenticatedDeploymentWorkerScope(t *testing.T) {
	value := rootHelperDiscoveryRecord()
	workerID := uuid.NewString()
	sessionToken := workerTestToken("dtxw-session", 0x61)
	sessions := &workerOperationSessionStub{check: func(_ context.Context, request worker.SessionRequest) (worker.Assignment, error) {
		return worker.Assignment{
			DeploymentID: request.DeploymentID, WorkerID: request.WorkerID, OwnerID: value.Binding.OwnerID,
		}, nil
	}}
	deliveries := &rootHelperDiscoveryStub{value: value}
	handler := newRootHelperBootstrapControlHandler(sessions, deliveries)
	handler.capabilities = newCapabilityIssuerStub(t, value.Binding.AgentInstanceID, value.Binding.DeploymentID, value.UpdatedAt)
	handler.now = func() time.Time { return value.UpdatedAt }
	response, err := handler.AcquirePending(
		workerAuthorizationContext("DTX-Worker-Session "+sessionToken),
		&agentv1.RootHelperBootstrapControlServiceAcquirePendingRequest{
			DeploymentId: value.Binding.DeploymentID, WorkerId: workerID,
		})
	if err != nil {
		t.Fatal(err)
	}
	if deliveries.scope != (helperkey.DiscoveryScope{
		DeploymentID: value.Binding.DeploymentID, OwnerID: value.Binding.OwnerID, WorkerID: workerID,
	}) {
		t.Fatalf("discovery scope=%+v", deliveries.scope)
	}
	delivery := response.GetDelivery()
	if delivery.GetBinding().GetDeliveryId() != value.Binding.DeliveryID ||
		delivery.GetBinding().GetWorkerPrincipalId() != value.Binding.WorkerPrincipalID ||
		len(delivery.GetPublicKey()) != ed25519.PublicKeySize || len(delivery.GetNonce()) != 32 ||
		len(response.GetInstallerDeliveryCbor()) == 0 || len(response.GetSignedCapabilityCbor()) == 0 {
		t.Fatalf("public delivery=%+v", delivery)
	}
}

func TestRootHelperCurrentReturnsReadyDeliveryForResponseLossRecovery(t *testing.T) {
	value := rootHelperDiscoveryRecord()
	value.State, value.Revision = helperkey.StateReady, 5
	value.ProofObservedAt, value.RevokedAt, value.ReadyAt = value.UpdatedAt, value.UpdatedAt, value.UpdatedAt
	workerID := uuid.NewString()
	sessions := &workerOperationSessionStub{check: func(_ context.Context, request worker.SessionRequest) (worker.Assignment, error) {
		return worker.Assignment{
			DeploymentID: request.DeploymentID, WorkerID: request.WorkerID, OwnerID: value.Binding.OwnerID,
		}, nil
	}}
	response, err := newRootHelperBootstrapControlHandler(sessions, &rootHelperDiscoveryStub{value: value}).Current(
		workerAuthorizationContext("DTX-Worker-Session "+workerTestToken("dtxw-session", 0x62)),
		&agentv1.RootHelperBootstrapControlServiceCurrentRequest{
			DeploymentId: value.Binding.DeploymentID, WorkerId: workerID,
		})
	if err != nil || response.GetDelivery().GetState() !=
		agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_READY {
		t.Fatalf("current=%+v err=%v", response, err)
	}
}

func rootHelperDiscoveryRecord() helperkey.Record {
	now := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	agentID, deploymentID, deliveryID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	instanceID := "i-0123456789abcdef0"
	publicKey, nonce := make([]byte, ed25519.PublicKeySize), make([]byte, 32)
	name := "dtx/" + agentID + "/deployments/" + deploymentID + "/" + helperkey.SecretSlot
	kms := "arn:aws:kms:us-west-2:123456789012:key/key"
	return helperkey.Record{
		Binding: helperkey.DeviceBinding{
			SchemaVersion: helperkey.SchemaV1, AgentInstanceID: agentID, OwnerID: "owner-helper-rpc",
			DeliveryID: deliveryID, DeploymentID: deploymentID, BindingRevision: 1,
			InstanceID: instanceID, WorkerRoleARN: "arn:aws:iam::123456789012:role/worker",
			WorkerPrincipalID: "AROATESTROLEIDENTIFIER:" + instanceID,
			HelperID:          "root-helper", SignerKeyID: "root-helper-1",
			PublicKeyDigest: rootHelperDigest(publicKey), NonceDigest: rootHelperDigest(nonce),
			SecretPlan: helperkey.SecretPlan{
				Partition: "aws", AccountID: "123456789012", Region: "us-west-2",
				Name: name, VersionID: deliveryID, KMSKeyARN: kms,
				TargetPath: helperkey.SecretTarget, FileMode: helperkey.SecretMode,
			},
			Secret: helperkey.SecretCoordinate{
				ARN:  "arn:aws:secretsmanager:us-west-2:123456789012:secret:" + name + "-Ab12Cd",
				Name: name, VersionID: deliveryID, KMSKeyARN: kms,
			},
		},
		PublicKey: publicKey, Nonce: nonce, State: helperkey.StateGrant, Revision: 2,
		CreatedAt: now, UpdatedAt: now,
	}
}

func rootHelperDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
