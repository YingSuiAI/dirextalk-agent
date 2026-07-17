package workeroperation

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCurrentReadyReceiptVerifierUsesExactLiveTrustTuple(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	operation := Operation{
		SchemaVersion: SchemaV1, OperationID: uuid.NewString(), DeploymentID: uuid.NewString(),
		OwnerID: "owner-verifier", Action: ActionRestart, LifecycleRestartRef: "restart",
		ExecutionBundleDigest:           "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExpectedInstalledManifestDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		State:                           StateLeased, WorkerID: uuid.NewString(), LeaseEpoch: 3,
		LeaseExpiresAt: time.Date(2026, 7, 17, 12, 5, 0, 0, time.UTC),
		Revision:       2, CreatedAt: time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 7, 17, 12, 1, 0, 0, time.UTC),
	}
	receipt, err := SignReceipt(RootHelperReceipt{
		SchemaVersion: SchemaV1, OperationID: operation.OperationID, DeploymentID: operation.DeploymentID,
		OwnerID: operation.OwnerID, Action: operation.Action, LifecycleRestartRef: operation.LifecycleRestartRef,
		ExecutionBundleDigest: operation.ExecutionBundleDigest, LeaseEpoch: operation.LeaseEpoch,
		InstallManifestDigest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		RestartObservationDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ObservedAt:               operation.UpdatedAt, HelperID: "root-helper", SignerKeyID: "signer-2",
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keys := &readyKeyStore{
		deploymentID: receipt.DeploymentID, helperID: receipt.HelperID,
		signerKeyID: receipt.SignerKeyID, publicKey: publicKey, ready: true,
	}
	verifier := CurrentReadyReceiptVerifier{Keys: keys}
	if err := verifier.Verify(context.Background(), receipt); err != nil {
		t.Fatalf("current ready receipt rejected: %v", err)
	}
	if keys.calls != 1 {
		t.Fatalf("ready key lookups=%d want=1", keys.calls)
	}

	for name, mutate := range map[string]func(*readyKeyStore){
		"revoked": func(store *readyKeyStore) { store.ready = false },
		"old signer after rotation": func(store *readyKeyStore) {
			store.ready = true
			store.signerKeyID = "signer-3"
		},
		"other helper": func(store *readyKeyStore) {
			store.signerKeyID = receipt.SignerKeyID
			store.helperID = "other-helper"
		},
		"other deployment": func(store *readyKeyStore) {
			store.helperID = receipt.HelperID
			store.deploymentID = uuid.NewString()
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := *keys
			copy.deploymentID, copy.helperID, copy.signerKeyID, copy.ready =
				receipt.DeploymentID, receipt.HelperID, receipt.SignerKeyID, true
			mutate(&copy)
			if err := (CurrentReadyReceiptVerifier{Keys: &copy}).Verify(context.Background(), receipt); !errors.Is(err, ErrInvalid) {
				t.Fatalf("non-current key accepted: %v", err)
			}
		})
	}
}

type readyKeyStore struct {
	deploymentID string
	helperID     string
	signerKeyID  string
	publicKey    ed25519.PublicKey
	ready        bool
	calls        int
}

func (store *readyKeyStore) CurrentReadyPublicKey(_ context.Context, deploymentID, helperID, signerKeyID string) (ed25519.PublicKey, error) {
	store.calls++
	if !store.ready || deploymentID != store.deploymentID || helperID != store.helperID || signerKeyID != store.signerKeyID {
		return nil, errors.New("not current")
	}
	return store.publicKey, nil
}
