package postgres_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/google/uuid"
)

func TestRootHelperKeyStoreResolvesOnlyExactCurrentReadyKey(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	keyStore, err := postgres.NewRootHelperKeyStore(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	first := readyHelperKeyRecord(t, instanceID, uuid.NewString(), "root-helper", "signer-1")
	if _, err := keyStore.CreateIdempotent(ctx, first, uuid.NewString(), sha256.Sum256([]byte("first"))); err != nil {
		t.Fatalf("create first ready key: %v", err)
	}
	resolved, err := keyStore.CurrentReadyPublicKey(ctx, first.Binding.DeploymentID, first.Binding.HelperID, first.Binding.SignerKeyID)
	if err != nil || !ed25519.PublicKey(first.PublicKey).Equal(resolved) {
		t.Fatalf("resolve current ready key err=%v equal=%v", err, ed25519.PublicKey(first.PublicKey).Equal(resolved))
	}

	if _, err := keyStore.CurrentReadyPublicKey(ctx, first.Binding.DeploymentID, first.Binding.HelperID, "signer-old"); !errors.Is(err, helperkey.ErrNotFound) {
		t.Fatalf("wrong signer lookup err=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE root_helper_key_deliveries
		SET snapshot_json=jsonb_set(snapshot_json,'{Binding,HelperID}','"other-helper"'::jsonb)
		WHERE delivery_id=$1`, first.Binding.DeliveryID); err != nil {
		t.Fatal(err)
	}
	if _, err := keyStore.CurrentReadyPublicKey(ctx, first.Binding.DeploymentID, first.Binding.HelperID, first.Binding.SignerKeyID); !errors.Is(err, helperkey.ErrNotReady) {
		t.Fatalf("relational/snapshot mismatch err=%v", err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE root_helper_key_deliveries SET snapshot_json=$1,state='revoked' WHERE delivery_id=$2`, firstJSON, first.Binding.DeliveryID); err != nil {
		t.Fatal(err)
	}

	second := readyHelperKeyRecord(t, instanceID, first.Binding.DeploymentID, first.Binding.HelperID, "signer-2")
	if _, err := keyStore.CreateIdempotent(ctx, second, uuid.NewString(), sha256.Sum256([]byte("second"))); err != nil {
		t.Fatalf("create rotated ready key: %v", err)
	}
	if _, err := keyStore.CurrentReadyPublicKey(ctx, first.Binding.DeploymentID, first.Binding.HelperID, first.Binding.SignerKeyID); !errors.Is(err, helperkey.ErrNotFound) {
		t.Fatalf("revoked old signer lookup err=%v", err)
	}
	if _, err := keyStore.CurrentReadyPublicKey(ctx, second.Binding.DeploymentID, second.Binding.HelperID, second.Binding.SignerKeyID); err != nil {
		t.Fatalf("rotated current signer rejected: %v", err)
	}
}

func readyHelperKeyRecord(t *testing.T, instanceID, deploymentID, helperID, signerKeyID string) helperkey.Record {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	for index := range nonce {
		nonce[index] = byte(index + 1)
	}
	deliveryID := uuid.NewString()
	name := "dtx/" + instanceID + "/deployments/" + deploymentID + "/" + helperkey.SecretSlot
	kmsKeyARN := "arn:aws:kms:us-west-2:123456789012:key/test"
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	return helperkey.Record{
		Binding: helperkey.DeviceBinding{
			SchemaVersion: helperkey.SchemaV1, AgentInstanceID: instanceID, OwnerID: "owner-helper-store",
			DeliveryID: deliveryID, DeploymentID: deploymentID, BindingRevision: 1,
			InstanceID: "i-0123456789abcdef0", WorkerRoleARN: "arn:aws:iam::123456789012:role/worker",
			WorkerPrincipalID: "AROATESTROLEIDENTIFIER:i-0123456789abcdef0",
			HelperID:          helperID, SignerKeyID: signerKeyID, PublicKeyDigest: testSHA256(publicKey),
			SecretPlan: helperkey.SecretPlan{
				Partition: "aws", AccountID: "123456789012", Region: "us-west-2", Name: name,
				VersionID: deliveryID, KMSKeyARN: kmsKeyARN, TargetPath: helperkey.SecretTarget, FileMode: helperkey.SecretMode,
			},
			Secret: helperkey.SecretCoordinate{
				ARN:  "arn:aws:secretsmanager:us-west-2:123456789012:secret:" + name + "-Ab12Cd",
				Name: name, VersionID: deliveryID, KMSKeyARN: kmsKeyARN,
			},
			NonceDigest: testSHA256(nonce),
		},
		PublicKey: publicKey, Nonce: nonce, State: helperkey.StateReady, Revision: 4,
		ProofObservedAt: now, RevokedAt: now.Add(time.Minute), ReadyAt: now.Add(2 * time.Minute),
		CreatedAt: now.Add(-time.Minute), UpdatedAt: now.Add(2 * time.Minute),
	}
}

func testSHA256(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
