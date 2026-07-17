package helperkey

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDiscoverCurrentBindsAuthenticatedWorkerIdentity(t *testing.T) {
	repository := NewMemoryRepository()
	service, _ := NewService(repository, &publisherFake{}, &revokerFake{}, time.Now)
	value := discoveryRecord(StateGrant)
	_, _ = repository.CreateIdempotent(context.Background(), value, uuid.NewString(), [32]byte{1})
	workerID := uuid.NewString()
	repository.BindWorkerSession(value.Binding.DeploymentID, workerID, value.Binding.OwnerID,
		value.Binding.InstanceID, value.Binding.WorkerPrincipalID)

	found, err := service.DiscoverCurrent(context.Background(), DiscoveryScope{
		DeploymentID: value.Binding.DeploymentID, OwnerID: value.Binding.OwnerID, WorkerID: workerID,
	})
	if err != nil || found.Binding.DeliveryID != value.Binding.DeliveryID {
		t.Fatalf("found=%+v err=%v", found, err)
	}
	for _, scope := range []DiscoveryScope{
		{DeploymentID: uuid.NewString(), OwnerID: value.Binding.OwnerID, WorkerID: workerID},
		{DeploymentID: value.Binding.DeploymentID, OwnerID: "owner-other", WorkerID: workerID},
		{DeploymentID: value.Binding.DeploymentID, OwnerID: value.Binding.OwnerID, WorkerID: uuid.NewString()},
	} {
		if _, err := service.DiscoverCurrent(context.Background(), scope); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-scope discovery err=%v scope=%+v", err, scope)
		}
	}
}

func TestDiscoverCurrentIncludesReadyRecoveryAndFailsClosedOnDuplicate(t *testing.T) {
	repository := NewMemoryRepository()
	service, _ := NewService(repository, &publisherFake{}, &revokerFake{}, time.Now)
	ready := discoveryRecord(StateReady)
	_, _ = repository.CreateIdempotent(context.Background(), ready, uuid.NewString(), [32]byte{1})
	workerID := uuid.NewString()
	repository.BindWorkerSession(ready.Binding.DeploymentID, workerID, ready.Binding.OwnerID,
		ready.Binding.InstanceID, ready.Binding.WorkerPrincipalID)
	if found, err := service.DiscoverCurrent(context.Background(), DiscoveryScope{
		DeploymentID: ready.Binding.DeploymentID, OwnerID: ready.Binding.OwnerID, WorkerID: workerID,
	}); err != nil || found.State != StateReady {
		t.Fatalf("ready recovery=%+v err=%v", found, err)
	}

	duplicate := ready.Clone()
	duplicate.Binding.DeliveryID, duplicate.Binding.SignerKeyID = uuid.NewString(), "root-helper-duplicate"
	duplicate.Binding.SecretPlan.VersionID = duplicate.Binding.DeliveryID
	duplicate.Binding.Secret.VersionID = duplicate.Binding.DeliveryID
	_, _ = repository.CreateIdempotent(context.Background(), duplicate, uuid.NewString(), [32]byte{2})
	if _, err := service.DiscoverCurrent(context.Background(), DiscoveryScope{
		DeploymentID: ready.Binding.DeploymentID, OwnerID: ready.Binding.OwnerID, WorkerID: workerID,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate discovery err=%v", err)
	}
}

func discoveryRecord(state State) Record {
	now := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	binding := testBinding()
	public := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	nonce := make([]byte, 32)
	binding.PublicKeyDigest, binding.NonceDigest = digest(public), digest(nonce)
	binding.Secret = SecretCoordinate{
		ARN:  "arn:aws:secretsmanager:us-west-2:123456789012:secret:" + binding.SecretPlan.Name + "-Ab12Cd",
		Name: binding.SecretPlan.Name, VersionID: binding.DeliveryID, KMSKeyARN: binding.SecretPlan.KMSKeyARN,
	}
	value := Record{
		Binding: binding, PublicKey: public, Nonce: nonce, State: state, Revision: 2,
		CreatedAt: now, UpdatedAt: now,
	}
	if state == StateReady {
		value.Revision = 5
		value.ProofObservedAt, value.RevokedAt, value.ReadyAt = now, now, now
	}
	return value
}
