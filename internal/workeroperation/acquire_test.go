package workeroperation

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAcquireNextRecoversResponseLossWithoutAdvancingLease(t *testing.T) {
	now := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	repository := NewMemoryRepository()
	service, _ := NewService(repository, Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{}}, func() time.Time { return now })
	deploymentID, workerID := uuid.NewString(), uuid.NewString()
	created := createAcquireFixture(t, service, deploymentID)
	first, err := service.AcquireNext(context.Background(), AcquireRequest{
		DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(), LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := service.AcquireNext(context.Background(), AcquireRequest{
		DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(), LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.OperationID != created.OperationID || recovered.LeaseEpoch != first.LeaseEpoch ||
		recovered.Revision != first.Revision || !recovered.LeaseExpiresAt.Equal(first.LeaseExpiresAt) {
		t.Fatalf("recovered=%+v first=%+v", recovered, first)
	}
}

func TestAcquireNextConcurrentWorkersCannotStealActiveLease(t *testing.T) {
	now := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	service, _ := NewService(NewMemoryRepository(), Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{}}, func() time.Time { return now })
	deploymentID := uuid.NewString()
	createAcquireFixture(t, service, deploymentID)
	var wait sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := service.AcquireNext(context.Background(), AcquireRequest{
				DeploymentID: deploymentID, WorkerID: uuid.NewString(),
				IdempotencyKey: uuid.NewString(), LeaseDuration: time.Minute,
			})
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	successes, notFound := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrNotFound):
			notFound++
		default:
			t.Fatalf("unexpected acquire error: %v", err)
		}
	}
	if successes != 1 || notFound != 1 {
		t.Fatalf("successes=%d notFound=%d", successes, notFound)
	}
}

func TestAcquireNextIsDeploymentScopedAndEmptyIsNotFound(t *testing.T) {
	now := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	service, _ := NewService(NewMemoryRepository(), Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{}}, func() time.Time { return now })
	createAcquireFixture(t, service, uuid.NewString())
	if _, err := service.AcquireNext(context.Background(), AcquireRequest{
		DeploymentID: uuid.NewString(), WorkerID: uuid.NewString(),
		IdempotencyKey: uuid.NewString(), LeaseDuration: time.Minute,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-deployment acquire err=%v", err)
	}
}

func TestAcquireNextFailsClosedForDuplicateActiveAssignments(t *testing.T) {
	now := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	repository := NewMemoryRepository()
	service, _ := NewService(repository, Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{}}, func() time.Time { return now })
	deploymentID, workerID := uuid.NewString(), uuid.NewString()
	for range 2 {
		value := createAcquireFixture(t, service, deploymentID)
		stored := repository.operations[value.OperationID]
		stored.State, stored.WorkerID, stored.LeaseEpoch = StateLeased, workerID, 1
		stored.LeaseExpiresAt, stored.Revision, stored.UpdatedAt = now.Add(time.Minute), 2, now
		repository.operations[value.OperationID] = stored
	}
	if _, err := service.AcquireNext(context.Background(), AcquireRequest{
		DeploymentID: deploymentID, WorkerID: workerID,
		IdempotencyKey: uuid.NewString(), LeaseDuration: time.Minute,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate active acquire err=%v", err)
	}
}

func createAcquireFixture(t *testing.T, service *Service, deploymentID string) Operation {
	t.Helper()
	value, err := service.CreateRestart(context.Background(), CreateRestartRequest{
		OperationID: uuid.NewString(), DeploymentID: deploymentID, OwnerID: "owner-acquire",
		LifecycleRestartRef:             "restart-service",
		ExecutionBundleDigest:           "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExpectedInstalledManifestDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		IdempotencyKey:                  uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}
