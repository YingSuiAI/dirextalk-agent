package workeroperation

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRestartRunnerIsClosedAndRecoversResponseLoss(t *testing.T) {
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	repository := NewMemoryRepository()
	service, err := NewService(repository, Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{"root-1": publicKey}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	operationID, deploymentID, ownerID, workerID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	created, err := service.CreateRestart(context.Background(), CreateRestartRequest{
		OperationID: operationID, DeploymentID: deploymentID, OwnerID: ownerID,
		LifecycleRestartRef: "restart", ExecutionBundleDigest: testDigest('a'), IdempotencyKey: uuid.NewString(),
		ExpectedInstalledManifestDigest: testDigest('b'),
	})
	if err != nil {
		t.Fatal(err)
	}
	helper := &fakeRootHelper{privateKey: privateKey, now: func() time.Time { return now }}
	control := &responseLossControl{Service: service}
	runner := Runner{Control: control, Helper: helper}
	claim := ClaimRequest{
		OperationID: operationID, DeploymentID: deploymentID, WorkerID: workerID,
		IdempotencyKey: uuid.NewString(), ExpectedRevision: created.Revision, LeaseDuration: time.Minute,
	}
	if _, err := runner.RunRestart(context.Background(), claim); !errors.Is(err, errResponseLost) {
		t.Fatalf("first completion error = %v, want response loss", err)
	}
	restarted := Runner{Control: service, Helper: helper}
	completed, err := restarted.RunRestart(context.Background(), claim)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != StateSucceeded || completed.Receipt == nil || completed.Receipt.InstallManifestDigest != testDigest('b') ||
		completed.Receipt.RestartObservationDigest != testDigest('c') || helper.calls != 1 {
		t.Fatalf("response-loss recovery re-executed helper or lost receipt: %#v calls=%d", completed, helper.calls)
	}
	if completed.Receipt.SchemaVersion != SchemaV1 {
		t.Fatalf("receipt is not authenticated root-helper receipt: %#v", completed.Receipt)
	}
}

func TestRestartLeaseRecoveryFencesLateResult(t *testing.T) {
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	repository := NewMemoryRepository()
	service, _ := NewService(repository, Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{"root-1": publicKey}}, func() time.Time { return now })
	created, err := service.CreateRestart(context.Background(), CreateRestartRequest{
		OperationID: uuid.NewString(), DeploymentID: uuid.NewString(), OwnerID: uuid.NewString(),
		LifecycleRestartRef: "restart-service", ExecutionBundleDigest: testDigest('d'), IdempotencyKey: uuid.NewString(),
		ExpectedInstalledManifestDigest: testDigest('f'),
	})
	if err != nil {
		t.Fatal(err)
	}
	workerID := uuid.NewString()
	first, err := service.Claim(context.Background(), ClaimRequest{
		OperationID: created.OperationID, DeploymentID: created.DeploymentID, WorkerID: workerID,
		IdempotencyKey: uuid.NewString(), ExpectedRevision: created.Revision, LeaseDuration: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	now = first.LeaseExpiresAt.Add(time.Nanosecond)
	second, err := service.Claim(context.Background(), ClaimRequest{
		OperationID: created.OperationID, DeploymentID: created.DeploymentID, WorkerID: workerID,
		IdempotencyKey: uuid.NewString(), ExpectedRevision: first.Revision, LeaseDuration: time.Minute,
	})
	if err != nil || second.LeaseEpoch != first.LeaseEpoch+1 {
		t.Fatalf("reclaim = %#v, %v", second, err)
	}
	late := signedTestReceipt(t, privateKey, created, first.LeaseEpoch, now)
	_, err = service.Complete(context.Background(), CompleteRequest{
		OperationID: created.OperationID, DeploymentID: created.DeploymentID, WorkerID: workerID,
		LeaseEpoch: first.LeaseEpoch, IdempotencyKey: uuid.NewString(), ExpectedRevision: second.Revision, Receipt: late,
	})
	if !errors.Is(err, ErrStaleLease) {
		t.Fatalf("late result error = %v, want stale lease", err)
	}
}

func TestExactIdempotencyRejectsPayloadConflict(t *testing.T) {
	now := time.Now().UTC()
	publicKey, _, _ := ed25519.GenerateKey(nil)
	service, _ := NewService(NewMemoryRepository(), Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{"root-1": publicKey}}, func() time.Time { return now })
	key := uuid.NewString()
	request := CreateRestartRequest{
		OperationID: uuid.NewString(), DeploymentID: uuid.NewString(), OwnerID: uuid.NewString(),
		LifecycleRestartRef: "restart", ExecutionBundleDigest: testDigest('e'), IdempotencyKey: key,
		ExpectedInstalledManifestDigest: testDigest('b'),
	}
	first, err := service.CreateRestart(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := service.CreateRestart(context.Background(), request)
	if err != nil || replayed.Revision != first.Revision {
		t.Fatalf("exact replay = %#v, %v", replayed, err)
	}
	request.LifecycleRestartRef = "other-restart"
	if _, err := service.CreateRestart(context.Background(), request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting replay error = %v", err)
	}
}

type fakeRootHelper struct {
	privateKey ed25519.PrivateKey
	now        func() time.Time
	calls      int
}

func (helper *fakeRootHelper) Restart(_ context.Context, capability RestartCapability) (RootHelperReceipt, error) {
	helper.calls++
	return SignReceipt(RootHelperReceipt{
		SchemaVersion: SchemaV1, OperationID: capability.OperationID, DeploymentID: capability.DeploymentID,
		OwnerID: capability.OwnerID, Action: capability.Action, LifecycleRestartRef: capability.LifecycleRestartRef,
		ExecutionBundleDigest: capability.ExecutionBundleDigest, LeaseEpoch: capability.LeaseEpoch,
		InstallManifestDigest: capability.ExpectedInstalledManifestDigest, RestartObservationDigest: testDigest('c'),
		ExpectedDeploymentRevision:       capability.ExpectedDeploymentRevision,
		ExpectedManagedServiceRevision:   capability.ExpectedManagedServiceRevision,
		ExpectedKnowledgeBindingRevision: capability.ExpectedKnowledgeBindingRevision,
		ObservedAt:                       helper.now(), HelperID: "root-helper-1", SignerKeyID: "root-1",
	}, helper.privateKey)
}

func TestLifecycleDeliveryAcceptsOnlyClosedActionsAndFencesReceiptAction(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	service, _ := NewService(NewMemoryRepository(), Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{"root-1": publicKey}}, func() time.Time { return now })
	for _, action := range []Action{ActionStop, ActionBackup, ActionRestore, ActionUpgrade, ActionRollback, ActionDestroy} {
		t.Run(string(action), func(t *testing.T) {
			created, err := service.CreateLifecycle(context.Background(), CreateLifecycleRequest{
				OperationID: uuid.NewString(), DeploymentID: uuid.NewString(), OwnerID: "owner-lifecycle",
				Action: action, LifecycleRef: "knowledge-" + string(action),
				ExecutionBundleDigest: testDigest('a'), ExpectedInstalledManifestDigest: testDigest('b'),
				ExpectedDeploymentRevision: 7, ExpectedManagedServiceRevision: 3, ExpectedKnowledgeBindingRevision: 2,
				IdempotencyKey: uuid.NewString(),
			})
			if err != nil || created.Action != action {
				t.Fatalf("created=%#v err=%v", created, err)
			}
			claim, err := service.Claim(context.Background(), ClaimRequest{
				OperationID: created.OperationID, DeploymentID: created.DeploymentID, WorkerID: uuid.NewString(),
				IdempotencyKey: uuid.NewString(), ExpectedRevision: created.Revision, LeaseDuration: time.Minute,
			})
			if err != nil {
				t.Fatal(err)
			}
			mismatched := signedTestReceipt(t, privateKey, created, claim.LeaseEpoch, now)
			mismatched.Action = ActionRestart
			mismatched, _ = SignReceipt(mismatched, privateKey)
			if _, err := service.Complete(context.Background(), CompleteRequest{
				OperationID: created.OperationID, DeploymentID: created.DeploymentID, WorkerID: claim.WorkerID,
				LeaseEpoch: claim.LeaseEpoch, IdempotencyKey: uuid.NewString(), ExpectedRevision: claim.Revision,
				Receipt: mismatched,
			}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("mismatched receipt action err=%v", err)
			}
		})
	}
	if _, err := service.CreateLifecycle(context.Background(), CreateLifecycleRequest{
		OperationID: uuid.NewString(), DeploymentID: uuid.NewString(), OwnerID: "owner-lifecycle",
		Action: "shell", LifecycleRef: "knowledge-stop", ExecutionBundleDigest: testDigest('a'),
		ExpectedInstalledManifestDigest: testDigest('b'), IdempotencyKey: uuid.NewString(),
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("open action accepted: %v", err)
	}
}

func TestGenerationSwapFailureRequiresSignedObservationAcrossServiceRestart(t *testing.T) {
	for _, action := range []Action{ActionRestore, ActionUpgrade, ActionRollback} {
		t.Run(string(action), func(t *testing.T) {
			now := time.Date(2026, 7, 19, 15, 0, 0, 0, time.UTC)
			publicKey, privateKey, _ := ed25519.GenerateKey(nil)
			repository := NewMemoryRepository()
			service, _ := NewService(repository,
				Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{"root-1": publicKey}},
				func() time.Time { return now })
			created, err := service.CreateLifecycle(context.Background(), CreateLifecycleRequest{
				OperationID: uuid.NewString(), DeploymentID: uuid.NewString(), OwnerID: "owner-recovery",
				Action: action, LifecycleRef: "knowledge-" + string(action),
				ExecutionBundleDigest: testDigest('7'), ExpectedInstalledManifestDigest: testDigest('8'),
				ExpectedDeploymentRevision: 7, ExpectedManagedServiceRevision: 11,
				ExpectedKnowledgeBindingRevision: 13, IdempotencyKey: uuid.NewString(),
			})
			if err != nil {
				t.Fatal(err)
			}
			claim, err := service.Claim(context.Background(), ClaimRequest{
				OperationID: created.OperationID, DeploymentID: created.DeploymentID,
				WorkerID: uuid.NewString(), IdempotencyKey: uuid.NewString(),
				ExpectedRevision: created.Revision, LeaseDuration: time.Minute,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Complete(context.Background(), CompleteRequest{
				OperationID: created.OperationID, DeploymentID: created.DeploymentID,
				WorkerID: claim.WorkerID, LeaseEpoch: claim.LeaseEpoch,
				IdempotencyKey: uuid.NewString(), ExpectedRevision: claim.Revision,
				FailureCode: "root_helper_failed",
			}); !errors.Is(err, ErrSignedObservationRequired) {
				t.Fatalf("unsigned %s failure error=%v", action, err)
			}
			stillLeased, err := service.Get(context.Background(), created.OperationID)
			if err != nil || stillLeased.State != StateLeased || stillLeased.Revision != claim.Revision ||
				stillLeased.LeaseEpoch != claim.LeaseEpoch {
				t.Fatalf("unsigned %s failure changed operation=%#v err=%v", action, stillLeased, err)
			}

			restarted, _ := NewService(repository,
				Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{"root-1": publicKey}},
				func() time.Time { return now })
			receipt, err := SignReceipt(RootHelperReceipt{
				SchemaVersion: SchemaV1, OperationID: created.OperationID, DeploymentID: created.DeploymentID,
				OwnerID: created.OwnerID, Action: action, LifecycleRestartRef: created.LifecycleRestartRef,
				ExecutionBundleDigest: created.ExecutionBundleDigest, LeaseEpoch: claim.LeaseEpoch,
				InstallManifestDigest:            created.ExpectedInstalledManifestDigest,
				RestartObservationDigest:         testDigest('9'),
				ExpectedDeploymentRevision:       created.ExpectedDeploymentRevision,
				ExpectedManagedServiceRevision:   created.ExpectedManagedServiceRevision,
				ExpectedKnowledgeBindingRevision: created.ExpectedKnowledgeBindingRevision,
				ObservedAt:                       now, HelperID: "root-helper-1", SignerKeyID: "root-1",
			}, privateKey)
			if err != nil {
				t.Fatal(err)
			}
			completed, err := restarted.Complete(context.Background(), CompleteRequest{
				OperationID: created.OperationID, DeploymentID: created.DeploymentID,
				WorkerID: claim.WorkerID, LeaseEpoch: claim.LeaseEpoch,
				IdempotencyKey: uuid.NewString(), ExpectedRevision: claim.Revision, Receipt: receipt,
			})
			if err != nil || completed.State != StateSucceeded || completed.Receipt == nil {
				t.Fatalf("signed %s recovery completion=%#v err=%v", action, completed, err)
			}
		})
	}
}

func TestUnsignedBackupFailureRetainsNormalTerminalBehavior(t *testing.T) {
	now := time.Date(2026, 7, 19, 15, 0, 0, 0, time.UTC)
	publicKey, _, _ := ed25519.GenerateKey(nil)
	service, _ := NewService(NewMemoryRepository(),
		Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{"root-1": publicKey}},
		func() time.Time { return now })
	created, err := service.CreateLifecycle(context.Background(), CreateLifecycleRequest{
		OperationID: uuid.NewString(), DeploymentID: uuid.NewString(), OwnerID: "owner-backup",
		Action: ActionBackup, LifecycleRef: "knowledge-backup", ExecutionBundleDigest: testDigest('1'),
		ExpectedInstalledManifestDigest: testDigest('2'), ExpectedDeploymentRevision: 7,
		ExpectedManagedServiceRevision: 11, ExpectedKnowledgeBindingRevision: 13,
		IdempotencyKey: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := service.Claim(context.Background(), ClaimRequest{
		OperationID: created.OperationID, DeploymentID: created.DeploymentID, WorkerID: uuid.NewString(),
		IdempotencyKey: uuid.NewString(), ExpectedRevision: created.Revision, LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	failed, err := service.Complete(context.Background(), CompleteRequest{
		OperationID: created.OperationID, DeploymentID: created.DeploymentID, WorkerID: claim.WorkerID,
		LeaseEpoch: claim.LeaseEpoch, IdempotencyKey: uuid.NewString(), ExpectedRevision: claim.Revision,
		FailureCode: "root_helper_failed",
	})
	if err != nil || failed.State != StateFailed || failed.FailureCode != "root_helper_failed" {
		t.Fatalf("ordinary backup failure=%#v err=%v", failed, err)
	}
}

var errResponseLost = errors.New("response lost")

type responseLossControl struct {
	*Service
	lost bool
}

func (control *responseLossControl) Complete(ctx context.Context, request CompleteRequest) (Operation, error) {
	value, err := control.Service.Complete(ctx, request)
	if err == nil && !control.lost {
		control.lost = true
		return Operation{}, errResponseLost
	}
	return value, err
}

func signedTestReceipt(t *testing.T, key ed25519.PrivateKey, operation Operation, epoch int64, at time.Time) RootHelperReceipt {
	t.Helper()
	receipt, err := SignReceipt(RootHelperReceipt{
		SchemaVersion: SchemaV1, OperationID: operation.OperationID, DeploymentID: operation.DeploymentID,
		OwnerID: operation.OwnerID, Action: ActionRestart, LifecycleRestartRef: operation.LifecycleRestartRef,
		ExecutionBundleDigest: operation.ExecutionBundleDigest, LeaseEpoch: epoch,
		InstallManifestDigest: operation.ExpectedInstalledManifestDigest, RestartObservationDigest: testDigest('1'),
		ExpectedDeploymentRevision:       operation.ExpectedDeploymentRevision,
		ExpectedManagedServiceRevision:   operation.ExpectedManagedServiceRevision,
		ExpectedKnowledgeBindingRevision: operation.ExpectedKnowledgeBindingRevision,
		ObservedAt:                       at, HelperID: "root-helper-1", SignerKeyID: "root-1",
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func testDigest(value byte) string {
	return "sha256:" + string(make([]byte, 0)) + repeatByte(value, 64)
}

func repeatByte(value byte, count int) string {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return string(result)
}
