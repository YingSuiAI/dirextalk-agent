package managedlifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
)

type lifecycleDeviceStore struct{ value cloudapproval.DeviceKeyV1 }

func (store lifecycleDeviceStore) GetDeviceKey(context.Context, string) (cloudapproval.DeviceKeyV1, error) {
	return store.value, nil
}

type lifecycleScopeStore struct{ value ScopeV1 }

func (store lifecycleScopeStore) BuildManagedKnowledgeLifecycleScope(_ context.Context, owner, deployment, service string, action Action) (ScopeV1, error) {
	value := store.value
	if value.OwnerID != owner || value.DeploymentID != deployment || value.ManagedServiceID != service || value.Action != action {
		return ScopeV1{}, ErrRevisionConflict
	}
	return value, nil
}

type lifecycleMemoryStore struct {
	mu         sync.Mutex
	challenges map[string]ChallengeV1
	operations map[string]OperationV1
	prepares   map[string]ChallengeV1
	approvals  map[string]OperationV1
}

func newLifecycleMemoryStore() *lifecycleMemoryStore {
	return &lifecycleMemoryStore{challenges: map[string]ChallengeV1{}, operations: map[string]OperationV1{}, prepares: map[string]ChallengeV1{}, approvals: map[string]OperationV1{}}
}
func lifecycleReplayKey(m Mutation) string {
	return m.Caller.ClientID + "/" + m.Caller.CredentialID + "/" + m.IdempotencyKey
}
func (store *lifecycleMemoryStore) CreateChallenge(_ context.Context, m Mutation, challenge ChallengeV1) (ChallengeV1, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := lifecycleReplayKey(m)
	if replay, found := store.prepares[key]; found {
		if replay.OperationID != challenge.OperationID {
			return ChallengeV1{}, ErrIdempotencyConflict
		}
		return replay, nil
	}
	store.prepares[key], store.challenges[challenge.ChallengeID] = challenge, challenge
	return challenge, nil
}
func (store *lifecycleMemoryStore) GetChallenge(_ context.Context, owner, id string) (ChallengeV1, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, found := store.challenges[id]
	if !found || value.Scope.OwnerID != owner {
		return ChallengeV1{}, ErrNotFound
	}
	return value, nil
}
func (store *lifecycleMemoryStore) Approve(_ context.Context, m Mutation, signature SignatureV1, workerID string, at time.Time) (OperationV1, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := lifecycleReplayKey(m)
	if replay, found := store.approvals[key]; found {
		return replay, nil
	}
	challenge, found := store.challenges[signature.ChallengeID]
	if !found {
		return OperationV1{}, ErrNotFound
	}
	approved := at
	value := OperationV1{Challenge: challenge, Status: StatusScheduled, WorkerOperationID: workerID, Revision: 2, CreatedAt: challenge.IssuedAt, UpdatedAt: at, ApprovedAt: &approved}
	store.approvals[key], store.operations[challenge.OperationID] = value, value
	return value, nil
}
func (store *lifecycleMemoryStore) Get(_ context.Context, owner, id string) (OperationV1, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, found := store.operations[id]
	if !found || value.Challenge.Scope.OwnerID != owner {
		return OperationV1{}, ErrNotFound
	}
	return value, nil
}
func (store *lifecycleMemoryStore) ListActive(_ context.Context, limit int) ([]OperationV1, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	values := make([]OperationV1, 0)
	for _, value := range store.operations {
		if value.Status == StatusScheduled || value.Status == StatusRunning {
			values = append(values, value)
			if len(values) == limit {
				break
			}
		}
	}
	return values, nil
}
func (store *lifecycleMemoryStore) Transition(_ context.Context, id string, expected int64, next Status, code string, at time.Time) (OperationV1, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, found := store.operations[id]
	if !found {
		return OperationV1{}, ErrNotFound
	}
	if value.Revision != expected {
		return OperationV1{}, ErrRevisionConflict
	}
	value.Status, value.ErrorCode, value.UpdatedAt, value.Revision = next, code, at, value.Revision+1
	value.RequiresNewApproval = next == StatusDestroyBlocked
	if value.Validate() != nil {
		return OperationV1{}, ErrInvalid
	}
	store.operations[id] = value
	return value, nil
}

func lifecycleFixture(t *testing.T, action Action) (*Service, *lifecycleMemoryStore, ed25519.PrivateKey, PrepareCommand, time.Time) {
	t.Helper()
	now := time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agent, deployment, managed, binding := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	scope := ScopeV1{SchemaVersion: ScopeSchemaV1, AgentInstanceID: agent, OwnerID: "owner-a", DeploymentID: deployment, ManagedServiceID: managed, KnowledgeBindingID: binding, DeploymentRevision: 7, ManagedServiceRevision: 3, KnowledgeBindingRevision: 2, RecipeDigest: lifecycleDigest('a'), Action: action, LifecycleRef: "knowledge-" + string(action), ExecutionBundleDigest: lifecycleDigest('b'), InstalledManifestDigest: lifecycleDigest('c')}
	store := newLifecycleMemoryStore()
	service, err := NewService(agent, store, lifecycleDeviceStore{cloudapproval.DeviceKeyV1{KeyID: "device-a", AgentInstanceID: agent, OwnerID: "owner-a", Revision: 1, Status: cloudapproval.DeviceKeyActive, PublicKey: public, NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}}, lifecycleScopeStore{scope}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return service, store, private, PrepareCommand{Caller: MutationScope{ClientID: "client-a", CredentialID: uuid.NewString()}, IdempotencyKey: uuid.NewString(), OwnerID: "owner-a", DeploymentID: deployment, ManagedServiceID: managed, KnowledgeBindingID: binding, SignerKeyID: "device-a", ExpectedDeploymentRevision: 7, Action: action}, now
}

func TestManagedKnowledgeLifecycleSignatureScopesExactActionAndOwner(t *testing.T) {
	service, _, private, prepare, _ := lifecycleFixture(t, ActionBackup)
	challenge, err := service.Prepare(context.Background(), prepare)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignatureFor(challenge, private)
	if err != nil {
		t.Fatal(err)
	}
	approve := ApproveCommand{Caller: MutationScope{ClientID: prepare.Caller.ClientID, CredentialID: prepare.Caller.CredentialID}, IdempotencyKey: uuid.NewString(), OwnerID: prepare.OwnerID, DeploymentID: prepare.DeploymentID, OperationID: challenge.OperationID, ScopeDigest: challenge.ScopeDigest, ExpectedRevision: 1, Signature: signature}
	if _, err = service.Approve(context.Background(), approve); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ApproveCommand){"owner": func(c *ApproveCommand) { c.OwnerID = "owner-b" }, "deployment": func(c *ApproveCommand) { c.DeploymentID = uuid.NewString() }, "operation": func(c *ApproveCommand) { c.OperationID = uuid.NewString() }, "scope": func(c *ApproveCommand) { c.ScopeDigest = lifecycleDigest('f') }} {
		t.Run(name, func(t *testing.T) {
			value := approve
			value.IdempotencyKey = uuid.NewString()
			mutate(&value)
			if _, err := service.Approve(context.Background(), value); !errors.Is(err, ErrRevisionConflict) && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrApprovalRequired) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestManagedKnowledgeLifecyclePrepareAndApproveReplayExactly(t *testing.T) {
	service, _, private, prepare, _ := lifecycleFixture(t, ActionStop)
	first, err := service.Prepare(context.Background(), prepare)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := service.Prepare(context.Background(), prepare)
	if err != nil || replay.ChallengeID != first.ChallengeID {
		t.Fatalf("prepare replay=%+v err=%v", replay, err)
	}
	signature, _ := SignatureFor(first, private)
	approve := ApproveCommand{Caller: prepare.Caller, IdempotencyKey: uuid.NewString(), OwnerID: prepare.OwnerID, DeploymentID: prepare.DeploymentID, OperationID: first.OperationID, ScopeDigest: first.ScopeDigest, ExpectedRevision: 1, Signature: signature}
	operation, err := service.Approve(context.Background(), approve)
	if err != nil {
		t.Fatal(err)
	}
	replayOp, err := service.Approve(context.Background(), approve)
	if err != nil || replayOp.WorkerOperationID != operation.WorkerOperationID {
		t.Fatalf("approve replay=%+v err=%v", replayOp, err)
	}
}

func TestManagedKnowledgeLifecycleSchedulesReportsAndRequiresFreshDestroyApproval(t *testing.T) {
	service, store, private, prepare, _ := lifecycleFixture(t, ActionDestroy)
	challenge, err := service.Prepare(context.Background(), prepare)
	if err != nil {
		t.Fatal(err)
	}
	signature, _ := SignatureFor(challenge, private)
	operation, err := service.Approve(context.Background(), ApproveCommand{Caller: prepare.Caller, IdempotencyKey: uuid.NewString(), OwnerID: prepare.OwnerID, DeploymentID: prepare.DeploymentID, OperationID: challenge.OperationID, ScopeDigest: challenge.ScopeDigest, ExpectedRevision: 1, Signature: signature})
	if err != nil || operation.Status != StatusScheduled || operation.WorkerOperationID == "" {
		t.Fatalf("scheduled=%+v err=%v", operation, err)
	}
	blocked, err := service.Report(context.Background(), prepare.OwnerID, operation.Challenge.OperationID, operation.Revision, false, "root_helper_failed")
	if err != nil || blocked.Status != StatusDestroyBlocked || !blocked.RequiresNewApproval {
		t.Fatalf("blocked=%+v err=%v", blocked, err)
	}
	if _, err := service.Report(context.Background(), prepare.OwnerID, operation.Challenge.OperationID, blocked.Revision, true, ""); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("blocked retry err=%v", err)
	}
	fresh := prepare
	fresh.IdempotencyKey = uuid.NewString()
	challenge2, err := service.Prepare(context.Background(), fresh)
	if err != nil || challenge2.OperationID == challenge.OperationID {
		t.Fatalf("fresh challenge=%+v err=%v", challenge2, err)
	}
	if _, err := store.Get(context.Background(), prepare.OwnerID, operation.Challenge.OperationID); err != nil {
		t.Fatal(err)
	}
}

type lifecycleWorkerReader struct{ value workeroperation.Operation }

func (reader lifecycleWorkerReader) Get(context.Context, string) (workeroperation.Operation, error) {
	return reader.value, nil
}

func TestManagedKnowledgeLifecycleReconcilesExactWorkerReceiptAndBlocksFailedDestroy(t *testing.T) {
	service, _, private, prepare, now := lifecycleFixture(t, ActionDestroy)
	challenge, err := service.Prepare(context.Background(), prepare)
	if err != nil {
		t.Fatal(err)
	}
	signature, _ := SignatureFor(challenge, private)
	operation, err := service.Approve(context.Background(), ApproveCommand{
		Caller: prepare.Caller, IdempotencyKey: uuid.NewString(), OwnerID: prepare.OwnerID,
		DeploymentID: prepare.DeploymentID, OperationID: challenge.OperationID,
		ScopeDigest: challenge.ScopeDigest, ExpectedRevision: 1, Signature: signature,
	})
	if err != nil {
		t.Fatal(err)
	}
	worker := workeroperation.Operation{
		SchemaVersion: workeroperation.SchemaV1, OperationID: operation.WorkerOperationID,
		DeploymentID: prepare.DeploymentID, OwnerID: prepare.OwnerID, Action: workeroperation.ActionDestroy,
		LifecycleRestartRef: challenge.Scope.LifecycleRef, ExecutionBundleDigest: challenge.Scope.ExecutionBundleDigest,
		ExpectedInstalledManifestDigest:  challenge.Scope.InstalledManifestDigest,
		ExpectedDeploymentRevision:       challenge.Scope.DeploymentRevision,
		ExpectedManagedServiceRevision:   challenge.Scope.ManagedServiceRevision,
		ExpectedKnowledgeBindingRevision: challenge.Scope.KnowledgeBindingRevision,
		State:                            workeroperation.StateFailed, WorkerID: uuid.NewString(), LeaseEpoch: 1,
		FailureCode: "root_helper_failed", Revision: 3, CreatedAt: now, UpdatedAt: now,
	}
	if worker.Validate() != nil {
		t.Fatal("invalid worker fixture")
	}
	if err := service.ConfigureWorkerOperations(lifecycleWorkerReader{value: worker}); err != nil {
		t.Fatal(err)
	}
	if err := service.ReconcileOnce(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	blocked, err := service.repository.Get(context.Background(), prepare.OwnerID, operation.Challenge.OperationID)
	if err != nil || blocked.Status != StatusDestroyBlocked || !blocked.RequiresNewApproval {
		t.Fatalf("blocked=%#v err=%v", blocked, err)
	}

	driftedService, _, driftPrivate, driftPrepare, driftNow := lifecycleFixture(t, ActionBackup)
	driftChallenge, _ := driftedService.Prepare(context.Background(), driftPrepare)
	driftSignature, _ := SignatureFor(driftChallenge, driftPrivate)
	driftOperation, _ := driftedService.Approve(context.Background(), ApproveCommand{
		Caller: driftPrepare.Caller, IdempotencyKey: uuid.NewString(), OwnerID: driftPrepare.OwnerID,
		DeploymentID: driftPrepare.DeploymentID, OperationID: driftChallenge.OperationID,
		ScopeDigest: driftChallenge.ScopeDigest, ExpectedRevision: 1, Signature: driftSignature,
	})
	driftWorker := workeroperation.Operation{
		SchemaVersion: workeroperation.SchemaV1, OperationID: driftOperation.WorkerOperationID,
		DeploymentID: driftPrepare.DeploymentID, OwnerID: driftPrepare.OwnerID, Action: workeroperation.ActionStop,
		LifecycleRestartRef: driftChallenge.Scope.LifecycleRef, ExecutionBundleDigest: driftChallenge.Scope.ExecutionBundleDigest,
		ExpectedInstalledManifestDigest:  driftChallenge.Scope.InstalledManifestDigest,
		ExpectedDeploymentRevision:       driftChallenge.Scope.DeploymentRevision,
		ExpectedManagedServiceRevision:   driftChallenge.Scope.ManagedServiceRevision,
		ExpectedKnowledgeBindingRevision: driftChallenge.Scope.KnowledgeBindingRevision,
		State:                            workeroperation.StatePending, Revision: 1, CreatedAt: driftNow, UpdatedAt: driftNow,
	}
	_ = driftedService.ConfigureWorkerOperations(lifecycleWorkerReader{value: driftWorker})
	if _, err := driftedService.Get(context.Background(), driftPrepare.OwnerID, driftOperation.Challenge.OperationID); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("worker action drift err=%v", err)
	}
}

func TestManagedKnowledgeRestoreFailureStaysRecoverableAcrossServiceRestart(t *testing.T) {
	service, store, private, prepare, now := lifecycleFixture(t, ActionRestore)
	challenge, err := service.Prepare(context.Background(), prepare)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignatureFor(challenge, private)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := service.Approve(context.Background(), ApproveCommand{
		Caller: prepare.Caller, IdempotencyKey: uuid.NewString(), OwnerID: prepare.OwnerID,
		DeploymentID: prepare.DeploymentID, OperationID: challenge.OperationID,
		ScopeDigest: challenge.ScopeDigest, ExpectedRevision: 1, Signature: signature,
	})
	if err != nil {
		t.Fatal(err)
	}

	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	workerRepository := workeroperation.NewMemoryRepository()
	workerService, err := workeroperation.NewService(
		workerRepository,
		workeroperation.Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{"root-1": rootPublic}},
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	created, err := workerService.CreateLifecycle(context.Background(), workeroperation.CreateLifecycleRequest{
		OperationID: operation.WorkerOperationID, DeploymentID: prepare.DeploymentID, OwnerID: prepare.OwnerID,
		Action: workeroperation.ActionRestore, LifecycleRef: challenge.Scope.LifecycleRef,
		ExecutionBundleDigest:            challenge.Scope.ExecutionBundleDigest,
		ExpectedInstalledManifestDigest:  challenge.Scope.InstalledManifestDigest,
		ExpectedDeploymentRevision:       challenge.Scope.DeploymentRevision,
		ExpectedManagedServiceRevision:   challenge.Scope.ManagedServiceRevision,
		ExpectedKnowledgeBindingRevision: challenge.Scope.KnowledgeBindingRevision,
		IdempotencyKey:                   uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := workerService.Claim(context.Background(), workeroperation.ClaimRequest{
		OperationID: created.OperationID, DeploymentID: created.DeploymentID, WorkerID: uuid.NewString(),
		IdempotencyKey: uuid.NewString(), ExpectedRevision: created.Revision, LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureWorkerOperations(workerService); err != nil {
		t.Fatal(err)
	}
	running, err := service.Get(context.Background(), prepare.OwnerID, operation.Challenge.OperationID)
	if err != nil || running.Status != StatusRunning {
		t.Fatalf("running=%#v err=%v", running, err)
	}

	_, err = workerService.Complete(context.Background(), workeroperation.CompleteRequest{
		OperationID: created.OperationID, DeploymentID: created.DeploymentID, WorkerID: claim.WorkerID,
		LeaseEpoch: claim.LeaseEpoch, IdempotencyKey: uuid.NewString(), ExpectedRevision: claim.Revision,
		FailureCode: "root_helper_failed",
	})
	if !errors.Is(err, workeroperation.ErrSignedObservationRequired) {
		t.Fatalf("unsigned restore failure err=%v", err)
	}

	restartedWorkers, err := workeroperation.NewService(
		workerRepository,
		workeroperation.Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{"root-1": rootPublic}},
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	restartedLifecycle, err := NewService(service.agentID, store, service.devices, service.scopes, service.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := restartedLifecycle.ConfigureWorkerOperations(restartedWorkers); err != nil {
		t.Fatal(err)
	}
	stillRunning, err := restartedLifecycle.Get(context.Background(), prepare.OwnerID, operation.Challenge.OperationID)
	if err != nil || stillRunning.Status != StatusRunning || stillRunning.Revision != running.Revision {
		t.Fatalf("post-restart lifecycle=%#v err=%v", stillRunning, err)
	}

	receipt, err := workeroperation.SignReceipt(workeroperation.RootHelperReceipt{
		SchemaVersion: workeroperation.SchemaV1, OperationID: created.OperationID,
		DeploymentID: created.DeploymentID, OwnerID: created.OwnerID, Action: created.Action,
		LifecycleRestartRef: created.LifecycleRestartRef, ExecutionBundleDigest: created.ExecutionBundleDigest,
		LeaseEpoch: claim.LeaseEpoch, InstallManifestDigest: created.ExpectedInstalledManifestDigest,
		RestartObservationDigest:         lifecycleDigest('d'),
		ExpectedDeploymentRevision:       created.ExpectedDeploymentRevision,
		ExpectedManagedServiceRevision:   created.ExpectedManagedServiceRevision,
		ExpectedKnowledgeBindingRevision: created.ExpectedKnowledgeBindingRevision,
		ObservedAt:                       now, HelperID: "root-helper-1", SignerKeyID: "root-1",
	}, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := restartedWorkers.Complete(context.Background(), workeroperation.CompleteRequest{
		OperationID: created.OperationID, DeploymentID: created.DeploymentID, WorkerID: claim.WorkerID,
		LeaseEpoch: claim.LeaseEpoch, IdempotencyKey: uuid.NewString(), ExpectedRevision: claim.Revision,
		Receipt: receipt,
	})
	if err != nil || completed.State != workeroperation.StateSucceeded || !completed.LeaseExpiresAt.IsZero() {
		t.Fatalf("completed=%#v err=%v", completed, err)
	}
	released, err := restartedLifecycle.Get(context.Background(), prepare.OwnerID, operation.Challenge.OperationID)
	if err != nil || released.Status != StatusSucceeded {
		t.Fatalf("released lifecycle=%#v err=%v", released, err)
	}
}

func lifecycleDigest(value byte) string { return fmt.Sprintf("sha256:%064x", value) }
