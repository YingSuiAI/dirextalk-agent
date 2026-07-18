package rpcapi

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type workerOperationSessionStub struct {
	calls int
	check func(context.Context, worker.SessionRequest) (worker.Assignment, error)
}

func (stub *workerOperationSessionStub) GetCurrentAssignment(ctx context.Context, request worker.SessionRequest) (worker.Assignment, error) {
	stub.calls++
	return stub.check(ctx, request)
}

func TestWorkerServiceOperationRequiresDeploymentWorkerSession(t *testing.T) {
	publicKey, _, _ := ed25519.GenerateKey(nil)
	operations, _ := workeroperation.NewService(workeroperation.NewMemoryRepository(),
		workeroperation.Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{"root-1": publicKey}}, time.Now)
	sessions := &workerOperationSessionStub{check: func(context.Context, worker.SessionRequest) (worker.Assignment, error) {
		t.Fatal("unauthenticated request reached session backend")
		return worker.Assignment{}, nil
	}}
	handler := newWorkerServiceOperationHandler(sessions, operations)
	request := &agentv1.WorkerServiceOperationServiceGetRequest{
		OperationId: uuid.NewString(), DeploymentId: uuid.NewString(), WorkerId: uuid.NewString(),
	}
	for _, ctx := range []context.Context{
		context.Background(),
		workerAuthorizationContext("Bearer service-key"),
		workerAuthorizationContext("DTX-Worker-Enroll " + workerTestToken("dtxw-enroll", 0x31)),
	} {
		if _, err := handler.Get(ctx, request); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("Get code = %s, want Unauthenticated", status.Code(err))
		}
	}
	if sessions.calls != 0 {
		t.Fatalf("session calls = %d, want zero", sessions.calls)
	}
}

func TestWorkerServiceOperationClaimUsesAuthenticatedDeploymentScope(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	publicKey, _, _ := ed25519.GenerateKey(nil)
	operations, _ := workeroperation.NewService(workeroperation.NewMemoryRepository(),
		workeroperation.Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{"root-1": publicKey}}, func() time.Time { return now })
	deploymentID, workerID := uuid.NewString(), uuid.NewString()
	created, err := operations.CreateRestart(context.Background(), workeroperation.CreateRestartRequest{
		OperationID: uuid.NewString(), DeploymentID: deploymentID, OwnerID: "owner-a",
		LifecycleRestartRef: "restart-service", ExecutionBundleDigest: workerOperationTestDigest('a'),
		ExpectedInstalledManifestDigest: workerOperationTestDigest('c'),
		IdempotencyKey:                  uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionToken := workerTestToken("dtxw-session", 0x51)
	sessions := &workerOperationSessionStub{check: func(ctx context.Context, request worker.SessionRequest) (worker.Assignment, error) {
		if request.DeploymentID != deploymentID || request.WorkerID != workerID || string(request.Credential) != sessionToken {
			t.Fatalf("session scope = %#v", request)
		}
		return worker.Assignment{DeploymentID: deploymentID, WorkerID: workerID}, nil
	}}
	handler := newWorkerServiceOperationHandler(sessions, operations)
	response, err := handler.Claim(workerAuthorizationContext("DTX-Worker-Session "+sessionToken),
		&agentv1.WorkerServiceOperationServiceClaimRequest{
			OperationId: created.OperationID, DeploymentId: deploymentID, WorkerId: workerID,
			IdempotencyKey: uuid.NewString(), ExpectedRevision: created.Revision, LeaseDurationSeconds: 30,
		})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetAssignment().GetAction() != agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_RESTART ||
		response.GetAssignment().GetLifecycleRestartRef() != "restart-service" ||
		response.GetAssignment().GetExecutionBundleDigest() != workerOperationTestDigest('a') {
		t.Fatalf("claim response = %#v", response.GetAssignment())
	}
}

func TestWorkerServiceOperationAcquireNextDoesNotRequireOperationID(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	publicKey, _, _ := ed25519.GenerateKey(nil)
	operations, _ := workeroperation.NewService(workeroperation.NewMemoryRepository(),
		workeroperation.Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{"root-1": publicKey}}, func() time.Time { return now })
	deploymentID, workerID := uuid.NewString(), uuid.NewString()
	created, err := operations.CreateRestart(context.Background(), workeroperation.CreateRestartRequest{
		OperationID: uuid.NewString(), DeploymentID: deploymentID, OwnerID: "owner-a",
		LifecycleRestartRef: "restart-service", ExecutionBundleDigest: workerOperationTestDigest('b'),
		ExpectedInstalledManifestDigest: workerOperationTestDigest('c'),
		IdempotencyKey:                  uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionToken := workerTestToken("dtxw-session", 0x52)
	sessions := &workerOperationSessionStub{check: func(_ context.Context, request worker.SessionRequest) (worker.Assignment, error) {
		return worker.Assignment{DeploymentID: request.DeploymentID, WorkerID: request.WorkerID}, nil
	}}
	handler := newWorkerServiceOperationHandler(sessions, operations)
	handler.capabilities = newCapabilityIssuerStub(t, uuid.NewString(), deploymentID, now)
	handler.now = func() time.Time { return now }
	response, err := handler.AcquireNext(
		workerAuthorizationContext("DTX-Worker-Session "+sessionToken),
		&agentv1.WorkerServiceOperationServiceAcquireNextRequest{
			DeploymentId: deploymentID, WorkerId: workerID,
			IdempotencyKey: uuid.NewString(), LeaseDurationSeconds: 30,
		})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetAssignment().GetOperationId() != created.OperationID ||
		response.GetAssignment().GetWorkerId() != workerID ||
		response.GetAssignment().GetExpectedInstalledManifestDigest() != workerOperationTestDigest('c') ||
		len(response.GetInstallerDeliveryCbor()) == 0 || len(response.GetSignedCapabilityCbor()) == 0 {
		t.Fatalf("acquire response=%+v", response.GetAssignment())
	}
}

func TestWorkerServiceOperationRPCRejectsUnsignedRestoreFailureAndKeepsLeaseRecoverable(t *testing.T) {
	now := time.Date(2026, 7, 19, 14, 0, 0, 0, time.UTC)
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	operations, _ := workeroperation.NewService(workeroperation.NewMemoryRepository(),
		workeroperation.Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{"root-1": publicKey}},
		func() time.Time { return now })
	deploymentID, workerID := uuid.NewString(), uuid.NewString()
	created, err := operations.CreateLifecycle(context.Background(), workeroperation.CreateLifecycleRequest{
		OperationID: uuid.NewString(), DeploymentID: deploymentID, OwnerID: "owner-recovery",
		Action: workeroperation.ActionRestore, LifecycleRef: "knowledge-restore",
		ExecutionBundleDigest:           workerOperationTestDigest('7'),
		ExpectedInstalledManifestDigest: workerOperationTestDigest('8'),
		ExpectedDeploymentRevision:      7, ExpectedManagedServiceRevision: 11,
		ExpectedKnowledgeBindingRevision: 13, IdempotencyKey: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := operations.Claim(context.Background(), workeroperation.ClaimRequest{
		OperationID: created.OperationID, DeploymentID: deploymentID, WorkerID: workerID,
		IdempotencyKey: uuid.NewString(), ExpectedRevision: created.Revision, LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionToken := workerTestToken("dtxw-session", 0x54)
	sessions := &workerOperationSessionStub{check: func(_ context.Context, request worker.SessionRequest) (worker.Assignment, error) {
		if request.DeploymentID != deploymentID || request.WorkerID != workerID ||
			string(request.Credential) != sessionToken {
			t.Fatalf("session scope=%#v", request)
		}
		return worker.Assignment{DeploymentID: deploymentID, WorkerID: workerID}, nil
	}}
	handler := newWorkerServiceOperationHandler(sessions, operations)
	ctx := workerAuthorizationContext("DTX-Worker-Session " + sessionToken)
	_, err = handler.Complete(ctx, &agentv1.WorkerServiceOperationServiceCompleteRequest{
		OperationId: created.OperationID, DeploymentId: deploymentID, WorkerId: workerID,
		LeaseEpoch: claim.LeaseEpoch, ExpectedRevision: claim.Revision,
		IdempotencyKey: uuid.NewString(), FailureCode: "root_helper_failed",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unsigned restore completion code=%s err=%v", status.Code(err), err)
	}
	stillLeased, err := operations.Get(context.Background(), created.OperationID)
	if err != nil || stillLeased.State != workeroperation.StateLeased ||
		stillLeased.Revision != claim.Revision || stillLeased.LeaseEpoch != claim.LeaseEpoch {
		t.Fatalf("unsigned restore changed operation=%#v err=%v", stillLeased, err)
	}
	receipt, err := workeroperation.SignReceipt(workeroperation.RootHelperReceipt{
		SchemaVersion: workeroperation.SchemaV1, OperationID: created.OperationID,
		DeploymentID: deploymentID, OwnerID: created.OwnerID, Action: workeroperation.ActionRestore,
		LifecycleRestartRef: created.LifecycleRestartRef, ExecutionBundleDigest: created.ExecutionBundleDigest,
		LeaseEpoch: claim.LeaseEpoch, InstallManifestDigest: created.ExpectedInstalledManifestDigest,
		RestartObservationDigest:         workerOperationTestDigest('9'),
		ExpectedDeploymentRevision:       created.ExpectedDeploymentRevision,
		ExpectedManagedServiceRevision:   created.ExpectedManagedServiceRevision,
		ExpectedKnowledgeBindingRevision: created.ExpectedKnowledgeBindingRevision,
		ObservedAt:                       now, HelperID: "root-helper-1", SignerKeyID: "root-1",
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	response, err := handler.Complete(ctx, &agentv1.WorkerServiceOperationServiceCompleteRequest{
		OperationId: created.OperationID, DeploymentId: deploymentID, WorkerId: workerID,
		LeaseEpoch: claim.LeaseEpoch, ExpectedRevision: claim.Revision,
		IdempotencyKey: uuid.NewString(), Receipt: workerServiceOperationReceiptToProto(receipt),
	})
	if err != nil || response.GetOperation().GetState() !=
		agentv1.WorkerServiceOperationState_WORKER_SERVICE_OPERATION_STATE_SUCCEEDED {
		t.Fatalf("signed restore recovery response=%#v err=%v", response, err)
	}
}

func TestWorkerServiceOperationScopeDriftFailsBeforeCapabilityDelivery(t *testing.T) {
	now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
	publicKey, _, _ := ed25519.GenerateKey(nil)
	operations, _ := workeroperation.NewService(workeroperation.NewMemoryRepository(),
		workeroperation.Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{"root-1": publicKey}}, func() time.Time { return now })
	deploymentID, workerID := uuid.NewString(), uuid.NewString()
	created, err := operations.CreateLifecycle(context.Background(), workeroperation.CreateLifecycleRequest{
		OperationID: uuid.NewString(), DeploymentID: deploymentID, OwnerID: "owner-a",
		Action: workeroperation.ActionDestroy, LifecycleRef: "restart-service",
		ExecutionBundleDigest: workerOperationTestDigest('b'), ExpectedInstalledManifestDigest: workerOperationTestDigest('c'),
		ExpectedDeploymentRevision: 7, ExpectedManagedServiceRevision: 3, ExpectedKnowledgeBindingRevision: 2,
		IdempotencyKey: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sessions := &workerOperationSessionStub{check: func(_ context.Context, request worker.SessionRequest) (worker.Assignment, error) {
		return worker.Assignment{DeploymentID: request.DeploymentID, OwnerID: created.OwnerID, WorkerID: request.WorkerID}, nil
	}}
	handler := newWorkerServiceOperationHandler(sessions, operations)
	capabilities := newCapabilityIssuerStub(t, uuid.NewString(), deploymentID, now)
	capabilities.restartErr = workeroperation.ErrRevisionConflict
	handler.capabilities, handler.now = capabilities, func() time.Time { return now }
	_, err = handler.AcquireNext(workerAuthorizationContext("DTX-Worker-Session "+workerTestToken("dtxw-session", 0x53)),
		&agentv1.WorkerServiceOperationServiceAcquireNextRequest{
			DeploymentId: deploymentID, WorkerId: workerID, IdempotencyKey: uuid.NewString(), LeaseDurationSeconds: 3900,
		})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("acquire code=%s err=%v", status.Code(err), err)
	}
	failed, err := operations.Get(context.Background(), created.OperationID)
	if err != nil || failed.State != workeroperation.StateFailed || failed.FailureCode != "authorization_scope_drift" {
		t.Fatalf("failed=%#v err=%v", failed, err)
	}
}

func workerOperationTestDigest(value byte) string {
	result := make([]byte, 64)
	for index := range result {
		result[index] = value
	}
	return "sha256:" + string(result)
}
