package pairingworker

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer/roothelper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestWorkerClientTreatsRootAndCompleteResponseLossAsRetryable(t *testing.T) {
	response := workerAcquireResponse(t)
	t.Run("root socket failure does not durably fail the operation", func(t *testing.T) {
		rpc := &pairingWorkerRPCFake{acquire: response}
		root := &pairingWorkerRootFake{beginErr: roothelper.ErrUnavailable}
		err := newWorkerClient(rpc, root).RunNext(context.Background())
		if status.Code(err) != codes.Unavailable || rpc.completeCalls != 0 || root.beginCalls != 1 {
			t.Fatalf("root response-loss handling err=%v completes=%d root_calls=%d", err, rpc.completeCalls, root.beginCalls)
		}
	})
	t.Run("lost Complete response remains replayable without failure code", func(t *testing.T) {
		rpc := &pairingWorkerRPCFake{acquire: response, completeErr: status.Error(codes.Unavailable, "transport lost")}
		root := &pairingWorkerRootFake{begin: roothelper.PairingBeginReceiptV1{SchemaVersion: roothelper.PairingBeginReceiptSchemaV1}}
		err := newWorkerClient(rpc, root).RunNext(context.Background())
		if status.Code(err) != codes.Unavailable || rpc.completeCalls != 1 || rpc.completeRequest == nil ||
			rpc.completeRequest.GetFailureCode() != "" || len(rpc.completeRequest.GetEncryptedRootHelperReceiptCbor()) == 0 {
			t.Fatalf("Complete response-loss handling err=%v request=%#v", err, rpc.completeRequest)
		}
	})
}

func workerAcquireResponse(t *testing.T) *agentv1.PairingWorkerOperationServiceAcquireNextResponse {
	t.Helper()
	delivery, err := canonical.Marshal(installer.DeliveryV1{})
	if err != nil {
		t.Fatal(err)
	}
	capability, err := canonical.Marshal(installer.SignedRootHelperPairingCapabilityV1{})
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.PairingWorkerOperationServiceAcquireNextResponse{
		Assignment: &agentv1.PairingWorkerOperationAssignment{
			OperationId: "11111111-1111-1111-1111-111111111111", DeploymentId: "deployment", WorkerId: "worker",
			Action:             agentv1.PairingWorkerOperationAction_PAIRING_WORKER_OPERATION_ACTION_BEGIN,
			RecipientPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", LeaseEpoch: 1, Revision: 2,
		},
		InstallerDeliveryCbor: delivery, SignedCapabilityCbor: capability,
		HelperPublicKey: make([]byte, ed25519.PublicKeySize),
	}
}

func newWorkerClient(rpc agentv1.PairingWorkerOperationServiceClient, root RootControl) WorkerClient {
	return WorkerClient{
		RPC: rpc, Root: root, DeploymentID: "deployment", WorkerID: "worker", Lease: 5 * time.Second,
		Session: []byte("dtxw-session.abcdefghijklmnopqrstuvwxyz0123456789"),
	}
}

type pairingWorkerRPCFake struct {
	acquire         *agentv1.PairingWorkerOperationServiceAcquireNextResponse
	acquireErr      error
	completeErr     error
	completeCalls   int
	completeRequest *agentv1.PairingWorkerOperationServiceCompleteRequest
}

func (fake *pairingWorkerRPCFake) AcquireNext(context.Context, *agentv1.PairingWorkerOperationServiceAcquireNextRequest, ...grpc.CallOption) (*agentv1.PairingWorkerOperationServiceAcquireNextResponse, error) {
	return fake.acquire, fake.acquireErr
}

func (fake *pairingWorkerRPCFake) Complete(_ context.Context, request *agentv1.PairingWorkerOperationServiceCompleteRequest, _ ...grpc.CallOption) (*agentv1.PairingWorkerOperationServiceCompleteResponse, error) {
	fake.completeCalls++
	fake.completeRequest = request
	return &agentv1.PairingWorkerOperationServiceCompleteResponse{Revision: 3}, fake.completeErr
}

type pairingWorkerRootFake struct {
	begin      roothelper.PairingBeginReceiptV1
	beginErr   error
	beginCalls int
}

func (fake *pairingWorkerRootFake) PairingBegin(context.Context, installer.DeliveryV1, installer.SignedRootHelperPairingCapabilityV1, string, ed25519.PublicKey) (roothelper.PairingBeginReceiptV1, error) {
	fake.beginCalls++
	return fake.begin, fake.beginErr
}

func (*pairingWorkerRootFake) PairingResume(context.Context, installer.DeliveryV1, installer.SignedRootHelperPairingCapabilityV1, ed25519.PublicKey) (roothelper.PairingResumeReceiptV1, error) {
	return roothelper.PairingResumeReceiptV1{}, roothelper.ErrUnavailable
}
