package knowledgeworker

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/knowledge"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type knowledgeRPCFake struct {
	operation          *agentv1.KnowledgeWorkerOperation
	acquireCalls       int
	completeCalls      int
	completedPoint     string
	completedCount     int32
	expectedDeployment string
	t                  *testing.T
}

func (fake *knowledgeRPCFake) AcquireKnowledgeOperation(ctx context.Context, request *agentv1.AcquireKnowledgeOperationRequest, _ ...grpc.CallOption) (*agentv1.AcquireKnowledgeOperationResponse, error) {
	fake.acquireCalls++
	fake.requireAuthorization(ctx)
	if request.GetDeploymentId() != fake.expectedDeployment || !canonicalUUID(request.GetWorkerId()) || request.GetLeaseDurationSeconds() != 10 {
		fake.t.Fatalf("acquire request=%+v", request)
	}
	return &agentv1.AcquireKnowledgeOperationResponse{Operation: fake.operation}, nil
}

func (fake *knowledgeRPCFake) CompleteKnowledgeOperation(ctx context.Context, request *agentv1.CompleteKnowledgeOperationRequest, _ ...grpc.CallOption) (*agentv1.CompleteKnowledgeOperationResponse, error) {
	fake.completeCalls++
	fake.requireAuthorization(ctx)
	if request.GetDeploymentId() != fake.operation.GetBinding().GetDeploymentId() || request.GetOperationId() != fake.operation.GetOperationId() || request.GetLeaseId() != fake.operation.GetLeaseId() || !request.GetResult().GetAcknowledged() {
		fake.t.Fatalf("complete request=%+v", request)
	}
	fake.completedPoint = request.GetResult().GetPointId()
	fake.completedCount = request.GetResult().GetIndexedSegmentCount()
	return &agentv1.CompleteKnowledgeOperationResponse{}, nil
}

func (fake *knowledgeRPCFake) requireAuthorization(ctx context.Context) {
	values, _ := metadata.FromOutgoingContext(ctx)
	if got := values.Get("authorization"); len(got) != 1 || got[0] != "DTX-Worker-Session dtxw-session."+string(make([]byte, 32)) {
		fake.t.Fatalf("authorization=%q", got)
	}
}

type knowledgeAdapterFake struct {
	calls int
	point string
}

func (fake *knowledgeAdapterFake) Execute(_ context.Context, operation *agentv1.KnowledgeWorkerOperation) *agentv1.KnowledgeWorkerResult {
	fake.calls++
	memory := operation.GetStoreMemory()
	if memory == nil || string(memory.GetContent()) != "worker private content" {
		return &agentv1.KnowledgeWorkerResult{ErrorCode: "internal"}
	}
	return &agentv1.KnowledgeWorkerResult{
		Acknowledged: true, SizeBytes: int64(len(memory.GetContent())), ContentSha256: memory.GetContentSha256(),
		PointId: fake.point, IndexedSegmentCount: 1,
	}
}

func TestWorkerClientAuthorizesExecutesAndCompletesExactLease(t *testing.T) {
	deploymentID, workerID := uuid.NewString(), uuid.NewString()
	content := []byte("worker private content")
	operation := &agentv1.KnowledgeWorkerOperation{
		OperationId: uuid.NewString(), LeaseId: uuid.NewString(), LeaseExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
		Binding: &agentv1.KnowledgeWorkerBinding{OwnerId: "owner-worker", BindingId: uuid.NewString(), DeploymentId: deploymentID, ManagedServiceId: uuid.NewString()},
		Request: &agentv1.KnowledgeWorkerOperation_StoreMemory{StoreMemory: &agentv1.KnowledgeWorkerStoreMemory{SourceId: uuid.NewString(), Content: content, ContentSha256: knowledge.SHA256(content)}},
	}
	rpc := &knowledgeRPCFake{operation: operation, expectedDeployment: deploymentID, t: t}
	adapter := &knowledgeAdapterFake{point: uuid.NewString()}
	client := &WorkerClient{
		RPC: rpc, Adapter: adapter, DeploymentID: deploymentID, WorkerID: workerID, Lease: 10 * time.Second,
		Session: append([]byte("dtxw-session."), make([]byte, 32)...),
	}
	if err := client.RunNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rpc.acquireCalls != 1 || rpc.completeCalls != 1 || adapter.calls != 1 || rpc.completedPoint != adapter.point || rpc.completedCount != 1 {
		t.Fatalf("acquire=%d complete=%d adapter=%d point=%q count=%d", rpc.acquireCalls, rpc.completeCalls, adapter.calls, rpc.completedPoint, rpc.completedCount)
	}
	if len(operation.GetStoreMemory().GetContent()) != 0 {
		t.Fatal("leased content was not cleared")
	}
	client.Close()
	if len(client.Session) != 0 {
		t.Fatal("Worker session was not cleared")
	}
}

func TestWorkerClientRejectsCrossDeploymentBeforeAdapter(t *testing.T) {
	workerID := uuid.NewString()
	operation := &agentv1.KnowledgeWorkerOperation{
		OperationId: uuid.NewString(), LeaseId: uuid.NewString(), LeaseExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
		Binding: &agentv1.KnowledgeWorkerBinding{OwnerId: "owner-worker", BindingId: uuid.NewString(), DeploymentId: uuid.NewString(), ManagedServiceId: uuid.NewString()},
		Request: &agentv1.KnowledgeWorkerOperation_Status{Status: &agentv1.KnowledgeWorkerStatus{}},
	}
	clientDeploymentID := uuid.NewString()
	rpc := &knowledgeRPCFake{operation: operation, expectedDeployment: clientDeploymentID, t: t}
	adapter := &knowledgeAdapterFake{point: uuid.NewString()}
	client := &WorkerClient{RPC: rpc, Adapter: adapter, DeploymentID: clientDeploymentID, WorkerID: workerID, Lease: 10 * time.Second, Session: append([]byte("dtxw-session."), make([]byte, 32)...)}
	if err := client.RunNext(context.Background()); err == nil || adapter.calls != 0 || rpc.completeCalls != 0 {
		t.Fatalf("error=%v adapter=%d complete=%d", err, adapter.calls, rpc.completeCalls)
	}
}
