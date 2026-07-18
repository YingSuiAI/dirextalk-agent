package rpcapi

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/knowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/knowledgeworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestKnowledgeWorkerControlRequiresSessionAndFencesDeployment(t *testing.T) {
	broker, _ := knowledgeworker.NewBroker(time.Now)
	deploymentID, workerID := uuid.NewString(), uuid.NewString()
	backend := &workerBackendStub{current: func(ctx context.Context, request worker.SessionRequest) (worker.Assignment, error) {
		if values, _ := metadata.FromIncomingContext(ctx); len(values.Get("authorization")) != 0 {
			t.Fatal("Worker authorization reached the domain backend")
		}
		return worker.Assignment{DeploymentID: request.DeploymentID, WorkerID: request.WorkerID, OwnerID: "owner-knowledge", Revision: 4}, nil
	}}
	service := newKnowledgeWorkerControlHandler(backend, broker)
	request := &agentv1.AcquireKnowledgeOperationRequest{DeploymentId: deploymentID, WorkerId: workerID, LeaseDurationSeconds: 10}
	if _, err := service.AcquireKnowledgeOperation(context.Background(), request); status.Code(err) != codes.Unauthenticated || backend.calls != 0 {
		t.Fatalf("unauthenticated acquire code=%s calls=%d err=%v", status.Code(err), backend.calls, err)
	}

	content := []byte("relay memory")
	config := knowledge.ConfigSpec{DeploymentID: deploymentID, ManagedServiceID: uuid.NewString(), RecipeDigest: knowledge.SHA256([]byte("recipe")), EmbeddingProfileID: knowledge.LocalMultilingualE5SmallProfileID, Enabled: true}
	backendResult := make(chan error, 1)
	go func() {
		_, err := broker.StoreMemory(context.Background(), knowledge.MemoryContent{OwnerID: "owner-knowledge", BindingID: uuid.NewString(), SourceID: uuid.NewString(), Content: content, ContentSHA256: knowledge.SHA256(content), Title: "fixture", Binding: config})
		backendResult <- err
	}()

	ctx := workerAuthorizationContext("DTX-Worker-Session " + workerTestToken("dtxw-session", 0x44))
	response, err := service.AcquireKnowledgeOperation(ctx, request)
	if err != nil || response.GetOperation().GetStoreMemory() == nil || backend.calls != 1 {
		t.Fatalf("acquire response=%+v calls=%d err=%v", response, backend.calls, err)
	}
	operation := response.GetOperation()
	if _, err := service.CompleteKnowledgeOperation(ctx, &agentv1.CompleteKnowledgeOperationRequest{
		DeploymentId: uuid.NewString(), WorkerId: workerID, OperationId: operation.GetOperationId(), LeaseId: operation.GetLeaseId(),
		Result: &agentv1.KnowledgeWorkerResult{Acknowledged: true, SizeBytes: int64(len(content)), ContentSha256: knowledge.SHA256(content), PointId: uuid.NewString(), IndexedSegmentCount: 1},
	}); status.Code(err) != codes.NotFound {
		t.Fatalf("cross-deployment completion code=%s err=%v", status.Code(err), err)
	}
	if _, err := service.CompleteKnowledgeOperation(ctx, &agentv1.CompleteKnowledgeOperationRequest{
		DeploymentId: deploymentID, WorkerId: workerID, OperationId: operation.GetOperationId(), LeaseId: operation.GetLeaseId(),
		Result: &agentv1.KnowledgeWorkerResult{Acknowledged: true, SizeBytes: int64(len(content)), ContentSha256: knowledge.SHA256(content), PointId: uuid.NewString(), IndexedSegmentCount: 1},
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-backendResult; err != nil {
		t.Fatalf("backend result = %v", err)
	}
}
