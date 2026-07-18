package knowledgeworker

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/knowledge"
	"github.com/google/uuid"
)

func TestBrokerFencesDeploymentLeaseAndReplaysStableChunk(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	broker, err := NewBroker(func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	deploymentID := uuid.NewString()
	value := chunkFixture(deploymentID)
	result := make(chan error, 1)
	go func() { result <- broker.StageAttachmentChunk(context.Background(), value) }()

	wrongContext, cancelWrong := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelWrong()
	if _, err := broker.Acquire(wrongContext, value.OwnerID, uuid.NewString(), 10*time.Second); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong deployment acquire error = %v", err)
	}
	operation, err := broker.Acquire(context.Background(), value.OwnerID, deploymentID, 10*time.Second)
	if err != nil || operation.GetStageChunk() == nil || operation.GetStageChunk().GetChunkSha256() != value.ChunkSHA256 {
		t.Fatalf("operation=%+v err=%v", operation, err)
	}
	if err := broker.Complete(value.OwnerID, deploymentID, operation.GetOperationId(), uuid.NewString(), &agentv1.KnowledgeWorkerResult{Acknowledged: true}); !errors.Is(err, ErrLease) {
		t.Fatalf("wrong lease completion error = %v", err)
	}
	if err := broker.Complete(value.OwnerID, deploymentID, operation.GetOperationId(), operation.GetLeaseId(), &agentv1.KnowledgeWorkerResult{Acknowledged: true}); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatalf("stage result = %v", err)
	}
	if err := broker.StageAttachmentChunk(context.Background(), value); err != nil {
		t.Fatalf("stable replay = %v", err)
	}
	idle, cancelIdle := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelIdle()
	if _, err := broker.Acquire(idle, value.OwnerID, deploymentID, 10*time.Second); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replay queued another operation: %v", err)
	}
	if !broker.Available() {
		t.Fatal("recent authenticated acquire did not mark backend available")
	}
}

func TestBrokerRejectsInvalidEvidenceAndRequeuesExpiredLease(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	broker, _ := NewBroker(func() time.Time { return now })
	deploymentID := uuid.NewString()
	value := memoryFixture(deploymentID)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := broker.StoreMemory(ctx, value)
		result <- err
	}()
	first, err := broker.Acquire(ctx, value.OwnerID, deploymentID, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Complete(value.OwnerID, deploymentID, first.GetOperationId(), first.GetLeaseId(), &agentv1.KnowledgeWorkerResult{
		Acknowledged: true, SizeBytes: int64(len(value.Content)) + 1, ContentSha256: value.ContentSHA256, PointId: uuid.NewString(), IndexedSegmentCount: 1,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid receipt error = %v", err)
	}
	now = now.Add(6 * time.Second)
	second, err := broker.Acquire(ctx, value.OwnerID, deploymentID, 5*time.Second)
	if err != nil || second.GetOperationId() != first.GetOperationId() || second.GetLeaseId() == first.GetLeaseId() {
		t.Fatalf("requeued operation=%+v err=%v", second, err)
	}
	if err := broker.Complete(value.OwnerID, deploymentID, second.GetOperationId(), second.GetLeaseId(), &agentv1.KnowledgeWorkerResult{
		Acknowledged: true, SizeBytes: int64(len(value.Content)), ContentSha256: value.ContentSHA256, PointId: uuid.NewString(), IndexedSegmentCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatalf("memory result = %v", err)
	}
}

func TestBrokerRejectsUntrustedKnowledgeMetadata(t *testing.T) {
	deploymentID := uuid.NewString()
	chunk := chunkFixture(deploymentID)
	chunk.MediaType = "text/plain; charset=utf-8"
	if validRequest(&agentv1.KnowledgeWorkerOperation{Binding: bindingToProto(chunk.OwnerID, chunk.BindingID, chunk.Binding), Request: &agentv1.KnowledgeWorkerOperation_StageChunk{StageChunk: &agentv1.KnowledgeWorkerStageChunk{
		SourceId: chunk.SourceID, UploadId: chunk.UploadID, MediaType: chunk.MediaType, DeclaredSizeBytes: chunk.DeclaredSizeBytes,
		OffsetBytes: chunk.OffsetBytes, ChunkOrdinal: chunk.ChunkOrdinal, Chunk: chunk.Chunk, ChunkSha256: chunk.ChunkSHA256, Title: chunk.Title,
	}}}) {
		t.Fatal("relay accepted a parameterized media type")
	}
	memory := memoryFixture(deploymentID)
	memory.Title = "bad\nmetadata"
	if validRequest(&agentv1.KnowledgeWorkerOperation{Binding: bindingToProto(memory.OwnerID, memory.BindingID, memory.Binding), Request: &agentv1.KnowledgeWorkerOperation_StoreMemory{StoreMemory: &agentv1.KnowledgeWorkerStoreMemory{
		SourceId: memory.SourceID, Content: memory.Content, ContentSha256: memory.ContentSHA256, Title: memory.Title,
	}}}) {
		t.Fatal("relay accepted a control character in memory metadata")
	}
}

func TestBrokerAcquireAndCompleteFenceOwnerWithinDeployment(t *testing.T) {
	broker, _ := NewBroker(time.Now)
	deploymentID := uuid.NewString()
	value := memoryFixture(deploymentID)
	result := make(chan error, 1)
	go func() {
		_, err := broker.StoreMemory(context.Background(), value)
		result <- err
	}()

	wrongCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := broker.Acquire(wrongCtx, "another-owner", deploymentID, 10*time.Second); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-owner acquire error = %v", err)
	}
	operation, err := broker.Acquire(context.Background(), value.OwnerID, deploymentID, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &agentv1.KnowledgeWorkerResult{Acknowledged: true, SizeBytes: int64(len(value.Content)), ContentSha256: value.ContentSHA256, PointId: uuid.NewString(), IndexedSegmentCount: 1}
	if err := broker.Complete("another-owner", deploymentID, operation.GetOperationId(), operation.GetLeaseId(), receipt); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-owner completion error = %v", err)
	}
	if err := broker.Complete(value.OwnerID, deploymentID, operation.GetOperationId(), operation.GetLeaseId(), receipt); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestBrokerActiveLongPollKeepsFirstMutationAvailableBeyondIdleWindow(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	broker, _ := NewBroker(func() time.Time { return now })
	deploymentID := uuid.NewString()
	value := memoryFixture(deploymentID)
	acquired := make(chan *agentv1.KnowledgeWorkerOperation, 1)
	acquireErr := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		operation, err := broker.Acquire(ctx, value.OwnerID, deploymentID, 10*time.Second)
		acquired <- operation
		acquireErr <- err
	}()
	deadline := time.Now().Add(time.Second)
	for {
		broker.mu.Lock()
		active := broker.activeWaiters[deploymentID]
		broker.mu.Unlock()
		if active == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("authenticated long poll did not register")
		}
		runtime.Gosched()
	}
	now = now.Add(workerAvailability + time.Second)
	if !broker.Available() {
		t.Fatal("active authenticated long poll expired before the first mutation")
	}
	result := make(chan error, 1)
	go func() {
		_, err := broker.StoreMemory(context.Background(), value)
		result <- err
	}()
	operation := <-acquired
	if err := <-acquireErr; err != nil || operation == nil {
		t.Fatalf("long-poll acquire operation=%+v err=%v", operation, err)
	}
	if err := broker.Complete(value.OwnerID, deploymentID, operation.GetOperationId(), operation.GetLeaseId(), &agentv1.KnowledgeWorkerResult{
		Acknowledged: true, SizeBytes: int64(len(value.Content)), ContentSha256: value.ContentSHA256,
		PointId: uuid.NewString(), IndexedSegmentCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatalf("first mutation after idle window failed: %v", err)
	}
}

func TestBrokerSearchIsNotCachedAndStatusIsTyped(t *testing.T) {
	broker, _ := NewBroker(time.Now)
	config := configFixture(uuid.NewString())
	query := knowledge.SearchQuery{OwnerID: config.OwnerID, BindingID: config.BindingID, ExpectedBindingRevision: 1, Query: "持久化测试", Limit: 3}
	searchResult := make(chan []knowledge.SearchMatch, 1)
	searchErr := make(chan error, 1)
	go func() {
		matches, err := broker.Search(context.Background(), config, query)
		searchResult <- matches
		searchErr <- err
	}()
	operation, err := broker.Acquire(context.Background(), config.OwnerID, config.Spec.DeploymentID, 10*time.Second)
	if err != nil || operation.GetSearch().GetQuery() != query.Query {
		t.Fatalf("search operation=%+v err=%v", operation, err)
	}
	match := &agentv1.KnowledgeWorkerSearchMatch{SourceId: uuid.NewString(), ChunkRef: "chunk:0", Score: 0.91}
	if err := broker.Complete(config.OwnerID, config.Spec.DeploymentID, operation.GetOperationId(), operation.GetLeaseId(), &agentv1.KnowledgeWorkerResult{Acknowledged: true, Matches: []*agentv1.KnowledgeWorkerSearchMatch{match}}); err != nil {
		t.Fatal(err)
	}
	if err := <-searchErr; err != nil {
		t.Fatal(err)
	}
	if matches := <-searchResult; len(matches) != 1 || matches[0].SourceID != match.SourceId {
		t.Fatalf("matches=%+v", matches)
	}

	statusResult := make(chan knowledge.BackendStatus, 1)
	statusErr := make(chan error, 1)
	challenge := &knowledge.PersistenceChallenge{PointID: uuid.NewString(), SourceID: match.SourceId, SizeBytes: 17, ContentSHA256: knowledge.SHA256([]byte("persistent memory"))}
	go func() {
		value, err := broker.Status(context.Background(), config, challenge)
		statusResult <- value
		statusErr <- err
	}()
	statusOperation, err := broker.Acquire(context.Background(), config.OwnerID, config.Spec.DeploymentID, 10*time.Second)
	if err != nil || statusOperation.GetStatus() == nil || statusOperation.GetStatus().GetPointId() != challenge.PointID || statusOperation.GetStatus().GetSourceId() != challenge.SourceID || statusOperation.GetStatus().GetContentSha256() != challenge.ContentSHA256 {
		t.Fatalf("status operation=%+v err=%v", statusOperation, err)
	}
	if err := broker.Complete(config.OwnerID, config.Spec.DeploymentID, statusOperation.GetOperationId(), statusOperation.GetLeaseId(), &agentv1.KnowledgeWorkerResult{
		Acknowledged: true, BackendStatus: agentv1.KnowledgeWorkerBackendStatus_KNOWLEDGE_WORKER_BACKEND_STATUS_READY,
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-statusErr; err != nil {
		t.Fatal(err)
	}
	if status := <-statusResult; status != knowledge.BackendReady {
		t.Fatalf("status=%q", status)
	}
}

func chunkFixture(deploymentID string) knowledge.AttachmentChunk {
	content := []byte("knowledge chunk")
	config := configFixture(deploymentID)
	return knowledge.AttachmentChunk{
		OwnerID: config.OwnerID, BindingID: config.BindingID, SourceID: uuid.NewString(), UploadID: uuid.NewString(),
		MediaType: "text/plain", DeclaredSizeBytes: int64(len(content)), OffsetBytes: 0, ChunkOrdinal: 0,
		Chunk: content, ChunkSHA256: knowledge.SHA256(content), Title: "fixture", Binding: config.Spec,
	}
}

func memoryFixture(deploymentID string) knowledge.MemoryContent {
	content := []byte("durable knowledge memory")
	config := configFixture(deploymentID)
	return knowledge.MemoryContent{
		OwnerID: config.OwnerID, BindingID: config.BindingID, SourceID: uuid.NewString(), Content: content,
		ContentSHA256: knowledge.SHA256(content), Title: "fixture", Binding: config.Spec,
	}
}

func configFixture(deploymentID string) knowledge.Config {
	return knowledge.Config{
		OwnerID: "owner-knowledge", BindingID: uuid.NewString(), Revision: 1,
		Spec: knowledge.ConfigSpec{DeploymentID: deploymentID, ManagedServiceID: uuid.NewString(), RecipeDigest: knowledge.SHA256([]byte("recipe")), EmbeddingProfileID: knowledge.LocalMultilingualE5SmallProfileID, Enabled: true},
	}
}
