package knowledgeadapter

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type pipeDialer struct {
	handle  func([]byte) ([]byte, error)
	request chan []byte
}

func (dialer *pipeDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	if network != "unix" || address != DefaultSocketPath || dialer == nil || dialer.handle == nil {
		return nil, errors.New("unexpected adapter dial")
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		request, err := readFrame(server, maximumRequestBytes)
		if err != nil {
			return
		}
		if dialer.request != nil {
			dialer.request <- append([]byte(nil), request...)
		}
		response, err := dialer.handle(request)
		clear(request)
		if err == nil {
			_ = writeFrame(server, response)
		}
		clear(response)
	}()
	return client, nil
}

func TestClientStoreMemoryUsesStableFencesAndValidatesReceipt(t *testing.T) {
	operation := memoryOperationFixture()
	dialer := &pipeDialer{request: make(chan []byte, 1)}
	dialer.handle = func(payload []byte) ([]byte, error) {
		var request struct {
			Version        int             `json:"version"`
			OperationID    string          `json:"operation_id"`
			IdempotencyKey string          `json:"idempotency_key"`
			Operation      string          `json:"operation"`
			Body           storeMemoryBody `json:"body"`
		}
		if err := decodeExact(payload, &request); err != nil {
			return nil, err
		}
		if request.Version != 1 || request.Operation != "store_memory" || request.IdempotencyKey != operation.GetOperationId() || request.Body.Content != string(operation.GetStoreMemory().GetContent()) || request.Body.ContentSHA256 != "f04db5fccd3f5d39d88d4224d314f167404bc99210e43b68e02a5a66495ee306" {
			return nil, ErrInvalid
		}
		result, _ := json.Marshal(memoryResult{
			OwnerID: request.Body.OwnerID, BindingID: request.Body.BindingID, PointID: uuid.NewString(),
			SourceID: request.Body.MemoryID, RevisionID: request.Body.RevisionID, Kind: "memory",
			ContentSize: request.Body.ContentSize, ContentSHA256: request.Body.ContentSHA256, IndexedSegmentCount: 1,
		})
		return json.Marshal(responseEnvelope{Version: 1, OperationID: request.OperationID, OK: true, Result: result})
	}
	client, err := newClient(dialer)
	if err != nil {
		t.Fatal(err)
	}
	result := client.Execute(context.Background(), operation)
	if result.GetErrorCode() != "" || !result.GetAcknowledged() || result.GetSizeBytes() != 17 || result.GetContentSha256() != "sha256:f04db5fccd3f5d39d88d4224d314f167404bc99210e43b68e02a5a66495ee306" || !canonicalUUID(result.GetPointId()) || result.GetIndexedSegmentCount() != 1 {
		t.Fatalf("result=%+v", result)
	}
	if len(operation.GetStoreMemory().GetContent()) != 0 {
		t.Fatal("relay memory was not wiped after the local call")
	}
	request := <-dialer.request
	defer clear(request)
	if string(request) == "" {
		t.Fatal("adapter request was not framed")
	}
}

func TestClientSearchReturnsOnlyFencedIdentifiersAndClearsText(t *testing.T) {
	operation := operationFixture()
	operation.Request = &agentv1.KnowledgeWorkerOperation_Search{Search: &agentv1.KnowledgeWorkerSearch{Query: "cedar semantic probe", Limit: 2}}
	sourceID := uuid.NewString()
	dialer := &pipeDialer{}
	dialer.handle = func(payload []byte) ([]byte, error) {
		var request struct {
			Version     int        `json:"version"`
			OperationID string     `json:"operation_id"`
			Operation   string     `json:"operation"`
			Body        searchBody `json:"body"`
		}
		if err := decodeExact(payload, &request); err != nil || request.Operation != "search" || request.Body.Query != "cedar semantic probe" {
			return nil, ErrInvalid
		}
		result, _ := json.Marshal(searchResult{Results: []searchMatch{{
			PointID: uuid.NewString(), OwnerID: request.Body.OwnerID, BindingID: request.Body.BindingID, SourceID: sourceID,
			RevisionID: derivedUUID("revision", request.Body.OwnerID, request.Body.BindingID, sourceID), Kind: "memory",
			Content: "private intended search excerpt", Score: 0.92, ContentSize: 31,
			ContentSHA256: "5de258b8660b238d8eacb9de8d6f5b80bb4d7ecb8f5896f8c515199fe3b9203b",
		}}})
		return json.Marshal(responseEnvelope{Version: 1, OperationID: request.OperationID, OK: true, Result: result})
	}
	client, _ := newClient(dialer)
	result := client.Execute(context.Background(), operation)
	if result.GetErrorCode() != "" || len(result.GetMatches()) != 1 || result.GetMatches()[0].GetSourceId() != sourceID || result.GetMatches()[0].GetChunkRef() == "chunk:"+sourceID || result.GetMatches()[0].GetScore() != 0.92 {
		t.Fatalf("result=%+v", result)
	}
	if operation.GetSearch().GetQuery() != "" {
		t.Fatal("relay query was not cleared")
	}
}

func TestClientStatusRequiresPinnedRuntimeAndPersistenceEvidence(t *testing.T) {
	sourceID := uuid.NewString()
	pointID := uuid.NewString()
	digest := "sha256:5de258b8660b238d8eacb9de8d6f5b80bb4d7ecb8f5896f8c515199fe3b9203b"
	operation := operationFixture()
	operation.Request = &agentv1.KnowledgeWorkerOperation_Status{Status: &agentv1.KnowledgeWorkerStatus{PointId: pointID, SourceId: sourceID, ContentSize: 18, ContentSha256: digest}}
	dialer := &pipeDialer{}
	dialer.handle = func(payload []byte) ([]byte, error) {
		var request struct {
			Version     int        `json:"version"`
			OperationID string     `json:"operation_id"`
			Operation   string     `json:"operation"`
			Body        statusBody `json:"body"`
		}
		if err := decodeExact(payload, &request); err != nil || request.Operation != "status" || request.Body.Challenge == nil {
			return nil, ErrInvalid
		}
		result, _ := json.Marshal(statusResult{
			OwnerID: request.Body.OwnerID, BindingID: request.Body.BindingID, Model: expectedModel,
			ModelRevision: expectedModelRevision, Dimensions: expectedDimensions, ExecutionProvider: expectedProvider,
			Collection: expectedCollection, Status: "green", Ready: true,
			Persistence: &statusPersistence{PointID: pointID, SourceID: sourceID, RevisionID: request.Body.Challenge.RevisionID, ContentSize: 18, ContentSHA256: request.Body.Challenge.ContentSHA256, Verified: true},
		})
		return json.Marshal(responseEnvelope{Version: 1, OperationID: request.OperationID, OK: true, Result: result})
	}
	client, _ := newClient(dialer)
	result := client.Execute(context.Background(), operation)
	if result.GetErrorCode() != "" || result.GetBackendStatus() != agentv1.KnowledgeWorkerBackendStatus_KNOWLEDGE_WORKER_BACKEND_STATUS_READY {
		t.Fatalf("result=%+v", result)
	}
}

func TestClientMapsOnlyClosedAdapterErrors(t *testing.T) {
	operation := operationFixture()
	operation.Request = &agentv1.KnowledgeWorkerOperation_DeleteSource{DeleteSource: &agentv1.KnowledgeWorkerDeleteSource{SourceId: uuid.NewString()}}
	dialer := &pipeDialer{handle: func(payload []byte) ([]byte, error) {
		var request requestEnvelope
		if err := decodeExact(payload, &request); err != nil {
			return nil, err
		}
		return json.Marshal(responseEnvelope{Version: 1, OperationID: request.OperationID, Error: &adapterError{Code: "dependency_unavailable", Field: "qdrant"}})
	}}
	client, _ := newClient(dialer)
	if result := client.Execute(context.Background(), operation); result.GetErrorCode() != "adapter_unavailable" || result.GetAcknowledged() {
		t.Fatalf("result=%+v", result)
	}
}

func TestRequestForOperationRejectsUntrustedKnowledgeMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*agentv1.KnowledgeWorkerOperation)
	}{
		{name: "memory title", mutate: func(value *agentv1.KnowledgeWorkerOperation) { value.GetStoreMemory().Title = "bad\nmetadata" }},
		{name: "attachment media", mutate: func(value *agentv1.KnowledgeWorkerOperation) {
			content := []byte("attachment")
			value.Request = &agentv1.KnowledgeWorkerOperation_StageChunk{StageChunk: &agentv1.KnowledgeWorkerStageChunk{
				SourceId: uuid.NewString(), UploadId: uuid.NewString(), MediaType: "text/html", Title: "fixture", DeclaredSizeBytes: int64(len(content)), Chunk: content, ChunkSha256: prefixedSHA256(content),
			}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operation := memoryOperationFixture()
			test.mutate(operation)
			if _, err := requestForOperation(operation); !errors.Is(err, ErrInvalid) {
				t.Fatalf("request error = %v", err)
			}
		})
	}
}

func memoryOperationFixture() *agentv1.KnowledgeWorkerOperation {
	content := []byte("persistent memory")
	operation := operationFixture()
	operation.Request = &agentv1.KnowledgeWorkerOperation_StoreMemory{StoreMemory: &agentv1.KnowledgeWorkerStoreMemory{
		SourceId: uuid.NewString(), Content: content, ContentSha256: prefixedSHA256(content), Title: "fixture",
	}}
	return operation
}

func operationFixture() *agentv1.KnowledgeWorkerOperation {
	return &agentv1.KnowledgeWorkerOperation{
		OperationId: uuid.NewString(), LeaseId: uuid.NewString(), LeaseExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
		Binding: &agentv1.KnowledgeWorkerBinding{
			OwnerId: "owner:knowledge", BindingId: uuid.NewString(), DeploymentId: uuid.NewString(), ManagedServiceId: uuid.NewString(),
			RecipeDigest: "sha256:5de258b8660b238d8eacb9de8d6f5b80bb4d7ecb8f5896f8c515199fe3b9203b", EmbeddingProfileId: "local-multilingual-e5-small-v1",
		},
	}
}
