package knowledgeadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/google/uuid"
)

const (
	DefaultSocketPath       = "/run/dirextalk-knowledge/adapter.sock"
	protocolVersion         = 1
	maximumRequestBytes     = 8 << 20
	maximumResponseBytes    = 1 << 20
	expectedModel           = "intfloat/multilingual-e5-small"
	expectedModelRevision   = "0e60b8d9d2166d80387f86e3b48ec9ced55f4d15"
	expectedCollection      = "dirextalk_knowledge_v1"
	expectedProvider        = "CPUExecutionProvider"
	expectedDimensions      = 384
	maximumSearchTextBytes  = 16 << 10
	maximumAttachmentBytes  = 64 << 20
	maximumMemoryBytes      = 1 << 20
	maximumAdapterErrorCode = 64
)

var (
	ErrInvalid   = errors.New("knowledge adapter relay request is invalid")
	ErrTransport = errors.New("knowledge adapter socket is unavailable")
	fieldPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	adapterIDNS  = uuid.MustParse("70b13468-659b-5f2f-a80b-39258cb5d63e")
)

type socketDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// Client translates the authenticated, closed Worker operation union onto the
// fixed local adapter socket. It never accepts a runtime-selected path, URL,
// model, provider, collection, credential, or command.
type Client struct {
	dialer socketDialer
}

func NewClient() *Client { return &Client{dialer: &net.Dialer{}} }

func newClient(dialer socketDialer) (*Client, error) {
	if dialer == nil {
		return nil, ErrInvalid
	}
	return &Client{dialer: dialer}, nil
}

type requestEnvelope struct {
	Version        int    `json:"version"`
	OperationID    string `json:"operation_id"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	Operation      string `json:"operation"`
	Body           any    `json:"body"`
}

type responseEnvelope struct {
	Version     int             `json:"version"`
	OperationID string          `json:"operation_id"`
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result,omitempty"`
	Error       *adapterError   `json:"error,omitempty"`
}

type adapterError struct {
	Code  string `json:"code"`
	Field string `json:"field"`
}

func (client *Client) Execute(ctx context.Context, operation *agentv1.KnowledgeWorkerOperation) *agentv1.KnowledgeWorkerResult {
	defer clearOperation(operation)
	request, err := requestForOperation(operation)
	if err != nil {
		return failedResult("internal")
	}
	defer clearRequest(request)

	response, err := client.call(ctx, operation, request)
	if err != nil {
		if errors.Is(err, ErrTransport) {
			return failedResult("adapter_unavailable")
		}
		return failedResult("internal")
	}
	if !response.OK {
		return failedResult(relayErrorCode(response.Error))
	}
	result, err := resultForOperation(operation, response.Result)
	if err != nil {
		return failedResult("internal")
	}
	return result
}

func (client *Client) call(ctx context.Context, operation *agentv1.KnowledgeWorkerOperation, request requestEnvelope) (responseEnvelope, error) {
	if client == nil || client.dialer == nil || ctx == nil || operation == nil {
		return responseEnvelope{}, ErrInvalid
	}
	payload, err := json.Marshal(request)
	if err != nil || len(payload) == 0 || len(payload) > maximumRequestBytes {
		clear(payload)
		return responseEnvelope{}, ErrInvalid
	}
	defer clear(payload)
	connection, err := client.dialer.DialContext(ctx, "unix", DefaultSocketPath)
	if err != nil {
		return responseEnvelope{}, ErrTransport
	}
	defer connection.Close()
	deadline := time.Now().Add(time.Minute)
	if expires := operation.GetLeaseExpiresAt(); expires != nil && expires.IsValid() && expires.AsTime().Before(deadline) {
		deadline = expires.AsTime()
	}
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if !deadline.After(time.Now()) || connection.SetDeadline(deadline) != nil {
		return responseEnvelope{}, ErrTransport
	}
	if err := writeFrame(connection, payload); err != nil {
		return responseEnvelope{}, ErrTransport
	}
	encoded, err := readFrame(connection, maximumResponseBytes)
	if err != nil {
		return responseEnvelope{}, ErrTransport
	}
	defer clear(encoded)
	var response responseEnvelope
	if decodeExact(encoded, &response) != nil || response.Version != protocolVersion || response.OperationID != request.OperationID {
		return responseEnvelope{}, ErrInvalid
	}
	if response.OK {
		if response.Error != nil || len(response.Result) == 0 || bytes.Equal(response.Result, []byte("null")) {
			return responseEnvelope{}, ErrInvalid
		}
	} else if len(response.Result) != 0 || response.Error == nil || !validAdapterError(*response.Error) {
		return responseEnvelope{}, ErrInvalid
	}
	return response, nil
}

func requestForOperation(operation *agentv1.KnowledgeWorkerOperation) (requestEnvelope, error) {
	if operation == nil || !canonicalUUID(operation.GetOperationId()) || !canonicalUUID(operation.GetLeaseId()) || operation.GetLeaseExpiresAt() == nil || !operation.GetLeaseExpiresAt().IsValid() {
		return requestEnvelope{}, ErrInvalid
	}
	binding := operation.GetBinding()
	if binding == nil || !validOwner(binding.GetOwnerId()) || !canonicalUUID(binding.GetBindingId()) || !canonicalUUID(binding.GetDeploymentId()) || !canonicalUUID(binding.GetManagedServiceId()) ||
		!validSHA256Prefixed(binding.GetRecipeDigest()) || binding.GetEmbeddingProfileId() != "local-multilingual-e5-small-v1" {
		return requestEnvelope{}, ErrInvalid
	}
	request := requestEnvelope{Version: protocolVersion, OperationID: operation.GetOperationId()}
	revision := func(sourceID string) string {
		return derivedUUID("revision", binding.GetOwnerId(), binding.GetBindingId(), sourceID)
	}
	switch value := operation.GetRequest().(type) {
	case *agentv1.KnowledgeWorkerOperation_StageChunk:
		chunk := value.StageChunk
		if chunk == nil || !canonicalUUID(chunk.GetSourceId()) || !canonicalUUID(chunk.GetUploadId()) || !validMediaType(chunk.GetMediaType()) || !validTitle(chunk.GetTitle()) || len(chunk.GetChunk()) == 0 || len(chunk.GetChunk()) > 256<<10 ||
			chunk.GetDeclaredSizeBytes() < 1 || chunk.GetDeclaredSizeBytes() > maximumAttachmentBytes || chunk.GetOffsetBytes() < 0 ||
			chunk.GetOffsetBytes() > chunk.GetDeclaredSizeBytes()-int64(len(chunk.GetChunk())) || chunk.GetChunkOrdinal() < 0 || chunk.GetChunkOrdinal() >= 256 ||
			!validSHA256Prefixed(chunk.GetChunkSha256()) || prefixedSHA256(chunk.GetChunk()) != chunk.GetChunkSha256() {
			return requestEnvelope{}, ErrInvalid
		}
		request.Operation, request.IdempotencyKey = "stage_chunk", operation.GetOperationId()
		request.Body = &stageChunkBody{
			OwnerID: binding.GetOwnerId(), BindingID: binding.GetBindingId(), SourceID: chunk.GetSourceId(), UploadID: chunk.GetUploadId(),
			ChunkID:    derivedUUID("chunk", binding.GetOwnerId(), binding.GetBindingId(), chunk.GetSourceId(), chunk.GetUploadId(), strconv.FormatInt(int64(chunk.GetChunkOrdinal()), 10)),
			RevisionID: revision(chunk.GetSourceId()), OffsetBytes: chunk.GetOffsetBytes(), ChunkIndex: chunk.GetChunkOrdinal(),
			DeclaredSizeBytes: chunk.GetDeclaredSizeBytes(), ContentBase64: base64.StdEncoding.EncodeToString(chunk.GetChunk()),
			ContentSize: len(chunk.GetChunk()), ContentSHA256: strings.TrimPrefix(chunk.GetChunkSha256(), "sha256:"),
		}
	case *agentv1.KnowledgeWorkerOperation_CommitAttachment:
		commit := value.CommitAttachment
		if commit == nil || !canonicalUUID(commit.GetSourceId()) || !canonicalUUID(commit.GetUploadId()) || !validMediaType(commit.GetMediaType()) ||
			commit.GetDeclaredSizeBytes() < 1 || commit.GetDeclaredSizeBytes() > maximumAttachmentBytes || commit.GetChunkCount() < 1 || commit.GetChunkCount() > 256 ||
			!validTitle(commit.GetTitle()) || !validSHA256Prefixed(commit.GetContentSha256()) {
			return requestEnvelope{}, ErrInvalid
		}
		request.Operation, request.IdempotencyKey = "commit_attachment", operation.GetOperationId()
		request.Body = commitAttachmentBody{OwnerID: binding.GetOwnerId(), BindingID: binding.GetBindingId(), SourceID: commit.GetSourceId(), UploadID: commit.GetUploadId(), RevisionID: revision(commit.GetSourceId()), Title: commit.GetTitle(), MediaType: commit.GetMediaType(), ChunkCount: commit.GetChunkCount(), ContentSize: commit.GetDeclaredSizeBytes(), ContentSHA256: strings.TrimPrefix(commit.GetContentSha256(), "sha256:")}
	case *agentv1.KnowledgeWorkerOperation_StoreMemory:
		memory := value.StoreMemory
		if memory == nil || !canonicalUUID(memory.GetSourceId()) || !validTitle(memory.GetTitle()) || len(memory.GetContent()) == 0 || len(memory.GetContent()) > maximumMemoryBytes || !utf8.Valid(memory.GetContent()) || !validSHA256Prefixed(memory.GetContentSha256()) || prefixedSHA256(memory.GetContent()) != memory.GetContentSha256() {
			return requestEnvelope{}, ErrInvalid
		}
		request.Operation, request.IdempotencyKey = "store_memory", operation.GetOperationId()
		request.Body = &storeMemoryBody{OwnerID: binding.GetOwnerId(), BindingID: binding.GetBindingId(), MemoryID: memory.GetSourceId(), RevisionID: revision(memory.GetSourceId()), Content: string(memory.GetContent()), ContentSize: len(memory.GetContent()), ContentSHA256: strings.TrimPrefix(memory.GetContentSha256(), "sha256:")}
	case *agentv1.KnowledgeWorkerOperation_DeleteSource:
		deleted := value.DeleteSource
		if deleted == nil || !canonicalUUID(deleted.GetSourceId()) {
			return requestEnvelope{}, ErrInvalid
		}
		request.Operation, request.IdempotencyKey = "delete", operation.GetOperationId()
		request.Body = deleteBody{OwnerID: binding.GetOwnerId(), BindingID: binding.GetBindingId(), SourceID: deleted.GetSourceId(), RevisionID: revision(deleted.GetSourceId())}
	case *agentv1.KnowledgeWorkerOperation_Search:
		search := value.Search
		if search == nil || search.GetQuery() == "" || !utf8.ValidString(search.GetQuery()) || strings.ContainsRune(search.GetQuery(), '\x00') || len([]byte(search.GetQuery())) > 16<<10 || search.GetLimit() < 1 || search.GetLimit() > 50 || len(search.GetSourceIds()) > 50 {
			return requestEnvelope{}, ErrInvalid
		}
		seenSources := make(map[string]struct{}, len(search.GetSourceIds()))
		for _, sourceID := range search.GetSourceIds() {
			if !canonicalUUID(sourceID) {
				return requestEnvelope{}, ErrInvalid
			}
			if _, duplicate := seenSources[sourceID]; duplicate {
				return requestEnvelope{}, ErrInvalid
			}
			seenSources[sourceID] = struct{}{}
		}
		request.Operation = "search"
		request.Body = &searchBody{OwnerID: binding.GetOwnerId(), BindingID: binding.GetBindingId(), Query: search.GetQuery(), Limit: search.GetLimit(), SourceIDs: append([]string(nil), search.GetSourceIds()...)}
	case *agentv1.KnowledgeWorkerOperation_Status:
		status := value.Status
		if status == nil {
			return requestEnvelope{}, ErrInvalid
		}
		body := statusBody{OwnerID: binding.GetOwnerId(), BindingID: binding.GetBindingId()}
		if status.GetSourceId() != "" {
			if !canonicalUUID(status.GetSourceId()) || status.GetContentSize() < 1 || status.GetContentSize() > maximumAttachmentBytes || !validSHA256Prefixed(status.GetContentSha256()) {
				return requestEnvelope{}, ErrInvalid
			}
			if !canonicalUUID(status.GetPointId()) {
				return requestEnvelope{}, ErrInvalid
			}
			body.Challenge = &statusChallenge{PointID: status.GetPointId(), SourceID: status.GetSourceId(), RevisionID: revision(status.GetSourceId()), ContentSize: status.GetContentSize(), ContentSHA256: strings.TrimPrefix(status.GetContentSha256(), "sha256:")}
		} else if status.GetContentSize() != 0 || status.GetContentSha256() != "" {
			return requestEnvelope{}, ErrInvalid
		}
		request.Operation, request.Body = "status", body
	default:
		return requestEnvelope{}, ErrInvalid
	}
	return request, nil
}

type stageChunkBody struct {
	OwnerID           string `json:"owner_id"`
	BindingID         string `json:"binding_id"`
	SourceID          string `json:"source_id"`
	UploadID          string `json:"upload_id"`
	ChunkID           string `json:"chunk_id"`
	RevisionID        string `json:"revision_id"`
	OffsetBytes       int64  `json:"offset_bytes"`
	ChunkIndex        int32  `json:"chunk_index"`
	DeclaredSizeBytes int64  `json:"declared_size_bytes"`
	ContentBase64     string `json:"content_base64"`
	ContentSize       int    `json:"content_size"`
	ContentSHA256     string `json:"content_sha256"`
}
type commitAttachmentBody struct {
	OwnerID       string `json:"owner_id"`
	BindingID     string `json:"binding_id"`
	SourceID      string `json:"source_id"`
	UploadID      string `json:"upload_id"`
	RevisionID    string `json:"revision_id"`
	Title         string `json:"title"`
	MediaType     string `json:"media_type"`
	ChunkCount    int32  `json:"chunk_count"`
	ContentSize   int64  `json:"content_size"`
	ContentSHA256 string `json:"content_sha256"`
}
type storeMemoryBody struct {
	OwnerID       string `json:"owner_id"`
	BindingID     string `json:"binding_id"`
	MemoryID      string `json:"memory_id"`
	RevisionID    string `json:"revision_id"`
	Content       string `json:"content"`
	ContentSize   int    `json:"content_size"`
	ContentSHA256 string `json:"content_sha256"`
}
type deleteBody struct {
	OwnerID    string `json:"owner_id"`
	BindingID  string `json:"binding_id"`
	SourceID   string `json:"source_id"`
	RevisionID string `json:"revision_id"`
}
type searchBody struct {
	OwnerID   string   `json:"owner_id"`
	BindingID string   `json:"binding_id"`
	Query     string   `json:"query"`
	Limit     int32    `json:"limit"`
	SourceIDs []string `json:"source_ids,omitempty"`
}
type statusBody struct {
	OwnerID   string           `json:"owner_id"`
	BindingID string           `json:"binding_id"`
	Challenge *statusChallenge `json:"challenge,omitempty"`
}
type statusChallenge struct {
	PointID       string `json:"point_id"`
	SourceID      string `json:"source_id"`
	RevisionID    string `json:"revision_id"`
	ContentSize   int64  `json:"content_size"`
	ContentSHA256 string `json:"content_sha256"`
}

func resultForOperation(operation *agentv1.KnowledgeWorkerOperation, raw json.RawMessage) (*agentv1.KnowledgeWorkerResult, error) {
	binding := operation.GetBinding()
	revision := func(sourceID string) string {
		return derivedUUID("revision", binding.GetOwnerId(), binding.GetBindingId(), sourceID)
	}
	switch value := operation.GetRequest().(type) {
	case *agentv1.KnowledgeWorkerOperation_StageChunk:
		var result stageResult
		if decodeExact(raw, &result) != nil || result.OwnerID != binding.GetOwnerId() || result.BindingID != binding.GetBindingId() || result.SourceID != value.StageChunk.GetSourceId() || result.UploadID != value.StageChunk.GetUploadId() || result.RevisionID != revision(result.SourceID) || !result.Staged || result.OffsetBytes != value.StageChunk.GetOffsetBytes() || result.ChunkIndex != value.StageChunk.GetChunkOrdinal() || result.DeclaredSizeBytes != value.StageChunk.GetDeclaredSizeBytes() || result.ContentSize != len(value.StageChunk.GetChunk()) || result.ContentSHA256 != strings.TrimPrefix(value.StageChunk.GetChunkSha256(), "sha256:") || result.ChunkID != derivedUUID("chunk", result.OwnerID, result.BindingID, result.SourceID, result.UploadID, strconv.FormatInt(int64(result.ChunkIndex), 10)) {
			return nil, ErrInvalid
		}
		return &agentv1.KnowledgeWorkerResult{Acknowledged: true}, nil
	case *agentv1.KnowledgeWorkerOperation_CommitAttachment:
		var result commitResult
		commit := value.CommitAttachment
		if decodeExact(raw, &result) != nil || result.OwnerID != binding.GetOwnerId() || result.BindingID != binding.GetBindingId() || !canonicalUUID(result.PointID) || result.PointID == result.SourceID || result.SourceID != commit.GetSourceId() || result.UploadID != commit.GetUploadId() || result.RevisionID != revision(result.SourceID) || result.Kind != "attachment" || result.ChunkCount != commit.GetChunkCount() || result.ContentSize != commit.GetDeclaredSizeBytes() || result.ContentSHA256 != strings.TrimPrefix(commit.GetContentSha256(), "sha256:") || result.IndexedSegmentCount < 1 || result.IndexedSegmentCount > 32769 {
			return nil, ErrInvalid
		}
		return &agentv1.KnowledgeWorkerResult{Acknowledged: true, SizeBytes: result.ContentSize, ContentSha256: "sha256:" + result.ContentSHA256, PointId: result.PointID, IndexedSegmentCount: result.IndexedSegmentCount}, nil
	case *agentv1.KnowledgeWorkerOperation_StoreMemory:
		var result memoryResult
		memory := value.StoreMemory
		if decodeExact(raw, &result) != nil || result.OwnerID != binding.GetOwnerId() || result.BindingID != binding.GetBindingId() || !canonicalUUID(result.PointID) || result.PointID == result.SourceID || result.SourceID != memory.GetSourceId() || result.RevisionID != revision(result.SourceID) || result.Kind != "memory" || result.ContentSize != len(memory.GetContent()) || result.ContentSHA256 != strings.TrimPrefix(memory.GetContentSha256(), "sha256:") || result.IndexedSegmentCount < 1 || result.IndexedSegmentCount > 512 {
			return nil, ErrInvalid
		}
		return &agentv1.KnowledgeWorkerResult{Acknowledged: true, SizeBytes: int64(result.ContentSize), ContentSha256: "sha256:" + result.ContentSHA256, PointId: result.PointID, IndexedSegmentCount: result.IndexedSegmentCount}, nil
	case *agentv1.KnowledgeWorkerOperation_DeleteSource:
		var result deleteResult
		deleted := value.DeleteSource
		if decodeExact(raw, &result) != nil || result.OwnerID != binding.GetOwnerId() || result.BindingID != binding.GetBindingId() || result.SourceID != deleted.GetSourceId() || result.RevisionID != revision(result.SourceID) || !result.Deleted {
			return nil, ErrInvalid
		}
		return &agentv1.KnowledgeWorkerResult{Acknowledged: true}, nil
	case *agentv1.KnowledgeWorkerOperation_Search:
		var result searchResult
		if decodeExact(raw, &result) != nil || len(result.Results) > int(value.Search.GetLimit()) {
			clearSearchResult(&result)
			return nil, ErrInvalid
		}
		matches := make([]*agentv1.KnowledgeWorkerSearchMatch, 0, len(result.Results))
		for index := range result.Results {
			match := &result.Results[index]
			if match.OwnerID != binding.GetOwnerId() || match.BindingID != binding.GetBindingId() || !canonicalUUID(match.PointID) || !canonicalUUID(match.SourceID) || match.RevisionID != revision(match.SourceID) || (match.Kind != "attachment" && match.Kind != "memory") || !utf8.ValidString(match.Content) || len([]byte(match.Content)) > maximumSearchTextBytes || math.IsNaN(match.Score) || math.IsInf(match.Score, 0) || match.Score < 0 || match.Score > 1 || match.ContentSize < 1 || match.ContentSize > maximumAttachmentBytes || !validSHA256Hex(match.ContentSHA256) {
				clearSearchResult(&result)
				return nil, ErrInvalid
			}
			matches = append(matches, &agentv1.KnowledgeWorkerSearchMatch{SourceId: match.SourceID, ChunkRef: "chunk:" + match.PointID, Score: match.Score})
		}
		clearSearchResult(&result)
		return &agentv1.KnowledgeWorkerResult{Acknowledged: true, Matches: matches}, nil
	case *agentv1.KnowledgeWorkerOperation_Status:
		var result statusResult
		if decodeExact(raw, &result) != nil || result.OwnerID != binding.GetOwnerId() || result.BindingID != binding.GetBindingId() || !result.Ready || result.Model != expectedModel || result.ModelRevision != expectedModelRevision || result.Dimensions != expectedDimensions || result.ExecutionProvider != expectedProvider || result.Collection != expectedCollection {
			return nil, ErrInvalid
		}
		if status := value.Status; status.GetSourceId() != "" {
			if result.Persistence == nil || result.Persistence.PointID != status.GetPointId() || result.Persistence.SourceID != status.GetSourceId() || result.Persistence.RevisionID != revision(status.GetSourceId()) || result.Persistence.ContentSize != status.GetContentSize() || result.Persistence.ContentSHA256 != strings.TrimPrefix(status.GetContentSha256(), "sha256:") || !result.Persistence.Verified {
				return nil, ErrInvalid
			}
		} else if result.Persistence != nil {
			return nil, ErrInvalid
		}
		backend := agentv1.KnowledgeWorkerBackendStatus_KNOWLEDGE_WORKER_BACKEND_STATUS_UNAVAILABLE
		switch result.Status {
		case "green":
			backend = agentv1.KnowledgeWorkerBackendStatus_KNOWLEDGE_WORKER_BACKEND_STATUS_READY
		case "yellow":
			backend = agentv1.KnowledgeWorkerBackendStatus_KNOWLEDGE_WORKER_BACKEND_STATUS_DEGRADED
		case "red", "grey":
		default:
			return nil, ErrInvalid
		}
		return &agentv1.KnowledgeWorkerResult{Acknowledged: true, BackendStatus: backend}, nil
	default:
		return nil, ErrInvalid
	}
}

type stageResult struct {
	OwnerID           string `json:"owner_id"`
	BindingID         string `json:"binding_id"`
	SourceID          string `json:"source_id"`
	UploadID          string `json:"upload_id"`
	ChunkID           string `json:"chunk_id"`
	RevisionID        string `json:"revision_id"`
	OffsetBytes       int64  `json:"offset_bytes"`
	ChunkIndex        int32  `json:"chunk_index"`
	DeclaredSizeBytes int64  `json:"declared_size_bytes"`
	ContentSize       int    `json:"content_size"`
	ContentSHA256     string `json:"content_sha256"`
	Staged            bool   `json:"staged"`
}
type commitResult struct {
	OwnerID             string `json:"owner_id"`
	BindingID           string `json:"binding_id"`
	PointID             string `json:"point_id"`
	SourceID            string `json:"source_id"`
	UploadID            string `json:"upload_id"`
	RevisionID          string `json:"revision_id"`
	Kind                string `json:"kind"`
	ChunkCount          int32  `json:"chunk_count"`
	ContentSize         int64  `json:"content_size"`
	ContentSHA256       string `json:"content_sha256"`
	IndexedSegmentCount int32  `json:"indexed_segment_count"`
}
type memoryResult struct {
	OwnerID             string `json:"owner_id"`
	BindingID           string `json:"binding_id"`
	PointID             string `json:"point_id"`
	SourceID            string `json:"source_id"`
	RevisionID          string `json:"revision_id"`
	Kind                string `json:"kind"`
	ContentSize         int    `json:"content_size"`
	ContentSHA256       string `json:"content_sha256"`
	IndexedSegmentCount int32  `json:"indexed_segment_count"`
}
type deleteResult struct {
	OwnerID    string `json:"owner_id"`
	BindingID  string `json:"binding_id"`
	SourceID   string `json:"source_id"`
	RevisionID string `json:"revision_id"`
	Deleted    bool   `json:"deleted"`
}
type searchResult struct {
	Results []searchMatch `json:"results"`
}
type searchMatch struct {
	PointID          string  `json:"point_id"`
	OwnerID          string  `json:"owner_id"`
	BindingID        string  `json:"binding_id"`
	SourceID         string  `json:"source_id"`
	RevisionID       string  `json:"revision_id"`
	Kind             string  `json:"kind"`
	Content          string  `json:"content"`
	ContentTruncated bool    `json:"content_truncated"`
	Score            float64 `json:"score"`
	ContentSize      int64   `json:"content_size"`
	ContentSHA256    string  `json:"content_sha256"`
}
type statusResult struct {
	OwnerID           string             `json:"owner_id"`
	BindingID         string             `json:"binding_id"`
	Model             string             `json:"model"`
	ModelRevision     string             `json:"model_revision"`
	Dimensions        int                `json:"dimensions"`
	ExecutionProvider string             `json:"execution_provider"`
	Collection        string             `json:"collection"`
	Status            string             `json:"status"`
	Ready             bool               `json:"ready"`
	Persistence       *statusPersistence `json:"persistence,omitempty"`
}
type statusPersistence struct {
	PointID       string `json:"point_id"`
	SourceID      string `json:"source_id"`
	RevisionID    string `json:"revision_id"`
	ContentSize   int64  `json:"content_size"`
	ContentSHA256 string `json:"content_sha256"`
	Verified      bool   `json:"verified"`
}

func relayErrorCode(value *adapterError) string {
	if value == nil {
		return "internal"
	}
	switch value.Code {
	case "dependency_unavailable":
		return "adapter_unavailable"
	case "idempotency_conflict", "persistence_mismatch":
		return "conflict"
	case "invalid_content":
		return "invalid_content"
	default:
		return "internal"
	}
}

func failedResult(code string) *agentv1.KnowledgeWorkerResult {
	return &agentv1.KnowledgeWorkerResult{ErrorCode: code}
}

func validAdapterError(value adapterError) bool {
	if len(value.Code) == 0 || len(value.Code) > maximumAdapterErrorCode || !fieldPattern.MatchString(value.Field) {
		return false
	}
	switch value.Code {
	case "invalid_request", "idempotency_conflict", "invalid_content", "dependency_unavailable", "persistence_mismatch", "unauthorized", "internal_error":
		return true
	default:
		return false
	}
}

func decodeExact(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func writeFrame(writer io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > maximumRequestBytes {
		return ErrInvalid
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := io.Copy(writer, bytes.NewReader(payload))
	return err
}

func readFrame(reader io.Reader, maximum uint32) ([]byte, error) {
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil || size == 0 || size > maximum {
		return nil, ErrTransport
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		clear(payload)
		return nil, ErrTransport
	}
	return payload, nil
}

func clearRequest(value requestEnvelope) {
	switch body := value.Body.(type) {
	case *stageChunkBody:
		body.ContentBase64 = ""
	case *storeMemoryBody:
		body.Content = ""
	case *searchBody:
		body.Query = ""
	}
}

func clearOperation(value *agentv1.KnowledgeWorkerOperation) {
	if value == nil {
		return
	}
	if chunk := value.GetStageChunk(); chunk != nil {
		clear(chunk.Chunk)
		chunk.Chunk = nil
	}
	if memory := value.GetStoreMemory(); memory != nil {
		clear(memory.Content)
		memory.Content = nil
	}
	if search := value.GetSearch(); search != nil {
		search.Query = ""
	}
}

func clearSearchResult(value *searchResult) {
	if value == nil {
		return
	}
	for index := range value.Results {
		value.Results[index].Content = ""
	}
	value.Results = nil
}

func derivedUUID(kind string, parts ...string) string {
	joined := kind + "\x00" + strings.Join(parts, "\x00")
	return uuid.NewSHA1(adapterIDNS, []byte(joined)).String()
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}
func validOwner(value string) bool {
	return value != "" && len([]byte(value)) <= 255 && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n\t")
}
func validMediaType(value string) bool {
	return value == "text/plain" || value == "text/markdown" || value == "application/json"
}
func validTitle(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len([]byte(value)) <= 255 && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n\t")
}
func validSHA256Prefixed(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validSHA256Hex(strings.TrimPrefix(value, "sha256:"))
}
func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}
func prefixedSHA256(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
