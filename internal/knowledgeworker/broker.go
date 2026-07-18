package knowledgeworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/knowledge"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	minimumLease        = 5 * time.Second
	maximumLease        = 60 * time.Second
	completedRetention  = 10 * time.Minute
	workerAvailability  = 2 * time.Minute
	maximumPending      = 256
	maximumErrorCodeLen = 64
)

var (
	ErrInvalid   = errors.New("knowledge Worker relay request is invalid")
	ErrNotFound  = errors.New("knowledge Worker relay operation was not found")
	ErrLease     = errors.New("knowledge Worker relay lease is stale")
	ErrCapacity  = errors.New("knowledge Worker relay capacity is exhausted")
	ErrAdapter   = errors.New("knowledge Worker adapter operation failed")
	allowedCodes = map[string]struct{}{
		"adapter_unavailable": {},
		"conflict":            {},
		"internal":            {},
		"invalid_content":     {},
	}
)

type completedResult struct {
	acknowledged bool
	sizeBytes    int64
	contentHash  string
	matches      []knowledge.SearchMatch
	status       knowledge.BackendStatus
	errorCode    string
	pointID      string
	segmentCount int32
}

type pendingOperation struct {
	ownerID      string
	deploymentID string
	request      *agentv1.KnowledgeWorkerOperation
	requestHash  [sha256.Size]byte
	done         chan struct{}
	waiters      int
	queued       bool
	claimed      bool
	leaseID      string
	leaseExpires time.Time
	completed    bool
	completedAt  time.Time
	result       completedResult
}

// Broker is an in-memory, bounded rendezvous between synchronous Knowledge
// RPCs and an outbound-only Worker. PostgreSQL owns mutation metadata and the
// Worker adapter owns staged bytes/vectors. A control-plane restart therefore
// loses only in-flight transport calls; stable client and adapter identities
// make their retries safe.
type Broker struct {
	mu             sync.Mutex
	pending        map[string]*pendingOperation
	queues         map[string][]string
	notify         map[string]chan struct{}
	workerLastSeen map[string]time.Time
	activeWaiters  map[string]int
	now            func() time.Time
}

func NewBroker(now func() time.Time) (*Broker, error) {
	if now == nil {
		return nil, ErrInvalid
	}
	return &Broker{
		pending: make(map[string]*pendingOperation), queues: make(map[string][]string),
		notify: make(map[string]chan struct{}), workerLastSeen: make(map[string]time.Time),
		activeWaiters: make(map[string]int), now: now,
	}, nil
}

func (broker *Broker) Available() bool {
	if broker == nil {
		return false
	}
	now := broker.now().UTC()
	broker.mu.Lock()
	defer broker.mu.Unlock()
	broker.cleanupLocked(now)
	for _, seen := range broker.workerLastSeen {
		if now.Sub(seen) <= workerAvailability {
			return true
		}
	}
	for _, count := range broker.activeWaiters {
		if count > 0 {
			return true
		}
	}
	return false
}

func (broker *Broker) StageAttachmentChunk(ctx context.Context, value knowledge.AttachmentChunk) error {
	request := &agentv1.KnowledgeWorkerOperation{Binding: bindingToProto(value.OwnerID, value.BindingID, value.Binding), Request: &agentv1.KnowledgeWorkerOperation_StageChunk{StageChunk: &agentv1.KnowledgeWorkerStageChunk{
		SourceId: value.SourceID, UploadId: value.UploadID, MediaType: value.MediaType, DeclaredSizeBytes: value.DeclaredSizeBytes,
		OffsetBytes: value.OffsetBytes, ChunkOrdinal: value.ChunkOrdinal, Chunk: append([]byte(nil), value.Chunk...),
		ChunkSha256: value.ChunkSHA256, Title: value.Title,
	}}}
	result, err := broker.submit(ctx, request, true)
	clear(request.GetStageChunk().Chunk)
	if err != nil {
		return err
	}
	if result.errorCode != "" {
		return ErrAdapter
	}
	if !result.acknowledged {
		return knowledge.ErrInvalidBackend
	}
	return nil
}

func (broker *Broker) CommitAttachment(ctx context.Context, value knowledge.AttachmentCommit) (knowledge.ContentReceipt, error) {
	request := &agentv1.KnowledgeWorkerOperation{Binding: bindingToProto(value.OwnerID, value.BindingID, value.Binding), Request: &agentv1.KnowledgeWorkerOperation_CommitAttachment{CommitAttachment: &agentv1.KnowledgeWorkerCommitAttachment{
		SourceId: value.SourceID, UploadId: value.UploadID, MediaType: value.MediaType, DeclaredSizeBytes: value.DeclaredSizeBytes,
		ChunkCount: value.ChunkCount, ContentSha256: value.ContentSHA256, Title: value.Title,
	}}}
	result, err := broker.submit(ctx, request, true)
	if err != nil {
		return knowledge.ContentReceipt{}, err
	}
	if result.errorCode != "" {
		return knowledge.ContentReceipt{}, ErrAdapter
	}
	return knowledge.ContentReceipt{SizeBytes: result.sizeBytes, ContentSHA256: result.contentHash, PointID: result.pointID, IndexedSegmentCount: result.segmentCount}, nil
}

func (broker *Broker) StoreMemory(ctx context.Context, value knowledge.MemoryContent) (knowledge.ContentReceipt, error) {
	request := &agentv1.KnowledgeWorkerOperation{Binding: bindingToProto(value.OwnerID, value.BindingID, value.Binding), Request: &agentv1.KnowledgeWorkerOperation_StoreMemory{StoreMemory: &agentv1.KnowledgeWorkerStoreMemory{
		SourceId: value.SourceID, Content: append([]byte(nil), value.Content...), ContentSha256: value.ContentSHA256, Title: value.Title,
	}}}
	result, err := broker.submit(ctx, request, true)
	clear(request.GetStoreMemory().Content)
	if err != nil {
		return knowledge.ContentReceipt{}, err
	}
	if result.errorCode != "" {
		return knowledge.ContentReceipt{}, ErrAdapter
	}
	return knowledge.ContentReceipt{SizeBytes: result.sizeBytes, ContentSHA256: result.contentHash, PointID: result.pointID, IndexedSegmentCount: result.segmentCount}, nil
}

func (broker *Broker) DeleteSource(ctx context.Context, value knowledge.SourceTarget) error {
	request := &agentv1.KnowledgeWorkerOperation{Binding: bindingToProto(value.OwnerID, value.BindingID, value.Binding), Request: &agentv1.KnowledgeWorkerOperation_DeleteSource{DeleteSource: &agentv1.KnowledgeWorkerDeleteSource{SourceId: value.SourceID}}}
	result, err := broker.submit(ctx, request, true)
	if err != nil {
		return err
	}
	if result.errorCode != "" {
		return ErrAdapter
	}
	if !result.acknowledged {
		return knowledge.ErrInvalidBackend
	}
	return nil
}

func (broker *Broker) Search(ctx context.Context, config knowledge.Config, query knowledge.SearchQuery) ([]knowledge.SearchMatch, error) {
	request := &agentv1.KnowledgeWorkerOperation{Binding: bindingToProto(config.OwnerID, config.BindingID, config.Spec), Request: &agentv1.KnowledgeWorkerOperation_Search{Search: &agentv1.KnowledgeWorkerSearch{
		Query: query.Query, Limit: int32(query.Limit), SourceIds: append([]string(nil), query.SourceIDs...),
	}}}
	result, err := broker.submit(ctx, request, false)
	if err != nil {
		return nil, err
	}
	if result.errorCode != "" {
		return nil, ErrAdapter
	}
	return append([]knowledge.SearchMatch(nil), result.matches...), nil
}

func (broker *Broker) Status(ctx context.Context, config knowledge.Config, challenge *knowledge.PersistenceChallenge) (knowledge.BackendStatus, error) {
	statusRequest := &agentv1.KnowledgeWorkerStatus{}
	if challenge != nil {
		statusRequest.PointId = challenge.PointID
		statusRequest.SourceId = challenge.SourceID
		statusRequest.ContentSize = challenge.SizeBytes
		statusRequest.ContentSha256 = challenge.ContentSHA256
	}
	request := &agentv1.KnowledgeWorkerOperation{Binding: bindingToProto(config.OwnerID, config.BindingID, config.Spec), Request: &agentv1.KnowledgeWorkerOperation_Status{Status: statusRequest}}
	result, err := broker.submit(ctx, request, false)
	if err != nil {
		return knowledge.BackendUnavailable, err
	}
	if result.errorCode != "" {
		return knowledge.BackendUnavailable, ErrAdapter
	}
	return result.status, nil
}

func (broker *Broker) Acquire(ctx context.Context, ownerID, deploymentID string, lease time.Duration) (*agentv1.KnowledgeWorkerOperation, error) {
	if broker == nil || ctx == nil || !validOwner(ownerID) || !canonicalUUID(deploymentID) || lease < minimumLease || lease > maximumLease {
		return nil, ErrInvalid
	}
	broker.mu.Lock()
	broker.activeWaiters[deploymentID]++
	broker.workerLastSeen[deploymentID] = broker.now().UTC()
	broker.mu.Unlock()
	defer broker.releaseAcquireWaiter(deploymentID)
	for {
		now := broker.now().UTC()
		broker.mu.Lock()
		broker.cleanupLocked(now)
		broker.workerLastSeen[deploymentID] = now
		broker.requeueExpiredLocked(deploymentID, now)
		if operation := broker.takeLocked(ownerID, deploymentID, lease, now); operation != nil {
			broker.mu.Unlock()
			return operation, nil
		}
		notify := broker.notifyLocked(deploymentID)
		broker.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ErrNotFound
		case <-notify:
		}
	}
}

func (broker *Broker) releaseAcquireWaiter(deploymentID string) {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if broker.activeWaiters[deploymentID] <= 1 {
		delete(broker.activeWaiters, deploymentID)
		return
	}
	broker.activeWaiters[deploymentID]--
}

func (broker *Broker) Complete(ownerID, deploymentID, operationID, leaseID string, value *agentv1.KnowledgeWorkerResult) error {
	if broker == nil || !validOwner(ownerID) || !canonicalUUID(deploymentID) || !canonicalUUID(operationID) || !canonicalUUID(leaseID) || value == nil {
		return ErrInvalid
	}
	now := broker.now().UTC()
	broker.mu.Lock()
	defer broker.mu.Unlock()
	broker.cleanupLocked(now)
	operation, ok := broker.pending[operationID]
	if !ok || operation.ownerID != ownerID || operation.deploymentID != deploymentID {
		return ErrNotFound
	}
	if operation.completed {
		if operation.leaseID != leaseID {
			return ErrLease
		}
		return nil
	}
	if !operation.claimed || operation.leaseID != leaseID || !now.Before(operation.leaseExpires) {
		return ErrLease
	}
	result, err := validateResult(operation.request, value)
	if err != nil {
		return err
	}
	operation.result = result
	operation.completed = true
	operation.completedAt = now
	operation.claimed = false
	clearOperationContent(operation.request)
	operation.request = nil
	close(operation.done)
	return nil
}

func (broker *Broker) submit(ctx context.Context, request *agentv1.KnowledgeWorkerOperation, cache bool) (completedResult, error) {
	if broker == nil || ctx == nil || request == nil || request.GetBinding() == nil || !validRequest(request) {
		clearOperationContent(request)
		return completedResult{}, ErrInvalid
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		clearOperationContent(request)
		return completedResult{}, ErrInvalid
	}
	requestHash := sha256.Sum256(encoded)
	clear(encoded)
	operationID := uuid.NewSHA1(uuid.NameSpaceOID, requestHash[:]).String()
	if !cache {
		operationID = uuid.NewString()
	}
	deploymentID := request.GetBinding().GetDeploymentId()
	now := broker.now().UTC()
	broker.mu.Lock()
	broker.cleanupLocked(now)
	operation, exists := broker.pending[operationID]
	if exists {
		if operation.requestHash != requestHash || operation.deploymentID != deploymentID {
			broker.mu.Unlock()
			clearOperationContent(request)
			return completedResult{}, ErrInvalid
		}
		clearOperationContent(request)
	} else {
		if len(broker.pending) >= maximumPending {
			broker.mu.Unlock()
			clearOperationContent(request)
			return completedResult{}, ErrCapacity
		}
		operation = &pendingOperation{ownerID: request.GetBinding().GetOwnerId(), deploymentID: deploymentID, request: request, requestHash: requestHash, done: make(chan struct{}), queued: true}
		broker.pending[operationID] = operation
		broker.queues[deploymentID] = append(broker.queues[deploymentID], operationID)
		broker.signalLocked(deploymentID)
	}
	operation.waiters++
	done := operation.done
	broker.mu.Unlock()

	select {
	case <-ctx.Done():
		broker.releaseWaiter(operationID)
		return completedResult{}, ErrAdapter
	case <-done:
		broker.mu.Lock()
		operation, ok := broker.pending[operationID]
		if !ok || !operation.completed {
			broker.mu.Unlock()
			return completedResult{}, ErrAdapter
		}
		result := cloneResult(operation.result)
		operation.waiters--
		if !cache && operation.waiters == 0 {
			delete(broker.pending, operationID)
		}
		broker.mu.Unlock()
		return result, nil
	}
}

func (broker *Broker) releaseWaiter(operationID string) {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	operation, ok := broker.pending[operationID]
	if !ok {
		return
	}
	if operation.waiters > 0 {
		operation.waiters--
	}
	if operation.waiters == 0 && !operation.completed {
		clearOperationContent(operation.request)
		broker.removeQueuedLocked(operation.deploymentID, operationID)
		delete(broker.pending, operationID)
	}
}

func (broker *Broker) removeQueuedLocked(deploymentID, operationID string) {
	queue := broker.queues[deploymentID]
	for index := range queue {
		if queue[index] != operationID {
			continue
		}
		copy(queue[index:], queue[index+1:])
		queue[len(queue)-1] = ""
		queue = queue[:len(queue)-1]
		break
	}
	if len(queue) == 0 {
		delete(broker.queues, deploymentID)
		return
	}
	broker.queues[deploymentID] = queue
}

func (broker *Broker) takeLocked(ownerID, deploymentID string, lease time.Duration, now time.Time) *agentv1.KnowledgeWorkerOperation {
	queue := broker.queues[deploymentID]
	remaining := len(queue)
	for remaining > 0 && len(queue) > 0 {
		remaining--
		operationID := queue[0]
		queue = queue[1:]
		operation, ok := broker.pending[operationID]
		if !ok || operation.completed || operation.claimed || !operation.queued || operation.request == nil {
			continue
		}
		if operation.ownerID != ownerID {
			queue = append(queue, operationID)
			continue
		}
		operation.queued = false
		operation.claimed = true
		operation.leaseID = uuid.NewString()
		operation.leaseExpires = now.Add(lease)
		broker.queues[deploymentID] = queue
		result := proto.Clone(operation.request).(*agentv1.KnowledgeWorkerOperation)
		result.OperationId = operationID
		result.LeaseId = operation.leaseID
		result.LeaseExpiresAt = timestamppb.New(operation.leaseExpires)
		return result
	}
	broker.queues[deploymentID] = queue
	return nil
}

func (broker *Broker) requeueExpiredLocked(deploymentID string, now time.Time) {
	for operationID, operation := range broker.pending {
		if operation.deploymentID != deploymentID || operation.completed || !operation.claimed || now.Before(operation.leaseExpires) {
			continue
		}
		operation.claimed = false
		operation.leaseID = ""
		operation.leaseExpires = time.Time{}
		if !operation.queued && operation.request != nil {
			operation.queued = true
			broker.queues[deploymentID] = append(broker.queues[deploymentID], operationID)
		}
	}
}

func (broker *Broker) cleanupLocked(now time.Time) {
	for operationID, operation := range broker.pending {
		if operation.completed && operation.waiters == 0 && now.Sub(operation.completedAt) > completedRetention {
			delete(broker.pending, operationID)
		}
	}
	for deploymentID, seen := range broker.workerLastSeen {
		if now.Sub(seen) > workerAvailability && broker.activeWaiters[deploymentID] == 0 {
			delete(broker.workerLastSeen, deploymentID)
		}
	}
}

func (broker *Broker) notifyLocked(deploymentID string) chan struct{} {
	if channel := broker.notify[deploymentID]; channel != nil {
		return channel
	}
	channel := make(chan struct{})
	broker.notify[deploymentID] = channel
	return channel
}

func (broker *Broker) signalLocked(deploymentID string) {
	channel := broker.notifyLocked(deploymentID)
	close(channel)
	broker.notify[deploymentID] = make(chan struct{})
}

func bindingToProto(ownerID, bindingID string, spec knowledge.ConfigSpec) *agentv1.KnowledgeWorkerBinding {
	return &agentv1.KnowledgeWorkerBinding{
		OwnerId: ownerID, BindingId: bindingID, DeploymentId: spec.DeploymentID, ManagedServiceId: spec.ManagedServiceID,
		RecipeDigest: spec.RecipeDigest, EmbeddingProfileId: spec.EmbeddingProfileID,
	}
}

func validRequest(value *agentv1.KnowledgeWorkerOperation) bool {
	binding := value.GetBinding()
	if value.GetOperationId() != "" || value.GetLeaseId() != "" || value.GetLeaseExpiresAt() != nil || !validOwner(binding.GetOwnerId()) ||
		!canonicalUUID(binding.GetBindingId()) || !canonicalUUID(binding.GetDeploymentId()) || !canonicalUUID(binding.GetManagedServiceId()) ||
		!validDigest(binding.GetRecipeDigest()) || strings.TrimSpace(binding.GetEmbeddingProfileId()) != knowledge.LocalMultilingualE5SmallProfileID {
		return false
	}
	switch request := value.GetRequest().(type) {
	case *agentv1.KnowledgeWorkerOperation_StageChunk:
		chunk := request.StageChunk
		return chunk != nil && canonicalUUID(chunk.GetSourceId()) && canonicalUUID(chunk.GetUploadId()) && validKnowledgeMediaType(chunk.GetMediaType()) &&
			chunk.GetDeclaredSizeBytes() > 0 && chunk.GetDeclaredSizeBytes() <= knowledge.MaxAttachmentSizeBytes && chunk.GetOffsetBytes() >= 0 &&
			chunk.GetChunkOrdinal() >= 0 && chunk.GetChunkOrdinal() < 256 && len(chunk.GetChunk()) > 0 && len(chunk.GetChunk()) <= knowledge.MaxAttachmentChunkBytes &&
			chunk.GetOffsetBytes() <= chunk.GetDeclaredSizeBytes()-int64(len(chunk.GetChunk())) && validDigest(chunk.GetChunkSha256()) &&
			knowledge.SHA256(chunk.GetChunk()) == chunk.GetChunkSha256() && validRelayTitle(chunk.GetTitle())
	case *agentv1.KnowledgeWorkerOperation_CommitAttachment:
		commit := request.CommitAttachment
		return commit != nil && canonicalUUID(commit.GetSourceId()) && canonicalUUID(commit.GetUploadId()) && validKnowledgeMediaType(commit.GetMediaType()) &&
			commit.GetDeclaredSizeBytes() > 0 && commit.GetDeclaredSizeBytes() <= knowledge.MaxAttachmentSizeBytes && commit.GetChunkCount() > 0 && commit.GetChunkCount() <= 256 &&
			validDigest(commit.GetContentSha256()) && validRelayTitle(commit.GetTitle())
	case *agentv1.KnowledgeWorkerOperation_StoreMemory:
		memory := request.StoreMemory
		return memory != nil && canonicalUUID(memory.GetSourceId()) && len(memory.GetContent()) > 0 && len(memory.GetContent()) <= knowledge.MaxMemorySizeBytes &&
			validDigest(memory.GetContentSha256()) && knowledge.SHA256(memory.GetContent()) == memory.GetContentSha256() && validRelayTitle(memory.GetTitle())
	case *agentv1.KnowledgeWorkerOperation_DeleteSource:
		return request.DeleteSource != nil && canonicalUUID(request.DeleteSource.GetSourceId())
	case *agentv1.KnowledgeWorkerOperation_Search:
		search := request.Search
		if search == nil || strings.TrimSpace(search.GetQuery()) == "" || len(search.GetQuery()) > knowledge.MaxSearchQueryBytes || search.GetLimit() < 1 || search.GetLimit() > knowledge.MaxSearchResults || len(search.GetSourceIds()) > knowledge.MaxSearchResults {
			return false
		}
		for _, sourceID := range search.GetSourceIds() {
			if !canonicalUUID(sourceID) {
				return false
			}
		}
		return true
	case *agentv1.KnowledgeWorkerOperation_Status:
		status := request.Status
		if status == nil {
			return false
		}
		if status.GetSourceId() == "" {
			return status.GetPointId() == "" && status.GetContentSize() == 0 && status.GetContentSha256() == ""
		}
		return canonicalUUID(status.GetPointId()) && canonicalUUID(status.GetSourceId()) && status.GetContentSize() > 0 && status.GetContentSize() <= knowledge.MaxAttachmentSizeBytes && validDigest(status.GetContentSha256())
	default:
		return false
	}
}

func validateResult(operation *agentv1.KnowledgeWorkerOperation, value *agentv1.KnowledgeWorkerResult) (completedResult, error) {
	if operation == nil || value == nil || len(value.GetErrorCode()) > maximumErrorCodeLen {
		return completedResult{}, ErrInvalid
	}
	if code := strings.TrimSpace(value.GetErrorCode()); code != "" {
		if _, ok := allowedCodes[code]; !ok || value.GetAcknowledged() || value.GetSizeBytes() != 0 || value.GetContentSha256() != "" || len(value.GetMatches()) != 0 || value.GetBackendStatus() != agentv1.KnowledgeWorkerBackendStatus_KNOWLEDGE_WORKER_BACKEND_STATUS_UNSPECIFIED || value.GetPointId() != "" || value.GetIndexedSegmentCount() != 0 {
			return completedResult{}, ErrInvalid
		}
		return completedResult{errorCode: code}, nil
	}
	result := completedResult{acknowledged: value.GetAcknowledged(), sizeBytes: value.GetSizeBytes(), contentHash: strings.ToLower(strings.TrimSpace(value.GetContentSha256())), pointID: value.GetPointId(), segmentCount: value.GetIndexedSegmentCount()}
	switch request := operation.GetRequest().(type) {
	case *agentv1.KnowledgeWorkerOperation_StageChunk, *agentv1.KnowledgeWorkerOperation_DeleteSource:
		if !value.GetAcknowledged() || value.GetSizeBytes() != 0 || value.GetContentSha256() != "" || len(value.GetMatches()) != 0 || value.GetBackendStatus() != agentv1.KnowledgeWorkerBackendStatus_KNOWLEDGE_WORKER_BACKEND_STATUS_UNSPECIFIED || value.GetPointId() != "" || value.GetIndexedSegmentCount() != 0 {
			return completedResult{}, ErrInvalid
		}
	case *agentv1.KnowledgeWorkerOperation_CommitAttachment:
		maximumSegments := indexedSegmentUpperBound(request.CommitAttachment.GetDeclaredSizeBytes() + int64(len([]byte(request.CommitAttachment.GetTitle()))) + 2)
		if !value.GetAcknowledged() || value.GetSizeBytes() != request.CommitAttachment.GetDeclaredSizeBytes() || value.GetContentSha256() != request.CommitAttachment.GetContentSha256() || len(value.GetMatches()) != 0 || value.GetBackendStatus() != agentv1.KnowledgeWorkerBackendStatus_KNOWLEDGE_WORKER_BACKEND_STATUS_UNSPECIFIED || !canonicalUUID(value.GetPointId()) || value.GetPointId() == request.CommitAttachment.GetSourceId() || value.GetIndexedSegmentCount() < 1 || value.GetIndexedSegmentCount() > maximumSegments {
			return completedResult{}, ErrInvalid
		}
	case *agentv1.KnowledgeWorkerOperation_StoreMemory:
		maximumSegments := indexedSegmentUpperBound(int64(len(request.StoreMemory.GetContent())))
		if !value.GetAcknowledged() || value.GetSizeBytes() != int64(len(request.StoreMemory.GetContent())) || value.GetContentSha256() != request.StoreMemory.GetContentSha256() || len(value.GetMatches()) != 0 || value.GetBackendStatus() != agentv1.KnowledgeWorkerBackendStatus_KNOWLEDGE_WORKER_BACKEND_STATUS_UNSPECIFIED || !canonicalUUID(value.GetPointId()) || value.GetPointId() == request.StoreMemory.GetSourceId() || value.GetIndexedSegmentCount() < 1 || value.GetIndexedSegmentCount() > maximumSegments {
			return completedResult{}, ErrInvalid
		}
	case *agentv1.KnowledgeWorkerOperation_Search:
		if !value.GetAcknowledged() || value.GetSizeBytes() != 0 || value.GetContentSha256() != "" || len(value.GetMatches()) > int(request.Search.GetLimit()) || value.GetBackendStatus() != agentv1.KnowledgeWorkerBackendStatus_KNOWLEDGE_WORKER_BACKEND_STATUS_UNSPECIFIED || value.GetPointId() != "" || value.GetIndexedSegmentCount() != 0 {
			return completedResult{}, ErrInvalid
		}
		result.matches = make([]knowledge.SearchMatch, 0, len(value.GetMatches()))
		for _, match := range value.GetMatches() {
			if match == nil {
				return completedResult{}, ErrInvalid
			}
			result.matches = append(result.matches, knowledge.SearchMatch{SourceID: match.GetSourceId(), ChunkRef: match.GetChunkRef(), Score: match.GetScore()})
		}
	case *agentv1.KnowledgeWorkerOperation_Status:
		if !value.GetAcknowledged() || value.GetSizeBytes() != 0 || value.GetContentSha256() != "" || len(value.GetMatches()) != 0 || value.GetPointId() != "" || value.GetIndexedSegmentCount() != 0 {
			return completedResult{}, ErrInvalid
		}
		switch value.GetBackendStatus() {
		case agentv1.KnowledgeWorkerBackendStatus_KNOWLEDGE_WORKER_BACKEND_STATUS_READY:
			result.status = knowledge.BackendReady
		case agentv1.KnowledgeWorkerBackendStatus_KNOWLEDGE_WORKER_BACKEND_STATUS_DEGRADED:
			result.status = knowledge.BackendDegraded
		case agentv1.KnowledgeWorkerBackendStatus_KNOWLEDGE_WORKER_BACKEND_STATUS_UNAVAILABLE:
			result.status = knowledge.BackendUnavailable
		default:
			return completedResult{}, ErrInvalid
		}
	default:
		return completedResult{}, ErrInvalid
	}
	return result, nil
}

func clearOperationContent(value *agentv1.KnowledgeWorkerOperation) {
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

func cloneResult(value completedResult) completedResult {
	value.matches = append([]knowledge.SearchMatch(nil), value.matches...)
	return value
}

func validOwner(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 255 && !strings.ContainsAny(value, "\x00\r\n\t")
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func validKnowledgeMediaType(value string) bool {
	return value == "text/plain" || value == "text/markdown" || value == "application/json"
}

func validRelayTitle(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len([]byte(value)) <= knowledge.MaxSourceTitleBytes && !strings.ContainsAny(value, "\x00\r\n\t")
}

func indexedSegmentUpperBound(size int64) int32 {
	if size <= 0 {
		return 0
	}
	return int32((size + 2047) / 2048)
}

var _ knowledge.Backend = (*Broker)(nil)
