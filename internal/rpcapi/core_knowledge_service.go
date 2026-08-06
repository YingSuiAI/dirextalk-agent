package rpcapi

import (
	"context"
	"errors"
	"io"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CoreKnowledgeService adapts the Core v1 knowledge service to gRPC.
type CoreKnowledgeService struct {
	agentv1.UnimplementedCoreKnowledgeServiceServer
	service *coreknowledge.Service
}

var _ agentv1.CoreKnowledgeServiceServer = (*CoreKnowledgeService)(nil)

func NewCoreKnowledgeService(service *coreknowledge.Service) (*CoreKnowledgeService, error) {
	if service == nil {
		return nil, errors.New("core knowledge service requires service")
	}
	return &CoreKnowledgeService{service: service}, nil
}

func (s *CoreKnowledgeService) CreateMount(ctx context.Context, r *agentv1.CoreKnowledgeServiceCreateMountRequest) (*agentv1.CoreKnowledgeServiceCreateMountResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	v, err := s.service.CreateMount(ctx, coreknowledge.MountCommand{IdempotencyKey: r.GetIdempotencyKey(), SourceID: r.GetSourceId(), Title: r.GetTitle(), RelativePath: r.GetRelativePath(), Digest: r.GetDigest(), SizeBytes: r.GetSizeBytes(), MediaType: r.GetMediaType()})
	if err != nil {
		return nil, coreKnowledgeRPCError(err)
	}
	return &agentv1.CoreKnowledgeServiceCreateMountResponse{Source: coreKnowledgeSourceProto(v)}, nil
}

func (s *CoreKnowledgeService) Upload(stream grpc.ClientStreamingServer[agentv1.CoreKnowledgeServiceUploadRequest, agentv1.CoreKnowledgeServiceUploadResponse]) error {
	if stream == nil {
		return status.Error(codes.InvalidArgument, "stream is required")
	}
	ctx := stream.Context()
	var session coreknowledge.UploadSession
	var metadata coreknowledge.UploadMetadata
	var haveMetadata bool
	var lastChunkKey string
	var lastChunkOrdinal int32
	var lastChunkOffset int64
	for {
		r, err := stream.Recv()
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if errors.Is(err, grpc.ErrClientConnClosing) {
			return err
		}
		if err == io.EOF {
			if !haveMetadata {
				return status.Error(codes.InvalidArgument, "metadata is required before upload chunks")
			}
			return stream.SendAndClose(&agentv1.CoreKnowledgeServiceUploadResponse{Session: coreKnowledgeUploadSessionProto(session)})
		}
		if err != nil {
			return err
		}
		if r == nil {
			return status.Error(codes.InvalidArgument, "request is required")
		}
		switch p := r.GetPart().(type) {
		case *agentv1.CoreKnowledgeServiceUploadRequest_Metadata:
			if haveMetadata {
				return status.Error(codes.InvalidArgument, "upload metadata must be sent exactly once")
			}
			m := p.Metadata
			if m == nil {
				return status.Error(codes.InvalidArgument, "metadata is required")
			}
			metadata = coreknowledge.UploadMetadata{IdempotencyKey: m.GetIdempotencyKey(), UploadID: m.GetUploadId(), SourceID: m.GetSourceId(), Title: m.GetTitle(), RelativePath: m.GetRelativePath(), MediaType: m.GetMediaType(), DeclaredSize: m.GetDeclaredSizeBytes(), ContentSHA256: m.GetContentSha256()}
			u, e := s.service.StartUpload(ctx, metadata)
			if e != nil {
				return coreKnowledgeRPCError(e)
			}
			metadata = u.Metadata
			session = u.Session
			haveMetadata = true
		case *agentv1.CoreKnowledgeServiceUploadRequest_Chunk:
			if !haveMetadata {
				return status.Error(codes.InvalidArgument, "metadata must be the first upload message")
			}
			c := p.Chunk
			if c == nil {
				return status.Error(codes.InvalidArgument, "chunk is required")
			}
			if c.GetUploadId() != metadata.UploadID || c.GetIdempotencyKey() == "" {
				return status.Error(codes.InvalidArgument, "chunk upload identity does not match metadata")
			}
			isReplay := c.GetIdempotencyKey() == lastChunkKey && c.GetOrdinal() == lastChunkOrdinal && c.GetOffsetBytes() == lastChunkOffset
			if !isReplay && (c.GetOrdinal() != session.NextOrdinal || c.GetOffsetBytes() != session.ReceivedSize) {
				return status.Error(codes.InvalidArgument, "upload chunks must be contiguous and ordered")
			}
			chunk := append([]byte(nil), c.GetData()...)
			u, e := s.service.AppendUploadChunk(ctx, coreknowledge.UploadChunk{IdempotencyKey: c.GetIdempotencyKey(), UploadID: c.GetUploadId(), Ordinal: c.GetOrdinal(), OffsetBytes: c.GetOffsetBytes(), Data: chunk, ChunkSHA256: c.GetChunkSha256()})
			clear(chunk)
			if e != nil {
				return coreKnowledgeRPCError(e)
			}
			session = u.Session
			lastChunkKey, lastChunkOrdinal, lastChunkOffset = c.GetIdempotencyKey(), c.GetOrdinal(), c.GetOffsetBytes()
		default:
			return status.Error(codes.InvalidArgument, "upload message must contain metadata or chunk")
		}
	}
}

func (s *CoreKnowledgeService) CommitUpload(ctx context.Context, r *agentv1.CoreKnowledgeServiceCommitUploadRequest) (*agentv1.CoreKnowledgeServiceCommitUploadResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	u, source, err := s.service.CommitUpload(ctx, coreknowledge.CommitUploadCommand{IdempotencyKey: r.GetIdempotencyKey(), UploadID: r.GetUploadId(), ExpectedRevision: r.GetExpectedRevision(), ContentSHA256: r.GetContentSha256()})
	if err != nil {
		return nil, coreKnowledgeRPCError(err)
	}
	return &agentv1.CoreKnowledgeServiceCommitUploadResponse{Source: coreKnowledgeSourceProto(source), Session: coreKnowledgeUploadSessionProto(u.Session)}, nil
}

func (s *CoreKnowledgeService) AbortUpload(ctx context.Context, r *agentv1.CoreKnowledgeServiceAbortUploadRequest) (*agentv1.CoreKnowledgeServiceAbortUploadResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := s.service.AbortUpload(ctx, coreknowledge.AbortUploadCommand{IdempotencyKey: r.GetIdempotencyKey(), UploadID: r.GetUploadId(), ExpectedRevision: r.GetExpectedRevision()}); err != nil {
		return nil, coreKnowledgeRPCError(err)
	}
	return &agentv1.CoreKnowledgeServiceAbortUploadResponse{}, nil
}

func (s *CoreKnowledgeService) CreateMemory(ctx context.Context, r *agentv1.CoreKnowledgeServiceCreateMemoryRequest) (*agentv1.CoreKnowledgeServiceCreateMemoryResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	v, err := s.service.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: r.GetIdempotencyKey(), SourceID: r.GetSourceId(), Title: r.GetTitle(), Content: r.GetContent(), ContentSHA256: r.GetContentSha256(), MediaType: r.GetMediaType()})
	if err != nil {
		return nil, coreKnowledgeRPCError(err)
	}
	return &agentv1.CoreKnowledgeServiceCreateMemoryResponse{Source: coreKnowledgeSourceProto(v)}, nil
}

func (s *CoreKnowledgeService) ListSources(ctx context.Context, r *agentv1.CoreKnowledgeServiceListSourcesRequest) (*agentv1.CoreKnowledgeServiceListSourcesResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	q := coreknowledge.ListQuery{PageSize: int(r.GetPageSize()), PageToken: r.GetPageToken()}
	var ok bool
	if r.GetKind() != agentv1.CoreKnowledgeSourceKind_CORE_KNOWLEDGE_SOURCE_KIND_UNSPECIFIED {
		q.Kind, ok = coreKnowledgeKindFromProto(r.GetKind())
		if !ok {
			return nil, status.Error(codes.InvalidArgument, "kind is invalid")
		}
	}
	if r.GetStatus() != agentv1.CoreKnowledgeSourceStatus_CORE_KNOWLEDGE_SOURCE_STATUS_UNSPECIFIED {
		q.Status, ok = coreKnowledgeStatusFromProto(r.GetStatus())
		if !ok {
			return nil, status.Error(codes.InvalidArgument, "status is invalid")
		}
	}
	p, err := s.service.List(ctx, q)
	if err != nil {
		return nil, coreKnowledgeRPCError(err)
	}
	out := &agentv1.CoreKnowledgeServiceListSourcesResponse{NextPageToken: p.NextPageToken, Sources: make([]*agentv1.CoreKnowledgeSource, 0, len(p.Sources))}
	for _, v := range p.Sources {
		out.Sources = append(out.Sources, coreKnowledgeSourceProto(v))
	}
	return out, nil
}

func (s *CoreKnowledgeService) GetSource(ctx context.Context, r *agentv1.CoreKnowledgeServiceGetSourceRequest) (*agentv1.CoreKnowledgeServiceGetSourceResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	v, err := s.service.Get(ctx, r.GetSourceId())
	if err != nil {
		return nil, coreKnowledgeRPCError(err)
	}
	return &agentv1.CoreKnowledgeServiceGetSourceResponse{Source: coreKnowledgeSourceProto(v)}, nil
}

func (s *CoreKnowledgeService) DeleteSource(ctx context.Context, r *agentv1.CoreKnowledgeServiceDeleteSourceRequest) (*agentv1.CoreKnowledgeServiceDeleteSourceResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	v, err := s.service.Delete(ctx, coreknowledge.DeleteCommand{IdempotencyKey: r.GetIdempotencyKey(), SourceID: r.GetSourceId(), ExpectedRevision: r.GetExpectedRevision()})
	if err != nil {
		return nil, coreKnowledgeRPCError(err)
	}
	return &agentv1.CoreKnowledgeServiceDeleteSourceResponse{Source: coreKnowledgeSourceProto(v)}, nil
}

func (s *CoreKnowledgeService) GetStatus(ctx context.Context, r *agentv1.CoreKnowledgeServiceGetStatusRequest) (*agentv1.CoreKnowledgeServiceGetStatusResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	v, err := s.service.Status(ctx)
	if err != nil {
		return nil, coreKnowledgeRPCError(err)
	}
	return &agentv1.CoreKnowledgeServiceGetStatusResponse{ReadyCount: int32(v.ReadyCount), UploadingCount: int32(v.UploadingCount), IndexingCount: int32(v.IndexingCount), FailedCount: int32(v.FailedCount), CleanupPendingCount: int32(v.CleanupPendingCount), CheckedAt: timestamppb.New(v.CheckedAt)}, nil
}

func (s *CoreKnowledgeService) Index(ctx context.Context, r *agentv1.CoreKnowledgeServiceIndexRequest) (*agentv1.CoreKnowledgeServiceIndexResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	v, err := s.service.Index(ctx, coreknowledge.IndexRequest{IdempotencyKey: r.GetIdempotencyKey(), SourceIDs: append([]string(nil), r.GetSourceIds()...)})
	if err != nil {
		return nil, coreKnowledgeRPCError(err)
	}
	return &agentv1.CoreKnowledgeServiceIndexResponse{Task: &agentv1.CoreKnowledgeTaskReference{TaskId: v.TaskID}}, nil
}

func (s *CoreKnowledgeService) Search(ctx context.Context, r *agentv1.CoreKnowledgeServiceSearchRequest) (*agentv1.CoreKnowledgeServiceSearchResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	v, err := s.service.Search(ctx, coreknowledge.SearchQuery{Query: r.GetQuery(), SourceIDs: append([]string(nil), r.GetSourceIds()...), Limit: int(r.GetLimit()), PageToken: r.GetPageToken()})
	if err != nil {
		return nil, coreKnowledgeRPCError(err)
	}
	out := &agentv1.CoreKnowledgeServiceSearchResponse{
		NextPageToken:            v.NextPageToken,
		EmbeddingProfileId:       v.EmbeddingProfileID,
		EmbeddingProfileRevision: v.EmbeddingProfileRevision,
		EmbeddingModel:           v.EmbeddingModel,
		EmbeddingGeneration:      v.EmbeddingGeneration,
		CollectionConfigDigest:   v.CollectionConfigDigest,
		Matches:                  make([]*agentv1.CoreKnowledgeSearchMatch, 0, len(v.Matches)),
	}
	for _, m := range v.Matches {
		out.Matches = append(out.Matches, &agentv1.CoreKnowledgeSearchMatch{SourceId: m.SourceID, ChunkRef: m.ChunkRef, Snippet: m.Snippet, Score: m.Score})
	}
	return out, nil
}

func coreKnowledgeSourceProto(v coreknowledge.Source) *agentv1.CoreKnowledgeSource {
	return &agentv1.CoreKnowledgeSource{SourceId: v.ID, Kind: coreKnowledgeKindProto(v.Kind), Status: coreKnowledgeStatusProto(v.Status), Title: v.Title, RelativePath: v.RelativePath, Digest: v.Digest, SizeBytes: v.SizeBytes, MediaType: v.MediaType, Revision: v.Revision, CreatedAt: timestampOrNil(v.CreatedAt), UpdatedAt: timestampOrNil(v.UpdatedAt), ErrorCode: v.ErrorCode}
}
func coreKnowledgeUploadSessionProto(v coreknowledge.UploadSession) *agentv1.CoreKnowledgeUploadSession {
	return &agentv1.CoreKnowledgeUploadSession{UploadId: v.UploadID, SourceId: v.SourceID, ReceivedSizeBytes: v.ReceivedSize, NextOrdinal: v.NextOrdinal, Revision: v.Revision}
}
func coreKnowledgeKindProto(v coreknowledge.SourceKind) agentv1.CoreKnowledgeSourceKind {
	switch v {
	case coreknowledge.SourceKindMount:
		return agentv1.CoreKnowledgeSourceKind_CORE_KNOWLEDGE_SOURCE_KIND_MOUNT
	case coreknowledge.SourceKindUpload:
		return agentv1.CoreKnowledgeSourceKind_CORE_KNOWLEDGE_SOURCE_KIND_UPLOAD
	case coreknowledge.SourceKindMemory:
		return agentv1.CoreKnowledgeSourceKind_CORE_KNOWLEDGE_SOURCE_KIND_MEMORY
	}
	return agentv1.CoreKnowledgeSourceKind_CORE_KNOWLEDGE_SOURCE_KIND_UNSPECIFIED
}
func coreKnowledgeKindFromProto(v agentv1.CoreKnowledgeSourceKind) (coreknowledge.SourceKind, bool) {
	switch v {
	case agentv1.CoreKnowledgeSourceKind_CORE_KNOWLEDGE_SOURCE_KIND_MOUNT:
		return coreknowledge.SourceKindMount, true
	case agentv1.CoreKnowledgeSourceKind_CORE_KNOWLEDGE_SOURCE_KIND_UPLOAD:
		return coreknowledge.SourceKindUpload, true
	case agentv1.CoreKnowledgeSourceKind_CORE_KNOWLEDGE_SOURCE_KIND_MEMORY:
		return coreknowledge.SourceKindMemory, true
	}
	return "", false
}
func coreKnowledgeStatusProto(v coreknowledge.SourceStatus) agentv1.CoreKnowledgeSourceStatus {
	switch v {
	case coreknowledge.SourceStatusUploading:
		return agentv1.CoreKnowledgeSourceStatus_CORE_KNOWLEDGE_SOURCE_STATUS_UPLOADING
	case coreknowledge.SourceStatusReady:
		return agentv1.CoreKnowledgeSourceStatus_CORE_KNOWLEDGE_SOURCE_STATUS_READY
	case coreknowledge.SourceStatusIndexing:
		return agentv1.CoreKnowledgeSourceStatus_CORE_KNOWLEDGE_SOURCE_STATUS_INDEXING
	case coreknowledge.SourceStatusFailed:
		return agentv1.CoreKnowledgeSourceStatus_CORE_KNOWLEDGE_SOURCE_STATUS_FAILED
	case coreknowledge.SourceStatusDeleting:
		return agentv1.CoreKnowledgeSourceStatus_CORE_KNOWLEDGE_SOURCE_STATUS_DELETING
	case coreknowledge.SourceStatusCleanupPending:
		return agentv1.CoreKnowledgeSourceStatus_CORE_KNOWLEDGE_SOURCE_STATUS_CLEANUP_PENDING
	case coreknowledge.SourceStatusDeleted:
		return agentv1.CoreKnowledgeSourceStatus_CORE_KNOWLEDGE_SOURCE_STATUS_DELETED
	}
	return agentv1.CoreKnowledgeSourceStatus_CORE_KNOWLEDGE_SOURCE_STATUS_UNSPECIFIED
}
func coreKnowledgeStatusFromProto(v agentv1.CoreKnowledgeSourceStatus) (coreknowledge.SourceStatus, bool) {
	switch v {
	case agentv1.CoreKnowledgeSourceStatus_CORE_KNOWLEDGE_SOURCE_STATUS_UPLOADING:
		return coreknowledge.SourceStatusUploading, true
	case agentv1.CoreKnowledgeSourceStatus_CORE_KNOWLEDGE_SOURCE_STATUS_READY:
		return coreknowledge.SourceStatusReady, true
	case agentv1.CoreKnowledgeSourceStatus_CORE_KNOWLEDGE_SOURCE_STATUS_INDEXING:
		return coreknowledge.SourceStatusIndexing, true
	case agentv1.CoreKnowledgeSourceStatus_CORE_KNOWLEDGE_SOURCE_STATUS_FAILED:
		return coreknowledge.SourceStatusFailed, true
	case agentv1.CoreKnowledgeSourceStatus_CORE_KNOWLEDGE_SOURCE_STATUS_DELETING:
		return coreknowledge.SourceStatusDeleting, true
	case agentv1.CoreKnowledgeSourceStatus_CORE_KNOWLEDGE_SOURCE_STATUS_CLEANUP_PENDING:
		return coreknowledge.SourceStatusCleanupPending, true
	case agentv1.CoreKnowledgeSourceStatus_CORE_KNOWLEDGE_SOURCE_STATUS_DELETED:
		return coreknowledge.SourceStatusDeleted, true
	}
	return "", false
}
func coreKnowledgeRPCError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	switch {
	case errors.Is(err, coreknowledge.ErrInvalid), errors.Is(err, coreknowledge.ErrPathTraversal), errors.Is(err, coreknowledge.ErrLimitExceeded):
		return status.Error(codes.InvalidArgument, "invalid knowledge request")
	case errors.Is(err, coreknowledge.ErrNotFound):
		return status.Error(codes.NotFound, "knowledge source was not found")
	case errors.Is(err, coreknowledge.ErrIdempotencyConflict):
		return status.Error(codes.AlreadyExists, "knowledge idempotency key conflict")
	case errors.Is(err, coreknowledge.ErrRevisionConflict), errors.Is(err, coreknowledge.ErrCursorConflict):
		return status.Error(codes.Aborted, "knowledge revision or cursor conflict")
	case errors.Is(err, coreknowledge.ErrActiveTasks):
		return status.Error(codes.FailedPrecondition, coreknowledge.ActiveTasksPublicMessage)
	case errors.Is(err, coreknowledge.ErrChecksumMismatch):
		return status.Error(codes.DataLoss, "knowledge checksum mismatch")
	case errors.Is(err, coreknowledge.ErrCleanupPending), errors.Is(err, coreknowledge.ErrSourceReferenced), errors.Is(err, coreknowledge.ErrIneligible):
		return status.Error(codes.FailedPrecondition, "knowledge source cannot be mutated")
	case errors.Is(err, coreknowledge.ErrFilesystemUnavailable):
		return status.Error(codes.Unavailable, "knowledge filesystem is unavailable")
	default:
		return status.Error(codes.Unavailable, "knowledge persistence is unavailable")
	}
}
