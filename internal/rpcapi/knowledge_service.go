package rpcapi

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/knowledge"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type KnowledgeCoordinator interface {
	Capabilities(string) (knowledge.Capabilities, error)
	GetConfig(context.Context, string, string) (knowledge.Config, error)
	PutConfig(context.Context, knowledge.MutationScope, knowledge.PutConfigCommand) (knowledge.Config, error)
	ListSources(context.Context, knowledge.ListSourcesQuery) (knowledge.SourcePage, error)
	StartAttachmentUpload(context.Context, knowledge.MutationScope, knowledge.StartAttachmentUploadCommand) (knowledge.AttachmentUpload, error)
	AppendAttachmentChunk(context.Context, knowledge.MutationScope, knowledge.AppendAttachmentChunkCommand) (knowledge.AttachmentUpload, error)
	CommitAttachmentUpload(context.Context, knowledge.MutationScope, knowledge.CommitAttachmentUploadCommand) (knowledge.AttachmentUpload, knowledge.Source, error)
	CreateMemory(context.Context, knowledge.MutationScope, knowledge.CreateMemoryCommand) (knowledge.Source, error)
	DeleteSource(context.Context, knowledge.MutationScope, knowledge.DeleteSourceCommand) (knowledge.Source, error)
	Search(context.Context, knowledge.SearchQuery) (knowledge.SearchResult, error)
	Status(context.Context, string, string) (knowledge.Status, error)
}

type KnowledgeService struct {
	agentv1.UnimplementedKnowledgeServiceServer
	coordinator KnowledgeCoordinator
}

func NewKnowledgeService(coordinator KnowledgeCoordinator) *KnowledgeService {
	return &KnowledgeService{coordinator: coordinator}
}

func (service *KnowledgeService) GetKnowledgeCapabilities(_ context.Context, request *agentv1.GetKnowledgeCapabilitiesRequest) (*agentv1.GetKnowledgeCapabilitiesResponse, error) {
	if service == nil || service.coordinator == nil {
		return nil, status.Error(codes.Unimplemented, "knowledge service is unavailable")
	}
	capabilities, err := service.coordinator.Capabilities(request.GetOwnerId())
	if err != nil {
		return nil, publicKnowledgeError(err)
	}
	return &agentv1.GetKnowledgeCapabilitiesResponse{Capabilities: &agentv1.KnowledgeCapabilities{
		Config: capabilities.Config, AttachmentUpload: capabilities.AttachmentUpload, Memory: capabilities.Memory, Search: capabilities.Search,
		EmbeddingProfileIds:    append([]string(nil), capabilities.EmbeddingProfileIDs...),
		MaxAttachmentSizeBytes: capabilities.MaxAttachmentSizeBytes, MaxAttachmentChunkBytes: int32(capabilities.MaxAttachmentChunkBytes),
		MaxSearchResults: int32(capabilities.MaxSearchResults),
	}}, nil
}

func (service *KnowledgeService) GetKnowledgeConfig(ctx context.Context, request *agentv1.GetKnowledgeConfigRequest) (*agentv1.GetKnowledgeConfigResponse, error) {
	if service == nil || service.coordinator == nil {
		return nil, status.Error(codes.Unimplemented, "knowledge service is unavailable")
	}
	config, err := service.coordinator.GetConfig(ctx, request.GetOwnerId(), request.GetBindingId())
	if err != nil {
		return nil, publicKnowledgeError(err)
	}
	return &agentv1.GetKnowledgeConfigResponse{Config: knowledgeConfigToProto(config)}, nil
}

func (service *KnowledgeService) PutKnowledgeConfig(ctx context.Context, request *agentv1.PutKnowledgeConfigRequest) (*agentv1.PutKnowledgeConfigResponse, error) {
	scope, err := knowledgeMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service == nil || service.coordinator == nil {
		return nil, status.Error(codes.Unimplemented, "knowledge service is unavailable")
	}
	spec := request.GetSpec()
	command := knowledge.PutConfigCommand{
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(), BindingID: request.GetBindingId(), ExpectedRevision: request.GetExpectedRevision(),
		Spec: knowledge.ConfigSpec{DeploymentID: spec.GetDeploymentId(), ManagedServiceID: spec.GetManagedServiceId(), RecipeDigest: spec.GetRecipeDigest(),
			EmbeddingProfileID: spec.GetEmbeddingProfileId(), Enabled: spec.GetEnabled()},
	}
	if command.ExpectedRevision < 1 {
		return nil, status.Error(codes.FailedPrecondition, "knowledge binding creation is reserved for Managed acceptance")
	}
	current, err := service.coordinator.GetConfig(ctx, command.OwnerID, command.BindingID)
	if err != nil {
		return nil, publicKnowledgeError(err)
	}
	if current.OwnerID != command.OwnerID || current.BindingID != command.BindingID || !current.Spec.SameIdentity(command.Spec) {
		return nil, status.Error(codes.FailedPrecondition, "knowledge binding identity is immutable")
	}
	config, err := service.coordinator.PutConfig(ctx, scope, command)
	if err != nil {
		return nil, publicKnowledgeError(err)
	}
	return &agentv1.PutKnowledgeConfigResponse{Config: knowledgeConfigToProto(config)}, nil
}

func (service *KnowledgeService) ListKnowledgeSources(ctx context.Context, request *agentv1.ListKnowledgeSourcesRequest) (*agentv1.ListKnowledgeSourcesResponse, error) {
	if service == nil || service.coordinator == nil {
		return nil, status.Error(codes.Unimplemented, "knowledge service is unavailable")
	}
	after, err := decodeKnowledgePageToken(request.GetPageToken())
	if err != nil {
		return nil, publicKnowledgeError(err)
	}
	page, err := service.coordinator.ListSources(ctx, knowledge.ListSourcesQuery{
		OwnerID: request.GetOwnerId(), BindingID: request.GetBindingId(), PageSize: int(request.GetPageSize()), AfterSourceID: after,
	})
	if err != nil {
		return nil, publicKnowledgeError(err)
	}
	response := &agentv1.ListKnowledgeSourcesResponse{Sources: make([]*agentv1.KnowledgeSource, 0, len(page.Sources))}
	for _, source := range page.Sources {
		response.Sources = append(response.Sources, knowledgeSourceToProto(source))
	}
	response.NextPageToken = encodeKnowledgePageToken(page.NextSourceID)
	return response, nil
}

func (service *KnowledgeService) StartKnowledgeAttachmentUpload(ctx context.Context, request *agentv1.StartKnowledgeAttachmentUploadRequest) (*agentv1.StartKnowledgeAttachmentUploadResponse, error) {
	scope, err := knowledgeMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service == nil || service.coordinator == nil {
		return nil, status.Error(codes.Unimplemented, "knowledge service is unavailable")
	}
	upload, err := service.coordinator.StartAttachmentUpload(ctx, scope, knowledge.StartAttachmentUploadCommand{
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(), BindingID: request.GetBindingId(), SourceID: request.GetSourceId(),
		UploadID: request.GetUploadId(), MediaType: request.GetMediaType(), DeclaredSizeBytes: request.GetDeclaredSizeBytes(),
		ExpectedBindingRevision: request.GetExpectedBindingRevision(),
		Title:                   request.GetTitle(),
	})
	if err != nil {
		return nil, publicKnowledgeError(err)
	}
	return &agentv1.StartKnowledgeAttachmentUploadResponse{Upload: knowledgeUploadToProto(upload)}, nil
}

func (service *KnowledgeService) AppendKnowledgeAttachmentChunk(ctx context.Context, request *agentv1.AppendKnowledgeAttachmentChunkRequest) (*agentv1.AppendKnowledgeAttachmentChunkResponse, error) {
	scope, err := knowledgeMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service == nil || service.coordinator == nil {
		return nil, status.Error(codes.Unimplemented, "knowledge service is unavailable")
	}
	chunk := append([]byte(nil), request.GetChunk()...)
	defer clear(chunk)
	upload, err := service.coordinator.AppendAttachmentChunk(ctx, scope, knowledge.AppendAttachmentChunkCommand{
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(), BindingID: request.GetBindingId(), UploadID: request.GetUploadId(),
		ExpectedUploadRevision: request.GetExpectedUploadRevision(), OffsetBytes: request.GetOffsetBytes(), ChunkOrdinal: request.GetChunkOrdinal(),
		Chunk: chunk, ChunkSHA256: request.GetChunkSha256(),
	})
	if err != nil {
		return nil, publicKnowledgeError(err)
	}
	return &agentv1.AppendKnowledgeAttachmentChunkResponse{Upload: knowledgeUploadToProto(upload)}, nil
}

func (service *KnowledgeService) CommitKnowledgeAttachmentUpload(ctx context.Context, request *agentv1.CommitKnowledgeAttachmentUploadRequest) (*agentv1.CommitKnowledgeAttachmentUploadResponse, error) {
	scope, err := knowledgeMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service == nil || service.coordinator == nil {
		return nil, status.Error(codes.Unimplemented, "knowledge service is unavailable")
	}
	upload, source, err := service.coordinator.CommitAttachmentUpload(ctx, scope, knowledge.CommitAttachmentUploadCommand{
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(), BindingID: request.GetBindingId(), UploadID: request.GetUploadId(),
		ExpectedUploadRevision: request.GetExpectedUploadRevision(), ContentSHA256: request.GetContentSha256(),
	})
	if err != nil {
		return nil, publicKnowledgeError(err)
	}
	return &agentv1.CommitKnowledgeAttachmentUploadResponse{Upload: knowledgeUploadToProto(upload), Source: knowledgeSourceToProto(source)}, nil
}

func (service *KnowledgeService) CreateKnowledgeMemory(ctx context.Context, request *agentv1.CreateKnowledgeMemoryRequest) (*agentv1.CreateKnowledgeMemoryResponse, error) {
	scope, err := knowledgeMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service == nil || service.coordinator == nil {
		return nil, status.Error(codes.Unimplemented, "knowledge service is unavailable")
	}
	content := append([]byte(nil), request.GetContent()...)
	defer clear(content)
	source, err := service.coordinator.CreateMemory(ctx, scope, knowledge.CreateMemoryCommand{
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(), BindingID: request.GetBindingId(), SourceID: request.GetSourceId(),
		ExpectedBindingRevision: request.GetExpectedBindingRevision(), Content: content, ContentSHA256: request.GetContentSha256(),
		Title: request.GetTitle(),
	})
	if err != nil {
		return nil, publicKnowledgeError(err)
	}
	return &agentv1.CreateKnowledgeMemoryResponse{Source: knowledgeSourceToProto(source)}, nil
}

func (service *KnowledgeService) DeleteKnowledgeSource(ctx context.Context, request *agentv1.DeleteKnowledgeSourceRequest) (*agentv1.DeleteKnowledgeSourceResponse, error) {
	scope, err := knowledgeMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service == nil || service.coordinator == nil {
		return nil, status.Error(codes.Unimplemented, "knowledge service is unavailable")
	}
	source, err := service.coordinator.DeleteSource(ctx, scope, knowledge.DeleteSourceCommand{
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(), BindingID: request.GetBindingId(), SourceID: request.GetSourceId(),
		ExpectedBindingRevision: request.GetExpectedBindingRevision(), ExpectedSourceRevision: request.GetExpectedSourceRevision(),
	})
	if err != nil {
		return nil, publicKnowledgeError(err)
	}
	return &agentv1.DeleteKnowledgeSourceResponse{Source: knowledgeSourceToProto(source)}, nil
}

func (service *KnowledgeService) SearchKnowledge(ctx context.Context, request *agentv1.SearchKnowledgeRequest) (*agentv1.SearchKnowledgeResponse, error) {
	if service == nil || service.coordinator == nil {
		return nil, status.Error(codes.Unimplemented, "knowledge service is unavailable")
	}
	result, err := service.coordinator.Search(ctx, knowledge.SearchQuery{
		OwnerID: request.GetOwnerId(), BindingID: request.GetBindingId(), ExpectedBindingRevision: request.GetExpectedBindingRevision(),
		Query: request.GetQuery(), Limit: int(request.GetLimit()), SourceIDs: append([]string(nil), request.GetSourceIds()...),
	})
	if err != nil {
		return nil, publicKnowledgeError(err)
	}
	response := &agentv1.SearchKnowledgeResponse{BindingRevision: result.BindingRevision, Matches: make([]*agentv1.KnowledgeSearchMatch, 0, len(result.Matches))}
	for _, match := range result.Matches {
		response.Matches = append(response.Matches, &agentv1.KnowledgeSearchMatch{SourceId: match.SourceID, ChunkRef: match.ChunkRef, Score: match.Score})
	}
	return response, nil
}

func (service *KnowledgeService) GetKnowledgeStatus(ctx context.Context, request *agentv1.GetKnowledgeStatusRequest) (*agentv1.GetKnowledgeStatusResponse, error) {
	if service == nil || service.coordinator == nil {
		return nil, status.Error(codes.Unimplemented, "knowledge service is unavailable")
	}
	value, err := service.coordinator.Status(ctx, request.GetOwnerId(), request.GetBindingId())
	if err != nil {
		return nil, publicKnowledgeError(err)
	}
	return &agentv1.GetKnowledgeStatusResponse{Status: &agentv1.KnowledgeStatus{
		OwnerId: value.OwnerID, BindingId: value.BindingID, Enabled: value.Enabled, BackendStatus: knowledgeBackendStatusToProto(value.BackendStatus),
		ReadySourceCount: int32(value.ReadySourceCount), UploadingSourceCount: int32(value.UploadingSourceCount),
		FailedSourceCount: int32(value.FailedSourceCount), BindingRevision: value.BindingRevision, CheckedAt: timestamppb.New(value.CheckedAt),
	}}, nil
}

func knowledgeMutationScope(ctx context.Context) (knowledge.MutationScope, error) {
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok {
		return knowledge.MutationScope{}, status.Error(codes.Unauthenticated, "authenticated caller is required")
	}
	scope := knowledge.MutationScope{ClientID: principal.ClientID, CredentialID: principal.CredentialID}
	if err := scope.Validate(); err != nil {
		return knowledge.MutationScope{}, status.Error(codes.Unauthenticated, "authenticated caller identity is invalid")
	}
	return scope, nil
}

func publicKnowledgeError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, knowledge.ErrInvalid), errors.Is(err, knowledge.ErrInvalidCaller):
		return status.Error(codes.InvalidArgument, "knowledge request is invalid")
	case errors.Is(err, knowledge.ErrNotFound):
		return status.Error(codes.NotFound, "requested knowledge entity was not found")
	case errors.Is(err, knowledge.ErrRevision):
		return status.Error(codes.Aborted, "knowledge revision does not match")
	case errors.Is(err, knowledge.ErrConflict):
		return status.Error(codes.AlreadyExists, "knowledge idempotency or ordering conflict")
	case errors.Is(err, knowledge.ErrImmutableConfig), errors.Is(err, knowledge.ErrState), errors.Is(err, knowledge.ErrAmbiguousConfig):
		return status.Error(codes.FailedPrecondition, "knowledge binding state does not allow the operation")
	case errors.Is(err, knowledge.ErrUnavailable):
		return status.Error(codes.Unavailable, "knowledge backend is unavailable")
	default:
		return status.Error(codes.Internal, "knowledge operation failed")
	}
}

func knowledgeConfigToProto(config knowledge.Config) *agentv1.KnowledgeConfig {
	return &agentv1.KnowledgeConfig{
		OwnerId: config.OwnerID, BindingId: config.BindingID, Revision: config.Revision,
		Spec: &agentv1.KnowledgeConfigSpec{DeploymentId: config.Spec.DeploymentID, ManagedServiceId: config.Spec.ManagedServiceID,
			RecipeDigest: config.Spec.RecipeDigest, EmbeddingProfileId: config.Spec.EmbeddingProfileID, Enabled: config.Spec.Enabled},
		CreatedAt: timestamppb.New(config.CreatedAt), UpdatedAt: timestamppb.New(config.UpdatedAt),
	}
}

func knowledgeSourceToProto(source knowledge.Source) *agentv1.KnowledgeSource {
	return &agentv1.KnowledgeSource{
		OwnerId: source.OwnerID, BindingId: source.BindingID, SourceId: source.SourceID,
		Kind: knowledgeSourceKindToProto(source.Kind), Status: knowledgeSourceStatusToProto(source.Status), MediaType: source.MediaType,
		SizeBytes: source.SizeBytes, ContentSha256: source.ContentSHA256, ChunkCount: source.ChunkCount, Revision: source.Revision,
		CreatedAt: timestamppb.New(source.CreatedAt), UpdatedAt: timestamppb.New(source.UpdatedAt),
		Title: source.Title, ErrorCode: source.ErrorCode,
	}
}

func knowledgeUploadToProto(upload knowledge.AttachmentUpload) *agentv1.KnowledgeAttachmentUpload {
	return &agentv1.KnowledgeAttachmentUpload{
		OwnerId: upload.OwnerID, BindingId: upload.BindingID, SourceId: upload.SourceID, UploadId: upload.UploadID,
		Status: knowledgeUploadStatusToProto(upload.Status), MediaType: upload.MediaType, DeclaredSizeBytes: upload.DeclaredSizeBytes,
		ReceivedSizeBytes: upload.ReceivedSizeBytes, NextChunkOrdinal: upload.NextChunkOrdinal, Revision: upload.Revision,
		CreatedAt: timestamppb.New(upload.CreatedAt), UpdatedAt: timestamppb.New(upload.UpdatedAt),
		BindingRevision: upload.BindingRevision,
	}
}

func knowledgeSourceKindToProto(value knowledge.SourceKind) agentv1.KnowledgeSourceKind {
	switch value {
	case knowledge.SourceAttachment:
		return agentv1.KnowledgeSourceKind_KNOWLEDGE_SOURCE_KIND_ATTACHMENT
	case knowledge.SourceMemory:
		return agentv1.KnowledgeSourceKind_KNOWLEDGE_SOURCE_KIND_MEMORY
	default:
		return agentv1.KnowledgeSourceKind_KNOWLEDGE_SOURCE_KIND_UNSPECIFIED
	}
}

func knowledgeSourceStatusToProto(value knowledge.SourceStatus) agentv1.KnowledgeSourceStatus {
	switch value {
	case knowledge.SourceUploading:
		return agentv1.KnowledgeSourceStatus_KNOWLEDGE_SOURCE_STATUS_UPLOADING
	case knowledge.SourceReady:
		return agentv1.KnowledgeSourceStatus_KNOWLEDGE_SOURCE_STATUS_READY
	case knowledge.SourceDeleting:
		return agentv1.KnowledgeSourceStatus_KNOWLEDGE_SOURCE_STATUS_DELETING
	case knowledge.SourceDeleted:
		return agentv1.KnowledgeSourceStatus_KNOWLEDGE_SOURCE_STATUS_DELETED
	case knowledge.SourceFailed:
		return agentv1.KnowledgeSourceStatus_KNOWLEDGE_SOURCE_STATUS_FAILED
	default:
		return agentv1.KnowledgeSourceStatus_KNOWLEDGE_SOURCE_STATUS_UNSPECIFIED
	}
}

func knowledgeUploadStatusToProto(value knowledge.UploadStatus) agentv1.KnowledgeUploadStatus {
	switch value {
	case knowledge.UploadReceiving:
		return agentv1.KnowledgeUploadStatus_KNOWLEDGE_UPLOAD_STATUS_RECEIVING
	case knowledge.UploadCommitted:
		return agentv1.KnowledgeUploadStatus_KNOWLEDGE_UPLOAD_STATUS_COMMITTED
	case knowledge.UploadFailed:
		return agentv1.KnowledgeUploadStatus_KNOWLEDGE_UPLOAD_STATUS_FAILED
	default:
		return agentv1.KnowledgeUploadStatus_KNOWLEDGE_UPLOAD_STATUS_UNSPECIFIED
	}
}

func knowledgeBackendStatusToProto(value knowledge.BackendStatus) agentv1.KnowledgeBackendStatus {
	switch value {
	case knowledge.BackendReady:
		return agentv1.KnowledgeBackendStatus_KNOWLEDGE_BACKEND_STATUS_READY
	case knowledge.BackendDegraded:
		return agentv1.KnowledgeBackendStatus_KNOWLEDGE_BACKEND_STATUS_DEGRADED
	case knowledge.BackendUnavailable:
		return agentv1.KnowledgeBackendStatus_KNOWLEDGE_BACKEND_STATUS_UNAVAILABLE
	default:
		return agentv1.KnowledgeBackendStatus_KNOWLEDGE_BACKEND_STATUS_UNSPECIFIED
	}
}

func encodeKnowledgePageToken(sourceID string) string {
	if sourceID == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(sourceID))
}

func decodeKnowledgePageToken(token string) (string, error) {
	if token == "" {
		return "", nil
	}
	if len(token) > 128 || strings.ContainsAny(token, "\r\n\t ") {
		return "", knowledge.ErrInvalid
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != 36 {
		return "", knowledge.ErrInvalid
	}
	return string(decoded), nil
}
