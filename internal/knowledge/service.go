package knowledge

import (
	"context"
	"errors"
	"strings"
	"time"
)

type Repository interface {
	GetConfig(context.Context, string, string) (Config, error)
	PutConfig(context.Context, MutationScope, PutConfigCommand) (Config, error)
	ListSources(context.Context, ListSourcesQuery) (SourcePage, error)
	StartAttachmentUpload(context.Context, MutationScope, StartAttachmentUploadCommand) (AttachmentUpload, error)
	AppendAttachmentChunk(context.Context, MutationScope, AppendAttachmentChunkCommand, func(context.Context, AttachmentChunk) error) (AttachmentUpload, error)
	CommitAttachmentUpload(context.Context, MutationScope, CommitAttachmentUploadCommand, func(context.Context, AttachmentCommit) (ContentReceipt, error)) (AttachmentUpload, Source, error)
	CreateMemory(context.Context, MutationScope, CreateMemoryCommand, func(context.Context, MemoryContent) (ContentReceipt, error)) (Source, error)
	DeleteSource(context.Context, MutationScope, DeleteSourceCommand, func(context.Context, SourceTarget) error) (Source, error)
	ValidateSearchSources(context.Context, string, string, []string) error
	StatusFacts(context.Context, string, string) (StatusFacts, error)
}

type BlobStager interface {
	// Mutations are called with immutable binding facts and stable
	// source/upload/chunk identities. Implementations must be idempotent: the
	// same exact call may be repeated after a database commit outcome is lost.
	// They must reject an existing identity with a different digest or scope.
	Available() bool
	StageAttachmentChunk(context.Context, AttachmentChunk) error
	CommitAttachment(context.Context, AttachmentCommit) (ContentReceipt, error)
	StoreMemory(context.Context, MemoryContent) (ContentReceipt, error)
	DeleteSource(context.Context, SourceTarget) error
}

type SearchBackend interface {
	Search(context.Context, Config, SearchQuery) ([]SearchMatch, error)
	Status(context.Context, Config, *PersistenceChallenge) (BackendStatus, error)
}

type Backend interface {
	BlobStager
	SearchBackend
}

type UnavailableBackend struct{}

func (UnavailableBackend) Available() bool { return false }
func (UnavailableBackend) StageAttachmentChunk(context.Context, AttachmentChunk) error {
	return ErrUnavailable
}
func (UnavailableBackend) CommitAttachment(context.Context, AttachmentCommit) (ContentReceipt, error) {
	return ContentReceipt{}, ErrUnavailable
}
func (UnavailableBackend) StoreMemory(context.Context, MemoryContent) (ContentReceipt, error) {
	return ContentReceipt{}, ErrUnavailable
}
func (UnavailableBackend) DeleteSource(context.Context, SourceTarget) error { return ErrUnavailable }
func (UnavailableBackend) Search(context.Context, Config, SearchQuery) ([]SearchMatch, error) {
	return nil, ErrUnavailable
}
func (UnavailableBackend) Status(context.Context, Config, *PersistenceChallenge) (BackendStatus, error) {
	return BackendUnavailable, nil
}

type Capabilities struct {
	Config                  bool
	AttachmentUpload        bool
	Memory                  bool
	Search                  bool
	EmbeddingProfileIDs     []string
	MaxAttachmentSizeBytes  int64
	MaxAttachmentChunkBytes int
	MaxSearchResults        int
}

type Service struct {
	repository Repository
	backend    Backend
	catalog    Catalog
	now        func() time.Time
}

func NewService(repository Repository, backend Backend, catalog Catalog, now func() time.Time) (*Service, error) {
	if repository == nil || backend == nil || now == nil || len(catalog.IDs()) == 0 {
		return nil, ErrInvalid
	}
	return &Service{repository: repository, backend: backend, catalog: catalog, now: now}, nil
}

func (service *Service) Capabilities(ownerID string) (Capabilities, error) {
	ownerID = stringsTrim(ownerID)
	if !validOwnerID(ownerID) {
		return Capabilities{}, ErrInvalid
	}
	available := service.backend.Available()
	return Capabilities{
		Config: true, AttachmentUpload: available, Memory: available, Search: available,
		EmbeddingProfileIDs: service.catalog.IDs(), MaxAttachmentSizeBytes: MaxAttachmentSizeBytes,
		MaxAttachmentChunkBytes: MaxAttachmentChunkBytes, MaxSearchResults: MaxSearchResults,
	}, nil
}

func (service *Service) GetConfig(ctx context.Context, ownerID, bindingID string) (Config, error) {
	ownerID, bindingID = stringsTrim(ownerID), stringsTrim(bindingID)
	if !validOwnerID(ownerID) || (bindingID != "" && !canonicalUUID(bindingID)) {
		return Config{}, ErrInvalid
	}
	return service.repository.GetConfig(ctx, ownerID, bindingID)
}

func (service *Service) PutConfig(ctx context.Context, scope MutationScope, command PutConfigCommand) (Config, error) {
	if err := scope.Validate(); err != nil {
		return Config{}, err
	}
	validated, err := command.Validated(service.catalog)
	if err != nil {
		return Config{}, err
	}
	return service.repository.PutConfig(ctx, scope, validated)
}

func (service *Service) ListSources(ctx context.Context, query ListSourcesQuery) (SourcePage, error) {
	validated, err := query.Validated()
	if err != nil {
		return SourcePage{}, err
	}
	return service.repository.ListSources(ctx, validated)
}

func (service *Service) StartAttachmentUpload(ctx context.Context, scope MutationScope, command StartAttachmentUploadCommand) (AttachmentUpload, error) {
	if err := service.requireMutation(scope); err != nil {
		return AttachmentUpload{}, err
	}
	validated, err := command.Validated()
	if err != nil {
		return AttachmentUpload{}, err
	}
	return service.repository.StartAttachmentUpload(ctx, scope, validated)
}

func (service *Service) AppendAttachmentChunk(ctx context.Context, scope MutationScope, command AppendAttachmentChunkCommand) (AttachmentUpload, error) {
	if err := service.requireMutation(scope); err != nil {
		return AttachmentUpload{}, err
	}
	validated, err := command.Validated()
	if err != nil {
		return AttachmentUpload{}, err
	}
	return service.repository.AppendAttachmentChunk(ctx, scope, validated, func(callContext context.Context, chunk AttachmentChunk) error {
		if err := service.backend.StageAttachmentChunk(callContext, chunk); err != nil {
			return ErrUnavailable
		}
		return nil
	})
}

func (service *Service) CommitAttachmentUpload(ctx context.Context, scope MutationScope, command CommitAttachmentUploadCommand) (AttachmentUpload, Source, error) {
	if err := service.requireMutation(scope); err != nil {
		return AttachmentUpload{}, Source{}, err
	}
	validated, err := command.Validated()
	if err != nil {
		return AttachmentUpload{}, Source{}, err
	}
	return service.repository.CommitAttachmentUpload(ctx, scope, validated, func(callContext context.Context, commit AttachmentCommit) (ContentReceipt, error) {
		receipt, backendErr := service.backend.CommitAttachment(callContext, commit)
		if backendErr != nil {
			return ContentReceipt{}, ErrUnavailable
		}
		if !receipt.valid(commit.DeclaredSizeBytes, commit.ContentSHA256) {
			return ContentReceipt{}, ErrInvalidBackend
		}
		return receipt, nil
	})
}

func (service *Service) CreateMemory(ctx context.Context, scope MutationScope, command CreateMemoryCommand) (Source, error) {
	if err := service.requireMutation(scope); err != nil {
		return Source{}, err
	}
	validated, err := command.Validated()
	if err != nil {
		return Source{}, err
	}
	return service.repository.CreateMemory(ctx, scope, validated, func(callContext context.Context, memory MemoryContent) (ContentReceipt, error) {
		receipt, backendErr := service.backend.StoreMemory(callContext, memory)
		if backendErr != nil {
			return ContentReceipt{}, ErrUnavailable
		}
		if !receipt.valid(int64(len(memory.Content)), memory.ContentSHA256) {
			return ContentReceipt{}, ErrInvalidBackend
		}
		return receipt, nil
	})
}

func (service *Service) DeleteSource(ctx context.Context, scope MutationScope, command DeleteSourceCommand) (Source, error) {
	if err := service.requireMutation(scope); err != nil {
		return Source{}, err
	}
	validated, err := command.Validated()
	if err != nil {
		return Source{}, err
	}
	return service.repository.DeleteSource(ctx, scope, validated, func(callContext context.Context, target SourceTarget) error {
		if err := service.backend.DeleteSource(callContext, target); err != nil {
			return ErrUnavailable
		}
		return nil
	})
}

func (service *Service) Search(ctx context.Context, query SearchQuery) (SearchResult, error) {
	validated, err := query.Validated()
	if err != nil {
		return SearchResult{}, err
	}
	config, err := service.repository.GetConfig(ctx, validated.OwnerID, validated.BindingID)
	if err != nil {
		return SearchResult{}, err
	}
	if config.OwnerID != validated.OwnerID || config.BindingID != validated.BindingID {
		return SearchResult{}, ErrNotFound
	}
	if config.Revision != validated.ExpectedBindingRevision {
		return SearchResult{}, ErrRevision
	}
	if !config.Spec.Enabled {
		return SearchResult{}, ErrState
	}
	if err := service.repository.ValidateSearchSources(ctx, config.OwnerID, config.BindingID, validated.SourceIDs); err != nil {
		return SearchResult{}, err
	}
	matches, err := service.backend.Search(ctx, config, validated)
	if err != nil {
		return SearchResult{}, ErrUnavailable
	}
	if len(matches) > validated.Limit {
		return SearchResult{}, ErrInvalidBackend
	}
	result := SearchResult{Matches: append([]SearchMatch(nil), matches...), BindingRevision: config.Revision}
	requested := make(map[string]struct{}, len(validated.SourceIDs))
	for _, sourceID := range validated.SourceIDs {
		requested[sourceID] = struct{}{}
	}
	for _, match := range result.Matches {
		if err := match.validate(); err != nil {
			return SearchResult{}, err
		}
		if len(requested) > 0 {
			if _, ok := requested[match.SourceID]; !ok {
				return SearchResult{}, ErrInvalidBackend
			}
		}
	}
	sourceIDs := make([]string, 0, len(result.Matches))
	seen := make(map[string]struct{}, len(result.Matches))
	for _, match := range result.Matches {
		if _, ok := seen[match.SourceID]; ok {
			continue
		}
		seen[match.SourceID] = struct{}{}
		sourceIDs = append(sourceIDs, match.SourceID)
	}
	if err := service.repository.ValidateSearchSources(ctx, config.OwnerID, config.BindingID, sourceIDs); err != nil {
		if errors.Is(err, ErrNotFound) {
			return SearchResult{}, ErrInvalidBackend
		}
		return SearchResult{}, err
	}
	return result, nil
}

func (service *Service) Status(ctx context.Context, ownerID, bindingID string) (Status, error) {
	config, err := service.GetConfig(ctx, ownerID, bindingID)
	if err != nil {
		return Status{}, err
	}
	facts, err := service.repository.StatusFacts(ctx, config.OwnerID, config.BindingID)
	if err != nil {
		return Status{}, err
	}
	backendStatus, err := service.backend.Status(ctx, config, facts.PersistenceChallenge)
	if err != nil {
		backendStatus = BackendUnavailable
	}
	if backendStatus != BackendUnavailable && backendStatus != BackendReady && backendStatus != BackendDegraded {
		return Status{}, ErrInvalidBackend
	}
	return Status{
		OwnerID: config.OwnerID, BindingID: config.BindingID, Enabled: config.Spec.Enabled, BackendStatus: backendStatus,
		ReadySourceCount: facts.ReadySourceCount, UploadingSourceCount: facts.UploadingSourceCount,
		FailedSourceCount: facts.FailedSourceCount, BindingRevision: config.Revision, CheckedAt: service.now().UTC(),
	}, nil
}

func (service *Service) requireMutation(scope MutationScope) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if !service.backend.Available() {
		return ErrUnavailable
	}
	return nil
}

func stringsTrim(value string) string {
	// Kept local to make every service entry normalize before repository access.
	return strings.TrimSpace(value)
}
