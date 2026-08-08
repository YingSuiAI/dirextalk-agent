package coreknowledge

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

type Service struct {
	repository Repository
	indexer    Indexer
}

func NewService(repository Repository, indexer Indexer) (*Service, error) {
	if repository == nil || repository.ContentPort() == nil {
		return nil, ErrInvalid
	}
	return &Service{repository: repository, indexer: indexer}, nil
}

func (s *Service) CreateMount(ctx context.Context, command MountCommand) (Source, error) {
	if err := command.validate(); err != nil {
		return Source{}, err
	}
	value, err := s.repository.CreateMount(ctx, command)
	if err == nil {
		s.requestAutomaticIndex(ctx, value)
	}
	return value, safeError(err)
}
func (s *Service) StartUpload(ctx context.Context, metadata UploadMetadata) (Upload, error) {
	if err := metadata.validate(); err != nil {
		return Upload{}, err
	}
	value, err := s.repository.StartUpload(ctx, metadata)
	return value, safeError(err)
}
func (s *Service) AppendUploadChunk(ctx context.Context, chunk UploadChunk) (Upload, error) {
	if err := chunk.validate(); err != nil {
		return Upload{}, err
	}
	value, err := s.repository.AppendUploadChunk(ctx, chunk)
	return value, safeError(err)
}
func (s *Service) CommitUpload(ctx context.Context, command CommitUploadCommand) (Upload, Source, error) {
	if err := command.validate(); err != nil {
		return Upload{}, Source{}, err
	}
	upload, source, err := s.repository.CommitUpload(ctx, command)
	if err == nil {
		s.requestAutomaticIndex(ctx, source)
	}
	return upload, source, safeError(err)
}

// AbortUpload is an idempotent, revision-bound cancellation of a receiving
// upload. Repository implementations retain the durable cleanup intent.
func (s *Service) AbortUpload(ctx context.Context, command AbortUploadCommand) error {
	if s == nil || s.repository == nil {
		return ErrInvalid
	}
	return s.repository.AbortUpload(ctx, command)
}
func (s *Service) CreateMemory(ctx context.Context, command MemoryCommand) (Source, error) {
	command = NormalizeMemoryCommand(command)
	if err := command.validate(); err != nil {
		return Source{}, err
	}
	value, err := s.repository.CreateMemory(ctx, command)
	if err == nil {
		s.requestAutomaticIndex(ctx, value)
	}
	return value, safeError(err)
}
func (s *Service) UpdateMemory(ctx context.Context, command UpdateMemoryCommand) (Source, error) {
	if err := command.validate(); err != nil {
		return Source{}, err
	}
	value, err := s.repository.UpdateMemory(ctx, command)
	if err == nil {
		s.requestAutomaticIndex(ctx, value)
	}
	return value, safeError(err)
}
func (s *Service) Get(ctx context.Context, id string) (Source, error) {
	value, err := s.repository.Get(ctx, id)
	return value, safeError(err)
}

// GetUpload returns the durable upload cursor for resumable transport calls.
// The repository remains the authority for revision and next ordinal.
func (s *Service) GetUpload(ctx context.Context, id string) (Upload, error) {
	reader, ok := s.repository.(UploadReader)
	if !ok {
		return Upload{}, ErrNotFound
	}
	value, err := reader.GetUpload(ctx, id)
	return value, safeError(err)
}

func (s *Service) GetMemory(ctx context.Context, id string) (Memory, error) {
	reader, ok := s.repository.(MemoryReader)
	if !ok {
		return Memory{}, ErrNotFound
	}
	value, err := reader.GetMemory(ctx, id)
	return value, safeError(err)
}

func (s *Service) ListMemories(ctx context.Context, query ListQuery) (MemoryPage, error) {
	if query.Kind == "" {
		query.Kind = SourceKindMemory
	}
	if err := query.validate(); err != nil {
		return MemoryPage{}, err
	}
	reader, ok := s.repository.(MemoryReader)
	if !ok {
		return MemoryPage{}, ErrNotFound
	}
	value, err := reader.ListMemories(ctx, query)
	return value, safeError(err)
}
func (s *Service) List(ctx context.Context, query ListQuery) (Page, error) {
	if err := query.validate(); err != nil {
		return Page{}, err
	}
	value, err := s.repository.List(ctx, query)
	return value, safeError(err)
}
func (s *Service) Delete(ctx context.Context, command DeleteCommand) (Source, error) {
	if err := command.validate(); err != nil {
		return Source{}, err
	}
	value, err := s.repository.Delete(ctx, command)
	return value, safeError(err)
}
func (s *Service) Status(ctx context.Context) (Status, error) {
	value, err := s.repository.Status(ctx)
	return value, safeError(err)
}

func (s *Service) QuotaStatus(ctx context.Context) (QuotaStatus, error) {
	reader, ok := s.repository.(QuotaStatusReader)
	if !ok {
		return QuotaStatus{}, ErrConflict
	}
	status, err := reader.QuotaStatus(ctx)
	return status, safeError(err)
}

func (s *Service) GetEmbeddingConfig(ctx context.Context) (EmbeddingConfig, error) {
	reader, ok := s.repository.(EmbeddingConfigReader)
	if !ok {
		return EmbeddingConfig{}, ErrNotFound
	}
	value, err := reader.GetEmbeddingConfig(ctx)
	return value, safeError(err)
}

// SourceEmbeddingStatus returns the repository-authoritative vector state for
// one source. The method is intentionally optional: metadata-only/in-memory
// repositories report ErrNotFound rather than pretending a ready source has a
// promoted vector.
func (s *Service) SourceEmbeddingStatus(ctx context.Context, sourceID string) (EmbeddingSourceStatus, error) {
	if s == nil || s.repository == nil || sourceID == "" {
		return EmbeddingSourceStatus{}, ErrInvalid
	}
	reader, ok := s.repository.(EmbeddingSourceStatusReader)
	if !ok {
		return EmbeddingSourceStatus{}, ErrNotFound
	}
	config, err := s.GetEmbeddingConfig(ctx)
	if err != nil {
		return EmbeddingSourceStatus{}, err
	}
	return reader.GetEmbeddingSourceStatus(ctx, sourceID, config)
}

// ReconcileAutoIndex scans the durable source projection and enqueues missing
// or stale generations. It is safe to call at startup and periodically: the
// source CAS in RequestIndex plus its deterministic idempotency key make a
// crash between a metadata commit and task creation replayable.
func (s *Service) ReconcileAutoIndex(ctx context.Context, limit int) error {
	if s == nil || s.repository == nil || s.indexer == nil {
		return nil
	}
	reader, ok := s.repository.(AutoIndexCandidateReader)
	if !ok {
		return nil
	}
	if limit <= 0 || limit > 256 {
		limit = 64
	}
	config, err := s.GetEmbeddingConfig(ctx)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	if config.EmbeddingProfileID == uuid.Nil.String() {
		return nil
	}
	candidates, err := reader.ListAutoIndexCandidates(ctx, config.EmbeddingProfileID, config.CollectionConfigDigest, limit)
	if err != nil {
		return err
	}
	for _, source := range candidates {
		s.requestAutomaticIndexWithConfig(ctx, source, config)
	}
	return nil
}

func (s *Service) requestAutomaticIndex(ctx context.Context, source Source) {
	if s == nil || s.indexer == nil || source.ID == "" || source.Revision <= 0 {
		return
	}
	config, err := s.GetEmbeddingConfig(ctx)
	if err != nil {
		return
	}
	s.requestAutomaticIndexWithConfig(ctx, source, config)
}

func (s *Service) requestAutomaticIndexWithConfig(ctx context.Context, source Source, config EmbeddingConfig) {
	if s == nil || s.indexer == nil || source.ID == "" || source.Revision <= 0 || config.EmbeddingProfileID == "" || config.EmbeddingProfileID == uuid.Nil.String() || config.CollectionConfigDigest == "" {
		return
	}
	profileRevision := config.EmbeddingProfileRevision
	var expectedBinding *ActiveEmbeddingBinding
	if reader, ok := s.repository.(ActiveEmbeddingBindingReader); ok {
		binding, err := reader.ActiveEmbeddingBinding(ctx)
		if err != nil || binding.ProfileID != config.EmbeddingProfileID || binding.ProfileRevision <= 0 || !strings.EqualFold(binding.CollectionDigest, config.CollectionConfigDigest) {
			return
		}
		profileRevision = binding.ProfileRevision
		expectedBinding = &binding
	}
	key := uuid.NewSHA1(uuid.NameSpaceURL, []byte("dirextalk/knowledge/auto-index/"+source.ID+"/"+strconv.FormatInt(source.Revision, 10)+"/"+config.EmbeddingProfileID+"/"+strconv.FormatInt(profileRevision, 10)+"/"+config.CollectionConfigDigest)).String()
	_, _ = s.Index(ctx, IndexRequest{SourceIDs: []string{source.ID}, IdempotencyKey: key, ExpectedBinding: expectedBinding})
}

// EmbeddingStatus returns promoted/stale vector counts when the repository
// exposes an authoritative generation projection. Older or in-memory
// repositories intentionally return ErrNotFound so callers can report a
// conservative zero-indexed status without fabricating promotion.
func (s *Service) EmbeddingStatus(ctx context.Context) (indexed, stale int, err error) {
	reader, ok := s.repository.(EmbeddingStatusReader)
	if !ok {
		return 0, 0, ErrNotFound
	}
	indexed, stale, err = reader.EmbeddingStatus(ctx)
	if err != nil {
		return 0, 0, safeError(err)
	}
	if indexed < 0 || stale < 0 {
		return 0, 0, ErrConflict
	}
	return indexed, stale, nil
}

func (s *Service) UpdateEmbeddingConfig(ctx context.Context, command EmbeddingConfigCommand) (EmbeddingConfig, error) {
	if !validUUID(command.IdempotencyKey) || command.ExpectedRevision < 1 || !validUUID(command.EmbeddingProfileID) || command.Dimension <= 0 || command.Dimension > 16384 || command.Collection == "" || len(command.Collection) > 255 {
		return EmbeddingConfig{}, ErrInvalid
	}
	store, ok := s.repository.(EmbeddingConfigStore)
	if !ok {
		return EmbeddingConfig{}, ErrNotFound
	}
	value, err := store.UpdateEmbeddingConfig(ctx, command)
	return value, safeError(err)
}

// BindEmbeddingProfile switches the owner-scoped embedding profile while
// preserving the collection and vector dimension.  The profile binding is a
// separate durable transaction from model sync, so callers must treat a
// returned error as a failed synchronization and retry with the same
// idempotency key; a restart/reconcile can safely converge an already applied
// binding because the desired profile is checked before issuing a mutation.
func (s *Service) BindEmbeddingProfile(ctx context.Context, profileID string) (EmbeddingConfig, error) {
	if s == nil || s.repository == nil || !validUUID(profileID) {
		return EmbeddingConfig{}, ErrInvalid
	}
	for attempt := 0; attempt < 2; attempt++ {
		current, err := s.GetEmbeddingConfig(ctx)
		if err != nil {
			return EmbeddingConfig{}, err
		}
		if current.EmbeddingProfileID == profileID {
			return current, nil
		}
		key := uuid.NewSHA1(uuid.NameSpaceURL, []byte("dirextalk/knowledge/bind-embedding/"+profileID+"/"+strconv.FormatInt(current.Revision, 10))).String()
		bound, updateErr := s.UpdateEmbeddingConfig(ctx, EmbeddingConfigCommand{
			IdempotencyKey: key, ExpectedRevision: current.Revision,
			EmbeddingProfileID: profileID, Dimension: current.Dimension,
			Collection: current.Collection, CollectionConfigDigest: current.CollectionConfigDigest,
		})
		if updateErr == nil {
			return bound, nil
		}
		if !errors.Is(updateErr, ErrRevisionConflict) {
			return EmbeddingConfig{}, updateErr
		}
	}
	return EmbeddingConfig{}, ErrRevisionConflict
}

func (s *Service) DisableEmbeddingProfile(ctx context.Context, profileID string) (EmbeddingConfig, error) {
	if s == nil || s.repository == nil || !validUUID(profileID) {
		return EmbeddingConfig{}, ErrInvalid
	}
	disabler, ok := s.repository.(EmbeddingProfileDisabler)
	if !ok {
		return EmbeddingConfig{}, ErrNotFound
	}
	value, err := disabler.DisableEmbeddingProfile(ctx, profileID)
	return value, safeError(err)
}

func (s *Service) Search(ctx context.Context, query SearchQuery) (SearchPage, error) {
	if err := query.validate(); err != nil {
		return SearchPage{}, err
	}
	value, err := s.repository.Search(ctx, query)
	return value, safeError(err)
}

func (s *Service) Index(ctx context.Context, request IndexRequest) (TaskReference, error) {
	if s.indexer == nil {
		return TaskReference{}, ErrConflict
	}
	if !validUUID(request.IdempotencyKey) {
		return TaskReference{}, ErrInvalid
	}
	seen := make(map[string]struct{}, len(request.SourceIDs))
	for _, id := range request.SourceIDs {
		if !validUUID(id) {
			return TaskReference{}, ErrInvalid
		}
		if _, ok := seen[id]; ok {
			return TaskReference{}, ErrInvalid
		}
		seen[id] = struct{}{}
	}
	if err := s.repository.ResolveSources(ctx, request.SourceIDs); err != nil {
		if errors.Is(err, ErrIneligible) {
			if reader, ok := s.indexer.(ExistingIndexReader); ok {
				if ref, found, lookupErr := reader.FindExistingIndex(ctx, request); lookupErr != nil {
					return TaskReference{}, safeError(lookupErr)
				} else if found {
					if err := ref.validate(); err != nil {
						return TaskReference{}, ErrConflict
					}
					return ref, nil
				}
			}
		}
		return TaskReference{}, safeError(err)
	}
	ref, err := s.indexer.RequestIndex(ctx, request)
	if err != nil {
		return TaskReference{}, safeError(err)
	}
	if err := ref.validate(); err != nil {
		return TaskReference{}, ErrConflict
	}
	return ref, nil
}

func safeError(err error) error {
	if err == nil {
		return nil
	}
	for _, candidate := range []error{ErrInvalid, ErrNotFound, ErrConflict, ErrIdempotencyConflict, ErrRevisionConflict, ErrChecksumMismatch, ErrPathTraversal, ErrCleanupPending} {
		if errors.Is(err, candidate) {
			return candidate
		}
	}
	for _, candidate := range []error{ErrLimitExceeded, ErrQuotaExceeded, ErrIneligible, ErrSourceReferenced, ErrCursorConflict, ErrFilesystemUnavailable} {
		if errors.Is(err, candidate) {
			return candidate
		}
	}
	return ErrConflict
}
