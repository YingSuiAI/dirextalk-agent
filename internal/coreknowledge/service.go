package coreknowledge

import (
	"context"
	"errors"
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
	if err := command.validate(); err != nil {
		return Source{}, err
	}
	value, err := s.repository.CreateMemory(ctx, command)
	return value, safeError(err)
}
func (s *Service) Get(ctx context.Context, id string) (Source, error) {
	value, err := s.repository.Get(ctx, id)
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
	for _, candidate := range []error{ErrLimitExceeded, ErrIneligible, ErrSourceReferenced, ErrCursorConflict, ErrFilesystemUnavailable} {
		if errors.Is(err, candidate) {
			return candidate
		}
	}
	return ErrConflict
}
