package coreknowledge

import (
	"context"
	"testing"
	"time"
)

type autoIndexRepository struct {
	*MemoryRepository
	config     EmbeddingConfig
	candidates []Source
}

func (r *autoIndexRepository) GetEmbeddingConfig(context.Context) (EmbeddingConfig, error) {
	return r.config, nil
}

func (r *autoIndexRepository) ListAutoIndexCandidates(_ context.Context, profileID, digest string, limit int) ([]Source, error) {
	result := make([]Source, 0, limit)
	for _, source := range r.candidates {
		if profileID == r.config.EmbeddingProfileID && digest == r.config.CollectionConfigDigest {
			result = append(result, source)
			if len(result) == limit {
				break
			}
		}
	}
	return result, nil
}

type recordingIndexer struct {
	requests      []IndexRequest
	existing      TaskReference
	existingFound bool
}

func (i *recordingIndexer) RequestIndex(_ context.Context, request IndexRequest) (TaskReference, error) {
	i.requests = append(i.requests, request)
	return TaskReference{TaskID: "00000000-0000-4000-8000-000000000001"}, nil
}

func (i *recordingIndexer) FindExistingIndex(context.Context, IndexRequest) (TaskReference, bool, error) {
	return i.existing, i.existingFound, nil
}

func TestServiceAutomaticallyIndexesMutationsWithDeterministicReplayKey(t *testing.T) {
	base, err := NewMemoryRepository(time.Now, testOpener{}, NewMemoryContentPort(1<<20), referenceFence{})
	if err != nil {
		t.Fatal(err)
	}
	repo := &autoIndexRepository{MemoryRepository: base, config: EmbeddingConfig{EmbeddingProfileID: "11111111-1111-4111-8111-111111111111", CollectionConfigDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Revision: 1}}
	indexer := &recordingIndexer{}
	service, err := NewService(repo, indexer)
	if err != nil {
		t.Fatal(err)
	}
	key := "22222222-2222-4222-8222-222222222222"
	first, err := service.CreateMemory(context.Background(), MemoryCommand{IdempotencyKey: key, SourceID: "33333333-3333-4333-8333-333333333333", Content: "durable memory", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	if len(indexer.requests) != 1 || len(indexer.requests[0].SourceIDs) != 1 || indexer.requests[0].SourceIDs[0] != first.ID {
		t.Fatalf("automatic index request = %#v", indexer.requests)
	}
	second, err := service.CreateMemory(context.Background(), MemoryCommand{IdempotencyKey: key, SourceID: first.ID, Content: "durable memory", MediaType: "text/plain"})
	if err != nil || second.ID != first.ID {
		t.Fatalf("memory replay = %+v err=%v", second, err)
	}
	if len(indexer.requests) != 2 || indexer.requests[0].IdempotencyKey != indexer.requests[1].IdempotencyKey {
		t.Fatalf("automatic replay key changed: %#v", indexer.requests)
	}
}

func TestServiceReconcileAutoIndexIsRestartSafeAndBounded(t *testing.T) {
	base, err := NewMemoryRepository(time.Now, testOpener{}, NewMemoryContentPort(1<<20), referenceFence{})
	if err != nil {
		t.Fatal(err)
	}
	repo := &autoIndexRepository{MemoryRepository: base, config: EmbeddingConfig{EmbeddingProfileID: "11111111-1111-4111-8111-111111111111", CollectionConfigDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Revision: 1}}
	indexer := &recordingIndexer{}
	service, err := NewService(repo, indexer)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := base.CreateMemory(context.Background(), MemoryCommand{IdempotencyKey: "44444444-4444-4444-8444-444444444444", SourceID: "33333333-3333-4333-8333-333333333333", Content: "queued memory", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	repo.candidates = []Source{candidate}
	if err := service.ReconcileAutoIndex(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if len(indexer.requests) != 1 || indexer.requests[0].SourceIDs[0] != repo.candidates[0].ID {
		t.Fatalf("reconcile request = %#v", indexer.requests)
	}
	if err := service.ReconcileAutoIndex(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(indexer.requests) != 2 || indexer.requests[0].IdempotencyKey != indexer.requests[1].IdempotencyKey {
		t.Fatalf("restart reconcile key changed: %#v", indexer.requests)
	}
}

func TestServiceAutomaticallyIndexesCommittedUploadsAndMemoryUpdates(t *testing.T) {
	base, err := NewMemoryRepository(time.Now, testOpener{}, NewMemoryContentPort(1<<20), referenceFence{})
	if err != nil {
		t.Fatal(err)
	}
	repo := &autoIndexRepository{MemoryRepository: base, config: EmbeddingConfig{EmbeddingProfileID: "11111111-1111-4111-8111-111111111111", CollectionConfigDigest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", Revision: 1}}
	indexer := &recordingIndexer{}
	service, err := NewService(repo, indexer)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	payload := []byte("committed upload")
	upload, err := service.StartUpload(ctx, UploadMetadata{IdempotencyKey: "55555555-5555-4555-8555-555555555555", MediaType: "text/plain", DeclaredSize: int64(len(payload)), ContentSHA256: digestBytes(payload)})
	if err != nil {
		t.Fatal(err)
	}
	upload, err = service.AppendUploadChunk(ctx, UploadChunk{IdempotencyKey: "66666666-6666-4666-8666-666666666666", UploadID: upload.ID, Ordinal: 0, Data: payload, ChunkSHA256: digestBytes(payload)})
	if err != nil {
		t.Fatal(err)
	}
	_, uploaded, err := service.CommitUpload(ctx, CommitUploadCommand{IdempotencyKey: "77777777-7777-4777-8777-777777777777", UploadID: upload.ID, ExpectedRevision: upload.Revision, ContentSHA256: digestBytes(payload)})
	if err != nil {
		t.Fatal(err)
	}
	if len(indexer.requests) != 1 || indexer.requests[0].SourceIDs[0] != uploaded.ID {
		t.Fatalf("automatic upload index request = %#v", indexer.requests)
	}
	memory, err := service.CreateMemory(ctx, MemoryCommand{IdempotencyKey: "88888888-8888-4888-8888-888888888888", SourceID: "99999999-9999-4999-8999-999999999999", Content: "before update", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := service.UpdateMemory(ctx, UpdateMemoryCommand{IdempotencyKey: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", SourceID: memory.ID, ExpectedRevision: memory.Revision, Content: "after update", ContentSHA256: digestBytes([]byte("after update")), MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	if len(indexer.requests) != 3 || indexer.requests[1].SourceIDs[0] != memory.ID || indexer.requests[2].SourceIDs[0] != updated.ID {
		t.Fatalf("automatic memory index requests = %#v", indexer.requests)
	}
	if indexer.requests[1].IdempotencyKey == indexer.requests[2].IdempotencyKey {
		t.Fatalf("memory revision did not change automatic replay key: %#v", indexer.requests)
	}
}

type ineligibleResolveRepository struct {
	*MemoryRepository
}

func (*ineligibleResolveRepository) ResolveSources(context.Context, []string) error {
	return ErrIneligible
}

func TestServiceExplicitIndexConvergesOnActiveAutomaticTask(t *testing.T) {
	base, err := NewMemoryRepository(time.Now, testOpener{}, NewMemoryContentPort(1<<20), referenceFence{})
	if err != nil {
		t.Fatal(err)
	}
	source, err := base.CreateMemory(context.Background(), MemoryCommand{IdempotencyKey: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", SourceID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Content: "active index", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	indexer := &recordingIndexer{existing: TaskReference{TaskID: "00000000-0000-4000-8000-000000000002"}, existingFound: true}
	service, err := NewService(&ineligibleResolveRepository{MemoryRepository: base}, indexer)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := service.Index(context.Background(), IndexRequest{IdempotencyKey: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", SourceIDs: []string{source.ID}})
	if err != nil || ref.TaskID != indexer.existing.TaskID || len(indexer.requests) != 0 {
		t.Fatalf("explicit index did not converge on active task: ref=%+v err=%v requests=%#v", ref, err, indexer.requests)
	}
	indexer.existingFound = false
	if _, err := service.Index(context.Background(), IndexRequest{IdempotencyKey: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", SourceIDs: []string{source.ID}}); err != ErrIneligible {
		t.Fatalf("unmatched active task error=%v, want %v", err, ErrIneligible)
	}
}

func TestServiceBindEmbeddingProfilePreservesCollectionAndIsReplaySafe(t *testing.T) {
	base, err := NewMemoryRepository(time.Now, testOpener{}, NewMemoryContentPort(1<<20), referenceFence{})
	if err != nil {
		t.Fatal(err)
	}
	initial := EmbeddingConfig{EmbeddingProfileID: "11111111-1111-4111-8111-111111111111", Dimension: 2, Collection: "knowledge", CollectionConfigDigest: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", Revision: 1}
	if _, err := base.EnsureEmbeddingConfig(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := service.BindEmbeddingProfile(context.Background(), "22222222-2222-4222-8222-222222222222")
	if err != nil {
		t.Fatal(err)
	}
	if bound.EmbeddingProfileID != "22222222-2222-4222-8222-222222222222" || bound.Dimension != initial.Dimension || bound.Collection != initial.Collection || bound.CollectionConfigDigest != initial.CollectionConfigDigest || bound.Revision != initial.Revision+1 {
		t.Fatalf("binding changed immutable collection settings: %+v", bound)
	}
	replayed, err := service.BindEmbeddingProfile(context.Background(), bound.EmbeddingProfileID)
	if err != nil || replayed.Revision != bound.Revision {
		t.Fatalf("binding replay changed config: %+v err=%v", replayed, err)
	}
}

func TestServiceBindEmbeddingProfileMakesReadySourcesAutoIndexCandidates(t *testing.T) {
	base, err := NewMemoryRepository(time.Now, testOpener{}, NewMemoryContentPort(1<<20), referenceFence{})
	if err != nil {
		t.Fatal(err)
	}
	repo := &autoIndexRepository{MemoryRepository: base, config: EmbeddingConfig{EmbeddingProfileID: "11111111-1111-4111-8111-111111111111", Dimension: 2, Collection: "knowledge", CollectionConfigDigest: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", Revision: 1}}
	if _, err := base.EnsureEmbeddingConfig(context.Background(), repo.config); err != nil {
		t.Fatal(err)
	}
	source, err := base.CreateMemory(context.Background(), MemoryCommand{IdempotencyKey: "33333333-3333-4333-8333-333333333333", SourceID: "44444444-4444-4444-8444-444444444444", Content: "stale after profile switch", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	repo.candidates = []Source{source}
	indexer := &recordingIndexer{}
	service, err := NewService(repo, indexer)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := service.BindEmbeddingProfile(context.Background(), "55555555-5555-4555-8555-555555555555")
	if err != nil {
		t.Fatal(err)
	}
	repo.config = bound
	if err := service.ReconcileAutoIndex(context.Background(), 8); err != nil {
		t.Fatal(err)
	}
	if len(indexer.requests) != 1 || indexer.requests[0].SourceIDs[0] != source.ID {
		t.Fatalf("stale source was not requeued after binding: %#v", indexer.requests)
	}
}
