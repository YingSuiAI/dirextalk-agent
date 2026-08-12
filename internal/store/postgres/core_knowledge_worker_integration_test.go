package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge/semantic"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type workerEmbedding struct{}

func (workerEmbedding) Embed(context.Context, coremodel.Profile, []string) ([][]float32, error) {
	return [][]float32{{1, 0}}, nil
}

type failingWorkerEmbedding struct{}

func (failingWorkerEmbedding) Embed(context.Context, coremodel.Profile, []string) ([][]float32, error) {
	return nil, context.DeadlineExceeded
}

type workerProfiles struct{ id string }

func (p workerProfiles) ResolveProfile(context.Context, string) (coremodel.Profile, error) {
	return coremodel.Profile{ID: p.id, Provider: coremodel.ProviderOpenAICompatible, Model: "embed", APIKey: "test"}, nil
}

// blockingStageStore deterministically holds the external upsert after the
// cancellation tombstone has been committed, reproducing a late provider
// response after a sweep deleted the first staging collection.
type blockingStageStore struct {
	semantic.StagedVectorStore
	started chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	deletes int
}

func (s *blockingStageStore) UpsertGeneration(ctx context.Context, generation, sourceID string, revision int64, chunks []semantic.Chunk) error {
	s.once.Do(func() { close(s.started) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.release:
	}
	return s.StagedVectorStore.UpsertGeneration(ctx, generation, sourceID, revision, chunks)
}

func (s *blockingStageStore) DeleteGeneration(ctx context.Context, generation string) error {
	s.mu.Lock()
	s.deletes++
	s.mu.Unlock()
	return s.StagedVectorStore.DeleteGeneration(ctx, generation)
}

func (s *blockingStageStore) DeleteStagingGeneration(ctx context.Context, generation string) error {
	return s.DeleteGeneration(ctx, generation)
}

func (s *blockingStageStore) deleteCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deletes
}

func TestCoreKnowledgeWorkerPostgresRequestClaimPromoteAndSearchBinding(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	profileID := uuid.NewString()
	createTestEmbeddingProfile(ctx, t, repo.store, profileID, "embed", "test")
	mem, err := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), Title: "w", Content: "worker content", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	configDigest := strings.Repeat("a", 64)
	if _, err := repo.EnsureEmbeddingConfig(ctx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: profileID, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: configDigest, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	idx, err := NewKnowledgeIndexer(repo.store, profileID, configDigest)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := idx.RequestIndex(ctx, coreknowledge.IndexRequest{SourceIDs: []string{mem.ID}, IdempotencyKey: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(repo.store)
	task, _, err := tasks.ClaimNextDue(ctx, "knowledge-test", time.Now().UTC(), time.Minute, 1)
	if err != nil || task.ID != ref.TaskID {
		t.Fatalf("claim=%v %#v", err, task)
	}
	store, _ := semantic.NewMemoryStore(2)
	engine, _ := semantic.NewIndexEngine(semantic.IndexConfig{Embedder: workerEmbedding{}, VectorStore: store, ProfileResolver: workerProfiles{id: profileID}, EmbeddingProfileID: profileID, Dimension: 2})
	handler, _ := NewKnowledgeTaskHandler(repo.store, nil, repo.content.(*pgKnowledgeContent), engine)
	out := handler(ctx, task)
	if out.Err != nil {
		t.Fatal(out.Err)
	}
	got, err := tasks.GetTask(ctx, task.ID)
	if err != nil || got.Status != coretask.StatusSucceeded {
		t.Fatalf("task=%#v err=%v", got, err)
	}
	var promoted string
	if err := repo.store.pool.QueryRow(ctx, `SELECT promoted_generation FROM core_knowledge_sources WHERE source_id=$1`, mem.ID).Scan(&promoted); err != nil || promoted == "" {
		t.Fatalf("promoted=%q err=%v", promoted, err)
	}
}

func TestCoreKnowledgeWorkerPostgresTamperAndStageSweep(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	profileID := uuid.NewString()
	createTestProfile(ctx, t, repo.store, profileID, "embed", "test")
	mem, _ := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), Title: "w", Content: "worker content", MediaType: "text/plain"})
	cfg := strings.Repeat("b", 64)
	idx, _ := NewKnowledgeIndexer(repo.store, profileID, cfg)
	ref, err := idx.RequestIndex(ctx, coreknowledge.IndexRequest{SourceIDs: []string{mem.ID}, IdempotencyKey: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with the durable job payload before claim; handler must refuse side effects.
	_, err = repo.store.pool.Exec(ctx, `UPDATE core_knowledge_index_jobs SET expected_revisions='[999]'::jsonb WHERE task_id=$1`, ref.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(repo.store)
	task, _, err := tasks.ClaimNextDue(ctx, "knowledge-test", time.Now().UTC(), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := semantic.NewMemoryStore(2)
	engine, _ := semantic.NewIndexEngine(semantic.IndexConfig{Embedder: workerEmbedding{}, VectorStore: store, ProfileResolver: workerProfiles{id: profileID}, EmbeddingProfileID: profileID, Dimension: 2})
	handler, _ := NewKnowledgeTaskHandler(repo.store, nil, repo.content.(*pgKnowledgeContent), engine)
	out := handler(ctx, task)
	if out.Err == nil {
		t.Fatal("tamper accepted")
	}
	var status string
	_ = repo.store.pool.QueryRow(ctx, `SELECT status FROM core_knowledge_index_jobs WHERE task_id=$1`, task.ID).Scan(&status)
	if status != "failed" {
		t.Fatalf("job status=%s", status)
	}
	_ = SweepStaleKnowledgeStages(ctx, repo.store)
}

func TestCoreKnowledgeWorkerPostgresEmbeddingFailureCommitsTerminalState(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	profileID := uuid.NewString()
	createTestProfile(ctx, t, repo.store, profileID, "embed", "test")
	mem, err := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), Title: "failure", Content: "embedding failure", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := NewKnowledgeIndexer(repo.store, profileID, strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := idx.RequestIndex(ctx, coreknowledge.IndexRequest{SourceIDs: []string{mem.ID}, IdempotencyKey: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(repo.store)
	task, _, err := tasks.ClaimNextDue(ctx, "knowledge-failure", time.Now().UTC(), time.Minute, 1)
	if err != nil || task.ID != ref.TaskID {
		t.Fatalf("claim=%v %#v", err, task)
	}
	store, _ := semantic.NewMemoryStore(2)
	engine, _ := semantic.NewIndexEngine(semantic.IndexConfig{Embedder: failingWorkerEmbedding{}, VectorStore: store, ProfileResolver: workerProfiles{id: profileID}, EmbeddingProfileID: profileID, Dimension: 2})
	handler, _ := NewKnowledgeTaskHandler(repo.store, nil, repo.content.(*pgKnowledgeContent), engine)
	out := handler(ctx, task)
	if out.Err == nil || !out.TerminalOwned {
		t.Fatalf("outcome=%#v", out)
	}
	got, err := tasks.GetTask(ctx, task.ID)
	if err != nil || got.Status != coretask.StatusFailed || got.FailureCode != "knowledge_index_failed" {
		t.Fatalf("task=%#v err=%v", got, err)
	}
	var jobStatus, jobCode, sourceStatus, sourceCode string
	if err := repo.store.pool.QueryRow(ctx, `SELECT status,error_code FROM core_knowledge_index_jobs WHERE task_id=$1`, task.ID).Scan(&jobStatus, &jobCode); err != nil {
		t.Fatal(err)
	}
	if err := repo.store.pool.QueryRow(ctx, `SELECT status,error_code FROM core_knowledge_sources WHERE source_id=$1`, mem.ID).Scan(&sourceStatus, &sourceCode); err != nil {
		t.Fatal(err)
	}
	if jobStatus != "failed" || jobCode != "knowledge_index_failed" || sourceStatus != string(coreknowledge.SourceStatusReady) || sourceCode != "knowledge_index_failed" {
		t.Fatalf("job=%s/%s source=%s/%s", jobStatus, jobCode, sourceStatus, sourceCode)
	}
	var cleanupCount int
	if err := repo.store.pool.QueryRow(ctx, `SELECT count(*) FROM core_knowledge_generation_cleanup WHERE source_id=$1`, mem.ID).Scan(&cleanupCount); err != nil || cleanupCount != 1 {
		t.Fatalf("cleanup count=%d err=%v", cleanupCount, err)
	}
}

func TestCoreKnowledgeWorkerPostgresMemoryUpdateSupersedesInFlightIndex(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	profileID := uuid.NewString()
	createTestProfile(ctx, t, repo.store, profileID, "embed", "test")
	configDigest := strings.Repeat("2", 64)
	if _, err := repo.EnsureEmbeddingConfig(ctx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: profileID, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: configDigest, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	indexer, err := NewKnowledgeIndexer(repo.store, profileID, configDigest)
	if err != nil {
		t.Fatal(err)
	}
	indexer.SetEmbeddingConfigReader(repo)
	service, err := coreknowledge.NewService(repo, indexer)
	if err != nil {
		t.Fatal(err)
	}
	memory, err := service.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), Title: "initial", Content: "initial memory", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := service.UpdateMemory(ctx, coreknowledge.UpdateMemoryCommand{IdempotencyKey: uuid.NewString(), SourceID: memory.ID, ExpectedRevision: memory.Revision, Title: "updated", Content: "updated memory", MediaType: "text/plain"})
	if err != nil || updated.Revision != memory.Revision+1 {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
	current, err := service.GetMemory(ctx, memory.ID)
	if err != nil || current.Content != "updated memory" || current.Revision != updated.Revision {
		t.Fatalf("current=%+v err=%v", current, err)
	}

	tasks := NewCoreTaskStore(repo.store)
	backend, _ := semantic.NewMemoryStore(2)
	engine, _ := semantic.NewIndexEngine(semantic.IndexConfig{Embedder: workerEmbedding{}, VectorStore: backend, ProfileResolver: workerProfiles{id: profileID}, EmbeddingProfileID: profileID, Dimension: 2, ConfigReader: repo})
	handler, _ := NewKnowledgeTaskHandler(repo.store, nil, repo.content.(*pgKnowledgeContent), engine)
	oldTask, _, err := tasks.ClaimNextDue(ctx, "knowledge-old", time.Now().UTC(), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	oldOutcome := handler(ctx, oldTask)
	if oldOutcome.Err == nil || !oldOutcome.TerminalOwned {
		t.Fatalf("old outcome=%#v", oldOutcome)
	}
	var sourceStatus, sourceError string
	var sourceRevision int64
	if err := repo.store.pool.QueryRow(ctx, `SELECT status,error_code,revision FROM core_knowledge_sources WHERE source_id=$1`, memory.ID).Scan(&sourceStatus, &sourceError, &sourceRevision); err != nil {
		t.Fatal(err)
	}
	if sourceStatus != string(coreknowledge.SourceStatusIndexing) || sourceError != "" || sourceRevision != updated.Revision {
		t.Fatalf("source after superseded failure=%s/%s revision=%d", sourceStatus, sourceError, sourceRevision)
	}
	newTask, _, err := tasks.ClaimNextDue(ctx, "knowledge-new", time.Now().UTC(), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.store.pool.Exec(ctx, `UPDATE core_knowledge_sources SET error_code='knowledge_index_failed' WHERE source_id=$1`, memory.ID); err != nil {
		t.Fatal(err)
	}
	newOutcome := handler(ctx, newTask)
	if newOutcome.Err != nil {
		t.Fatalf("new outcome=%#v", newOutcome)
	}
	current, err = service.GetMemory(ctx, memory.ID)
	if err != nil || current.Content != "updated memory" || current.Revision != updated.Revision {
		t.Fatalf("promoted current=%+v err=%v", current, err)
	}
	if err := repo.store.pool.QueryRow(ctx, `SELECT status,error_code,revision FROM core_knowledge_sources WHERE source_id=$1`, memory.ID).Scan(&sourceStatus, &sourceError, &sourceRevision); err != nil {
		t.Fatal(err)
	}
	if sourceStatus != string(coreknowledge.SourceStatusReady) || sourceError != "" || sourceRevision != updated.Revision {
		t.Fatalf("promoted source=%s/%s revision=%d", sourceStatus, sourceError, sourceRevision)
	}
}

func TestCoreKnowledgePostgresDisableFirstGenerationAndReaddEmbeddingProfile(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	models, err := coremodel.NewService(repo.store, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientProfileID := "embedding-readd"
	firstKey := "first-write-only-key"
	first, err := models.Sync(ctx, coremodel.SyncProfileCommand{
		IdempotencyKey:            uuid.NewString(),
		DefaultEmbeddingProfileID: clientProfileID,
		Entries: []coremodel.SyncProfileEntry{{
			ClientProfileID: clientProfileID, DisplayName: "Embedding", Provider: coremodel.ProviderOpenAICompatible,
			ModelKind: coremodel.ModelKindEmbedding, BaseURL: "https://example.invalid/v1", Model: "embed-v1", APIKey: &firstKey,
		}},
	})
	if err != nil || len(first.Profiles) != 1 {
		t.Fatalf("first sync=%+v err=%v", first, err)
	}
	profileID := coremodel.SyncProfileID(clientProfileID)
	configDigest := strings.Repeat("4", 64)
	if _, err := repo.EnsureEmbeddingConfig(ctx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: profileID, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: configDigest, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	indexer, err := NewKnowledgeIndexer(repo.store, profileID, configDigest)
	if err != nil {
		t.Fatal(err)
	}
	indexer.SetEmbeddingConfigReader(repo)
	knowledge, err := coreknowledge.NewService(repo, indexer)
	if err != nil {
		t.Fatal(err)
	}
	memory, err := knowledge.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), Title: "preserved", Content: "keep this memory text", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	var firstTaskID, firstGeneration string
	if err := repo.store.pool.QueryRow(ctx, `SELECT task_id::text,generation FROM core_knowledge_index_jobs WHERE profile_id=$1 AND status='queued'`, profileID).Scan(&firstTaskID, &firstGeneration); err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(repo.store)
	claimed, _, err := tasks.ClaimNextDue(ctx, "disable-race-worker", time.Now().UTC(), time.Minute, 1)
	if err != nil || claimed.ID != firstTaskID {
		t.Fatalf("claimed=%+v err=%v", claimed, err)
	}
	if _, err := repo.store.pool.Exec(ctx, `INSERT INTO core_knowledge_vector_generations(generation,state) VALUES($1,'staged')`, firstGeneration); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.store.pool.Exec(ctx, `INSERT INTO core_knowledge_vectors(point_id,generation,state,source_id,revision,chunk_ref,digest,snippet,embedding) VALUES($1,$2,'staged',$3,$4,'chunk-0',$5,'staged','[1,0]')`, uuid.New(), firstGeneration, memory.ID, memory.Revision, strings.Repeat("5", 64)); err != nil {
		t.Fatal(err)
	}
	disabled, err := knowledge.DisableEmbeddingProfile(ctx, profileID)
	if err != nil || disabled.EmbeddingProfileID != uuid.Nil.String() {
		t.Fatalf("disabled=%+v err=%v", disabled, err)
	}
	// A disabled binding is a durable product state, not a one-process state.
	// Recomposition after restart must keep Knowledge available for text
	// memory while semantic indexing remains honestly unavailable.
	restartedIndexer, err := NewKnowledgeIndexer(repo.store, disabled.EmbeddingProfileID, disabled.CollectionConfigDigest)
	if err != nil {
		t.Fatalf("restart disabled Knowledge indexer: %v", err)
	}
	restartedIndexer.SetEmbeddingConfigReader(repo)
	if _, err = restartedIndexer.RequestIndex(ctx, coreknowledge.IndexRequest{IdempotencyKey: uuid.NewString(), SourceIDs: []string{memory.ID}}); !errors.Is(err, coreknowledge.ErrNotFound) {
		t.Fatalf("disabled restart index err=%v, want embedding unavailable", err)
	}
	kept, err := knowledge.GetMemory(ctx, memory.ID)
	if err != nil || kept.Content != "keep this memory text" {
		t.Fatalf("kept=%+v err=%v", kept, err)
	}
	keptSource, err := knowledge.Get(ctx, memory.ID)
	if err != nil || keptSource.Status != coreknowledge.SourceStatusReady || keptSource.ErrorCode != "" {
		t.Fatalf("kept source=%+v err=%v", keptSource, err)
	}
	var taskStatus, jobStatus string
	if err := repo.store.pool.QueryRow(ctx, `SELECT task.status,job.status FROM core_tasks task JOIN core_knowledge_index_jobs job ON job.task_id=task.task_id WHERE task.task_id=$1`, firstTaskID).Scan(&taskStatus, &jobStatus); err != nil {
		t.Fatal(err)
	}
	var vectors int
	if err := repo.store.pool.QueryRow(ctx, `SELECT count(*) FROM core_knowledge_vectors WHERE generation=$1`, firstGeneration).Scan(&vectors); err != nil {
		t.Fatal(err)
	}
	if taskStatus != "canceled" || jobStatus != "canceled" || vectors != 0 {
		t.Fatalf("disabled task/job/vectors=%s/%s/%d", taskStatus, jobStatus, vectors)
	}
	backend, _ := semantic.NewMemoryStore(2)
	engine, _ := semantic.NewIndexEngine(semantic.IndexConfig{Embedder: workerEmbedding{}, VectorStore: backend, ProfileResolver: workerProfiles{id: profileID}, EmbeddingProfileID: profileID, Dimension: 2, ConfigReader: repo})
	handler, _ := NewKnowledgeTaskHandler(repo.store, nil, repo.content.(*pgKnowledgeContent), engine)
	lateOutcome := handler(ctx, claimed)
	if lateOutcome.Err == nil || !lateOutcome.TerminalOwned {
		t.Fatalf("late disabled worker outcome=%#v", lateOutcome)
	}
	var promotedRevision int64
	if err := repo.store.pool.QueryRow(ctx, `SELECT promoted_revision FROM core_knowledge_sources WHERE source_id=$1`, memory.ID).Scan(&promotedRevision); err != nil || promotedRevision != 0 {
		t.Fatalf("late worker promoted revision=%d err=%v", promotedRevision, err)
	}
	if _, err := models.Sync(ctx, coremodel.SyncProfileCommand{IdempotencyKey: uuid.NewString()}); err != nil {
		t.Fatal(err)
	}
	if _, err := models.Delete(ctx, coremodel.DeleteProfileCommand{ID: profileID, IdempotencyKey: uuid.NewString(), ExpectedRevision: first.Profiles[0].Revision}); err != nil {
		t.Fatal(err)
	}
	withoutKey, err := models.Sync(ctx, coremodel.SyncProfileCommand{IdempotencyKey: uuid.NewString(), Entries: []coremodel.SyncProfileEntry{{ClientProfileID: clientProfileID, DisplayName: "Embedding 2", Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindEmbedding, BaseURL: "https://example.invalid/v1", Model: "embed-v2"}}})
	if !errors.Is(err, coremodel.ErrAPIKeyUnavailable) || len(withoutKey.Profiles) != 0 {
		t.Fatalf("readd without key=%+v err=%v", withoutKey, err)
	}
	secondKey := "second-write-only-key"
	second, err := models.Sync(ctx, coremodel.SyncProfileCommand{
		IdempotencyKey:            uuid.NewString(),
		DefaultEmbeddingProfileID: clientProfileID,
		Entries:                   []coremodel.SyncProfileEntry{{ClientProfileID: clientProfileID, DisplayName: "Embedding 2", Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindEmbedding, BaseURL: "https://example.invalid/v1", Model: "embed-v2", APIKey: &secondKey}},
	})
	if err != nil || len(second.Profiles) != 1 {
		t.Fatalf("second sync=%+v err=%v", second, err)
	}
	resolved, err := models.ResolveClientProfile(ctx, clientProfileID)
	if err != nil || resolved.ID != profileID || resolved.Revision <= first.Profiles[0].Revision || resolved.CredentialVersion <= first.Profiles[0].CredentialVersion {
		t.Fatalf("resolved=%+v first=%+v err=%v", resolved, first.Profiles[0], err)
	}
	if _, err := knowledge.BindEmbeddingProfile(ctx, resolved.ID); err != nil {
		t.Fatal(err)
	}
	if err := knowledge.ReconcileAutoIndex(ctx, 64); err != nil {
		t.Fatal(err)
	}
	var rebuiltProfileID string
	if err := repo.store.pool.QueryRow(ctx, `SELECT profile_id::text FROM core_knowledge_index_jobs WHERE profile_id=$1 AND status='queued' ORDER BY created_at DESC LIMIT 1`, profileID).Scan(&rebuiltProfileID); err != nil || rebuiltProfileID != profileID {
		t.Fatalf("rebuilt profile=%q err=%v", rebuiltProfileID, err)
	}
}

func TestCoreKnowledgeWorkerPostgresCancellationRestoresSource(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	profileID := uuid.NewString()
	createTestProfile(ctx, t, repo.store, profileID, "embed", "test")
	mem, _ := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), Title: "cancel", Content: "cancel me", MediaType: "text/plain"})
	idx, _ := NewKnowledgeIndexer(repo.store, profileID, strings.Repeat("c", 64))
	ref, err := idx.RequestIndex(ctx, coreknowledge.IndexRequest{SourceIDs: []string{mem.ID}, IdempotencyKey: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(repo.store)
	current, err := tasks.GetTask(ctx, ref.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tasks.CancelTask(ctx, coretask.CancelCommand{TaskID: ref.TaskID, Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("d", 64), ExpectedRevision: current.Revision}, Reason: "test cancel", At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	var jobStatus, sourceStatus string
	if err := repo.store.pool.QueryRow(ctx, `SELECT status FROM core_knowledge_index_jobs WHERE task_id=$1`, ref.TaskID).Scan(&jobStatus); err != nil {
		t.Fatal(err)
	}
	if err := repo.store.pool.QueryRow(ctx, `SELECT status FROM core_knowledge_sources WHERE source_id=$1`, mem.ID).Scan(&sourceStatus); err != nil {
		t.Fatal(err)
	}
	if jobStatus != "canceled" || sourceStatus != string(coreknowledge.SourceStatusReady) {
		t.Fatalf("job=%s source=%s", jobStatus, sourceStatus)
	}
}

func TestCoreKnowledgeWorkerPostgresCancelLateUpsertRetainsTombstoneAndRecleans(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	profileID := uuid.NewString()
	createTestProfile(ctx, t, repo.store, profileID, "embed", "test")
	mem, err := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), Title: "race", Content: "late upsert", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := NewKnowledgeIndexer(repo.store, profileID, strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := idx.RequestIndex(ctx, coreknowledge.IndexRequest{SourceIDs: []string{mem.ID}, IdempotencyKey: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(repo.store)
	task, _, err := tasks.ClaimNextDue(ctx, "knowledge-race", time.Now().UTC(), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := semantic.NewMemoryStore(2)
	backend := &blockingStageStore{StagedVectorStore: base, started: make(chan struct{}), release: make(chan struct{})}
	engine, _ := semantic.NewIndexEngine(semantic.IndexConfig{Embedder: workerEmbedding{}, VectorStore: backend, ProfileResolver: workerProfiles{id: profileID}, EmbeddingProfileID: profileID, Dimension: 2})
	handler, _ := NewKnowledgeTaskHandler(repo.store, nil, repo.content.(*pgKnowledgeContent), engine)
	done := make(chan coreruntime.ManagedOutcome, 1)
	go func() { done <- handler(context.Background(), task) }()
	select {
	case <-backend.started:
	case <-time.After(5 * time.Second):
		t.Fatal("upsert did not block")
	}
	current, err := tasks.GetTask(ctx, ref.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tasks.CancelTask(ctx, coretask.CancelCommand{TaskID: ref.TaskID, Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("f", 64), ExpectedRevision: current.Revision}, Reason: "race", At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := SweepStaleKnowledgeStagesWithBackend(ctx, repo.store, backend); err != nil {
		t.Fatal(err)
	}
	close(backend.release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not exit after canceled upsert")
	}
	if err := SweepStaleKnowledgeStagesWithBackend(ctx, repo.store, backend); err != nil {
		t.Fatal(err)
	}
	if backend.deleteCount() < 2 {
		t.Fatalf("late upsert was not cleaned twice: deletes=%d", backend.deleteCount())
	}
	var count int
	if err := repo.store.pool.QueryRow(ctx, `SELECT count(*) FROM core_knowledge_generation_cleanup WHERE source_id=$1`, mem.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("canceled tombstone count=%d err=%v", count, err)
	}
	// Restart-equivalent repeated sweep retains the tombstone and issues a final
	// idempotent delete rather than allowing a late stage to become orphaned.
	if err := SweepStaleKnowledgeStagesWithBackend(ctx, repo.store, backend); err != nil {
		t.Fatal(err)
	}
	if backend.deleteCount() < 3 {
		t.Fatalf("restart sweep did not re-delete: %d", backend.deleteCount())
	}
}

func TestCoreKnowledgeGenerationCleanupIntentSweepsAfterBackendSuccess(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	sourceID := uuid.NewString()
	now := time.Now().UTC()
	_, err := repo.store.pool.Exec(ctx, `INSERT INTO core_knowledge_sources(source_id,kind,status,title,digest,size_bytes,media_type,revision,created_at,updated_at) VALUES($1,'memory','ready','cleanup','',1,'text/plain',1,$2,$2)`, sourceID, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.store.pool.Exec(ctx, `INSERT INTO core_knowledge_generation_cleanup(source_id,generation) VALUES($1,'old-generation')`, sourceID); err != nil {
		t.Fatal(err)
	}
	backend, _ := semantic.NewMemoryStore(2)
	if err := backend.EnsureGeneration(ctx, "old-generation"); err != nil {
		t.Fatal(err)
	}
	if err := SweepStaleKnowledgeStagesWithBackend(ctx, repo.store, backend); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := repo.store.pool.QueryRow(ctx, `SELECT count(*) FROM core_knowledge_generation_cleanup WHERE source_id=$1`, sourceID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("cleanup count=%d err=%v", count, err)
	}
}

func TestCoreKnowledgePromotedCleanupIntentSweeps(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	sourceID := uuid.NewString()
	now := time.Now().UTC()
	_, err := repo.store.pool.Exec(ctx, `INSERT INTO core_knowledge_sources(source_id,kind,status,title,digest,size_bytes,media_type,revision,created_at,updated_at) VALUES($1,'memory','ready','cleanup','',1,'text/plain',1,$2,$2)`, sourceID, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.store.pool.Exec(ctx, `INSERT INTO core_knowledge_generation_cleanup(source_id,generation,cleanup_kind,revision) VALUES($1,'old-generation','promoted',1)`, sourceID); err != nil {
		t.Fatal(err)
	}
	backend, _ := semantic.NewMemoryStore(2)
	if err := backend.EnsureGeneration(ctx, "old-generation"); err != nil {
		t.Fatal(err)
	}
	_ = backend.DeletePromotedGeneration(ctx, "old-generation", sourceID, 1)
	if err := SweepStaleKnowledgeStagesWithBackend(ctx, repo.store, backend); err != nil {
		t.Fatal(err)
	}
	var count int
	_ = repo.store.pool.QueryRow(ctx, `SELECT count(*) FROM core_knowledge_generation_cleanup WHERE source_id=$1`, sourceID).Scan(&count)
	if count != 0 {
		t.Fatalf("count=%d", count)
	}
}
