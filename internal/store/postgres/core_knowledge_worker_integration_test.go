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

type recordingWorkerEmbedding struct {
	mu       sync.Mutex
	profiles []string
}

func (e *recordingWorkerEmbedding) Embed(_ context.Context, profile coremodel.Profile, _ []string) ([][]float32, error) {
	e.mu.Lock()
	e.profiles = append(e.profiles, profile.ID)
	e.mu.Unlock()
	return [][]float32{{1, 0}}, nil
}

func (e *recordingWorkerEmbedding) profileIDs() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.profiles...)
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
	createTestProfile(ctx, t, repo.store, profileID, "embed", "test")
	mem, err := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), Title: "w", Content: "worker content", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	configDigest := strings.Repeat("a", 64)
	idx, err := NewKnowledgeIndexer(repo.store, profileID, 2, configDigest)
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

func TestCoreKnowledgeWorkerUsesQueuedOwnerBindingAfterConfigRotation(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	owner := coretask.OwnerScope{OwnerID: "@knowledge-worker-owner:example.test", AccountGeneration: 5}
	ownerCtx, err := coretask.WithOwnerScope(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	profileA, profileB := uuid.NewString(), uuid.NewString()
	createTestProfile(ownerCtx, t, repo.store, profileA, "queued-profile", "queued-secret")
	createTestProfile(ownerCtx, t, repo.store, profileB, "current-profile", "current-secret")
	digest := strings.Repeat("8", 64)
	if _, err = repo.EnsureEmbeddingConfig(ctx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: profileB, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: digest, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.EnsureEmbeddingConfig(ownerCtx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: profileA, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: digest, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	memory, err := repo.CreateMemory(ownerCtx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), SourceID: uuid.NewString(), Title: "queued binding", Content: "use the queued profile", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	indexer, err := NewKnowledgeIndexer(repo.store, profileA, 2, digest)
	if err != nil {
		t.Fatal(err)
	}
	indexer.SetEmbeddingConfigReader(repo)
	ref, err := indexer.RequestIndex(ownerCtx, coreknowledge.IndexRequest{IdempotencyKey: uuid.NewString(), SourceIDs: []string{memory.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.UpdateEmbeddingConfig(ownerCtx, coreknowledge.EmbeddingConfigCommand{IdempotencyKey: uuid.NewString(), EmbeddingProfileID: profileB, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: digest, ExpectedRevision: 1}); !errors.Is(err, coreknowledge.ErrActiveTasks) {
		t.Fatalf("active Knowledge task model switch err=%v, want active tasks", err)
	}
	// Simulate a rolling-upgrade legacy process bypassing the new admission
	// rule. The worker must still honor its immutable queued binding.
	if _, err = repo.store.pool.Exec(ctx, `UPDATE core_knowledge_embedding_config SET embedding_profile_id=$1,revision=revision+1,updated_at=clock_timestamp() WHERE owner_id=$2 AND account_generation=$3`, profileB, owner.OwnerID, owner.AccountGeneration); err != nil {
		t.Fatal(err)
	}
	var jobDimension, payloadDimension int
	if err = repo.store.pool.QueryRow(ctx, `SELECT job.embedding_dimension,(task.payload_json #>> '{knowledge_index,embedding_dimension}')::integer FROM core_knowledge_index_jobs job JOIN core_tasks task ON task.task_id=job.task_id WHERE job.task_id=$1`, ref.TaskID).Scan(&jobDimension, &payloadDimension); err != nil {
		t.Fatal(err)
	}
	if jobDimension != 2 || payloadDimension != 2 {
		t.Fatalf("immutable dimensions job=%d payload=%d", jobDimension, payloadDimension)
	}
	tasks := NewCoreTaskStore(repo.store)
	task, _, err := tasks.ClaimNextDue(ctx, "knowledge-binding", time.Now().UTC(), time.Minute, 1)
	if err != nil || task.ID != ref.TaskID {
		t.Fatalf("claim=%+v err=%v", task, err)
	}
	backend, _ := semantic.NewMemoryStore(2)
	embedder := &recordingWorkerEmbedding{}
	engine, err := semantic.NewIndexEngine(semantic.IndexConfig{Embedder: embedder, VectorStore: backend, ProfileResolver: repo.store, EmbeddingProfileID: profileB, Dimension: 2, ConfigReader: repo})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewKnowledgeTaskHandler(repo.store, nil, repo.content.(*pgKnowledgeContent), engine)
	if err != nil {
		t.Fatal(err)
	}
	if outcome := handler(ctx, task); outcome.Err != nil {
		t.Fatalf("worker outcome=%+v", outcome)
	}
	if profiles := embedder.profileIDs(); len(profiles) != 1 || profiles[0] != profileA {
		t.Fatalf("embedded with profiles=%v, want immutable queued profile %s", profiles, profileA)
	}
	var promotedProfile string
	if err = repo.store.pool.QueryRow(ctx, `SELECT promoted_profile_id::text FROM core_knowledge_sources WHERE source_id=$1`, memory.ID).Scan(&promotedProfile); err != nil || promotedProfile != profileA {
		t.Fatalf("promoted profile=%s err=%v, want %s", promotedProfile, err, profileA)
	}
}

func TestCoreKnowledgeModelSwitchSucceedsAfterActiveTaskCancellation(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	owner := coretask.OwnerScope{OwnerID: "@knowledge-switch-owner:example.test", AccountGeneration: 6}
	ownerCtx, err := coretask.WithOwnerScope(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	profileA, profileB := uuid.NewString(), uuid.NewString()
	createTestProfile(ownerCtx, t, repo.store, profileA, "profile-a", "secret-a")
	createTestProfile(ownerCtx, t, repo.store, profileB, "profile-b", "secret-b")
	digest := strings.Repeat("7", 64)
	if _, err = repo.EnsureEmbeddingConfig(ownerCtx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: profileA, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: digest, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	memory, err := repo.CreateMemory(ownerCtx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), SourceID: uuid.NewString(), Content: "cancel before switch", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	indexer, err := NewKnowledgeIndexer(repo.store, profileA, 2, digest)
	if err != nil {
		t.Fatal(err)
	}
	indexer.SetEmbeddingConfigReader(repo)
	ref, err := indexer.RequestIndex(ownerCtx, coreknowledge.IndexRequest{IdempotencyKey: uuid.NewString(), SourceIDs: []string{memory.ID}})
	if err != nil {
		t.Fatal(err)
	}
	command := coreknowledge.EmbeddingConfigCommand{IdempotencyKey: uuid.NewString(), EmbeddingProfileID: profileB, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: digest, ExpectedRevision: 1}
	if _, err = repo.UpdateEmbeddingConfig(ownerCtx, command); !errors.Is(err, coreknowledge.ErrActiveTasks) {
		t.Fatalf("active model switch err=%v", err)
	}
	tasks := NewCoreTaskStore(repo.store)
	task, err := tasks.GetTask(ownerCtx, ref.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tasks.CancelTask(ownerCtx, coretask.CancelCommand{
		TaskID: ref.TaskID,
		Mutation: coretask.MutationCommand{
			IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("6", 64), ExpectedRevision: task.Revision,
		},
		Reason: "switch model",
		At:     time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	command.IdempotencyKey = uuid.NewString()
	bound, err := repo.UpdateEmbeddingConfig(ownerCtx, command)
	if err != nil || bound.EmbeddingProfileID != profileB || bound.Revision != 2 {
		t.Fatalf("binding after cancellation=%+v err=%v", bound, err)
	}
}

func TestCoreKnowledgeGenericFailurePathsReleaseModelSwitchFence(t *testing.T) {
	tests := []struct {
		name, code, cleanupKind string
		timeout                 bool
		terminal                func(context.Context, *CoreTaskStore, coretask.Task, coretask.Lease, time.Time) error
	}{
		{
			name: "crashed_worker_times_out_during_reclaim", code: "task_timed_out", cleanupKind: "canceled_staging", timeout: true,
			terminal: func(ctx context.Context, tasks *CoreTaskStore, _ coretask.Task, _ coretask.Lease, at time.Time) error {
				_, _, err := tasks.ClaimNextDue(ctx, "knowledge-reclaimer", at.Add(2*time.Hour), time.Minute, 1)
				if errors.Is(err, coretask.ErrNotFound) {
					return nil
				}
				return err
			},
		},
		{
			name: "generic_worker_failure", code: "worker_failed", cleanupKind: "staging",
			terminal: func(ctx context.Context, tasks *CoreTaskStore, task coretask.Task, lease coretask.Lease, at time.Time) error {
				return tasks.FailTask(ctx, coretask.FailCommand{
					Fence:     coretask.Fence{TaskID: task.ID, Attempt: lease.Attempt, LeaseEpoch: lease.Epoch, ExpectedRevision: task.Revision},
					ErrorCode: "worker_failed", ErrorSummary: "worker failed", At: at,
				})
			},
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, repo, cleanup := knowledgePGFixture(t)
			defer cleanup()
			owner := coretask.OwnerScope{OwnerID: "@knowledge-terminal-owner:example.test", AccountGeneration: int64(index + 11)}
			ownerCtx, err := coretask.WithOwnerScope(ctx, owner)
			if err != nil {
				t.Fatal(err)
			}
			profileA, profileB := uuid.NewString(), uuid.NewString()
			createTestProfile(ownerCtx, t, repo.store, profileA, "profile-a", "secret-a")
			createTestProfile(ownerCtx, t, repo.store, profileB, "profile-b", "secret-b")
			digest := strings.Repeat("5", 64)
			if _, err = repo.EnsureEmbeddingConfig(ownerCtx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: profileA, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: digest, Revision: 1}); err != nil {
				t.Fatal(err)
			}
			memory, err := repo.CreateMemory(ownerCtx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), SourceID: uuid.NewString(), Content: "terminal cleanup", MediaType: "text/plain"})
			if err != nil {
				t.Fatal(err)
			}
			indexer, err := NewKnowledgeIndexer(repo.store, profileA, 2, digest)
			if err != nil {
				t.Fatal(err)
			}
			indexer.SetEmbeddingConfigReader(repo)
			ref, err := indexer.RequestIndex(ownerCtx, coreknowledge.IndexRequest{IdempotencyKey: uuid.NewString(), SourceIDs: []string{memory.ID}})
			if err != nil {
				t.Fatal(err)
			}
			if test.timeout {
				if _, err = repo.store.pool.Exec(ctx, `UPDATE core_tasks SET timeout_seconds=1 WHERE task_id=$1`, ref.TaskID); err != nil {
					t.Fatal(err)
				}
			}
			tasks := NewCoreTaskStore(repo.store)
			at := time.Now().UTC()
			task, lease, err := tasks.ClaimNextDue(ctx, "knowledge-worker", at, time.Minute, 1)
			if err != nil || task.ID != ref.TaskID {
				t.Fatalf("claim=%+v lease=%+v err=%v", task, lease, err)
			}
			if err = test.terminal(ctx, tasks, task, lease, at.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			got, err := tasks.GetTask(ownerCtx, ref.TaskID)
			if err != nil || got.Status != coretask.StatusFailed || got.FailureCode != test.code {
				t.Fatalf("task=%+v err=%v", got, err)
			}
			var jobStatus, jobCode, sourceStatus, sourceCode, cleanupKind string
			if err = repo.store.pool.QueryRow(ctx, `SELECT status,error_code FROM core_knowledge_index_jobs WHERE task_id=$1`, ref.TaskID).Scan(&jobStatus, &jobCode); err != nil {
				t.Fatal(err)
			}
			if err = repo.store.pool.QueryRow(ctx, `SELECT status,error_code FROM core_knowledge_sources WHERE source_id=$1`, memory.ID).Scan(&sourceStatus, &sourceCode); err != nil {
				t.Fatal(err)
			}
			if err = repo.store.pool.QueryRow(ctx, `SELECT cleanup_kind FROM core_knowledge_generation_cleanup WHERE source_id=$1`, memory.ID).Scan(&cleanupKind); err != nil {
				t.Fatal(err)
			}
			if jobStatus != "failed" || jobCode != test.code || sourceStatus != string(coreknowledge.SourceStatusReady) || sourceCode != test.code || cleanupKind != test.cleanupKind {
				t.Fatalf("job=%s/%s source=%s/%s cleanup=%s", jobStatus, jobCode, sourceStatus, sourceCode, cleanupKind)
			}
			var activeRefs int
			if err = repo.store.pool.QueryRow(ctx, `SELECT count(*) FROM core_model_profile_active_refs WHERE owner_kind='task' AND owner_id=$1`, ref.TaskID).Scan(&activeRefs); err != nil || activeRefs != 0 {
				t.Fatalf("active refs=%d err=%v", activeRefs, err)
			}
			bound, err := repo.UpdateEmbeddingConfig(ownerCtx, coreknowledge.EmbeddingConfigCommand{
				IdempotencyKey: uuid.NewString(), EmbeddingProfileID: profileB, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: digest, ExpectedRevision: 1,
			})
			if err != nil || bound.EmbeddingProfileID != profileB {
				t.Fatalf("model switch after terminal=%+v err=%v", bound, err)
			}
		})
	}
}

func TestCoreKnowledgeWorkerPostgresTamperAndStageSweep(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	profileID := uuid.NewString()
	createTestProfile(ctx, t, repo.store, profileID, "embed", "test")
	mem, _ := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), Title: "w", Content: "worker content", MediaType: "text/plain"})
	cfg := strings.Repeat("b", 64)
	idx, _ := NewKnowledgeIndexer(repo.store, profileID, 2, cfg)
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
	idx, err := NewKnowledgeIndexer(repo.store, profileID, 2, strings.Repeat("1", 64))
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
	indexer, err := NewKnowledgeIndexer(repo.store, profileID, 2, configDigest)
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

func TestCoreKnowledgeWorkerPostgresCancellationRestoresSource(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	profileID := uuid.NewString()
	createTestProfile(ctx, t, repo.store, profileID, "embed", "test")
	mem, _ := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), Title: "cancel", Content: "cancel me", MediaType: "text/plain"})
	idx, _ := NewKnowledgeIndexer(repo.store, profileID, 2, strings.Repeat("c", 64))
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
	idx, err := NewKnowledgeIndexer(repo.store, profileID, 2, strings.Repeat("e", 64))
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
