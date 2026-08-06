package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type pgKnowledgeContent struct {
	mu         sync.Mutex
	objects    map[string][]byte
	next       int
	failDelete bool
}

func (p *pgKnowledgeContent) OpenContent(_ context.Context, ref coreknowledge.ContentReference) (io.ReadCloser, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	b, ok := p.objects[ref.Ref]
	if !ok || int64(len(b)) != ref.SizeBytes {
		return nil, coreknowledge.ErrChecksumMismatch
	}
	h := sha256.Sum256(b)
	if ref.Digest != "" && !strings.EqualFold(hex.EncodeToString(h[:]), ref.Digest) {
		return nil, coreknowledge.ErrChecksumMismatch
	}
	return io.NopCloser(strings.NewReader(string(b))), nil
}

func (p *pgKnowledgeContent) Begin(context.Context, coreknowledge.UploadMetadata) (coreknowledge.ContentSink, error) {
	return &pgKnowledgeSink{p: p, h: sha256.New()}, nil
}
func (p *pgKnowledgeContent) Delete(_ context.Context, ref coreknowledge.ContentReference) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failDelete {
		p.failDelete = false
		return coreknowledge.ErrCleanupPending
	}
	delete(p.objects, ref.Ref)
	return nil
}

type pgKnowledgeSink struct {
	p    *pgKnowledgeContent
	data []byte
	h    interface{ Write([]byte) (int, error) }
	size int64
	done bool
	ref  string
}

func (s *pgKnowledgeSink) Write(b []byte) (int, error) {
	if s.done {
		return 0, coreknowledge.ErrConflict
	}
	s.data = append(s.data, b...)
	return s.h.Write(b)
}
func (s *pgKnowledgeSink) Size() int64 { return int64(len(s.data)) }
func (s *pgKnowledgeSink) SHA256() string {
	h := sha256.Sum256(s.data)
	return hex.EncodeToString(h[:])
}
func (s *pgKnowledgeSink) Finalize(_ context.Context, d string, n int64) (coreknowledge.ContentReference, error) {
	if s.Size() != n || !strings.EqualFold(s.SHA256(), d) {
		return coreknowledge.ContentReference{}, coreknowledge.ErrChecksumMismatch
	}
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	s.p.next++
	s.ref = "pg-content-" + uuid.NewString()
	if s.p.objects == nil {
		s.p.objects = map[string][]byte{}
	}
	s.p.objects[s.ref] = append([]byte(nil), s.data...)
	s.done = true
	return coreknowledge.ContentReference{Ref: s.ref, Digest: s.SHA256(), SizeBytes: n}, nil
}
func (s *pgKnowledgeSink) Abort(context.Context) error { s.done = true; return nil }

type pgKnowledgeOpener struct{}

func (pgKnowledgeOpener) OpenManaged(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("mounted")), nil
}

type pgKnowledgeSearch struct{}

func (pgKnowledgeSearch) Search(_ context.Context, q coreknowledge.SearchQuery) (coreknowledge.SearchPage, error) {
	id := q.SourceIDs[0]
	return coreknowledge.SearchPage{Matches: []coreknowledge.SearchMatch{
		{SourceID: id, ChunkRef: "chunk:0", Snippet: "verified semantic result 0", Score: .9},
		{SourceID: id, ChunkRef: "chunk:1", Snippet: "verified semantic result 1", Score: .9},
		{SourceID: id, ChunkRef: "chunk:2", Snippet: "verified semantic result 2", Score: .9},
	}}, nil
}

type pgKnowledgeProvenanceSearch struct {
	profileID string
	digest    string
}

type pgMemoryRecallSearch struct {
	calls [][]string
}

func (s *pgMemoryRecallSearch) Search(_ context.Context, q coreknowledge.SearchQuery) (coreknowledge.SearchPage, error) {
	if q.Kind != coreknowledge.SourceKindMemory || q.Limit != 8 || len(q.SourceIDs) == 0 || len(q.SourceIDs) > knowledgeRecallBindingBatchSize {
		return coreknowledge.SearchPage{}, coreknowledge.ErrInvalid
	}
	ids := append([]string(nil), q.SourceIDs...)
	s.calls = append(s.calls, ids)
	return coreknowledge.SearchPage{Matches: []coreknowledge.SearchMatch{{SourceID: ids[0], ChunkRef: "chunk:0", Snippet: "recalled memory", Score: float64(len(s.calls))}}}, nil
}

func (s pgKnowledgeProvenanceSearch) Search(_ context.Context, q coreknowledge.SearchQuery) (coreknowledge.SearchPage, error) {
	if len(q.SourceIDs) == 0 {
		return coreknowledge.SearchPage{}, coreknowledge.ErrInvalid
	}
	return coreknowledge.SearchPage{
		Matches: []coreknowledge.SearchMatch{
			{SourceID: q.SourceIDs[0], ChunkRef: "chunk:0", Snippet: "pinned result 0", Score: .9},
			{SourceID: q.SourceIDs[0], ChunkRef: "chunk:1", Snippet: "pinned result 1", Score: .8},
		},
		SearchProvenance: coreknowledge.SearchProvenance{
			EmbeddingProfileID:       s.profileID,
			EmbeddingProfileRevision: 7,
			EmbeddingModel:           "embedding-model-v1",
			EmbeddingGeneration:      "generation-v1",
			CollectionConfigDigest:   s.digest,
		},
	}, nil
}

func knowledgePGFixture(t *testing.T) (context.Context, *CoreKnowledgeStore, func()) {
	return knowledgePGFixtureWithMaxConns(t, 0)
}

func knowledgePGFixtureWithMaxConns(t *testing.T, maxConns int32) (context.Context, *CoreKnowledgeStore, func()) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("DIREXTALK_TEST_DATABASE_URL"))
	if dsn == "" {
		dsn = strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	}
	if dsn == "" {
		t.Skip("DIREXTALK_TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil || admin.Ping(ctx) != nil {
		if admin != nil {
			admin.Close()
		}
		cancel()
		t.Skipf("postgres unavailable: %v", err)
	}
	schema := "dtx_knowledge_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		cancel()
		t.Skipf("create schema: %v", err)
	}
	cfg, _ := pgxpool.ParseConfig(dsn)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		_ = dropKnowledgeSchema(admin, quoted)
		admin.Close()
		cancel()
		t.Fatal(err)
	}
	instance := uuid.NewString()
	if err = ApplyMigrations(ctx, pool, instance); err != nil {
		pool.Close()
		_ = dropKnowledgeSchema(admin, quoted)
		admin.Close()
		cancel()
		t.Fatal(err)
	}
	store, err := New(pool, instance, testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	content := &pgKnowledgeContent{}
	repo, err := NewCoreKnowledgeStore(store, CoreKnowledgeStoreConfig{
		Content: content, ManagedFiles: pgKnowledgeOpener{}, Search: pgKnowledgeSearch{},
	})
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		pool.Close()
		_, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_ = dropKnowledgeSchema(admin, quoted)
		admin.Close()
		cancel()
	}
	return ctx, repo, cleanup
}

func TestCoreKnowledgeRequestIndexDoesNotReborrowTransactionPool(t *testing.T) {
	tests := []struct {
		name, owner string
		maxConns    int32
		holdConns   int
	}{
		{name: "single_connection", owner: "@knowledge-single-connection:example.test", maxConns: 1},
		{name: "saturated_pool", owner: "@knowledge-saturated-pool:example.test", maxConns: 2, holdConns: 1},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, repo, cleanup := knowledgePGFixtureWithMaxConns(t, test.maxConns)
			defer cleanup()
			ownerCtx, err := coretask.WithOwnerScope(ctx, coretask.OwnerScope{OwnerID: test.owner, AccountGeneration: int64(index + 21)})
			if err != nil {
				t.Fatal(err)
			}
			profileID := uuid.NewString()
			createTestProfile(ownerCtx, t, repo.store, profileID, "pool-profile", "pool-secret")
			digest := strings.Repeat("4", 64)
			if _, err = repo.EnsureEmbeddingConfig(ownerCtx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: profileID, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: digest, Revision: 1}); err != nil {
				t.Fatal(err)
			}
			memory, err := repo.CreateMemory(ownerCtx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), SourceID: uuid.NewString(), Content: "pool binding", MediaType: "text/plain"})
			if err != nil {
				t.Fatal(err)
			}
			indexer, err := NewKnowledgeIndexer(repo.store, profileID, 2, digest)
			if err != nil {
				t.Fatal(err)
			}
			indexer.SetEmbeddingConfigReader(repo)
			held := make([]*pgxpool.Conn, 0, test.holdConns)
			for range test.holdConns {
				connection, acquireErr := repo.store.pool.Acquire(ctx)
				if acquireErr != nil {
					t.Fatal(acquireErr)
				}
				held = append(held, connection)
			}
			defer func() {
				for _, connection := range held {
					connection.Release()
				}
			}()
			requestCtx, cancel := context.WithTimeout(ownerCtx, 2*time.Second)
			defer cancel()
			ref, err := indexer.RequestIndex(requestCtx, coreknowledge.IndexRequest{IdempotencyKey: uuid.NewString(), SourceIDs: []string{memory.ID}})
			if err != nil || !coretask.ValidUUID(ref.TaskID) {
				t.Fatalf("request index ref=%+v err=%v", ref, err)
			}
		})
	}
}
func dropKnowledgeSchema(pool *pgxpool.Pool, schema string) error {
	_, err := pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	return err
}

func TestCoreKnowledgePostgresPersistenceAndCursor(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	memKey := uuid.NewString()
	mem, err := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: memKey, Title: "memory", Content: "semantic text", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	replay, err := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: memKey, Title: "memory", Content: "semantic text", MediaType: "text/plain"})
	if err != nil || replay.ID != mem.ID {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	var wg sync.WaitGroup
	concurrentKey := uuid.NewString()
	results := make(chan coreknowledge.Source, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, e := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: concurrentKey, Title: "concurrent", Content: "same", MediaType: "text/plain"})
			results <- s
			errs <- e
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	var concurrentID string
	for s := range results {
		if concurrentID == "" {
			concurrentID = s.ID
		} else if s.ID != concurrentID {
			t.Fatalf("concurrent replay IDs differ: %q vs %q", concurrentID, s.ID)
		}
	}
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	upKey := uuid.NewString()
	data := []byte("uploaded")
	h := sha256.Sum256(data)
	upload, err := repo.StartUpload(ctx, coreknowledge.UploadMetadata{IdempotencyKey: upKey, Title: "upload", MediaType: "text/plain", DeclaredSize: int64(len(data)), ContentSHA256: hex.EncodeToString(h[:])})
	if err != nil {
		t.Fatal(err)
	}
	chunkKey := uuid.NewString()
	upload, err = repo.AppendUploadChunk(ctx, coreknowledge.UploadChunk{IdempotencyKey: chunkKey, UploadID: upload.ID, Ordinal: 0, OffsetBytes: 0, Data: data, ChunkSHA256: hex.EncodeToString(h[:])})
	if err != nil {
		t.Fatal(err)
	}
	_, source, err := repo.CommitUpload(ctx, coreknowledge.CommitUploadCommand{IdempotencyKey: uuid.NewString(), UploadID: upload.ID, ExpectedRevision: upload.Revision, ContentSHA256: hex.EncodeToString(h[:])})
	if err != nil {
		t.Fatal(err)
	}
	page, err := repo.List(ctx, coreknowledge.ListQuery{PageSize: 1})
	if err != nil || len(page.Sources) != 1 || page.NextPageToken == "" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	next, err := repo.List(ctx, coreknowledge.ListQuery{PageSize: 1, PageToken: page.NextPageToken})
	if err != nil || len(next.Sources) != 1 {
		t.Fatalf("next=%+v err=%v", next, err)
	}
	if _, err = repo.List(ctx, coreknowledge.ListQuery{PageSize: 1, Kind: coreknowledge.SourceKindUpload, PageToken: page.NextPageToken}); err != coreknowledge.ErrCursorConflict {
		t.Fatalf("filter-bound cursor error = %v", err)
	}
	clock := time.Now().UTC()
	repo.now = func() time.Time { return clock }
	firstSearch, err := repo.Search(ctx, coreknowledge.SearchQuery{Query: "semantic", SourceIDs: []string{mem.ID}, Limit: 1})
	if err != nil || len(firstSearch.Matches) != 1 || firstSearch.NextPageToken == "" {
		t.Fatalf("first search page=%+v err=%v", firstSearch, err)
	}
	secondSearch, err := repo.Search(ctx, coreknowledge.SearchQuery{Query: "semantic", SourceIDs: []string{mem.ID}, Limit: 1, PageToken: firstSearch.NextPageToken})
	if err != nil || len(secondSearch.Matches) != 1 || secondSearch.Matches[0].ChunkRef != "chunk:1" {
		t.Fatalf("second search page=%+v err=%v", secondSearch, err)
	}
	if _, err = repo.Search(ctx, coreknowledge.SearchQuery{Query: "semantic", SourceIDs: nil, Limit: 1, PageToken: firstSearch.NextPageToken}); err != coreknowledge.ErrCursorConflict {
		t.Fatalf("search filter-bound cursor error=%v", err)
	}
	clock = clock.Add(knowledgeSnapshotTTL + time.Second)
	if _, err = repo.Search(ctx, coreknowledge.SearchQuery{Query: "semantic", SourceIDs: []string{mem.ID}, Limit: 1, PageToken: firstSearch.NextPageToken}); err != coreknowledge.ErrCursorConflict {
		t.Fatalf("expired search cursor error=%v", err)
	}
	deleted, err := repo.Delete(ctx, coreknowledge.DeleteCommand{IdempotencyKey: uuid.NewString(), SourceID: source.ID, ExpectedRevision: source.Revision})
	if err != nil || deleted.Status != coreknowledge.SourceStatusDeleted {
		t.Fatalf("delete=%+v err=%v", deleted, err)
	}
	// Metadata survives construction of a fresh repository instance, while a
	// cleanup failure is represented durably and can be retried with a fresh key.
	content := repo.content.(*pgKnowledgeContent)
	content.mu.Lock()
	content.failDelete = true
	content.mu.Unlock()
	failed, err := repo.Delete(ctx, coreknowledge.DeleteCommand{IdempotencyKey: uuid.NewString(), SourceID: mem.ID, ExpectedRevision: mem.Revision})
	if err != coreknowledge.ErrCleanupPending || failed.Status != coreknowledge.SourceStatusCleanupPending {
		t.Fatalf("cleanup pending=%+v err=%v", failed, err)
	}
	fresh, err := NewCoreKnowledgeStore(repo.store, CoreKnowledgeStoreConfig{
		Content: content, ManagedFiles: pgKnowledgeOpener{}, Search: pgKnowledgeSearch{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if persisted, err := fresh.Get(ctx, mem.ID); err != nil || persisted.Status != coreknowledge.SourceStatusCleanupPending {
		t.Fatalf("restart persisted source=%+v err=%v", persisted, err)
	}
	if retried, err := fresh.Delete(ctx, coreknowledge.DeleteCommand{IdempotencyKey: uuid.NewString(), SourceID: mem.ID, ExpectedRevision: failed.Revision}); err != nil || retried.Status != coreknowledge.SourceStatusDeleted {
		t.Fatalf("cleanup retry=%+v err=%v", retried, err)
	}
}

func TestCoreKnowledgePostgresMemoryRecallIsSnapshotFreeAndBatchesAllPromotedMemories(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	profileID := uuid.NewString()
	digest := strings.Repeat("a", 64)
	createTestProfile(ctx, t, repo.store, profileID, "recall-embedding", "recall-secret")
	insertSource := func(kind, status string, promoted bool) {
		t.Helper()
		id := uuid.NewString()
		generation := ""
		promotedRevision := int64(0)
		var promotedProfile any
		promotedProfileRevision := int64(0)
		promotedDigest := ""
		if promoted {
			generation = "recall-" + id
			promotedRevision = 1
			promotedProfile = profileID
			promotedProfileRevision = 1
			promotedDigest = digest
		}
		if _, err := repo.store.pool.Exec(ctx, `INSERT INTO core_knowledge_sources(source_id,kind,status,title,digest,size_bytes,media_type,revision,promoted_generation,promoted_revision,promoted_profile_id,promoted_profile_revision,promoted_collection_config_digest) VALUES($1,$2,$3,'recall',repeat('b',64),1,'text/plain',1,$4,$5,$6,$7,$8)`, id, kind, status, generation, promotedRevision, promotedProfile, promotedProfileRevision, promotedDigest); err != nil {
			t.Fatal(err)
		}
	}
	for range 129 {
		insertSource("memory", "ready", true)
	}
	insertSource("memory", "ready", false)
	insertSource("upload", "ready", true)
	search := &pgMemoryRecallSearch{}
	repo.search = search
	var snapshotsBefore int
	if err := repo.store.pool.QueryRow(ctx, `SELECT count(*) FROM core_knowledge_list_snapshots`).Scan(&snapshotsBefore); err != nil {
		t.Fatal(err)
	}
	page, err := repo.RecallMemory(ctx, "where do I live", 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(search.calls) != 2 || len(search.calls[0]) != 128 || len(search.calls[1]) != 1 || len(page.Matches) != 2 {
		t.Fatalf("batch sizes=%v matches=%+v", []int{len(search.calls[0]), len(search.calls[1])}, page.Matches)
	}
	var snapshotsAfter int
	if err := repo.store.pool.QueryRow(ctx, `SELECT count(*) FROM core_knowledge_list_snapshots`).Scan(&snapshotsAfter); err != nil {
		t.Fatal(err)
	}
	if snapshotsAfter != snapshotsBefore {
		t.Fatalf("private recall persisted search snapshot: before=%d after=%d", snapshotsBefore, snapshotsAfter)
	}
}

func TestCoreKnowledgePostgresMemoryRecallRequiresExactOwnerGeneration(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	owner := coretask.OwnerScope{OwnerID: "@knowledge-recall-owner:example.test", AccountGeneration: 3}
	ownerCtx, err := coretask.WithOwnerScope(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	profileID := uuid.NewString()
	digest := strings.Repeat("a", 64)
	createTestProfile(ctx, t, repo.store, profileID, "recall-scope-embedding", "recall-scope-secret")
	sources := []struct {
		id    string
		scope coretask.OwnerScope
	}{
		{id: "11111111-1111-4111-8111-111111111111", scope: owner},
		{id: "22222222-2222-4222-8222-222222222222", scope: coretask.OwnerScope{OwnerID: "@knowledge-recall-foreign:example.test", AccountGeneration: owner.AccountGeneration}},
		{id: "33333333-3333-4333-8333-333333333333", scope: coretask.OwnerScope{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration + 1}},
	}
	for _, source := range sources {
		if _, err := repo.store.pool.Exec(ctx, `INSERT INTO core_knowledge_sources(source_id,owner_id,account_generation,kind,status,title,digest,size_bytes,media_type,revision,promoted_generation,promoted_revision,promoted_profile_id,promoted_profile_revision,promoted_collection_config_digest) VALUES($1,$2,$3,'memory','ready','scoped recall',repeat('b',64),1,'text/plain',1,$4,1,$5,1,$6)`, source.id, source.scope.OwnerID, source.scope.AccountGeneration, "recall-"+source.id, profileID, digest); err != nil {
			t.Fatal(err)
		}
	}
	search := &pgMemoryRecallSearch{}
	repo.search = search
	page, err := repo.RecallMemory(ownerCtx, "where do I live", 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(search.calls) != 1 || len(search.calls[0]) != 1 || search.calls[0][0] != sources[0].id {
		t.Fatalf("recall candidate ids=%v, want only owner generation source %q", search.calls, sources[0].id)
	}
	if len(page.Matches) != 1 || page.Matches[0].SourceID != sources[0].id {
		t.Fatalf("recall matches=%+v, want only owner generation source %q", page.Matches, sources[0].id)
	}
}

func TestCoreKnowledgePostgresCreateMemoryDefaultsTitleBeforeReplayDigest(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	key := uuid.NewString()
	first, err := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: key, Content: "default title", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Title != "memory" {
		t.Fatalf("default memory title=%q, want memory", first.Title)
	}
	replay, err := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: key, Title: "memory", Content: "default title", MediaType: "text/plain"})
	if err != nil || replay.ID != first.ID || replay.Title != first.Title {
		t.Fatalf("normalized replay=%+v first=%+v err=%v", replay, first, err)
	}
	if _, err := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: key, Title: "different", Content: "default title", MediaType: "text/plain"}); !errors.Is(err, coreknowledge.ErrIdempotencyConflict) {
		t.Fatalf("changed title replay error=%v, want idempotency conflict", err)
	}
}

func TestCoreKnowledgeReplayIdentityIsOwnerGenerationScoped(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	ctxA, err := coretask.WithOwnerScope(ctx, coretask.OwnerScope{OwnerID: "@knowledge-replay-a:example.test", AccountGeneration: 3})
	if err != nil {
		t.Fatal(err)
	}
	ctxB, err := coretask.WithOwnerScope(ctx, coretask.OwnerScope{OwnerID: "@knowledge-replay-b:example.test", AccountGeneration: 8})
	if err != nil {
		t.Fatal(err)
	}
	key := uuid.NewString()
	a, err := repo.CreateMemory(ctxA, coreknowledge.MemoryCommand{
		IdempotencyKey: key, SourceID: uuid.NewString(), Title: "owner-a", Content: "owner-a", MediaType: "text/plain",
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := repo.CreateMemory(ctxB, coreknowledge.MemoryCommand{
		IdempotencyKey: key, SourceID: uuid.NewString(), Title: "owner-b", Content: "owner-b", MediaType: "text/plain",
	})
	if err != nil {
		t.Fatalf("owner-b create with same raw key: %v", err)
	}
	if a.ID == b.ID || a.Title != "owner-a" || b.Title != "owner-b" {
		t.Fatalf("cross-owner Knowledge replay a=%#v b=%#v", a, b)
	}
	var receipts int
	if err = repo.store.pool.QueryRow(ctx, `SELECT count(*) FROM core_knowledge_mutation_replays WHERE operation='memory' AND idempotency_key=$1`, key).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 2 {
		t.Fatalf("Knowledge replay receipts=%d, want 2", receipts)
	}
}

func TestPublicKnowledgeGeneratedIDsAreOwnerGenerationScoped(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	service, err := coreknowledge.NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	registry := agentcapability.NewCoreRegistry(agentcapability.CoreBindings{Knowledge: service})
	capability, ok := registry.Get("agent.knowledge.v1")
	if !ok {
		t.Fatal("Knowledge capability is not registered")
	}
	publicContext := func(owner string, generation int64) context.Context {
		return capabilityclient.WithCallContext(ctx, &capv1.CallContext{}, &capv1.PermissionContext{AuthenticatedOwnerId: owner, AccountGeneration: generation})
	}
	ctxA := publicContext("@knowledge-generated-a:example.test", 2)
	ctxB := publicContext("@knowledge-generated-b:example.test", 7)
	memoryKey := uuid.NewString()
	memoryRequest := []byte(fmt.Sprintf(`{"idempotency_key":%q,"title":"generated memory","content":"generated memory"}`, memoryKey))
	createMemory := func(callCtx context.Context) string {
		raw, callErr := capability.HandleOperation(callCtx, "create_memory", memoryRequest)
		if callErr != nil {
			t.Fatal(callErr)
		}
		var result struct {
			MemoryID string `json:"memory_id"`
		}
		if callErr = json.Unmarshal(raw, &result); callErr != nil {
			t.Fatal(callErr)
		}
		return result.MemoryID
	}
	memoryA, memoryB := createMemory(ctxA), createMemory(ctxB)
	if memoryA == "" || memoryB == "" || memoryA == memoryB {
		t.Fatalf("generated Memory IDs a=%q b=%q", memoryA, memoryB)
	}

	uploadKey := uuid.NewString()
	uploadBytes := []byte("generated upload")
	uploadDigest := sha256.Sum256(uploadBytes)
	uploadRequest := []byte(fmt.Sprintf(`{"idempotency_key":%q,"title":"generated upload","declared_size":%d,"content_sha256":%q,"media_type":"text/plain"}`, uploadKey, len(uploadBytes), hex.EncodeToString(uploadDigest[:])))
	startUpload := func(callCtx context.Context) (string, string) {
		raw, callErr := capability.HandleOperation(callCtx, "start_upload", uploadRequest)
		if callErr != nil {
			t.Fatal(callErr)
		}
		var result struct {
			UploadID string `json:"upload_id"`
			SourceID string `json:"source_id"`
		}
		if callErr = json.Unmarshal(raw, &result); callErr != nil {
			t.Fatal(callErr)
		}
		return result.UploadID, result.SourceID
	}
	uploadA, sourceA := startUpload(ctxA)
	uploadB, sourceB := startUpload(ctxB)
	if uploadA == "" || uploadB == "" || sourceA == "" || sourceB == "" || uploadA == uploadB || sourceA == sourceB {
		t.Fatalf("generated Upload IDs a=%q/%q b=%q/%q", uploadA, sourceA, uploadB, sourceB)
	}
}

func TestCoreKnowledgePublicResourcesAreOwnerGenerationScoped(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	service, err := coreknowledge.NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	registry := agentcapability.NewCoreRegistry(agentcapability.CoreBindings{Knowledge: service})
	capability, ok := registry.Get("agent.knowledge.v1")
	if !ok {
		t.Fatal("Knowledge capability is not registered")
	}
	publicContext := func(owner string, generation int64) context.Context {
		return capabilityclient.WithCallContext(ctx, &capv1.CallContext{}, &capv1.PermissionContext{AuthenticatedOwnerId: owner, AccountGeneration: generation})
	}
	ctxA := publicContext("@knowledge-resource-owner:example.test", 4)
	foreignContexts := []context.Context{
		publicContext("@knowledge-resource-foreign:example.test", 4),
		publicContext("@knowledge-resource-owner:example.test", 5),
	}
	call := func(callCtx context.Context, operation, request string) ([]byte, error) {
		t.Helper()
		return capability.HandleOperation(callCtx, operation, []byte(request))
	}
	createMemory := func(title, content string) string {
		t.Helper()
		raw, callErr := call(ctxA, "create_memory", fmt.Sprintf(`{"title":%q,"content":%q,"idempotency_key":%q}`, title, content, uuid.NewString()))
		if callErr != nil {
			t.Fatal(callErr)
		}
		var result struct {
			MemoryID string `json:"memory_id"`
		}
		if json.Unmarshal(raw, &result) != nil || result.MemoryID == "" {
			t.Fatalf("create Memory result=%s", raw)
		}
		return result.MemoryID
	}
	memoryA := createMemory("owner memory a", "owner-only memory a")
	_ = createMemory("owner memory b", "owner-only memory b")

	uploadBytes := []byte("abc")
	uploadDigest := sha256.Sum256(uploadBytes)
	startRaw, err := call(ctxA, "start_upload", fmt.Sprintf(`{"title":"owner upload","declared_size":3,"content_sha256":%q,"media_type":"text/plain","idempotency_key":%q}`, hex.EncodeToString(uploadDigest[:]), uuid.NewString()))
	if err != nil {
		t.Fatal(err)
	}
	var upload struct {
		UploadID string `json:"upload_id"`
		SourceID string `json:"source_id"`
	}
	if json.Unmarshal(startRaw, &upload) != nil || upload.UploadID == "" || upload.SourceID == "" {
		t.Fatalf("start Upload result=%s", startRaw)
	}

	listRaw, err := call(ctxA, "list_sources", `{"limit":1}`)
	if err != nil {
		t.Fatal(err)
	}
	var sourcePage struct {
		NextPageToken string `json:"next_page_token"`
	}
	if json.Unmarshal(listRaw, &sourcePage) != nil || sourcePage.NextPageToken == "" {
		t.Fatalf("owner source page=%s", listRaw)
	}
	searchRaw, err := call(ctxA, "search_memory", fmt.Sprintf(`{"query":"owner-only","source_ids":[%q],"limit":1}`, memoryA))
	if err != nil {
		t.Fatal(err)
	}
	var searchPage struct {
		NextCursor string `json:"next_cursor"`
	}
	if json.Unmarshal(searchRaw, &searchPage) != nil || searchPage.NextCursor == "" {
		t.Fatalf("owner search page=%s", searchRaw)
	}

	for index, foreign := range foreignContexts {
		for _, request := range []struct {
			operation string
			payload   string
		}{
			{"get_source", fmt.Sprintf(`{"source_id":%q}`, memoryA)},
			{"get_memory", fmt.Sprintf(`{"memory_id":%q}`, memoryA)},
			{"update_memory", fmt.Sprintf(`{"memory_id":%q,"expected_revision":1,"title":"stolen","content":"stolen","idempotency_key":%q}`, memoryA, uuid.NewString())},
			{"delete_memory", fmt.Sprintf(`{"memory_id":%q,"expected_revision":1,"idempotency_key":%q}`, memoryA, uuid.NewString())},
			{"delete_source", fmt.Sprintf(`{"source_id":%q,"expected_revision":1,"idempotency_key":%q}`, upload.SourceID, uuid.NewString())},
			{"append_upload_chunk", fmt.Sprintf(`{"upload_id":%q,"ordinal":0,"offset_bytes":0,"data":"YWJj","chunk_sha256":%q,"idempotency_key":%q}`, upload.UploadID, hex.EncodeToString(uploadDigest[:]), uuid.NewString())},
			{"commit_upload", fmt.Sprintf(`{"upload_id":%q,"expected_revision":1,"content_sha256":%q,"idempotency_key":%q}`, upload.UploadID, hex.EncodeToString(uploadDigest[:]), uuid.NewString())},
			{"search_memory", fmt.Sprintf(`{"query":"owner-only","source_ids":[%q],"limit":1}`, memoryA)},
		} {
			if _, callErr := call(foreign, request.operation, request.payload); !errors.Is(callErr, coreknowledge.ErrNotFound) {
				t.Fatalf("foreign context %d %s err=%v, want not found", index, request.operation, callErr)
			}
		}
		foreignList, callErr := call(foreign, "list_sources", `{}`)
		if callErr != nil {
			t.Fatalf("foreign context %d list: %v", index, callErr)
		}
		var listed struct {
			Sources []json.RawMessage `json:"sources"`
		}
		if json.Unmarshal(foreignList, &listed) != nil || len(listed.Sources) != 0 {
			t.Fatalf("foreign context %d listed owner sources: %s", index, foreignList)
		}
		foreignMemories, callErr := call(foreign, "list_memories", `{}`)
		if callErr != nil {
			t.Fatalf("foreign context %d list memories: %v", index, callErr)
		}
		var memories struct {
			Items []json.RawMessage `json:"items"`
		}
		if json.Unmarshal(foreignMemories, &memories) != nil || len(memories.Items) != 0 {
			t.Fatalf("foreign context %d listed owner memories: %s", index, foreignMemories)
		}
		statusRaw, callErr := call(foreign, "status", `{}`)
		if callErr != nil {
			t.Fatalf("foreign context %d status: %v", index, callErr)
		}
		var status struct {
			Count int `json:"count"`
		}
		if json.Unmarshal(statusRaw, &status) != nil || status.Count != 0 {
			t.Fatalf("foreign context %d status counted owner sources: %s", index, statusRaw)
		}
		if _, callErr = call(foreign, "list_sources", fmt.Sprintf(`{"limit":1,"page_token":%q}`, sourcePage.NextPageToken)); !errors.Is(callErr, coreknowledge.ErrCursorConflict) {
			t.Fatalf("foreign context %d reused owner list cursor err=%v", index, callErr)
		}
		if _, callErr = call(foreign, "search_memory", fmt.Sprintf(`{"query":"owner-only","source_ids":[%q],"limit":1,"page_token":%q}`, memoryA, searchPage.NextCursor)); !errors.Is(callErr, coreknowledge.ErrCursorConflict) {
			t.Fatalf("foreign context %d reused owner search cursor err=%v", index, callErr)
		}
	}

	if _, err = call(ctxA, "append_upload_chunk", fmt.Sprintf(`{"upload_id":%q,"ordinal":0,"offset_bytes":0,"data":"YWJj","chunk_sha256":%q,"idempotency_key":%q}`, upload.UploadID, hex.EncodeToString(uploadDigest[:]), uuid.NewString())); err != nil {
		t.Fatalf("owner append after foreign attempts: %v", err)
	}
	if _, err = call(ctxA, "commit_upload", fmt.Sprintf(`{"upload_id":%q,"expected_revision":2,"content_sha256":%q,"idempotency_key":%q}`, upload.UploadID, hex.EncodeToString(uploadDigest[:]), uuid.NewString())); err != nil {
		t.Fatalf("owner commit after foreign attempts: %v", err)
	}
}

func TestCoreKnowledgeEmbeddingConfigIsOwnerGenerationScoped(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	ownerA := coretask.OwnerScope{OwnerID: "@knowledge-config-owner:example.test", AccountGeneration: 3}
	ownerB := coretask.OwnerScope{OwnerID: "@knowledge-config-foreign:example.test", AccountGeneration: 3}
	ownerANext := coretask.OwnerScope{OwnerID: ownerA.OwnerID, AccountGeneration: 4}
	ctxA, err := coretask.WithOwnerScope(ctx, ownerA)
	if err != nil {
		t.Fatal(err)
	}
	ctxB, err := coretask.WithOwnerScope(ctx, ownerB)
	if err != nil {
		t.Fatal(err)
	}
	ctxANext, err := coretask.WithOwnerScope(ctx, ownerANext)
	if err != nil {
		t.Fatal(err)
	}
	profiles := []struct {
		ctx   context.Context
		id    string
		model string
	}{
		{ctxA, uuid.NewString(), "owner-a-embedding"},
		{ctxB, uuid.NewString(), "owner-b-embedding"},
		{ctxANext, uuid.NewString(), "owner-a-next-embedding"},
	}
	digest := strings.Repeat("f", 64)
	for _, profile := range profiles {
		createTestProfile(profile.ctx, t, repo.store, profile.id, profile.model, profile.model+"-secret")
		config, ensureErr := repo.EnsureEmbeddingConfig(profile.ctx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: profile.id, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: digest, Revision: 1})
		if ensureErr != nil {
			t.Fatalf("ensure %s config: %v", profile.model, ensureErr)
		}
		if config.EmbeddingProfileID != profile.id {
			t.Fatalf("%s config profile=%s want=%s", profile.model, config.EmbeddingProfileID, profile.id)
		}
	}
	for _, profile := range profiles {
		config, getErr := repo.GetEmbeddingConfig(profile.ctx)
		if getErr != nil || config.EmbeddingProfileID != profile.id || config.Revision != 1 {
			t.Fatalf("get %s config=%+v err=%v", profile.model, config, getErr)
		}
	}
}

func TestCoreKnowledgePostgresSearchCursorPinsProvenanceAcrossRebind(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	oldProfile, newProfile := uuid.NewString(), uuid.NewString()
	digest := strings.Repeat("a", 64)
	if _, err := repo.EnsureEmbeddingConfig(ctx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: oldProfile, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: digest, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	searchRepo, err := NewCoreKnowledgeStore(repo.store, CoreKnowledgeStoreConfig{Content: repo.content, ManagedFiles: pgKnowledgeOpener{}, Search: pgKnowledgeProvenanceSearch{profileID: oldProfile, digest: digest}})
	if err != nil {
		t.Fatal(err)
	}
	source, err := searchRepo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), SourceID: uuid.NewString(), Content: "pinned semantic result", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := searchRepo.Search(ctx, coreknowledge.SearchQuery{Query: "semantic", SourceIDs: []string{source.ID}, Limit: 1})
	if err != nil || len(first.Matches) != 1 || first.NextPageToken == "" {
		t.Fatalf("first search=%+v err=%v", first, err)
	}
	if first.EmbeddingProfileID != oldProfile || first.EmbeddingProfileRevision != 7 || first.EmbeddingModel != "embedding-model-v1" || first.EmbeddingGeneration != "generation-v1" || first.CollectionConfigDigest != digest {
		t.Fatalf("first provenance=%+v", first.SearchProvenance)
	}
	if _, err := searchRepo.UpdateEmbeddingConfig(ctx, coreknowledge.EmbeddingConfigCommand{IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, EmbeddingProfileID: newProfile, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: digest}); err != nil {
		t.Fatal(err)
	}
	second, err := searchRepo.Search(ctx, coreknowledge.SearchQuery{Query: "semantic", SourceIDs: []string{source.ID}, Limit: 1, PageToken: first.NextPageToken})
	if err != nil || len(second.Matches) != 1 || second.Matches[0].ChunkRef != "chunk:1" {
		t.Fatalf("second search=%+v err=%v", second, err)
	}
	if second.EmbeddingProfileID != oldProfile || second.EmbeddingProfileRevision != 7 || second.EmbeddingModel != "embedding-model-v1" || second.EmbeddingGeneration != "generation-v1" || second.CollectionConfigDigest != digest {
		t.Fatalf("rebound cursor relabeled provenance=%+v", second.SearchProvenance)
	}
	var snapshotProfile, snapshotModel, snapshotGeneration, snapshotDigest string
	var snapshotRevision int64
	if err := searchRepo.store.pool.QueryRow(ctx, `SELECT embedding_profile_id::text,embedding_profile_revision,embedding_model,embedding_generation,embedding_collection_config_digest FROM core_knowledge_list_snapshots WHERE snapshot_id=$1`, decodeSnapshotIDForTest(t, first.NextPageToken)).Scan(&snapshotProfile, &snapshotRevision, &snapshotModel, &snapshotGeneration, &snapshotDigest); err != nil {
		t.Fatal(err)
	}
	if snapshotProfile != oldProfile || snapshotRevision != 7 || snapshotModel != "embedding-model-v1" || snapshotGeneration != "generation-v1" || snapshotDigest != digest {
		t.Fatalf("snapshot provenance=%q/%d/%q/%q/%q", snapshotProfile, snapshotRevision, snapshotModel, snapshotGeneration, snapshotDigest)
	}
}

func decodeSnapshotIDForTest(t *testing.T, token string) string {
	t.Helper()
	c, err := decodeKnowledgeCursor(token)
	if err != nil {
		t.Fatal(err)
	}
	return c.SnapshotID
}

func TestCoreKnowledgePostgresMemoryReplacementCleanupRecoversAfterDeleteFailure(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	content := repo.content.(*pgKnowledgeContent)
	memory, err := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{
		IdempotencyKey: uuid.NewString(), Title: "replace me", Content: "old memory", MediaType: "text/plain",
	})
	if err != nil {
		t.Fatal(err)
	}
	var oldRef string
	if err := repo.store.pool.QueryRow(ctx, `SELECT content_ref FROM core_knowledge_sources WHERE source_id=$1`, memory.ID).Scan(&oldRef); err != nil {
		t.Fatal(err)
	}
	content.mu.Lock()
	content.failDelete = true
	content.mu.Unlock()
	updated, err := repo.UpdateMemory(ctx, coreknowledge.UpdateMemoryCommand{
		IdempotencyKey: uuid.NewString(), SourceID: memory.ID, ExpectedRevision: memory.Revision,
		Title: "replaced", Content: "new memory", MediaType: "text/plain",
	})
	if err != nil || updated.Revision != memory.Revision+1 {
		t.Fatalf("metadata replacement failed after old delete outage: updated=%+v err=%v", updated, err)
	}
	var operation, pendingRef string
	var attempts int
	if err := repo.store.pool.QueryRow(ctx, `SELECT operation,content_ref,attempts FROM core_knowledge_cleanup WHERE source_id=$1`, memory.ID).Scan(&operation, &pendingRef, &attempts); err != nil {
		t.Fatal(err)
	}
	if operation != knowledgeMemoryReplaceCleanup || pendingRef != oldRef || attempts < 1 {
		t.Fatalf("replacement cleanup intent=%q ref=%q attempts=%d", operation, pendingRef, attempts)
	}
	content.mu.Lock()
	_, oldStillPresent := content.objects[oldRef]
	content.mu.Unlock()
	if !oldStillPresent {
		t.Fatal("injected delete failure unexpectedly removed old content")
	}
	if _, err := repo.UpdateMemory(ctx, coreknowledge.UpdateMemoryCommand{
		IdempotencyKey: uuid.NewString(), SourceID: memory.ID, ExpectedRevision: updated.Revision,
		Title: "blocked while cleanup pending", Content: "must wait", MediaType: "text/plain",
	}); err != coreknowledge.ErrCleanupPending {
		t.Fatalf("replacement update crossed pending cleanup boundary: %v", err)
	}
	fresh, err := NewCoreKnowledgeStore(repo.store, CoreKnowledgeStoreConfig{Content: content, ManagedFiles: pgKnowledgeOpener{}, Search: pgKnowledgeSearch{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.RecoverPendingCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := repo.store.pool.QueryRow(ctx, `SELECT count(*) FROM core_knowledge_cleanup WHERE source_id=$1 AND operation=$2`, memory.ID, knowledgeMemoryReplaceCleanup).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("replacement cleanup intent remained after recovery: %d", remaining)
	}
	content.mu.Lock()
	_, oldStillPresent = content.objects[oldRef]
	content.mu.Unlock()
	if oldStillPresent {
		t.Fatal("recovery did not remove old content")
	}
	var currentRef string
	if err := repo.store.pool.QueryRow(ctx, `SELECT content_ref FROM core_knowledge_sources WHERE source_id=$1`, memory.ID).Scan(&currentRef); err != nil {
		t.Fatal(err)
	}
	if currentRef == oldRef || currentRef == "" {
		t.Fatalf("current content ref=%q after replacement", currentRef)
	}
}

func TestCoreKnowledgeRecoveryUpdatesPublicOwnerReplay(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	owner := coretask.OwnerScope{OwnerID: "@knowledge-recovery-owner:example.test", AccountGeneration: 6}
	ownerCtx, err := coretask.WithOwnerScope(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	memory, err := repo.CreateMemory(ownerCtx, coreknowledge.MemoryCommand{
		IdempotencyKey: uuid.NewString(), SourceID: uuid.NewString(), Title: "recover delete", Content: "recover delete", MediaType: "text/plain",
	})
	if err != nil {
		t.Fatal(err)
	}
	content, ok := repo.content.(*pgKnowledgeContent)
	if !ok {
		t.Fatal("unexpected Knowledge content fixture")
	}
	content.failDelete = true
	deleteKey := uuid.NewString()
	command := coreknowledge.DeleteCommand{IdempotencyKey: deleteKey, SourceID: memory.ID, ExpectedRevision: memory.Revision, Kind: coreknowledge.SourceKindMemory}
	if _, err = repo.Delete(ownerCtx, command); !errors.Is(err, coreknowledge.ErrCleanupPending) {
		t.Fatalf("initial delete err=%v, want cleanup pending", err)
	}
	if err = repo.RecoverPendingCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	var status string
	if err = repo.store.pool.QueryRow(ctx, `SELECT status FROM core_knowledge_sources WHERE source_id=$1`, memory.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != string(coreknowledge.SourceStatusDeleted) {
		t.Fatalf("recovered public source status=%q, want deleted", status)
	}
	var raw []byte
	if err = repo.store.pool.QueryRow(ctx, `SELECT response_json FROM core_knowledge_mutation_replays WHERE owner_id=$1 AND account_generation=$2 AND operation='delete' AND idempotency_key=$3`, owner.OwnerID, owner.AccountGeneration, deleteKey).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var replay knowledgeReplay
	if err = json.Unmarshal(raw, &replay); err != nil || replay.Source.Status != coreknowledge.SourceStatusDeleted {
		t.Fatalf("recovered public replay=%#v err=%v", replay, err)
	}
}

func TestCoreKnowledgePostgresDeleteResolvesPendingMemoryReplacement(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	content := repo.content.(*pgKnowledgeContent)
	memory, err := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), Title: "before delete", Content: "before delete", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	content.mu.Lock()
	content.failDelete = true
	content.mu.Unlock()
	updated, err := repo.UpdateMemory(ctx, coreknowledge.UpdateMemoryCommand{IdempotencyKey: uuid.NewString(), SourceID: memory.ID, ExpectedRevision: memory.Revision, Title: "replacement", Content: "replacement", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := repo.Delete(ctx, coreknowledge.DeleteCommand{IdempotencyKey: uuid.NewString(), SourceID: memory.ID, ExpectedRevision: updated.Revision, Kind: coreknowledge.SourceKindMemory})
	if err != nil || deleted.Status != coreknowledge.SourceStatusDeleted {
		t.Fatalf("delete did not resolve replacement cleanup: deleted=%+v err=%v", deleted, err)
	}
	var pending int
	if err := repo.store.pool.QueryRow(ctx, `SELECT count(*) FROM core_knowledge_cleanup WHERE source_id=$1`, memory.ID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("cleanup ledger remained after source delete: %d", pending)
	}
	content.mu.Lock()
	remaining := len(content.objects)
	content.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("content objects remained after replacement/delete convergence: %d", remaining)
	}
}

func TestCoreKnowledgePostgresListMemoriesHidesDeletedContent(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	memory, err := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{
		IdempotencyKey: uuid.NewString(),
		Title:          "delete me",
		Content:        "plaintext must not be reopened after delete",
		MediaType:      "text/plain",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.Delete(ctx, coreknowledge.DeleteCommand{
		IdempotencyKey:   uuid.NewString(),
		SourceID:         memory.ID,
		ExpectedRevision: memory.Revision,
		Kind:             coreknowledge.SourceKindMemory,
	}); err != nil {
		t.Fatal(err)
	}
	page, err := repo.ListMemories(ctx, coreknowledge.ListQuery{PageSize: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range page.Items {
		if item.ID == memory.ID {
			t.Fatalf("deleted memory was listed: %#v", item)
		}
	}
	if _, err = repo.GetMemory(ctx, memory.ID); !errors.Is(err, coreknowledge.ErrNotFound) {
		t.Fatalf("deleted memory get error = %v, want ErrNotFound", err)
	}
}

func TestCoreKnowledgePostgresAutoIndexCandidateAndPromotionProjection(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	profileID := uuid.NewString()
	collectionDigest := strings.Repeat("a", 64)
	createTestProfile(ctx, t, repo.store, profileID, "auto-index-embed", "auto-index-secret")
	config, err := repo.EnsureEmbeddingConfig(ctx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: profileID, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: collectionDigest, Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	source, err := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), SourceID: uuid.NewString(), Title: "auto-index", Content: "restart safe semantic memory", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := repo.ListAutoIndexCandidates(ctx, config.EmbeddingProfileID, config.CollectionConfigDigest, 8)
	if err != nil || len(candidates) != 1 || candidates[0].ID != source.ID {
		t.Fatalf("unpromoted candidates = %+v err=%v", candidates, err)
	}
	state, err := repo.GetEmbeddingSourceStatus(ctx, source.ID, config)
	if err != nil || state.Indexed || state.Status != coreknowledge.SourceStatusReady || !state.Stale {
		t.Fatalf("unpromoted state = %+v err=%v", state, err)
	}
	generation := "auto-generation-" + uuid.NewString()
	if _, err := repo.store.pool.Exec(ctx, `UPDATE core_knowledge_sources SET promoted_generation=$2,promoted_revision=revision,promoted_profile_id=$3,promoted_profile_revision=1,promoted_collection_config_digest=$4 WHERE source_id=$1`, source.ID, generation, profileID, collectionDigest); err != nil {
		t.Fatal(err)
	}
	state, err = repo.GetEmbeddingSourceStatus(ctx, source.ID, config)
	if err != nil || !state.Indexed || state.Stale || state.PromotedRevision != source.Revision {
		t.Fatalf("promoted state = %+v err=%v", state, err)
	}
	candidates, err = repo.ListAutoIndexCandidates(ctx, config.EmbeddingProfileID, config.CollectionConfigDigest, 8)
	if err != nil || len(candidates) != 0 {
		t.Fatalf("promoted candidates = %+v err=%v", candidates, err)
	}
}

func TestCoreKnowledgeAutoIndexCandidatesRequireExactOwnerScope(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	ownerA := coretask.OwnerScope{OwnerID: "@knowledge-candidate-a:example.test", AccountGeneration: 3}
	ownerB := coretask.OwnerScope{OwnerID: "@knowledge-candidate-b:example.test", AccountGeneration: 8}
	ctxA, err := coretask.WithOwnerScope(ctx, ownerA)
	if err != nil {
		t.Fatal(err)
	}
	ctxB, err := coretask.WithOwnerScope(ctx, ownerB)
	if err != nil {
		t.Fatal(err)
	}
	internal, err := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), SourceID: uuid.NewString(), Content: "internal", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	sourceA, err := repo.CreateMemory(ctxA, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), SourceID: uuid.NewString(), Content: "owner a", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	sourceB, err := repo.CreateMemory(ctxB, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), SourceID: uuid.NewString(), Content: "owner b", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	profileID, digest := uuid.NewString(), strings.Repeat("9", 64)
	for name, scoped := range map[string]struct {
		ctx  context.Context
		want string
	}{
		"internal": {ctx: ctx, want: internal.ID},
		"owner_a":  {ctx: ctxA, want: sourceA.ID},
		"owner_b":  {ctx: ctxB, want: sourceB.ID},
	} {
		t.Run(name, func(t *testing.T) {
			candidates, listErr := repo.ListAutoIndexCandidates(scoped.ctx, profileID, digest, 8)
			if listErr != nil || len(candidates) != 1 || candidates[0].ID != scoped.want {
				t.Fatalf("candidates=%+v err=%v, want only %s", candidates, listErr, scoped.want)
			}
		})
	}
	scopes, err := ListKnowledgeOwnerScopes(ctx, repo.store, 8)
	if err != nil || len(scopes) != 2 || scopes[0] != ownerA || scopes[1] != ownerB {
		t.Fatalf("public Knowledge scopes=%+v err=%v, want owner A and B only", scopes, err)
	}
}

func TestCoreKnowledgeIndexerAutoExplicitAndConcurrentReplay(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	profileID := uuid.NewString()
	createTestProfile(ctx, t, repo.store, profileID, "auto-index-embed", "auto-index-secret")
	collectionDigest := strings.Repeat("d", 64)
	config, err := repo.EnsureEmbeddingConfig(ctx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: profileID, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: collectionDigest, Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	indexer, err := NewKnowledgeIndexer(repo.store, profileID, config.Dimension, collectionDigest)
	if err != nil {
		t.Fatal(err)
	}
	indexer.SetEmbeddingConfigReader(repo)
	service, err := coreknowledge.NewService(repo, indexer)
	if err != nil {
		t.Fatal(err)
	}
	source, err := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), SourceID: uuid.NewString(), Content: "automatic task", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	autoKey := uuid.NewString()
	auto, err := indexer.RequestIndex(ctx, coreknowledge.IndexRequest{IdempotencyKey: autoKey, SourceIDs: []string{source.ID}})
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := service.Index(ctx, coreknowledge.IndexRequest{IdempotencyKey: uuid.NewString(), SourceIDs: []string{source.ID}})
	if err != nil || explicit.TaskID != auto.TaskID {
		t.Fatalf("explicit request did not converge on automatic task: explicit=%+v auto=%+v err=%v", explicit, auto, err)
	}
	restarted, err := NewKnowledgeIndexer(repo.store, config.EmbeddingProfileID, config.Dimension, config.CollectionConfigDigest)
	if err != nil {
		t.Fatal(err)
	}
	restarted.SetEmbeddingConfigReader(repo)
	replayed, err := restarted.RequestIndex(ctx, coreknowledge.IndexRequest{IdempotencyKey: autoKey, SourceIDs: []string{source.ID}})
	if err != nil || replayed.TaskID != auto.TaskID {
		t.Fatalf("restart replay changed automatic task: replay=%+v auto=%+v err=%v", replayed, auto, err)
	}
	concurrentSource, err := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), SourceID: uuid.NewString(), Content: "concurrent task", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{uuid.NewString(), uuid.NewString()}
	refs := make([]coreknowledge.TaskReference, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for n := range keys {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			refs[index], errs[index] = indexer.RequestIndex(ctx, coreknowledge.IndexRequest{IdempotencyKey: keys[index], SourceIDs: []string{concurrentSource.ID}})
		}(n)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || refs[0].TaskID == "" || refs[0].TaskID != refs[1].TaskID {
		t.Fatalf("concurrent requests diverged: refs=%+v errs=%v", refs, errs)
	}
	if _, err := service.Index(ctx, coreknowledge.IndexRequest{IdempotencyKey: uuid.NewString(), SourceIDs: []string{source.ID, concurrentSource.ID}}); err != coreknowledge.ErrIneligible {
		t.Fatalf("different source set unexpectedly converged: %v", err)
	}
}

func TestCoreKnowledgeAutoIndexPreservesSourceOwnerScope(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	ownerA := coretask.OwnerScope{OwnerID: "@knowledge-owner-a:example.test", AccountGeneration: 4}
	ownerB := coretask.OwnerScope{OwnerID: "@knowledge-owner-b:example.test", AccountGeneration: 9}
	ctxA, err := coretask.WithOwnerScope(ctx, ownerA)
	if err != nil {
		t.Fatal(err)
	}
	ctxB, err := coretask.WithOwnerScope(ctx, ownerB)
	if err != nil {
		t.Fatal(err)
	}
	profileID := uuid.NewString()
	createTestProfile(ctxA, t, repo.store, profileID, "owner-index-embed", "owner-index-secret")
	digest := strings.Repeat("e", 64)
	if _, err = repo.EnsureEmbeddingConfig(ctxA, coreknowledge.EmbeddingConfig{EmbeddingProfileID: profileID, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: digest, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	source, err := repo.CreateMemory(ctxA, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), SourceID: uuid.NewString(), Content: "owner scoped automatic task", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	indexer, err := NewKnowledgeIndexer(repo.store, profileID, 2, digest)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := indexer.RequestIndex(ctxA, coreknowledge.IndexRequest{IdempotencyKey: uuid.NewString(), SourceIDs: []string{source.ID}})
	if err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(repo.store)
	if _, err = tasks.GetTask(ctxB, ref.TaskID); !errors.Is(err, coretask.ErrNotFound) {
		t.Fatalf("foreign owner read auto-index Task err=%v", err)
	}
	if task, ownerErr := tasks.GetTask(ctxA, ref.TaskID); ownerErr != nil || task.ID != ref.TaskID {
		t.Fatalf("owner read auto-index Task=%#v err=%v", task, ownerErr)
	}
}

func TestCoreKnowledgePostgresEmbeddingBindingMarksReadySourceStaleAndRequeues(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	oldProfile, newProfile := uuid.NewString(), uuid.NewString()
	createTestProfile(ctx, t, repo.store, oldProfile, "old-embed", "old-secret")
	createTestProfile(ctx, t, repo.store, newProfile, "new-embed", "new-secret")
	digest := strings.Repeat("f", 64)
	config, err := repo.EnsureEmbeddingConfig(ctx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: oldProfile, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: digest, Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	source, err := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), SourceID: uuid.NewString(), Content: "already promoted", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.store.pool.Exec(ctx, `UPDATE core_knowledge_sources SET promoted_generation=$2,promoted_revision=revision,promoted_profile_id=$3,promoted_profile_revision=1,promoted_collection_config_digest=$4 WHERE source_id=$1`, source.ID, "generation-old", oldProfile, digest); err != nil {
		t.Fatal(err)
	}
	indexer, err := NewKnowledgeIndexer(repo.store, oldProfile, 2, digest)
	if err != nil {
		t.Fatal(err)
	}
	indexer.SetEmbeddingConfigReader(repo)
	service, err := coreknowledge.NewService(repo, indexer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.BindEmbeddingProfile(ctx, newProfile); err != nil {
		t.Fatal(err)
	}
	bound, err := repo.GetEmbeddingConfig(ctx)
	if err != nil || bound.EmbeddingProfileID != newProfile || bound.Revision != config.Revision+1 {
		t.Fatalf("bound config=%+v err=%v", bound, err)
	}
	state, err := repo.GetEmbeddingSourceStatus(ctx, source.ID, bound)
	if err != nil || !state.Stale || state.Indexed {
		t.Fatalf("ready source did not become stale after binding: %+v err=%v", state, err)
	}
	if err := service.ReconcileAutoIndex(ctx, 8); err != nil {
		t.Fatal(err)
	}
	state, err = repo.GetEmbeddingSourceStatus(ctx, source.ID, bound)
	if err != nil || state.Status != coreknowledge.SourceStatusIndexing {
		t.Fatalf("stale source was not requeued: %+v err=%v", state, err)
	}
	var jobs int
	if err := repo.store.pool.QueryRow(ctx, `SELECT count(*) FROM core_knowledge_index_jobs WHERE source_ids @> jsonb_build_array($1::text) AND profile_id=$2::uuid AND status='queued'`, source.ID, newProfile).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatalf("new binding index job count=%d err=%v", jobs, err)
	}
}

func TestCoreKnowledgePostgresListCursorFreezesProjection(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	a, _ := repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), Title: "a", Content: "a", MediaType: "text/plain"})
	_, _ = repo.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), Title: "b", Content: "b", MediaType: "text/plain"})
	page, err := repo.List(ctx, coreknowledge.ListQuery{PageSize: 1})
	if err != nil || len(page.Sources) != 1 || page.NextPageToken == "" {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	if _, err = repo.Delete(ctx, coreknowledge.DeleteCommand{IdempotencyKey: uuid.NewString(), SourceID: a.ID, ExpectedRevision: a.Revision}); err != nil {
		t.Fatal(err)
	}
	next, err := repo.List(ctx, coreknowledge.ListQuery{PageSize: 1, PageToken: page.NextPageToken})
	if err != nil || len(next.Sources) != 1 {
		t.Fatalf("next=%#v err=%v", next, err)
	}
}

func TestCoreKnowledgePostgresResumeAfterRenameBeforeMetadata(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	store := repo.store
	root := t.TempDir()
	content, err := coreknowledge.NewRootContentPort(root, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer content.Close()
	repo, err = NewCoreKnowledgeStore(store, CoreKnowledgeStoreConfig{Content: content})
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("rename-before-metadata")
	h := sha256.Sum256(data)
	digest := hex.EncodeToString(h[:])
	meta := coreknowledge.UploadMetadata{UploadID: uuid.NewString(), SourceID: uuid.NewString(), IdempotencyKey: uuid.NewString(), Title: "uncertain", MediaType: "text/plain", DeclaredSize: int64(len(data)), ContentSHA256: digest}
	u, err := repo.StartUpload(ctx, meta)
	if err != nil {
		t.Fatal(err)
	}
	if u, err = repo.AppendUploadChunk(ctx, coreknowledge.UploadChunk{IdempotencyKey: uuid.NewString(), UploadID: u.ID, Ordinal: 0, OffsetBytes: 0, Data: data, ChunkSHA256: digest}); err != nil {
		t.Fatal(err)
	}
	// Simulate the crash window after the content rename and before the DB
	// metadata transaction commits. A fresh repository must discover the final
	// deterministic object and repeat Finalize idempotently.
	sink, err := repo.sinkFor(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sink.Finalize(ctx, digest, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewCoreKnowledgeStore(store, CoreKnowledgeStoreConfig{Content: content})
	if err != nil {
		t.Fatal(err)
	}
	_, source, err := fresh.CommitUpload(ctx, coreknowledge.CommitUploadCommand{IdempotencyKey: uuid.NewString(), UploadID: u.ID, ExpectedRevision: u.Revision, ContentSHA256: digest})
	if err != nil || source.Status != coreknowledge.SourceStatusReady {
		t.Fatalf("resume commit source=%+v err=%v", source, err)
	}
	// Two uploads with identical bytes receive distinct immutable references.
	meta2 := meta
	meta2.UploadID, meta2.SourceID, meta2.IdempotencyKey = uuid.NewString(), uuid.NewString(), uuid.NewString()
	u2, err := fresh.StartUpload(ctx, meta2)
	if err != nil {
		t.Fatal(err)
	}
	if u2, err = fresh.AppendUploadChunk(ctx, coreknowledge.UploadChunk{IdempotencyKey: uuid.NewString(), UploadID: u2.ID, Ordinal: 0, OffsetBytes: 0, Data: data, ChunkSHA256: digest}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = fresh.CommitUpload(ctx, coreknowledge.CommitUploadCommand{IdempotencyKey: uuid.NewString(), UploadID: u2.ID, ExpectedRevision: u2.Revision, ContentSHA256: digest}); err != nil {
		t.Fatal(err)
	}
	var ref1, ref2 string
	if err = store.pool.QueryRow(ctx, `SELECT content_ref FROM core_knowledge_sources WHERE source_id=$1`, source.ID).Scan(&ref1); err != nil {
		t.Fatal(err)
	}
	if err = store.pool.QueryRow(ctx, `SELECT content_ref FROM core_knowledge_sources WHERE source_id=$1`, meta2.SourceID).Scan(&ref2); err != nil {
		t.Fatal(err)
	}
	if ref1 == "" || ref1 == ref2 || filepath.Base(ref1) == filepath.Base(ref2) {
		t.Fatalf("same-digest refs are not distinct: %q %q", ref1, ref2)
	}
}
