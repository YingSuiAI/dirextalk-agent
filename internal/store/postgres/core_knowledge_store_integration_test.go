package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
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

func knowledgePGFixture(t *testing.T) (context.Context, *CoreKnowledgeStore, func()) {
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
	store, err := New(pool, instance)
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
