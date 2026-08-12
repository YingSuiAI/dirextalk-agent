package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type pgKnowledgeContent struct {
	objects map[string][]byte
}

func (p *pgKnowledgeContent) Begin(context.Context, coreknowledge.UploadMetadata) (coreknowledge.ContentSink, error) {
	return &pgKnowledgeSink{parent: p}, nil
}

func (p *pgKnowledgeContent) Delete(_ context.Context, ref coreknowledge.ContentReference) error {
	delete(p.objects, ref.Ref)
	return nil
}

type pgKnowledgeSink struct {
	parent *pgKnowledgeContent
	data   []byte
}

func (s *pgKnowledgeSink) Write(data []byte) (int, error) {
	s.data = append(s.data, data...)
	return len(data), nil
}

func (s *pgKnowledgeSink) Size() int64 { return int64(len(s.data)) }
func (s *pgKnowledgeSink) SHA256() string {
	digest := sha256.Sum256(s.data)
	return hex.EncodeToString(digest[:])
}
func (s *pgKnowledgeSink) Finalize(_ context.Context, digest string, size int64) (coreknowledge.ContentReference, error) {
	if size != s.Size() || !strings.EqualFold(digest, s.SHA256()) {
		return coreknowledge.ContentReference{}, coreknowledge.ErrChecksumMismatch
	}
	if s.parent.objects == nil {
		s.parent.objects = make(map[string][]byte)
	}
	ref := "pg-content-" + uuid.NewString()
	s.parent.objects[ref] = append([]byte(nil), s.data...)
	return coreknowledge.ContentReference{Ref: ref, Digest: s.SHA256(), SizeBytes: size}, nil
}
func (s *pgKnowledgeSink) Abort(context.Context) error { return nil }

type pgKnowledgeOpener struct{}

func (pgKnowledgeOpener) OpenManaged(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("mounted")), nil
}

type pgKnowledgeSearch struct{}

func (pgKnowledgeSearch) Search(_ context.Context, query coreknowledge.SearchQuery) (coreknowledge.SearchPage, error) {
	if len(query.SourceIDs) == 0 {
		return coreknowledge.SearchPage{}, coreknowledge.ErrInvalid
	}
	id := query.SourceIDs[0]
	return coreknowledge.SearchPage{Matches: []coreknowledge.SearchMatch{
		{SourceID: id, ChunkRef: "chunk:0", Snippet: "verified semantic result 0", Score: .9},
		{SourceID: id, ChunkRef: "chunk:1", Snippet: "verified semantic result 1", Score: .8},
	}}, nil
}

func createTestEmbeddingProfile(ctx context.Context, t *testing.T, store *Store, id, model, apiKey string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := store.CreateProfile(ctx, coremodel.Profile{ID: id, DisplayName: "test embedding", Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindEmbedding, BaseURL: "https://example.invalid", Model: model, APIKey: apiKey, ContextWindow: 32768, Revision: 1, CreatedAt: now, UpdatedAt: now}, uuid.NewString(), strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
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
		t.Fatal(err)
	}
	instance := uuid.NewString()
	if err = ApplyMigrations(ctx, pool, instance); err != nil {
		pool.Close()
		admin.Close()
		cancel()
		if strings.Contains(err.Error(), `extension "vector" is not available`) {
			t.Skipf("pgvector unavailable: %v", err)
		}
		t.Fatal(err)
	}
	store, err := New(pool, instance, testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	repo, err := NewCoreKnowledgeStore(store, CoreKnowledgeStoreConfig{Content: &pgKnowledgeContent{}, ManagedFiles: pgKnowledgeOpener{}, Search: pgKnowledgeSearch{}})
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE")
		admin.Close()
		cancel()
	}
	return ctx, repo, cleanup
}
