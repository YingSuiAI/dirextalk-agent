package knowledge_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/knowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestKnowledgePostgresOwnerIdempotencyDigestReplayAndMetadataOnlyPersistence(t *testing.T) {
	pool, instanceID := newKnowledgeTestPool(t)
	repository, err := knowledge.NewPostgresRepository(pool, instanceID, knowledge.DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scope := knowledge.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()}
	bindingID := uuid.NewString()
	put := knowledge.PutConfigCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: "owner-knowledge-a", BindingID: bindingID,
		Spec: knowledge.ConfigSpec{
			DeploymentID: uuid.NewString(), ManagedServiceID: uuid.NewString(), RecipeDigest: knowledge.SHA256([]byte("recipe")),
			EmbeddingProfileID: knowledge.LocalMultilingualE5SmallProfileID, Enabled: true,
		},
	}
	created, err := repository.PutConfig(ctx, scope, put)
	if err != nil || created.Revision != 1 {
		t.Fatalf("create config = %+v, err = %v", created, err)
	}
	replayed, err := repository.PutConfig(ctx, scope, put)
	if err != nil || replayed != created {
		t.Fatalf("replay config = %+v, err = %v", replayed, err)
	}
	conflict := put
	conflict.Spec.Enabled = false
	if _, err := repository.PutConfig(ctx, scope, conflict); !errors.Is(err, knowledge.ErrConflict) {
		t.Fatalf("changed replay error = %v", err)
	}
	if _, err := repository.GetConfig(ctx, "owner-knowledge-b", bindingID); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatalf("cross-owner read error = %v", err)
	}
	resolved, err := repository.GetConfig(ctx, put.OwnerID, "")
	if err != nil || resolved.BindingID != bindingID {
		t.Fatalf("owner default config = %+v, err = %v", resolved, err)
	}

	canary := []byte("private-document-canary-sk-0123456789abcdefghijklmnopqrstuvwxyz")
	sourceID, uploadID := uuid.NewString(), uuid.NewString()
	upload, err := repository.StartAttachmentUpload(ctx, scope, knowledge.StartAttachmentUploadCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: put.OwnerID, BindingID: bindingID, SourceID: sourceID, UploadID: uploadID,
		MediaType: "text/plain", DeclaredSizeBytes: int64(len(canary)), ExpectedBindingRevision: created.Revision,
		Title: "integration fixture",
	})
	if err != nil || upload.Revision != 1 {
		t.Fatalf("start upload = %+v, err = %v", upload, err)
	}
	appendCommand := knowledge.AppendAttachmentChunkCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: put.OwnerID, BindingID: bindingID, UploadID: uploadID,
		ExpectedUploadRevision: upload.Revision, OffsetBytes: 0, ChunkOrdinal: 0, Chunk: canary, ChunkSHA256: knowledge.SHA256(canary),
	}
	stageCalls := 0
	staged := []byte(nil)
	stage := func(_ context.Context, chunk knowledge.AttachmentChunk) error {
		stageCalls++
		if chunk.Binding != put.Spec || chunk.Title != "integration fixture" {
			t.Fatal("stager did not receive immutable binding/title")
		}
		staged = append([]byte(nil), chunk.Chunk...)
		return nil
	}
	upload, err = repository.AppendAttachmentChunk(ctx, scope, appendCommand, stage)
	if err != nil || upload.ReceivedSizeBytes != int64(len(canary)) || stageCalls != 1 {
		t.Fatalf("append upload = %+v, calls = %d, err = %v", upload, stageCalls, err)
	}
	replayedUpload, err := repository.AppendAttachmentChunk(ctx, scope, appendCommand, stage)
	if err != nil || replayedUpload != upload || stageCalls != 1 {
		t.Fatalf("replay upload = %+v, calls = %d, err = %v", replayedUpload, stageCalls, err)
	}
	different := appendCommand
	different.Chunk = bytes.Repeat([]byte{'x'}, len(canary))
	different.ChunkSHA256 = knowledge.SHA256(different.Chunk)
	if _, err := repository.AppendAttachmentChunk(ctx, scope, different, stage); !errors.Is(err, knowledge.ErrConflict) || stageCalls != 1 {
		t.Fatalf("changed chunk replay error = %v, calls = %d", err, stageCalls)
	}

	upload, source, err := repository.CommitAttachmentUpload(ctx, scope, knowledge.CommitAttachmentUploadCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: put.OwnerID, BindingID: bindingID, UploadID: uploadID,
		ExpectedUploadRevision: upload.Revision, ContentSHA256: knowledge.SHA256(canary),
	}, func(_ context.Context, commit knowledge.AttachmentCommit) (knowledge.ContentReceipt, error) {
		if !bytes.Equal(staged, canary) || commit.ContentSHA256 != knowledge.SHA256(staged) || commit.Binding != put.Spec {
			t.Fatal("commit did not bind staged content")
		}
		return knowledge.ContentReceipt{SizeBytes: int64(len(staged)), ContentSHA256: knowledge.SHA256(staged), PointID: uuid.NewString(), IndexedSegmentCount: 1}, nil
	})
	if err != nil || upload.Status != knowledge.UploadCommitted || source.Status != knowledge.SourceReady {
		t.Fatalf("commit upload = %+v source = %+v err = %v", upload, source, err)
	}
	memoryCanary := []byte("private-memory-canary-sk-abcdefghijklmnopqrstuvwxyz012345")
	memorySourceID := uuid.NewString()
	memory, err := repository.CreateMemory(ctx, scope, knowledge.CreateMemoryCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: put.OwnerID, BindingID: bindingID, SourceID: memorySourceID,
		ExpectedBindingRevision: created.Revision, Content: memoryCanary, ContentSHA256: knowledge.SHA256(memoryCanary), Title: "durable memory fixture",
	}, func(_ context.Context, value knowledge.MemoryContent) (knowledge.ContentReceipt, error) {
		if value.Binding != put.Spec {
			t.Fatal("memory stager did not receive immutable binding")
		}
		return knowledge.ContentReceipt{SizeBytes: int64(len(value.Content)), ContentSHA256: knowledge.SHA256(value.Content), PointID: uuid.NewString(), IndexedSegmentCount: 1}, nil
	})
	if err != nil || memory.Status != knowledge.SourceReady || memory.Title != "durable memory fixture" {
		t.Fatalf("create memory = %+v, err = %v", memory, err)
	}
	deleteCommand := knowledge.DeleteSourceCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: put.OwnerID, BindingID: bindingID, SourceID: memorySourceID,
		ExpectedBindingRevision: created.Revision, ExpectedSourceRevision: memory.Revision,
	}
	deleteCalls := 0
	deleted, err := repository.DeleteSource(ctx, scope, deleteCommand, func(_ context.Context, target knowledge.SourceTarget) error {
		deleteCalls++
		if target.SourceID != memorySourceID || target.OwnerID != put.OwnerID {
			t.Fatal("delete target lost owner/source binding")
		}
		if target.Binding != put.Spec {
			t.Fatal("delete target lost immutable binding")
		}
		return nil
	})
	if err != nil || deleted.Status != knowledge.SourceDeleted || deleteCalls != 1 {
		t.Fatalf("delete memory = %+v calls=%d err=%v", deleted, deleteCalls, err)
	}
	replayedDelete, err := repository.DeleteSource(ctx, scope, deleteCommand, func(context.Context, knowledge.SourceTarget) error {
		deleteCalls++
		return nil
	})
	if err != nil || replayedDelete != deleted || deleteCalls != 1 {
		t.Fatalf("replay delete = %+v calls=%d err=%v", replayedDelete, deleteCalls, err)
	}

	for _, secretBytes := range [][]byte{canary, memoryCanary} {
		for _, table := range []string{"knowledge_configs", "knowledge_sources", "knowledge_uploads", "knowledge_upload_chunks"} {
			var leaked bool
			query := "SELECT EXISTS (SELECT 1 FROM " + pgx.Identifier{table}.Sanitize() + " AS value WHERE to_jsonb(value)::text LIKE $1)"
			if err := pool.QueryRow(ctx, query, "%"+string(secretBytes)+"%").Scan(&leaked); err != nil {
				t.Fatal(err)
			}
			if leaked {
				t.Fatalf("knowledge bytes leaked into %s", table)
			}
		}
		var leaked bool
		if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1 FROM idempotency_records
		    WHERE operation LIKE 'knowledge.%' AND to_jsonb(idempotency_records)::text LIKE $1
		)`, "%"+string(secretBytes)+"%").Scan(&leaked); err != nil {
			t.Fatal(err)
		}
		if leaked {
			t.Fatal("knowledge bytes leaked into idempotency metadata")
		}
	}
	var payloadColumns int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name LIKE 'knowledge_%'
		  AND (data_type IN ('bytea','json','jsonb','ARRAY') OR udt_name='vector')`).Scan(&payloadColumns); err != nil {
		t.Fatal(err)
	}
	if payloadColumns != 0 {
		t.Fatalf("knowledge PostgreSQL schema contains %d blob/vector-capable columns", payloadColumns)
	}

	restarted, err := knowledge.NewPostgresRepository(pool, instanceID, knowledge.DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	page, err := restarted.ListSources(ctx, knowledge.ListSourcesQuery{OwnerID: put.OwnerID, BindingID: bindingID, PageSize: 10})
	if err != nil || len(page.Sources) != 1 || page.Sources[0].ContentSHA256 != knowledge.SHA256(canary) {
		t.Fatalf("restart sources = %+v, err = %v", page, err)
	}
	if err := restarted.ValidateSearchSources(ctx, put.OwnerID, bindingID, []string{sourceID}); err != nil {
		t.Fatalf("validate owned search source: %v", err)
	}
	if err := restarted.ValidateSearchSources(ctx, "owner-knowledge-b", bindingID, []string{sourceID}); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatalf("cross-owner search source error = %v", err)
	}
	second := put
	second.IdempotencyKey = uuid.NewString()
	second.BindingID = uuid.NewString()
	second.Spec.DeploymentID = uuid.NewString()
	second.Spec.ManagedServiceID = uuid.NewString()
	if _, err := restarted.PutConfig(ctx, scope, second); err != nil {
		t.Fatalf("create second owner config: %v", err)
	}
	if _, err := restarted.GetConfig(ctx, put.OwnerID, ""); !errors.Is(err, knowledge.ErrAmbiguousConfig) {
		t.Fatalf("ambiguous owner config error = %v", err)
	}
}

func newKnowledgeTestPool(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set AGENT_TEST_POSTGRES_DSN to run PostgreSQL integration tests")
	}
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("AGENT_TEST_POSTGRES_DSN is invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	adminPool, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal("open PostgreSQL administration pool")
	}
	schema := "dtx_agent_knowledge_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		adminPool.Close()
		t.Fatal("create isolated PostgreSQL schema")
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		adminPool.Close()
		t.Fatal("AGENT_TEST_POSTGRES_DSN is invalid")
	}
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.ConnConfig.RuntimeParams["application_name"] = "dirextalk-agent-knowledge-test"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		adminPool.Close()
		t.Fatal("open isolated PostgreSQL pool")
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, err := adminPool.Exec(cleanupContext, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("drop isolated PostgreSQL schema failed: %v", err)
		}
		adminPool.Close()
	})
	instanceID := uuid.NewString()
	if err := postgres.ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatalf("apply Agent migrations: %v", err)
	}
	return pool, instanceID
}
