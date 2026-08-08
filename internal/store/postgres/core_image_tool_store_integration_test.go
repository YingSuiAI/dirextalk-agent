package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreimagetool"
	"github.com/YingSuiAI/dirextalk-agent/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCoreImageToolPostgresIdempotencyBindingConsumeAndByteClear(t *testing.T) {
	ctx, store, cleanup := imageToolPGFixture(t)
	defer cleanup()
	repo := NewCoreImageToolStore(store)
	payload := []byte("image-bytes")
	digestBytes := sha256.Sum256(payload)
	digest := hex.EncodeToString(digestBytes[:])
	requestID, beginKey := uuid.NewString(), uuid.NewString()
	begin := coreimagetool.BeginCommand{OwnerID: "owner", AccountGeneration: 7, IdempotencyKey: beginKey, ImageRequestID: requestID, Name: "a.png", MIMEType: "image/png", DeclaredSize: uint64(len(payload)), ContentSHA256: digest}
	upload, err := repo.Begin(ctx, begin)
	if err != nil || upload.ImageRequestID != requestID || upload.Revision != 1 {
		t.Fatalf("begin=%+v err=%v", upload, err)
	}
	replay, err := repo.Begin(ctx, begin)
	if err != nil || replay != upload {
		t.Fatalf("begin replay=%+v err=%v", replay, err)
	}
	changed := begin
	changed.Name = "other.png"
	if _, err = repo.Begin(ctx, changed); !errors.Is(err, coreimagetool.ErrConflict) {
		t.Fatalf("changed begin error=%v", err)
	}
	appendKey := uuid.NewString()
	appendCommand := coreimagetool.AppendCommand{OwnerID: "owner", AccountGeneration: 7, IdempotencyKey: appendKey, UploadID: upload.UploadID, ExpectedRevision: 1, Ordinal: 0, OffsetBytes: 0, Data: append([]byte(nil), payload...), ChunkSHA256: digest}
	appended, err := repo.Append(ctx, appendCommand)
	if err != nil || appended.ReceivedSize != uint64(len(payload)) || appended.Revision != 2 {
		t.Fatalf("append=%+v err=%v", appended, err)
	}
	appendCommand.Data = append([]byte(nil), payload...)
	if replay, err = repo.Append(ctx, appendCommand); err != nil || replay != appended {
		t.Fatalf("append replay=%+v err=%v", replay, err)
	}
	commitKey := uuid.NewString()
	commit := coreimagetool.CommitCommand{OwnerID: "owner", AccountGeneration: 7, IdempotencyKey: commitKey, UploadID: upload.UploadID, ExpectedRevision: 2, ContentSHA256: digest}
	source, err := repo.Commit(ctx, commit)
	if err != nil || source.Revision != 1 || source.ImageRequestID != requestID {
		t.Fatalf("commit=%+v err=%v", source, err)
	}
	if _, err = repo.Consume(ctx, coreimagetool.ConsumeCommand{OwnerID: "other", AccountGeneration: 7, ImageRequestID: requestID, SourceID: source.SourceID, SourceRevision: 1}); !errors.Is(err, coreimagetool.ErrConflict) {
		t.Fatalf("foreign consume error=%v", err)
	}
	consumed, err := repo.Consume(ctx, coreimagetool.ConsumeCommand{OwnerID: "owner", AccountGeneration: 7, ImageRequestID: requestID, SourceID: source.SourceID, SourceRevision: 1})
	if err != nil || string(consumed.Content) != string(payload) {
		t.Fatalf("consume=%+v err=%v", consumed.Source, err)
	}
	consumed.Destroy()
	var status string
	var stored []byte
	var received uint64
	if err = store.pool.QueryRow(context.Background(), `SELECT status,content_bytes,received_size FROM core_image_tool_uploads WHERE source_id=$1`, source.SourceID).Scan(&status, &stored, &received); err != nil || status != "consumed" || len(stored) != 0 || received != 0 {
		t.Fatalf("stored status=%s bytes=%d received=%d err=%v", status, len(stored), received, err)
	}
	if _, err = repo.Consume(ctx, coreimagetool.ConsumeCommand{OwnerID: "owner", AccountGeneration: 7, ImageRequestID: requestID, SourceID: source.SourceID, SourceRevision: 1}); !errors.Is(err, coreimagetool.ErrConsumed) {
		t.Fatalf("second consume error=%v", err)
	}
	if replay, err = repo.Begin(ctx, begin); err != nil || replay != upload {
		t.Fatalf("late begin replay=%+v err=%v", replay, err)
	}
	expired := begin
	expired.IdempotencyKey, expired.ImageRequestID = uuid.NewString(), uuid.NewString()
	expiredUpload, err := repo.Begin(ctx, expired)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.pool.Exec(ctx, `UPDATE core_image_tool_uploads SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 second' WHERE upload_id=$1`, expiredUpload.UploadID); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.Consume(ctx, coreimagetool.ConsumeCommand{OwnerID: "owner", AccountGeneration: 7, ImageRequestID: expired.ImageRequestID, SourceID: expiredUpload.SourceID, SourceRevision: 1}); !errors.Is(err, coreimagetool.ErrExpired) {
		t.Fatalf("expired consume error=%v", err)
	}
	fresh := begin
	fresh.IdempotencyKey, fresh.ImageRequestID = uuid.NewString(), uuid.NewString()
	if _, err = repo.Begin(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	var remains bool
	if err = store.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM core_image_tool_uploads WHERE upload_id=$1)`, expiredUpload.UploadID).Scan(&remains); err != nil || remains {
		t.Fatalf("expired cleanup remains=%v err=%v", remains, err)
	}
}

func imageToolPGFixture(t *testing.T) (context.Context, *Store, func()) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("DIREXTALK_TEST_DATABASE_URL"))
	if dsn == "" {
		dsn = strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	}
	if dsn == "" {
		t.Skip("DIREXTALK_TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		cancel()
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
	schema := "dtx_image_tool_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	if _, err = pool.Exec(ctx, `CREATE TABLE agent_account_deprovisions(owner_id text NOT NULL,account_generation bigint NOT NULL CHECK(account_generation>0),state text NOT NULL,updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(owner_id,account_generation))`); err != nil {
		t.Fatal(err)
	}
	script, err := migrations.Files.ReadFile("000006_image_tools_v1.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(script)); err != nil {
		t.Fatal(err)
	}
	store, err := New(pool, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		pool.Close()
		dropCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_, _ = admin.Exec(dropCtx, "DROP SCHEMA "+quoted+" CASCADE")
		admin.Close()
		cancel()
	}
	return ctx, store, cleanup
}
