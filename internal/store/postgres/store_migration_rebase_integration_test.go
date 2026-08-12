package postgres

import (
	"context"
	"crypto/sha256"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestApplyMigrationsReconcilesLegacyRebasedCloudWorkerPair(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("AGENT_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "dtx_migration_rebase_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	if _, err := pool.Exec(ctx, `CREATE TABLE agent_schema_migrations (
		version bigint PRIMARY KEY,
		checksum bytea NOT NULL CHECK (octet_length(checksum)=32),
		applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
	)`); err != nil {
		t.Fatal(err)
	}
	ordered := migrations.Ordered()
	for index := 0; index < 8; index++ {
		applyMigrationForTest(t, ctx, pool, int64(index+1), ordered[index].Script)
	}
	applyMigrationForTest(t, ctx, pool, legacyGrantSnapshotVersion, ordered[currentGrantSnapshotVersion-1].Script)
	applyMigrationForTest(t, ctx, pool, legacyCentralCompletionVersion, ordered[currentCentralCompletionVersion-1].Script)

	instanceID := uuid.NewString()
	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatal(err)
	}
	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatalf("reapply reconciled migrations: %v", err)
	}
	rows, err := pool.Query(ctx, `SELECT version,checksum FROM agent_schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var count int
	for rows.Next() {
		var version int64
		var checksum []byte
		if err := rows.Scan(&version, &checksum); err != nil {
			t.Fatal(err)
		}
		count++
		if version != int64(count) {
			t.Fatalf("migration version=%d at row=%d", version, count)
		}
		want := sha256.Sum256(ordered[count-1].Script)
		if string(checksum) != string(want[:]) {
			t.Fatalf("migration %d checksum did not reconcile", version)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != int(migrations.CurrentVersion) {
		t.Fatalf("migration count=%d want=%d", count, migrations.CurrentVersion)
	}
}

func TestReconcileLegacyRebasedMigrationsRejectsPartialPair(t *testing.T) {
	ordered := migrations.Ordered()
	grantChecksum := sha256.Sum256(ordered[currentGrantSnapshotVersion-1].Script)
	applied := map[int64][]byte{
		legacyGrantSnapshotVersion: grantChecksum[:],
	}

	_, err := reconcileLegacyRebasedMigrations(context.Background(), nil, applied)
	if err == nil || !strings.Contains(err.Error(), "layout is incomplete") {
		t.Fatalf("partial legacy pair error=%v", err)
	}
}

func applyMigrationForTest(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	version int64,
	script []byte,
) {
	t.Helper()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, string(script)); err != nil {
		t.Fatalf("apply fixture migration %d: %v", version, err)
	}
	checksum := sha256.Sum256(script)
	if _, err := tx.Exec(ctx, `INSERT INTO agent_schema_migrations(version,checksum) VALUES($1,$2)`, version, checksum[:]); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
