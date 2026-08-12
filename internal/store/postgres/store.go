package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	"github.com/YingSuiAI/dirextalk-agent/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const currentSchemaVersion int64 = migrations.CurrentVersion

type Store struct {
	pool       *pgxpool.Pool
	instanceID uuid.UUID
	// secretKey is injected only by Core composition when encrypted secret
	// operations are enabled. A nil key deliberately fails those operations
	// closed while leaving non-secret stores usable for migration/tests.
	secretKey *secretbox.Keyring
}

// Pool exposes the already configured Agent-owned pool to infrastructure
// components that need to participate in the same PostgreSQL transaction
// boundary (for example the capability operation ledger).  Callers must not
// close the returned pool; Store owns its lifecycle.
func (s *Store) Pool() *pgxpool.Pool {
	if s == nil {
		return nil
	}
	return s.pool
}

func New(pool *pgxpool.Pool, instanceID string, secretKeys ...*secretbox.Keyring) (*Store, error) {
	if pool == nil {
		return nil, errors.New("postgres pool is required")
	}
	if len(secretKeys) > 1 {
		return nil, errors.New("postgres store accepts at most one secret key")
	}
	parsed, err := uuid.Parse(instanceID)
	if err != nil {
		return nil, fmt.Errorf("parse agent instance id: %w", err)
	}
	return &Store{pool: pool, instanceID: parsed, secretKey: firstKey(secretKeys)}, nil
}

func firstKey(keys []*secretbox.Keyring) *secretbox.Keyring {
	if len(keys) == 0 {
		return nil
	}
	return keys[0]
}

func Open(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse postgres configuration: %w", err)
	}
	config.ConnConfig.RuntimeParams["application_name"] = "dirextalk-agent"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return pool, nil
}

func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool, instanceID string) error {
	parsed, err := uuid.Parse(instanceID)
	if err != nil {
		return fmt.Errorf("parse agent instance id: %w", err)
	}
	connection, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer connection.Release()
	if _, err := connection.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(0x4454584147454e54)); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	defer func() {
		_, _ = connection.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", int64(0x4454584147454e54))
	}()

	if _, err := connection.Exec(ctx, `CREATE TABLE IF NOT EXISTS agent_schema_migrations (
		version bigint PRIMARY KEY,
		checksum bytea NOT NULL CHECK (octet_length(checksum)=32),
		applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
	)`); err != nil {
		return fmt.Errorf("ensure migration ledger: %w", err)
	}
	rows, err := connection.Query(ctx, `SELECT version, checksum FROM agent_schema_migrations`)
	if err != nil {
		return fmt.Errorf("read migration ledger: %w", err)
	}
	applied := make(map[int64][]byte)
	for rows.Next() {
		var version int64
		var checksum []byte
		if err := rows.Scan(&version, &checksum); err != nil {
			rows.Close()
			return fmt.Errorf("scan migration version: %w", err)
		}
		applied[version] = checksum
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate migration versions: %w", err)
	}
	applied, err = reconcileLegacyRebasedMigrations(ctx, connection, applied)
	if err != nil {
		return err
	}

	entries := migrations.Entries()
	for _, entry := range entries {
		version, err := migrationVersion(entry)
		if err != nil {
			return err
		}
		script, err := migrations.Files.ReadFile(entry)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry, err)
		}
		checksum := sha256.Sum256(script)
		if recorded, ok := applied[version]; ok {
			if !bytes.Equal(recorded, checksum[:]) {
				return fmt.Errorf("migration %d checksum does not match the applied schema", version)
			}
			continue
		}
		tx, err := connection.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", entry, err)
		}
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", entry, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agent_schema_migrations (version, checksum) VALUES ($1,$2)`, version, checksum[:]); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", entry, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", entry, err)
		}
	}

	result, err := connection.Exec(ctx, `INSERT INTO agent_instance_metadata (agent_instance_id) VALUES ($1) ON CONFLICT (singleton) DO NOTHING`, parsed)
	if err != nil {
		return fmt.Errorf("initialize agent instance metadata: %w", err)
	}
	_ = result
	return verifySchemaOn(ctx, connection, parsed)
}

const (
	legacyGrantSnapshotVersion      = int64(9)
	legacyCentralCompletionVersion  = int64(10)
	currentGrantSnapshotVersion     = int64(13)
	currentCentralCompletionVersion = int64(14)
)

// A pre-Adam build shipped the current migrations 13 and 14 as versions 9 and
// 10. Rebase-safe recovery relocates only that exact pair after checking the
// schema effects. Every other checksum mismatch remains a hard failure.
func reconcileLegacyRebasedMigrations(
	ctx context.Context,
	connection *pgxpool.Conn,
	applied map[int64][]byte,
) (map[int64][]byte, error) {
	ordered := migrations.Ordered()
	if len(ordered) < int(currentCentralCompletionVersion) {
		return nil, errors.New("migration bundle is incomplete")
	}
	grantChecksum := sha256.Sum256(ordered[currentGrantSnapshotVersion-1].Script)
	completionChecksum := sha256.Sum256(ordered[currentCentralCompletionVersion-1].Script)
	grantLegacy := bytes.Equal(applied[legacyGrantSnapshotVersion], grantChecksum[:])
	completionLegacy := bytes.Equal(applied[legacyCentralCompletionVersion], completionChecksum[:])
	if !grantLegacy && !completionLegacy {
		return applied, nil
	}
	if !grantLegacy || !completionLegacy || applied[currentGrantSnapshotVersion] != nil ||
		applied[currentCentralCompletionVersion] != nil || applied[11] != nil || applied[12] != nil {
		return nil, errors.New("legacy rebased migration layout is incomplete")
	}

	tx, err := connection.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin legacy migration reconciliation: %w", err)
	}
	defer tx.Rollback(ctx)
	var maximumOutputNullable string
	if err := tx.QueryRow(ctx, `SELECT is_nullable FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='core_cloud_worker_model_grants'
		AND column_name='model_maximum_output_tokens'`).Scan(&maximumOutputNullable); err != nil {
		return nil, fmt.Errorf("verify legacy grant migration column: %w", err)
	}
	var grantConstraint, completionForeignKey bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM pg_constraint c
		JOIN pg_class t ON t.oid=c.conrelid
		JOIN pg_namespace n ON n.oid=t.relnamespace
		WHERE n.nspname=current_schema() AND t.relname='core_cloud_worker_model_grants'
		AND c.conname='core_cloud_worker_model_grants_model_maximum_output_tokens_check'
		AND c.contype='c' AND c.convalidated
	)`).Scan(&grantConstraint); err != nil {
		return nil, fmt.Errorf("verify legacy grant migration constraint: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM pg_constraint c
		JOIN pg_class t ON t.oid=c.conrelid
		JOIN pg_namespace n ON n.oid=t.relnamespace
		WHERE n.nspname=current_schema() AND t.relname='core_cloud_worker_completion_outbox'
		AND c.conname='core_cloud_worker_completion_outbox_result_message_id_fkey'
	)`).Scan(&completionForeignKey); err != nil {
		return nil, fmt.Errorf("verify legacy completion migration constraint: %w", err)
	}
	if maximumOutputNullable != "NO" || !grantConstraint || completionForeignKey {
		return nil, errors.New("legacy rebased migration schema evidence is invalid")
	}
	tag, err := tx.Exec(ctx, `UPDATE agent_schema_migrations SET version=CASE version
		WHEN $1 THEN $2 WHEN $3 THEN $4 ELSE version END
		WHERE (version=$1 AND checksum=$5) OR (version=$3 AND checksum=$6)`,
		legacyGrantSnapshotVersion, currentGrantSnapshotVersion,
		legacyCentralCompletionVersion, currentCentralCompletionVersion,
		grantChecksum[:], completionChecksum[:])
	if err != nil {
		return nil, fmt.Errorf("relocate legacy rebased migrations: %w", err)
	}
	if tag.RowsAffected() != 2 {
		return nil, errors.New("legacy rebased migration ledger changed concurrently")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit legacy migration reconciliation: %w", err)
	}
	next := make(map[int64][]byte, len(applied))
	for version, checksum := range applied {
		switch version {
		case legacyGrantSnapshotVersion:
			next[currentGrantSnapshotVersion] = checksum
		case legacyCentralCompletionVersion:
			next[currentCentralCompletionVersion] = checksum
		default:
			next[version] = checksum
		}
	}
	return next, nil
}

func VerifySchema(ctx context.Context, pool *pgxpool.Pool, instanceID string) error {
	parsed, err := uuid.Parse(instanceID)
	if err != nil {
		return fmt.Errorf("parse agent instance id: %w", err)
	}
	connection, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire schema verification connection: %w", err)
	}
	defer connection.Release()
	return verifySchemaOn(ctx, connection, parsed)
}

type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func verifySchemaOn(ctx context.Context, query rowQuerier, expected uuid.UUID) error {
	var version int64
	if err := query.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM agent_schema_migrations`).Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version != currentSchemaVersion {
		return fmt.Errorf("schema version %d does not match required version %d", version, currentSchemaVersion)
	}
	var actual uuid.UUID
	if err := query.QueryRow(ctx, `SELECT agent_instance_id FROM agent_instance_metadata WHERE singleton=true`).Scan(&actual); err != nil {
		return fmt.Errorf("read agent instance metadata: %w", err)
	}
	if actual != expected {
		return fmt.Errorf("database belongs to agent instance %s, not %s", actual, expected)
	}
	return nil
}

func migrationVersion(name string) (int64, error) {
	base := name
	if index := strings.IndexByte(base, '_'); index >= 0 {
		base = base[:index]
	}
	version, err := strconv.ParseInt(base, 10, 64)
	if err != nil || version < 1 {
		return 0, fmt.Errorf("invalid migration filename %q", name)
	}
	return version, nil
}
