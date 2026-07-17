package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const currentSchemaVersion int64 = 38

type Store struct {
	pool       *pgxpool.Pool
	instanceID uuid.UUID
}

func New(pool *pgxpool.Pool, instanceID string) (*Store, error) {
	if pool == nil {
		return nil, errors.New("postgres pool is required")
	}
	parsed, err := uuid.Parse(instanceID)
	if err != nil {
		return nil, fmt.Errorf("parse agent instance id: %w", err)
	}
	return &Store{pool: pool, instanceID: parsed}, nil
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

	entries, err := fs.Glob(migrations.Files, "*.up.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	sort.Strings(entries)
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
