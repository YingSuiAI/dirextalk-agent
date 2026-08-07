package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	PostgresLedgerTable = "core_cloud_worker_aws_ledger"
	maxLedgerJSONBytes  = 256 * 1024
)

// PostgresLedgerSchemaRequirement is documentation/input for the owning Adam
// migration. The ledger never executes DDL at runtime.
const PostgresLedgerSchemaRequirement = `CREATE TABLE core_cloud_worker_aws_ledger (
    identity_key text PRIMARY KEY,
    owner_id text NOT NULL,
    account_id char(12) NOT NULL,
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    region text NOT NULL,
    execution_id uuid NOT NULL,
    task_id uuid NOT NULL,
    task_attempt bigint NOT NULL CHECK (task_attempt > 0),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    provider_id text NOT NULL,
    launch_identity char(64) NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    plan_digest char(64) NOT NULL,
    infrastructure_digest char(64) NOT NULL,
    intent_digest char(64) NOT NULL,
    state text NOT NULL,
    destroy_deadline timestamptz NOT NULL,
    cleanup_requested_at timestamptz NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    record_json jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (account_id, account_generation, owner_id, execution_id)
);
CREATE INDEX core_cloud_worker_aws_ledger_reap_idx
    ON core_cloud_worker_aws_ledger (destroy_deadline, identity_key)
    WHERE state <> 'verified_destroyed';`

var (
	insertLedgerSQL = `INSERT INTO core_cloud_worker_aws_ledger
        (identity_key, owner_id, account_id, account_generation, region, execution_id,
         task_id, task_attempt, lease_epoch, provider_id, launch_identity, generation,
         plan_digest, infrastructure_digest, intent_digest, state, destroy_deadline,
         cleanup_requested_at, revision, record_json, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20::jsonb,$21,$22)
        ON CONFLICT (identity_key) DO NOTHING`
	getLedgerSQL = `SELECT record_json FROM core_cloud_worker_aws_ledger
        WHERE identity_key=$1 AND owner_id=$2 AND account_id=$3 AND account_generation=$4
          AND region=$5 AND execution_id=$6 AND task_id=$7 AND task_attempt=$8
		  AND lease_epoch=$9 AND provider_id=$10 AND launch_identity=$11 AND generation=$12`
	getLedgerByExecutionSQL = `SELECT record_json FROM core_cloud_worker_aws_ledger
        WHERE account_id=$1 AND account_generation=$2 AND owner_id=$3 AND execution_id=$4`
	casLedgerSQL = `UPDATE core_cloud_worker_aws_ledger
        SET state=$16, cleanup_requested_at=$17, revision=$18, record_json=$19::jsonb, updated_at=$20
        WHERE identity_key=$1 AND owner_id=$2 AND account_id=$3 AND account_generation=$4
          AND region=$5 AND execution_id=$6 AND task_id=$7 AND task_attempt=$8
          AND lease_epoch=$9 AND provider_id=$10 AND launch_identity=$11 AND generation=$12
          AND plan_digest=$13 AND infrastructure_digest=$14 AND intent_digest=$15
	          AND revision=$21 AND (state <> 'verified_destroyed' OR $16 IN ('verified_destroyed','destroying'))`
	listReapableLedgerSQL = `SELECT record_json FROM core_cloud_worker_aws_ledger
	        WHERE (state <> 'verified_destroyed'
	          AND (cleanup_requested_at IS NOT NULL OR destroy_deadline <= $1))
	           OR state = 'verified_destroyed'
	        ORDER BY destroy_deadline, identity_key`
	ledgerReadySQL = `SELECT COALESCE(to_regclass('core_cloud_worker_aws_ledger')::text, '')`
)

type postgresLedgerDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

type PostgresLedger struct{ db postgresLedgerDB }

func NewPostgresLedger(pool *pgxpool.Pool) (*PostgresLedger, error) {
	if pool == nil {
		return nil, ErrInvalid
	}
	return &PostgresLedger{db: pool}, nil
}

func newPostgresLedger(db postgresLedgerDB) (*PostgresLedger, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &PostgresLedger{db: db}, nil
}

// Ready is fail-closed and read-only. Runtime composition must not publish an
// AWS route unless this check and the SDK client's readiness both pass.
func (ledger *PostgresLedger) Ready(ctx context.Context) error {
	if ledger == nil || ledger.db == nil || ctx == nil {
		return ErrInvalid
	}
	var table string
	if err := ledger.db.QueryRow(ctx, ledgerReadySQL).Scan(&table); err != nil || table != PostgresLedgerTable {
		return errors.Join(ErrNotFound, err)
	}
	return nil
}

func (ledger *PostgresLedger) CreateIntent(ctx context.Context, proposed LedgerRecord) (LedgerRecord, error) {
	if ledger == nil || ledger.db == nil || ctx == nil || proposed.Validate() != nil {
		return LedgerRecord{}, ErrInvalid
	}
	encoded, err := encodeLedgerRecord(proposed)
	if err != nil {
		return LedgerRecord{}, err
	}
	args := ledgerIdentityArgs(proposed.Identity)
	args = append(args, proposed.Plan.Digest, proposed.Plan.InfrastructureDigest, proposed.Intent.IntentDigest,
		string(proposed.State), proposed.Plan.DestroyDeadline, nullableTime(proposed.CleanupRequestedAt), proposed.Revision,
		encoded, proposed.CreatedAt, proposed.UpdatedAt)
	tag, err := ledger.db.Exec(ctx, insertLedgerSQL, args...)
	if err != nil {
		return LedgerRecord{}, errors.Join(ErrConflict, err)
	}
	if tag.RowsAffected() == 1 {
		return proposed.clone(), nil
	}
	stored, err := ledger.GetByExecution(ctx, LookupFor(proposed.Identity))
	if err != nil {
		return LedgerRecord{}, err
	}
	if !stored.Identity.Equal(proposed.Identity) || stored.Plan.Digest != proposed.Plan.Digest || stored.Plan.InfrastructureDigest != proposed.Plan.InfrastructureDigest ||
		stored.Intent.IntentDigest != proposed.Intent.IntentDigest {
		return LedgerRecord{}, ErrConflict
	}
	return stored, nil
}

func (ledger *PostgresLedger) GetByExecution(ctx context.Context, lookup ExecutionLookup) (LedgerRecord, error) {
	if ledger == nil || ledger.db == nil || ctx == nil || lookup.Validate() != nil {
		return LedgerRecord{}, ErrInvalid
	}
	var encoded []byte
	if err := ledger.db.QueryRow(ctx, getLedgerByExecutionSQL, lookup.AccountID, lookup.AccountGeneration, lookup.OwnerID, lookup.ExecutionID).Scan(&encoded); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return LedgerRecord{}, ErrNotFound
		}
		return LedgerRecord{}, errors.Join(ErrNotFound, err)
	}
	record, err := decodeLedgerRecord(encoded)
	if err != nil {
		return LedgerRecord{}, err
	}
	if executionLedgerKey(LookupFor(record.Identity)) != executionLedgerKey(lookup) {
		return LedgerRecord{}, ErrIdentityMismatch
	}
	return record, nil
}

func (ledger *PostgresLedger) Get(ctx context.Context, identity ExecutionIdentity) (LedgerRecord, error) {
	if ledger == nil || ledger.db == nil || ctx == nil || identity.Validate() != nil {
		return LedgerRecord{}, ErrInvalid
	}
	var encoded []byte
	if err := ledger.db.QueryRow(ctx, getLedgerSQL, ledgerIdentityArgs(identity)...).Scan(&encoded); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return LedgerRecord{}, ErrNotFound
		}
		return LedgerRecord{}, errors.Join(ErrNotFound, err)
	}
	record, err := decodeLedgerRecord(encoded)
	if err != nil {
		return LedgerRecord{}, err
	}
	if !record.Identity.Equal(identity) {
		return LedgerRecord{}, ErrIdentityMismatch
	}
	return record, nil
}

func (ledger *PostgresLedger) CompareAndSwap(ctx context.Context, next LedgerRecord, expectedRevision uint64) (LedgerRecord, error) {
	if ledger == nil || ledger.db == nil || ctx == nil || next.Validate() != nil || expectedRevision == 0 || next.Revision != expectedRevision+1 {
		return LedgerRecord{}, ErrInvalid
	}
	encoded, err := encodeLedgerRecord(next)
	if err != nil {
		return LedgerRecord{}, err
	}
	args := ledgerIdentityArgs(next.Identity)
	args = append(args, next.Plan.Digest, next.Plan.InfrastructureDigest, next.Intent.IntentDigest,
		string(next.State), nullableTime(next.CleanupRequestedAt), next.Revision, encoded, next.UpdatedAt, expectedRevision)
	tag, err := ledger.db.Exec(ctx, casLedgerSQL, args...)
	if err != nil {
		return LedgerRecord{}, errors.Join(ErrConflict, err)
	}
	if tag.RowsAffected() != 1 {
		return LedgerRecord{}, ErrConflict
	}
	return next.clone(), nil
}

func (ledger *PostgresLedger) ListReapable(ctx context.Context, before time.Time) ([]LedgerRecord, error) {
	if ledger == nil || ledger.db == nil || ctx == nil || before.IsZero() {
		return nil, ErrInvalid
	}
	rows, err := ledger.db.Query(ctx, listReapableLedgerSQL, before.UTC())
	if err != nil {
		return nil, errors.Join(ErrCloudReadback, err)
	}
	defer rows.Close()
	result := make([]LedgerRecord, 0)
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return nil, errors.Join(ErrCloudReadback, err)
		}
		record, err := decodeLedgerRecord(encoded)
		if err != nil {
			return nil, err
		}
		if record.State == LifecycleVerifiedDestroyed {
			if record.tombstoneAuditDue(before.UTC()) {
				result = append(result, record)
			}
			continue
		}
		if record.CleanupRequestedAt.IsZero() && record.Plan.DestroyDeadline.After(before.UTC()) {
			return nil, ErrIdentityMismatch
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrCloudReadback, err)
	}
	return result, nil
}

func ledgerIdentityArgs(identity ExecutionIdentity) []any {
	return []any{ledgerKey(identity), identity.OwnerID, identity.AccountID, identity.AccountGeneration, identity.Region,
		identity.ExecutionID, identity.TaskID, identity.TaskAttempt, identity.LeaseEpoch, identity.ProviderID,
		identity.LaunchIdentity, identity.Generation}
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func encodeLedgerRecord(record LedgerRecord) ([]byte, error) {
	if record.Validate() != nil {
		return nil, ErrInvalid
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) == 0 || len(encoded) > maxLedgerJSONBytes {
		return nil, fmt.Errorf("%w: ledger JSON is invalid", ErrInvalid)
	}
	return encoded, nil
}

func decodeLedgerRecord(encoded []byte) (LedgerRecord, error) {
	if len(encoded) == 0 || len(encoded) > maxLedgerJSONBytes {
		return LedgerRecord{}, ErrIdentityMismatch
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record LedgerRecord
	if err := decoder.Decode(&record); err != nil || record.Validate() != nil {
		return LedgerRecord{}, ErrIdentityMismatch
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return LedgerRecord{}, ErrIdentityMismatch
	}
	return record, nil
}

var _ ResourceLedger = (*PostgresLedger)(nil)
