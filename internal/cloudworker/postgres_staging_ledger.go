package cloudworker

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
	PostgresStagingLedgerTable = "core_cloud_worker_input_staging"
	maxStagingRecordJSONBytes  = 128 * 1024
)

// PostgresStagingLedgerSchemaRequirement is consumed by the single owning
// Adam migration. Runtime code never creates or alters schema.
const PostgresStagingLedgerSchemaRequirement = `CREATE TABLE core_cloud_worker_input_staging (
    identity_key text PRIMARY KEY,
    identity_digest char(64) NOT NULL CHECK (identity_digest ~ '^[a-f0-9]{64}$'),
    owner_id text NOT NULL,
    account_id char(12) NOT NULL,
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    region text NOT NULL,
    provider_id text NOT NULL,
    execution_id uuid NOT NULL,
    plan_digest char(64) NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
    input_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('intent_recorded','put_started','put_uncertain','version_bound','delete_started','delete_uncertain','verified_destroyed')),
    version_id text NOT NULL DEFAULT '',
    mutation_lease_until timestamptz,
    mutation_attempts integer NOT NULL DEFAULT 0 CHECK (mutation_attempts BETWEEN 0 AND 1),
    delete_attempts integer NOT NULL DEFAULT 0 CHECK (delete_attempts >= 0),
    revision bigint NOT NULL CHECK (revision > 0),
    record_json jsonb NOT NULL CHECK (jsonb_typeof(record_json) = 'object' AND pg_column_size(record_json) <= 131072),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (account_id, account_generation, owner_id, execution_id, input_id)
);
CREATE INDEX core_cloud_worker_input_staging_cleanup_idx
    ON core_cloud_worker_input_staging (owner_id, account_generation, execution_id, input_id)
    WHERE state <> 'verified_destroyed';`

var (
	insertStagingRecordSQL = `INSERT INTO core_cloud_worker_input_staging
        (identity_key,identity_digest,owner_id,account_id,account_generation,region,provider_id,
         execution_id,plan_digest,input_id,state,version_id,mutation_lease_until,mutation_attempts,
         delete_attempts,revision,record_json,created_at,updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::jsonb,$18,$19)
        ON CONFLICT (identity_key) DO NOTHING`
	getStagingRecordSQL = `SELECT record_json FROM core_cloud_worker_input_staging
        WHERE identity_key=$1 AND identity_digest=$2`
	casStagingRecordSQL = `UPDATE core_cloud_worker_input_staging
        SET state=$3,version_id=$4,mutation_lease_until=$5,mutation_attempts=$6,
            delete_attempts=$7,revision=$8,record_json=$9::jsonb,updated_at=$10
        WHERE identity_key=$1 AND identity_digest=$2 AND revision=$11
          AND (state, $3) IN (
            ('intent_recorded','put_started'),('intent_recorded','verified_destroyed'),
            ('put_started','put_uncertain'),('put_started','version_bound'),('put_started','verified_destroyed'),
            ('put_uncertain','version_bound'),('put_uncertain','verified_destroyed'),
            ('version_bound','delete_started'),
            ('delete_started','delete_started'),('delete_started','delete_uncertain'),('delete_started','verified_destroyed'),
            ('delete_uncertain','delete_started'),('delete_uncertain','verified_destroyed'),
            ('verified_destroyed','verified_destroyed'))`
	listStagingExecutionSQL = `SELECT record_json FROM core_cloud_worker_input_staging
        WHERE owner_id=$1 AND account_generation=$2 AND execution_id=$3
        ORDER BY input_id`
	stagingLedgerReadySQL = `SELECT COALESCE(to_regclass('core_cloud_worker_input_staging')::text, '')`
)

type stagingLedgerDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

type PostgresStagingLedger struct{ db stagingLedgerDB }

func NewPostgresStagingLedger(pool *pgxpool.Pool) (*PostgresStagingLedger, error) {
	if pool == nil {
		return nil, ErrInvalid
	}
	return &PostgresStagingLedger{db: pool}, nil
}

func newPostgresStagingLedger(db stagingLedgerDB) (*PostgresStagingLedger, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &PostgresStagingLedger{db: db}, nil
}

func (ledger *PostgresStagingLedger) Ready(ctx context.Context) error {
	if ledger == nil || ledger.db == nil || ctx == nil {
		return ErrInvalid
	}
	var table string
	if err := ledger.db.QueryRow(ctx, stagingLedgerReadySQL).Scan(&table); err != nil || table != PostgresStagingLedgerTable {
		return errors.Join(ErrNotFound, err)
	}
	return nil
}

func (ledger *PostgresStagingLedger) CreateIntent(ctx context.Context, proposed StagingRecord) (StagingRecord, error) {
	if ledger == nil || ledger.db == nil || ctx == nil || proposed.Validate() != nil || proposed.State != StagingIntentRecorded {
		return StagingRecord{}, ErrInvalid
	}
	encoded, err := encodeStagingRecord(proposed)
	if err != nil {
		return StagingRecord{}, err
	}
	identity := proposed.Identity
	tag, err := ledger.db.Exec(ctx, insertStagingRecordSQL,
		stagingKey(identity), identity.IntentDigest(), identity.OwnerID, identity.AccountID, identity.AccountGeneration,
		identity.Region, identity.ProviderID, identity.ExecutionID, identity.PlanDigest, identity.InputID,
		string(proposed.State), proposed.VersionID, nullableStagingTime(proposed.MutationLeaseUntil), proposed.MutationAttempts,
		proposed.DeleteAttempts, proposed.Revision, encoded, proposed.CreatedAt, proposed.UpdatedAt)
	if err != nil {
		return StagingRecord{}, errors.Join(ErrConflict, err)
	}
	if tag.RowsAffected() == 1 {
		return proposed, nil
	}
	stored, err := ledger.Get(ctx, identity)
	if err != nil || stored.Identity != identity {
		return StagingRecord{}, errors.Join(ErrConflict, err)
	}
	return stored, nil
}

func (ledger *PostgresStagingLedger) Get(ctx context.Context, identity StagingObjectIdentity) (StagingRecord, error) {
	if ledger == nil || ledger.db == nil || ctx == nil || identity.Validate() != nil {
		return StagingRecord{}, ErrInvalid
	}
	var encoded []byte
	if err := ledger.db.QueryRow(ctx, getStagingRecordSQL, stagingKey(identity), identity.IntentDigest()).Scan(&encoded); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return StagingRecord{}, ErrNotFound
		}
		return StagingRecord{}, errors.Join(ErrNotFound, err)
	}
	record, err := decodeStagingRecord(encoded)
	if err != nil || record.Identity != identity {
		return StagingRecord{}, errors.Join(ErrConflict, err)
	}
	return record, nil
}

func (ledger *PostgresStagingLedger) CompareAndSwap(ctx context.Context, next StagingRecord, expectedRevision uint64) (StagingRecord, error) {
	if ledger == nil || ledger.db == nil || ctx == nil || next.Validate() != nil || expectedRevision == 0 || next.Revision != expectedRevision+1 {
		return StagingRecord{}, ErrInvalid
	}
	current, err := ledger.Get(ctx, next.Identity)
	if err != nil || current.Revision != expectedRevision || !validStagingTransition(current, next) {
		return StagingRecord{}, errors.Join(ErrConflict, err)
	}
	encoded, err := encodeStagingRecord(next)
	if err != nil {
		return StagingRecord{}, err
	}
	tag, err := ledger.db.Exec(ctx, casStagingRecordSQL, stagingKey(next.Identity), next.Identity.IntentDigest(), string(next.State), next.VersionID,
		nullableStagingTime(next.MutationLeaseUntil), next.MutationAttempts, next.DeleteAttempts, next.Revision, encoded, next.UpdatedAt, expectedRevision)
	if err != nil || tag.RowsAffected() != 1 {
		return StagingRecord{}, errors.Join(ErrConflict, err)
	}
	return next, nil
}

func (ledger *PostgresStagingLedger) ListExecution(ctx context.Context, owner string, accountGeneration uint64, executionID string) ([]StagingRecord, error) {
	if ledger == nil || ledger.db == nil || ctx == nil || owner == "" || accountGeneration == 0 || !validUUID(executionID) {
		return nil, ErrInvalid
	}
	rows, err := ledger.db.Query(ctx, listStagingExecutionSQL, owner, accountGeneration, executionID)
	if err != nil {
		return nil, errors.Join(ErrNotFound, err)
	}
	defer rows.Close()
	result := make([]StagingRecord, 0)
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return nil, errors.Join(ErrInvalid, err)
		}
		record, err := decodeStagingRecord(encoded)
		if err != nil || record.Identity.OwnerID != owner || record.Identity.AccountGeneration != accountGeneration || record.Identity.ExecutionID != executionID {
			return nil, errors.Join(ErrConflict, err)
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrInvalid, err)
	}
	return result, nil
}

func encodeStagingRecord(record StagingRecord) ([]byte, error) {
	if record.Validate() != nil {
		return nil, ErrInvalid
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) == 0 || len(encoded) > maxStagingRecordJSONBytes {
		return nil, fmt.Errorf("%w: staging record JSON", ErrInvalid)
	}
	return encoded, nil
}

func decodeStagingRecord(encoded []byte) (StagingRecord, error) {
	if len(encoded) == 0 || len(encoded) > maxStagingRecordJSONBytes {
		return StagingRecord{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record StagingRecord
	if err := decoder.Decode(&record); err != nil {
		return StagingRecord{}, errors.Join(ErrInvalid, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || record.Validate() != nil {
		return StagingRecord{}, ErrInvalid
	}
	return record, nil
}

func nullableStagingTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

var _ StagingLedger = (*PostgresStagingLedger)(nil)
