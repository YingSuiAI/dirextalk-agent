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
	PostgresOutputJournalTable = "core_cloud_worker_output_journals"
	PostgresOutputVersionTable = "core_cloud_worker_output_versions"
	maxOutputRecordJSONBytes   = 128 * 1024
)

// PostgresOutputJournalSchemaRequirement is consumed by the single fresh-state
// Cloud Worker migration. Runtime code never creates or alters schema.
const PostgresOutputJournalSchemaRequirement = `CREATE TABLE core_cloud_worker_output_journals (
    identity_key text PRIMARY KEY,
    identity_digest char(64) NOT NULL CHECK (identity_digest ~ '^[a-f0-9]{64}$'),
    execution_identity_digest char(64) NOT NULL CHECK (execution_identity_digest ~ '^[a-f0-9]{64}$'),
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    account_id char(12) NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    region text NOT NULL CHECK (length(region) BETWEEN 1 AND 64),
    credential_id uuid NOT NULL,
    credential_revision bigint NOT NULL CHECK (credential_revision > 0),
    provider_id text NOT NULL CHECK (length(provider_id) BETWEEN 1 AND 2048),
    execution_id uuid NOT NULL REFERENCES core_cloud_worker_executions(execution_id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL REFERENCES core_cloud_worker_plans(plan_id) ON DELETE RESTRICT,
    plan_digest char(64) NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
    task_id uuid NOT NULL REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    task_attempt integer NOT NULL CHECK (task_attempt > 0),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    bucket text NOT NULL CHECK (length(bucket) BETWEEN 3 AND 63),
    key_prefix text NOT NULL CHECK (length(key_prefix) BETWEEN 1 AND 1024),
    kms_key_arn text NOT NULL CHECK (length(kms_key_arn) BETWEEN 1 AND 2048),
    state text NOT NULL CHECK (state IN ('approved','cleaning','verified_clean')),
    inventory_attempts integer NOT NULL DEFAULT 0 CHECK (inventory_attempts >= 0),
    revision bigint NOT NULL CHECK (revision > 0),
    record_json jsonb NOT NULL CHECK (jsonb_typeof(record_json) = 'object' AND pg_column_size(record_json) <= 131072),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    verified_clean_at timestamptz,
    UNIQUE (execution_id, task_attempt, lease_epoch),
    FOREIGN KEY (credential_id, credential_revision)
        REFERENCES core_aws_credential_revisions(credential_id, revision) ON DELETE RESTRICT,
    CHECK (updated_at >= created_at),
    CHECK ((state = 'approved') = (inventory_attempts = 0)),
    CHECK ((state = 'verified_clean') = (verified_clean_at IS NOT NULL)),
    CHECK (verified_clean_at IS NULL OR verified_clean_at >= created_at)
);
CREATE INDEX core_cloud_worker_output_journals_cleanup_idx
    ON core_cloud_worker_output_journals (owner_id, account_generation, execution_id, task_attempt, lease_epoch)
    WHERE state <> 'verified_clean';

CREATE TABLE core_cloud_worker_output_versions (
    identity_key text PRIMARY KEY,
    identity_digest char(64) NOT NULL CHECK (identity_digest ~ '^[a-f0-9]{64}$'),
    execution_identity_digest char(64) NOT NULL CHECK (execution_identity_digest ~ '^[a-f0-9]{64}$'),
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    account_id char(12) NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    region text NOT NULL CHECK (length(region) BETWEEN 1 AND 64),
    credential_id uuid NOT NULL,
    credential_revision bigint NOT NULL CHECK (credential_revision > 0),
    provider_id text NOT NULL CHECK (length(provider_id) BETWEEN 1 AND 2048),
    execution_id uuid NOT NULL REFERENCES core_cloud_worker_executions(execution_id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL REFERENCES core_cloud_worker_plans(plan_id) ON DELETE RESTRICT,
    plan_digest char(64) NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
    task_id uuid NOT NULL REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    bucket text NOT NULL CHECK (length(bucket) BETWEEN 3 AND 63),
    key_prefix text NOT NULL CHECK (length(key_prefix) BETWEEN 1 AND 1024),
    kms_key_arn text NOT NULL CHECK (length(kms_key_arn) BETWEEN 1 AND 2048),
    object_key text NOT NULL CHECK (length(object_key) BETWEEN 1 AND 1024),
    version_id text NOT NULL CHECK (length(version_id) BETWEEN 1 AND 1024),
    delete_marker boolean NOT NULL,
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    state text NOT NULL CHECK (state IN ('discovered','delete_started','delete_uncertain','verified_deleted','retained')),
    delete_attempts integer NOT NULL DEFAULT 0 CHECK (delete_attempts >= 0),
    revision bigint NOT NULL CHECK (revision > 0),
    record_json jsonb NOT NULL CHECK (jsonb_typeof(record_json) = 'object' AND pg_column_size(record_json) <= 131072),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    verified_deleted_at timestamptz,
    UNIQUE (bucket, object_key, version_id),
    FOREIGN KEY (credential_id, credential_revision)
        REFERENCES core_aws_credential_revisions(credential_id, revision) ON DELETE RESTRICT,
    CHECK (updated_at >= created_at),
    CHECK (NOT delete_marker OR size_bytes = 0),
    CHECK (state NOT IN ('discovered','retained') OR delete_attempts = 0),
    CHECK ((state = 'verified_deleted') = (verified_deleted_at IS NOT NULL)),
    CHECK (verified_deleted_at IS NULL OR verified_deleted_at >= created_at)
);
CREATE INDEX core_cloud_worker_output_versions_cleanup_idx
    ON core_cloud_worker_output_versions (owner_id, account_generation, execution_id, state, object_key, version_id)
    WHERE state NOT IN ('verified_deleted','retained');`

var (
	insertOutputJournalSQL = `INSERT INTO core_cloud_worker_output_journals
        (identity_key,identity_digest,execution_identity_digest,owner_id,account_id,account_generation,region,
         credential_id,credential_revision,provider_id,execution_id,plan_id,plan_digest,task_id,task_attempt,
         lease_epoch,bucket,key_prefix,kms_key_arn,state,inventory_attempts,revision,record_json,created_at,
         updated_at,verified_clean_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23::jsonb,$24,$25,$26)
        ON CONFLICT (identity_key) DO NOTHING`
	getOutputJournalSQL = `SELECT record_json FROM core_cloud_worker_output_journals
        WHERE identity_key=$1 AND identity_digest=$2`
	listOutputJournalsSQL = `SELECT record_json FROM core_cloud_worker_output_journals
        WHERE execution_identity_digest=$1 ORDER BY task_attempt,lease_epoch`
	casOutputJournalSQL = `UPDATE core_cloud_worker_output_journals
        SET state=$3,inventory_attempts=$4,revision=$5,record_json=$6::jsonb,updated_at=$7,verified_clean_at=$8
        WHERE identity_key=$1 AND identity_digest=$2 AND revision=$9`
	insertOutputVersionSQL = `INSERT INTO core_cloud_worker_output_versions
        (identity_key,identity_digest,execution_identity_digest,owner_id,account_id,account_generation,region,
         credential_id,credential_revision,provider_id,execution_id,plan_id,plan_digest,task_id,bucket,key_prefix,
         kms_key_arn,object_key,version_id,delete_marker,size_bytes,state,delete_attempts,revision,record_json,
         created_at,updated_at,verified_deleted_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25::jsonb,$26,$27,$28)
        ON CONFLICT (identity_key) DO NOTHING`
	getOutputVersionSQL = `SELECT record_json FROM core_cloud_worker_output_versions
        WHERE identity_key=$1 AND identity_digest=$2`
	listOutputVersionsSQL = `SELECT record_json FROM core_cloud_worker_output_versions
        WHERE execution_identity_digest=$1 ORDER BY object_key,version_id`
	casOutputVersionSQL = `UPDATE core_cloud_worker_output_versions
        SET state=$3,delete_attempts=$4,revision=$5,record_json=$6::jsonb,updated_at=$7,verified_deleted_at=$8
        WHERE identity_key=$1 AND identity_digest=$2 AND revision=$9`
	outputJournalReadySQL = `SELECT COALESCE(to_regclass('core_cloud_worker_output_journals')::text, ''),
        COALESCE(to_regclass('core_cloud_worker_output_versions')::text, '')`
)

type outputJournalDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

type PostgresOutputJournalLedger struct{ db outputJournalDB }

func NewPostgresOutputJournalLedger(pool *pgxpool.Pool) (*PostgresOutputJournalLedger, error) {
	if pool == nil {
		return nil, ErrInvalid
	}
	return &PostgresOutputJournalLedger{db: pool}, nil
}

func newPostgresOutputJournalLedger(db outputJournalDB) (*PostgresOutputJournalLedger, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &PostgresOutputJournalLedger{db: db}, nil
}

func (ledger *PostgresOutputJournalLedger) Ready(ctx context.Context) error {
	if ledger == nil || ledger.db == nil || ctx == nil {
		return ErrInvalid
	}
	var journals, versions string
	if err := ledger.db.QueryRow(ctx, outputJournalReadySQL).Scan(&journals, &versions); err != nil ||
		journals != PostgresOutputJournalTable || versions != PostgresOutputVersionTable {
		return errors.Join(ErrNotFound, err)
	}
	return nil
}

func (ledger *PostgresOutputJournalLedger) EnsureJournal(ctx context.Context, proposed OutputJournalRecord) (OutputJournalRecord, error) {
	if ledger == nil || ledger.db == nil || ctx == nil || proposed.Validate() != nil || proposed.State != OutputJournalApproved {
		return OutputJournalRecord{}, ErrInvalid
	}
	encoded, err := encodeOutputRecord(proposed)
	if err != nil {
		return OutputJournalRecord{}, err
	}
	identity, execution := proposed.Identity, proposed.Identity.OutputExecutionIdentity
	tag, err := ledger.db.Exec(ctx, insertOutputJournalSQL,
		outputJournalKey(identity), digestValue(identity), digestValue(execution), execution.OwnerID, execution.AccountID,
		execution.AccountGeneration, execution.Region, execution.CredentialID, execution.CredentialRevision,
		execution.ProviderID, execution.ExecutionID, execution.PlanID, execution.PlanDigest, execution.TaskID,
		identity.Attempt, identity.LeaseEpoch, execution.Bucket, execution.KeyPrefix, execution.KMSKeyARN,
		string(proposed.State), proposed.InventoryAttempts, proposed.Revision, encoded, proposed.CreatedAt,
		proposed.UpdatedAt, nullableOutputTime(proposed.VerifiedCleanAt))
	if err != nil {
		return OutputJournalRecord{}, errors.Join(ErrConflict, err)
	}
	if tag.RowsAffected() == 1 {
		return proposed, nil
	}
	stored, err := ledger.getJournal(ctx, identity)
	if err != nil || stored.Identity != identity {
		return OutputJournalRecord{}, errors.Join(ErrConflict, err)
	}
	return stored, nil
}

func (ledger *PostgresOutputJournalLedger) ListJournals(ctx context.Context, identity OutputExecutionIdentity) ([]OutputJournalRecord, error) {
	if ledger == nil || ledger.db == nil || ctx == nil || identity.Validate() != nil {
		return nil, ErrInvalid
	}
	rows, err := ledger.db.Query(ctx, listOutputJournalsSQL, digestValue(identity))
	if err != nil {
		return nil, errors.Join(ErrNotFound, err)
	}
	defer rows.Close()
	result := make([]OutputJournalRecord, 0)
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return nil, errors.Join(ErrInvalid, err)
		}
		var record OutputJournalRecord
		if err := decodeOutputRecord(encoded, &record); err != nil || record.Identity.OutputExecutionIdentity != identity {
			return nil, errors.Join(ErrConflict, err)
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

func (ledger *PostgresOutputJournalLedger) CompareAndSwapJournal(ctx context.Context, next OutputJournalRecord, expectedRevision uint64) (OutputJournalRecord, error) {
	if ledger == nil || ledger.db == nil || ctx == nil || next.Validate() != nil || expectedRevision == 0 || next.Revision != expectedRevision+1 {
		return OutputJournalRecord{}, ErrInvalid
	}
	current, err := ledger.getJournal(ctx, next.Identity)
	if err != nil || current.Revision != expectedRevision || !validOutputJournalTransition(current, next) {
		return OutputJournalRecord{}, errors.Join(ErrConflict, err)
	}
	encoded, err := encodeOutputRecord(next)
	if err != nil {
		return OutputJournalRecord{}, err
	}
	tag, err := ledger.db.Exec(ctx, casOutputJournalSQL, outputJournalKey(next.Identity), digestValue(next.Identity), string(next.State),
		next.InventoryAttempts, next.Revision, encoded, next.UpdatedAt, nullableOutputTime(next.VerifiedCleanAt), expectedRevision)
	if err != nil || tag.RowsAffected() != 1 {
		return OutputJournalRecord{}, errors.Join(ErrConflict, err)
	}
	return next, nil
}

func (ledger *PostgresOutputJournalLedger) DiscoverVersion(ctx context.Context, proposed OutputVersionRecord) (OutputVersionRecord, error) {
	if ledger == nil || ledger.db == nil || ctx == nil || proposed.Validate() != nil || proposed.State != OutputVersionDiscovered {
		return OutputVersionRecord{}, ErrInvalid
	}
	encoded, err := encodeOutputRecord(proposed)
	if err != nil {
		return OutputVersionRecord{}, err
	}
	identity, execution := proposed.Observation.Identity, proposed.Observation.Identity.OutputExecutionIdentity
	tag, err := ledger.db.Exec(ctx, insertOutputVersionSQL,
		outputVersionKey(identity), digestValue(identity), digestValue(execution), execution.OwnerID, execution.AccountID,
		execution.AccountGeneration, execution.Region, execution.CredentialID, execution.CredentialRevision,
		execution.ProviderID, execution.ExecutionID, execution.PlanID, execution.PlanDigest, execution.TaskID,
		execution.Bucket, execution.KeyPrefix, execution.KMSKeyARN, identity.Key, identity.VersionID, identity.DeleteMarker,
		proposed.Observation.SizeBytes, string(proposed.State), proposed.DeleteAttempts, proposed.Revision, encoded,
		proposed.CreatedAt, proposed.UpdatedAt, nullableOutputTime(proposed.VerifiedDeletedAt))
	if err != nil {
		return OutputVersionRecord{}, errors.Join(ErrConflict, err)
	}
	if tag.RowsAffected() == 1 {
		return proposed, nil
	}
	stored, err := ledger.getVersion(ctx, identity)
	if err != nil || stored.Observation.Identity != identity || stored.Observation.SizeBytes != proposed.Observation.SizeBytes {
		return OutputVersionRecord{}, errors.Join(ErrConflict, err)
	}
	return stored, nil
}

func (ledger *PostgresOutputJournalLedger) ListVersions(ctx context.Context, identity OutputExecutionIdentity) ([]OutputVersionRecord, error) {
	if ledger == nil || ledger.db == nil || ctx == nil || identity.Validate() != nil {
		return nil, ErrInvalid
	}
	rows, err := ledger.db.Query(ctx, listOutputVersionsSQL, digestValue(identity))
	if err != nil {
		return nil, errors.Join(ErrNotFound, err)
	}
	defer rows.Close()
	result := make([]OutputVersionRecord, 0)
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return nil, errors.Join(ErrInvalid, err)
		}
		var record OutputVersionRecord
		if err := decodeOutputRecord(encoded, &record); err != nil || record.Observation.Identity.OutputExecutionIdentity != identity {
			return nil, errors.Join(ErrConflict, err)
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

func (ledger *PostgresOutputJournalLedger) CompareAndSwapVersion(ctx context.Context, next OutputVersionRecord, expectedRevision uint64) (OutputVersionRecord, error) {
	if ledger == nil || ledger.db == nil || ctx == nil || next.Validate() != nil || expectedRevision == 0 || next.Revision != expectedRevision+1 {
		return OutputVersionRecord{}, ErrInvalid
	}
	current, err := ledger.getVersion(ctx, next.Observation.Identity)
	if err != nil || current.Revision != expectedRevision || !validOutputVersionTransition(current, next) {
		return OutputVersionRecord{}, errors.Join(ErrConflict, err)
	}
	encoded, err := encodeOutputRecord(next)
	if err != nil {
		return OutputVersionRecord{}, err
	}
	tag, err := ledger.db.Exec(ctx, casOutputVersionSQL, outputVersionKey(next.Observation.Identity), digestValue(next.Observation.Identity),
		string(next.State), next.DeleteAttempts, next.Revision, encoded, next.UpdatedAt,
		nullableOutputTime(next.VerifiedDeletedAt), expectedRevision)
	if err != nil || tag.RowsAffected() != 1 {
		return OutputVersionRecord{}, errors.Join(ErrConflict, err)
	}
	return next, nil
}

func (ledger *PostgresOutputJournalLedger) getJournal(ctx context.Context, identity OutputJournalIdentity) (OutputJournalRecord, error) {
	if identity.Validate() != nil {
		return OutputJournalRecord{}, ErrInvalid
	}
	var encoded []byte
	if err := ledger.db.QueryRow(ctx, getOutputJournalSQL, outputJournalKey(identity), digestValue(identity)).Scan(&encoded); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OutputJournalRecord{}, ErrNotFound
		}
		return OutputJournalRecord{}, err
	}
	var record OutputJournalRecord
	if err := decodeOutputRecord(encoded, &record); err != nil || record.Identity != identity {
		return OutputJournalRecord{}, errors.Join(ErrConflict, err)
	}
	return record, nil
}

func (ledger *PostgresOutputJournalLedger) getVersion(ctx context.Context, identity OutputVersionIdentity) (OutputVersionRecord, error) {
	if identity.Validate() != nil {
		return OutputVersionRecord{}, ErrInvalid
	}
	var encoded []byte
	if err := ledger.db.QueryRow(ctx, getOutputVersionSQL, outputVersionKey(identity), digestValue(identity)).Scan(&encoded); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OutputVersionRecord{}, ErrNotFound
		}
		return OutputVersionRecord{}, err
	}
	var record OutputVersionRecord
	if err := decodeOutputRecord(encoded, &record); err != nil || record.Observation.Identity != identity {
		return OutputVersionRecord{}, errors.Join(ErrConflict, err)
	}
	return record, nil
}

func encodeOutputRecord(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > maxOutputRecordJSONBytes {
		return nil, fmt.Errorf("%w: output journal JSON", ErrInvalid)
	}
	return encoded, nil
}

func decodeOutputRecord(encoded []byte, target any) error {
	if len(encoded) == 0 || len(encoded) > maxOutputRecordJSONBytes || target == nil {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.Join(ErrInvalid, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	switch value := target.(type) {
	case *OutputJournalRecord:
		return value.Validate()
	case *OutputVersionRecord:
		return value.Validate()
	default:
		return ErrInvalid
	}
}

func nullableOutputTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

var _ OutputJournalLedger = (*PostgresOutputJournalLedger)(nil)
