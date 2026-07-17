package postgres

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type WorkerServiceOperationStore struct {
	pool       *pgxpool.Pool
	instanceID uuid.UUID
}

var _ workeroperation.Repository = (*WorkerServiceOperationStore)(nil)

func NewWorkerServiceOperationStore(store *Store) (*WorkerServiceOperationStore, error) {
	if store == nil || store.pool == nil || store.instanceID == uuid.Nil {
		return nil, workeroperation.ErrInvalid
	}
	return &WorkerServiceOperationStore{pool: store.pool, instanceID: store.instanceID}, nil
}

func (store *WorkerServiceOperationStore) CreateIdempotent(ctx context.Context, value workeroperation.Operation, mutation workeroperation.Mutation) (workeroperation.Operation, error) {
	if ctx == nil || value.Validate() != nil || mutation.ExpectedRevision != 0 {
		return workeroperation.Operation{}, workeroperation.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return workeroperation.Operation{}, fmt.Errorf("begin worker service operation create: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replayed, found, err := readWorkerOperationReplay(ctx, tx, value.OperationID, "create", mutation); err != nil {
		return workeroperation.Operation{}, err
	} else if found {
		return commitWorkerOperationReplay(ctx, tx, replayed)
	}
	snapshot, err := json.Marshal(value)
	if err != nil {
		return workeroperation.Operation{}, workeroperation.ErrInvalid
	}
	tag, err := tx.Exec(ctx, `INSERT INTO worker_service_operations
		(operation_id,agent_instance_id,deployment_id,owner_id,action,lifecycle_restart_ref,execution_bundle_digest,
		 expected_installed_manifest_digest,state,worker_id,lease_epoch,revision,snapshot_json,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL,$10,$11,$12,$13,$14) ON CONFLICT DO NOTHING`,
		value.OperationID, store.instanceID, value.DeploymentID, value.OwnerID, value.Action,
		value.LifecycleRestartRef, value.ExecutionBundleDigest, value.ExpectedInstalledManifestDigest,
		value.State, value.LeaseEpoch, value.Revision,
		snapshot, value.CreatedAt.UTC(), value.UpdatedAt.UTC())
	if err != nil {
		return workeroperation.Operation{}, fmt.Errorf("insert worker service operation: %w", err)
	}
	if tag.RowsAffected() != 1 {
		replayed, found, replayErr := readWorkerOperationReplay(ctx, tx, value.OperationID, "create", mutation)
		if replayErr != nil {
			return workeroperation.Operation{}, replayErr
		}
		if !found {
			return workeroperation.Operation{}, workeroperation.ErrIdempotencyConflict
		}
		return commitWorkerOperationReplay(ctx, tx, replayed)
	}
	if err := insertWorkerOperationReplay(ctx, tx, value.OperationID, "create", mutation, value, snapshot); err != nil {
		return workeroperation.Operation{}, err
	}
	return commitWorkerOperationReplay(ctx, tx, value)
}

func (store *WorkerServiceOperationStore) Get(ctx context.Context, operationID string) (workeroperation.Operation, error) {
	if ctx == nil {
		return workeroperation.Operation{}, workeroperation.ErrInvalid
	}
	return scanWorkerServiceOperation(store.pool.QueryRow(ctx, workerOperationSelect+`
		WHERE operation_id=$1 AND agent_instance_id=$2`, operationID, store.instanceID))
}

func (store *WorkerServiceOperationStore) MutateIdempotent(
	ctx context.Context,
	operationID, operation string,
	mutation workeroperation.Mutation,
	update func(*workeroperation.Operation) error,
) (workeroperation.Operation, error) {
	if ctx == nil || (operation != "claim" && operation != "complete") || update == nil {
		return workeroperation.Operation{}, workeroperation.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return workeroperation.Operation{}, fmt.Errorf("begin worker service operation mutation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replayed, found, err := readWorkerOperationReplay(ctx, tx, operationID, operation, mutation); err != nil {
		return workeroperation.Operation{}, err
	} else if found {
		return commitWorkerOperationReplay(ctx, tx, replayed)
	}
	current, err := scanWorkerServiceOperation(tx.QueryRow(ctx, workerOperationSelect+`
		WHERE operation_id=$1 AND agent_instance_id=$2 FOR UPDATE`, operationID, store.instanceID))
	if err != nil {
		return workeroperation.Operation{}, err
	}
	if current.Revision != mutation.ExpectedRevision {
		replayed, found, replayErr := readWorkerOperationReplay(ctx, tx, operationID, operation, mutation)
		if replayErr != nil {
			return workeroperation.Operation{}, replayErr
		}
		if found {
			return commitWorkerOperationReplay(ctx, tx, replayed)
		}
		return workeroperation.Operation{}, workeroperation.ErrRevisionConflict
	}
	next := current.Clone()
	if err := update(&next); err != nil {
		return workeroperation.Operation{}, err
	}
	if next.Validate() != nil {
		return workeroperation.Operation{}, workeroperation.ErrInvalid
	}
	snapshot, err := json.Marshal(next)
	if err != nil {
		return workeroperation.Operation{}, workeroperation.ErrInvalid
	}
	tag, err := tx.Exec(ctx, `UPDATE worker_service_operations SET
		state=$1,worker_id=$2,lease_epoch=$3,revision=$4,snapshot_json=$5,updated_at=$6
		WHERE operation_id=$7 AND agent_instance_id=$8 AND revision=$9`,
		next.State, nullableUUID(next.WorkerID), next.LeaseEpoch, next.Revision, snapshot, next.UpdatedAt.UTC(),
		next.OperationID, store.instanceID, current.Revision)
	if err != nil {
		return workeroperation.Operation{}, fmt.Errorf("update worker service operation: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return workeroperation.Operation{}, workeroperation.ErrRevisionConflict
	}
	if err := insertWorkerOperationReplay(ctx, tx, operationID, operation, mutation, next, snapshot); err != nil {
		return workeroperation.Operation{}, err
	}
	return commitWorkerOperationReplay(ctx, tx, next)
}

func (store *WorkerServiceOperationStore) AcquireNext(ctx context.Context, selection workeroperation.AcquireSelection) (workeroperation.Operation, error) {
	if ctx == nil || selection.Now.IsZero() || selection.DeploymentID == "" || selection.WorkerID == "" {
		return workeroperation.Operation{}, workeroperation.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return workeroperation.Operation{}, fmt.Errorf("begin worker service operation acquire: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Serialize discovery per deployment so two polling Workers cannot both
	// observe the same oldest pending/expired assignment.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		store.instanceID.String()+"\x00"+selection.DeploymentID); err != nil {
		return workeroperation.Operation{}, fmt.Errorf("lock worker service operation deployment: %w", err)
	}
	if replayed, found, err := readWorkerAcquireReplay(ctx, tx, store.instanceID, selection); err != nil {
		return workeroperation.Operation{}, err
	} else if found {
		return commitWorkerOperationReplay(ctx, tx, replayed)
	}

	rows, err := tx.Query(ctx, workerOperationSelect+`
		WHERE agent_instance_id=$1 AND deployment_id=$2 AND state=$3 AND worker_id=$4
		  AND (snapshot_json->>'LeaseExpiresAt')::timestamptz > $5
		ORDER BY created_at,operation_id LIMIT 2 FOR UPDATE`,
		store.instanceID, selection.DeploymentID, workeroperation.StateLeased, selection.WorkerID, selection.Now.UTC())
	if err != nil {
		return workeroperation.Operation{}, fmt.Errorf("query active worker service operation: %w", err)
	}
	active := make([]workeroperation.Operation, 0, 2)
	for rows.Next() {
		value, scanErr := scanWorkerServiceOperation(rows)
		if scanErr != nil {
			rows.Close()
			return workeroperation.Operation{}, scanErr
		}
		active = append(active, value)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return workeroperation.Operation{}, fmt.Errorf("iterate active worker service operation: %w", err)
	}
	if len(active) > 1 {
		return workeroperation.Operation{}, workeroperation.ErrInvalid
	}
	if len(active) == 1 {
		snapshot, marshalErr := json.Marshal(active[0])
		if marshalErr != nil {
			return workeroperation.Operation{}, workeroperation.ErrInvalid
		}
		if err := insertWorkerOperationReplay(ctx, tx, active[0].OperationID, "acquire",
			selection.Mutation, active[0], snapshot); err != nil {
			return workeroperation.Operation{}, err
		}
		return commitWorkerOperationReplay(ctx, tx, active[0])
	}

	current, err := scanWorkerServiceOperation(tx.QueryRow(ctx, workerOperationSelect+`
		WHERE agent_instance_id=$1 AND deployment_id=$2
		  AND (state=$3 OR (state=$4 AND (snapshot_json->>'LeaseExpiresAt')::timestamptz <= $5))
		ORDER BY created_at,operation_id LIMIT 1 FOR UPDATE`,
		store.instanceID, selection.DeploymentID, workeroperation.StatePending,
		workeroperation.StateLeased, selection.Now.UTC()))
	if err != nil {
		return workeroperation.Operation{}, err
	}
	next := current.Clone()
	next.State, next.WorkerID = workeroperation.StateLeased, selection.WorkerID
	next.LeaseEpoch++
	next.LeaseExpiresAt = selection.Now.Add(selection.LeaseDuration)
	next.Revision++
	next.UpdatedAt = selection.Now
	if next.Validate() != nil {
		return workeroperation.Operation{}, workeroperation.ErrInvalid
	}
	snapshot, err := json.Marshal(next)
	if err != nil {
		return workeroperation.Operation{}, workeroperation.ErrInvalid
	}
	tag, err := tx.Exec(ctx, `UPDATE worker_service_operations SET
		state=$1,worker_id=$2,lease_epoch=$3,revision=$4,snapshot_json=$5,updated_at=$6
		WHERE operation_id=$7 AND agent_instance_id=$8 AND revision=$9`,
		next.State, next.WorkerID, next.LeaseEpoch, next.Revision, snapshot, next.UpdatedAt.UTC(),
		next.OperationID, store.instanceID, current.Revision)
	if err != nil {
		return workeroperation.Operation{}, fmt.Errorf("acquire worker service operation: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return workeroperation.Operation{}, workeroperation.ErrRevisionConflict
	}
	if err := insertWorkerOperationReplay(ctx, tx, next.OperationID, "acquire", selection.Mutation, next, snapshot); err != nil {
		return workeroperation.Operation{}, err
	}
	return commitWorkerOperationReplay(ctx, tx, next)
}

const workerOperationSelect = `SELECT operation_id,deployment_id,owner_id,action,lifecycle_restart_ref,
	execution_bundle_digest,expected_installed_manifest_digest,state,worker_id,lease_epoch,revision,snapshot_json,created_at,updated_at
	FROM worker_service_operations`

type workerOperationScanner interface{ Scan(...any) error }

func scanWorkerServiceOperation(scanner workerOperationScanner) (workeroperation.Operation, error) {
	var (
		value        workeroperation.Operation
		operationID  uuid.UUID
		deploymentID uuid.UUID
		workerID     *uuid.UUID
		snapshot     []byte
	)
	if err := scanner.Scan(&operationID, &deploymentID, &value.OwnerID, &value.Action, &value.LifecycleRestartRef,
		&value.ExecutionBundleDigest, &value.ExpectedInstalledManifestDigest, &value.State, &workerID, &value.LeaseEpoch, &value.Revision,
		&snapshot, &value.CreatedAt, &value.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return workeroperation.Operation{}, workeroperation.ErrNotFound
		}
		return workeroperation.Operation{}, fmt.Errorf("scan worker service operation: %w", err)
	}
	var decoded workeroperation.Operation
	if json.Unmarshal(snapshot, &decoded) != nil {
		return workeroperation.Operation{}, workeroperation.ErrInvalid
	}
	value.OperationID, value.DeploymentID = operationID.String(), deploymentID.String()
	if workerID != nil {
		value.WorkerID = workerID.String()
	}
	if decoded.OperationID != value.OperationID || decoded.DeploymentID != value.DeploymentID ||
		decoded.OwnerID != value.OwnerID || decoded.Action != value.Action ||
		decoded.LifecycleRestartRef != value.LifecycleRestartRef ||
		decoded.ExecutionBundleDigest != value.ExecutionBundleDigest ||
		decoded.ExpectedInstalledManifestDigest != value.ExpectedInstalledManifestDigest || decoded.State != value.State ||
		decoded.WorkerID != value.WorkerID || decoded.LeaseEpoch != value.LeaseEpoch ||
		decoded.Revision != value.Revision || !decoded.CreatedAt.Equal(value.CreatedAt) ||
		!decoded.UpdatedAt.Equal(value.UpdatedAt) || decoded.Validate() != nil {
		return workeroperation.Operation{}, workeroperation.ErrInvalid
	}
	return decoded, nil
}

type workerOperationQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readWorkerOperationReplay(ctx context.Context, query workerOperationQuery, operationID, operation string, mutation workeroperation.Mutation) (workeroperation.Operation, bool, error) {
	var storedHash, response []byte
	var responseRevision int64
	err := query.QueryRow(ctx, `SELECT request_hash,response_revision,response_json
		FROM worker_service_operation_replays WHERE operation_id=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE`,
		operationID, operation, mutation.IdempotencyKey).Scan(&storedHash, &responseRevision, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return workeroperation.Operation{}, false, nil
	}
	if err != nil {
		return workeroperation.Operation{}, false, fmt.Errorf("read worker service operation replay: %w", err)
	}
	if subtle.ConstantTimeCompare(storedHash, mutation.RequestHash[:]) != 1 {
		return workeroperation.Operation{}, false, workeroperation.ErrIdempotencyConflict
	}
	var value workeroperation.Operation
	if json.Unmarshal(response, &value) != nil || value.Revision != responseRevision || value.Validate() != nil {
		return workeroperation.Operation{}, false, workeroperation.ErrInvalid
	}
	return value, true, nil
}

func readWorkerAcquireReplay(ctx context.Context, query workerOperationQuery, instanceID uuid.UUID,
	selection workeroperation.AcquireSelection) (workeroperation.Operation, bool, error) {
	var storedHash, response []byte
	var responseRevision int64
	err := query.QueryRow(ctx, `SELECT replay.request_hash,replay.response_revision,replay.response_json
		FROM worker_service_operation_replays replay
		JOIN worker_service_operations operation ON operation.operation_id=replay.operation_id
		WHERE operation.agent_instance_id=$1 AND operation.deployment_id=$2
		  AND replay.operation='acquire' AND replay.idempotency_key=$3
		FOR UPDATE`,
		instanceID, selection.DeploymentID, selection.Mutation.IdempotencyKey,
	).Scan(&storedHash, &responseRevision, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return workeroperation.Operation{}, false, nil
	}
	if err != nil {
		return workeroperation.Operation{}, false, fmt.Errorf("read worker service operation acquire replay: %w", err)
	}
	if subtle.ConstantTimeCompare(storedHash, selection.Mutation.RequestHash[:]) != 1 {
		return workeroperation.Operation{}, false, workeroperation.ErrIdempotencyConflict
	}
	var value workeroperation.Operation
	if json.Unmarshal(response, &value) != nil || value.Revision != responseRevision ||
		value.DeploymentID != selection.DeploymentID || value.WorkerID != selection.WorkerID || value.Validate() != nil {
		return workeroperation.Operation{}, false, workeroperation.ErrInvalid
	}
	return value, true, nil
}

func insertWorkerOperationReplay(ctx context.Context, tx pgx.Tx, operationID, operation string, mutation workeroperation.Mutation, response workeroperation.Operation, responseJSON []byte) error {
	_, err := tx.Exec(ctx, `INSERT INTO worker_service_operation_replays
		(operation_id,operation,idempotency_key,request_hash,response_revision,response_json)
		VALUES($1,$2,$3,$4,$5,$6)`,
		operationID, operation, mutation.IdempotencyKey, mutation.RequestHash[:], response.Revision, responseJSON)
	if err != nil {
		return fmt.Errorf("insert worker service operation replay: %w", err)
	}
	return nil
}

func commitWorkerOperationReplay(ctx context.Context, tx pgx.Tx, value workeroperation.Operation) (workeroperation.Operation, error) {
	if err := tx.Commit(ctx); err != nil {
		return workeroperation.Operation{}, fmt.Errorf("commit worker service operation: %w", err)
	}
	return value.Clone(), nil
}
