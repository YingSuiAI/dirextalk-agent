package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/pairingworker"
	"github.com/jackc/pgx/v5"
)

type PairingWorkerOperationStore struct{ store *Store }

func NewPairingWorkerOperationStore(store *Store) (*PairingWorkerOperationStore, error) {
	if store == nil {
		return nil, pairingworker.ErrInvalid
	}
	return &PairingWorkerOperationStore{store: store}, nil
}

func (store *PairingWorkerOperationStore) Create(ctx context.Context, value pairingworker.Operation, key string, hash [32]byte) (pairingworker.Operation, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return pairingworker.Operation{}, pairingworker.ErrInvalid
	}
	defer clear(encoded)
	tx, err := store.store.pool.Begin(ctx)
	if err != nil {
		return pairingworker.Operation{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `INSERT INTO pairing_worker_operations
		(operation_id,agent_instance_id,deployment_id,state,revision,snapshot_json,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(operation_id) DO NOTHING`,
		value.OperationID, store.store.instanceID, value.DeploymentID, value.State, value.Revision, encoded, value.CreatedAt, value.UpdatedAt)
	if err != nil {
		return pairingworker.Operation{}, err
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		return store.readReplay(ctx, value.OperationID, "create", key, hash)
	}
	_, err = tx.Exec(ctx, `INSERT INTO pairing_worker_operation_replays(operation_id,operation,idempotency_key,request_hash,response_json)
		VALUES($1,'create',$2,$3,$4)`, value.OperationID, key, hash[:], encoded)
	if err != nil {
		return pairingworker.Operation{}, err
	}
	return value, tx.Commit(ctx)
}

func (store *PairingWorkerOperationStore) Get(ctx context.Context, id string) (pairingworker.Operation, error) {
	var encoded []byte
	err := store.store.pool.QueryRow(ctx, `SELECT snapshot_json FROM pairing_worker_operations
		WHERE agent_instance_id=$1 AND operation_id=$2`, store.store.instanceID, id).Scan(&encoded)
	return decodePairingWorkerOperation(encoded, err)
}

func (store *PairingWorkerOperationStore) AcquireNext(ctx context.Context, deployment, worker, _ string, now time.Time, lease time.Duration) (pairingworker.Operation, error) {
	tx, err := store.store.pool.Begin(ctx)
	if err != nil {
		return pairingworker.Operation{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var encoded []byte
	err = tx.QueryRow(ctx, `SELECT snapshot_json FROM pairing_worker_operations
		WHERE agent_instance_id=$1 AND deployment_id=$2 AND
		((state='leased' AND worker_id=$4 AND lease_expires_at > $3) OR state='pending' OR
		 (state='leased' AND lease_expires_at <= $3))
		ORDER BY CASE WHEN state='leased' AND worker_id=$4 AND lease_expires_at > $3 THEN 0 ELSE 1 END,
		 created_at,operation_id FOR UPDATE SKIP LOCKED LIMIT 1`,
		store.store.instanceID, deployment, now, worker).Scan(&encoded)
	value, err := decodePairingWorkerOperation(encoded, err)
	if err != nil {
		return pairingworker.Operation{}, err
	}
	if value.State == pairingworker.StateLeased && value.WorkerID == worker && now.Before(value.LeaseExpiresAt) {
		return value, tx.Commit(ctx)
	}
	value.State, value.WorkerID, value.LeaseEpoch = pairingworker.StateLeased, worker, value.LeaseEpoch+1
	if value.ExecutionEpoch == 0 {
		// Persisted in snapshot_json with the command so a re-lease cannot
		// manufacture a different immutable root-helper execution identity.
		value.ExecutionEpoch = 1
	}
	value.LeaseExpiresAt, value.Revision, value.UpdatedAt = now.Add(lease), value.Revision+1, now
	encoded, _ = json.Marshal(value)
	_, err = tx.Exec(ctx, `UPDATE pairing_worker_operations SET state=$3,worker_id=$4,lease_expires_at=$5,
		revision=$6,snapshot_json=$7,updated_at=$8 WHERE agent_instance_id=$1 AND operation_id=$2`,
		store.store.instanceID, value.OperationID, value.State, worker, value.LeaseExpiresAt, value.Revision, encoded, now)
	clear(encoded)
	if err != nil {
		return pairingworker.Operation{}, err
	}
	return value, tx.Commit(ctx)
}

func (store *PairingWorkerOperationStore) Complete(ctx context.Context, id, worker string, epoch, expected int64,
	key string, hash [32]byte, result *pairingworker.Result, failure string, now time.Time,
) (pairingworker.Operation, error) {
	tx, err := store.store.pool.Begin(ctx)
	if err != nil {
		return pairingworker.Operation{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var encoded []byte
	err = tx.QueryRow(ctx, `SELECT snapshot_json FROM pairing_worker_operations
		WHERE agent_instance_id=$1 AND operation_id=$2 FOR UPDATE`, store.store.instanceID, id).Scan(&encoded)
	value, err := decodePairingWorkerOperation(encoded, err)
	if err != nil {
		return pairingworker.Operation{}, err
	}
	if value.State == pairingworker.StateSucceeded || value.State == pairingworker.StateFailed {
		_ = tx.Rollback(ctx)
		return store.readReplay(ctx, id, "complete", key, hash)
	}
	if value.State != pairingworker.StateLeased || value.WorkerID != worker || value.LeaseEpoch != epoch ||
		value.Revision != expected || !now.Before(value.LeaseExpiresAt) {
		return pairingworker.Operation{}, pairingworker.ErrLease
	}
	value.LeaseExpiresAt, value.Revision, value.UpdatedAt = time.Time{}, value.Revision+1, now
	if failure != "" {
		value.State, value.FailureCode = pairingworker.StateFailed, failure
	} else {
		value.State, value.Result = pairingworker.StateSucceeded, result
	}
	encoded, _ = json.Marshal(value)
	_, err = tx.Exec(ctx, `UPDATE pairing_worker_operations SET state=$3,lease_expires_at=NULL,revision=$4,
		snapshot_json=$5,updated_at=$6 WHERE agent_instance_id=$1 AND operation_id=$2`,
		store.store.instanceID, id, value.State, value.Revision, encoded, now)
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO pairing_worker_operation_replays(operation_id,operation,idempotency_key,request_hash,response_json)
			VALUES($1,'complete',$2,$3,$4)`, id, key, hash[:], encoded)
	}
	clear(encoded)
	if err != nil {
		if isUniqueViolation(err) {
			_ = tx.Rollback(ctx)
			return store.readReplay(ctx, id, "complete", key, hash)
		}
		return pairingworker.Operation{}, err
	}
	return value, tx.Commit(ctx)
}

func (store *PairingWorkerOperationStore) readReplay(ctx context.Context, id, operation, key string, hash [32]byte) (pairingworker.Operation, error) {
	var savedHash, encoded []byte
	err := store.store.pool.QueryRow(ctx, `SELECT request_hash,response_json FROM pairing_worker_operation_replays
		WHERE operation_id=$1 AND operation=$2 AND idempotency_key=$3`, id, operation, key).Scan(&savedHash, &encoded)
	if err != nil || !jsonBytesEqual(savedHash, hash[:]) {
		return pairingworker.Operation{}, pairingworker.ErrRevisionConflict
	}
	return decodePairingWorkerOperation(encoded, nil)
}

func decodePairingWorkerOperation(encoded []byte, err error) (pairingworker.Operation, error) {
	if errors.Is(err, pgx.ErrNoRows) {
		return pairingworker.Operation{}, pairingworker.ErrNotFound
	}
	if err != nil {
		return pairingworker.Operation{}, err
	}
	var value pairingworker.Operation
	if json.Unmarshal(encoded, &value) != nil || value.Validate() != nil {
		return pairingworker.Operation{}, pairingworker.ErrInvalid
	}
	return value, nil
}

func jsonBytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
