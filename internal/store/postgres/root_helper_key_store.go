package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RootHelperKeyStore struct {
	pool       *pgxpool.Pool
	instanceID uuid.UUID
}

func NewRootHelperKeyStore(store *Store) (*RootHelperKeyStore, error) {
	if store == nil || store.pool == nil || store.instanceID == uuid.Nil {
		return nil, helperkey.ErrInvalid
	}
	return &RootHelperKeyStore{pool: store.pool, instanceID: store.instanceID}, nil
}

func (s *RootHelperKeyStore) CreateIdempotent(ctx context.Context, value helperkey.Record, key string, hash [32]byte) (helperkey.Record, error) {
	if value.Validate() != nil {
		return helperkey.Record{}, helperkey.ErrInvalid
	}
	raw, _ := json.Marshal(value)
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return helperkey.Record{}, helperkey.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `INSERT INTO root_helper_key_deliveries
		(delivery_id,agent_instance_id,deployment_id,instance_id,helper_id,signer_key_id,public_key,public_key_digest,secret_arn,secret_version_id,state,revision,snapshot_json,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT DO NOTHING`,
		value.Binding.DeliveryID, s.instanceID, value.Binding.DeploymentID, value.Binding.InstanceID, value.Binding.HelperID, value.Binding.SignerKeyID,
		value.PublicKey, value.Binding.PublicKeyDigest, value.Binding.Secret.ARN, value.Binding.Secret.VersionID, value.State, value.Revision, raw, value.CreatedAt, value.UpdatedAt)
	if err != nil {
		return helperkey.Record{}, helperkey.ErrUnavailable
	}
	if tag.RowsAffected() == 0 {
		replayed, ok, err := readRootHelperReplay(ctx, tx, value.Binding.DeliveryID, "create", key, hash)
		if err != nil || !ok {
			return helperkey.Record{}, helperkey.ErrConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return helperkey.Record{}, helperkey.ErrUnavailable
		}
		return replayed, nil
	}
	if err := insertRootHelperReplay(ctx, tx, value.Binding.DeliveryID, "create", key, hash, value); err != nil {
		return helperkey.Record{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return helperkey.Record{}, helperkey.ErrUnavailable
	}
	return value.Clone(), nil
}

func (s *RootHelperKeyStore) Get(ctx context.Context, id string) (helperkey.Record, error) {
	return scanRootHelper(s.pool.QueryRow(ctx, `SELECT snapshot_json FROM root_helper_key_deliveries WHERE delivery_id=$1 AND agent_instance_id=$2`, id, s.instanceID))
}

func (s *RootHelperKeyStore) DiscoverCurrent(ctx context.Context, scope helperkey.DiscoveryScope) (helperkey.Record, error) {
	deploymentID, deploymentErr := uuid.Parse(scope.DeploymentID)
	workerID, workerErr := uuid.Parse(scope.WorkerID)
	if deploymentErr != nil || workerErr != nil || deploymentID == uuid.Nil || workerID == uuid.Nil ||
		deploymentID.String() != scope.DeploymentID || workerID.String() != scope.WorkerID || scope.OwnerID == "" {
		return helperkey.Record{}, helperkey.ErrInvalid
	}
	rows, err := s.pool.Query(ctx, `SELECT delivery.snapshot_json
		FROM root_helper_key_deliveries delivery
		WHERE delivery.agent_instance_id=$1 AND delivery.deployment_id=$2
		  AND delivery.state = ANY($3::text[])
		  AND EXISTS (
		    SELECT 1
		    FROM worker_deployments deployment
		    JOIN worker_identity_enrollment_replays identity
		      ON identity.deployment_id=deployment.deployment_id
		     AND identity.caller_worker_id=deployment.worker_id
		     AND identity.provider_instance_id=deployment.provider_instance_id
		    WHERE deployment.agent_instance_id=delivery.agent_instance_id
		      AND deployment.deployment_id=delivery.deployment_id
		      AND deployment.owner_id=$4 AND deployment.worker_id=$5
		      AND delivery.snapshot_json #>> '{Binding,OwnerID}'=deployment.owner_id
		      AND delivery.snapshot_json #>> '{Binding,InstanceID}'=identity.provider_instance_id
		      AND delivery.snapshot_json #>> '{Binding,WorkerPrincipalID}'=identity.principal_id
		  )
		ORDER BY delivery.created_at DESC,delivery.delivery_id
		LIMIT 2`,
		s.instanceID, deploymentID,
		[]string{string(helperkey.StateGrant), string(helperkey.StateProof), string(helperkey.StateRevoking),
			string(helperkey.StateVerifiedRevoked), string(helperkey.StateReady)},
		scope.OwnerID, workerID)
	if err != nil {
		return helperkey.Record{}, helperkey.ErrUnavailable
	}
	defer rows.Close()
	values := make([]helperkey.Record, 0, 2)
	for rows.Next() {
		value, scanErr := scanRootHelper(rows)
		if scanErr != nil {
			return helperkey.Record{}, scanErr
		}
		values = append(values, value)
	}
	if rows.Err() != nil {
		return helperkey.Record{}, helperkey.ErrUnavailable
	}
	if len(values) == 0 {
		return helperkey.Record{}, helperkey.ErrNotFound
	}
	if len(values) != 1 {
		return helperkey.Record{}, helperkey.ErrConflict
	}
	value := values[0]
	if value.Binding.AgentInstanceID != s.instanceID.String() ||
		value.Binding.DeploymentID != scope.DeploymentID || value.Binding.OwnerID != scope.OwnerID {
		return helperkey.Record{}, helperkey.ErrInvalid
	}
	return value.Clone(), nil
}

// CurrentReadyPublicKey returns only the exact current
// deployment/helper/signer trust tuple. The validated snapshot remains the
// authority; the relational fields exist only to make this lookup indexable.
func (s *RootHelperKeyStore) CurrentReadyPublicKey(ctx context.Context, deploymentID, helperID, signerKeyID string) (ed25519.PublicKey, error) {
	parsedDeployment, err := uuid.Parse(deploymentID)
	if err != nil || parsedDeployment == uuid.Nil || parsedDeployment.String() != deploymentID || helperID == "" || signerKeyID == "" {
		return nil, helperkey.ErrInvalid
	}
	value, err := scanRootHelper(s.pool.QueryRow(ctx, `SELECT snapshot_json FROM root_helper_key_deliveries
		WHERE agent_instance_id=$1 AND deployment_id=$2 AND helper_id=$3 AND signer_key_id=$4 AND state=$5`,
		s.instanceID, parsedDeployment, helperID, signerKeyID, helperkey.StateReady))
	if err != nil {
		return nil, err
	}
	if value.State != helperkey.StateReady || value.Binding.AgentInstanceID != s.instanceID.String() ||
		value.Binding.DeploymentID != deploymentID || value.Binding.HelperID != helperID || value.Binding.SignerKeyID != signerKeyID {
		return nil, helperkey.ErrNotReady
	}
	return ed25519.PublicKey(bytes.Clone(value.PublicKey)), nil
}

// CurrentReadyRootHelper returns the single current ready binding for a
// deployment/helper pair. Callers use this as a fail-closed readiness gate
// before creating privileged Worker service-operation intents.
func (s *RootHelperKeyStore) CurrentReadyRootHelper(ctx context.Context, deploymentID, helperID string) (helperkey.Record, error) {
	parsedDeployment, err := uuid.Parse(deploymentID)
	if err != nil || parsedDeployment == uuid.Nil || parsedDeployment.String() != deploymentID || helperID == "" {
		return helperkey.Record{}, helperkey.ErrInvalid
	}
	value, err := scanRootHelper(s.pool.QueryRow(ctx, `SELECT snapshot_json FROM root_helper_key_deliveries
		WHERE agent_instance_id=$1 AND deployment_id=$2 AND helper_id=$3 AND state=$4`,
		s.instanceID, parsedDeployment, helperID, helperkey.StateReady))
	if err != nil {
		return helperkey.Record{}, err
	}
	if value.State != helperkey.StateReady || value.Binding.AgentInstanceID != s.instanceID.String() ||
		value.Binding.DeploymentID != deploymentID || value.Binding.HelperID != helperID {
		return helperkey.Record{}, helperkey.ErrNotReady
	}
	return value.Clone(), nil
}

func (s *RootHelperKeyStore) UpdateIdempotent(ctx context.Context, id string, expected helperkey.State, key string, hash [32]byte, update func(*helperkey.Record) error) (helperkey.Record, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return helperkey.Record{}, helperkey.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	operation := string(expected)
	if replayed, ok, err := readRootHelperReplay(ctx, tx, id, operation, key, hash); err != nil {
		return helperkey.Record{}, err
	} else if ok {
		if err := tx.Commit(ctx); err != nil {
			return helperkey.Record{}, helperkey.ErrUnavailable
		}
		return replayed, nil
	}
	current, err := scanRootHelper(tx.QueryRow(ctx, `SELECT snapshot_json FROM root_helper_key_deliveries WHERE delivery_id=$1 AND agent_instance_id=$2 FOR UPDATE`, id, s.instanceID))
	if err != nil {
		return helperkey.Record{}, err
	}
	if current.State != expected {
		return helperkey.Record{}, helperkey.ErrConflict
	}
	next := current.Clone()
	if update == nil || update(&next) != nil || next.Validate() != nil {
		return helperkey.Record{}, helperkey.ErrInvalid
	}
	raw, _ := json.Marshal(next)
	tag, err := tx.Exec(ctx, `UPDATE root_helper_key_deliveries SET state=$1,revision=$2,snapshot_json=$3,updated_at=$4
		WHERE delivery_id=$5 AND agent_instance_id=$6 AND revision=$7`, next.State, next.Revision, raw, next.UpdatedAt, id, s.instanceID, current.Revision)
	if err != nil || tag.RowsAffected() != 1 {
		return helperkey.Record{}, helperkey.ErrConflict
	}
	if err := insertRootHelperReplay(ctx, tx, id, operation, key, hash, next); err != nil {
		return helperkey.Record{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return helperkey.Record{}, helperkey.ErrUnavailable
	}
	return next.Clone(), nil
}

type rootHelperRow interface{ Scan(...any) error }

func scanRootHelper(row rootHelperRow) (helperkey.Record, error) {
	var raw []byte
	if err := row.Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return helperkey.Record{}, helperkey.ErrNotFound
		}
		return helperkey.Record{}, helperkey.ErrUnavailable
	}
	var value helperkey.Record
	if json.Unmarshal(raw, &value) != nil || value.Validate() != nil {
		return helperkey.Record{}, helperkey.ErrInvalid
	}
	return value, nil
}

func readRootHelperReplay(ctx context.Context, tx pgx.Tx, id, operation, key string, hash [32]byte) (helperkey.Record, bool, error) {
	var stored, raw []byte
	err := tx.QueryRow(ctx, `SELECT request_hash,response_json FROM root_helper_key_delivery_replays
		WHERE delivery_id=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE`, id, operation, key).Scan(&stored, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return helperkey.Record{}, false, nil
	}
	if err != nil {
		return helperkey.Record{}, false, helperkey.ErrUnavailable
	}
	if subtle.ConstantTimeCompare(stored, hash[:]) != 1 {
		return helperkey.Record{}, false, helperkey.ErrConflict
	}
	var value helperkey.Record
	if json.Unmarshal(raw, &value) != nil || value.Validate() != nil {
		return helperkey.Record{}, false, helperkey.ErrInvalid
	}
	return value, true, nil
}

func insertRootHelperReplay(ctx context.Context, tx pgx.Tx, id, operation, key string, hash [32]byte, value helperkey.Record) error {
	raw, _ := json.Marshal(value)
	_, err := tx.Exec(ctx, `INSERT INTO root_helper_key_delivery_replays
		(delivery_id,operation,idempotency_key,request_hash,response_revision,response_json) VALUES($1,$2,$3,$4,$5,$6)`,
		id, operation, key, hash[:], value.Revision, raw)
	if err != nil {
		return helperkey.ErrUnavailable
	}
	return nil
}

var _ helperkey.Repository = (*RootHelperKeyStore)(nil)
