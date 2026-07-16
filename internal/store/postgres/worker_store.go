package postgres

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	workerSnapshotSchemaV1 = 1
	workerReplayAADDomain  = "dirextalk.agent/worker-enrollment-replay/v1"
	workerCreateAADDomain  = "dirextalk.agent/worker-create-replay/v1"
)

type WorkerStore struct {
	pool       *pgxpool.Pool
	instanceID uuid.UUID
	replayKey  [32]byte
	random     io.Reader
}

var _ worker.Repository = (*WorkerStore)(nil)

func (store *Store) NewWorkerStore(replayKey []byte) (*WorkerStore, error) {
	if store == nil || store.pool == nil || len(replayKey) != 32 {
		return nil, worker.ErrInvalid
	}
	var key [32]byte
	copy(key[:], replayKey)
	var empty [32]byte
	if subtle.ConstantTimeCompare(key[:], empty[:]) == 1 {
		return nil, worker.ErrInvalid
	}
	return &WorkerStore{pool: store.pool, instanceID: store.instanceID, replayKey: key, random: cryptorand.Reader}, nil
}

func (store *WorkerStore) CreateIdempotent(
	ctx context.Context,
	deployment worker.Deployment,
	mutation worker.ControlMutationRecord,
	replayCredential []byte,
) (worker.Deployment, []byte, error) {
	parsedCredential, parsedKey, err := validateWorkerControlMutation(mutation)
	if err != nil || validateWorkerDeployment(deployment) != nil || len(replayCredential) < 32 || len(replayCredential) > 128 {
		return worker.Deployment{}, nil, worker.ErrInvalid
	}
	parsedDeployment, _ := uuid.Parse(deployment.DeploymentID)
	responseJSON, err := encodeWorkerSnapshot(deployment)
	if err != nil {
		return worker.Deployment{}, nil, err
	}
	nonce, ciphertext, err := store.sealCreateCredential(
		mutation.ClientID, parsedCredential, parsedKey, parsedDeployment, mutation.RequestHash, replayCredential,
	)
	if err != nil {
		return worker.Deployment{}, nil, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return worker.Deployment{}, nil, fmt.Errorf("begin worker create: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	result, err := tx.Exec(ctx, `
		INSERT INTO worker_deployment_create_replays (
			caller_client_id, caller_credential_id, idempotency_key, deployment_id, request_hash,
			nonce, enrollment_ciphertext, response_revision, response_schema_version, response_json
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (caller_client_id, caller_credential_id, idempotency_key) DO NOTHING`,
		mutation.ClientID, parsedCredential, parsedKey, parsedDeployment, mutation.RequestHash[:], nonce, ciphertext,
		deployment.Revision, workerSnapshotSchemaV1, responseJSON,
	)
	if err != nil {
		return worker.Deployment{}, nil, fmt.Errorf("claim worker create replay: %w", err)
	}
	if result.RowsAffected() == 0 {
		var storedDeployment uuid.UUID
		var storedHash, storedNonce, storedCiphertext, storedResponse []byte
		var storedRevision int64
		var storedSchema int
		err = tx.QueryRow(ctx, `
			SELECT deployment_id, request_hash, nonce, enrollment_ciphertext,
			       response_revision, response_schema_version, response_json
			FROM worker_deployment_create_replays
			WHERE caller_client_id=$1 AND caller_credential_id=$2 AND idempotency_key=$3
			FOR SHARE`, mutation.ClientID, parsedCredential, parsedKey).Scan(
			&storedDeployment, &storedHash, &storedNonce, &storedCiphertext, &storedRevision, &storedSchema, &storedResponse,
		)
		if err != nil {
			return worker.Deployment{}, nil, fmt.Errorf("load worker create replay: %w", err)
		}
		if storedDeployment != parsedDeployment || subtle.ConstantTimeCompare(storedHash, mutation.RequestHash[:]) != 1 {
			return worker.Deployment{}, nil, worker.ErrIdempotencyConflict
		}
		stored, decodeErr := decodeWorkerSnapshot(storedSchema, storedResponse)
		if decodeErr != nil || stored.Revision != storedRevision || stored.DeploymentID != storedDeployment.String() {
			return worker.Deployment{}, nil, worker.ErrInvalid
		}
		credential, openErr := store.openCreateCredential(
			mutation.ClientID, parsedCredential, parsedKey, storedDeployment, mutation.RequestHash, storedNonce, storedCiphertext,
		)
		if openErr != nil {
			return worker.Deployment{}, nil, openErr
		}
		if err := tx.Commit(ctx); err != nil {
			wipeBytes(credential)
			return worker.Deployment{}, nil, fmt.Errorf("commit worker create replay: %w", err)
		}
		return stored, credential, nil
	}

	if err := store.insertWorkerDeployment(ctx, tx, deployment); err != nil {
		return worker.Deployment{}, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return worker.Deployment{}, nil, fmt.Errorf("commit worker create: %w", err)
	}
	return cloneWorkerDeployment(deployment), bytes.Clone(replayCredential), nil
}

func (store *WorkerStore) insertWorkerDeployment(ctx context.Context, query interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, deployment worker.Deployment) error {
	evidence, err := encodeWorkerEvidence(deployment.Evidence)
	if err != nil {
		return worker.ErrInvalid
	}
	_, err = query.Exec(ctx, `
		INSERT INTO worker_deployments (
			deployment_id, agent_instance_id, owner_id, task_id, step_id, control_plane_endpoint,
			recipe_bundle_ref, recipe_bundle_sha256, execution_bundle_ref, execution_bundle_sha256, execution_timeout_seconds,
			installer_delivery_json, installer_command_ids,
			worker_id, provider_instance_id, state, outcome, artifact_prefix, checkpoint_prefix, evidence_prefix, log_prefix,
			secret_refs, enrollment_digest, enrollment_expires_at, enrollment_consumed_at, session_digest,
			lease_attempt, lease_epoch, lease_expires_at, last_heartbeat_at, checkpoint_ref, result_ref,
			evidence_json, cancel_reason, revision, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37)`,
		deployment.DeploymentID, store.instanceID, deployment.OwnerID, deployment.TaskID, deployment.StepID,
		deployment.ControlPlaneEndpoint, deployment.RecipeBundle.S3Ref, deployment.RecipeBundle.SHA256[:],
		deployment.ExecutionBundle.S3Ref, deployment.ExecutionBundle.SHA256[:], int64(deployment.ExecutionTimeout/time.Second),
		installerDeliveryJSON(deployment.InstallerDelivery), nonNilWorkerCommandIDs(deployment.InstallerCommandIDs),
		nullableUUID(deployment.WorkerID), nullableString(deployment.ProviderInstanceID), deployment.State, deployment.Outcome,
		deployment.Access.ArtifactPrefix, deployment.Access.CheckpointPrefix, deployment.Access.EvidencePrefix,
		deployment.Access.LogPrefix, nonNilWorkerSecretRefs(deployment.Access.SecretRefs), deployment.Enrollment.CredentialDigest[:],
		deployment.Enrollment.ExpiresAt.UTC(), nullableTime(deployment.Enrollment.ConsumedAt), nullableDigest(deployment.SessionDigest),
		deployment.Lease.Attempt, deployment.Lease.Epoch, nullableTime(deployment.Lease.ExpiresAt),
		nullableTime(deployment.Lease.LastHeartbeatAt), deployment.Lease.CheckpointRef, deployment.ResultRef,
		evidence, deployment.CancelReason, deployment.Revision, deployment.CreatedAt.UTC(), deployment.UpdatedAt.UTC(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return worker.ErrAlreadyExists
		}
		return fmt.Errorf("create worker deployment: %w", err)
	}
	return nil
}

func (store *WorkerStore) Get(ctx context.Context, deploymentID string) (worker.Deployment, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(deploymentID))
	if err != nil || parsed == uuid.Nil {
		return worker.Deployment{}, worker.ErrInvalid
	}
	deployment, err := scanWorkerDeployment(store.pool.QueryRow(ctx, workerSelectSQL+` WHERE deployment_id=$1 AND agent_instance_id=$2`, parsed, store.instanceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return worker.Deployment{}, worker.ErrNotFound
	}
	if err != nil {
		return worker.Deployment{}, fmt.Errorf("get worker deployment: %w", err)
	}
	return deployment, nil
}

func (store *WorkerStore) EnrollIdempotent(
	ctx context.Context,
	deploymentID string,
	mutation worker.Mutation,
	replayCredential []byte,
	update func(*worker.Deployment) error,
) (worker.Deployment, []byte, error) {
	parsedDeployment, parsedCaller, parsedKey, err := validateWorkerMutation(deploymentID, mutation, "enroll")
	if err != nil || len(replayCredential) < 32 || len(replayCredential) > 128 || update == nil {
		return worker.Deployment{}, nil, worker.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return worker.Deployment{}, nil, fmt.Errorf("begin worker enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var storedHash, nonce, ciphertext, responseJSON []byte
	var responseSchema int
	err = tx.QueryRow(ctx, `
		SELECT request_hash, nonce, session_ciphertext, response_schema_version, response_json
		FROM worker_enrollment_replays
		WHERE deployment_id=$1 AND caller_worker_id=$2 AND idempotency_key=$3
		FOR UPDATE`, parsedDeployment, parsedCaller, parsedKey).Scan(&storedHash, &nonce, &ciphertext, &responseSchema, &responseJSON)
	if err == nil {
		if subtle.ConstantTimeCompare(storedHash, mutation.RequestHash[:]) != 1 {
			return worker.Deployment{}, nil, worker.ErrIdempotencyConflict
		}
		deployment, decodeErr := decodeWorkerSnapshot(responseSchema, responseJSON)
		if decodeErr != nil {
			return worker.Deployment{}, nil, decodeErr
		}
		credential, openErr := store.openEnrollmentCredential(parsedDeployment, parsedCaller, parsedKey, mutation.RequestHash, nonce, ciphertext)
		if openErr != nil {
			return worker.Deployment{}, nil, openErr
		}
		if err := tx.Commit(ctx); err != nil {
			wipeBytes(credential)
			return worker.Deployment{}, nil, fmt.Errorf("commit worker enrollment replay: %w", err)
		}
		return deployment, credential, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return worker.Deployment{}, nil, fmt.Errorf("read worker enrollment replay: %w", err)
	}

	current, err := loadWorkerForUpdate(ctx, tx, parsedDeployment, store.instanceID)
	if err != nil {
		return worker.Deployment{}, nil, err
	}
	if current.Revision != mutation.ExpectedRevision {
		return worker.Deployment{}, nil, worker.ErrRevisionConflict
	}
	next := cloneWorkerDeployment(current)
	if err := update(&next); err != nil {
		return worker.Deployment{}, nil, err
	}
	if err := validateWorkerTransition(current, next); err != nil {
		return worker.Deployment{}, nil, err
	}
	if err := saveWorkerDeployment(ctx, tx, store.instanceID, current.Revision, next); err != nil {
		return worker.Deployment{}, nil, err
	}
	responseJSON, err = encodeWorkerSnapshot(next)
	if err != nil {
		return worker.Deployment{}, nil, err
	}
	nonce, ciphertext, err = store.sealEnrollmentCredential(parsedDeployment, parsedCaller, parsedKey, mutation.RequestHash, replayCredential)
	if err != nil {
		return worker.Deployment{}, nil, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO worker_enrollment_replays (
			deployment_id, caller_worker_id, idempotency_key, expected_revision, request_hash, nonce, session_ciphertext,
			response_revision, response_schema_version, response_json
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		parsedDeployment, parsedCaller, parsedKey, mutation.ExpectedRevision, mutation.RequestHash[:], nonce, ciphertext,
		next.Revision, workerSnapshotSchemaV1, responseJSON,
	); err != nil {
		return worker.Deployment{}, nil, fmt.Errorf("persist worker enrollment replay: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return worker.Deployment{}, nil, fmt.Errorf("commit worker enrollment: %w", err)
	}
	return next, bytes.Clone(replayCredential), nil
}

func (store *WorkerStore) UpdateIdempotent(
	ctx context.Context,
	deploymentID string,
	mutation worker.Mutation,
	update func(*worker.Deployment) error,
) (worker.Deployment, error) {
	parsedDeployment, parsedCaller, parsedKey, err := validateWorkerMutation(deploymentID, mutation, "")
	if err != nil || update == nil || mutation.Operation == "enroll" {
		return worker.Deployment{}, worker.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return worker.Deployment{}, fmt.Errorf("begin worker mutation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var storedHash, responseJSON []byte
	var responseSchema int
	err = tx.QueryRow(ctx, `
		SELECT request_hash, response_schema_version, response_json
		FROM worker_mutation_replays
		WHERE deployment_id=$1 AND caller_worker_id=$2 AND operation=$3 AND idempotency_key=$4
		FOR UPDATE`, parsedDeployment, parsedCaller, mutation.Operation, parsedKey).Scan(&storedHash, &responseSchema, &responseJSON)
	if err == nil {
		if subtle.ConstantTimeCompare(storedHash, mutation.RequestHash[:]) != 1 {
			return worker.Deployment{}, worker.ErrIdempotencyConflict
		}
		deployment, decodeErr := decodeWorkerSnapshot(responseSchema, responseJSON)
		if decodeErr != nil {
			return worker.Deployment{}, decodeErr
		}
		if err := tx.Commit(ctx); err != nil {
			return worker.Deployment{}, fmt.Errorf("commit worker mutation replay: %w", err)
		}
		return deployment, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return worker.Deployment{}, fmt.Errorf("read worker mutation replay: %w", err)
	}
	current, err := loadWorkerForUpdate(ctx, tx, parsedDeployment, store.instanceID)
	if err != nil {
		return worker.Deployment{}, err
	}
	if current.Revision != mutation.ExpectedRevision {
		return worker.Deployment{}, worker.ErrRevisionConflict
	}
	next := cloneWorkerDeployment(current)
	if err := update(&next); err != nil {
		return worker.Deployment{}, err
	}
	if err := validateWorkerTransition(current, next); err != nil {
		return worker.Deployment{}, err
	}
	if err := saveWorkerDeployment(ctx, tx, store.instanceID, current.Revision, next); err != nil {
		return worker.Deployment{}, err
	}
	responseJSON, err = encodeWorkerSnapshot(next)
	if err != nil {
		return worker.Deployment{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO worker_mutation_replays (
			deployment_id, caller_worker_id, operation, idempotency_key, expected_revision, request_hash,
			response_schema_version, response_json
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		parsedDeployment, parsedCaller, mutation.Operation, parsedKey, mutation.ExpectedRevision, mutation.RequestHash[:],
		workerSnapshotSchemaV1, responseJSON,
	); err != nil {
		return worker.Deployment{}, fmt.Errorf("persist worker mutation replay: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return worker.Deployment{}, fmt.Errorf("commit worker mutation: %w", err)
	}
	return next, nil
}

func (store *WorkerStore) UpdateControl(ctx context.Context, deploymentID string, update func(*worker.Deployment) error) (worker.Deployment, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(deploymentID))
	if err != nil || parsed == uuid.Nil || update == nil {
		return worker.Deployment{}, worker.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return worker.Deployment{}, fmt.Errorf("begin worker control mutation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := loadWorkerForUpdate(ctx, tx, parsed, store.instanceID)
	if err != nil {
		return worker.Deployment{}, err
	}
	next := cloneWorkerDeployment(current)
	if err := update(&next); err != nil {
		return worker.Deployment{}, err
	}
	if err := validateWorkerTransition(current, next); err != nil {
		return worker.Deployment{}, err
	}
	if err := saveWorkerDeployment(ctx, tx, store.instanceID, current.Revision, next); err != nil {
		return worker.Deployment{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return worker.Deployment{}, fmt.Errorf("commit worker control mutation: %w", err)
	}
	return next, nil
}

const workerSelectSQL = `
	SELECT deployment_id, owner_id, task_id, step_id, control_plane_endpoint, worker_id, provider_instance_id,
	       recipe_bundle_ref, recipe_bundle_sha256, execution_bundle_ref, execution_bundle_sha256, execution_timeout_seconds,
	       installer_delivery_json, installer_command_ids,
	       state, outcome, artifact_prefix, checkpoint_prefix, evidence_prefix, log_prefix,
	       secret_refs, enrollment_digest, enrollment_expires_at, enrollment_consumed_at,
	       session_digest, lease_attempt, lease_epoch, lease_expires_at, last_heartbeat_at,
	       checkpoint_ref, result_ref, evidence_json, cancel_reason, revision, created_at, updated_at
	FROM worker_deployments`

type workerRow interface{ Scan(...any) error }

func scanWorkerDeployment(row workerRow) (worker.Deployment, error) {
	var deployment worker.Deployment
	var deploymentID, taskID, stepID uuid.UUID
	var workerID *uuid.UUID
	var providerInstanceID *string
	var enrollmentDigest, sessionDigest, evidenceJSON, recipeDigest, executionDigest, installerDeliveryJSON []byte
	var executionTimeoutSeconds int64
	var consumedAt, leaseExpiresAt, heartbeatAt *time.Time
	if err := row.Scan(
		&deploymentID, &deployment.OwnerID, &taskID, &stepID, &deployment.ControlPlaneEndpoint, &workerID, &providerInstanceID,
		&deployment.RecipeBundle.S3Ref, &recipeDigest, &deployment.ExecutionBundle.S3Ref, &executionDigest, &executionTimeoutSeconds,
		&installerDeliveryJSON, &deployment.InstallerCommandIDs,
		&deployment.State, &deployment.Outcome, &deployment.Access.ArtifactPrefix, &deployment.Access.CheckpointPrefix,
		&deployment.Access.EvidencePrefix, &deployment.Access.LogPrefix, &deployment.Access.SecretRefs,
		&enrollmentDigest, &deployment.Enrollment.ExpiresAt, &consumedAt, &sessionDigest,
		&deployment.Lease.Attempt, &deployment.Lease.Epoch, &leaseExpiresAt, &heartbeatAt,
		&deployment.Lease.CheckpointRef, &deployment.ResultRef, &evidenceJSON, &deployment.CancelReason,
		&deployment.Revision, &deployment.CreatedAt, &deployment.UpdatedAt,
	); err != nil {
		return worker.Deployment{}, err
	}
	if len(enrollmentDigest) != sha256.Size || (len(sessionDigest) != 0 && len(sessionDigest) != sha256.Size) || len(recipeDigest) != sha256.Size || len(executionDigest) != sha256.Size {
		return worker.Deployment{}, errors.New("worker persisted digest has invalid length")
	}
	copy(deployment.RecipeBundle.SHA256[:], recipeDigest)
	copy(deployment.ExecutionBundle.SHA256[:], executionDigest)
	if len(installerDeliveryJSON) != 0 {
		var delivery installer.DeliveryV1
		if json.Unmarshal(installerDeliveryJSON, &delivery) != nil {
			return worker.Deployment{}, errors.New("worker persisted installer delivery is invalid")
		}
		deployment.InstallerDelivery = &delivery
	}
	deployment.ExecutionTimeout = time.Duration(executionTimeoutSeconds) * time.Second
	copy(deployment.Enrollment.CredentialDigest[:], enrollmentDigest)
	copy(deployment.SessionDigest[:], sessionDigest)
	deployment.DeploymentID, deployment.TaskID, deployment.StepID = deploymentID.String(), taskID.String(), stepID.String()
	if workerID != nil {
		deployment.WorkerID = workerID.String()
	}
	if providerInstanceID != nil {
		deployment.ProviderInstanceID = *providerInstanceID
	}
	if consumedAt != nil {
		deployment.Enrollment.ConsumedAt = consumedAt.UTC()
	}
	if leaseExpiresAt != nil {
		deployment.Lease.ExpiresAt = leaseExpiresAt.UTC()
	}
	if heartbeatAt != nil {
		deployment.Lease.LastHeartbeatAt = heartbeatAt.UTC()
	}
	if err := json.Unmarshal(evidenceJSON, &deployment.Evidence); err != nil {
		return worker.Deployment{}, fmt.Errorf("decode worker evidence: %w", err)
	}
	deployment.Enrollment.ExpiresAt = deployment.Enrollment.ExpiresAt.UTC()
	deployment.CreatedAt = deployment.CreatedAt.UTC()
	deployment.UpdatedAt = deployment.UpdatedAt.UTC()
	return deployment, nil
}

func loadWorkerForUpdate(ctx context.Context, tx pgx.Tx, deploymentID, instanceID uuid.UUID) (worker.Deployment, error) {
	deployment, err := scanWorkerDeployment(tx.QueryRow(ctx, workerSelectSQL+` WHERE deployment_id=$1 AND agent_instance_id=$2 FOR UPDATE`, deploymentID, instanceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return worker.Deployment{}, worker.ErrNotFound
	}
	if err != nil {
		return worker.Deployment{}, fmt.Errorf("lock worker deployment: %w", err)
	}
	return deployment, nil
}

func saveWorkerDeployment(ctx context.Context, tx pgx.Tx, instanceID uuid.UUID, expectedRevision int64, deployment worker.Deployment) error {
	if err := validateWorkerDeployment(deployment); err != nil || deployment.Revision != expectedRevision+1 {
		return worker.ErrRevisionConflict
	}
	evidence, err := encodeWorkerEvidence(deployment.Evidence)
	if err != nil {
		return worker.ErrInvalid
	}
	result, err := tx.Exec(ctx, `
		UPDATE worker_deployments SET
			worker_id=$4, provider_instance_id=$5,
			recipe_bundle_ref=$6, recipe_bundle_sha256=$7, execution_bundle_ref=$8, execution_bundle_sha256=$9,
			artifact_prefix=$10, checkpoint_prefix=$11, evidence_prefix=$12, log_prefix=$13, secret_refs=$14,
			state=$15, outcome=$16, enrollment_consumed_at=$17, session_digest=$18,
			lease_attempt=$19, lease_epoch=$20, lease_expires_at=$21, last_heartbeat_at=$22,
			checkpoint_ref=$23, result_ref=$24, evidence_json=$25, cancel_reason=$26,
			revision=$27, updated_at=$28
		WHERE deployment_id=$1 AND agent_instance_id=$2 AND revision=$3`,
		deployment.DeploymentID, instanceID, expectedRevision, nullableUUID(deployment.WorkerID), nullableString(deployment.ProviderInstanceID),
		deployment.RecipeBundle.S3Ref, deployment.RecipeBundle.SHA256[:], deployment.ExecutionBundle.S3Ref, deployment.ExecutionBundle.SHA256[:],
		deployment.Access.ArtifactPrefix, deployment.Access.CheckpointPrefix, deployment.Access.EvidencePrefix, deployment.Access.LogPrefix, nonNilWorkerSecretRefs(deployment.Access.SecretRefs),
		deployment.State, deployment.Outcome, nullableTime(deployment.Enrollment.ConsumedAt), nullableDigest(deployment.SessionDigest),
		deployment.Lease.Attempt, deployment.Lease.Epoch, nullableTime(deployment.Lease.ExpiresAt),
		nullableTime(deployment.Lease.LastHeartbeatAt), deployment.Lease.CheckpointRef, deployment.ResultRef,
		evidence, deployment.CancelReason, deployment.Revision, deployment.UpdatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("save worker deployment: %w", err)
	}
	if result.RowsAffected() != 1 {
		return worker.ErrRevisionConflict
	}
	return nil
}

func validateWorkerTransition(current, next worker.Deployment) error {
	if current.DeploymentID != next.DeploymentID || current.OwnerID != next.OwnerID || current.TaskID != next.TaskID || current.StepID != next.StepID ||
		current.ControlPlaneEndpoint != next.ControlPlaneEndpoint || current.RecipeBundle != next.RecipeBundle || current.ExecutionBundle != next.ExecutionBundle ||
		current.ProviderInstanceID != next.ProviderInstanceID ||
		!reflect.DeepEqual(current.InstallerDelivery, next.InstallerDelivery) || !slices.Equal(current.InstallerCommandIDs, next.InstallerCommandIDs) ||
		current.ExecutionTimeout != next.ExecutionTimeout || current.Access.ArtifactPrefix != next.Access.ArtifactPrefix ||
		current.Access.CheckpointPrefix != next.Access.CheckpointPrefix || current.Access.EvidencePrefix != next.Access.EvidencePrefix ||
		current.Access.LogPrefix != next.Access.LogPrefix || !slices.Equal(current.Access.SecretRefs, next.Access.SecretRefs) ||
		current.Enrollment.CredentialDigest != next.Enrollment.CredentialDigest || !current.Enrollment.ExpiresAt.Equal(next.Enrollment.ExpiresAt) ||
		!current.CreatedAt.Equal(next.CreatedAt) || next.Revision != current.Revision+1 {
		return worker.ErrRevisionConflict
	}
	if (current.WorkerID != "" && current.WorkerID != next.WorkerID) ||
		(!current.Enrollment.ConsumedAt.IsZero() && !current.Enrollment.ConsumedAt.Equal(next.Enrollment.ConsumedAt)) ||
		(!zeroDigest(current.SessionDigest) && current.SessionDigest != next.SessionDigest) ||
		next.Lease.Epoch < current.Lease.Epoch || next.Lease.Attempt < current.Lease.Attempt {
		return worker.ErrRevisionConflict
	}
	return validateWorkerDeployment(next)
}

func validateWorkerDeployment(deployment worker.Deployment) error {
	for _, value := range []string{deployment.DeploymentID, deployment.TaskID, deployment.StepID} {
		parsed, err := uuid.Parse(value)
		if err != nil || parsed == uuid.Nil {
			return worker.ErrInvalid
		}
	}
	if deployment.WorkerID != "" {
		parsed, err := uuid.Parse(deployment.WorkerID)
		if err != nil || parsed == uuid.Nil {
			return worker.ErrInvalid
		}
	}
	if deployment.ProviderInstanceID != "" && !validWorkerProviderInstanceID(deployment.ProviderInstanceID) {
		return worker.ErrInvalid
	}
	endpoint, err := url.Parse(deployment.ControlPlaneEndpoint)
	if err != nil || endpoint.Scheme != "grpcs" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || security.ContainsLikelySecret(deployment.ControlPlaneEndpoint) {
		return worker.ErrInvalid
	}
	if deployment.OwnerID == "" || len(deployment.OwnerID) > 255 || security.ContainsLikelySecret(deployment.OwnerID) || deployment.Access.Validate() != nil ||
		deployment.RecipeBundle.Validate() != nil || deployment.ExecutionBundle.Validate() != nil || deployment.ExecutionTimeout < time.Second ||
		deployment.ExecutionTimeout > 7*24*time.Hour || deployment.ExecutionTimeout%time.Second != 0 ||
		deployment.Revision < 1 || deployment.CreatedAt.IsZero() || deployment.UpdatedAt.IsZero() || deployment.Enrollment.ExpiresAt.IsZero() {
		return worker.ErrInvalid
	}
	if worker.ValidateInstallerCapability(deployment.DeploymentID, deployment.TaskID, deployment.RecipeBundle, deployment.InstallerDelivery, deployment.InstallerCommandIDs) != nil {
		return worker.ErrInvalid
	}
	if len(deployment.Evidence) > 2048 || security.ContainsLikelySecret(deployment.CancelReason) || security.ContainsLikelySecret(deployment.ResultRef) || security.ContainsLikelySecret(deployment.Lease.CheckpointRef) {
		return worker.ErrInvalid
	}
	for _, evidence := range deployment.Evidence {
		if evidence.Trust != worker.TrustWorkerClaim || security.ContainsLikelySecret(evidence.Ref) {
			return worker.ErrInvalid
		}
		typed := evidence.ObjectSHA256 != "" || evidence.SizeBytes != 0 || evidence.MediaType != ""
		if typed {
			if len(evidence.ObjectSHA256) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(evidence.ObjectSHA256, "sha256:") {
				return worker.ErrInvalid
			}
			rawDigest, err := hex.DecodeString(strings.TrimPrefix(evidence.ObjectSHA256, "sha256:"))
			if err != nil || len(rawDigest) != sha256.Size {
				return worker.ErrInvalid
			}
			var digest [sha256.Size]byte
			copy(digest[:], rawDigest)
			if (worker.ObjectClaim{Ref: evidence.Ref, SHA256: digest, SizeBytes: evidence.SizeBytes, MediaType: evidence.MediaType}).Validate() != nil {
				return worker.ErrInvalid
			}
		}
	}
	if deployment.Enrollment.ExpiresAt.Before(deployment.CreatedAt) || deployment.UpdatedAt.Before(deployment.CreatedAt) {
		return worker.ErrInvalid
	}
	switch deployment.State {
	case worker.StatePendingEnrollment:
		if deployment.Outcome != worker.OutcomePending || deployment.WorkerID != "" || !deployment.Enrollment.ConsumedAt.IsZero() || !zeroDigest(deployment.SessionDigest) || deployment.Lease.Attempt != 0 || deployment.Lease.Epoch != 0 || !deployment.Lease.ExpiresAt.IsZero() {
			return worker.ErrInvalid
		}
	case worker.StateReady:
		if deployment.Outcome != worker.OutcomePending || deployment.WorkerID == "" || deployment.Enrollment.ConsumedAt.IsZero() || zeroDigest(deployment.SessionDigest) || !deployment.Lease.ExpiresAt.IsZero() {
			return worker.ErrInvalid
		}
	case worker.StateLeased, worker.StateCancelRequested:
		if deployment.Outcome != worker.OutcomePending || deployment.WorkerID == "" || deployment.Enrollment.ConsumedAt.IsZero() || zeroDigest(deployment.SessionDigest) || deployment.Lease.Attempt < 1 || deployment.Lease.Epoch < 1 || deployment.Lease.ExpiresAt.IsZero() || deployment.Lease.LastHeartbeatAt.IsZero() {
			return worker.ErrInvalid
		}
	case worker.StateFinished:
		if deployment.Outcome == worker.OutcomePending || !deployment.Lease.ExpiresAt.IsZero() {
			return worker.ErrInvalid
		}
		unenrolledCancel := deployment.Outcome == worker.OutcomeCanceled && deployment.WorkerID == "" && deployment.Enrollment.ConsumedAt.IsZero() && zeroDigest(deployment.SessionDigest)
		enrolled := deployment.WorkerID != "" && !deployment.Enrollment.ConsumedAt.IsZero() && !zeroDigest(deployment.SessionDigest)
		if !unenrolledCancel && !enrolled {
			return worker.ErrInvalid
		}
	default:
		return worker.ErrInvalid
	}
	return nil
}

type workerSnapshotV1 struct {
	SchemaVersion int               `json:"schema_version"`
	Deployment    worker.Deployment `json:"deployment"`
}

func encodeWorkerSnapshot(deployment worker.Deployment) ([]byte, error) {
	encoded, err := json.Marshal(workerSnapshotV1{SchemaVersion: workerSnapshotSchemaV1, Deployment: deployment})
	if err != nil {
		return nil, fmt.Errorf("encode worker idempotency snapshot: %w", err)
	}
	return encoded, nil
}

func decodeWorkerSnapshot(schemaVersion int, encoded []byte) (worker.Deployment, error) {
	var snapshot workerSnapshotV1
	if schemaVersion != workerSnapshotSchemaV1 || json.Unmarshal(encoded, &snapshot) != nil || snapshot.SchemaVersion != workerSnapshotSchemaV1 {
		return worker.Deployment{}, errors.New("worker idempotency snapshot is invalid")
	}
	if err := validateWorkerDeployment(snapshot.Deployment); err != nil {
		return worker.Deployment{}, errors.New("worker idempotency snapshot failed validation")
	}
	return snapshot.Deployment, nil
}

func validateWorkerMutation(deploymentID string, mutation worker.Mutation, expectedOperation string) (uuid.UUID, uuid.UUID, uuid.UUID, error) {
	deployment, err := uuid.Parse(strings.TrimSpace(deploymentID))
	if err != nil || deployment == uuid.Nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, worker.ErrInvalid
	}
	caller, err := uuid.Parse(strings.TrimSpace(mutation.CallerWorkerID))
	if err != nil || caller == uuid.Nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, worker.ErrInvalid
	}
	key, err := uuid.Parse(strings.TrimSpace(mutation.IdempotencyKey))
	if err != nil || key == uuid.Nil || mutation.ExpectedRevision < 1 || mutation.Operation == "" || len(mutation.Operation) > 64 ||
		(expectedOperation != "" && mutation.Operation != expectedOperation) {
		return uuid.Nil, uuid.Nil, uuid.Nil, worker.ErrInvalid
	}
	var empty [sha256.Size]byte
	if subtle.ConstantTimeCompare(mutation.RequestHash[:], empty[:]) == 1 {
		return uuid.Nil, uuid.Nil, uuid.Nil, worker.ErrInvalid
	}
	return deployment, caller, key, nil
}

func validateWorkerControlMutation(mutation worker.ControlMutationRecord) (uuid.UUID, uuid.UUID, error) {
	clientID := strings.TrimSpace(mutation.ClientID)
	if clientID == "" || clientID != mutation.ClientID || len(clientID) > 255 || strings.ContainsAny(clientID, "\x00\r\n") || security.ContainsLikelySecret(clientID) {
		return uuid.Nil, uuid.Nil, worker.ErrInvalid
	}
	credentialID, err := uuid.Parse(strings.TrimSpace(mutation.CredentialID))
	if err != nil || credentialID == uuid.Nil || credentialID.String() != mutation.CredentialID {
		return uuid.Nil, uuid.Nil, worker.ErrInvalid
	}
	key, err := uuid.Parse(strings.TrimSpace(mutation.IdempotencyKey))
	if err != nil || key == uuid.Nil || key.String() != mutation.IdempotencyKey {
		return uuid.Nil, uuid.Nil, worker.ErrInvalid
	}
	var empty [sha256.Size]byte
	if subtle.ConstantTimeCompare(mutation.RequestHash[:], empty[:]) == 1 {
		return uuid.Nil, uuid.Nil, worker.ErrInvalid
	}
	return credentialID, key, nil
}

func (store *WorkerStore) sealCreateCredential(
	clientID string,
	credentialID, key, deploymentID uuid.UUID,
	requestHash [sha256.Size]byte,
	plaintext []byte,
) ([]byte, []byte, error) {
	aead, err := store.replayAEAD()
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(store.random, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate worker create replay nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, workerCreateReplayAAD(clientID, credentialID, key, deploymentID, requestHash))
	return nonce, ciphertext, nil
}

func (store *WorkerStore) openCreateCredential(
	clientID string,
	credentialID, key, deploymentID uuid.UUID,
	requestHash [sha256.Size]byte,
	nonce, ciphertext []byte,
) ([]byte, error) {
	aead, err := store.replayAEAD()
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil, worker.ErrInvalidCredential
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, workerCreateReplayAAD(clientID, credentialID, key, deploymentID, requestHash))
	if err != nil || len(plaintext) < 32 || len(plaintext) > 128 {
		wipeBytes(plaintext)
		return nil, worker.ErrInvalidCredential
	}
	return plaintext, nil
}

func workerCreateReplayAAD(
	clientID string,
	credentialID, key, deploymentID uuid.UUID,
	requestHash [sha256.Size]byte,
) []byte {
	aad := make([]byte, 0, len(workerCreateAADDomain)+len(clientID)+16*3+sha256.Size+5)
	aad = append(aad, workerCreateAADDomain...)
	aad = append(aad, 0)
	aad = append(aad, clientID...)
	aad = append(aad, 0)
	aad = append(aad, credentialID[:]...)
	aad = append(aad, 0)
	aad = append(aad, key[:]...)
	aad = append(aad, 0)
	aad = append(aad, deploymentID[:]...)
	aad = append(aad, 0)
	aad = append(aad, requestHash[:]...)
	return aad
}

func (store *WorkerStore) sealEnrollmentCredential(deploymentID, workerID, key uuid.UUID, requestHash [sha256.Size]byte, plaintext []byte) ([]byte, []byte, error) {
	aead, err := store.replayAEAD()
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(store.random, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate worker replay nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, workerReplayAAD(deploymentID, workerID, key, requestHash))
	return nonce, ciphertext, nil
}

func (store *WorkerStore) openEnrollmentCredential(deploymentID, workerID, key uuid.UUID, requestHash [sha256.Size]byte, nonce, ciphertext []byte) ([]byte, error) {
	aead, err := store.replayAEAD()
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil, worker.ErrInvalidCredential
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, workerReplayAAD(deploymentID, workerID, key, requestHash))
	if err != nil || len(plaintext) < 32 || len(plaintext) > 128 {
		wipeBytes(plaintext)
		return nil, worker.ErrInvalidCredential
	}
	return plaintext, nil
}

func (store *WorkerStore) replayAEAD() (cipher.AEAD, error) {
	block, err := aes.NewCipher(store.replayKey[:])
	if err != nil {
		return nil, fmt.Errorf("initialize worker replay cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

func workerReplayAAD(deploymentID, workerID, key uuid.UUID, requestHash [sha256.Size]byte) []byte {
	aad := make([]byte, 0, len(workerReplayAADDomain)+16*3+sha256.Size+4)
	aad = append(aad, workerReplayAADDomain...)
	aad = append(aad, 0)
	aad = append(aad, deploymentID[:]...)
	aad = append(aad, 0)
	aad = append(aad, workerID[:]...)
	aad = append(aad, 0)
	aad = append(aad, key[:]...)
	aad = append(aad, 0)
	aad = append(aad, requestHash[:]...)
	return aad
}

func nullableUUID(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parsed, err := uuid.Parse(value)
	if err != nil {
		return nil
	}
	return parsed
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func nullableDigest(value [sha256.Size]byte) any {
	if zeroDigest(value) {
		return nil
	}
	return value[:]
}

func nullableString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func validWorkerProviderInstanceID(value string) bool {
	if len(value) < 10 || len(value) > 19 || !strings.HasPrefix(value, "i-") {
		return false
	}
	for _, character := range value[2:] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func zeroDigest(value [sha256.Size]byte) bool {
	var empty [sha256.Size]byte
	return subtle.ConstantTimeCompare(value[:], empty[:]) == 1
}

func isUniqueViolation(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "23505"
}

func cloneWorkerDeployment(deployment worker.Deployment) worker.Deployment {
	deployment.Access.SecretRefs = slices.Clone(deployment.Access.SecretRefs)
	deployment.Evidence = slices.Clone(deployment.Evidence)
	return deployment
}

func encodeWorkerEvidence(evidence []worker.EvidenceRef) ([]byte, error) {
	if evidence == nil {
		evidence = []worker.EvidenceRef{}
	}
	return json.Marshal(evidence)
}

func nonNilWorkerSecretRefs(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nonNilWorkerCommandIDs(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func installerDeliveryJSON(value *installer.DeliveryV1) any {
	if value == nil {
		return nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return encoded
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
