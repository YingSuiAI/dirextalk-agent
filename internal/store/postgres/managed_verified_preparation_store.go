package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/managed"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var verifiedPreparationRequestDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func (store *Store) CreateVerifiedPreparation(ctx context.Context, mutation managed.Mutation, value managed.VerifiedPreparationV1) (managed.VerifiedPreparationV1, error) {
	if store == nil || store.pool == nil || ctx == nil || validateVerifiedPreparationMutation(mutation) != nil ||
		value.Validate() != nil || value.AgentInstanceID != store.instanceID.String() {
		return managed.VerifiedPreparationV1{}, managed.ErrInvalid
	}
	snapshotJSON, err := json.Marshal(value.Snapshot)
	if err != nil {
		return managed.VerifiedPreparationV1{}, managed.ErrInvalid
	}
	attestationsJSON, err := json.Marshal(value.Attestations)
	if err != nil {
		return managed.VerifiedPreparationV1{}, managed.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return managed.VerifiedPreparationV1{}, fmt.Errorf("begin verified preparation create: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO cloud_managed_verified_preparations
		(preparation_id,agent_instance_id,owner_id,deployment_id,expected_deployment_revision,snapshot_digest,
		 snapshot_json,attestations_json,create_client_id,create_credential_id,create_idempotency_key,create_request_hash,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT DO NOTHING`,
		value.PreparationID, store.instanceID, value.OwnerID, value.DeploymentID, value.ExpectedDeploymentRevision,
		value.SnapshotDigest, snapshotJSON, attestationsJSON, mutation.ClientID, mutation.CredentialID,
		mutation.IdempotencyKey, mutation.RequestHash, value.CreatedAt.UTC()); err != nil {
		return managed.VerifiedPreparationV1{}, fmt.Errorf("persist verified preparation: %w", err)
	}
	stored, meta, err := readVerifiedPreparation(ctx, tx, store.instanceID,
		`create_client_id=$2 AND create_credential_id=$3 AND create_idempotency_key=$4`,
		mutation.ClientID, mutation.CredentialID, mutation.IdempotencyKey)
	if errors.Is(err, managed.ErrNotFound) {
		stored, meta, err = readVerifiedPreparation(ctx, tx, store.instanceID,
			`deployment_id=$2 AND expected_deployment_revision=$3`, value.DeploymentID, value.ExpectedDeploymentRevision)
	}
	if errors.Is(err, managed.ErrNotFound) {
		return managed.VerifiedPreparationV1{}, managed.ErrRevisionConflict
	}
	if err != nil {
		return managed.VerifiedPreparationV1{}, err
	}
	if !sameVerifiedPreparation(stored, value, meta, mutation) {
		return managed.VerifiedPreparationV1{}, managed.ErrRevisionConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return managed.VerifiedPreparationV1{}, fmt.Errorf("commit verified preparation: %w", err)
	}
	return stored, nil
}

func (store *Store) GetVerifiedPreparation(ctx context.Context, ownerID, preparationID string) (managed.VerifiedPreparationV1, error) {
	if store == nil || store.pool == nil || ctx == nil || !validVerifiedPreparationOwner(ownerID) ||
		!validVerifiedPreparationUUID(preparationID) {
		return managed.VerifiedPreparationV1{}, managed.ErrInvalid
	}
	value, _, err := readVerifiedPreparation(ctx, store.pool, store.instanceID,
		`owner_id=$2 AND preparation_id=$3`, ownerID, preparationID)
	return value, err
}

func (store *Store) GetLatestVerifiedPreparation(ctx context.Context, ownerID, deploymentID string) (managed.VerifiedPreparationV1, error) {
	if store == nil || store.pool == nil || ctx == nil || !validVerifiedPreparationOwner(ownerID) ||
		!validVerifiedPreparationUUID(deploymentID) {
		return managed.VerifiedPreparationV1{}, managed.ErrInvalid
	}
	return scanLatestVerifiedPreparation(store.pool.QueryRow(ctx, verifiedPreparationSelect+`
		WHERE agent_instance_id=$1 AND owner_id=$2 AND deployment_id=$3
		ORDER BY expected_deployment_revision DESC LIMIT 1`, store.instanceID, ownerID, deploymentID), store.instanceID)
}

const verifiedPreparationSelect = `SELECT preparation_id,owner_id,deployment_id,expected_deployment_revision,
	snapshot_digest,snapshot_json,attestations_json,create_client_id,create_credential_id,
	create_idempotency_key,create_request_hash,created_at FROM cloud_managed_verified_preparations`

type verifiedPreparationMeta struct {
	snapshotJSON       []byte
	attestationsJSON   []byte
	createClientID     string
	createCredentialID uuid.UUID
	createKey          uuid.UUID
	createRequestHash  string
}

type verifiedPreparationScanner interface{ Scan(...any) error }

func scanLatestVerifiedPreparation(scanner verifiedPreparationScanner, instanceID uuid.UUID) (managed.VerifiedPreparationV1, error) {
	value, _, err := scanVerifiedPreparation(scanner, instanceID)
	return value, err
}

func scanVerifiedPreparation(scanner verifiedPreparationScanner, instanceID uuid.UUID) (managed.VerifiedPreparationV1, verifiedPreparationMeta, error) {
	var value managed.VerifiedPreparationV1
	var meta verifiedPreparationMeta
	if err := scanner.Scan(&value.PreparationID, &value.OwnerID, &value.DeploymentID, &value.ExpectedDeploymentRevision,
		&value.SnapshotDigest, &meta.snapshotJSON, &meta.attestationsJSON, &meta.createClientID,
		&meta.createCredentialID, &meta.createKey, &meta.createRequestHash, &value.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return value, meta, managed.ErrNotFound
		}
		return value, meta, err
	}
	value.SchemaVersion = managed.VerifiedPreparationSchemaV1
	value.AgentInstanceID = instanceID.String()
	if json.Unmarshal(meta.snapshotJSON, &value.Snapshot) != nil ||
		json.Unmarshal(meta.attestationsJSON, &value.Attestations) != nil {
		return managed.VerifiedPreparationV1{}, verifiedPreparationMeta{}, managed.ErrInvalid
	}
	value.CreatedAt = value.CreatedAt.UTC()
	value.Snapshot.Scope.HealthObservedAt = value.Snapshot.Scope.HealthObservedAt.UTC()
	for index := range value.Attestations {
		value.Attestations[index].ObservedAt = value.Attestations[index].ObservedAt.UTC()
	}
	if value.Validate() != nil {
		return managed.VerifiedPreparationV1{}, verifiedPreparationMeta{}, managed.ErrInvalid
	}
	return value, meta, nil
}

type verifiedPreparationQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readVerifiedPreparation(ctx context.Context, query verifiedPreparationQuery, instanceID uuid.UUID, predicate string, args ...any) (managed.VerifiedPreparationV1, verifiedPreparationMeta, error) {
	return scanVerifiedPreparation(query.QueryRow(ctx, verifiedPreparationSelect+`
		WHERE agent_instance_id=$1 AND `+predicate, append([]any{instanceID}, args...)...), instanceID)
}

func sameVerifiedPreparation(stored, candidate managed.VerifiedPreparationV1, meta verifiedPreparationMeta, mutation managed.Mutation) bool {
	return stored.PreparationID == candidate.PreparationID && stored.AgentInstanceID == candidate.AgentInstanceID &&
		stored.OwnerID == candidate.OwnerID && stored.DeploymentID == candidate.DeploymentID &&
		stored.ExpectedDeploymentRevision == candidate.ExpectedDeploymentRevision &&
		stored.SnapshotDigest == candidate.SnapshotDigest &&
		sameVerifiedAttestations(stored.Attestations, candidate.Attestations) && meta.createClientID == mutation.ClientID &&
		meta.createCredentialID.String() == mutation.CredentialID && meta.createKey.String() == mutation.IdempotencyKey &&
		meta.createRequestHash == mutation.RequestHash
}

func sameVerifiedAttestations(left, right []managed.VerifiedAttestationV1) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].AttestationID != right[index].AttestationID || left[index].Kind != right[index].Kind ||
			left[index].Digest != right[index].Digest || !left[index].ObservedAt.Equal(right[index].ObservedAt) {
			return false
		}
	}
	return true
}

func validateVerifiedPreparationMutation(value managed.Mutation) error {
	client := strings.TrimSpace(value.ClientID)
	if client == "" || client != value.ClientID || len(client) > 255 || security.ContainsLikelySecret(client) ||
		!validVerifiedPreparationUUID(value.CredentialID) || !validVerifiedPreparationUUID(value.IdempotencyKey) ||
		!verifiedPreparationRequestDigest.MatchString(value.RequestHash) {
		return managed.ErrInvalid
	}
	return nil
}

func validVerifiedPreparationOwner(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed != "" && trimmed == value && len(value) <= 255 && !security.ContainsLikelySecret(value)
}
func validVerifiedPreparationUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}
