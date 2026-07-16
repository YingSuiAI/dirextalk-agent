package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"strings"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	clouddestroy "github.com/YingSuiAI/dirextalk-agent/internal/cloud/destroy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var _ clouddestroy.Repository = (*Store)(nil)

const cloudDestroyColumns = `operation_id, agent_instance_id, owner_id, deployment_id, plan_id, connection_id,
       challenge_id, approval_id, signer_key_id, expected_deployment_revision, scope_digest, scope_json,
       signing_payload, challenge_expires_at, signature, status, error_code, blocked_reason, revision,
       prepare_client_id, prepare_credential_id, prepare_idempotency_key, prepare_request_hash,
       approve_client_id, approve_credential_id, approve_idempotency_key, approve_request_hash,
       created_at, updated_at, approved_at`

type destroyRow struct {
	Operation clouddestroy.OperationV1
	Prepare   clouddestroy.Mutation
	Approve   *clouddestroy.Mutation
}

func (store *Store) CreateDestroyChallenge(ctx context.Context, mutation clouddestroy.Mutation, challenge clouddestroy.ChallengeV1) (clouddestroy.ChallengeV1, error) {
	if store == nil || store.pool == nil || mutation.Validate() != nil || challenge.Validate() != nil || mutation.OwnerID != challenge.Scope.OwnerID ||
		challenge.Scope.AgentInstanceID != store.instanceID.String() {
		return clouddestroy.ChallengeV1{}, clouddestroy.ErrInvalid
	}
	payload, err := challenge.SigningPayload()
	if err != nil || !bytes.Equal(payload, challenge.SigningCBOR) {
		return clouddestroy.ChallengeV1{}, clouddestroy.ErrInvalid
	}
	digest, err := clouddestroy.ScopeDigest(challenge.Scope)
	if err != nil || digest != challenge.ScopeDigest {
		return clouddestroy.ChallengeV1{}, clouddestroy.ErrInvalid
	}
	scopeJSON, err := json.Marshal(clouddestroy.NormalizeScope(challenge.Scope))
	if err != nil {
		return clouddestroy.ChallengeV1{}, clouddestroy.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return clouddestroy.ChallengeV1{}, clouddestroy.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, readErr := readDestroyRow(ctx, tx, ` WHERE prepare_client_id=$1 AND prepare_credential_id=$2 AND prepare_idempotency_key=$3 FOR UPDATE`,
		mutation.Caller.ClientID, mutation.Caller.CredentialID, mutation.IdempotencyKey)
	if readErr == nil {
		if !sameDestroyPrepare(existing, mutation, challenge) {
			return clouddestroy.ChallengeV1{}, clouddestroy.ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return clouddestroy.ChallengeV1{}, clouddestroy.ErrUnavailable
		}
		return existing.Operation.Challenge, nil
	}
	if !errors.Is(readErr, clouddestroy.ErrNotFound) {
		return clouddestroy.ChallengeV1{}, readErr
	}
	result, err := tx.Exec(ctx, `INSERT INTO cloud_destroy_operations (
		operation_id, agent_instance_id, owner_id, deployment_id, plan_id, connection_id,
		challenge_id, approval_id, signer_key_id, expected_deployment_revision, scope_digest, scope_json,
		signing_payload, challenge_expires_at, status, revision,
		prepare_client_id, prepare_credential_id, prepare_idempotency_key, prepare_request_hash,
		created_at, updated_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,1,$16,$17,$18,$19,$20,$20)
	ON CONFLICT (prepare_client_id, prepare_credential_id, prepare_idempotency_key) DO NOTHING`,
		challenge.OperationID, store.instanceID, challenge.Scope.OwnerID, challenge.Scope.DeploymentID,
		challenge.Scope.PlanID, challenge.Scope.ConnectionID, challenge.ChallengeID, challenge.ApprovalID,
		challenge.SignerKeyID, challenge.Scope.DeploymentRevision, challenge.ScopeDigest, scopeJSON,
		challenge.SigningCBOR, challenge.ExpiresAt.UTC(), clouddestroy.StatusAwaitingApproval,
		mutation.Caller.ClientID, mutation.Caller.CredentialID, mutation.IdempotencyKey, mutation.RequestHash[:], challenge.IssuedAt.UTC())
	if err != nil {
		if isUniqueViolation(err) {
			return clouddestroy.ChallengeV1{}, clouddestroy.ErrIdempotencyConflict
		}
		return clouddestroy.ChallengeV1{}, clouddestroy.ErrUnavailable
	}
	if result.RowsAffected() == 0 {
		existing, readErr = readDestroyRow(ctx, tx, ` WHERE prepare_client_id=$1 AND prepare_credential_id=$2 AND prepare_idempotency_key=$3 FOR UPDATE`,
			mutation.Caller.ClientID, mutation.Caller.CredentialID, mutation.IdempotencyKey)
		if readErr != nil {
			return clouddestroy.ChallengeV1{}, readErr
		}
		if !sameDestroyPrepare(existing, mutation, challenge) {
			return clouddestroy.ChallengeV1{}, clouddestroy.ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return clouddestroy.ChallengeV1{}, clouddestroy.ErrUnavailable
		}
		return existing.Operation.Challenge, nil
	}
	if err := tx.Commit(ctx); err != nil {
		return clouddestroy.ChallengeV1{}, clouddestroy.ErrUnavailable
	}
	return challenge, nil
}

func (store *Store) GetDestroyChallenge(ctx context.Context, ownerID, challengeID string) (clouddestroy.ChallengeV1, error) {
	if store == nil || store.pool == nil || strings.TrimSpace(ownerID) == "" {
		return clouddestroy.ChallengeV1{}, clouddestroy.ErrInvalid
	}
	row, err := readDestroyRow(ctx, store.pool, ` WHERE agent_instance_id=$1 AND owner_id=$2 AND challenge_id=$3`, store.instanceID, ownerID, challengeID)
	if err != nil {
		return clouddestroy.ChallengeV1{}, err
	}
	return row.Operation.Challenge, nil
}

func (store *Store) ApproveDestroy(ctx context.Context, mutation clouddestroy.Mutation, challengeID string, expectedDeploymentRevision int64, signature clouddestroy.SignatureV1, approvedAt time.Time) (clouddestroy.OperationV1, error) {
	if store == nil || store.pool == nil || mutation.Validate() != nil || signature.Validate() != nil || expectedDeploymentRevision < 1 || approvedAt.IsZero() {
		return clouddestroy.OperationV1{}, clouddestroy.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return clouddestroy.OperationV1{}, clouddestroy.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, readErr := readDestroyRow(ctx, tx, ` WHERE approve_client_id=$1 AND approve_credential_id=$2 AND approve_idempotency_key=$3 FOR UPDATE`,
		mutation.Caller.ClientID, mutation.Caller.CredentialID, mutation.IdempotencyKey)
	if readErr == nil {
		if !sameDestroyApprove(existing, mutation, challengeID, signature) {
			return clouddestroy.OperationV1{}, clouddestroy.ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return clouddestroy.OperationV1{}, clouddestroy.ErrUnavailable
		}
		return existing.Operation, nil
	}
	if !errors.Is(readErr, clouddestroy.ErrNotFound) {
		return clouddestroy.OperationV1{}, readErr
	}
	current, err := readDestroyRow(ctx, tx, ` WHERE agent_instance_id=$1 AND challenge_id=$2 FOR UPDATE`, store.instanceID, challengeID)
	if err != nil {
		return clouddestroy.OperationV1{}, err
	}
	challenge := current.Operation.Challenge
	if current.Operation.Status != clouddestroy.StatusAwaitingApproval {
		if !sameDestroyApprove(current, mutation, challengeID, signature) {
			return clouddestroy.OperationV1{}, clouddestroy.ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return clouddestroy.OperationV1{}, clouddestroy.ErrUnavailable
		}
		return current.Operation, nil
	}
	if challenge.Scope.OwnerID != mutation.OwnerID || challenge.Scope.DeploymentRevision != expectedDeploymentRevision ||
		signature.ApprovalID != challenge.ApprovalID ||
		signature.ChallengeID != challenge.ChallengeID || signature.SignerKeyID != challenge.SignerKeyID ||
		!signature.ExpiresAt.Equal(challenge.ExpiresAt) || approvedAt.Before(challenge.IssuedAt) || !approvedAt.Before(challenge.ExpiresAt) {
		return clouddestroy.OperationV1{}, clouddestroy.ErrRevisionConflict
	}
	var publicKey []byte
	var deviceAgent uuid.UUID
	var deviceOwner, deviceStatus string
	var notBefore, expiresAt time.Time
	var revokedAt *time.Time
	err = tx.QueryRow(ctx, `SELECT public_key, agent_instance_id, owner_id, status, not_before, expires_at, revoked_at
		FROM cloud_approval_devices WHERE key_id=$1 FOR SHARE`, challenge.SignerKeyID).
		Scan(&publicKey, &deviceAgent, &deviceOwner, &deviceStatus, &notBefore, &expiresAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return clouddestroy.OperationV1{}, clouddestroy.ErrApprovalRequired
	}
	if err != nil {
		return clouddestroy.OperationV1{}, clouddestroy.ErrUnavailable
	}
	if deviceAgent != store.instanceID || deviceOwner != mutation.OwnerID || deviceStatus != string(cloudapproval.DeviceKeyActive) || revokedAt != nil ||
		approvedAt.Before(notBefore) || !approvedAt.Before(expiresAt) || !ed25519.Verify(ed25519.PublicKey(publicKey), challenge.SigningCBOR, signature.Signature) {
		return clouddestroy.OperationV1{}, clouddestroy.ErrApprovalRequired
	}
	result, err := tx.Exec(ctx, `UPDATE cloud_destroy_operations SET
		signature=$2, status=$3, revision=revision+1, approve_client_id=$4, approve_credential_id=$5,
		approve_idempotency_key=$6, approve_request_hash=$7, approved_at=$8, updated_at=$8
		WHERE operation_id=$1 AND status='awaiting_approval' AND revision=1`, challenge.OperationID, signature.Signature,
		clouddestroy.StatusApproved, mutation.Caller.ClientID, mutation.Caller.CredentialID, mutation.IdempotencyKey,
		mutation.RequestHash[:], approvedAt.UTC())
	if err != nil {
		if isUniqueViolation(err) {
			return clouddestroy.OperationV1{}, clouddestroy.ErrIdempotencyConflict
		}
		return clouddestroy.OperationV1{}, clouddestroy.ErrUnavailable
	}
	if result.RowsAffected() != 1 {
		return clouddestroy.OperationV1{}, clouddestroy.ErrRevisionConflict
	}
	updated, err := readDestroyRow(ctx, tx, ` WHERE operation_id=$1`, challenge.OperationID)
	if err != nil {
		return clouddestroy.OperationV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return clouddestroy.OperationV1{}, clouddestroy.ErrUnavailable
	}
	return updated.Operation, nil
}

func (store *Store) GetDestroyOperation(ctx context.Context, ownerID, operationID string) (clouddestroy.OperationV1, error) {
	if store == nil || store.pool == nil || strings.TrimSpace(ownerID) == "" {
		return clouddestroy.OperationV1{}, clouddestroy.ErrInvalid
	}
	row, err := readDestroyRow(ctx, store.pool, ` WHERE agent_instance_id=$1 AND owner_id=$2 AND operation_id=$3`, store.instanceID, ownerID, operationID)
	return row.Operation, err
}

func (store *Store) ListPendingDestroy(ctx context.Context, limit int) ([]clouddestroy.OperationV1, error) {
	if store == nil || store.pool == nil || limit < 1 || limit > 256 {
		return nil, clouddestroy.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, `SELECT `+cloudDestroyColumns+` FROM cloud_destroy_operations
		WHERE agent_instance_id=$1 AND status IN ('approved','destroying','destroy_blocked')
		ORDER BY updated_at, operation_id LIMIT $2`, store.instanceID, limit)
	if err != nil {
		return nil, clouddestroy.ErrUnavailable
	}
	defer rows.Close()
	result := make([]clouddestroy.OperationV1, 0, limit)
	for rows.Next() {
		row, scanErr := scanDestroyRow(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, row.Operation)
	}
	if rows.Err() != nil {
		return nil, clouddestroy.ErrUnavailable
	}
	return result, nil
}

func (store *Store) SaveDestroyOperation(ctx context.Context, next clouddestroy.OperationV1, expectedRevision int64) (clouddestroy.OperationV1, error) {
	if store == nil || store.pool == nil || expectedRevision < 2 || clouddestroy.ValidateOperation(next) != nil {
		return clouddestroy.OperationV1{}, clouddestroy.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return clouddestroy.OperationV1{}, clouddestroy.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := readDestroyRow(ctx, tx, ` WHERE operation_id=$1 FOR UPDATE`, next.Challenge.OperationID)
	if err != nil {
		return clouddestroy.OperationV1{}, err
	}
	if current.Operation.Revision != expectedRevision || !sameDestroyIdentity(current.Operation, next) || !validDestroyTransition(current.Operation.Status, next.Status) {
		return clouddestroy.OperationV1{}, clouddestroy.ErrRevisionConflict
	}
	next.Revision = expectedRevision + 1
	result, err := tx.Exec(ctx, `UPDATE cloud_destroy_operations SET status=$2,error_code=$3,blocked_reason=$4,revision=$5,updated_at=$6
		WHERE operation_id=$1 AND revision=$7`, next.Challenge.OperationID, next.Status, nullableDestroyString(next.ErrorCode),
		nullableDestroyString(next.BlockedReason), next.Revision, next.UpdatedAt.UTC(), expectedRevision)
	if err != nil || result.RowsAffected() != 1 {
		return clouddestroy.OperationV1{}, clouddestroy.ErrRevisionConflict
	}
	updated, err := readDestroyRow(ctx, tx, ` WHERE operation_id=$1`, next.Challenge.OperationID)
	if err != nil {
		return clouddestroy.OperationV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return clouddestroy.OperationV1{}, clouddestroy.ErrUnavailable
	}
	return updated.Operation, nil
}

type destroyRowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readDestroyRow(ctx context.Context, query destroyRowQuerier, suffix string, args ...any) (destroyRow, error) {
	return scanDestroyRow(query.QueryRow(ctx, `SELECT `+cloudDestroyColumns+` FROM cloud_destroy_operations`+suffix, args...))
}

type destroyScanner interface{ Scan(...any) error }

func scanDestroyRow(row destroyScanner) (destroyRow, error) {
	var operationID, agentID, deploymentID, planID, connectionID, challengeID, approvalID uuid.UUID
	var ownerID, signerKeyID, scopeDigest string
	var scopeJSON, signingPayload, signature, prepareHash, approveHash []byte
	var expectedRevision, revision int64
	var status clouddestroy.Status
	var errorCode, blockedReason, approveClientID *string
	var prepareClientID string
	var prepareCredentialID, prepareIdempotencyKey uuid.UUID
	var approveCredentialID, approveIdempotencyKey *uuid.UUID
	var challengeExpiresAt, createdAt, updatedAt time.Time
	var approvedAt *time.Time
	err := row.Scan(&operationID, &agentID, &ownerID, &deploymentID, &planID, &connectionID,
		&challengeID, &approvalID, &signerKeyID, &expectedRevision, &scopeDigest, &scopeJSON,
		&signingPayload, &challengeExpiresAt, &signature, &status, &errorCode, &blockedReason, &revision,
		&prepareClientID, &prepareCredentialID, &prepareIdempotencyKey, &prepareHash,
		&approveClientID, &approveCredentialID, &approveIdempotencyKey, &approveHash,
		&createdAt, &updatedAt, &approvedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return destroyRow{}, clouddestroy.ErrNotFound
	}
	if err != nil || len(prepareHash) != 32 {
		return destroyRow{}, clouddestroy.ErrUnavailable
	}
	var scope clouddestroy.ScopeV1
	if json.Unmarshal(scopeJSON, &scope) != nil {
		return destroyRow{}, clouddestroy.ErrUnavailable
	}
	challenge := clouddestroy.ChallengeV1{OperationID: operationID.String(), ChallengeID: challengeID.String(), ApprovalID: approvalID.String(),
		SignerKeyID: signerKeyID, Scope: scope, ScopeDigest: scopeDigest, IssuedAt: createdAt.UTC(), ExpiresAt: challengeExpiresAt.UTC(),
		SigningCBOR: append([]byte(nil), signingPayload...), Revision: 1}
	operation := clouddestroy.OperationV1{Challenge: challenge, Status: status, Signature: append([]byte(nil), signature...),
		Revision: revision, CreatedAt: createdAt.UTC(), UpdatedAt: updatedAt.UTC(), ApprovedAt: approvedAt}
	if errorCode != nil {
		operation.ErrorCode = *errorCode
	}
	if blockedReason != nil {
		operation.BlockedReason = *blockedReason
	}
	var prepareDigest [32]byte
	copy(prepareDigest[:], prepareHash)
	result := destroyRow{Operation: operation, Prepare: clouddestroy.Mutation{Caller: clouddestroy.MutationScope{ClientID: prepareClientID, CredentialID: prepareCredentialID.String()}, OwnerID: ownerID, IdempotencyKey: prepareIdempotencyKey.String(), RequestHash: prepareDigest}}
	if approveClientID != nil {
		if approveCredentialID == nil || approveIdempotencyKey == nil || len(approveHash) != 32 {
			return destroyRow{}, clouddestroy.ErrUnavailable
		}
		var approveDigest [32]byte
		copy(approveDigest[:], approveHash)
		result.Approve = &clouddestroy.Mutation{Caller: clouddestroy.MutationScope{ClientID: *approveClientID, CredentialID: approveCredentialID.String()}, OwnerID: ownerID, IdempotencyKey: approveIdempotencyKey.String(), RequestHash: approveDigest}
	}
	if agentID.String() != scope.AgentInstanceID || deploymentID.String() != scope.DeploymentID || planID.String() != scope.PlanID || connectionID.String() != scope.ConnectionID ||
		expectedRevision != scope.DeploymentRevision || clouddestroy.ValidateOperation(operation) != nil {
		return destroyRow{}, clouddestroy.ErrUnavailable
	}
	return result, nil
}

func sameDestroyPrepare(existing destroyRow, mutation clouddestroy.Mutation, challenge clouddestroy.ChallengeV1) bool {
	return existing.Prepare.Caller == mutation.Caller && existing.Prepare.OwnerID == mutation.OwnerID &&
		subtle.ConstantTimeCompare(existing.Prepare.RequestHash[:], mutation.RequestHash[:]) == 1 &&
		existing.Operation.Challenge.OperationID == challenge.OperationID && existing.Operation.Challenge.ChallengeID == challenge.ChallengeID &&
		existing.Operation.Challenge.ScopeDigest == challenge.ScopeDigest
}

func sameDestroyApprove(existing destroyRow, mutation clouddestroy.Mutation, challengeID string, signature clouddestroy.SignatureV1) bool {
	return existing.Approve != nil && existing.Approve.Caller == mutation.Caller && existing.Approve.OwnerID == mutation.OwnerID &&
		existing.Approve.IdempotencyKey == mutation.IdempotencyKey && subtle.ConstantTimeCompare(existing.Approve.RequestHash[:], mutation.RequestHash[:]) == 1 &&
		existing.Operation.Challenge.ChallengeID == challengeID && existing.Operation.Challenge.Scope.OwnerID == mutation.OwnerID &&
		bytes.Equal(existing.Operation.Signature, signature.Signature)
}

func sameDestroyIdentity(current, next clouddestroy.OperationV1) bool {
	return current.Challenge.OperationID == next.Challenge.OperationID && current.Challenge.ChallengeID == next.Challenge.ChallengeID &&
		current.Challenge.ApprovalID == next.Challenge.ApprovalID && current.Challenge.ScopeDigest == next.Challenge.ScopeDigest &&
		bytes.Equal(current.Signature, next.Signature)
}

func validDestroyTransition(current, next clouddestroy.Status) bool {
	switch current {
	case clouddestroy.StatusApproved:
		return next == clouddestroy.StatusDestroying || next == clouddestroy.StatusDestroyBlocked
	case clouddestroy.StatusDestroying:
		return next == clouddestroy.StatusVerifiedDestroyed || next == clouddestroy.StatusDestroyBlocked
	case clouddestroy.StatusDestroyBlocked:
		return next == clouddestroy.StatusDestroying || next == clouddestroy.StatusDestroyBlocked
	default:
		return false
	}
}

func nullableDestroyString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.TrimSpace(value)
}
