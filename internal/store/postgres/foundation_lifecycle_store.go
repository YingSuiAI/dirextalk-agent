package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudfoundation "github.com/YingSuiAI/dirextalk-agent/internal/cloud/foundation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const foundationLifecycleColumns = `operation_id, owner_id, challenge_id, approval_id, signer_key_id,
scope_digest, scope_json, signing_payload, challenge_expires_at, signature, status,
COALESCE(error_code,''), COALESCE(blocked_reason,''), revision, created_at, updated_at, approved_at,
prepare_client_id, prepare_credential_id::text`

func (store *Store) CreateFoundationLifecycleChallenge(ctx context.Context, mutation cloudfoundation.Mutation, challenge cloudfoundation.ChallengeV1) (cloudfoundation.ChallengeV1, error) {
	if store == nil || mutation.Validate() != nil || challenge.Validate() != nil || mutation.OwnerID != challenge.Scope.OwnerID || challenge.Scope.AgentInstanceID != store.instanceID.String() {
		return cloudfoundation.ChallengeV1{}, cloudfoundation.ErrInvalid
	}
	payload, err := challenge.SigningPayload()
	if err != nil || !bytes.Equal(payload, challenge.SigningCBOR) {
		return cloudfoundation.ChallengeV1{}, cloudfoundation.ErrInvalid
	}
	scopeJSON, err := json.Marshal(challenge.Scope)
	if err != nil {
		return cloudfoundation.ChallengeV1{}, cloudfoundation.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return cloudfoundation.ChallengeV1{}, cloudfoundation.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := tx.Exec(ctx, `INSERT INTO aws_foundation_lifecycle_operations
 (operation_id,agent_instance_id,owner_id,connection_id,action,bootstrap_session_id,expected_bootstrap_revision,
  expected_connection_revision,expected_credential_generation,challenge_id,approval_id,signer_key_id,scope_digest,
  scope_json,signing_payload,challenge_expires_at,status,revision,prepare_client_id,prepare_credential_id,
  prepare_idempotency_key,prepare_request_hash,created_at,updated_at)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'awaiting_approval',1,$17,$18,$19,$20,$21,$21)
 ON CONFLICT (prepare_client_id,prepare_credential_id,prepare_idempotency_key) DO NOTHING`,
		challenge.OperationID, store.instanceID, challenge.Scope.OwnerID, challenge.Scope.ConnectionID, challenge.Scope.Action,
		challenge.Scope.BootstrapSessionID, challenge.Scope.ExpectedBootstrapRevision, challenge.Scope.ExpectedConnectionRevision,
		challenge.Scope.ExpectedCredentialGeneration, challenge.ChallengeID, challenge.ApprovalID, challenge.SignerKeyID,
		challenge.ScopeDigest, scopeJSON, payload, challenge.ExpiresAt, mutation.Caller.ClientID, mutation.Caller.CredentialID,
		mutation.IdempotencyKey, mutation.RequestHash[:], challenge.IssuedAt)
	if err != nil {
		return cloudfoundation.ChallengeV1{}, cloudfoundation.ErrUnavailable
	}
	var stored foundationLifecycleRow
	if result.RowsAffected() == 1 {
		stored, err = readFoundationLifecycle(ctx, tx, challenge.OperationID, true)
	} else {
		stored, err = readFoundationLifecycleByPrepare(ctx, tx, mutation, true)
		if err == nil {
			var requestHash []byte
			err = tx.QueryRow(ctx, `SELECT prepare_request_hash FROM aws_foundation_lifecycle_operations WHERE operation_id=$1`, stored.operation.Challenge.OperationID).Scan(&requestHash)
			if err == nil && !bytes.Equal(requestHash, mutation.RequestHash[:]) {
				err = cloudfoundation.ErrIdempotencyConflict
			}
		}
	}
	if err != nil {
		return cloudfoundation.ChallengeV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return cloudfoundation.ChallengeV1{}, cloudfoundation.ErrUnavailable
	}
	return stored.operation.Challenge, nil
}

func (store *Store) GetFoundationLifecycleChallenge(ctx context.Context, ownerID, challengeID string) (cloudfoundation.ChallengeV1, error) {
	if store == nil || strings.TrimSpace(ownerID) == "" {
		return cloudfoundation.ChallengeV1{}, cloudfoundation.ErrInvalid
	}
	row, err := scanFoundationLifecycle(store.pool.QueryRow(ctx, `SELECT `+foundationLifecycleColumns+` FROM aws_foundation_lifecycle_operations WHERE agent_instance_id=$1 AND owner_id=$2 AND challenge_id=$3`, store.instanceID, ownerID, challengeID))
	if err != nil {
		return cloudfoundation.ChallengeV1{}, err
	}
	return row.operation.Challenge, nil
}

func (store *Store) ApproveFoundationLifecycle(ctx context.Context, mutation cloudfoundation.Mutation, signature cloudfoundation.SignatureV1, approvedAt time.Time) (cloudfoundation.OperationV1, error) {
	if store == nil || mutation.Validate() != nil || signature.Validate() != nil || approvedAt.IsZero() {
		return cloudfoundation.OperationV1{}, cloudfoundation.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return cloudfoundation.OperationV1{}, cloudfoundation.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replay, replayErr := readFoundationLifecycleByApprove(ctx, tx, mutation, true); replayErr == nil {
		var requestHash []byte
		if err := tx.QueryRow(ctx, `SELECT approve_request_hash FROM aws_foundation_lifecycle_operations WHERE operation_id=$1`, replay.operation.Challenge.OperationID).Scan(&requestHash); err != nil {
			return cloudfoundation.OperationV1{}, cloudfoundation.ErrUnavailable
		}
		if !bytes.Equal(requestHash, mutation.RequestHash[:]) {
			return cloudfoundation.OperationV1{}, cloudfoundation.ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return cloudfoundation.OperationV1{}, cloudfoundation.ErrUnavailable
		}
		return replay.operation, nil
	} else if !errors.Is(replayErr, cloudfoundation.ErrNotFound) {
		return cloudfoundation.OperationV1{}, replayErr
	}
	row, err := scanFoundationLifecycle(tx.QueryRow(ctx, `SELECT `+foundationLifecycleColumns+` FROM aws_foundation_lifecycle_operations WHERE agent_instance_id=$1 AND owner_id=$2 AND challenge_id=$3 FOR UPDATE`, store.instanceID, mutation.OwnerID, signature.ChallengeID))
	if err != nil {
		return cloudfoundation.OperationV1{}, err
	}
	challenge := row.operation.Challenge
	if row.operation.Status != cloudfoundation.StatusAwaitingApproval || challenge.ApprovalID != signature.ApprovalID || challenge.SignerKeyID != signature.SignerKeyID ||
		!challenge.ExpiresAt.Equal(signature.ExpiresAt) || !approvedAt.Before(challenge.ExpiresAt) {
		return cloudfoundation.OperationV1{}, cloudfoundation.ErrApprovalRequired
	}
	var publicKey []byte
	var deviceAgent, deviceOwner, status string
	var notBefore, expiresAt time.Time
	var revokedAt *time.Time
	if err := tx.QueryRow(ctx, `SELECT public_key,agent_instance_id::text,owner_id,status,not_before,expires_at,revoked_at FROM cloud_approval_devices WHERE key_id=$1 FOR SHARE`, signature.SignerKeyID).
		Scan(&publicKey, &deviceAgent, &deviceOwner, &status, &notBefore, &expiresAt, &revokedAt); err != nil {
		return cloudfoundation.OperationV1{}, cloudfoundation.ErrApprovalRequired
	}
	device := cloudapproval.DeviceKeyV1{KeyID: signature.SignerKeyID, AgentInstanceID: deviceAgent, OwnerID: deviceOwner, Revision: 1,
		Status: cloudapproval.DeviceKeyStatus(status), PublicKey: ed25519.PublicKey(publicKey), NotBefore: notBefore, ExpiresAt: expiresAt, RevokedAt: revokedAt}
	if deviceAgent != store.instanceID.String() || deviceOwner != mutation.OwnerID || device.ValidateAt(approvedAt) != nil || !ed25519.Verify(device.PublicKey, challenge.SigningCBOR, signature.Signature) {
		return cloudfoundation.OperationV1{}, cloudfoundation.ErrApprovalRequired
	}
	if challenge.Scope.Action == cloudfoundation.ActionTeardown || challenge.Scope.Action == cloudfoundation.ActionRemediate {
		var accountID, region, connectionStatus string
		var connectionRevision int64
		if err := tx.QueryRow(ctx, `SELECT account_id,region,status,revision FROM cloud_connections
		 WHERE agent_instance_id=$1 AND owner_id=$2 AND connection_id=$3 FOR UPDATE`, store.instanceID, mutation.OwnerID, challenge.Scope.ConnectionID).
			Scan(&accountID, &region, &connectionStatus, &connectionRevision); err != nil {
			return cloudfoundation.OperationV1{}, cloudfoundation.ErrRevisionConflict
		}
		validStatus := challenge.Scope.Action == cloudfoundation.ActionTeardown && (connectionStatus == "active" || connectionStatus == "degraded" || connectionStatus == "teardown_blocked")
		validStatus = validStatus || challenge.Scope.Action == cloudfoundation.ActionRemediate && connectionStatus == "teardown_blocked"
		if !validStatus || connectionRevision != challenge.Scope.ExpectedConnectionRevision || accountID != challenge.Scope.AccountID || region != challenge.Scope.Region {
			return cloudfoundation.OperationV1{}, cloudfoundation.ErrRevisionConflict
		}
		safe, err := foundationTeardownSafe(ctx, tx, store.instanceID, mutation.OwnerID, challenge.Scope.ConnectionID, accountID, region)
		if err != nil {
			return cloudfoundation.OperationV1{}, err
		}
		if !safe {
			return cloudfoundation.OperationV1{}, cloudfoundation.ErrRevisionConflict
		}
		changed, err := tx.Exec(ctx, `UPDATE cloud_connections SET status='tearing_down',revision=revision+1,updated_at=$4
		 WHERE connection_id=$1 AND owner_id=$2 AND revision=$3`, challenge.Scope.ConnectionID, mutation.OwnerID, connectionRevision, approvedAt)
		if err != nil || changed.RowsAffected() != 1 {
			return cloudfoundation.OperationV1{}, cloudfoundation.ErrRevisionConflict
		}
	}
	updated, err := scanFoundationLifecycle(tx.QueryRow(ctx, `UPDATE aws_foundation_lifecycle_operations SET signature=$2,status='approved',revision=revision+1,
 approve_client_id=$3,approve_credential_id=$4,approve_idempotency_key=$5,approve_request_hash=$6,approved_at=$7,updated_at=$7
 WHERE operation_id=$1 AND revision=$8 RETURNING `+foundationLifecycleColumns,
		challenge.OperationID, signature.Signature, mutation.Caller.ClientID, mutation.Caller.CredentialID, mutation.IdempotencyKey, mutation.RequestHash[:], approvedAt, row.operation.Revision))
	if err != nil {
		return cloudfoundation.OperationV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return cloudfoundation.OperationV1{}, cloudfoundation.ErrUnavailable
	}
	return updated.operation, nil
}

func (store *Store) GetFoundationLifecycleOperation(ctx context.Context, ownerID, operationID string) (cloudfoundation.OperationV1, error) {
	if store == nil || strings.TrimSpace(ownerID) == "" {
		return cloudfoundation.OperationV1{}, cloudfoundation.ErrInvalid
	}
	row, err := scanFoundationLifecycle(store.pool.QueryRow(ctx, `SELECT `+foundationLifecycleColumns+` FROM aws_foundation_lifecycle_operations WHERE agent_instance_id=$1 AND owner_id=$2 AND operation_id=$3`, store.instanceID, ownerID, operationID))
	if err != nil {
		return cloudfoundation.OperationV1{}, err
	}
	return row.operation, nil
}

// FoundationLifecycleRepository narrows Store to the independent Foundation
// authorization boundary without colliding with the older Worker-plan
// approval repository methods.
type FoundationLifecycleRepository struct{ store *Store }

func NewFoundationLifecycleRepository(store *Store) (*FoundationLifecycleRepository, error) {
	if store == nil {
		return nil, cloudfoundation.ErrInvalid
	}
	return &FoundationLifecycleRepository{store: store}, nil
}

func (repository *FoundationLifecycleRepository) CreateChallenge(ctx context.Context, mutation cloudfoundation.Mutation, challenge cloudfoundation.ChallengeV1) (cloudfoundation.ChallengeV1, error) {
	return repository.store.CreateFoundationLifecycleChallenge(ctx, mutation, challenge)
}
func (repository *FoundationLifecycleRepository) GetChallenge(ctx context.Context, ownerID, challengeID string) (cloudfoundation.ChallengeV1, error) {
	return repository.store.GetFoundationLifecycleChallenge(ctx, ownerID, challengeID)
}
func (repository *FoundationLifecycleRepository) Approve(ctx context.Context, mutation cloudfoundation.Mutation, signature cloudfoundation.SignatureV1, approvedAt time.Time) (cloudfoundation.OperationV1, error) {
	return repository.store.ApproveFoundationLifecycle(ctx, mutation, signature, approvedAt)
}
func (repository *FoundationLifecycleRepository) GetOperation(ctx context.Context, ownerID, operationID string) (cloudfoundation.OperationV1, error) {
	return repository.store.GetFoundationLifecycleOperation(ctx, ownerID, operationID)
}
func (repository *FoundationLifecycleRepository) CheckFoundationTeardown(ctx context.Context, ownerID, connectionID, accountID, region string) error {
	if repository == nil || repository.store == nil || strings.TrimSpace(ownerID) == "" || strings.TrimSpace(accountID) == "" || strings.TrimSpace(region) == "" {
		return cloudfoundation.ErrInvalid
	}
	parsed, err := uuid.Parse(connectionID)
	if err != nil || parsed == uuid.Nil || parsed.String() != connectionID {
		return cloudfoundation.ErrInvalid
	}
	safe, err := foundationTeardownSafe(ctx, repository.store.pool, repository.store.instanceID, ownerID, parsed.String(), accountID, region)
	if err != nil {
		return err
	}
	if !safe {
		return cloudfoundation.ErrRevisionConflict
	}
	return nil
}

func foundationTeardownSafe(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, agentInstanceID uuid.UUID, ownerID, connectionID, accountID, region string) (bool, error) {
	var safe bool
	err := query.QueryRow(ctx, `SELECT
	 NOT EXISTS (
	   SELECT 1 FROM cloud_resources resource
	   JOIN cloud_launch_operations launch ON launch.agent_instance_id=resource.agent_instance_id AND launch.deployment_id=resource.deployment_id
	   WHERE resource.agent_instance_id=$1 AND resource.owner_id=$2 AND launch.owner_id=$2 AND launch.connection_id=$3
	     AND (resource.state<>'verified_destroyed' OR resource.readback_exists=true)
	 )
	 AND NOT EXISTS (
	   SELECT 1 FROM worker_release_catalog
	   WHERE agent_instance_id=$1 AND account_id=$4 AND region=$5
	 )`, agentInstanceID, ownerID, connectionID, accountID, region).Scan(&safe)
	if err != nil {
		return false, cloudfoundation.ErrUnavailable
	}
	return safe, nil
}
func (repository *FoundationLifecycleRepository) ListExecutable(ctx context.Context, limit int) ([]cloudfoundation.OperationV1, error) {
	if repository == nil || limit < 1 || limit > 256 {
		return nil, cloudfoundation.ErrInvalid
	}
	rows, err := repository.store.pool.Query(ctx, `SELECT `+foundationLifecycleColumns+` FROM aws_foundation_lifecycle_operations
 WHERE agent_instance_id=$1 AND status IN ('approved','running','failed_retriable') ORDER BY updated_at,operation_id LIMIT $2`, repository.store.instanceID, limit)
	if err != nil {
		return nil, cloudfoundation.ErrUnavailable
	}
	defer rows.Close()
	result := make([]cloudfoundation.OperationV1, 0, limit)
	for rows.Next() {
		row, scanErr := scanFoundationLifecycle(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, row.operation)
	}
	if rows.Err() != nil {
		return nil, cloudfoundation.ErrUnavailable
	}
	rows.Close()
	for index := range result {
		if result[index].Challenge.Scope.Action != cloudfoundation.ActionEstablish {
			continue
		}
		if err := repository.store.pool.QueryRow(ctx, `SELECT EXISTS (
		 SELECT 1 FROM aws_foundation_lifecycle_operations
		 WHERE agent_instance_id=$1 AND owner_id=$2 AND connection_id=$3 AND action='establish' AND status='failed_terminal' AND operation_id<>$4
		)`, repository.store.instanceID, result[index].Challenge.Scope.OwnerID, result[index].Challenge.Scope.ConnectionID, result[index].Challenge.OperationID).Scan(&result[index].AdoptExisting); err != nil {
			return nil, cloudfoundation.ErrUnavailable
		}
		if result[index].AdoptExisting {
			result[index].Recovery = true
		}
	}
	return result, nil
}
func (repository *FoundationLifecycleRepository) MarkRunning(ctx context.Context, operationID string, expectedRevision int64) (cloudfoundation.OperationV1, error) {
	return repository.transition(ctx, operationID, expectedRevision, "running", "", "")
}
func (repository *FoundationLifecycleRepository) MarkFailed(ctx context.Context, operationID string, expectedRevision int64, blocked, terminal bool, reason string) (cloudfoundation.OperationV1, error) {
	status, code := "failed_retriable", "foundation_provider_failed"
	if blocked {
		status, code = "destroy_blocked", "foundation_destroy_blocked"
	} else if terminal {
		status, code = "failed_terminal", "fresh_bootstrap_required"
	}
	return repository.transition(ctx, operationID, expectedRevision, status, code, strings.TrimSpace(reason))
}
func (repository *FoundationLifecycleRepository) transition(ctx context.Context, operationID string, expectedRevision int64, status, code, reason string) (cloudfoundation.OperationV1, error) {
	if repository == nil || expectedRevision < 1 {
		return cloudfoundation.OperationV1{}, cloudfoundation.ErrInvalid
	}
	tx, err := repository.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return cloudfoundation.OperationV1{}, cloudfoundation.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := readFoundationLifecycle(ctx, tx, operationID, true)
	if errors.Is(err, cloudfoundation.ErrNotFound) || (err == nil && current.operation.Revision != expectedRevision) {
		return cloudfoundation.OperationV1{}, cloudfoundation.ErrRevisionConflict
	}
	if err != nil {
		return cloudfoundation.OperationV1{}, err
	}
	if status == "destroy_blocked" && (current.operation.Challenge.Scope.Action == cloudfoundation.ActionTeardown || current.operation.Challenge.Scope.Action == cloudfoundation.ActionRemediate) {
		scope := current.operation.Challenge.Scope
		changed, updateErr := tx.Exec(ctx, `UPDATE cloud_connections SET status='teardown_blocked',revision=revision+1,updated_at=clock_timestamp()
	 WHERE connection_id=$1 AND owner_id=$2 AND revision=$3 AND status='tearing_down'`, scope.ConnectionID, scope.OwnerID, scope.ExpectedConnectionRevision+1)
		if updateErr != nil || changed.RowsAffected() != 1 {
			return cloudfoundation.OperationV1{}, cloudfoundation.ErrRevisionConflict
		}
	}
	row, err := scanFoundationLifecycle(tx.QueryRow(ctx, `UPDATE aws_foundation_lifecycle_operations SET status=$3,error_code=NULLIF($4,''),blocked_reason=NULLIF($5,''),revision=revision+1,updated_at=clock_timestamp()
	 WHERE operation_id=$1 AND revision=$2 RETURNING `+foundationLifecycleColumns, operationID, expectedRevision, status, code, reason))
	if err != nil {
		return cloudfoundation.OperationV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return cloudfoundation.OperationV1{}, cloudfoundation.ErrUnavailable
	}
	return row.operation, nil
}
func (repository *FoundationLifecycleRepository) MarkSucceeded(ctx context.Context, operationID string, expectedRevision int64, result cloudfoundation.ExecutionResult) (cloudfoundation.OperationV1, error) {
	if repository == nil || expectedRevision < 1 || result.CredentialGeneration == 0 {
		return cloudfoundation.OperationV1{}, cloudfoundation.ErrInvalid
	}
	tx, err := repository.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return cloudfoundation.OperationV1{}, cloudfoundation.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := readFoundationLifecycle(ctx, tx, operationID, true)
	if err != nil {
		return cloudfoundation.OperationV1{}, err
	}
	if current.operation.Revision != expectedRevision || current.operation.Status != cloudfoundation.StatusRunning {
		return cloudfoundation.OperationV1{}, cloudfoundation.ErrRevisionConflict
	}
	scope := current.operation.Challenge.Scope
	var bootstrapKeyHandle *uuid.UUID
	var bootstrapStatus string
	var bootstrapRevision int64
	if err := tx.QueryRow(ctx, `SELECT key_handle,status,revision FROM secret_bootstrap_sessions
	 WHERE session_id=$1 AND creator_client_id=$2 FOR UPDATE`,
		scope.BootstrapSessionID, current.operation.Caller.ClientID).Scan(&bootstrapKeyHandle, &bootstrapStatus, &bootstrapRevision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return cloudfoundation.OperationV1{}, cloudfoundation.ErrRevisionConflict
		}
		return cloudfoundation.OperationV1{}, cloudfoundation.ErrUnavailable
	}
	uploadedSession := bootstrapStatus == "uploaded" && bootstrapRevision == int64(scope.ExpectedBootstrapRevision) && bootstrapKeyHandle != nil
	expiredDuringExecution := bootstrapStatus == "expired" && bootstrapRevision == int64(scope.ExpectedBootstrapRevision)+1 && bootstrapKeyHandle == nil
	if !uploadedSession && !expiredDuringExecution {
		return cloudfoundation.OperationV1{}, cloudfoundation.ErrRevisionConflict
	}
	switch scope.Action {
	case cloudfoundation.ActionEstablish:
		if result.ConnectionStatus != "active" || result.FoundationStackID == "" || result.ControlRoleARN == "" || result.CredentialGeneration != 1 {
			return cloudfoundation.OperationV1{}, cloudfoundation.ErrInvalid
		}
		if _, err = tx.Exec(ctx, `INSERT INTO cloud_connections (connection_id,agent_instance_id,owner_id,account_id,region,control_role_arn,foundation_stack_id,credential_generation,status,revision)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',1)`, scope.ConnectionID, repository.store.instanceID, scope.OwnerID, scope.AccountID, scope.Region, result.ControlRoleARN, result.FoundationStackID, result.CredentialGeneration); err != nil {
			return cloudfoundation.OperationV1{}, cloudfoundation.ErrRevisionConflict
		}
	case cloudfoundation.ActionUpgrade:
		if result.ConnectionStatus != "active" || result.FoundationStackID == "" || result.ControlRoleARN == "" || result.CredentialGeneration != scope.ExpectedCredentialGeneration {
			return cloudfoundation.OperationV1{}, cloudfoundation.ErrInvalid
		}
		changed, updateErr := tx.Exec(ctx, `UPDATE cloud_connections SET control_role_arn=$4,foundation_stack_id=$5,credential_generation=$6,status='active',revision=revision+1,updated_at=clock_timestamp()
 WHERE connection_id=$1 AND owner_id=$2 AND revision=$3`, scope.ConnectionID, scope.OwnerID, scope.ExpectedConnectionRevision, result.ControlRoleARN, result.FoundationStackID, result.CredentialGeneration)
		if updateErr != nil || changed.RowsAffected() != 1 {
			return cloudfoundation.OperationV1{}, cloudfoundation.ErrRevisionConflict
		}
	case cloudfoundation.ActionTeardown, cloudfoundation.ActionRemediate:
		if result.ConnectionStatus != "destroyed" || result.FoundationStackID != "" || result.ControlRoleARN != "" || result.CredentialGeneration != scope.ExpectedCredentialGeneration {
			return cloudfoundation.OperationV1{}, cloudfoundation.ErrInvalid
		}
		changed, updateErr := tx.Exec(ctx, `UPDATE cloud_connections SET control_role_arn='',foundation_stack_id='',status='destroyed',revision=revision+1,updated_at=clock_timestamp()
	 WHERE connection_id=$1 AND owner_id=$2 AND revision=$3 AND status='tearing_down'`, scope.ConnectionID, scope.OwnerID, scope.ExpectedConnectionRevision+1)
		if updateErr != nil || changed.RowsAffected() != 1 {
			return cloudfoundation.OperationV1{}, cloudfoundation.ErrRevisionConflict
		}
	default:
		return cloudfoundation.OperationV1{}, cloudfoundation.ErrInvalid
	}
	completed, err := scanFoundationLifecycle(tx.QueryRow(ctx, `UPDATE aws_foundation_lifecycle_operations SET status='succeeded',error_code=NULL,blocked_reason=NULL,revision=revision+1,updated_at=clock_timestamp()
 WHERE operation_id=$1 AND revision=$2 RETURNING `+foundationLifecycleColumns, operationID, expectedRevision))
	if err != nil {
		return cloudfoundation.OperationV1{}, err
	}
	if uploadedSession {
		consumed, consumeErr := tx.Exec(ctx, `UPDATE secret_bootstrap_sessions SET status='consumed',revision=revision+1,upload_token_hash=NULL,
		 idempotency_token_nonce=NULL,idempotency_token_ciphertext=NULL,key_handle=NULL,envelope_schema=NULL,client_public_key=NULL,
		 envelope_nonce=NULL,envelope_ciphertext=NULL,updated_at=clock_timestamp()
		 WHERE session_id=$1 AND revision=$2 AND status='uploaded' AND key_handle=$3 AND creator_client_id=$4`,
			scope.BootstrapSessionID, scope.ExpectedBootstrapRevision, *bootstrapKeyHandle, current.operation.Caller.ClientID)
		if consumeErr != nil || consumed.RowsAffected() != 1 {
			return cloudfoundation.OperationV1{}, cloudfoundation.ErrRevisionConflict
		}
		deleted, deleteErr := tx.Exec(ctx, `DELETE FROM secret_bootstrap_keys WHERE key_handle=$1 AND session_id=$2`, *bootstrapKeyHandle, scope.BootstrapSessionID)
		if deleteErr != nil || deleted.RowsAffected() != 1 {
			return cloudfoundation.OperationV1{}, cloudfoundation.ErrUnavailable
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return cloudfoundation.OperationV1{}, cloudfoundation.ErrUnavailable
	}
	return completed.operation, nil
}

type foundationLifecycleRow struct{ operation cloudfoundation.OperationV1 }
type foundationLifecycleScanner interface{ Scan(...any) error }

func scanFoundationLifecycle(scanner foundationLifecycleScanner) (foundationLifecycleRow, error) {
	var row foundationLifecycleRow
	var scopeJSON, signingPayload, signature []byte
	var approvedAt *time.Time
	if err := scanner.Scan(&row.operation.Challenge.OperationID, &row.operation.Challenge.Scope.OwnerID, &row.operation.Challenge.ChallengeID,
		&row.operation.Challenge.ApprovalID, &row.operation.Challenge.SignerKeyID, &row.operation.Challenge.ScopeDigest, &scopeJSON,
		&signingPayload, &row.operation.Challenge.ExpiresAt, &signature, &row.operation.Status, &row.operation.ErrorCode,
		&row.operation.BlockedReason, &row.operation.Revision, &row.operation.CreatedAt, &row.operation.UpdatedAt, &approvedAt,
		&row.operation.Caller.ClientID, &row.operation.Caller.CredentialID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return foundationLifecycleRow{}, cloudfoundation.ErrNotFound
		}
		return foundationLifecycleRow{}, cloudfoundation.ErrUnavailable
	}
	if json.Unmarshal(scopeJSON, &row.operation.Challenge.Scope) != nil {
		return foundationLifecycleRow{}, cloudfoundation.ErrUnavailable
	}
	row.operation.Challenge.SigningCBOR = append([]byte(nil), signingPayload...)
	row.operation.Challenge.IssuedAt = row.operation.CreatedAt
	row.operation.Challenge.Revision = 1
	row.operation.Signature = append([]byte(nil), signature...)
	row.operation.ApprovedAt = approvedAt
	if row.operation.Challenge.Validate() != nil || row.operation.Caller.Validate() != nil || row.operation.Challenge.Scope.OwnerID == "" {
		return foundationLifecycleRow{}, cloudfoundation.ErrUnavailable
	}
	payload, err := row.operation.Challenge.SigningPayload()
	if err != nil || !bytes.Equal(payload, signingPayload) {
		return foundationLifecycleRow{}, cloudfoundation.ErrUnavailable
	}
	return row, nil
}

func readFoundationLifecycle(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, operationID string, lock bool) (foundationLifecycleRow, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	return scanFoundationLifecycle(query.QueryRow(ctx, `SELECT `+foundationLifecycleColumns+` FROM aws_foundation_lifecycle_operations WHERE operation_id=$1`+suffix, operationID))
}
func readFoundationLifecycleByPrepare(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, mutation cloudfoundation.Mutation, lock bool) (foundationLifecycleRow, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	return scanFoundationLifecycle(query.QueryRow(ctx, `SELECT `+foundationLifecycleColumns+` FROM aws_foundation_lifecycle_operations WHERE prepare_client_id=$1 AND prepare_credential_id=$2 AND prepare_idempotency_key=$3`+suffix, mutation.Caller.ClientID, mutation.Caller.CredentialID, mutation.IdempotencyKey))
}
func readFoundationLifecycleByApprove(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, mutation cloudfoundation.Mutation, lock bool) (foundationLifecycleRow, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	return scanFoundationLifecycle(query.QueryRow(ctx, `SELECT `+foundationLifecycleColumns+` FROM aws_foundation_lifecycle_operations WHERE approve_client_id=$1 AND approve_credential_id=$2 AND approve_idempotency_key=$3`+suffix, mutation.Caller.ClientID, mutation.Caller.CredentialID, mutation.IdempotencyKey))
}
