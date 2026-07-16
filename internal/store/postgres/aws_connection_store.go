package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var _ cloudapp.FoundationLaunchHandoffRepository = (*Store)(nil)

func (store *Store) PutAWSIdentityEvidence(ctx context.Context, value cloudapp.AWSIdentityEvidence) error {
	if store == nil || validateAWSIdentityEvidence(value, store.instanceID) != nil {
		return cloudapp.ErrInvalid
	}
	result, err := store.pool.Exec(ctx, `
		INSERT INTO aws_identity_previews
		    (bootstrap_session_id, session_revision, agent_instance_id, owner_id, target_id,
		     account_id, principal_arn, principal_id, region, root_identity, observed_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (bootstrap_session_id) DO UPDATE
		SET observed_at=EXCLUDED.observed_at, expires_at=EXCLUDED.expires_at
		WHERE aws_identity_previews.session_revision=EXCLUDED.session_revision
		  AND aws_identity_previews.agent_instance_id=EXCLUDED.agent_instance_id
		  AND aws_identity_previews.owner_id=EXCLUDED.owner_id
		  AND aws_identity_previews.target_id=EXCLUDED.target_id
		  AND aws_identity_previews.account_id=EXCLUDED.account_id
		  AND aws_identity_previews.principal_arn=EXCLUDED.principal_arn
		  AND aws_identity_previews.principal_id=EXCLUDED.principal_id
		  AND aws_identity_previews.region=EXCLUDED.region
		  AND aws_identity_previews.root_identity=EXCLUDED.root_identity`,
		value.BootstrapSessionID, value.SessionRevision, value.AgentInstanceID, value.OwnerID, value.TargetID,
		value.Identity.AccountID, value.Identity.PrincipalARN, value.Identity.PrincipalID, value.Identity.Region,
		value.Identity.RootIdentity, value.ObservedAt.UTC(), value.ExpiresAt.UTC())
	if err != nil {
		return cloudapp.ErrUnavailable
	}
	if result.RowsAffected() != 1 {
		return cloudapp.ErrRevisionConflict
	}
	return nil
}

func (store *Store) BeginFoundationOperation(ctx context.Context, scope cloudapp.MutationScope, intent cloudapp.FoundationOperationIntent) (cloudapp.FoundationOperation, bool, error) {
	if store == nil || scope.Validate() != nil || validateFoundationIntent(intent) != nil || intent.Caller != scope {
		return cloudapp.FoundationOperation{}, false, cloudapp.ErrInvalid
	}
	operationID, _ := uuid.Parse(intent.OperationID)
	credentialID, _ := uuid.Parse(scope.CredentialID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return cloudapp.FoundationOperation{}, false, cloudapp.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := tx.Exec(ctx, `
		INSERT INTO aws_foundation_operations
		    (operation_id, agent_instance_id, caller_client_id, caller_credential_id, idempotency_key,
		     request_hash, owner_id, bootstrap_session_id, plan_id, connection_id, account_id, region,
		     expected_credential_generation, expected_session_revision, reaper_image_uri, status, revision)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'intent',1)
		ON CONFLICT (caller_client_id, caller_credential_id, idempotency_key) DO NOTHING`,
		operationID, store.instanceID, strings.TrimSpace(scope.ClientID), credentialID, intent.IdempotencyKey,
		intent.RequestHash[:], intent.OwnerID, intent.BootstrapSessionID, intent.PlanID, intent.ConnectionID,
		intent.AccountID, intent.Region, intent.ExpectedCredentialGeneration, intent.ExpectedSessionRevision, intent.ReaperImageURI)
	if err != nil {
		return cloudapp.FoundationOperation{}, false, cloudapp.ErrUnavailable
	}
	created := result.RowsAffected() == 1
	var operation cloudapp.FoundationOperation
	if created {
		operation, err = readFoundationOperation(ctx, tx, intent.OperationID, true)
	} else {
		operation, err = readFoundationOperationByIdempotency(ctx, tx, scope, intent.IdempotencyKey)
		if err == nil && !bytes.Equal(operation.RequestHash[:], intent.RequestHash[:]) {
			err = idempotency.ErrConflict
		}
	}
	if err != nil {
		return cloudapp.FoundationOperation{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return cloudapp.FoundationOperation{}, false, cloudapp.ErrUnavailable
	}
	return operation, created, nil
}

func (store *Store) ListRecoverableFoundationOperations(ctx context.Context, limit int) ([]cloudapp.FoundationOperation, error) {
	if store == nil || store.pool == nil || limit < 1 || limit > 256 {
		return nil, cloudapp.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, `SELECT `+foundationOperationColumns+` FROM aws_foundation_operations
		WHERE agent_instance_id=$1 AND status IN ('intent','running','failed_retriable')
		ORDER BY updated_at, operation_id LIMIT $2`, store.instanceID, limit)
	if err != nil {
		return nil, cloudapp.ErrUnavailable
	}
	defer rows.Close()
	result := make([]cloudapp.FoundationOperation, 0, limit)
	for rows.Next() {
		operation, scanErr := scanFoundationOperation(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, operation)
	}
	if rows.Err() != nil {
		return nil, cloudapp.ErrUnavailable
	}
	return result, nil
}

// ListPendingFoundationLaunchHandoffs treats each succeeded Foundation
// operation as a durable outbox until the exact Plan/Approval/Connection launch
// intent exists. A valid Plan can have exactly one accepted Approval; missing
// or ambiguous approval facts fail the scan closed instead of guessing.
func (store *Store) ListPendingFoundationLaunchHandoffs(ctx context.Context, limit int) ([]cloudapp.FoundationLaunchHandoff, error) {
	if store == nil || store.pool == nil || limit < 1 || limit > 256 {
		return nil, cloudapp.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, `
		SELECT operation.caller_client_id, operation.caller_credential_id,
		       operation.owner_id, operation.plan_id, accepted.approval_id
		FROM aws_foundation_operations AS operation
		CROSS JOIN LATERAL (
			SELECT CASE WHEN count(*)=1 THEN min(approval.approval_id::text)::uuid END AS approval_id
			FROM cloud_approvals AS approval
			WHERE approval.agent_instance_id=operation.agent_instance_id
			  AND approval.owner_id=operation.owner_id
			  AND approval.plan_id=operation.plan_id
		) AS accepted
		WHERE operation.agent_instance_id=$1 AND operation.status='succeeded'
		  AND NOT EXISTS (
			SELECT 1 FROM cloud_launch_operations AS launch
			WHERE launch.agent_instance_id=operation.agent_instance_id
			  AND launch.owner_id=operation.owner_id
			  AND launch.plan_id=operation.plan_id
			  AND launch.approval_id=accepted.approval_id
			  AND launch.connection_id=operation.connection_id
		  )
		ORDER BY operation.updated_at, operation.operation_id
		LIMIT $2`, store.instanceID, limit)
	if err != nil {
		return nil, cloudapp.ErrUnavailable
	}
	defer rows.Close()
	result := make([]cloudapp.FoundationLaunchHandoff, 0, limit)
	for rows.Next() {
		var value cloudapp.FoundationLaunchHandoff
		var credentialID, planID, approvalID uuid.UUID
		if err := rows.Scan(&value.Caller.ClientID, &credentialID, &value.OwnerID, &planID, &approvalID); err != nil {
			return nil, cloudapp.ErrUnavailable
		}
		value.Caller.CredentialID = credentialID.String()
		value.PlanID, value.ApprovalID = planID.String(), approvalID.String()
		if value.Caller.Validate() != nil || strings.TrimSpace(value.OwnerID) == "" {
			return nil, cloudapp.ErrUnavailable
		}
		result = append(result, value)
	}
	if rows.Err() != nil {
		return nil, cloudapp.ErrUnavailable
	}
	return result, nil
}

func (store *Store) MarkFoundationOperationRunning(ctx context.Context, operationID string, expectedRevision int64) (cloudapp.FoundationOperation, error) {
	if store == nil || expectedRevision < 1 {
		return cloudapp.FoundationOperation{}, cloudapp.ErrInvalid
	}
	parsed, err := uuid.Parse(operationID)
	if err != nil || parsed == uuid.Nil {
		return cloudapp.FoundationOperation{}, cloudapp.ErrInvalid
	}
	row := store.pool.QueryRow(ctx, `
		UPDATE aws_foundation_operations SET status='running', revision=revision+1, redacted_error=NULL, updated_at=clock_timestamp()
		WHERE operation_id=$1 AND revision=$2 AND status IN ('intent','failed_retriable')
		RETURNING `+foundationOperationColumns, parsed, expectedRevision)
	operation, err := scanFoundationOperation(row)
	if errors.Is(err, cloudapp.ErrNotFound) {
		return cloudapp.FoundationOperation{}, cloudapp.ErrRevisionConflict
	}
	return operation, err
}

func (store *Store) FinalizeFoundationOperation(ctx context.Context, operationID string, expectedRevision int64, sessionID string, expectedSessionRevision uint64, connection cloudapp.Connection) (cloudapp.FoundationOperation, error) {
	parsed, err := uuid.Parse(sessionID)
	if err != nil || parsed == uuid.Nil || expectedSessionRevision == 0 {
		return cloudapp.FoundationOperation{}, cloudapp.ErrInvalid
	}
	return store.completeFoundationOperation(ctx, operationID, expectedRevision, sessionID, expectedSessionRevision, connection)
}

func (store *Store) completeFoundationOperation(ctx context.Context, operationID string, expectedRevision int64, sessionID string, expectedSessionRevision uint64, connection cloudapp.Connection) (cloudapp.FoundationOperation, error) {
	if store == nil || expectedRevision < 1 || validateCloudConnection(connection) != nil {
		return cloudapp.FoundationOperation{}, cloudapp.ErrInvalid
	}
	parsed, err := uuid.Parse(operationID)
	if err != nil || parsed == uuid.Nil {
		return cloudapp.FoundationOperation{}, cloudapp.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return cloudapp.FoundationOperation{}, cloudapp.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := readFoundationOperation(ctx, tx, operationID, true)
	if err != nil {
		return cloudapp.FoundationOperation{}, err
	}
	if current.Revision != expectedRevision || current.Status != cloudapp.FoundationOperationRunning || current.ConnectionID != connection.ConnectionID ||
		current.OwnerID != connection.OwnerID || current.AccountID != connection.AccountID || current.Region != connection.Region {
		return cloudapp.FoundationOperation{}, cloudapp.ErrRevisionConflict
	}
	var bootstrapKeyHandle uuid.UUID
	if sessionID != "" {
		if current.BootstrapSessionID != sessionID {
			return cloudapp.FoundationOperation{}, cloudapp.ErrRevisionConflict
		}
		if err := tx.QueryRow(ctx, `
			SELECT key_handle FROM secret_bootstrap_sessions
			WHERE session_id=$1 AND revision=$2 AND status='uploaded' AND expires_at>clock_timestamp()
			  AND creator_client_id=(SELECT caller_client_id FROM aws_foundation_operations WHERE operation_id=$3)
			FOR UPDATE`, sessionID, expectedSessionRevision, parsed).Scan(&bootstrapKeyHandle); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return cloudapp.FoundationOperation{}, cloudapp.ErrRevisionConflict
			}
			return cloudapp.FoundationOperation{}, cloudapp.ErrUnavailable
		}
	}
	connectionID, _ := uuid.Parse(connection.ConnectionID)
	result, err := tx.Exec(ctx, `
		INSERT INTO cloud_connections
		    (connection_id, agent_instance_id, owner_id, account_id, region, control_role_arn,
		     foundation_stack_id, credential_generation, status, revision)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (connection_id) DO NOTHING`, connectionID, store.instanceID, connection.OwnerID,
		connection.AccountID, connection.Region, connection.ControlRoleARN, connection.FoundationStack,
		current.ExpectedCredentialGeneration+1, connection.Status, connection.Revision)
	if err != nil {
		return cloudapp.FoundationOperation{}, cloudapp.ErrUnavailable
	}
	if result.RowsAffected() == 0 {
		existing, loadErr := readCloudConnection(ctx, tx, connection.ConnectionID)
		if loadErr != nil || existing != connection {
			return cloudapp.FoundationOperation{}, cloudapp.ErrRevisionConflict
		}
	}
	responseJSON, _ := json.Marshal(connection)
	row := tx.QueryRow(ctx, `
		UPDATE aws_foundation_operations
		SET status='succeeded', connection_id=$3, response_json=$4, redacted_error=NULL,
		    revision=revision+1, updated_at=clock_timestamp()
		WHERE operation_id=$1 AND revision=$2 AND status='running'
		RETURNING `+foundationOperationColumns, parsed, expectedRevision, connectionID, responseJSON)
	completed, err := scanFoundationOperation(row)
	if err != nil {
		return cloudapp.FoundationOperation{}, cloudapp.ErrRevisionConflict
	}
	if sessionID != "" {
		result, updateErr := tx.Exec(ctx, `
			UPDATE secret_bootstrap_sessions
			SET status='consumed', revision=revision+1, upload_token_hash=NULL,
			    idempotency_token_nonce=NULL, idempotency_token_ciphertext=NULL,
			    key_handle=NULL, envelope_schema=NULL, client_public_key=NULL,
			    envelope_nonce=NULL, envelope_ciphertext=NULL, updated_at=clock_timestamp()
			WHERE session_id=$1 AND revision=$2 AND status='uploaded' AND key_handle=$3
			  AND creator_client_id=(SELECT caller_client_id FROM aws_foundation_operations WHERE operation_id=$4)`,
			sessionID, expectedSessionRevision, bootstrapKeyHandle, parsed)
		if updateErr != nil || result.RowsAffected() != 1 {
			return cloudapp.FoundationOperation{}, cloudapp.ErrRevisionConflict
		}
		if result, deleteErr := tx.Exec(ctx, `DELETE FROM secret_bootstrap_keys WHERE key_handle=$1 AND session_id=$2`, bootstrapKeyHandle, sessionID); deleteErr != nil || result.RowsAffected() != 1 {
			return cloudapp.FoundationOperation{}, cloudapp.ErrUnavailable
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return cloudapp.FoundationOperation{}, cloudapp.ErrUnavailable
	}
	return completed, nil
}

func (store *Store) FailFoundationOperation(ctx context.Context, operationID string, expectedRevision int64, blocked bool, unsafeError string) (cloudapp.FoundationOperation, error) {
	parsed, err := uuid.Parse(operationID)
	if store == nil || err != nil || parsed == uuid.Nil || expectedRevision < 1 {
		return cloudapp.FoundationOperation{}, cloudapp.ErrInvalid
	}
	statusValue := cloudapp.FoundationOperationFailedRetriable
	if blocked {
		statusValue = cloudapp.FoundationOperationDestroyBlocked
	}
	redacted := security.RedactText(strings.TrimSpace(unsafeError))
	if len(redacted) > 2048 {
		redacted = redacted[:2048]
	}
	row := store.pool.QueryRow(ctx, `
		UPDATE aws_foundation_operations SET status=$3, redacted_error=$4, revision=revision+1, updated_at=clock_timestamp()
		WHERE operation_id=$1 AND revision=$2 AND status='running'
		RETURNING `+foundationOperationColumns, parsed, expectedRevision, statusValue, redacted)
	operation, err := scanFoundationOperation(row)
	if errors.Is(err, cloudapp.ErrNotFound) {
		return cloudapp.FoundationOperation{}, cloudapp.ErrRevisionConflict
	}
	return operation, err
}

const foundationOperationColumns = `operation_id, caller_client_id, caller_credential_id, idempotency_key, request_hash, owner_id, bootstrap_session_id,
	plan_id, connection_id, account_id, region, expected_credential_generation, expected_session_revision, reaper_image_uri,
	status, response_json, redacted_error, revision, created_at, updated_at`

func readFoundationOperation(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, operationID string, forUpdate bool) (cloudapp.FoundationOperation, error) {
	suffix := ""
	if forUpdate {
		suffix = " FOR UPDATE"
	}
	return scanFoundationOperation(query.QueryRow(ctx, `SELECT `+foundationOperationColumns+` FROM aws_foundation_operations WHERE operation_id=$1`+suffix, operationID))
}

func readFoundationOperationByIdempotency(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, scope cloudapp.MutationScope, key string) (cloudapp.FoundationOperation, error) {
	return scanFoundationOperation(query.QueryRow(ctx, `SELECT `+foundationOperationColumns+` FROM aws_foundation_operations
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND idempotency_key=$3 FOR UPDATE`,
		strings.TrimSpace(scope.ClientID), scope.CredentialID, key))
}

func scanFoundationOperation(row rowScanner) (cloudapp.FoundationOperation, error) {
	var operation cloudapp.FoundationOperation
	var callerCredentialID uuid.UUID
	var requestHash, responseJSON []byte
	var redactedError *string
	if err := row.Scan(&operation.OperationID, &operation.Caller.ClientID, &callerCredentialID, &operation.IdempotencyKey, &requestHash, &operation.OwnerID,
		&operation.BootstrapSessionID, &operation.PlanID, &operation.ConnectionID, &operation.AccountID,
		&operation.Region, &operation.ExpectedCredentialGeneration, &operation.ExpectedSessionRevision, &operation.ReaperImageURI,
		&operation.Status, &responseJSON, &redactedError, &operation.Revision, &operation.CreatedAt, &operation.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return cloudapp.FoundationOperation{}, cloudapp.ErrNotFound
		}
		return cloudapp.FoundationOperation{}, cloudapp.ErrUnavailable
	}
	operation.Caller.CredentialID = callerCredentialID.String()
	if len(requestHash) != len(operation.RequestHash) {
		return cloudapp.FoundationOperation{}, cloudapp.ErrUnavailable
	}
	copy(operation.RequestHash[:], requestHash)
	if len(responseJSON) > 0 {
		var connection cloudapp.Connection
		if err := json.Unmarshal(responseJSON, &connection); err != nil || validateCloudConnection(connection) != nil {
			return cloudapp.FoundationOperation{}, cloudapp.ErrUnavailable
		}
		operation.Connection = &connection
	}
	if redactedError != nil {
		operation.RedactedError = *redactedError
	}
	operation.CreatedAt, operation.UpdatedAt = operation.CreatedAt.UTC(), operation.UpdatedAt.UTC()
	return operation, nil
}

func readCloudConnection(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, connectionID string) (cloudapp.Connection, error) {
	var value cloudapp.Connection
	if err := query.QueryRow(ctx, `SELECT connection_id, owner_id, account_id, region, control_role_arn,
		foundation_stack_id, status, revision FROM cloud_connections WHERE connection_id=$1`, connectionID).Scan(
		&value.ConnectionID, &value.OwnerID, &value.AccountID, &value.Region, &value.ControlRoleARN,
		&value.FoundationStack, &value.Status, &value.Revision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return cloudapp.Connection{}, cloudapp.ErrNotFound
		}
		return cloudapp.Connection{}, cloudapp.ErrUnavailable
	}
	return value, nil
}

func validateFoundationIntent(value cloudapp.FoundationOperationIntent) error {
	for _, identifier := range []string{value.OperationID, value.IdempotencyKey, value.BootstrapSessionID, value.PlanID, value.ConnectionID} {
		if parsed, err := uuid.Parse(identifier); err != nil || parsed == uuid.Nil {
			return cloudapp.ErrInvalid
		}
	}
	var zero [32]byte
	if value.Caller.Validate() != nil || value.ExpectedSessionRevision == 0 || bytes.Equal(value.RequestHash[:], zero[:]) || strings.TrimSpace(value.OwnerID) == "" ||
		!awsAccountPattern.MatchString(value.AccountID) || !awsRegionPattern.MatchString(value.Region) ||
		!awsImagePattern.MatchString(value.ReaperImageURI) || strings.Contains(strings.ToLower(value.ReaperImageURI), ":latest@") ||
		strings.Contains(strings.ToLower(value.ReaperImageURI), ":v1.0.3@") {
		return cloudapp.ErrInvalid
	}
	return nil
}

func validateCloudConnection(value cloudapp.Connection) error {
	parsed, err := uuid.Parse(value.ConnectionID)
	if err != nil || parsed == uuid.Nil || parsed.String() != value.ConnectionID || strings.TrimSpace(value.OwnerID) == "" || !awsAccountPattern.MatchString(value.AccountID) ||
		!awsRegionPattern.MatchString(value.Region) || strings.TrimSpace(value.ControlRoleARN) == "" ||
		strings.TrimSpace(value.FoundationStack) == "" || value.Status != "active" || value.Revision != 1 {
		return cloudapp.ErrInvalid
	}
	return nil
}

func (store *Store) GetAWSIdentityEvidence(ctx context.Context, sessionID string, revision uint64) (cloudapp.AWSIdentityEvidence, error) {
	parsed, err := uuid.Parse(sessionID)
	if store == nil || err != nil || parsed == uuid.Nil || revision == 0 {
		return cloudapp.AWSIdentityEvidence{}, cloudapp.ErrInvalid
	}
	var value cloudapp.AWSIdentityEvidence
	value.BootstrapSessionID = sessionID
	if err := store.pool.QueryRow(ctx, `
		SELECT session_revision, agent_instance_id, owner_id, target_id, account_id, principal_arn,
		       principal_id, region, root_identity, observed_at, expires_at
		FROM aws_identity_previews WHERE bootstrap_session_id=$1 AND session_revision=$2`, parsed, revision).Scan(
		&value.SessionRevision, &value.AgentInstanceID, &value.OwnerID, &value.TargetID,
		&value.Identity.AccountID, &value.Identity.PrincipalARN, &value.Identity.PrincipalID,
		&value.Identity.Region, &value.Identity.RootIdentity, &value.ObservedAt, &value.ExpiresAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return cloudapp.AWSIdentityEvidence{}, cloudapp.ErrNotFound
		}
		return cloudapp.AWSIdentityEvidence{}, cloudapp.ErrUnavailable
	}
	value.ObservedAt = value.ObservedAt.UTC()
	value.ExpiresAt = value.ExpiresAt.UTC()
	if validateAWSIdentityEvidence(value, store.instanceID) != nil {
		return cloudapp.AWSIdentityEvidence{}, cloudapp.ErrUnavailable
	}
	return value, nil
}

func validateAWSIdentityEvidence(value cloudapp.AWSIdentityEvidence, instanceID uuid.UUID) error {
	sessionID, err := uuid.Parse(value.BootstrapSessionID)
	if err != nil || sessionID == uuid.Nil || value.SessionRevision == 0 || value.AgentInstanceID != instanceID.String() ||
		strings.TrimSpace(value.OwnerID) == "" || strings.TrimSpace(value.TargetID) == "" ||
		!awsAccountPattern.MatchString(value.Identity.AccountID) || !awsRegionPattern.MatchString(value.Identity.Region) ||
		strings.TrimSpace(value.Identity.PrincipalARN) == "" || strings.TrimSpace(value.Identity.PrincipalID) == "" ||
		value.ObservedAt.IsZero() || value.ExpiresAt.IsZero() || !value.ObservedAt.Before(value.ExpiresAt) {
		return cloudapp.ErrInvalid
	}
	return nil
}
