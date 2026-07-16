package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	runtimeRequestStateInProgress = "in_progress"
	runtimeRequestStateCompleted  = "completed"
)

type toolExecutionSnapshot struct {
	SchemaVersion int                      `json:"schema_version"`
	Execution     runtimeapi.ToolExecution `json:"execution"`
}

func (store *Store) BeginRuntimeRequest(ctx context.Context, scope runtimeapi.MutationScope, command runtimeapi.RuntimeRequestCommand) (runtimeapi.RuntimeRequestClaim, error) {
	if err := scope.Validate(); err != nil {
		return runtimeapi.RuntimeRequestClaim{}, err
	}
	validated, err := command.Validated()
	if err != nil {
		return runtimeapi.RuntimeRequestClaim{}, err
	}
	digest, err := validated.Digest()
	if err != nil {
		return runtimeapi.RuntimeRequestClaim{}, err
	}
	callerCredentialID, _ := uuid.Parse(scope.CredentialID)
	clientID := strings.TrimSpace(scope.ClientID)
	leaseMicros := validated.LeaseDuration.Microseconds()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return runtimeapi.RuntimeRequestClaim{}, fmt.Errorf("begin runtime request claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	claim := runtimeapi.RuntimeRequestClaim{RequestID: validated.Request.RequestID, LeaseEpoch: 1}
	err = tx.QueryRow(ctx, `
		INSERT INTO runtime_requests (
		    caller_client_id, caller_credential_id, request_id, request_hash,
		    owner_id, conversation_id, state, lease_epoch, lease_expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,'in_progress',1,clock_timestamp()+($7::bigint*interval '1 microsecond'))
		ON CONFLICT (caller_client_id, caller_credential_id, request_id) DO NOTHING
		RETURNING lease_expires_at`, clientID, callerCredentialID, validated.Request.RequestID, digest[:],
		validated.Request.OwnerID, validated.Request.ConversationID, leaseMicros,
	).Scan(&claim.LeaseExpiresAt)
	if err == nil {
		claim.LeaseExpiresAt = claim.LeaseExpiresAt.UTC()
		if err := tx.Commit(ctx); err != nil {
			return runtimeapi.RuntimeRequestClaim{}, fmt.Errorf("commit runtime request claim: %w", err)
		}
		return claim, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return runtimeapi.RuntimeRequestClaim{}, fmt.Errorf("claim runtime request: %w", err)
	}

	var storedHash, responseJSON []byte
	var state string
	var leaseExpired bool
	var responseSchema int
	if err := tx.QueryRow(ctx, `
		SELECT request_hash, state, lease_epoch,
		       COALESCE(lease_expires_at, 'epoch'::timestamptz),
		       COALESCE(lease_expires_at <= clock_timestamp(), false),
		       COALESCE(response_schema_version, 0), response_json
		FROM runtime_requests
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3
		FOR UPDATE`, clientID, callerCredentialID, validated.Request.RequestID,
	).Scan(&storedHash, &state, &claim.LeaseEpoch, &claim.LeaseExpiresAt, &leaseExpired, &responseSchema, &responseJSON); err != nil {
		return runtimeapi.RuntimeRequestClaim{}, fmt.Errorf("read runtime request claim: %w", err)
	}
	if !bytes.Equal(storedHash, digest[:]) {
		return runtimeapi.RuntimeRequestClaim{}, runtimeapi.ErrRuntimeIdempotency
	}
	if state == runtimeRequestStateCompleted {
		response, err := decodeRuntimeResponseSnapshot(responseSchema, responseJSON)
		if err != nil {
			return runtimeapi.RuntimeRequestClaim{}, err
		}
		claim.Completed = true
		claim.LeaseExpiresAt = time.Time{}
		claim.Response = response
		if err := tx.Commit(ctx); err != nil {
			return runtimeapi.RuntimeRequestClaim{}, fmt.Errorf("commit runtime request replay: %w", err)
		}
		return claim, nil
	}
	if state != runtimeRequestStateInProgress {
		return runtimeapi.RuntimeRequestClaim{}, errors.New("stored runtime request state is invalid")
	}
	if !leaseExpired {
		return runtimeapi.RuntimeRequestClaim{}, runtimeapi.ErrRuntimeRequestInFlight
	}
	if err := tx.QueryRow(ctx, `
		UPDATE runtime_requests
		SET lease_epoch=lease_epoch+1,
		    lease_expires_at=clock_timestamp()+($4::bigint*interval '1 microsecond'),
		    updated_at=clock_timestamp()
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3 AND state='in_progress'
		RETURNING lease_epoch, lease_expires_at`, clientID, callerCredentialID, validated.Request.RequestID, leaseMicros,
	).Scan(&claim.LeaseEpoch, &claim.LeaseExpiresAt); err != nil {
		return runtimeapi.RuntimeRequestClaim{}, fmt.Errorf("reclaim runtime request: %w", err)
	}
	claim.LeaseExpiresAt = claim.LeaseExpiresAt.UTC()
	if err := tx.Commit(ctx); err != nil {
		return runtimeapi.RuntimeRequestClaim{}, fmt.Errorf("commit runtime request reclaim: %w", err)
	}
	return claim, nil
}

func (store *Store) BindRuntimeRequestMemoryMode(ctx context.Context, scope runtimeapi.MutationScope, command runtimeapi.BindRuntimeRequestMemoryModeCommand) (bool, error) {
	if err := scope.Validate(); err != nil {
		return false, err
	}
	validated, err := command.Validated()
	if err != nil {
		return false, err
	}
	clientID := strings.TrimSpace(scope.ClientID)
	callerCredentialID, _ := uuid.Parse(scope.CredentialID)
	var memoryDisabled bool
	err = store.pool.QueryRow(ctx, `
		UPDATE runtime_requests
		SET memory_disabled=COALESCE(memory_disabled, false) OR $4 OR conversation_id='',
		    updated_at=clock_timestamp()
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3
		  AND state='in_progress' AND lease_epoch=$5
		  AND lease_expires_at>clock_timestamp()
		RETURNING memory_disabled`, clientID, callerCredentialID, validated.RequestID,
		validated.MemoryDisabled, validated.LeaseEpoch,
	).Scan(&memoryDisabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, runtimeRequestLeaseError(ctx, store.pool, clientID, callerCredentialID, validated.RequestID)
	}
	if err != nil {
		return false, fmt.Errorf("bind runtime request memory mode: %w", err)
	}
	return memoryDisabled, nil
}

func (store *Store) RenewRuntimeRequest(ctx context.Context, scope runtimeapi.MutationScope, command runtimeapi.RenewRuntimeRequestCommand) (time.Time, error) {
	if err := scope.Validate(); err != nil {
		return time.Time{}, err
	}
	validated, err := command.Validated()
	if err != nil {
		return time.Time{}, err
	}
	clientID := strings.TrimSpace(scope.ClientID)
	callerCredentialID, _ := uuid.Parse(scope.CredentialID)
	var expiresAt time.Time
	err = store.pool.QueryRow(ctx, `
		UPDATE runtime_requests
		SET lease_expires_at=GREATEST(
		        lease_expires_at,
		        clock_timestamp()+($4::bigint*interval '1 microsecond')
		    ),
		    updated_at=clock_timestamp()
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3
		  AND state='in_progress' AND lease_epoch=$5
		  AND lease_expires_at>clock_timestamp()
		RETURNING lease_expires_at`, clientID, callerCredentialID, validated.RequestID,
		validated.LeaseDuration.Microseconds(), validated.LeaseEpoch,
	).Scan(&expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, runtimeRequestLeaseError(ctx, store.pool, clientID, callerCredentialID, validated.RequestID)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("renew runtime request: %w", err)
	}
	return expiresAt.UTC(), nil
}

func (store *Store) ReleaseRuntimeRequest(ctx context.Context, scope runtimeapi.MutationScope, command runtimeapi.ReleaseRuntimeRequestCommand) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	validated, err := command.Validated()
	if err != nil {
		return err
	}
	clientID := strings.TrimSpace(scope.ClientID)
	callerCredentialID, _ := uuid.Parse(scope.CredentialID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin release runtime request: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := tx.Exec(ctx, `
		UPDATE runtime_requests
		SET lease_expires_at=clock_timestamp(), updated_at=clock_timestamp()
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3
		  AND state='in_progress' AND lease_epoch=$4`, clientID, callerCredentialID,
		validated.RequestID, validated.LeaseEpoch)
	if err != nil {
		return fmt.Errorf("release runtime request: %w", err)
	}
	if result.RowsAffected() != 1 {
		return runtimeRequestLeaseError(ctx, tx, clientID, callerCredentialID, validated.RequestID)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE runtime_tool_executions
		SET lease_expires_at=clock_timestamp(), updated_at=clock_timestamp()
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3
		  AND state='in_progress'`, clientID, callerCredentialID, validated.RequestID); err != nil {
		return fmt.Errorf("release runtime request tools: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit runtime request release: %w", err)
	}
	return nil
}

func (store *Store) CompleteRuntimeRequest(ctx context.Context, scope runtimeapi.MutationScope, command runtimeapi.CompleteRuntimeRequestCommand) (runtimeapi.RuntimeResponseSnapshot, error) {
	if err := scope.Validate(); err != nil {
		return runtimeapi.RuntimeResponseSnapshot{}, err
	}
	if err := command.Validate(); err != nil {
		return runtimeapi.RuntimeResponseSnapshot{}, err
	}
	clientID := strings.TrimSpace(scope.ClientID)
	callerCredentialID, _ := uuid.Parse(scope.CredentialID)
	requestID := strings.TrimSpace(command.RequestID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return runtimeapi.RuntimeResponseSnapshot{}, fmt.Errorf("begin complete runtime request: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var ownerID, conversationID, state string
	var storedEpoch int64
	var leaseActive, memoryDisabled, memoryModeBound bool
	var responseSchema int
	var responseJSON []byte
	if err := tx.QueryRow(ctx, `
		SELECT owner_id, conversation_id, state, lease_epoch,
		       COALESCE(lease_expires_at > clock_timestamp(), false),
		       COALESCE(memory_disabled, false), memory_disabled IS NOT NULL,
		       COALESCE(response_schema_version, 0), response_json
		FROM runtime_requests
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3
		FOR UPDATE`, clientID, callerCredentialID, requestID,
	).Scan(&ownerID, &conversationID, &state, &storedEpoch, &leaseActive, &memoryDisabled, &memoryModeBound, &responseSchema, &responseJSON); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return runtimeapi.RuntimeResponseSnapshot{}, runtimeapi.ErrRuntimeRequestNotFound
		}
		return runtimeapi.RuntimeResponseSnapshot{}, fmt.Errorf("read runtime request completion: %w", err)
	}
	if state == runtimeRequestStateCompleted {
		if storedEpoch != command.LeaseEpoch {
			return runtimeapi.RuntimeResponseSnapshot{}, runtimeapi.ErrRuntimeStaleLease
		}
		response, err := decodeRuntimeResponseSnapshot(responseSchema, responseJSON)
		if err != nil {
			return runtimeapi.RuntimeResponseSnapshot{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return runtimeapi.RuntimeResponseSnapshot{}, fmt.Errorf("commit runtime request completion replay: %w", err)
		}
		return response, nil
	}
	if state != runtimeRequestStateInProgress || storedEpoch != command.LeaseEpoch || !leaseActive {
		return runtimeapi.RuntimeResponseSnapshot{}, runtimeapi.ErrRuntimeStaleLease
	}
	var toolInProgress bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1 FROM runtime_tool_executions
		    WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3
		      AND state='in_progress' AND lease_expires_at>clock_timestamp()
		)`, clientID, callerCredentialID, requestID).Scan(&toolInProgress); err != nil {
		return runtimeapi.RuntimeResponseSnapshot{}, fmt.Errorf("check runtime tool completion: %w", err)
	}
	if toolInProgress {
		return runtimeapi.RuntimeResponseSnapshot{}, runtimeapi.ErrRuntimeRequestInFlight
	}
	if !memoryModeBound {
		return runtimeapi.RuntimeResponseSnapshot{}, runtimeapi.ErrRuntimePersistence
	}

	result := command.Result
	if memoryDisabled {
		if command.Conversation.ConversationID != "" || command.ExpectedConversationRevision != 0 {
			return runtimeapi.RuntimeResponseSnapshot{}, runtimeapi.ErrRuntimeRevisionConflict
		}
		result.ConversationRevision = 0
	} else {
		if command.Conversation.OwnerID != ownerID || command.Conversation.ConversationID != conversationID {
			return runtimeapi.RuntimeResponseSnapshot{}, runtimeapi.ErrRuntimeRevisionConflict
		}
		saved, err := saveRuntimeConversationOn(ctx, tx, command.Conversation, command.ExpectedConversationRevision)
		if err != nil {
			return runtimeapi.RuntimeResponseSnapshot{}, err
		}
		result.ConversationRevision = saved.Revision
	}
	response := runtimeapi.RuntimeResponseSnapshot{SchemaVersion: runtimeapi.RuntimeResponseSnapshotSchemaV1, Result: result}
	if err := validateRuntimeResponseSnapshot(response); err != nil {
		return runtimeapi.RuntimeResponseSnapshot{}, err
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return runtimeapi.RuntimeResponseSnapshot{}, fmt.Errorf("encode runtime response snapshot: %w", err)
	}
	update, err := tx.Exec(ctx, `
		UPDATE runtime_requests
		SET state='completed', lease_expires_at=NULL, response_schema_version=$4,
		    response_json=$5, conversation_revision=$6, updated_at=clock_timestamp()
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3
		  AND state='in_progress' AND lease_epoch=$7`, clientID, callerCredentialID, requestID,
		response.SchemaVersion, encoded, result.ConversationRevision, command.LeaseEpoch)
	if err != nil {
		return runtimeapi.RuntimeResponseSnapshot{}, fmt.Errorf("complete runtime request: %w", err)
	}
	if update.RowsAffected() != 1 {
		return runtimeapi.RuntimeResponseSnapshot{}, runtimeapi.ErrRuntimeStaleLease
	}
	if err := tx.Commit(ctx); err != nil {
		return runtimeapi.RuntimeResponseSnapshot{}, fmt.Errorf("commit runtime request completion: %w", err)
	}
	return response, nil
}

func validateRuntimeResponseSnapshot(snapshot runtimeapi.RuntimeResponseSnapshot) error {
	if snapshot.SchemaVersion != runtimeapi.RuntimeResponseSnapshotSchemaV1 || snapshot.Result.ConversationRevision < 0 {
		return errors.New("invalid runtime response snapshot")
	}
	command := runtimeapi.CompleteRuntimeRequestCommand{RequestID: "snapshot", LeaseEpoch: 1, Result: snapshot.Result}
	if err := command.Validate(); err != nil {
		return err
	}
	return nil
}

func decodeRuntimeResponseSnapshot(schemaVersion int, encoded []byte) (runtimeapi.RuntimeResponseSnapshot, error) {
	if schemaVersion != runtimeapi.RuntimeResponseSnapshotSchemaV1 || len(encoded) == 0 {
		return runtimeapi.RuntimeResponseSnapshot{}, errors.New("invalid runtime response snapshot")
	}
	var snapshot runtimeapi.RuntimeResponseSnapshot
	if err := json.Unmarshal(encoded, &snapshot); err != nil {
		return runtimeapi.RuntimeResponseSnapshot{}, errors.New("invalid runtime response snapshot")
	}
	if err := validateRuntimeResponseSnapshot(snapshot); err != nil {
		return runtimeapi.RuntimeResponseSnapshot{}, errors.New("invalid runtime response snapshot")
	}
	return snapshot, nil
}

func (store *Store) BeginToolExecution(ctx context.Context, scope runtimeapi.MutationScope, command runtimeapi.ToolExecutionCommand) (runtimeapi.ToolExecutionClaim, error) {
	if err := scope.Validate(); err != nil {
		return runtimeapi.ToolExecutionClaim{}, err
	}
	validated, err := command.Validated()
	if err != nil {
		return runtimeapi.ToolExecutionClaim{}, err
	}
	digest, err := validated.Digest()
	if err != nil {
		return runtimeapi.ToolExecutionClaim{}, err
	}
	clientID := strings.TrimSpace(scope.ClientID)
	callerCredentialID, _ := uuid.Parse(scope.CredentialID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return runtimeapi.ToolExecutionClaim{}, fmt.Errorf("begin tool execution claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var parentState, ownerID, conversationID string
	var parentLeaseEpoch int64
	var parentLeaseActive, memoryModeBound bool
	if err := tx.QueryRow(ctx, `
		SELECT state, owner_id, conversation_id, lease_epoch,
		       COALESCE(lease_expires_at>clock_timestamp(), false),
		       memory_disabled IS NOT NULL
		FROM runtime_requests
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3
		FOR SHARE`, clientID, callerCredentialID, validated.RequestID,
	).Scan(&parentState, &ownerID, &conversationID, &parentLeaseEpoch, &parentLeaseActive, &memoryModeBound); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return runtimeapi.ToolExecutionClaim{}, runtimeapi.ErrRuntimeRequestNotFound
		}
		return runtimeapi.ToolExecutionClaim{}, fmt.Errorf("read parent runtime request: %w", err)
	}
	if ownerID != validated.OwnerID || conversationID != validated.ConversationID {
		return runtimeapi.ToolExecutionClaim{}, runtimeapi.ErrRuntimeIdempotency
	}
	if parentState != runtimeRequestStateInProgress || parentLeaseEpoch != validated.ParentLeaseEpoch || !parentLeaseActive {
		return runtimeapi.ToolExecutionClaim{}, runtimeapi.ErrRuntimeStaleLease
	}
	if !memoryModeBound {
		return runtimeapi.ToolExecutionClaim{}, runtimeapi.ErrRuntimePersistence
	}

	claim := runtimeapi.ToolExecutionClaim{RequestID: validated.RequestID, ToolCallID: validated.ToolCallID, LeaseEpoch: 1}
	if parentState == runtimeRequestStateInProgress {
		err = tx.QueryRow(ctx, `
			INSERT INTO runtime_tool_executions (
			    caller_client_id, caller_credential_id, request_id, tool_call_id, request_hash,
			    owner_id, conversation_id, tool_name, state, lease_epoch, lease_expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'in_progress',1,clock_timestamp()+($9::bigint*interval '1 microsecond'))
			ON CONFLICT (caller_client_id, caller_credential_id, request_id, tool_call_id) DO NOTHING
			RETURNING lease_expires_at`, clientID, callerCredentialID, validated.RequestID, validated.ToolCallID,
			digest[:], validated.OwnerID, validated.ConversationID, validated.Name, validated.LeaseDuration.Microseconds(),
		).Scan(&claim.LeaseExpiresAt)
		if err == nil {
			claim.LeaseExpiresAt = claim.LeaseExpiresAt.UTC()
			if err := tx.Commit(ctx); err != nil {
				return runtimeapi.ToolExecutionClaim{}, fmt.Errorf("commit tool execution claim: %w", err)
			}
			return claim, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return runtimeapi.ToolExecutionClaim{}, fmt.Errorf("claim tool execution: %w", err)
		}
	}

	var storedHash, resultJSON []byte
	var state string
	var leaseExpired bool
	var resultSchema int
	if err := tx.QueryRow(ctx, `
		SELECT request_hash, state, lease_epoch,
		       COALESCE(lease_expires_at, 'epoch'::timestamptz),
		       COALESCE(lease_expires_at <= clock_timestamp(), false),
		       COALESCE(result_schema_version, 0), result_json
		FROM runtime_tool_executions
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3 AND tool_call_id=$4
		FOR UPDATE`, clientID, callerCredentialID, validated.RequestID, validated.ToolCallID,
	).Scan(&storedHash, &state, &claim.LeaseEpoch, &claim.LeaseExpiresAt, &leaseExpired, &resultSchema, &resultJSON); err != nil {
		if errors.Is(err, pgx.ErrNoRows) && parentState == runtimeRequestStateCompleted {
			return runtimeapi.ToolExecutionClaim{}, runtimeapi.ErrRuntimeStaleLease
		}
		return runtimeapi.ToolExecutionClaim{}, fmt.Errorf("read tool execution claim: %w", err)
	}
	if !bytes.Equal(storedHash, digest[:]) {
		return runtimeapi.ToolExecutionClaim{}, runtimeapi.ErrRuntimeIdempotency
	}
	if state == runtimeRequestStateCompleted {
		execution, err := decodeToolExecutionSnapshot(resultSchema, resultJSON)
		if err != nil {
			return runtimeapi.ToolExecutionClaim{}, err
		}
		claim.Completed = true
		claim.LeaseExpiresAt = time.Time{}
		claim.Execution = execution
		if err := tx.Commit(ctx); err != nil {
			return runtimeapi.ToolExecutionClaim{}, fmt.Errorf("commit tool execution replay: %w", err)
		}
		return claim, nil
	}
	if state != runtimeRequestStateInProgress || parentState != runtimeRequestStateInProgress {
		return runtimeapi.ToolExecutionClaim{}, runtimeapi.ErrRuntimeStaleLease
	}
	if !leaseExpired {
		return runtimeapi.ToolExecutionClaim{}, runtimeapi.ErrRuntimeRequestInFlight
	}
	if err := tx.QueryRow(ctx, `
		UPDATE runtime_tool_executions
		SET lease_epoch=lease_epoch+1,
		    lease_expires_at=clock_timestamp()+($5::bigint*interval '1 microsecond'),
		    updated_at=clock_timestamp()
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3 AND tool_call_id=$4 AND state='in_progress'
		RETURNING lease_epoch, lease_expires_at`, clientID, callerCredentialID, validated.RequestID,
		validated.ToolCallID, validated.LeaseDuration.Microseconds(),
	).Scan(&claim.LeaseEpoch, &claim.LeaseExpiresAt); err != nil {
		return runtimeapi.ToolExecutionClaim{}, fmt.Errorf("reclaim tool execution: %w", err)
	}
	claim.LeaseExpiresAt = claim.LeaseExpiresAt.UTC()
	if err := tx.Commit(ctx); err != nil {
		return runtimeapi.ToolExecutionClaim{}, fmt.Errorf("commit tool execution reclaim: %w", err)
	}
	return claim, nil
}

func (store *Store) RenewToolExecution(ctx context.Context, scope runtimeapi.MutationScope, command runtimeapi.RenewToolExecutionCommand) (time.Time, error) {
	if err := scope.Validate(); err != nil {
		return time.Time{}, err
	}
	validated, err := command.Validated()
	if err != nil {
		return time.Time{}, err
	}
	clientID := strings.TrimSpace(scope.ClientID)
	callerCredentialID, _ := uuid.Parse(scope.CredentialID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return time.Time{}, fmt.Errorf("begin renew tool execution: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := requireActiveParentRuntimeLease(ctx, tx, clientID, callerCredentialID, validated.RequestID, validated.ParentLeaseEpoch); err != nil {
		return time.Time{}, err
	}
	var expiresAt time.Time
	err = tx.QueryRow(ctx, `
		UPDATE runtime_tool_executions
		SET lease_expires_at=GREATEST(
		        lease_expires_at,
		        clock_timestamp()+($5::bigint*interval '1 microsecond')
		    ),
		    updated_at=clock_timestamp()
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3 AND tool_call_id=$4
		  AND state='in_progress' AND lease_epoch=$6
		  AND lease_expires_at>clock_timestamp()
		RETURNING lease_expires_at`, clientID, callerCredentialID, validated.RequestID,
		validated.ToolCallID, validated.LeaseDuration.Microseconds(), validated.LeaseEpoch,
	).Scan(&expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, toolExecutionLeaseError(ctx, tx, clientID, callerCredentialID, validated.RequestID, validated.ToolCallID)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("renew tool execution: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return time.Time{}, fmt.Errorf("commit tool execution renewal: %w", err)
	}
	return expiresAt.UTC(), nil
}

func (store *Store) ReleaseToolExecution(ctx context.Context, scope runtimeapi.MutationScope, command runtimeapi.ReleaseToolExecutionCommand) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	validated, err := command.Validated()
	if err != nil {
		return err
	}
	clientID := strings.TrimSpace(scope.ClientID)
	callerCredentialID, _ := uuid.Parse(scope.CredentialID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin release tool execution: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := requireActiveParentRuntimeLease(ctx, tx, clientID, callerCredentialID, validated.RequestID, validated.ParentLeaseEpoch); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `
		UPDATE runtime_tool_executions
		SET lease_expires_at=clock_timestamp(), updated_at=clock_timestamp()
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3 AND tool_call_id=$4
		  AND state='in_progress' AND lease_epoch=$5`, clientID, callerCredentialID,
		validated.RequestID, validated.ToolCallID, validated.LeaseEpoch)
	if err != nil {
		return fmt.Errorf("release tool execution: %w", err)
	}
	if result.RowsAffected() != 1 {
		return toolExecutionLeaseError(ctx, tx, clientID, callerCredentialID, validated.RequestID, validated.ToolCallID)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tool execution release: %w", err)
	}
	return nil
}

func (store *Store) CompleteToolExecution(ctx context.Context, scope runtimeapi.MutationScope, command runtimeapi.CompleteToolExecutionCommand) (runtimeapi.ToolExecution, error) {
	if err := scope.Validate(); err != nil {
		return runtimeapi.ToolExecution{}, err
	}
	if err := command.Validate(); err != nil {
		return runtimeapi.ToolExecution{}, err
	}
	clientID := strings.TrimSpace(scope.ClientID)
	callerCredentialID, _ := uuid.Parse(scope.CredentialID)
	requestID := strings.TrimSpace(command.RequestID)
	toolCallID := strings.TrimSpace(command.ToolCallID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return runtimeapi.ToolExecution{}, fmt.Errorf("begin complete tool execution: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var parentState string
	var parentLeaseEpoch int64
	var parentLeaseActive bool
	if err := tx.QueryRow(ctx, `
		SELECT state, lease_epoch, COALESCE(lease_expires_at>clock_timestamp(), false)
		FROM runtime_requests
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3
		FOR SHARE`, clientID, callerCredentialID, requestID).Scan(&parentState, &parentLeaseEpoch, &parentLeaseActive); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return runtimeapi.ToolExecution{}, runtimeapi.ErrRuntimeRequestNotFound
		}
		return runtimeapi.ToolExecution{}, fmt.Errorf("read parent runtime request: %w", err)
	}
	var state, storedName string
	var storedEpoch int64
	var leaseActive bool
	var resultSchema int
	var resultJSON []byte
	if err := tx.QueryRow(ctx, `
		SELECT state, tool_name, lease_epoch, COALESCE(lease_expires_at > clock_timestamp(), false),
		       COALESCE(result_schema_version, 0), result_json
		FROM runtime_tool_executions
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3 AND tool_call_id=$4
		FOR UPDATE`, clientID, callerCredentialID, requestID, toolCallID,
	).Scan(&state, &storedName, &storedEpoch, &leaseActive, &resultSchema, &resultJSON); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return runtimeapi.ToolExecution{}, runtimeapi.ErrToolExecutionNotFound
		}
		return runtimeapi.ToolExecution{}, fmt.Errorf("read tool execution completion: %w", err)
	}
	if state == runtimeRequestStateCompleted {
		if storedEpoch != command.LeaseEpoch || parentState != runtimeRequestStateInProgress || parentLeaseEpoch != command.ParentLeaseEpoch || !parentLeaseActive {
			return runtimeapi.ToolExecution{}, runtimeapi.ErrRuntimeStaleLease
		}
		execution, err := decodeToolExecutionSnapshot(resultSchema, resultJSON)
		if err != nil {
			return runtimeapi.ToolExecution{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return runtimeapi.ToolExecution{}, fmt.Errorf("commit tool execution completion replay: %w", err)
		}
		return execution, nil
	}
	if parentState != runtimeRequestStateInProgress || parentLeaseEpoch != command.ParentLeaseEpoch || !parentLeaseActive || state != runtimeRequestStateInProgress || storedEpoch != command.LeaseEpoch || !leaseActive || storedName != strings.TrimSpace(command.Execution.Name) {
		return runtimeapi.ToolExecution{}, runtimeapi.ErrRuntimeStaleLease
	}
	snapshot := toolExecutionSnapshot{SchemaVersion: runtimeapi.ToolExecutionSnapshotSchemaV1, Execution: command.Execution}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return runtimeapi.ToolExecution{}, fmt.Errorf("encode tool execution snapshot: %w", err)
	}
	result, err := tx.Exec(ctx, `
		UPDATE runtime_tool_executions
		SET state='completed', lease_expires_at=NULL, result_schema_version=$5,
		    result_json=$6, updated_at=clock_timestamp()
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3 AND tool_call_id=$4
		  AND state='in_progress' AND lease_epoch=$7`, clientID, callerCredentialID, requestID, toolCallID,
		snapshot.SchemaVersion, encoded, command.LeaseEpoch)
	if err != nil {
		return runtimeapi.ToolExecution{}, fmt.Errorf("complete tool execution: %w", err)
	}
	if result.RowsAffected() != 1 {
		return runtimeapi.ToolExecution{}, runtimeapi.ErrRuntimeStaleLease
	}
	if err := tx.Commit(ctx); err != nil {
		return runtimeapi.ToolExecution{}, fmt.Errorf("commit tool execution completion: %w", err)
	}
	return command.Execution, nil
}

func decodeToolExecutionSnapshot(schemaVersion int, encoded []byte) (runtimeapi.ToolExecution, error) {
	if schemaVersion != runtimeapi.ToolExecutionSnapshotSchemaV1 || len(encoded) == 0 {
		return runtimeapi.ToolExecution{}, errors.New("invalid tool execution snapshot")
	}
	var snapshot toolExecutionSnapshot
	if err := json.Unmarshal(encoded, &snapshot); err != nil || snapshot.SchemaVersion != runtimeapi.ToolExecutionSnapshotSchemaV1 {
		return runtimeapi.ToolExecution{}, errors.New("invalid tool execution snapshot")
	}
	command := runtimeapi.CompleteToolExecutionCommand{
		RequestID: "snapshot", ToolCallID: snapshot.Execution.ToolCallID, ParentLeaseEpoch: 1, LeaseEpoch: 1, Execution: snapshot.Execution,
	}
	if err := command.Validate(); err != nil {
		return runtimeapi.ToolExecution{}, errors.New("invalid tool execution snapshot")
	}
	return snapshot.Execution, nil
}

type runtimeLeaseQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func runtimeRequestLeaseError(ctx context.Context, query runtimeLeaseQuerier, clientID string, credentialID uuid.UUID, requestID string) error {
	var exists bool
	err := query.QueryRow(ctx, `
		SELECT true FROM runtime_requests
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3`,
		clientID, credentialID, requestID).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return runtimeapi.ErrRuntimeRequestNotFound
	}
	if err != nil {
		return fmt.Errorf("read runtime request lease: %w", err)
	}
	return runtimeapi.ErrRuntimeStaleLease
}

func toolExecutionLeaseError(ctx context.Context, query runtimeLeaseQuerier, clientID string, credentialID uuid.UUID, requestID, toolCallID string) error {
	var exists bool
	err := query.QueryRow(ctx, `
		SELECT true FROM runtime_tool_executions
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3 AND tool_call_id=$4`,
		clientID, credentialID, requestID, toolCallID).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return runtimeapi.ErrToolExecutionNotFound
	}
	if err != nil {
		return fmt.Errorf("read tool execution lease: %w", err)
	}
	return runtimeapi.ErrRuntimeStaleLease
}

func requireActiveParentRuntimeLease(ctx context.Context, query runtimeLeaseQuerier, clientID string, credentialID uuid.UUID, requestID string, leaseEpoch int64) error {
	var active bool
	err := query.QueryRow(ctx, `
		SELECT state='in_progress' AND lease_epoch=$4 AND lease_expires_at>clock_timestamp()
		FROM runtime_requests
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3`,
		clientID, credentialID, requestID, leaseEpoch).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return runtimeapi.ErrRuntimeRequestNotFound
	}
	if err != nil {
		return fmt.Errorf("read parent runtime request lease: %w", err)
	}
	if !active {
		return runtimeapi.ErrRuntimeStaleLease
	}
	return nil
}
