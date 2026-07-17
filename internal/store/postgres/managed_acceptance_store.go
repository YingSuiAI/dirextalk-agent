package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/managed"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var managedRequestDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var managedErrorCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)

func (store *Store) FindManagedAcceptanceChallengeReplay(ctx context.Context, mutation managed.Mutation) (managed.ChallengeV1, error) {
	if err := validateManagedMutation(ctx, mutation); err != nil {
		return managed.ChallengeV1{}, err
	}
	value, meta, err := readManagedAcceptance(ctx, store.pool, store.instanceID,
		`prepare_client_id=$2 AND prepare_credential_id=$3 AND prepare_idempotency_key=$4`, false,
		mutation.ClientID, mutation.CredentialID, mutation.IdempotencyKey)
	if err != nil {
		return managed.ChallengeV1{}, err
	}
	if meta.prepareRequestHash != mutation.RequestHash {
		return managed.ChallengeV1{}, managed.ErrRevisionConflict
	}
	return value.Challenge, nil
}

func (store *Store) FindManagedAcceptanceApprovalReplay(ctx context.Context, mutation managed.Mutation) (managed.OperationV1, error) {
	if err := validateManagedMutation(ctx, mutation); err != nil {
		return managed.OperationV1{}, err
	}
	value, meta, err := readManagedAcceptance(ctx, store.pool, store.instanceID,
		`approve_client_id=$2 AND approve_credential_id=$3 AND approve_idempotency_key=$4`, false,
		mutation.ClientID, mutation.CredentialID, mutation.IdempotencyKey)
	if err != nil {
		return managed.OperationV1{}, err
	}
	if meta.approveRequestHash == nil || *meta.approveRequestHash != mutation.RequestHash {
		return managed.OperationV1{}, managed.ErrRevisionConflict
	}
	return value, nil
}

func (store *Store) CreateManagedAcceptanceChallenge(ctx context.Context, mutation managed.Mutation, challenge managed.ChallengeV1) (managed.ChallengeV1, error) {
	if err := validateManagedMutation(ctx, mutation); err != nil {
		return managed.ChallengeV1{}, err
	}
	if challenge.ApprovalID != challenge.Scope.AcceptanceID || challenge.Scope.AgentInstanceID != store.instanceID.String() ||
		challenge.Scope.OwnerID == "" || challenge.Scope.DeploymentID == "" || challenge.Scope.PlanID == "" ||
		challenge.Scope.ConnectionID == "" || challenge.Scope.PlanRevision < 1 || challenge.SignerKeyID == "" {
		return managed.ChallengeV1{}, managed.ErrInvalid
	}
	if _, err := challenge.SigningPayload(); err != nil {
		return managed.ChallengeV1{}, managed.ErrInvalid
	}
	payload, err := json.Marshal(challenge)
	if err != nil {
		return managed.ChallengeV1{}, managed.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return managed.ChallengeV1{}, fmt.Errorf("begin managed acceptance challenge: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `INSERT INTO cloud_managed_acceptance_operations
		(operation_id,agent_instance_id,owner_id,deployment_id,plan_id,plan_revision,connection_id,signer_key_id,
		 challenge_id,approval_id,challenge_json,status,revision,prepare_client_id,prepare_credential_id,
		 prepare_idempotency_key,prepare_request_hash,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$1,$10,'awaiting_approval',1,$11,$12,$13,$14,$15,$15)
		ON CONFLICT (agent_instance_id,prepare_client_id,prepare_credential_id,prepare_idempotency_key) DO NOTHING`,
		challenge.ApprovalID, store.instanceID, challenge.Scope.OwnerID, challenge.Scope.DeploymentID,
		challenge.Scope.PlanID, challenge.Scope.PlanRevision, challenge.Scope.ConnectionID, challenge.SignerKeyID,
		challenge.ChallengeID, payload, mutation.ClientID, mutation.CredentialID, mutation.IdempotencyKey,
		mutation.RequestHash, challenge.IssuedAt.UTC())
	if err != nil {
		if isUniqueViolation(err) {
			return managed.ChallengeV1{}, managed.ErrRevisionConflict
		}
		return managed.ChallengeV1{}, fmt.Errorf("persist managed acceptance challenge: %w", err)
	}
	stored, meta, err := readManagedAcceptance(ctx, tx, store.instanceID,
		`prepare_client_id=$2 AND prepare_credential_id=$3 AND prepare_idempotency_key=$4`, false,
		mutation.ClientID, mutation.CredentialID, mutation.IdempotencyKey)
	if err != nil {
		return managed.ChallengeV1{}, err
	}
	if meta.prepareRequestHash != mutation.RequestHash || stored.OperationID != challenge.ApprovalID ||
		stored.Challenge.ChallengeID != challenge.ChallengeID {
		return managed.ChallengeV1{}, managed.ErrRevisionConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return managed.ChallengeV1{}, fmt.Errorf("commit managed acceptance challenge: %w", err)
	}
	return stored.Challenge, nil
}

func (store *Store) GetManagedAcceptanceChallenge(ctx context.Context, ownerID, challengeID string) (managed.ChallengeV1, error) {
	if ctx == nil || !validManagedOwner(ownerID) || !validManagedUUID(challengeID) {
		return managed.ChallengeV1{}, managed.ErrInvalid
	}
	value, _, err := readManagedAcceptance(ctx, store.pool, store.instanceID,
		`owner_id=$2 AND challenge_id=$3`, false, ownerID, challengeID)
	return value.Challenge, err
}

func (store *Store) ApproveManagedAcceptance(ctx context.Context, mutation managed.Mutation, signature managed.SignatureV1, approvedAt time.Time) (managed.OperationV1, error) {
	if err := validateManagedMutation(ctx, mutation); err != nil {
		return managed.OperationV1{}, err
	}
	if !validManagedUUID(signature.ChallengeID) || !validManagedUUID(signature.ApprovalID) ||
		signature.SignerKeyID == "" || len(signature.Signature) != 64 || approvedAt.IsZero() {
		return managed.OperationV1{}, managed.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return managed.OperationV1{}, fmt.Errorf("begin managed acceptance approval: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replay, meta, replayErr := readManagedAcceptance(ctx, tx, store.instanceID,
		`approve_client_id=$2 AND approve_credential_id=$3 AND approve_idempotency_key=$4`, true,
		mutation.ClientID, mutation.CredentialID, mutation.IdempotencyKey); replayErr == nil {
		if !exactManagedApproval(replay, meta, mutation, signature) {
			return managed.OperationV1{}, managed.ErrRevisionConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return managed.OperationV1{}, fmt.Errorf("commit managed acceptance approval replay: %w", err)
		}
		return replay, nil
	} else if !errors.Is(replayErr, managed.ErrNotFound) {
		return managed.OperationV1{}, replayErr
	}
	value, _, err := readManagedAcceptance(ctx, tx, store.instanceID, `challenge_id=$2`, true, signature.ChallengeID)
	if err != nil {
		return managed.OperationV1{}, err
	}
	if value.Status != managed.StatusAwaitingApproval || value.Revision != 1 ||
		value.OperationID != signature.ApprovalID || value.Challenge.SignerKeyID != signature.SignerKeyID {
		return managed.OperationV1{}, managed.ErrRevisionConflict
	}
	result, err := tx.Exec(ctx, `UPDATE cloud_managed_acceptance_operations SET signature=$3,status='approved',revision=2,
		approve_client_id=$4,approve_credential_id=$5,approve_idempotency_key=$6,approve_request_hash=$7,approved_at=$8,updated_at=$8
		WHERE operation_id=$1 AND agent_instance_id=$2 AND revision=1 AND status='awaiting_approval'`,
		value.OperationID, store.instanceID, signature.Signature, mutation.ClientID, mutation.CredentialID,
		mutation.IdempotencyKey, mutation.RequestHash, approvedAt.UTC())
	if err != nil {
		if isUniqueViolation(err) {
			return managed.OperationV1{}, managed.ErrRevisionConflict
		}
		return managed.OperationV1{}, fmt.Errorf("persist managed acceptance approval: %w", err)
	}
	if result.RowsAffected() != 1 {
		return managed.OperationV1{}, managed.ErrRevisionConflict
	}
	approved, meta, err := readManagedAcceptance(ctx, tx, store.instanceID, `operation_id=$2`, false, value.OperationID)
	if err != nil || !exactManagedApproval(approved, meta, mutation, signature) {
		if err != nil {
			return managed.OperationV1{}, err
		}
		return managed.OperationV1{}, managed.ErrRevisionConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return managed.OperationV1{}, fmt.Errorf("commit managed acceptance approval: %w", err)
	}
	return approved, nil
}

func (store *Store) GetManagedAcceptanceOperation(ctx context.Context, ownerID, operationID string) (managed.OperationV1, error) {
	if ctx == nil || !validManagedOwner(ownerID) || !validManagedUUID(operationID) {
		return managed.OperationV1{}, managed.ErrInvalid
	}
	value, _, err := readManagedAcceptance(ctx, store.pool, store.instanceID,
		`owner_id=$2 AND operation_id=$3`, false, ownerID, operationID)
	return value, err
}

func (store *Store) ListExecutableManagedAcceptances(ctx context.Context, limit int) ([]managed.OperationV1, error) {
	if ctx == nil || limit < 1 || limit > 100 {
		return nil, managed.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, managedAcceptanceSelect+`
		WHERE agent_instance_id=$1 AND status IN ('approved','running')
		ORDER BY updated_at,operation_id LIMIT $2`, store.instanceID, limit)
	if err != nil {
		return nil, fmt.Errorf("list executable managed acceptances: %w", err)
	}
	defer rows.Close()
	var out []managed.OperationV1
	for rows.Next() {
		value, _, err := scanManagedAcceptance(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func (store *Store) TransitionManagedAcceptance(ctx context.Context, operationID string, expectedRevision int64, next managed.Status, code, summary string) (managed.OperationV1, error) {
	if ctx == nil || !validManagedUUID(operationID) || expectedRevision < 1 {
		return managed.OperationV1{}, managed.ErrInvalid
	}
	code = strings.TrimSpace(code)
	summary = security.RedactText(strings.TrimSpace(summary))
	if next == managed.StatusFailedTerminal {
		if !managedErrorCode.MatchString(code) || summary == "" || len(summary) > 4096 {
			return managed.OperationV1{}, managed.ErrInvalid
		}
	} else if code != "" || summary != "" {
		return managed.OperationV1{}, managed.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return managed.OperationV1{}, fmt.Errorf("begin managed acceptance transition: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, _, err := readManagedAcceptance(ctx, tx, store.instanceID, `operation_id=$2`, true, operationID)
	if err != nil {
		return managed.OperationV1{}, err
	}
	if current.Revision != expectedRevision {
		return managed.OperationV1{}, managed.ErrRevisionConflict
	}
	if current.Status == next {
		if current.ErrorCode != code || current.ErrorSummary != summary {
			return managed.OperationV1{}, managed.ErrRevisionConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return managed.OperationV1{}, err
		}
		return current, nil
	}
	if !validManagedTransition(current.Status, next) {
		return managed.OperationV1{}, managed.ErrRevisionConflict
	}
	result, err := tx.Exec(ctx, `UPDATE cloud_managed_acceptance_operations
		SET status=$4,error_code=$5,error_summary=$6,revision=revision+1,updated_at=clock_timestamp()
		WHERE operation_id=$1 AND agent_instance_id=$2 AND revision=$3 AND status=$7`,
		operationID, store.instanceID, expectedRevision, next, code, summary, current.Status)
	if err != nil {
		return managed.OperationV1{}, fmt.Errorf("transition managed acceptance: %w", err)
	}
	if result.RowsAffected() != 1 {
		return managed.OperationV1{}, managed.ErrRevisionConflict
	}
	updated, _, err := readManagedAcceptance(ctx, tx, store.instanceID, `operation_id=$2`, false, operationID)
	if err != nil {
		return managed.OperationV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return managed.OperationV1{}, fmt.Errorf("commit managed acceptance transition: %w", err)
	}
	return updated, nil
}

const managedAcceptanceSelect = `SELECT operation_id,challenge_json,status,signature,revision,error_code,error_summary,
	created_at,updated_at,approved_at,prepare_request_hash,approve_client_id,approve_credential_id,
	approve_idempotency_key,approve_request_hash FROM cloud_managed_acceptance_operations`

type managedAcceptanceMeta struct {
	challengeJSON       []byte
	prepareRequestHash  string
	approveClientID     *string
	approveCredentialID *uuid.UUID
	approveKey          *uuid.UUID
	approveRequestHash  *string
}

type managedAcceptanceScanner interface{ Scan(...any) error }

func scanManagedAcceptance(scanner managedAcceptanceScanner) (managed.OperationV1, managedAcceptanceMeta, error) {
	var value managed.OperationV1
	var meta managedAcceptanceMeta
	var approvedAt *time.Time
	if err := scanner.Scan(&value.OperationID, &meta.challengeJSON, &value.Status, &value.Signature, &value.Revision,
		&value.ErrorCode, &value.ErrorSummary, &value.CreatedAt, &value.UpdatedAt, &approvedAt,
		&meta.prepareRequestHash, &meta.approveClientID, &meta.approveCredentialID, &meta.approveKey, &meta.approveRequestHash); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return value, meta, managed.ErrNotFound
		}
		return value, meta, err
	}
	if json.Unmarshal(meta.challengeJSON, &value.Challenge) != nil {
		return value, meta, managed.ErrInvalid
	}
	value.ApprovedAt = approvedAt
	return value, meta, nil
}

type managedQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readManagedAcceptance(ctx context.Context, query managedQuery, instanceID uuid.UUID, predicate string, lock bool, args ...any) (managed.OperationV1, managedAcceptanceMeta, error) {
	sql := managedAcceptanceSelect + ` WHERE agent_instance_id=$1 AND ` + predicate
	if lock {
		sql += ` FOR UPDATE`
	}
	return scanManagedAcceptance(query.QueryRow(ctx, sql, append([]any{instanceID}, args...)...))
}

func exactManagedApproval(value managed.OperationV1, meta managedAcceptanceMeta, mutation managed.Mutation, signature managed.SignatureV1) bool {
	return value.Status != managed.StatusAwaitingApproval && value.OperationID == signature.ApprovalID &&
		value.Challenge.ChallengeID == signature.ChallengeID && value.Challenge.SignerKeyID == signature.SignerKeyID &&
		bytes.Equal(value.Signature, signature.Signature) && meta.approveClientID != nil && *meta.approveClientID == mutation.ClientID &&
		meta.approveCredentialID != nil && meta.approveCredentialID.String() == mutation.CredentialID &&
		meta.approveKey != nil && meta.approveKey.String() == mutation.IdempotencyKey &&
		meta.approveRequestHash != nil && *meta.approveRequestHash == mutation.RequestHash
}

func validateManagedMutation(ctx context.Context, mutation managed.Mutation) error {
	client := strings.TrimSpace(mutation.ClientID)
	if ctx == nil || client == "" || client != mutation.ClientID || len(client) > 255 || security.ContainsLikelySecret(client) ||
		!validManagedUUID(mutation.CredentialID) || !validManagedUUID(mutation.IdempotencyKey) ||
		!managedRequestDigest.MatchString(mutation.RequestHash) {
		return managed.ErrInvalid
	}
	return nil
}

func validManagedOwner(owner string) bool {
	trimmed := strings.TrimSpace(owner)
	return trimmed != "" && trimmed == owner && len(owner) <= 255 && !security.ContainsLikelySecret(owner)
}
func validManagedUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed != uuid.Nil && parsed.String() == strings.ToLower(value)
}
func validManagedTransition(current, next managed.Status) bool {
	return (current == managed.StatusApproved && next == managed.StatusRunning) ||
		(current == managed.StatusRunning && (next == managed.StatusSucceeded || next == managed.StatusFailedTerminal))
}
