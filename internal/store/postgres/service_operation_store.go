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

	serviceoperation "github.com/YingSuiAI/dirextalk-agent/internal/cloud/serviceoperation"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var serviceOperationRequestDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func (store *Store) FindServiceOperationChallengeReplay(ctx context.Context, mutation serviceoperation.Mutation) (serviceoperation.ChallengeV1, error) {
	if err := validateServiceOperationMutation(ctx, mutation); err != nil {
		return serviceoperation.ChallengeV1{}, err
	}
	value, meta, err := readServiceOperation(ctx, store.pool, store.instanceID,
		`prepare_client_id=$2 AND prepare_credential_id=$3 AND prepare_idempotency_key=$4`, false,
		mutation.ClientID, mutation.CredentialID, mutation.IdempotencyKey)
	if err != nil {
		return serviceoperation.ChallengeV1{}, err
	}
	if meta.prepareHash != mutation.RequestHash {
		return serviceoperation.ChallengeV1{}, serviceoperation.ErrRevisionConflict
	}
	return value.Challenge, nil
}

func (store *Store) CreateServiceOperationChallenge(ctx context.Context, mutation serviceoperation.Mutation, challenge serviceoperation.ChallengeV1) (serviceoperation.ChallengeV1, error) {
	if err := validateServiceOperationMutation(ctx, mutation); err != nil {
		return serviceoperation.ChallengeV1{}, err
	}
	if challenge.Scope.AgentInstanceID != store.instanceID.String() {
		return serviceoperation.ChallengeV1{}, serviceoperation.ErrInvalid
	}
	if _, err := challenge.SigningPayload(); err != nil {
		return serviceoperation.ChallengeV1{}, serviceoperation.ErrInvalid
	}
	encoded, err := json.Marshal(challenge)
	if err != nil {
		return serviceoperation.ChallengeV1{}, serviceoperation.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return serviceoperation.ChallengeV1{}, fmt.Errorf("begin service operation challenge: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	scope := challenge.Scope
	_, err = tx.Exec(ctx, `INSERT INTO cloud_service_operations
		(operation_id,agent_instance_id,owner_id,deployment_id,deployment_revision,connection_id,connection_revision,
		 plan_id,plan_revision,plan_hash,recipe_id,recipe_revision,recipe_digest,scope_digest,challenge_id,signer_key_id,
		 challenge_json,status,current_phase,revision,prepare_client_id,prepare_credential_id,prepare_idempotency_key,
		 prepare_request_hash,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'awaiting_approval','restart',1,$18,$19,$20,$21,$22,$22)
		ON CONFLICT (agent_instance_id,prepare_client_id,prepare_credential_id,prepare_idempotency_key) DO NOTHING`,
		challenge.OperationID, store.instanceID, scope.OwnerID, scope.DeploymentID, scope.DeploymentRevision,
		scope.ConnectionID, scope.ConnectionRevision, scope.PlanID, scope.PlanRevision, scope.PlanHash,
		scope.RecipeID, scope.RecipeRevision, scope.RecipeDigest, challenge.ScopeDigest, challenge.ChallengeID,
		challenge.SignerKeyID, encoded, mutation.ClientID, mutation.CredentialID, mutation.IdempotencyKey,
		mutation.RequestHash, challenge.IssuedAt.UTC())
	if err != nil {
		if isUniqueViolation(err) {
			return serviceoperation.ChallengeV1{}, serviceoperation.ErrRevisionConflict
		}
		return serviceoperation.ChallengeV1{}, fmt.Errorf("persist service operation challenge: %w", err)
	}
	stored, meta, err := readServiceOperation(ctx, tx, store.instanceID,
		`prepare_client_id=$2 AND prepare_credential_id=$3 AND prepare_idempotency_key=$4`, true,
		mutation.ClientID, mutation.CredentialID, mutation.IdempotencyKey)
	if err != nil {
		return serviceoperation.ChallengeV1{}, err
	}
	if meta.prepareHash != mutation.RequestHash || stored.OperationID != challenge.OperationID ||
		stored.Challenge.ChallengeID != challenge.ChallengeID {
		return serviceoperation.ChallengeV1{}, serviceoperation.ErrRevisionConflict
	}
	for index, phase := range serviceoperation.Phases() {
		if _, err := tx.Exec(ctx, `INSERT INTO cloud_service_operation_steps(operation_id,ordinal,phase,status,revision)
			VALUES($1,$2,$3,'pending',1) ON CONFLICT (operation_id,phase) DO NOTHING`,
			challenge.OperationID, index+1, phase); err != nil {
			return serviceoperation.ChallengeV1{}, fmt.Errorf("persist service operation phases: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return serviceoperation.ChallengeV1{}, fmt.Errorf("commit service operation challenge: %w", err)
	}
	return stored.Challenge, nil
}

func (store *Store) GetServiceOperationChallenge(ctx context.Context, ownerID, challengeID string) (serviceoperation.ChallengeV1, error) {
	if ctx == nil || !validServiceOperationOwner(ownerID) || !validServiceOperationUUID(challengeID) {
		return serviceoperation.ChallengeV1{}, serviceoperation.ErrInvalid
	}
	value, _, err := readServiceOperation(ctx, store.pool, store.instanceID,
		`owner_id=$2 AND challenge_id=$3`, false, ownerID, challengeID)
	return value.Challenge, err
}

func (store *Store) FindServiceOperationApprovalReplay(ctx context.Context, mutation serviceoperation.Mutation) (serviceoperation.OperationV1, error) {
	if err := validateServiceOperationMutation(ctx, mutation); err != nil {
		return serviceoperation.OperationV1{}, err
	}
	value, meta, err := readServiceOperation(ctx, store.pool, store.instanceID,
		`approve_client_id=$2 AND approve_credential_id=$3 AND approve_idempotency_key=$4`, false,
		mutation.ClientID, mutation.CredentialID, mutation.IdempotencyKey)
	if err != nil {
		return serviceoperation.OperationV1{}, err
	}
	if meta.approveHash == nil || *meta.approveHash != mutation.RequestHash {
		return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
	}
	value.Steps, err = readServiceOperationSteps(ctx, store.pool, value.OperationID)
	return value, err
}

func (store *Store) ApproveServiceOperation(ctx context.Context, mutation serviceoperation.Mutation, signature serviceoperation.SignatureV1, approvedAt time.Time) (serviceoperation.OperationV1, error) {
	if err := validateServiceOperationMutation(ctx, mutation); err != nil {
		return serviceoperation.OperationV1{}, err
	}
	if !validServiceOperationUUID(signature.ChallengeID) || !validServiceOperationUUID(signature.OperationID) ||
		signature.SignerKeyID == "" || len(signature.Signature) != 64 || approvedAt.IsZero() {
		return serviceoperation.OperationV1{}, serviceoperation.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return serviceoperation.OperationV1{}, fmt.Errorf("begin service operation approval: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replay, meta, replayErr := readServiceOperation(ctx, tx, store.instanceID,
		`approve_client_id=$2 AND approve_credential_id=$3 AND approve_idempotency_key=$4`, true,
		mutation.ClientID, mutation.CredentialID, mutation.IdempotencyKey); replayErr == nil {
		if !exactServiceOperationApproval(replay, meta, mutation, signature) {
			return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
		}
		replay.Steps, err = readServiceOperationSteps(ctx, tx, replay.OperationID)
		if err != nil {
			return serviceoperation.OperationV1{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return serviceoperation.OperationV1{}, err
		}
		return replay, nil
	} else if !errors.Is(replayErr, serviceoperation.ErrNotFound) {
		return serviceoperation.OperationV1{}, replayErr
	}
	current, _, err := readServiceOperation(ctx, tx, store.instanceID, `challenge_id=$2`, true, signature.ChallengeID)
	if err != nil {
		return serviceoperation.OperationV1{}, err
	}
	if current.Status != serviceoperation.StatusAwaitingApproval || current.Revision != 1 ||
		current.OperationID != signature.OperationID || current.Challenge.SignerKeyID != signature.SignerKeyID {
		return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
	}
	result, err := tx.Exec(ctx, `UPDATE cloud_service_operations SET signature=$3,status='approved',revision=2,
		approve_client_id=$4,approve_credential_id=$5,approve_idempotency_key=$6,approve_request_hash=$7,
		approved_at=$8,updated_at=$8 WHERE operation_id=$1 AND agent_instance_id=$2 AND revision=1 AND status='awaiting_approval'`,
		current.OperationID, store.instanceID, signature.Signature, mutation.ClientID, mutation.CredentialID,
		mutation.IdempotencyKey, mutation.RequestHash, approvedAt.UTC())
	if err != nil {
		if isUniqueViolation(err) {
			return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
		}
		return serviceoperation.OperationV1{}, err
	}
	if result.RowsAffected() != 1 {
		return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
	}
	approved, meta, err := readServiceOperation(ctx, tx, store.instanceID, `operation_id=$2`, false, current.OperationID)
	if err != nil || !exactServiceOperationApproval(approved, meta, mutation, signature) {
		if err != nil {
			return serviceoperation.OperationV1{}, err
		}
		return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
	}
	approved.Steps, err = readServiceOperationSteps(ctx, tx, approved.OperationID)
	if err != nil {
		return serviceoperation.OperationV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return serviceoperation.OperationV1{}, err
	}
	return approved, nil
}

func (store *Store) GetServiceOperation(ctx context.Context, ownerID, operationID string) (serviceoperation.OperationV1, error) {
	if ctx == nil || !validServiceOperationOwner(ownerID) || !validServiceOperationUUID(operationID) {
		return serviceoperation.OperationV1{}, serviceoperation.ErrInvalid
	}
	value, _, err := readServiceOperation(ctx, store.pool, store.instanceID,
		`owner_id=$2 AND operation_id=$3`, false, ownerID, operationID)
	if err == nil {
		value.Steps, err = readServiceOperationSteps(ctx, store.pool, operationID)
	}
	return value, err
}

func (store *Store) BeginServiceOperationPhase(ctx context.Context, operationID string, expectedRevision int64, phase serviceoperation.Phase, intentDigest string, at time.Time) (serviceoperation.OperationV1, error) {
	if ctx == nil || !validServiceOperationUUID(operationID) || expectedRevision < 2 ||
		!serviceOperationRequestDigest.MatchString(intentDigest) || at.IsZero() {
		return serviceoperation.OperationV1{}, serviceoperation.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return serviceoperation.OperationV1{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	value, _, err := readServiceOperation(ctx, tx, store.instanceID, `operation_id=$2`, true, operationID)
	if err != nil {
		return serviceoperation.OperationV1{}, err
	}
	if value.Revision != expectedRevision || value.CurrentPhase != phase ||
		(value.Status != serviceoperation.StatusApproved && value.Status != serviceoperation.StatusRunning) {
		return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
	}
	var status serviceoperation.StepStatus
	var revision int64
	var storedDigest *string
	if err := tx.QueryRow(ctx, `SELECT status,revision,intent_digest FROM cloud_service_operation_steps
		WHERE operation_id=$1 AND phase=$2 FOR UPDATE`, operationID, phase).Scan(&status, &revision, &storedDigest); err != nil {
		return serviceoperation.OperationV1{}, err
	}
	if status == serviceoperation.StepRunning && storedDigest != nil && *storedDigest == intentDigest {
		value.Steps, err = readServiceOperationSteps(ctx, tx, operationID)
		if err != nil {
			return serviceoperation.OperationV1{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return serviceoperation.OperationV1{}, err
		}
		return value, nil
	}
	if status != serviceoperation.StepPending || storedDigest != nil {
		return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
	}
	stepResult, err := tx.Exec(ctx, `UPDATE cloud_service_operation_steps SET status='running',revision=revision+1,
		intent_digest=$4,started_at=$5 WHERE operation_id=$1 AND phase=$2 AND revision=$3 AND status='pending'`,
		operationID, phase, revision, intentDigest, at.UTC())
	if err != nil || stepResult.RowsAffected() != 1 {
		if err != nil {
			return serviceoperation.OperationV1{}, err
		}
		return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
	}
	operationResult, err := tx.Exec(ctx, `UPDATE cloud_service_operations SET status='running',revision=revision+1,updated_at=$4
		WHERE operation_id=$1 AND agent_instance_id=$2 AND revision=$3`,
		operationID, store.instanceID, expectedRevision, at.UTC())
	if err != nil || operationResult.RowsAffected() != 1 {
		if err != nil {
			return serviceoperation.OperationV1{}, err
		}
		return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
	}
	updated, _, err := readServiceOperation(ctx, tx, store.instanceID, `operation_id=$2`, false, operationID)
	if err == nil {
		updated.Steps, err = readServiceOperationSteps(ctx, tx, operationID)
	}
	if err != nil {
		return serviceoperation.OperationV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return serviceoperation.OperationV1{}, err
	}
	return updated, nil
}

func (store *Store) AdvanceServiceOperationPhase(ctx context.Context, operationID string, expectedRevision int64, current, next serviceoperation.Phase, at time.Time) (serviceoperation.OperationV1, error) {
	if ctx == nil || !validServiceOperationUUID(operationID) || expectedRevision < 2 || at.IsZero() || next == "" {
		return serviceoperation.OperationV1{}, serviceoperation.ErrInvalid
	}
	if serviceoperation.ValidatePhaseAdvance(current, next) != nil {
		return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return serviceoperation.OperationV1{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	value, _, err := readServiceOperation(ctx, tx, store.instanceID, `operation_id=$2`, true, operationID)
	if err != nil {
		return serviceoperation.OperationV1{}, err
	}
	if value.Revision != expectedRevision || value.CurrentPhase != current ||
		(value.Status != serviceoperation.StatusApproved && value.Status != serviceoperation.StatusRunning) {
		return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
	}
	var ordinal int
	var stepStatus serviceoperation.StepStatus
	var stepRevision int64
	if err := tx.QueryRow(ctx, `SELECT ordinal,status,revision FROM cloud_service_operation_steps
		WHERE operation_id=$1 AND phase=$2 FOR UPDATE`, operationID, current).Scan(&ordinal, &stepStatus, &stepRevision); err != nil {
		return serviceoperation.OperationV1{}, err
	}
	if stepStatus != serviceoperation.StepRunning {
		return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
	}
	startedAt := at.UTC()
	stepResult, err := tx.Exec(ctx, `UPDATE cloud_service_operation_steps SET status='succeeded',revision=revision+1,
		started_at=COALESCE(started_at,$4),completed_at=$4 WHERE operation_id=$1 AND phase=$2 AND revision=$3`,
		operationID, current, stepRevision, startedAt)
	if err != nil {
		return serviceoperation.OperationV1{}, err
	}
	if stepResult.RowsAffected() != 1 {
		return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
	}
	result, err := tx.Exec(ctx, `UPDATE cloud_service_operations SET status=$4,current_phase=$5,revision=revision+1,updated_at=$6
		WHERE operation_id=$1 AND agent_instance_id=$2 AND revision=$3 AND current_phase=$7`,
		operationID, store.instanceID, expectedRevision, serviceoperation.StatusRunning, next, startedAt, current)
	if err != nil || result.RowsAffected() != 1 {
		if err != nil {
			return serviceoperation.OperationV1{}, err
		}
		return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
	}
	updated, _, err := readServiceOperation(ctx, tx, store.instanceID, `operation_id=$2`, false, operationID)
	if err == nil {
		updated.Steps, err = readServiceOperationSteps(ctx, tx, operationID)
	}
	if err != nil {
		return serviceoperation.OperationV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return serviceoperation.OperationV1{}, err
	}
	return updated, nil
}

func (store *Store) CompleteServiceOperation(ctx context.Context, operationID string, expectedRevision int64, result serviceoperation.ManagedPreparationResultV1, at time.Time) (serviceoperation.OperationV1, error) {
	if ctx == nil || !validServiceOperationUUID(operationID) || expectedRevision < 2 || result.Validate() != nil || at.IsZero() {
		return serviceoperation.OperationV1{}, serviceoperation.ErrInvalid
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return serviceoperation.OperationV1{}, serviceoperation.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return serviceoperation.OperationV1{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, _, err := readServiceOperation(ctx, tx, store.instanceID, `operation_id=$2`, true, operationID)
	if err != nil {
		return serviceoperation.OperationV1{}, err
	}
	if current.Revision != expectedRevision || current.Status != serviceoperation.StatusRunning || current.CurrentPhase != serviceoperation.PhaseFinalize || current.Result != nil {
		return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
	}
	var stepStatus serviceoperation.StepStatus
	var stepRevision int64
	if err := tx.QueryRow(ctx, `SELECT status,revision FROM cloud_service_operation_steps WHERE operation_id=$1 AND phase='finalize' FOR UPDATE`,
		operationID).Scan(&stepStatus, &stepRevision); err != nil {
		return serviceoperation.OperationV1{}, err
	}
	if stepStatus != serviceoperation.StepRunning {
		return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
	}
	stepResult, err := tx.Exec(ctx, `UPDATE cloud_service_operation_steps SET status='succeeded',revision=revision+1,completed_at=$4
		WHERE operation_id=$1 AND phase='finalize' AND revision=$2 AND status='running'`, operationID, stepRevision, "finalize", at.UTC())
	if err != nil || stepResult.RowsAffected() != 1 {
		if err != nil {
			return serviceoperation.OperationV1{}, err
		}
		return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
	}
	opResult, err := tx.Exec(ctx, `UPDATE cloud_service_operations SET status='succeeded',result_json=$4,revision=revision+1,updated_at=$5
		WHERE operation_id=$1 AND agent_instance_id=$2 AND revision=$3 AND status='running' AND current_phase='finalize'`,
		operationID, store.instanceID, expectedRevision, encoded, at.UTC())
	if err != nil || opResult.RowsAffected() != 1 {
		if err != nil {
			return serviceoperation.OperationV1{}, err
		}
		return serviceoperation.OperationV1{}, serviceoperation.ErrRevisionConflict
	}
	updated, _, err := readServiceOperation(ctx, tx, store.instanceID, `operation_id=$2`, false, operationID)
	if err == nil {
		updated.Steps, err = readServiceOperationSteps(ctx, tx, operationID)
	}
	if err != nil {
		return serviceoperation.OperationV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return serviceoperation.OperationV1{}, err
	}
	return updated, nil
}

func (store *Store) ListRecoverableServiceOperations(ctx context.Context, limit int) ([]serviceoperation.OperationV1, error) {
	if ctx == nil || limit < 1 || limit > 100 {
		return nil, serviceoperation.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, serviceOperationSelect+` WHERE agent_instance_id=$1 AND status IN ('approved','running')
		ORDER BY updated_at,operation_id LIMIT $2`, store.instanceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []serviceoperation.OperationV1
	for rows.Next() {
		value, _, err := scanServiceOperation(rows)
		if err != nil {
			return nil, err
		}
		value.Steps, err = readServiceOperationSteps(ctx, store.pool, value.OperationID)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

const serviceOperationSelect = `SELECT operation_id,challenge_json,status,current_phase,result_json,signature,revision,
	created_at,updated_at,approved_at,prepare_request_hash,approve_client_id,approve_credential_id,
	approve_idempotency_key,approve_request_hash FROM cloud_service_operations`

type serviceOperationMeta struct {
	challengeJSON     []byte
	resultJSON        []byte
	prepareHash       string
	approveClient     *string
	approveCredential *uuid.UUID
	approveKey        *uuid.UUID
	approveHash       *string
}
type serviceOperationScanner interface{ Scan(...any) error }

func scanServiceOperation(scanner serviceOperationScanner) (serviceoperation.OperationV1, serviceOperationMeta, error) {
	var value serviceoperation.OperationV1
	var meta serviceOperationMeta
	if err := scanner.Scan(&value.OperationID, &meta.challengeJSON, &value.Status, &value.CurrentPhase, &meta.resultJSON,
		&value.Signature, &value.Revision, &value.CreatedAt, &value.UpdatedAt, &value.ApprovedAt,
		&meta.prepareHash, &meta.approveClient, &meta.approveCredential, &meta.approveKey, &meta.approveHash); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return value, meta, serviceoperation.ErrNotFound
		}
		return value, meta, err
	}
	if json.Unmarshal(meta.challengeJSON, &value.Challenge) != nil {
		return value, meta, serviceoperation.ErrInvalid
	}
	if len(meta.resultJSON) > 0 {
		var result serviceoperation.ManagedPreparationResultV1
		if json.Unmarshal(meta.resultJSON, &result) != nil || result.Validate() != nil {
			return value, meta, serviceoperation.ErrInvalid
		}
		value.Result = &result
	}
	if value.Status == serviceoperation.StatusSucceeded && value.Result == nil || value.Status != serviceoperation.StatusSucceeded && value.Result != nil {
		return value, meta, serviceoperation.ErrInvalid
	}
	return value, meta, nil
}

type serviceOperationQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readServiceOperation(ctx context.Context, query serviceOperationQuery, instanceID uuid.UUID, predicate string, lock bool, args ...any) (serviceoperation.OperationV1, serviceOperationMeta, error) {
	statement := serviceOperationSelect + ` WHERE agent_instance_id=$1 AND ` + predicate
	if lock {
		statement += ` FOR UPDATE`
	}
	return scanServiceOperation(query.QueryRow(ctx, statement, append([]any{instanceID}, args...)...))
}

func readServiceOperationSteps(ctx context.Context, query interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, operationID string) ([]serviceoperation.StepV1, error) {
	rows, err := query.Query(ctx, `SELECT phase,ordinal,status,revision,intent_digest,started_at,completed_at
		FROM cloud_service_operation_steps WHERE operation_id=$1 ORDER BY ordinal`, operationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []serviceoperation.StepV1
	for rows.Next() {
		var value serviceoperation.StepV1
		if err := rows.Scan(&value.Phase, &value.Ordinal, &value.Status, &value.Revision, &value.IntentDigest, &value.StartedAt, &value.CompletedAt); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func exactServiceOperationApproval(value serviceoperation.OperationV1, meta serviceOperationMeta, mutation serviceoperation.Mutation, signature serviceoperation.SignatureV1) bool {
	return value.Status != serviceoperation.StatusAwaitingApproval && value.OperationID == signature.OperationID &&
		value.Challenge.ChallengeID == signature.ChallengeID && value.Challenge.SignerKeyID == signature.SignerKeyID &&
		bytes.Equal(value.Signature, signature.Signature) && meta.approveClient != nil && *meta.approveClient == mutation.ClientID &&
		meta.approveCredential != nil && meta.approveCredential.String() == mutation.CredentialID &&
		meta.approveKey != nil && meta.approveKey.String() == mutation.IdempotencyKey &&
		meta.approveHash != nil && *meta.approveHash == mutation.RequestHash
}

func validateServiceOperationMutation(ctx context.Context, mutation serviceoperation.Mutation) error {
	if ctx == nil || !validServiceOperationOwner(mutation.ClientID) || !validServiceOperationUUID(mutation.CredentialID) ||
		!validServiceOperationUUID(mutation.IdempotencyKey) || !serviceOperationRequestDigest.MatchString(mutation.RequestHash) {
		return serviceoperation.ErrInvalid
	}
	return nil
}
func validServiceOperationOwner(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed != "" && trimmed == value && len(value) <= 255 && !security.ContainsLikelySecret(value)
}
func validServiceOperationUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed != uuid.Nil && parsed.String() == strings.ToLower(value)
}
