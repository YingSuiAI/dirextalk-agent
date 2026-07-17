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
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var _ entrypoint.Repository = (*Store)(nil)

const cloudEntryPlanColumns = `entry_plan_id, agent_instance_id, owner_id, deployment_id, task_id,
       original_plan_id, original_plan_hash, original_approval_id, connection_id,
       worker_resource_id, worker_resource_revision, worker_spec_digest,
       scope_digest, scope_json, plan_hash, plan_cbor, status, revision,
       create_client_id, create_credential_id, create_idempotency_key, create_request_hash,
       created_at, updated_at`

const cloudEntryOperationColumns = `operation_id, agent_instance_id, owner_id, entry_plan_id,
       deployment_id, task_id, original_plan_id, original_plan_hash, original_approval_id,
       connection_id, challenge_id, entry_approval_id, signer_key_id,
       expected_entry_plan_revision, entry_plan_hash, scope_digest, challenge_json,
       signing_payload, challenge_issued_at, challenge_expires_at, signature_json, signature,
       status, error_code, error_summary, revision,
       prepare_client_id, prepare_credential_id, prepare_idempotency_key, prepare_request_hash,
       approve_client_id, approve_credential_id, approve_idempotency_key, approve_request_hash,
       created_at, updated_at, approved_at`

type entryPlanRow struct {
	Plan      entrypoint.PlanV1
	PlanHash  string
	PlanCBOR  []byte
	Create    entrypoint.Mutation
	CreatedAt time.Time
	UpdatedAt time.Time
}

type entryOperationRow struct {
	Operation          entrypoint.OperationV1
	EntryPlanID        string
	OwnerID            string
	DeploymentID       string
	TaskID             string
	OriginalPlanID     string
	OriginalPlanHash   string
	OriginalApprovalID string
	ConnectionID       string
	Prepare            entrypoint.Mutation
	Approve            *entrypoint.Mutation
}

// CreateEntryPlan records the canonical public-entry scope but never creates a
// provider resource. A separately verified approval is required for promotion.
func (store *Store) CreateEntryPlan(ctx context.Context, mutation entrypoint.Mutation, plan entrypoint.PlanV1) (entrypoint.PlanV1, error) {
	if store == nil || store.pool == nil || ctx == nil || mutation.Validate() != nil || plan.Validate() != nil ||
		plan.Status != entrypoint.PlanReadyForApproval || plan.Scope.AgentInstanceID != store.instanceID.String() || plan.Scope.OwnerID != mutation.OwnerID {
		return entrypoint.PlanV1{}, entrypoint.ErrInvalid
	}
	if !time.Now().UTC().Before(plan.Scope.Cost.ValidUntil) {
		return entrypoint.PlanV1{}, entrypoint.ErrRevisionConflict
	}
	planCBOR, err := plan.CanonicalCBOR()
	if err != nil {
		return entrypoint.PlanV1{}, entrypoint.ErrInvalid
	}
	planHash, err := plan.Hash()
	if err != nil {
		return entrypoint.PlanV1{}, entrypoint.ErrInvalid
	}
	scopeJSON, err := json.Marshal(entrypoint.NormalizeScope(plan.Scope))
	if err != nil {
		return entrypoint.PlanV1{}, entrypoint.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return entrypoint.PlanV1{}, entrypoint.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, readErr := readEntryPlanRow(ctx, tx, ` WHERE create_client_id=$1 AND create_credential_id=$2 AND create_idempotency_key=$3 FOR UPDATE`,
		mutation.Caller.ClientID, mutation.Caller.CredentialID, mutation.IdempotencyKey)
	if readErr == nil {
		if !sameEntryPlanCreate(existing, mutation, plan, planHash, planCBOR) {
			return entrypoint.PlanV1{}, entrypoint.ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return entrypoint.PlanV1{}, entrypoint.ErrUnavailable
		}
		return existing.Plan, nil
	}
	if !errors.Is(readErr, entrypoint.ErrNotFound) {
		return entrypoint.PlanV1{}, readErr
	}
	if err := store.validateEntryPlanPrerequisites(ctx, tx, plan.Scope); err != nil {
		return entrypoint.PlanV1{}, err
	}
	result, err := tx.Exec(ctx, `INSERT INTO cloud_entry_plans (
		entry_plan_id, agent_instance_id, owner_id, deployment_id, task_id,
		original_plan_id, original_plan_hash, original_approval_id, connection_id,
		worker_resource_id, worker_resource_revision, worker_spec_digest,
		scope_digest, scope_json, plan_hash, plan_cbor, status, revision,
		create_client_id, create_credential_id, create_idempotency_key, create_request_hash,
		created_at, updated_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$23)
	ON CONFLICT (create_client_id, create_credential_id, create_idempotency_key) DO NOTHING`,
		plan.EntryPlanID, store.instanceID, plan.Scope.OwnerID, plan.Scope.Worker.DeploymentID, plan.Scope.Worker.TaskID,
		plan.Scope.Worker.OriginalPlanID, plan.Scope.Worker.OriginalPlanHash, plan.Scope.Worker.OriginalApprovalID, plan.Scope.ConnectionID,
		plan.Scope.Worker.WorkerResourceID, plan.Scope.Worker.WorkerResourceRevision, plan.Scope.Worker.WorkerSpecDigest,
		plan.ScopeDigest, string(scopeJSON), planHash, planCBOR, plan.Status, int64(plan.Revision),
		mutation.Caller.ClientID, mutation.Caller.CredentialID, mutation.IdempotencyKey, mutation.RequestHash[:], plan.Scope.Cost.QuotedAt.UTC())
	if err != nil {
		if isUniqueViolation(err) {
			return entrypoint.PlanV1{}, entrypoint.ErrIdempotencyConflict
		}
		return entrypoint.PlanV1{}, entrypoint.ErrUnavailable
	}
	if result.RowsAffected() == 0 {
		existing, readErr = readEntryPlanRow(ctx, tx, ` WHERE create_client_id=$1 AND create_credential_id=$2 AND create_idempotency_key=$3 FOR UPDATE`,
			mutation.Caller.ClientID, mutation.Caller.CredentialID, mutation.IdempotencyKey)
		if readErr != nil {
			return entrypoint.PlanV1{}, readErr
		}
		if !sameEntryPlanCreate(existing, mutation, plan, planHash, planCBOR) {
			return entrypoint.PlanV1{}, entrypoint.ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return entrypoint.PlanV1{}, entrypoint.ErrUnavailable
		}
		return existing.Plan, nil
	}
	if err := appendEntryPlanEvent(ctx, tx, mutation, plan, plan.Scope.Cost.QuotedAt); err != nil {
		return entrypoint.PlanV1{}, entrypoint.ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return entrypoint.PlanV1{}, entrypoint.ErrUnavailable
	}
	return plan, nil
}

func (store *Store) GetEntryPlan(ctx context.Context, ownerID, entryPlanID string) (entrypoint.PlanV1, error) {
	if store == nil || store.pool == nil || ctx == nil || strings.TrimSpace(ownerID) == "" || !validEntryUUID(entryPlanID) {
		return entrypoint.PlanV1{}, entrypoint.ErrInvalid
	}
	row, err := readEntryPlanRow(ctx, store.pool, ` WHERE agent_instance_id=$1 AND owner_id=$2 AND entry_plan_id=$3`, store.instanceID, ownerID, entryPlanID)
	if err != nil {
		return entrypoint.PlanV1{}, err
	}
	return row.Plan, nil
}

// CreateEntryChallenge creates the one durable operation associated with a
// ready plan. A second prepare cannot replace a challenge that a device may
// already have seen.
func (store *Store) CreateEntryChallenge(ctx context.Context, mutation entrypoint.Mutation, challenge entrypoint.ChallengeV1) (entrypoint.ChallengeV1, error) {
	if store == nil || store.pool == nil || ctx == nil || mutation.Validate() != nil || challenge.Validate() != nil || challenge.Revision != 1 {
		return entrypoint.ChallengeV1{}, entrypoint.ErrInvalid
	}
	challengeNow := time.Now().UTC()
	if challenge.IssuedAt.After(challengeNow) {
		return entrypoint.ChallengeV1{}, entrypoint.ErrInvalid
	}
	if !challengeNow.Before(challenge.ExpiresAt) {
		return entrypoint.ChallengeV1{}, entrypoint.ErrApprovalExpired
	}
	payload, err := challenge.SigningPayload()
	if err != nil || !bytes.Equal(payload, challenge.SigningCBOR) {
		return entrypoint.ChallengeV1{}, entrypoint.ErrInvalid
	}
	challengeJSON, err := json.Marshal(challenge)
	if err != nil {
		return entrypoint.ChallengeV1{}, entrypoint.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return entrypoint.ChallengeV1{}, entrypoint.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, readErr := readEntryOperationRow(ctx, tx, ` WHERE prepare_client_id=$1 AND prepare_credential_id=$2 AND prepare_idempotency_key=$3 FOR UPDATE`,
		mutation.Caller.ClientID, mutation.Caller.CredentialID, mutation.IdempotencyKey)
	if readErr == nil {
		if !sameEntryPrepare(existing, mutation, challenge) {
			return entrypoint.ChallengeV1{}, entrypoint.ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return entrypoint.ChallengeV1{}, entrypoint.ErrUnavailable
		}
		return existing.Operation.Challenge, nil
	}
	if !errors.Is(readErr, entrypoint.ErrNotFound) {
		return entrypoint.ChallengeV1{}, readErr
	}
	planRow, err := readEntryPlanRow(ctx, tx, ` WHERE agent_instance_id=$1 AND owner_id=$2 AND entry_plan_id=$3 FOR UPDATE`,
		store.instanceID, mutation.OwnerID, challenge.EntryPlanID)
	if err != nil {
		return entrypoint.ChallengeV1{}, err
	}
	if planRow.Plan.Status != entrypoint.PlanReadyForApproval || planRow.Plan.Revision != challenge.EntryPlanRevision ||
		challenge.ValidateAgainstPlan(planRow.Plan) != nil || planRow.Plan.Scope.OwnerID != mutation.OwnerID {
		return entrypoint.ChallengeV1{}, entrypoint.ErrRevisionConflict
	}
	if err := store.validateEntryPlanPrerequisites(ctx, tx, planRow.Plan.Scope); err != nil {
		return entrypoint.ChallengeV1{}, err
	}
	if err := store.validateActiveEntryDevice(ctx, tx, challenge.SignerKeyID, mutation.OwnerID, challenge.IssuedAt); err != nil {
		return entrypoint.ChallengeV1{}, err
	}
	result, err := tx.Exec(ctx, `INSERT INTO cloud_entry_operations (
		operation_id, agent_instance_id, owner_id, entry_plan_id, deployment_id, task_id,
		original_plan_id, original_plan_hash, original_approval_id, connection_id,
		challenge_id, entry_approval_id, signer_key_id, expected_entry_plan_revision,
		entry_plan_hash, scope_digest, challenge_json, signing_payload,
		challenge_issued_at, challenge_expires_at, status, revision,
		prepare_client_id, prepare_credential_id, prepare_idempotency_key, prepare_request_hash,
		created_at, updated_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,1,$22,$23,$24,$25,$19,$19)
	ON CONFLICT (prepare_client_id, prepare_credential_id, prepare_idempotency_key) DO NOTHING`,
		challenge.OperationID, store.instanceID, mutation.OwnerID, challenge.EntryPlanID,
		planRow.Plan.Scope.Worker.DeploymentID, planRow.Plan.Scope.Worker.TaskID,
		planRow.Plan.Scope.Worker.OriginalPlanID, planRow.Plan.Scope.Worker.OriginalPlanHash,
		planRow.Plan.Scope.Worker.OriginalApprovalID, planRow.Plan.Scope.ConnectionID,
		challenge.ChallengeID, challenge.ApprovalID, challenge.SignerKeyID, int64(challenge.EntryPlanRevision),
		challenge.PlanHash, challenge.ScopeDigest, string(challengeJSON), payload,
		challenge.IssuedAt.UTC(), challenge.ExpiresAt.UTC(), entrypoint.StatusAwaitingApproval,
		mutation.Caller.ClientID, mutation.Caller.CredentialID, mutation.IdempotencyKey, mutation.RequestHash[:])
	if err != nil {
		if isUniqueViolation(err) {
			return entrypoint.ChallengeV1{}, entrypoint.ErrIdempotencyConflict
		}
		return entrypoint.ChallengeV1{}, entrypoint.ErrUnavailable
	}
	if result.RowsAffected() == 0 {
		existing, readErr = readEntryOperationRow(ctx, tx, ` WHERE prepare_client_id=$1 AND prepare_credential_id=$2 AND prepare_idempotency_key=$3 FOR UPDATE`,
			mutation.Caller.ClientID, mutation.Caller.CredentialID, mutation.IdempotencyKey)
		if readErr != nil {
			return entrypoint.ChallengeV1{}, readErr
		}
		if !sameEntryPrepare(existing, mutation, challenge) {
			return entrypoint.ChallengeV1{}, entrypoint.ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return entrypoint.ChallengeV1{}, entrypoint.ErrUnavailable
		}
		return existing.Operation.Challenge, nil
	}
	created, err := readEntryOperationRow(ctx, tx, ` WHERE operation_id=$1`, challenge.OperationID)
	if err != nil {
		return entrypoint.ChallengeV1{}, err
	}
	if err := appendEntryOperationEvent(ctx, tx, mutation, mutation.OwnerID, created.Operation); err != nil {
		return entrypoint.ChallengeV1{}, entrypoint.ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return entrypoint.ChallengeV1{}, entrypoint.ErrUnavailable
	}
	return challenge, nil
}

func (store *Store) GetEntryChallenge(ctx context.Context, ownerID, challengeID string) (entrypoint.ChallengeV1, error) {
	if store == nil || store.pool == nil || ctx == nil || strings.TrimSpace(ownerID) == "" || !validEntryUUID(challengeID) {
		return entrypoint.ChallengeV1{}, entrypoint.ErrInvalid
	}
	row, err := readEntryOperationRow(ctx, store.pool, ` WHERE agent_instance_id=$1 AND owner_id=$2 AND challenge_id=$3`, store.instanceID, ownerID, challengeID)
	if err != nil {
		return entrypoint.ChallengeV1{}, err
	}
	return row.Operation.Challenge, nil
}

// ApproveEntry atomically consumes a registered-device signature and promotes
// a ready plan. The original Worker approval is never reused for this step.
func (store *Store) ApproveEntry(ctx context.Context, mutation entrypoint.Mutation, challengeID string, expectedRevision uint64, signature entrypoint.SignatureV1, approvedAt time.Time) (entrypoint.OperationV1, error) {
	if store == nil || store.pool == nil || ctx == nil || mutation.Validate() != nil || !validEntryUUID(challengeID) || expectedRevision == 0 || signature.Validate() != nil || approvedAt.IsZero() {
		return entrypoint.OperationV1{}, entrypoint.ErrInvalid
	}
	actualNow := time.Now().UTC()
	// Approval time is control-plane evidence, not caller-controlled metadata.
	// Preserve the required input shape but persist the local acceptance time.
	approvedAt = actualNow.Truncate(time.Microsecond)
	signatureJSON, err := json.Marshal(signature)
	if err != nil {
		return entrypoint.OperationV1{}, entrypoint.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return entrypoint.OperationV1{}, entrypoint.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, readErr := readEntryOperationRow(ctx, tx, ` WHERE approve_client_id=$1 AND approve_credential_id=$2 AND approve_idempotency_key=$3 FOR UPDATE`,
		mutation.Caller.ClientID, mutation.Caller.CredentialID, mutation.IdempotencyKey)
	if readErr == nil {
		if !sameEntryApprove(existing, mutation, challengeID, signature) || existing.Operation.Challenge.EntryPlanRevision != expectedRevision {
			return entrypoint.OperationV1{}, entrypoint.ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return entrypoint.OperationV1{}, entrypoint.ErrUnavailable
		}
		return existing.Operation, nil
	}
	if !errors.Is(readErr, entrypoint.ErrNotFound) {
		return entrypoint.OperationV1{}, readErr
	}
	current, err := readEntryOperationRow(ctx, tx, ` WHERE agent_instance_id=$1 AND challenge_id=$2 FOR UPDATE`, store.instanceID, challengeID)
	if err != nil {
		return entrypoint.OperationV1{}, err
	}
	if current.Prepare.OwnerID != mutation.OwnerID {
		return entrypoint.OperationV1{}, entrypoint.ErrNotFound
	}
	if current.Operation.Challenge.EntryPlanID == "" || current.Operation.Challenge.EntryPlanRevision != expectedRevision ||
		current.Operation.Challenge.EntryPlanID != signature.EntryPlanID || current.Operation.Challenge.EntryPlanID != current.EntryPlanID {
		return entrypoint.OperationV1{}, entrypoint.ErrRevisionConflict
	}
	if current.Operation.Challenge.SignerKeyID == "" {
		return entrypoint.OperationV1{}, entrypoint.ErrNotFound
	}
	if current.Operation.Status != entrypoint.StatusAwaitingApproval {
		if !sameEntryApprove(current, mutation, challengeID, signature) {
			return entrypoint.OperationV1{}, entrypoint.ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return entrypoint.OperationV1{}, entrypoint.ErrUnavailable
		}
		return current.Operation, nil
	}
	planRow, err := readEntryPlanRow(ctx, tx, ` WHERE agent_instance_id=$1 AND owner_id=$2 AND entry_plan_id=$3 FOR UPDATE`,
		store.instanceID, mutation.OwnerID, current.EntryPlanID)
	if err != nil {
		return entrypoint.OperationV1{}, err
	}
	if planRow.Plan.Status != entrypoint.PlanReadyForApproval || planRow.Plan.Revision != expectedRevision ||
		current.Operation.Challenge.ValidateAgainstPlan(planRow.Plan) != nil || !entrySignatureMatchesChallenge(current.Operation.Challenge, signature) ||
		approvedAt.Before(current.Operation.Challenge.IssuedAt) || !approvedAt.Before(current.Operation.Challenge.ExpiresAt) {
		return entrypoint.OperationV1{}, entrypoint.ErrRevisionConflict
	}
	if err := store.validateEntryPlanPrerequisites(ctx, tx, planRow.Plan.Scope); err != nil {
		return entrypoint.OperationV1{}, err
	}
	if !actualNow.Before(current.Operation.Challenge.ExpiresAt) {
		return entrypoint.OperationV1{}, entrypoint.ErrApprovalExpired
	}
	publicKey, err := store.readActiveEntryDevice(ctx, tx, current.Operation.Challenge.SignerKeyID, mutation.OwnerID, actualNow)
	if err != nil {
		return entrypoint.OperationV1{}, err
	}
	if err := entrypoint.VerifyDeviceSignature(current.Operation.Challenge, signature, publicKey, actualNow); err != nil {
		return entrypoint.OperationV1{}, err
	}
	planUpdate, err := tx.Exec(ctx, `UPDATE cloud_entry_plans
		SET status=$2, updated_at=$3
		WHERE entry_plan_id=$1 AND status='ready_for_approval' AND revision=$4`,
		current.EntryPlanID, entrypoint.PlanApproved, approvedAt, int64(expectedRevision))
	if err != nil || planUpdate.RowsAffected() != 1 {
		return entrypoint.OperationV1{}, entrypoint.ErrRevisionConflict
	}
	operationUpdate, err := tx.Exec(ctx, `UPDATE cloud_entry_operations SET
		signature_json=$2, signature=$3, status=$4, revision=revision+1,
		approve_client_id=$5, approve_credential_id=$6, approve_idempotency_key=$7,
		approve_request_hash=$8, approved_at=$9, updated_at=$9
		WHERE operation_id=$1 AND status='awaiting_approval' AND revision=1`,
		current.Operation.Challenge.OperationID, string(signatureJSON), signature.Signature, entrypoint.StatusApproved,
		mutation.Caller.ClientID, mutation.Caller.CredentialID, mutation.IdempotencyKey, mutation.RequestHash[:], approvedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return entrypoint.OperationV1{}, entrypoint.ErrIdempotencyConflict
		}
		return entrypoint.OperationV1{}, entrypoint.ErrUnavailable
	}
	if operationUpdate.RowsAffected() != 1 {
		return entrypoint.OperationV1{}, entrypoint.ErrRevisionConflict
	}
	updated, err := readEntryOperationRow(ctx, tx, ` WHERE operation_id=$1`, current.Operation.Challenge.OperationID)
	if err != nil {
		return entrypoint.OperationV1{}, err
	}
	// The immutable entry-plan revision is the scope revision that the device
	// signed and intentionally does not change when its status becomes approved.
	// The operation event carries the plan ID, so consumers can refresh that
	// projection without receiving two plan events at the same revision.
	if err := appendEntryOperationEvent(ctx, tx, mutation, mutation.OwnerID, updated.Operation); err != nil {
		return entrypoint.OperationV1{}, entrypoint.ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return entrypoint.OperationV1{}, entrypoint.ErrUnavailable
	}
	return updated.Operation, nil
}

func (store *Store) GetEntryOperation(ctx context.Context, ownerID, operationID string) (entrypoint.OperationV1, error) {
	if store == nil || store.pool == nil || ctx == nil || strings.TrimSpace(ownerID) == "" || !validEntryUUID(operationID) {
		return entrypoint.OperationV1{}, entrypoint.ErrInvalid
	}
	row, err := readEntryOperationRow(ctx, store.pool, ` WHERE agent_instance_id=$1 AND owner_id=$2 AND operation_id=$3`, store.instanceID, ownerID, operationID)
	if err != nil {
		return entrypoint.OperationV1{}, err
	}
	return row.Operation, nil
}

// GetEntryPlanForOperation resolves the approved immutable entry scope for a
// pending durable operation. It intentionally accepts no caller-owned lookup:
// only the control-plane recovery loop receives operation identifiers from the
// durable pending queue. The read locks both rows and rechecks every duplicated
// ownership and scope binding before returning the plan.
func (store *Store) GetEntryPlanForOperation(ctx context.Context, operationID string) (entrypoint.PlanV1, error) {
	if store == nil || store.pool == nil || ctx == nil || !validEntryUUID(operationID) {
		return entrypoint.PlanV1{}, entrypoint.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return entrypoint.PlanV1{}, entrypoint.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()

	operation, err := readEntryOperationRow(ctx, tx, ` WHERE agent_instance_id=$1 AND operation_id=$2 FOR SHARE`, store.instanceID, operationID)
	if err != nil {
		return entrypoint.PlanV1{}, err
	}
	if !entryOperationRecoverable(operation.Operation.Status) {
		return entrypoint.PlanV1{}, entrypoint.ErrUnavailable
	}
	plan, err := readEntryPlanRow(ctx, tx, ` WHERE agent_instance_id=$1 AND entry_plan_id=$2 FOR SHARE`, store.instanceID, operation.EntryPlanID)
	if err != nil {
		return entrypoint.PlanV1{}, err
	}
	if !entryPlanMatchesRecoveryOperation(store.instanceID, plan, operation) {
		return entrypoint.PlanV1{}, entrypoint.ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return entrypoint.PlanV1{}, entrypoint.ErrUnavailable
	}
	return plan.Plan, nil
}

func (store *Store) ListPendingEntry(ctx context.Context, limit int) ([]entrypoint.OperationV1, error) {
	if store == nil || store.pool == nil || ctx == nil || limit < 1 || limit > 256 {
		return nil, entrypoint.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, `SELECT `+cloudEntryOperationColumns+` FROM cloud_entry_operations
		WHERE agent_instance_id=$1 AND status IN ('approved','provisioning','verifying','active','destroying','destroy_blocked')
		ORDER BY updated_at, operation_id LIMIT $2`, store.instanceID, limit)
	if err != nil {
		return nil, entrypoint.ErrUnavailable
	}
	defer rows.Close()
	result := make([]entrypoint.OperationV1, 0, limit)
	for rows.Next() {
		row, scanErr := scanEntryOperationRow(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, row.Operation)
	}
	if rows.Err() != nil {
		return nil, entrypoint.ErrUnavailable
	}
	return result, nil
}

// SaveEntryOperation is used only by the durable executor/reconciler. It
// fences every transition with the persisted operation revision and keeps the
// device-approved challenge/signature immutable.
func (store *Store) SaveEntryOperation(ctx context.Context, next entrypoint.OperationV1, expectedRevision int64) (entrypoint.OperationV1, error) {
	if store == nil || store.pool == nil || ctx == nil || expectedRevision < 2 || next.Validate() != nil {
		return entrypoint.OperationV1{}, entrypoint.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return entrypoint.OperationV1{}, entrypoint.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := readEntryOperationRow(ctx, tx, ` WHERE agent_instance_id=$1 AND operation_id=$2 FOR UPDATE`, store.instanceID, next.Challenge.OperationID)
	if err != nil {
		return entrypoint.OperationV1{}, err
	}
	if current.Operation.Revision != expectedRevision || !sameEntryOperationIdentity(current.Operation, next) ||
		!validEntryTransition(current.Operation.Status, next.Status) {
		return entrypoint.OperationV1{}, entrypoint.ErrRevisionConflict
	}
	next.Revision = expectedRevision + 1
	result, err := tx.Exec(ctx, `UPDATE cloud_entry_operations SET
		status=$3, error_code=$4, error_summary=$5, revision=$6, updated_at=$7
		WHERE agent_instance_id=$1 AND operation_id=$2 AND revision=$8`,
		store.instanceID, next.Challenge.OperationID, next.Status, nullableEntryString(string(next.ErrorCode)), nullableEntryString(next.ErrorSummary),
		next.Revision, next.UpdatedAt.UTC(), expectedRevision)
	if err != nil {
		return entrypoint.OperationV1{}, entrypoint.ErrUnavailable
	}
	if result.RowsAffected() != 1 {
		return entrypoint.OperationV1{}, entrypoint.ErrRevisionConflict
	}
	updated, err := readEntryOperationRow(ctx, tx, ` WHERE agent_instance_id=$1 AND operation_id=$2`, store.instanceID, next.Challenge.OperationID)
	if err != nil {
		return entrypoint.OperationV1{}, err
	}
	// Background reconciliation has no user request. Anchor its event to the
	// durable prepare caller rather than inventing an unscoped system actor.
	if err := appendEntryOperationEvent(ctx, tx, current.Prepare, current.OwnerID, updated.Operation); err != nil {
		return entrypoint.OperationV1{}, entrypoint.ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return entrypoint.OperationV1{}, entrypoint.ErrUnavailable
	}
	return updated.Operation, nil
}

const (
	entryPlanChangedEvent      = "cloud.entrypoint.plan.changed"
	entryOperationChangedEvent = "cloud.entrypoint.operation.changed"
)

// Entry events are intentionally a compact status projection. The signed
// scope, host, health route, certificate, CBOR, and device signature remain in
// the private entrypoint records and are never copied to task_events/outbox.
func appendEntryPlanEvent(ctx context.Context, tx pgx.Tx, actor entrypoint.Mutation, plan entrypoint.PlanV1, updatedAt time.Time) error {
	if actor.Validate() != nil || actor.OwnerID != plan.Scope.OwnerID || plan.Validate() != nil || updatedAt.IsZero() {
		return entrypoint.ErrInvalid
	}
	planID, err := uuid.Parse(plan.EntryPlanID)
	if err != nil || planID == uuid.Nil {
		return entrypoint.ErrInvalid
	}
	summary := struct {
		EntryPlanID string                `json:"entry_plan_id"`
		OwnerID     string                `json:"owner_id"`
		Status      entrypoint.PlanStatus `json:"status"`
		Revision    uint64                `json:"revision"`
		UpdatedAt   time.Time             `json:"updated_at"`
	}{
		EntryPlanID: plan.EntryPlanID,
		OwnerID:     plan.Scope.OwnerID,
		Status:      plan.Status,
		Revision:    plan.Revision,
		UpdatedAt:   updatedAt.UTC(),
	}
	return appendCloudFactEvent(ctx, tx, planID, "entrypoint_plan", entryPlanChangedEvent, plan.Revision, summary)
}

func appendEntryOperationEvent(ctx context.Context, tx pgx.Tx, actor entrypoint.Mutation, ownerID string, operation entrypoint.OperationV1) error {
	if actor.Validate() != nil || actor.OwnerID != ownerID || operation.Validate() != nil {
		return entrypoint.ErrInvalid
	}
	operationID, err := uuid.Parse(operation.Challenge.OperationID)
	if err != nil || operationID == uuid.Nil || operation.Revision < 1 {
		return entrypoint.ErrInvalid
	}
	fixedSummary, ok := entryOperationEventErrorSummary(operation.ErrorCode)
	if !ok {
		return entrypoint.ErrInvalid
	}
	summary := struct {
		OperationID  string               `json:"operation_id"`
		EntryPlanID  string               `json:"entry_plan_id"`
		OwnerID      string               `json:"owner_id"`
		Status       entrypoint.Status    `json:"status"`
		Revision     int64                `json:"revision"`
		UpdatedAt    time.Time            `json:"updated_at"`
		ErrorCode    entrypoint.ErrorCode `json:"error_code,omitempty"`
		ErrorSummary string               `json:"error_summary,omitempty"`
	}{
		OperationID:  operation.Challenge.OperationID,
		EntryPlanID:  operation.Challenge.EntryPlanID,
		OwnerID:      ownerID,
		Status:       operation.Status,
		Revision:     operation.Revision,
		UpdatedAt:    operation.UpdatedAt.UTC(),
		ErrorCode:    operation.ErrorCode,
		ErrorSummary: fixedSummary,
	}
	return appendCloudFactEvent(ctx, tx, operationID, "entrypoint_operation", entryOperationChangedEvent, uint64(operation.Revision), summary)
}

func entryOperationEventErrorSummary(code entrypoint.ErrorCode) (string, bool) {
	switch code {
	case entrypoint.ErrorCodeNone:
		return "", true
	case entrypoint.ErrorCodeWorkerNotReady:
		return "worker readiness check failed", true
	case entrypoint.ErrorCodeReadBackMismatch:
		return "independent read-back mismatch", true
	case entrypoint.ErrorCodeCertificateInvalid:
		return "certificate validation failed", true
	case entrypoint.ErrorCodeQuoteExpired:
		return "quote expired", true
	case entrypoint.ErrorCodeProvisioningFailed:
		return "provisioning failed", true
	case entrypoint.ErrorCodeVerificationFailed:
		return "verification failed", true
	case entrypoint.ErrorCodeDestroyBlocked:
		return "destruction blocked", true
	default:
		return "", false
	}
}

type entryRowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readEntryPlanRow(ctx context.Context, query entryRowQuerier, suffix string, args ...any) (entryPlanRow, error) {
	return scanEntryPlanRow(query.QueryRow(ctx, `SELECT `+cloudEntryPlanColumns+` FROM cloud_entry_plans`+suffix, args...))
}

type entryScanner interface{ Scan(...any) error }

func scanEntryPlanRow(row entryScanner) (entryPlanRow, error) {
	var entryPlanID, agentID, deploymentID, taskID, originalPlanID, originalApprovalID, connectionID, workerResourceID uuid.UUID
	var ownerID, originalPlanHash, workerSpecDigest, scopeDigest, planHash, createClientID string
	var workerResourceRevision, revision int64
	var scopeJSON, planCBOR, createHash []byte
	var status entrypoint.PlanStatus
	var createCredentialID, createIdempotencyKey uuid.UUID
	var createdAt, updatedAt time.Time
	err := row.Scan(&entryPlanID, &agentID, &ownerID, &deploymentID, &taskID,
		&originalPlanID, &originalPlanHash, &originalApprovalID, &connectionID,
		&workerResourceID, &workerResourceRevision, &workerSpecDigest,
		&scopeDigest, &scopeJSON, &planHash, &planCBOR, &status, &revision,
		&createClientID, &createCredentialID, &createIdempotencyKey, &createHash, &createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return entryPlanRow{}, entrypoint.ErrNotFound
	}
	if err != nil || len(createHash) != 32 || revision < 1 || workerResourceRevision < 1 {
		return entryPlanRow{}, entrypoint.ErrUnavailable
	}
	var scope entrypoint.ScopeV1
	if json.Unmarshal(scopeJSON, &scope) != nil {
		return entryPlanRow{}, entrypoint.ErrUnavailable
	}
	plan := entrypoint.PlanV1{SchemaVersion: entrypoint.PlanSchemaV1, EntryPlanID: entryPlanID.String(), Revision: uint64(revision), Status: status,
		Scope: scope, ScopeDigest: scopeDigest}
	canonicalCBOR, canonicalErr := plan.CanonicalCBOR()
	computedHash, hashErr := plan.Hash()
	if canonicalErr != nil || hashErr != nil || !bytes.Equal(canonicalCBOR, planCBOR) || computedHash != planHash ||
		!sameStoredEntryPlanFacts(plan, agentID, ownerID, deploymentID, taskID, originalPlanID, originalPlanHash, originalApprovalID,
			connectionID, workerResourceID, workerResourceRevision, workerSpecDigest) {
		return entryPlanRow{}, entrypoint.ErrUnavailable
	}
	var requestHash [32]byte
	copy(requestHash[:], createHash)
	mutation := entrypoint.Mutation{Caller: task.MutationScope{ClientID: createClientID, CredentialID: createCredentialID.String()},
		OwnerID: ownerID, IdempotencyKey: createIdempotencyKey.String(), RequestHash: requestHash}
	if mutation.Validate() != nil {
		return entryPlanRow{}, entrypoint.ErrUnavailable
	}
	return entryPlanRow{Plan: plan, PlanHash: planHash, PlanCBOR: append([]byte(nil), planCBOR...), Create: mutation,
		CreatedAt: createdAt.UTC(), UpdatedAt: updatedAt.UTC()}, nil
}

func readEntryOperationRow(ctx context.Context, query entryRowQuerier, suffix string, args ...any) (entryOperationRow, error) {
	return scanEntryOperationRow(query.QueryRow(ctx, `SELECT `+cloudEntryOperationColumns+` FROM cloud_entry_operations`+suffix, args...))
}

func scanEntryOperationRow(row entryScanner) (entryOperationRow, error) {
	var operationID, agentID, entryPlanID, deploymentID, taskID, originalPlanID, originalApprovalID, connectionID uuid.UUID
	var challengeID, approvalID uuid.UUID
	var ownerID, originalPlanHash, signerKeyID, entryPlanHash, scopeDigest, prepareClientID string
	var expectedPlanRevision, revision int64
	var challengeJSON, signingPayload, signatureJSON, signature, prepareHash, approveHash []byte
	var status entrypoint.Status
	var errorCode, errorSummary, approveClientID *string
	var prepareCredentialID, prepareIdempotencyKey uuid.UUID
	var approveCredentialID, approveIdempotencyKey *uuid.UUID
	var challengeIssuedAt, challengeExpiresAt, createdAt, updatedAt time.Time
	var approvedAt *time.Time
	err := row.Scan(&operationID, &agentID, &ownerID, &entryPlanID,
		&deploymentID, &taskID, &originalPlanID, &originalPlanHash, &originalApprovalID,
		&connectionID, &challengeID, &approvalID, &signerKeyID,
		&expectedPlanRevision, &entryPlanHash, &scopeDigest, &challengeJSON,
		&signingPayload, &challengeIssuedAt, &challengeExpiresAt, &signatureJSON, &signature,
		&status, &errorCode, &errorSummary, &revision,
		&prepareClientID, &prepareCredentialID, &prepareIdempotencyKey, &prepareHash,
		&approveClientID, &approveCredentialID, &approveIdempotencyKey, &approveHash,
		&createdAt, &updatedAt, &approvedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return entryOperationRow{}, entrypoint.ErrNotFound
	}
	if err != nil || len(prepareHash) != 32 || expectedPlanRevision < 1 || revision < 1 {
		return entryOperationRow{}, entrypoint.ErrUnavailable
	}
	var challenge entrypoint.ChallengeV1
	if json.Unmarshal(challengeJSON, &challenge) != nil {
		return entryOperationRow{}, entrypoint.ErrUnavailable
	}
	challenge.SigningCBOR = append([]byte(nil), signingPayload...)
	if challenge.Validate() != nil || !bytes.Equal(mustEntrySigningPayload(challenge), signingPayload) ||
		challenge.OperationID != operationID.String() || challenge.ChallengeID != challengeID.String() || challenge.ApprovalID != approvalID.String() ||
		challenge.EntryPlanID != entryPlanID.String() || challenge.EntryPlanRevision != uint64(expectedPlanRevision) ||
		challenge.PlanHash != entryPlanHash || challenge.ScopeDigest != scopeDigest || challenge.SignerKeyID != signerKeyID ||
		!challenge.IssuedAt.Equal(challengeIssuedAt) || !challenge.ExpiresAt.Equal(challengeExpiresAt) || agentID == uuid.Nil {
		return entryOperationRow{}, entrypoint.ErrUnavailable
	}
	operation := entrypoint.OperationV1{Challenge: challenge, Status: status, Revision: revision,
		CreatedAt: createdAt.UTC(), UpdatedAt: updatedAt.UTC(), ApprovedAt: cloneEntryTime(approvedAt)}
	if errorCode != nil {
		operation.ErrorCode = entrypoint.ErrorCode(*errorCode)
	}
	if errorSummary != nil {
		operation.ErrorSummary = *errorSummary
	}
	if signatureJSON != nil || signature != nil {
		if len(signatureJSON) == 0 || len(signature) == 0 {
			return entryOperationRow{}, entrypoint.ErrUnavailable
		}
		var value entrypoint.SignatureV1
		if json.Unmarshal(signatureJSON, &value) != nil {
			return entryOperationRow{}, entrypoint.ErrUnavailable
		}
		value.Signature = append([]byte(nil), signature...)
		operation.Signature = &value
	}
	if operation.Validate() != nil || operation.Challenge.EntryPlanID == "" ||
		operation.Challenge.EntryPlanRevision != uint64(expectedPlanRevision) || originalPlanHash == "" ||
		!sameStoredEntryOperationFacts(operation, agentID, ownerID, entryPlanID, deploymentID, taskID, originalPlanID,
			originalPlanHash, originalApprovalID, connectionID) {
		return entryOperationRow{}, entrypoint.ErrUnavailable
	}
	var prepareDigest [32]byte
	copy(prepareDigest[:], prepareHash)
	result := entryOperationRow{Operation: operation, EntryPlanID: entryPlanID.String(), OwnerID: ownerID,
		DeploymentID: deploymentID.String(), TaskID: taskID.String(), OriginalPlanID: originalPlanID.String(),
		OriginalPlanHash: originalPlanHash, OriginalApprovalID: originalApprovalID.String(), ConnectionID: connectionID.String(),
		Prepare: entrypoint.Mutation{Caller: task.MutationScope{ClientID: prepareClientID, CredentialID: prepareCredentialID.String()},
			OwnerID: ownerID, IdempotencyKey: prepareIdempotencyKey.String(), RequestHash: prepareDigest}}
	if result.Prepare.Validate() != nil {
		return entryOperationRow{}, entrypoint.ErrUnavailable
	}
	if approveClientID != nil {
		if approveCredentialID == nil || approveIdempotencyKey == nil || len(approveHash) != 32 {
			return entryOperationRow{}, entrypoint.ErrUnavailable
		}
		var approveDigest [32]byte
		copy(approveDigest[:], approveHash)
		approve := entrypoint.Mutation{Caller: task.MutationScope{ClientID: *approveClientID, CredentialID: approveCredentialID.String()},
			OwnerID: ownerID, IdempotencyKey: approveIdempotencyKey.String(), RequestHash: approveDigest}
		if approve.Validate() != nil {
			return entryOperationRow{}, entrypoint.ErrUnavailable
		}
		result.Approve = &approve
	} else if operation.Signature != nil {
		return entryOperationRow{}, entrypoint.ErrUnavailable
	}
	return result, nil
}

func entryOperationRecoverable(status entrypoint.Status) bool {
	switch status {
	case entrypoint.StatusApproved, entrypoint.StatusProvisioning, entrypoint.StatusVerifying, entrypoint.StatusActive,
		entrypoint.StatusDestroying, entrypoint.StatusDestroyBlocked:
		return true
	default:
		return false
	}
}

func entryPlanMatchesRecoveryOperation(instanceID uuid.UUID, plan entryPlanRow, operation entryOperationRow) bool {
	if plan.Plan.Validate() != nil || plan.Plan.Status != entrypoint.PlanApproved ||
		plan.Plan.Scope.AgentInstanceID != instanceID.String() || plan.Plan.Scope.OwnerID != operation.OwnerID ||
		plan.Plan.EntryPlanID != operation.EntryPlanID {
		return false
	}
	challenge := operation.Operation.Challenge
	if challenge.EntryPlanID != plan.Plan.EntryPlanID || challenge.EntryPlanRevision != plan.Plan.Revision ||
		challenge.PlanHash != plan.PlanHash || challenge.ScopeDigest != plan.Plan.ScopeDigest ||
		plan.Plan.Scope.Worker.DeploymentID != operation.DeploymentID ||
		plan.Plan.Scope.Worker.TaskID != operation.TaskID ||
		plan.Plan.Scope.Worker.OriginalPlanID != operation.OriginalPlanID ||
		plan.Plan.Scope.Worker.OriginalPlanHash != operation.OriginalPlanHash ||
		plan.Plan.Scope.Worker.OriginalApprovalID != operation.OriginalApprovalID ||
		plan.Plan.Scope.ConnectionID != operation.ConnectionID {
		return false
	}
	return operation.Prepare.OwnerID == operation.OwnerID
}

func (store *Store) validateEntryPlanPrerequisites(ctx context.Context, query entryRowQuerier, scope entrypoint.ScopeV1) error {
	var launchAgent, approvalAgent, connectionAgent, workerAgent, resourceAgent uuid.UUID
	var launchOwner, approvalOwner, connectionOwner, workerOwner, resourceOwner string
	var launchTaskID, launchPlanID, launchApprovalID, launchConnectionID uuid.UUID
	var originalPlanHash, originalPlanStatus, approvalPlanHash, connectionRegion, connectionStatus string
	var approvalPlanID uuid.UUID
	var workerTaskID uuid.UUID
	var workerState, workerOutcome string
	var workerRevision int64
	var workerInstanceID *string
	var resourceTaskID, resourceDeploymentID uuid.UUID
	var resourceRevision int64
	var resourceType, resourceRegion, resourceSpecDigest, resourcePlanHash, resourceProviderID, resourceRetention, resourceState string
	var resourceApprovalID *uuid.UUID
	var resourceDeadline, resourceObservedAt *time.Time
	var resourceAutoDestroy, resourceReadBackExists bool
	var resourceReadBackProviderID, resourceReadBackTagDigest string
	err := query.QueryRow(ctx, `SELECT
		launch.agent_instance_id, launch.owner_id, launch.task_id, launch.plan_id, launch.approval_id, launch.connection_id,
		plan.plan_hash, plan.status,
		approval.agent_instance_id, approval.owner_id, approval.plan_id, approval.plan_hash,
		connection.agent_instance_id, connection.owner_id, connection.region, connection.status,
		worker.agent_instance_id, worker.owner_id, worker.task_id, worker.state, worker.outcome, worker.revision, worker.provider_instance_id,
		resource.agent_instance_id, resource.owner_id, resource.task_id, resource.deployment_id, resource.resource_type,
		resource.region, resource.spec_digest, resource.approved_plan_hash, resource.approval_id, resource.provider_id,
		resource.retention, resource.destroy_deadline, resource.auto_destroy_approved, resource.state, resource.revision,
		resource.readback_exists, resource.readback_provider_id, resource.readback_observed_at, resource.readback_tag_digest
		FROM cloud_launch_operations launch
		JOIN cloud_plans plan ON plan.plan_id=launch.plan_id
		JOIN cloud_approvals approval ON approval.approval_id=launch.approval_id
		JOIN cloud_connections connection ON connection.connection_id=launch.connection_id
		JOIN worker_deployments worker ON worker.deployment_id=launch.deployment_id
		JOIN cloud_resources resource ON resource.resource_id=$2
		WHERE launch.deployment_id=$1
		FOR SHARE OF launch, plan, connection, worker, resource`, scope.Worker.DeploymentID, scope.Worker.WorkerResourceID).Scan(
		&launchAgent, &launchOwner, &launchTaskID, &launchPlanID, &launchApprovalID, &launchConnectionID,
		&originalPlanHash, &originalPlanStatus,
		&approvalAgent, &approvalOwner, &approvalPlanID, &approvalPlanHash,
		&connectionAgent, &connectionOwner, &connectionRegion, &connectionStatus,
		&workerAgent, &workerOwner, &workerTaskID, &workerState, &workerOutcome, &workerRevision, &workerInstanceID,
		&resourceAgent, &resourceOwner, &resourceTaskID, &resourceDeploymentID, &resourceType,
		&resourceRegion, &resourceSpecDigest, &resourcePlanHash, &resourceApprovalID, &resourceProviderID,
		&resourceRetention, &resourceDeadline, &resourceAutoDestroy, &resourceState, &resourceRevision,
		&resourceReadBackExists, &resourceReadBackProviderID, &resourceObservedAt, &resourceReadBackTagDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return entrypoint.ErrRevisionConflict
	}
	if err != nil {
		return entrypoint.ErrUnavailable
	}
	if launchAgent != store.instanceID || approvalAgent != store.instanceID || connectionAgent != store.instanceID || workerAgent != store.instanceID || resourceAgent != store.instanceID ||
		launchOwner != scope.OwnerID || approvalOwner != scope.OwnerID || connectionOwner != scope.OwnerID || workerOwner != scope.OwnerID || resourceOwner != scope.OwnerID ||
		launchTaskID.String() != scope.Worker.TaskID || workerTaskID.String() != scope.Worker.TaskID || resourceTaskID.String() != scope.Worker.TaskID ||
		launchPlanID.String() != scope.Worker.OriginalPlanID || approvalPlanID != launchPlanID || launchApprovalID.String() != scope.Worker.OriginalApprovalID ||
		launchConnectionID.String() != scope.ConnectionID || originalPlanHash != scope.Worker.OriginalPlanHash || originalPlanStatus != "approved" ||
		approvalPlanHash != scope.Worker.OriginalPlanHash ||
		connectionRegion != scope.Region || connectionStatus != "active" || workerState != "finished" || workerOutcome != string(entrypoint.WorkerOutcomeSucceeded) ||
		workerRevision != scope.Worker.DeploymentRevision || workerInstanceID == nil || *workerInstanceID != scope.Worker.InstanceID ||
		resourceDeploymentID.String() != scope.Worker.DeploymentID || resourceType != "ec2" || resourceRegion != scope.Region ||
		resourceSpecDigest != scope.Worker.WorkerSpecDigest || resourcePlanHash != scope.Worker.OriginalPlanHash || resourceApprovalID == nil ||
		resourceApprovalID.String() != scope.Worker.OriginalApprovalID || resourceProviderID != scope.Worker.InstanceID ||
		resourceRevision != scope.Worker.WorkerResourceRevision || !resourceReadBackExists ||
		resourceReadBackProviderID != scope.Worker.InstanceID || resourceReadBackTagDigest != scope.Worker.ReadBack.TagDigest ||
		resourceObservedAt == nil || !resourceObservedAt.Equal(scope.Worker.ReadBack.ObservedAt) {
		return entrypoint.ErrRevisionConflict
	}
	if !entryRetentionMatchesResource(scope, resourceRetention, resourceAutoDestroy, resourceDeadline, resourceState) {
		return entrypoint.ErrRevisionConflict
	}
	var quoteAgent, quoteConnection uuid.UUID
	var quoteOwner, quoteDigest string
	var quoteAt, quoteUntil time.Time
	err = query.QueryRow(ctx, `SELECT agent_instance_id, owner_id, connection_id, quote_digest, quoted_at, valid_until
		FROM cloud_quotes WHERE quote_id=$1 FOR SHARE`, scope.Cost.QuoteID).Scan(&quoteAgent, &quoteOwner, &quoteConnection, &quoteDigest, &quoteAt, &quoteUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return entrypoint.ErrRevisionConflict
	}
	if err != nil || quoteAgent != store.instanceID || quoteOwner != scope.OwnerID || quoteConnection.String() != scope.ConnectionID ||
		quoteDigest != scope.Cost.QuoteDigest || !quoteAt.Equal(scope.Cost.QuotedAt) || !quoteUntil.Equal(scope.Cost.ValidUntil) {
		return entrypoint.ErrRevisionConflict
	}
	return nil
}

func entryRetentionMatchesResource(scope entrypoint.ScopeV1, retention string, autoDestroy bool, deadline *time.Time, state string) bool {
	switch scope.Retention.Class {
	case entrypoint.RetentionEphemeral:
		return retention == string(task.RetentionEphemeralAutoDestroy) && autoDestroy && deadline != nil && deadline.Equal(scope.Retention.DestroyDeadline) && state == "active"
	case entrypoint.RetentionManaged:
		return retention == string(task.RetentionManaged) && !autoDestroy && deadline == nil && (state == "active" || state == "retained_managed")
	default:
		return false
	}
}

func (store *Store) validateActiveEntryDevice(ctx context.Context, query entryRowQuerier, keyID, ownerID string, at time.Time) error {
	_, err := store.readActiveEntryDevice(ctx, query, keyID, ownerID, at)
	return err
}

func (store *Store) readActiveEntryDevice(ctx context.Context, query entryRowQuerier, keyID, ownerID string, at time.Time) (ed25519.PublicKey, error) {
	var publicKey []byte
	var deviceAgent uuid.UUID
	var deviceOwner, status string
	var notBefore, expiresAt time.Time
	var revokedAt *time.Time
	err := query.QueryRow(ctx, `SELECT public_key, agent_instance_id, owner_id, status, not_before, expires_at, revoked_at
		FROM cloud_approval_devices WHERE key_id=$1 FOR SHARE`, keyID).Scan(&publicKey, &deviceAgent, &deviceOwner, &status, &notBefore, &expiresAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, entrypoint.ErrApprovalRequired
	}
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, entrypoint.ErrUnavailable
	}
	if deviceAgent != store.instanceID || deviceOwner != ownerID || status != string(cloudapproval.DeviceKeyActive) || revokedAt != nil {
		return nil, entrypoint.ErrApprovalRequired
	}
	if at.Before(notBefore) || !at.Before(expiresAt) {
		return nil, entrypoint.ErrApprovalExpired
	}
	return ed25519.PublicKey(append([]byte(nil), publicKey...)), nil
}

func sameStoredEntryPlanFacts(plan entrypoint.PlanV1, agentID uuid.UUID, ownerID string, deploymentID, taskID, originalPlanID uuid.UUID, originalPlanHash string, originalApprovalID, connectionID, workerResourceID uuid.UUID, workerResourceRevision int64, workerSpecDigest string) bool {
	worker := plan.Scope.Worker
	return agentID.String() == plan.Scope.AgentInstanceID && ownerID == plan.Scope.OwnerID &&
		deploymentID.String() == worker.DeploymentID && taskID.String() == worker.TaskID &&
		originalPlanID.String() == worker.OriginalPlanID && originalPlanHash == worker.OriginalPlanHash &&
		originalApprovalID.String() == worker.OriginalApprovalID && connectionID.String() == plan.Scope.ConnectionID &&
		workerResourceID.String() == worker.WorkerResourceID && workerResourceRevision == worker.WorkerResourceRevision &&
		workerSpecDigest == worker.WorkerSpecDigest
}

func sameStoredEntryOperationFacts(operation entrypoint.OperationV1, agentID uuid.UUID, ownerID string, entryPlanID, deploymentID, taskID, originalPlanID uuid.UUID, originalPlanHash string, originalApprovalID, connectionID uuid.UUID) bool {
	challenge := operation.Challenge
	return agentID != uuid.Nil && ownerID != "" && challenge.EntryPlanID == entryPlanID.String() &&
		operation.Challenge.EntryPlanID != "" && deploymentID != uuid.Nil && taskID != uuid.Nil && originalPlanID != uuid.Nil &&
		originalPlanHash != "" && originalApprovalID != uuid.Nil && connectionID != uuid.Nil
}

func sameEntryPlanCreate(existing entryPlanRow, mutation entrypoint.Mutation, plan entrypoint.PlanV1, planHash string, planCBOR []byte) bool {
	return sameEntryMutation(existing.Create, mutation) && existing.Plan.EntryPlanID == plan.EntryPlanID &&
		existing.Plan.ScopeDigest == plan.ScopeDigest && existing.PlanHash == planHash && bytes.Equal(existing.PlanCBOR, planCBOR)
}

func sameEntryPrepare(existing entryOperationRow, mutation entrypoint.Mutation, challenge entrypoint.ChallengeV1) bool {
	return sameEntryMutation(existing.Prepare, mutation) && existing.Operation.Challenge.OperationID == challenge.OperationID &&
		existing.Operation.Challenge.ChallengeID == challenge.ChallengeID && existing.Operation.Challenge.ApprovalID == challenge.ApprovalID &&
		existing.Operation.Challenge.EntryPlanID == challenge.EntryPlanID && existing.Operation.Challenge.EntryPlanRevision == challenge.EntryPlanRevision &&
		existing.Operation.Challenge.PlanHash == challenge.PlanHash && existing.Operation.Challenge.ScopeDigest == challenge.ScopeDigest &&
		existing.Operation.Challenge.SignerKeyID == challenge.SignerKeyID && existing.Operation.Challenge.IssuedAt.Equal(challenge.IssuedAt) &&
		existing.Operation.Challenge.ExpiresAt.Equal(challenge.ExpiresAt) && bytes.Equal(existing.Operation.Challenge.SigningCBOR, challenge.SigningCBOR)
}

func sameEntryApprove(existing entryOperationRow, mutation entrypoint.Mutation, challengeID string, signature entrypoint.SignatureV1) bool {
	return existing.Approve != nil && sameEntryMutation(*existing.Approve, mutation) &&
		existing.Operation.Challenge.ChallengeID == challengeID && existing.Prepare.OwnerID == mutation.OwnerID &&
		existing.Operation.Signature != nil && entrySignatureMatchesChallenge(existing.Operation.Challenge, signature) &&
		subtle.ConstantTimeCompare(existing.Operation.Signature.Signature, signature.Signature) == 1
}

func sameEntryMutation(left, right entrypoint.Mutation) bool {
	return left.Caller == right.Caller && left.OwnerID == right.OwnerID && left.IdempotencyKey == right.IdempotencyKey &&
		subtle.ConstantTimeCompare(left.RequestHash[:], right.RequestHash[:]) == 1
}

func entrySignatureMatchesChallenge(challenge entrypoint.ChallengeV1, signature entrypoint.SignatureV1) bool {
	return signature.ApprovalID == challenge.ApprovalID && signature.ChallengeID == challenge.ChallengeID &&
		signature.EntryPlanID == challenge.EntryPlanID && signature.EntryPlanRevision == challenge.EntryPlanRevision &&
		signature.PlanHash == challenge.PlanHash && signature.ScopeDigest == challenge.ScopeDigest &&
		signature.SignerKeyID == challenge.SignerKeyID && signature.ExpiresAt.Equal(challenge.ExpiresAt)
}

func sameEntryOperationIdentity(current, next entrypoint.OperationV1) bool {
	if current.Challenge.OperationID != next.Challenge.OperationID || current.Challenge.ChallengeID != next.Challenge.ChallengeID ||
		current.Challenge.ApprovalID != next.Challenge.ApprovalID || current.Challenge.EntryPlanID != next.Challenge.EntryPlanID ||
		current.Challenge.EntryPlanRevision != next.Challenge.EntryPlanRevision || current.Challenge.PlanHash != next.Challenge.PlanHash ||
		current.Challenge.ScopeDigest != next.Challenge.ScopeDigest || current.Challenge.SignerKeyID != next.Challenge.SignerKeyID ||
		!current.Challenge.IssuedAt.Equal(next.Challenge.IssuedAt) || !current.Challenge.ExpiresAt.Equal(next.Challenge.ExpiresAt) ||
		!bytes.Equal(current.Challenge.SigningCBOR, next.Challenge.SigningCBOR) || !entrySignaturePointersEqual(current.Signature, next.Signature) ||
		!entryTimePointersEqual(current.ApprovedAt, next.ApprovedAt) || !current.CreatedAt.Equal(next.CreatedAt) {
		return false
	}
	return true
}

func entrySignaturePointersEqual(left, right *entrypoint.SignatureV1) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.ApprovalID == right.ApprovalID && left.ChallengeID == right.ChallengeID && left.EntryPlanID == right.EntryPlanID &&
		left.EntryPlanRevision == right.EntryPlanRevision && left.PlanHash == right.PlanHash && left.ScopeDigest == right.ScopeDigest &&
		left.SignerKeyID == right.SignerKeyID && left.ExpiresAt.Equal(right.ExpiresAt) &&
		subtle.ConstantTimeCompare(left.Signature, right.Signature) == 1
}

func entryTimePointersEqual(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Equal(*right)
}

func validEntryTransition(current, next entrypoint.Status) bool {
	switch current {
	case entrypoint.StatusApproved:
		return next == entrypoint.StatusProvisioning || next == entrypoint.StatusFailed || next == entrypoint.StatusDestroying
	case entrypoint.StatusProvisioning:
		return next == entrypoint.StatusVerifying || next == entrypoint.StatusFailed || next == entrypoint.StatusDestroying
	case entrypoint.StatusVerifying:
		return next == entrypoint.StatusActive || next == entrypoint.StatusFailed || next == entrypoint.StatusDestroying
	case entrypoint.StatusActive, entrypoint.StatusFailed:
		return next == entrypoint.StatusDestroying
	case entrypoint.StatusDestroying:
		return next == entrypoint.StatusDestroyed || next == entrypoint.StatusDestroyBlocked
	case entrypoint.StatusDestroyBlocked:
		return next == entrypoint.StatusDestroying || next == entrypoint.StatusDestroyBlocked
	default:
		return false
	}
}

func mustEntrySigningPayload(challenge entrypoint.ChallengeV1) []byte {
	payload, err := challenge.SigningPayload()
	if err != nil {
		return nil
	}
	return payload
}

func cloneEntryTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}

func nullableEntryString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.TrimSpace(value)
}

func validEntryUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed != uuid.Nil
}
