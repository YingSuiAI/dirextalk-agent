package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const workerIdentityReplayAADDomain = "dirextalk.agent/worker-identity-enrollment-replay/v1"

func (store *WorkerStore) CreateIdentityChallengeIdempotent(ctx context.Context, intent worker.IdentityChallengeIntent) (worker.IdentityChallenge, error) {
	challengeID, deploymentID, workerID, key, err := validateIdentityChallengeIntent(intent)
	if err != nil {
		return worker.IdentityChallenge{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return worker.IdentityChallenge{}, fmt.Errorf("begin Worker identity challenge: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	challenge, err := scanWorkerIdentityChallenge(tx.QueryRow(ctx, workerIdentityChallengeSelect+`
		WHERE deployment_id=$1 AND worker_id=$2 AND idempotency_key=$3 AND agent_instance_id=$4`,
		deploymentID, workerID, key, store.instanceID))
	if err == nil {
		if subtle.ConstantTimeCompare(challenge.RequestHash[:], intent.RequestHash[:]) != 1 {
			return worker.IdentityChallenge{}, worker.ErrIdempotencyConflict
		}
		if challenge.ConsumedAt.IsZero() && !intent.CreatedAt.Before(challenge.ExpiresAt) {
			challenge, err = store.renewIdentityChallenge(ctx, tx, intent, challenge, deploymentID, workerID, key)
			if err != nil {
				return worker.IdentityChallenge{}, err
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return worker.IdentityChallenge{}, fmt.Errorf("commit Worker identity challenge replay: %w", err)
		}
		return challenge, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return worker.IdentityChallenge{}, fmt.Errorf("load Worker identity challenge replay: %w", err)
	}

	current, err := loadWorkerForUpdate(ctx, tx, deploymentID, store.instanceID)
	if err != nil {
		return worker.IdentityChallenge{}, err
	}
	challenge, err = scanWorkerIdentityChallenge(tx.QueryRow(ctx, workerIdentityChallengeSelect+`
		WHERE deployment_id=$1 AND worker_id=$2 AND idempotency_key=$3 AND agent_instance_id=$4`,
		deploymentID, workerID, key, store.instanceID))
	if err == nil {
		if subtle.ConstantTimeCompare(challenge.RequestHash[:], intent.RequestHash[:]) != 1 {
			return worker.IdentityChallenge{}, worker.ErrIdempotencyConflict
		}
		if challenge.ConsumedAt.IsZero() && !intent.CreatedAt.Before(challenge.ExpiresAt) {
			return worker.IdentityChallenge{}, worker.ErrIdentityChallengeExpired
		}
		if err := tx.Commit(ctx); err != nil {
			return worker.IdentityChallenge{}, fmt.Errorf("commit concurrent Worker identity challenge replay: %w", err)
		}
		return challenge, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return worker.IdentityChallenge{}, fmt.Errorf("load concurrent Worker identity challenge replay: %w", err)
	}
	if current.Revision != intent.ExpectedRevision {
		return worker.IdentityChallenge{}, worker.ErrRevisionConflict
	}
	if current.State != worker.StatePendingEnrollment || current.WorkerID != "" || !current.Enrollment.ConsumedAt.IsZero() {
		return worker.IdentityChallenge{}, worker.ErrEnrollmentConsumed
	}
	if !intent.CreatedAt.Before(current.Enrollment.ExpiresAt) {
		return worker.IdentityChallenge{}, worker.ErrEnrollmentExpired
	}

	binding, err := loadWorkerIdentityProviderBinding(ctx, tx, store.instanceID, deploymentID, current)
	if err != nil {
		return worker.IdentityChallenge{}, err
	}
	expiresAt := boundedIdentityChallengeExpiry(intent.ExpiresAt, current.Enrollment.ExpiresAt)

	challenge = worker.IdentityChallenge{
		ChallengeID: challengeID.String(), DeploymentID: deploymentID.String(), WorkerID: workerID.String(),
		OwnerID: binding.ownerID, AccountID: binding.accountID, Region: binding.region, ExpectedProviderInstanceID: binding.providerInstanceID,
		ExpectedRevision: intent.ExpectedRevision, RequestHash: intent.RequestHash, ExpiresAt: expiresAt, Revision: 1, CreatedAt: intent.CreatedAt.UTC(),
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO worker_identity_challenges (
			challenge_id, agent_instance_id, deployment_id, worker_id, idempotency_key, request_hash,
			owner_id, account_id, region, expected_provider_instance_id, expected_revision,
			expires_at, revision, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		challengeID, store.instanceID, deploymentID, workerID, key, intent.RequestHash[:], binding.ownerID, binding.accountID, binding.region,
		binding.providerInstanceID, intent.ExpectedRevision, challenge.ExpiresAt, challenge.Revision, challenge.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return worker.IdentityChallenge{}, worker.ErrIdempotencyConflict
		}
		return worker.IdentityChallenge{}, fmt.Errorf("persist Worker identity challenge: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return worker.IdentityChallenge{}, fmt.Errorf("commit Worker identity challenge: %w", err)
	}
	return challenge, nil
}

func (store *WorkerStore) renewIdentityChallenge(
	ctx context.Context,
	tx pgx.Tx,
	intent worker.IdentityChallengeIntent,
	observed worker.IdentityChallenge,
	deploymentID, workerID, key uuid.UUID,
) (worker.IdentityChallenge, error) {
	challenge, err := scanWorkerIdentityChallenge(tx.QueryRow(ctx, workerIdentityChallengeSelect+`
		WHERE deployment_id=$1 AND worker_id=$2 AND idempotency_key=$3 AND agent_instance_id=$4 FOR UPDATE`,
		deploymentID, workerID, key, store.instanceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return worker.IdentityChallenge{}, worker.ErrNotFound
	}
	if err != nil {
		return worker.IdentityChallenge{}, fmt.Errorf("lock Worker identity challenge renewal: %w", err)
	}
	if subtle.ConstantTimeCompare(challenge.RequestHash[:], intent.RequestHash[:]) != 1 {
		return worker.IdentityChallenge{}, worker.ErrIdempotencyConflict
	}
	if !challenge.ConsumedAt.IsZero() || intent.CreatedAt.Before(challenge.ExpiresAt) {
		return challenge, nil
	}
	if challenge.ChallengeID != observed.ChallengeID {
		return worker.IdentityChallenge{}, worker.ErrIdempotencyConflict
	}

	current, err := loadWorkerForUpdate(ctx, tx, deploymentID, store.instanceID)
	if err != nil {
		return worker.IdentityChallenge{}, err
	}
	if current.Revision != intent.ExpectedRevision || challenge.ExpectedRevision != intent.ExpectedRevision {
		return worker.IdentityChallenge{}, worker.ErrRevisionConflict
	}
	if current.State != worker.StatePendingEnrollment || current.WorkerID != "" || !current.Enrollment.ConsumedAt.IsZero() {
		return worker.IdentityChallenge{}, worker.ErrEnrollmentConsumed
	}
	if !intent.CreatedAt.Before(current.Enrollment.ExpiresAt) {
		return worker.IdentityChallenge{}, worker.ErrEnrollmentExpired
	}
	binding, err := loadWorkerIdentityProviderBinding(ctx, tx, store.instanceID, deploymentID, current)
	if err != nil {
		return worker.IdentityChallenge{}, err
	}
	if current.OwnerID != challenge.OwnerID || binding.ownerID != challenge.OwnerID || binding.accountID != challenge.AccountID ||
		binding.region != challenge.Region || binding.providerInstanceID != challenge.ExpectedProviderInstanceID {
		return worker.IdentityChallenge{}, worker.ErrIdentityUnavailable
	}
	if intent.ChallengeID == challenge.ChallengeID {
		return worker.IdentityChallenge{}, worker.ErrInvalid
	}

	expiresAt := boundedIdentityChallengeExpiry(intent.ExpiresAt, current.Enrollment.ExpiresAt)
	result, err := tx.Exec(ctx, `
		UPDATE worker_identity_challenges
		SET challenge_id=$3, expires_at=$4, created_at=$5, revision=revision+1
		WHERE challenge_id=$1 AND revision=$2 AND consumed_at IS NULL AND expires_at <= $5`,
		challenge.ChallengeID, challenge.Revision, intent.ChallengeID, expiresAt, intent.CreatedAt.UTC(),
	)
	if err != nil {
		return worker.IdentityChallenge{}, fmt.Errorf("renew Worker identity challenge: %w", err)
	}
	if result.RowsAffected() != 1 {
		return worker.IdentityChallenge{}, worker.ErrRevisionConflict
	}
	challenge.ChallengeID = intent.ChallengeID
	challenge.ExpiresAt = expiresAt
	challenge.CreatedAt = intent.CreatedAt.UTC()
	challenge.Revision++
	return challenge, nil
}

type workerIdentityProviderBinding struct {
	ownerID            string
	accountID          string
	region             string
	providerInstanceID string
}

func loadWorkerIdentityProviderBinding(
	ctx context.Context,
	tx pgx.Tx,
	instanceID, deploymentID uuid.UUID,
	current worker.Deployment,
) (workerIdentityProviderBinding, error) {
	var binding workerIdentityProviderBinding
	var matches int
	err := tx.QueryRow(ctx, `
		WITH provider_bindings AS (
		    SELECT cc.account_id, cc.region, launch.owner_id,
		           resource.provider_id
		    FROM cloud_launch_operations launch
		    JOIN cloud_connections cc
		      ON cc.connection_id=launch.connection_id
		     AND cc.agent_instance_id=launch.agent_instance_id
		     AND cc.owner_id=launch.owner_id
		    JOIN cloud_resources resource
		      ON resource.agent_instance_id=launch.agent_instance_id
		     AND resource.owner_id=launch.owner_id
		     AND resource.deployment_id=launch.deployment_id
		     AND resource.task_id=launch.task_id
		    WHERE launch.agent_instance_id=$1
		      AND launch.deployment_id=$2
		      AND launch.owner_id=$3
		      AND launch.task_id=$4
		      AND cc.status='active'
		      AND resource.resource_type='ec2'
		      AND resource.provider_id <> ''
		      AND resource.state IN ('provisioning','active')
		    UNION ALL
		    SELECT cc.account_id, cc.region, dispatch.owner_id,
		           resource.provider_id
		    FROM team_role_dispatches dispatch
		    JOIN team_executions execution
		      ON execution.execution_id=dispatch.execution_id
		     AND execution.agent_instance_id=dispatch.agent_instance_id
		     AND execution.owner_id=dispatch.owner_id
		     AND execution.task_id=dispatch.task_id
		    JOIN cloud_connections cc
		      ON cc.connection_id=execution.connection_id
		     AND cc.agent_instance_id=execution.agent_instance_id
		     AND cc.owner_id=execution.owner_id
		     AND cc.account_id=execution.account_id
		     AND cc.region=execution.region
		    JOIN cloud_resources resource
		      ON resource.agent_instance_id=dispatch.agent_instance_id
		     AND resource.owner_id=dispatch.owner_id
		     AND resource.deployment_id=dispatch.deployment_id
		     AND resource.task_id=dispatch.task_id
		    WHERE dispatch.agent_instance_id=$1
		      AND dispatch.deployment_id=$2
		      AND dispatch.owner_id=$3
		      AND dispatch.task_id=$4
		      AND dispatch.phase IN ('provisioning','active')
		      AND dispatch.published_evidence_json->>'connection_id'=
		          execution.connection_id::text
		      AND cc.status='active'
		      AND resource.resource_type='ec2'
		      AND resource.provider_id <> ''
		      AND resource.state IN ('provisioning','active')
		)
		SELECT account_id, region, owner_id, provider_id,
		       count(*) OVER ()
		FROM provider_bindings`,
		instanceID, deploymentID, current.OwnerID, current.TaskID,
	).Scan(&binding.accountID, &binding.region, &binding.ownerID, &binding.providerInstanceID, &matches)
	if errors.Is(err, pgx.ErrNoRows) {
		return workerIdentityProviderBinding{}, worker.ErrIdentityUnavailable
	}
	if err != nil {
		return workerIdentityProviderBinding{}, fmt.Errorf("load Worker identity provider binding: %w", err)
	}
	if matches != 1 || !validWorkerProviderInstanceID(binding.providerInstanceID) || binding.ownerID != current.OwnerID {
		return workerIdentityProviderBinding{}, worker.ErrIdentityUnavailable
	}
	return binding, nil
}

func boundedIdentityChallengeExpiry(challengeExpiry, enrollmentExpiry time.Time) time.Time {
	challengeExpiry, enrollmentExpiry = challengeExpiry.UTC(), enrollmentExpiry.UTC()
	if enrollmentExpiry.Before(challengeExpiry) {
		return enrollmentExpiry
	}
	return challengeExpiry
}

func (store *WorkerStore) GetIdentityChallenge(ctx context.Context, challengeID, deploymentID, workerID string) (worker.IdentityChallenge, error) {
	challenge, challengeErr := uuid.Parse(strings.TrimSpace(challengeID))
	deployment, deploymentErr := uuid.Parse(strings.TrimSpace(deploymentID))
	caller, workerErr := uuid.Parse(strings.TrimSpace(workerID))
	if challengeErr != nil || challenge == uuid.Nil || deploymentErr != nil || deployment == uuid.Nil || workerErr != nil || caller == uuid.Nil {
		return worker.IdentityChallenge{}, worker.ErrInvalid
	}
	stored, err := scanWorkerIdentityChallenge(store.pool.QueryRow(ctx, workerIdentityChallengeSelect+`
		WHERE challenge_id=$1 AND deployment_id=$2 AND worker_id=$3 AND agent_instance_id=$4`,
		challenge, deployment, caller, store.instanceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return worker.IdentityChallenge{}, worker.ErrNotFound
	}
	if err != nil {
		return worker.IdentityChallenge{}, fmt.Errorf("get Worker identity challenge: %w", err)
	}
	return stored, nil
}

func (store *WorkerStore) EnrollVerifiedIdentityIdempotent(ctx context.Context, record worker.IdentityEnrollmentRecord, replaySession []byte) (worker.Deployment, []byte, error) {
	challengeID, deploymentID, workerID, key, err := validateIdentityEnrollmentRecord(record, replaySession)
	if err != nil {
		return worker.Deployment{}, nil, fmt.Errorf("validate Worker identity enrollment record: %w", err)
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return worker.Deployment{}, nil, fmt.Errorf("begin Worker identity enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	challenge, err := scanWorkerIdentityChallenge(tx.QueryRow(ctx, workerIdentityChallengeSelect+`
		WHERE challenge_id=$1 AND deployment_id=$2 AND worker_id=$3 AND agent_instance_id=$4 FOR UPDATE`,
		challengeID, deploymentID, workerID, store.instanceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return worker.Deployment{}, nil, worker.ErrNotFound
	}
	if err != nil {
		return worker.Deployment{}, nil, fmt.Errorf("lock Worker identity challenge: %w", err)
	}

	var storedChallenge uuid.UUID
	var storedHash, nonce, ciphertext, responseJSON []byte
	var storedInstanceID, storedPrincipalID string
	var responseSchema int
	err = tx.QueryRow(ctx, `
		SELECT challenge_id, request_hash, provider_instance_id, principal_id, nonce, session_ciphertext,
		       response_schema_version, response_json
		FROM worker_identity_enrollment_replays
		WHERE deployment_id=$1 AND caller_worker_id=$2 AND idempotency_key=$3`,
		deploymentID, workerID, key,
	).Scan(&storedChallenge, &storedHash, &storedInstanceID, &storedPrincipalID, &nonce, &ciphertext, &responseSchema, &responseJSON)
	if err == nil {
		if storedChallenge != challengeID || storedInstanceID != record.Identity.InstanceID || storedPrincipalID != record.Identity.PrincipalID ||
			subtle.ConstantTimeCompare(storedHash, record.RequestHash[:]) != 1 {
			return worker.Deployment{}, nil, worker.ErrIdempotencyConflict
		}
		deployment, decodeErr := decodeWorkerSnapshot(responseSchema, responseJSON)
		if decodeErr != nil {
			return worker.Deployment{}, nil, decodeErr
		}
		session, openErr := store.openIdentitySession(deploymentID, workerID, key, challengeID, record.RequestHash, nonce, ciphertext)
		if openErr != nil {
			return worker.Deployment{}, nil, openErr
		}
		if err := tx.Commit(ctx); err != nil {
			wipeBytes(session)
			return worker.Deployment{}, nil, fmt.Errorf("commit Worker identity enrollment replay: %w", err)
		}
		return deployment, session, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return worker.Deployment{}, nil, fmt.Errorf("load Worker identity enrollment replay: %w", err)
	}
	if !challenge.ConsumedAt.IsZero() {
		return worker.Deployment{}, nil, worker.ErrIdentityChallengeConsumed
	}
	if !record.CompletedAt.Before(challenge.ExpiresAt) {
		return worker.Deployment{}, nil, worker.ErrIdentityChallengeExpired
	}
	if challenge.ExpectedRevision != record.ExpectedRevision || challenge.OwnerID != record.Identity.OwnerID ||
		challenge.AccountID != record.Identity.AccountID || challenge.Region != record.Identity.Region ||
		challenge.ExpectedProviderInstanceID != record.Identity.InstanceID || challenge.DeploymentID != record.Identity.DeploymentID {
		return worker.Deployment{}, nil, worker.ErrIdentityRejected
	}
	if err := record.Materialization.Validate(record.Identity.PrincipalID, record.DeploymentID); err != nil {
		return worker.Deployment{}, nil, worker.ErrIdentityRejected
	}

	current, err := loadWorkerForUpdate(ctx, tx, deploymentID, store.instanceID)
	if err != nil {
		return worker.Deployment{}, nil, err
	}
	if !record.CompletedAt.Before(current.Enrollment.ExpiresAt) {
		return worker.Deployment{}, nil, worker.ErrEnrollmentExpired
	}
	if current.Revision != record.ExpectedRevision {
		return worker.Deployment{}, nil, worker.ErrRevisionConflict
	}
	if current.OwnerID != challenge.OwnerID || current.State != worker.StatePendingEnrollment || current.WorkerID != "" || current.ProviderInstanceID != "" ||
		!current.Enrollment.ConsumedAt.IsZero() {
		return worker.Deployment{}, nil, worker.ErrIdentityRejected
	}
	next := cloneWorkerDeployment(current)
	next.WorkerID = workerID.String()
	next.ProviderInstanceID = record.Identity.InstanceID
	next.RecipeBundle = record.Materialization.RecipeBundle
	next.ExecutionBundle = record.Materialization.ExecutionBundle
	next.Access = record.Materialization.Access
	next.State = worker.StateReady
	next.SessionDigest = record.SessionDigest
	next.Enrollment.ConsumedAt = record.CompletedAt.UTC()
	next.Revision = current.Revision + 1
	next.UpdatedAt = record.CompletedAt.UTC()
	if err := validateWorkerIdentityTransition(current, next, record); err != nil {
		return worker.Deployment{}, nil, err
	}
	if err := saveWorkerDeployment(ctx, tx, store.instanceID, current.Revision, next); err != nil {
		return worker.Deployment{}, nil, err
	}
	result, err := tx.Exec(ctx, `
		UPDATE worker_identity_challenges
		SET consumed_at=$2, revision=revision+1
		WHERE challenge_id=$1 AND revision=$3 AND consumed_at IS NULL`,
		challengeID, record.CompletedAt.UTC(), challenge.Revision,
	)
	if err != nil || result.RowsAffected() != 1 {
		return worker.Deployment{}, nil, worker.ErrIdentityChallengeConsumed
	}
	responseJSON, err = encodeWorkerSnapshot(next)
	if err != nil {
		return worker.Deployment{}, nil, err
	}
	nonce, ciphertext, err = store.sealIdentitySession(deploymentID, workerID, key, challengeID, record.RequestHash, replaySession)
	if err != nil {
		return worker.Deployment{}, nil, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO worker_identity_enrollment_replays (
			deployment_id, caller_worker_id, idempotency_key, challenge_id, expected_revision, request_hash,
			provider_instance_id, principal_id, nonce, session_ciphertext,
			response_revision, response_schema_version, response_json, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		deploymentID, workerID, key, challengeID, record.ExpectedRevision, record.RequestHash[:],
		record.Identity.InstanceID, record.Identity.PrincipalID, nonce, ciphertext,
		next.Revision, workerSnapshotSchemaV1, responseJSON, record.CompletedAt.UTC(),
	)
	if err != nil {
		return worker.Deployment{}, nil, fmt.Errorf("persist Worker identity enrollment replay: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return worker.Deployment{}, nil, fmt.Errorf("commit Worker identity enrollment: %w", err)
	}
	return next, bytes.Clone(replaySession), nil
}

const workerIdentityChallengeSelect = `
	SELECT challenge_id, deployment_id, worker_id, owner_id, account_id, region,
	       expected_provider_instance_id, expected_revision, expires_at, consumed_at,
	       revision, created_at, request_hash
	FROM worker_identity_challenges`

type identityChallengeRow interface{ Scan(...any) error }

func scanWorkerIdentityChallenge(row identityChallengeRow) (worker.IdentityChallenge, error) {
	var challenge worker.IdentityChallenge
	var challengeID, deploymentID, workerID uuid.UUID
	var consumedAt *time.Time
	var requestHash []byte
	if err := row.Scan(
		&challengeID, &deploymentID, &workerID, &challenge.OwnerID, &challenge.AccountID, &challenge.Region,
		&challenge.ExpectedProviderInstanceID, &challenge.ExpectedRevision, &challenge.ExpiresAt, &consumedAt,
		&challenge.Revision, &challenge.CreatedAt, &requestHash,
	); err != nil {
		return worker.IdentityChallenge{}, err
	}
	if len(requestHash) != sha256.Size {
		return worker.IdentityChallenge{}, worker.ErrInvalid
	}
	copy(challenge.RequestHash[:], requestHash)
	challenge.ChallengeID, challenge.DeploymentID, challenge.WorkerID = challengeID.String(), deploymentID.String(), workerID.String()
	challenge.ExpiresAt, challenge.CreatedAt = challenge.ExpiresAt.UTC(), challenge.CreatedAt.UTC()
	if consumedAt != nil {
		challenge.ConsumedAt = consumedAt.UTC()
	}
	return challenge, nil
}

func validateIdentityChallengeIntent(intent worker.IdentityChallengeIntent) (uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, error) {
	challenge, challengeErr := uuid.Parse(strings.TrimSpace(intent.ChallengeID))
	deployment, deploymentErr := uuid.Parse(strings.TrimSpace(intent.DeploymentID))
	caller, workerErr := uuid.Parse(strings.TrimSpace(intent.WorkerID))
	key, keyErr := uuid.Parse(strings.TrimSpace(intent.IdempotencyKey))
	var empty [sha256.Size]byte
	if challengeErr != nil || challenge == uuid.Nil || deploymentErr != nil || deployment == uuid.Nil || workerErr != nil || caller == uuid.Nil ||
		keyErr != nil || key == uuid.Nil || intent.ExpectedRevision < 1 || intent.CreatedAt.IsZero() || !intent.ExpiresAt.After(intent.CreatedAt) ||
		subtle.ConstantTimeCompare(intent.RequestHash[:], empty[:]) == 1 {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, worker.ErrInvalid
	}
	return challenge, deployment, caller, key, nil
}

func validateIdentityEnrollmentRecord(record worker.IdentityEnrollmentRecord, session []byte) (uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, error) {
	challenge, challengeErr := uuid.Parse(strings.TrimSpace(record.ChallengeID))
	deployment, deploymentErr := uuid.Parse(strings.TrimSpace(record.DeploymentID))
	caller, workerErr := uuid.Parse(strings.TrimSpace(record.WorkerID))
	key, keyErr := uuid.Parse(strings.TrimSpace(record.IdempotencyKey))
	if challengeErr != nil || challenge == uuid.Nil || deploymentErr != nil || deployment == uuid.Nil || workerErr != nil || caller == uuid.Nil || keyErr != nil || key == uuid.Nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("identity enrollment identifiers: %w", worker.ErrInvalid)
	}
	if record.ExpectedRevision < 1 || record.CompletedAt.IsZero() {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("identity enrollment revision or time: %w", worker.ErrInvalid)
	}
	if len(session) < 32 || len(session) > 128 {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("identity enrollment session shape: %w", worker.ErrInvalid)
	}
	var empty [sha256.Size]byte
	if subtle.ConstantTimeCompare(record.RequestHash[:], empty[:]) == 1 || subtle.ConstantTimeCompare(record.SessionDigest[:], empty[:]) == 1 {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("identity enrollment digest presence: %w", worker.ErrInvalid)
	}
	return challenge, deployment, caller, key, nil
}

func validateWorkerIdentityTransition(current, next worker.Deployment, record worker.IdentityEnrollmentRecord) error {
	if current.DeploymentID != next.DeploymentID || current.OwnerID != next.OwnerID || current.TaskID != next.TaskID || current.StepID != next.StepID ||
		current.ControlPlaneEndpoint != next.ControlPlaneEndpoint || current.ExecutionTimeout != next.ExecutionTimeout ||
		current.Enrollment.CredentialDigest != next.Enrollment.CredentialDigest || !current.Enrollment.ExpiresAt.Equal(next.Enrollment.ExpiresAt) ||
		current.Outcome != next.Outcome || current.Lease != next.Lease || current.ResultRef != next.ResultRef ||
		!slices.Equal(current.Evidence, next.Evidence) || current.CancelReason != next.CancelReason || !current.CreatedAt.Equal(next.CreatedAt) ||
		next.Revision != current.Revision+1 || next.WorkerID != record.WorkerID || next.ProviderInstanceID != record.Identity.InstanceID ||
		next.RecipeBundle != record.Materialization.RecipeBundle || next.ExecutionBundle != record.Materialization.ExecutionBundle ||
		next.Access.ArtifactPrefix != record.Materialization.Access.ArtifactPrefix || next.Access.CheckpointPrefix != record.Materialization.Access.CheckpointPrefix ||
		next.Access.EvidencePrefix != record.Materialization.Access.EvidencePrefix || next.Access.LogPrefix != record.Materialization.Access.LogPrefix ||
		!slices.Equal(next.Access.SecretRefs, record.Materialization.Access.SecretRefs) {
		return worker.ErrRevisionConflict
	}
	return validateWorkerDeployment(next)
}

func (store *WorkerStore) sealIdentitySession(deploymentID, workerID, key, challengeID uuid.UUID, requestHash [sha256.Size]byte, plaintext []byte) ([]byte, []byte, error) {
	aead, err := store.replayAEAD()
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(store.random, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate Worker identity replay nonce: %w", err)
	}
	return nonce, aead.Seal(nil, nonce, plaintext, workerIdentityReplayAAD(deploymentID, workerID, key, challengeID, requestHash)), nil
}

func (store *WorkerStore) openIdentitySession(deploymentID, workerID, key, challengeID uuid.UUID, requestHash [sha256.Size]byte, nonce, ciphertext []byte) ([]byte, error) {
	aead, err := store.replayAEAD()
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil, worker.ErrInvalidCredential
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, workerIdentityReplayAAD(deploymentID, workerID, key, challengeID, requestHash))
	if err != nil || len(plaintext) < 32 || len(plaintext) > 128 {
		wipeBytes(plaintext)
		return nil, worker.ErrInvalidCredential
	}
	return plaintext, nil
}

func workerIdentityReplayAAD(deploymentID, workerID, key, challengeID uuid.UUID, requestHash [sha256.Size]byte) []byte {
	aad := make([]byte, 0, len(workerIdentityReplayAADDomain)+16*4+sha256.Size+5)
	aad = append(aad, workerIdentityReplayAADDomain...)
	for _, value := range [][16]byte{deploymentID, workerID, key, challengeID} {
		aad = append(aad, 0)
		aad = append(aad, value[:]...)
	}
	aad = append(aad, 0)
	return append(aad, requestHash[:]...)
}
