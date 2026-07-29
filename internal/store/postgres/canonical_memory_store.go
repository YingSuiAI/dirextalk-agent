package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/canonicalmemory"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	canonicalSnapshotSchemaV1 = 1

	recordWorkerEvidenceOperation  = "canonical.evidence.worker.record"
	recordTurnEvidenceOperation    = "canonical.evidence.turn.record"
	proposeMemoryOperation         = "canonical.memory.propose"
	createMemoryChallengeOperation = "canonical.memory.challenge.create"
	approveMemoryOperation         = "canonical.memory.approve"
	rejectMemoryCandidateOperation = "canonical.memory.reject"
	revokeMemoryOperation          = "canonical.memory.revoke"
)

type canonicalEvidenceSnapshot struct {
	SchemaVersion int                      `json:"schema_version"`
	Evidence      canonicalmemory.Evidence `json:"evidence"`
}

type canonicalCandidateSnapshot struct {
	SchemaVersion int                       `json:"schema_version"`
	Candidate     canonicalmemory.Candidate `json:"candidate"`
}

type canonicalChallengeSnapshot struct {
	SchemaVersion int                           `json:"schema_version"`
	Challenge     canonicalmemory.ChallengeFact `json:"challenge"`
}

type canonicalFactSnapshot struct {
	SchemaVersion int                  `json:"schema_version"`
	Fact          canonicalmemory.Fact `json:"fact"`
}

var _ canonicalmemory.Store = (*Store)(nil)

func (store *Store) RecordWorkerEvidence(
	ctx context.Context,
	scope task.MutationScope,
	command canonicalmemory.RecordWorkerEvidenceCommand,
) (canonicalmemory.Evidence, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return canonicalmemory.Evidence{}, canonicalStoreError(err)
	}
	if err := command.Validate(); err != nil {
		return canonicalmemory.Evidence{}, err
	}
	requestDigest, err := command.Digest()
	if err != nil {
		return canonicalmemory.Evidence{}, err
	}
	evidenceID, _ := uuid.Parse(command.EvidenceID)
	deploymentID, _ := uuid.Parse(command.DeploymentID)
	tx, err := store.pool.BeginTx(ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return canonicalmemory.Evidence{},
			fmt.Errorf("begin Worker evidence recording: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	replay, _, response, err := claimScopedIdempotency(
		ctx, tx, caller, recordWorkerEvidenceOperation,
		command.IdempotencyKey, requestDigest[:], evidenceID)
	if err != nil {
		return canonicalmemory.Evidence{}, canonicalStoreError(err)
	}
	if replay {
		evidence, err := decodeCanonicalEvidenceSnapshot(response)
		if err != nil {
			return canonicalmemory.Evidence{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return canonicalmemory.Evidence{},
				fmt.Errorf("commit Worker evidence replay: %w", err)
		}
		return evidence, nil
	}
	deployment, err := loadWorkerForUpdate(
		ctx, tx, deploymentID, store.instanceID)
	if err != nil {
		return canonicalmemory.Evidence{}, canonicalStoreError(err)
	}
	if deployment.OwnerID != command.OwnerID {
		return canonicalmemory.Evidence{}, canonicalmemory.ErrNotFound
	}
	var matched *canonicalmemory.Evidence
	for _, item := range deployment.Evidence {
		if item.Ref != command.Artifact.Ref ||
			item.ObjectSHA256 != command.Artifact.Digest ||
			item.Attempt != command.Attempt ||
			item.LeaseEpoch != command.LeaseEpoch {
			continue
		}
		candidate := canonicalmemory.Evidence{
			EvidenceID: evidenceID.String(),
			OwnerID:    command.OwnerID, Namespace: command.Namespace,
			Kind:         canonicalmemory.EvidenceWorkerClaim,
			Trust:        canonicalmemory.TrustUntrusted,
			Artifact:     command.Artifact,
			TaskID:       deployment.TaskID,
			DeploymentID: deployment.DeploymentID,
			Attempt:      item.Attempt, LeaseEpoch: item.LeaseEpoch,
			ObservedAt: item.RecordedAt.UTC().Truncate(time.Microsecond),
		}
		matched = &candidate
		break
	}
	if matched == nil || matched.ObservedAt.IsZero() {
		return canonicalmemory.Evidence{}, canonicalmemory.ErrEvidence
	}
	evidence, err := insertCanonicalEvidence(ctx, tx, store.instanceID,
		caller, *matched)
	if err != nil {
		return canonicalmemory.Evidence{}, err
	}
	if err := setScopedIdempotencyResponse(
		ctx, tx, caller, recordWorkerEvidenceOperation,
		command.IdempotencyKey,
		canonicalEvidenceSnapshot{
			SchemaVersion: canonicalSnapshotSchemaV1,
			Evidence:      evidence,
		},
	); err != nil {
		return canonicalmemory.Evidence{}, canonicalStoreError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return canonicalmemory.Evidence{},
			fmt.Errorf("commit Worker evidence: %w", err)
	}
	return evidence, nil
}

func (store *Store) RecordTurnEvidence(
	ctx context.Context,
	scope task.MutationScope,
	command canonicalmemory.RecordTurnEvidenceCommand,
) (canonicalmemory.Evidence, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return canonicalmemory.Evidence{}, canonicalStoreError(err)
	}
	if err := command.Validate(); err != nil {
		return canonicalmemory.Evidence{}, err
	}
	requestDigest, err := command.Digest()
	if err != nil {
		return canonicalmemory.Evidence{}, err
	}
	evidenceID, _ := uuid.Parse(command.EvidenceID)
	turnID, _ := uuid.Parse(command.TurnID)
	tx, err := store.pool.BeginTx(ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return canonicalmemory.Evidence{},
			fmt.Errorf("begin Turn evidence recording: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	replay, _, response, err := claimScopedIdempotency(
		ctx, tx, caller, recordTurnEvidenceOperation,
		command.IdempotencyKey, requestDigest[:], evidenceID)
	if err != nil {
		return canonicalmemory.Evidence{}, canonicalStoreError(err)
	}
	if replay {
		evidence, err := decodeCanonicalEvidenceSnapshot(response)
		if err != nil {
			return canonicalmemory.Evidence{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return canonicalmemory.Evidence{},
				fmt.Errorf("commit Turn evidence replay: %w", err)
		}
		return evidence, nil
	}
	var (
		taskID       *uuid.UUID
		observedAt   time.Time
		trust        canonicalmemory.EvidenceTrust
		artifactKind string
		origin       string
		authority    string
		validation   string
	)
	if command.Kind == canonicalmemory.EvidenceTaskResult {
		trust = canonicalmemory.TrustCorroborating
		artifactKind, origin, authority, validation =
			"result", "task", "task", "unspecified"
	} else {
		trust = canonicalmemory.TrustVerified
		artifactKind, origin, authority, validation =
			"validation", "validator", "validator", "passed"
	}
	err = tx.QueryRow(ctx, `
		SELECT turn_state.task_id, event.occurred_at
		FROM agent_turns turn_state
		JOIN agent_turn_events event
		  ON event.turn_id=turn_state.turn_id
		WHERE turn_state.turn_id=$1
		  AND turn_state.agent_instance_id=$2
		  AND turn_state.owner_id=$3
		  AND event.revision=$4
		  AND event.artifact_kind=$5
		  AND event.artifact_origin=$6
		  AND event.authority=$7
		  AND event.validation_outcome=$8
		  AND event.artifact_ref=$9
		  AND event.artifact_digest=$10
		FOR SHARE OF turn_state`,
		turnID, store.instanceID, command.OwnerID,
		command.TurnRevision, artifactKind, origin, authority,
		validation, command.Artifact.Ref, command.Artifact.Digest,
	).Scan(&taskID, &observedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return canonicalmemory.Evidence{}, canonicalmemory.ErrEvidence
	}
	if err != nil {
		return canonicalmemory.Evidence{},
			fmt.Errorf("read Turn evidence source: %w", err)
	}
	if command.Kind == canonicalmemory.EvidenceTaskResult &&
		taskID == nil {
		return canonicalmemory.Evidence{}, canonicalmemory.ErrEvidence
	}
	evidence := canonicalmemory.Evidence{
		EvidenceID: evidenceID.String(),
		OwnerID:    command.OwnerID, Namespace: command.Namespace,
		Kind: command.Kind, Trust: trust, Artifact: command.Artifact,
		TurnID: command.TurnID, TurnRevision: command.TurnRevision,
		ObservedAt: observedAt.UTC().Truncate(time.Microsecond),
	}
	if taskID != nil {
		evidence.TaskID = taskID.String()
	}
	evidence, err = insertCanonicalEvidence(
		ctx, tx, store.instanceID, caller, evidence)
	if err != nil {
		return canonicalmemory.Evidence{}, err
	}
	if err := setScopedIdempotencyResponse(
		ctx, tx, caller, recordTurnEvidenceOperation,
		command.IdempotencyKey,
		canonicalEvidenceSnapshot{
			SchemaVersion: canonicalSnapshotSchemaV1,
			Evidence:      evidence,
		},
	); err != nil {
		return canonicalmemory.Evidence{}, canonicalStoreError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return canonicalmemory.Evidence{},
			fmt.Errorf("commit Turn evidence: %w", err)
	}
	return evidence, nil
}

func (store *Store) ProposeCandidate(
	ctx context.Context,
	scope task.MutationScope,
	command canonicalmemory.ProposeCommand,
) (canonicalmemory.Candidate, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return canonicalmemory.Candidate{}, canonicalStoreError(err)
	}
	command, err = command.Validated()
	if err != nil {
		return canonicalmemory.Candidate{}, err
	}
	requestDigest, err := command.Digest()
	if err != nil {
		return canonicalmemory.Candidate{}, err
	}
	candidateID, _ := uuid.Parse(command.CandidateID)
	tx, err := store.pool.BeginTx(ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return canonicalmemory.Candidate{},
			fmt.Errorf("begin Canonical Memory proposal: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	replay, _, response, err := claimScopedIdempotency(
		ctx, tx, caller, proposeMemoryOperation,
		command.IdempotencyKey, requestDigest[:], candidateID)
	if err != nil {
		return canonicalmemory.Candidate{}, canonicalStoreError(err)
	}
	if replay {
		candidate, err := decodeCanonicalCandidateSnapshot(response)
		if err != nil {
			return canonicalmemory.Candidate{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return canonicalmemory.Candidate{},
				fmt.Errorf("commit Canonical Memory proposal replay: %w",
					err)
		}
		return candidate, nil
	}
	var databaseNow time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).
		Scan(&databaseNow); err != nil {
		return canonicalmemory.Candidate{},
			fmt.Errorf("read Canonical Memory proposal time: %w", err)
	}
	databaseNow = databaseNow.UTC().Truncate(time.Microsecond)
	if !databaseNow.Before(command.ExpiresAt) ||
		command.ExpiresAt.After(
			databaseNow.Add(canonicalmemory.CandidateLifetime+
				time.Minute)) {
		return canonicalmemory.Candidate{}, canonicalmemory.ErrInvalid
	}
	evidence, err := readCanonicalEvidenceSet(
		ctx, tx, store.instanceID, command.OwnerID,
		command.Namespace, command.EvidenceIDs, true)
	if err != nil {
		return canonicalmemory.Candidate{}, err
	}
	evidenceDigest, err := canonicalmemory.EvidenceSetDigest(evidence)
	if err != nil {
		return canonicalmemory.Candidate{}, err
	}
	candidateDigest, err := canonicalmemory.CandidateDigest(
		command.OwnerID, command.Namespace, command.MemoryKey,
		command.Kind, command.Title, command.Statement,
		command.Origin, command.Source)
	if err != nil {
		return canonicalmemory.Candidate{}, err
	}
	candidate, err := scanCanonicalCandidate(tx.QueryRow(ctx, `
		INSERT INTO canonical_memory_candidates (
		    candidate_id, agent_instance_id, caller_client_id,
		    caller_credential_id, owner_id, namespace, memory_key,
		    memory_kind, title, statement, candidate_digest, origin,
		    source_ref, source_digest, evidence_digest, status,
		    revision, expires_at)
		VALUES (
		    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
		    'pending',1,$16)
		RETURNING `+canonicalCandidateColumns,
		candidateID, store.instanceID, caller.ClientID,
		caller.CredentialID, command.OwnerID, command.Namespace,
		command.MemoryKey, command.Kind, command.Title,
		command.Statement, candidateDigest, command.Origin,
		command.Source.Ref, command.Source.Digest, evidenceDigest,
		command.ExpiresAt.UTC(),
	))
	if err != nil {
		return canonicalmemory.Candidate{},
			canonicalStoreError(fmt.Errorf(
				"insert Canonical Memory candidate: %w", err))
	}
	for _, item := range evidence {
		if _, err := tx.Exec(ctx, `
			INSERT INTO canonical_memory_candidate_evidence
			    (candidate_id, evidence_id)
			VALUES ($1,$2)`,
			candidateID, item.EvidenceID,
		); err != nil {
			return canonicalmemory.Candidate{},
				canonicalStoreError(fmt.Errorf(
					"link Canonical Memory evidence: %w", err))
		}
	}
	candidate.Evidence = evidence
	if candidate.Validate() != nil {
		return canonicalmemory.Candidate{}, canonicalmemory.ErrFactMismatch
	}
	if err := setScopedIdempotencyResponse(
		ctx, tx, caller, proposeMemoryOperation,
		command.IdempotencyKey,
		canonicalCandidateSnapshot{
			SchemaVersion: canonicalSnapshotSchemaV1,
			Candidate:     candidate,
		},
	); err != nil {
		return canonicalmemory.Candidate{}, canonicalStoreError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return canonicalmemory.Candidate{},
			fmt.Errorf("commit Canonical Memory proposal: %w", err)
	}
	return candidate, nil
}

func (store *Store) GetCandidate(
	ctx context.Context,
	ownerID,
	candidateID string,
) (canonicalmemory.Candidate, error) {
	parsed, err := uuid.Parse(candidateID)
	if err != nil || parsed == uuid.Nil || parsed.String() != candidateID ||
		ownerID != strings.TrimSpace(ownerID) || ownerID == "" ||
		len(ownerID) > 255 {
		return canonicalmemory.Candidate{}, canonicalmemory.ErrInvalid
	}
	candidate, err := readCanonicalCandidate(
		ctx, store.pool, store.instanceID, ownerID, parsed, false)
	if errors.Is(err, pgx.ErrNoRows) {
		return canonicalmemory.Candidate{}, canonicalmemory.ErrNotFound
	}
	if err != nil {
		return canonicalmemory.Candidate{}, err
	}
	return candidate, nil
}

func insertCanonicalEvidence(
	ctx context.Context,
	tx pgx.Tx,
	instanceID uuid.UUID,
	caller idempotencyCaller,
	evidence canonicalmemory.Evidence,
) (canonicalmemory.Evidence, error) {
	var (
		turnID, taskID, deploymentID any
		turnRevision                 any
		attempt, leaseEpoch          any
		validUntil                   any
	)
	if evidence.TurnID != "" {
		turnID = evidence.TurnID
		turnRevision = evidence.TurnRevision
	}
	if evidence.TaskID != "" {
		taskID = evidence.TaskID
	}
	if evidence.DeploymentID != "" {
		deploymentID = evidence.DeploymentID
		attempt = evidence.Attempt
		leaseEpoch = evidence.LeaseEpoch
	}
	if !evidence.ValidUntil.IsZero() {
		validUntil = evidence.ValidUntil.UTC()
	}
	inserted, err := scanCanonicalEvidence(tx.QueryRow(ctx, `
		INSERT INTO agent_evidence_ledger (
		    evidence_id, agent_instance_id, caller_client_id,
		    caller_credential_id, owner_id, namespace, evidence_kind,
		    trust_level, artifact_ref, artifact_digest, source_turn_id,
		    source_turn_revision, source_task_id, source_deployment_id,
		    source_attempt, source_lease_epoch, observed_at, valid_until)
		VALUES (
		    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
		    $16,$17,$18)
		RETURNING `+canonicalEvidenceColumns,
		evidence.EvidenceID, instanceID, caller.ClientID,
		caller.CredentialID, evidence.OwnerID, evidence.Namespace,
		evidence.Kind, evidence.Trust, evidence.Artifact.Ref,
		evidence.Artifact.Digest, turnID, turnRevision, taskID,
		deploymentID, attempt, leaseEpoch, evidence.ObservedAt.UTC(),
		validUntil,
	))
	if err != nil {
		return canonicalmemory.Evidence{},
			canonicalStoreError(fmt.Errorf(
				"insert Canonical Memory evidence: %w", err))
	}
	if inserted.Validate() != nil {
		return canonicalmemory.Evidence{}, canonicalmemory.ErrFactMismatch
	}
	return inserted, nil
}

const canonicalEvidenceColumns = `
	evidence_id, owner_id, namespace, evidence_kind, trust_level,
	artifact_ref, artifact_digest, source_turn_id, source_turn_revision,
	source_task_id, source_deployment_id, source_attempt,
	source_lease_epoch, observed_at, valid_until, created_at`

const canonicalJoinedEvidenceColumns = `
	evidence.evidence_id, evidence.owner_id, evidence.namespace,
	evidence.evidence_kind, evidence.trust_level, evidence.artifact_ref,
	evidence.artifact_digest, evidence.source_turn_id,
	evidence.source_turn_revision, evidence.source_task_id,
	evidence.source_deployment_id, evidence.source_attempt,
	evidence.source_lease_epoch, evidence.observed_at,
	evidence.valid_until, evidence.created_at`

type canonicalRow interface {
	Scan(...any) error
}

func scanCanonicalEvidence(row canonicalRow) (canonicalmemory.Evidence, error) {
	var (
		evidence                     canonicalmemory.Evidence
		evidenceID                   uuid.UUID
		turnID, taskID, deploymentID *uuid.UUID
		turnRevision, leaseEpoch     *int64
		attempt                      *int32
		validUntil                   *time.Time
	)
	if err := row.Scan(
		&evidenceID, &evidence.OwnerID, &evidence.Namespace,
		&evidence.Kind, &evidence.Trust, &evidence.Artifact.Ref,
		&evidence.Artifact.Digest, &turnID, &turnRevision, &taskID,
		&deploymentID, &attempt, &leaseEpoch, &evidence.ObservedAt,
		&validUntil, &evidence.CreatedAt,
	); err != nil {
		return canonicalmemory.Evidence{}, err
	}
	evidence.EvidenceID = evidenceID.String()
	if turnID != nil {
		evidence.TurnID = turnID.String()
		evidence.TurnRevision = *turnRevision
	}
	if taskID != nil {
		evidence.TaskID = taskID.String()
	}
	if deploymentID != nil {
		evidence.DeploymentID = deploymentID.String()
		evidence.Attempt = *attempt
		evidence.LeaseEpoch = *leaseEpoch
	}
	if validUntil != nil {
		evidence.ValidUntil = validUntil.UTC().Truncate(time.Microsecond)
	}
	evidence.ObservedAt = evidence.ObservedAt.UTC().
		Truncate(time.Microsecond)
	evidence.CreatedAt = evidence.CreatedAt.UTC().
		Truncate(time.Microsecond)
	return evidence, nil
}

func readCanonicalEvidenceSet(
	ctx context.Context,
	query canonicalQuery,
	instanceID uuid.UUID,
	ownerID,
	namespace string,
	evidenceIDs []string,
	lock bool,
) ([]canonicalmemory.Evidence, error) {
	if len(evidenceIDs) == 0 {
		return []canonicalmemory.Evidence{}, nil
	}
	parsed := make([]uuid.UUID, 0, len(evidenceIDs))
	for _, evidenceID := range evidenceIDs {
		value, err := uuid.Parse(evidenceID)
		if err != nil || value == uuid.Nil {
			return nil, canonicalmemory.ErrInvalid
		}
		parsed = append(parsed, value)
	}
	statement := `
		SELECT ` + canonicalEvidenceColumns + `
		FROM agent_evidence_ledger
		WHERE agent_instance_id=$1
		  AND owner_id=$2
		  AND namespace=$3
		  AND evidence_id=ANY($4::uuid[])
		ORDER BY evidence_id`
	if lock {
		statement += ` FOR SHARE`
	}
	rows, err := query.Query(ctx, statement, instanceID, ownerID,
		namespace, parsed)
	if err != nil {
		return nil, fmt.Errorf("read Canonical Memory evidence set: %w",
			err)
	}
	defer rows.Close()
	evidence := make([]canonicalmemory.Evidence, 0, len(parsed))
	for rows.Next() {
		item, err := scanCanonicalEvidence(rows)
		if err != nil {
			return nil, fmt.Errorf("scan Canonical Memory evidence: %w",
				err)
		}
		if item.Validate() != nil {
			return nil, canonicalmemory.ErrFactMismatch
		}
		evidence = append(evidence, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Canonical Memory evidence: %w",
			err)
	}
	if len(evidence) != len(parsed) {
		return nil, canonicalmemory.ErrEvidence
	}
	return evidence, nil
}

const canonicalCandidateColumns = `
	candidate_id, owner_id, namespace, memory_key, memory_kind, title,
	statement, candidate_digest, origin, source_ref, source_digest,
	evidence_digest, status, revision, expires_at, promoted_memory_id,
	promoted_memory_revision, rejection_reason, created_at, updated_at`

func scanCanonicalCandidate(row canonicalRow) (
	canonicalmemory.Candidate, error,
) {
	var (
		candidate              canonicalmemory.Candidate
		candidateID            uuid.UUID
		promotedMemoryID       *uuid.UUID
		promotedMemoryRevision *int64
	)
	if err := row.Scan(
		&candidateID, &candidate.OwnerID, &candidate.Namespace,
		&candidate.MemoryKey, &candidate.Kind, &candidate.Title,
		&candidate.Statement, &candidate.CandidateDigest,
		&candidate.Origin, &candidate.Source.Ref,
		&candidate.Source.Digest, &candidate.EvidenceDigest,
		&candidate.Status, &candidate.Revision, &candidate.ExpiresAt,
		&promotedMemoryID, &promotedMemoryRevision,
		&candidate.RejectionReason, &candidate.CreatedAt,
		&candidate.UpdatedAt,
	); err != nil {
		return canonicalmemory.Candidate{}, err
	}
	candidate.CandidateID = candidateID.String()
	if promotedMemoryID != nil {
		candidate.PromotedMemoryID = promotedMemoryID.String()
		candidate.PromotedMemoryRevision = *promotedMemoryRevision
	}
	candidate.ExpiresAt = candidate.ExpiresAt.UTC().
		Truncate(time.Microsecond)
	candidate.CreatedAt = candidate.CreatedAt.UTC().
		Truncate(time.Microsecond)
	candidate.UpdatedAt = candidate.UpdatedAt.UTC().
		Truncate(time.Microsecond)
	return candidate, nil
}

type canonicalQuery interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readCanonicalCandidate(
	ctx context.Context,
	query canonicalQuery,
	instanceID uuid.UUID,
	ownerID string,
	candidateID uuid.UUID,
	lock bool,
) (canonicalmemory.Candidate, error) {
	statement := `
		SELECT ` + canonicalCandidateColumns + `
		FROM canonical_memory_candidates
		WHERE candidate_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3`
	if lock {
		statement += ` FOR UPDATE`
	}
	candidate, err := scanCanonicalCandidate(
		query.QueryRow(ctx, statement, candidateID, instanceID, ownerID))
	if err != nil {
		return canonicalmemory.Candidate{}, err
	}
	rows, err := query.Query(ctx, `
		SELECT `+canonicalJoinedEvidenceColumns+`
		FROM canonical_memory_candidate_evidence link
		JOIN agent_evidence_ledger evidence
		  ON evidence.evidence_id=link.evidence_id
		WHERE link.candidate_id=$1
		ORDER BY evidence.evidence_id`,
		candidateID,
	)
	if err != nil {
		return canonicalmemory.Candidate{},
			fmt.Errorf("read candidate evidence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		item, err := scanCanonicalEvidence(rows)
		if err != nil {
			return canonicalmemory.Candidate{},
				fmt.Errorf("scan candidate evidence: %w", err)
		}
		candidate.Evidence = append(candidate.Evidence, item)
	}
	if err := rows.Err(); err != nil {
		return canonicalmemory.Candidate{},
			fmt.Errorf("iterate candidate evidence: %w", err)
	}
	if candidate.Validate() != nil {
		return canonicalmemory.Candidate{},
			canonicalmemory.ErrFactMismatch
	}
	return candidate, nil
}

func (store *Store) CreateCanonicalMemoryChallenge(
	ctx context.Context,
	scope task.MutationScope,
	command canonicalmemory.CreateChallengeCommand,
) (canonicalmemory.ChallengeFact, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return canonicalmemory.ChallengeFact{}, canonicalStoreError(err)
	}
	if err := command.Validate(); err != nil {
		return canonicalmemory.ChallengeFact{}, err
	}
	requestDigest, err := command.Digest()
	if err != nil {
		return canonicalmemory.ChallengeFact{}, err
	}
	challengeID, _ := uuid.Parse(command.ChallengeID)
	candidateID, _ := uuid.Parse(command.CandidateID)
	tx, err := store.pool.BeginTx(ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return canonicalmemory.ChallengeFact{},
			fmt.Errorf("begin Canonical Memory challenge: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	replay, _, response, err := claimScopedIdempotency(
		ctx, tx, caller, createMemoryChallengeOperation,
		command.IdempotencyKey, requestDigest[:], challengeID)
	if err != nil {
		return canonicalmemory.ChallengeFact{}, canonicalStoreError(err)
	}
	if replay {
		fact, err := decodeCanonicalChallengeSnapshot(response)
		if err != nil {
			return canonicalmemory.ChallengeFact{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return canonicalmemory.ChallengeFact{},
				fmt.Errorf("commit Canonical Memory challenge replay: %w",
					err)
		}
		return fact, nil
	}
	candidate, err := readCanonicalCandidate(
		ctx, tx, store.instanceID, command.OwnerID, candidateID, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return canonicalmemory.ChallengeFact{}, canonicalmemory.ErrNotFound
	}
	if err != nil {
		return canonicalmemory.ChallengeFact{}, err
	}
	var databaseNow time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).
		Scan(&databaseNow); err != nil {
		return canonicalmemory.ChallengeFact{},
			fmt.Errorf("read Canonical Memory challenge time: %w", err)
	}
	databaseNow = databaseNow.UTC().Truncate(time.Microsecond)
	if candidate.Revision != command.ExpectedCandidateRevision ||
		!candidate.PendingAt(databaseNow) ||
		canonicalmemory.ValidatePromotion(
			candidate, command.ValidUntil, databaseNow) != nil {
		return canonicalmemory.ChallengeFact{}, canonicalmemory.ErrEvidence
	}
	memoryID, err := canonicalmemory.DeriveMemoryID(
		store.instanceID.String(), candidate.OwnerID,
		candidate.Namespace, candidate.MemoryKey)
	if err != nil || memoryID != command.MemoryID {
		return canonicalmemory.ChallengeFact{},
			canonicalmemory.ErrFactMismatch
	}
	if err := lockCanonicalMemoryIdentity(ctx, tx, memoryID); err != nil {
		return canonicalmemory.ChallengeFact{}, err
	}
	current, err := readCanonicalMemoryProjection(
		ctx, tx, store.instanceID, command.OwnerID, memoryID, true)
	switch {
	case command.ExpectedMemoryRevision == 0 &&
		errors.Is(err, pgx.ErrNoRows):
	case command.ExpectedMemoryRevision == 0:
		if err != nil {
			return canonicalmemory.ChallengeFact{}, err
		}
		return canonicalmemory.ChallengeFact{},
			canonicalmemory.ErrRevisionConflict
	case command.ExpectedMemoryRevision > 0 && err == nil:
		if current.CurrentRevision != command.ExpectedMemoryRevision ||
			current.Namespace != candidate.Namespace ||
			current.MemoryKey != candidate.MemoryKey ||
			current.Kind != candidate.Kind {
			return canonicalmemory.ChallengeFact{},
				canonicalmemory.ErrRevisionConflict
		}
	default:
		if errors.Is(err, pgx.ErrNoRows) {
			return canonicalmemory.ChallengeFact{},
				canonicalmemory.ErrRevisionConflict
		}
		return canonicalmemory.ChallengeFact{}, err
	}
	device, err := readApprovalDevice(
		ctx, tx, command.SignerKeyID, true)
	if err != nil ||
		device.Device.AgentInstanceID != store.instanceID.String() ||
		device.Device.OwnerID != command.OwnerID ||
		device.Device.Status != cloudapproval.DeviceKeyActive ||
		device.Device.ValidateAt(databaseNow) != nil {
		return canonicalmemory.ChallengeFact{},
			canonicalmemory.ErrApprovalRequired
	}
	challenge, err := canonicalmemory.NewChallengeV1(
		candidate, store.instanceID.String(), command.ApprovalID,
		command.ChallengeID, command.MemoryID, command.SignerKeyID,
		command.ExpectedMemoryRevision, command.ValidUntil, databaseNow)
	if err != nil {
		return canonicalmemory.ChallengeFact{}, err
	}
	challengeJSON, err := json.Marshal(challenge)
	if err != nil {
		return canonicalmemory.ChallengeFact{}, canonicalmemory.ErrInvalid
	}
	signingPayload, err := challenge.SigningPayload()
	if err != nil {
		return canonicalmemory.ChallengeFact{}, err
	}
	var (
		validUntil any
		consumedAt *time.Time
		fact       canonicalmemory.ChallengeFact
	)
	if challenge.HasValidUntil {
		validUntil = challenge.ValidUntil
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO canonical_memory_approval_challenges (
		    challenge_id, approval_id, agent_instance_id, owner_id,
		    candidate_id, candidate_revision, candidate_digest,
		    evidence_digest, memory_id, expected_memory_revision,
		    namespace, memory_key, memory_kind, valid_until,
		    signer_key_id, challenge_json, signing_payload, issued_at,
		    expires_at, record_revision)
		VALUES (
		    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
		    $16,$17,$18,$19,1)
		RETURNING record_revision, consumed_at, created_at, updated_at`,
		challenge.ChallengeID, challenge.ApprovalID, store.instanceID,
		challenge.OwnerID, challenge.CandidateID,
		challenge.CandidateRevision, challenge.CandidateDigest,
		challenge.EvidenceDigest, challenge.MemoryID,
		challenge.ExpectedMemoryRevision, challenge.Namespace,
		challenge.MemoryKey, challenge.Kind, validUntil,
		challenge.SignerKeyID, challengeJSON, signingPayload,
		challenge.IssuedAt, challenge.ExpiresAt,
	).Scan(&fact.RecordRevision, &consumedAt, &fact.CreatedAt,
		&fact.UpdatedAt)
	if err != nil {
		return canonicalmemory.ChallengeFact{},
			canonicalStoreError(fmt.Errorf(
				"insert Canonical Memory challenge: %w", err))
	}
	fact.Challenge = challenge
	fact.CreatedAt = fact.CreatedAt.UTC().Truncate(time.Microsecond)
	fact.UpdatedAt = fact.UpdatedAt.UTC().Truncate(time.Microsecond)
	if consumedAt != nil {
		fact.ConsumedAt = consumedAt.UTC().Truncate(time.Microsecond)
	}
	if fact.Validate() != nil {
		return canonicalmemory.ChallengeFact{},
			canonicalmemory.ErrFactMismatch
	}
	if err := setScopedIdempotencyResponse(
		ctx, tx, caller, createMemoryChallengeOperation,
		command.IdempotencyKey,
		canonicalChallengeSnapshot{
			SchemaVersion: canonicalSnapshotSchemaV1,
			Challenge:     fact,
		},
	); err != nil {
		return canonicalmemory.ChallengeFact{}, canonicalStoreError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return canonicalmemory.ChallengeFact{},
			fmt.Errorf("commit Canonical Memory challenge: %w", err)
	}
	return fact, nil
}

func (store *Store) ApproveCandidate(
	ctx context.Context,
	scope task.MutationScope,
	command canonicalmemory.ApproveCommand,
) (canonicalmemory.Fact, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return canonicalmemory.Fact{}, canonicalStoreError(err)
	}
	if err := command.Validate(); err != nil {
		return canonicalmemory.Fact{}, err
	}
	requestDigest, err := command.Digest()
	if err != nil {
		return canonicalmemory.Fact{}, err
	}
	memoryID, _ := uuid.Parse(command.Signature.MemoryID)
	challengeID, _ := uuid.Parse(command.Signature.ChallengeID)
	candidateID, _ := uuid.Parse(command.Signature.CandidateID)
	tx, err := store.pool.BeginTx(ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return canonicalmemory.Fact{},
			fmt.Errorf("begin Canonical Memory approval: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	replay, _, response, err := claimScopedIdempotency(
		ctx, tx, caller, approveMemoryOperation,
		command.IdempotencyKey, requestDigest[:], memoryID)
	if err != nil {
		return canonicalmemory.Fact{}, canonicalStoreError(err)
	}
	if replay {
		fact, err := decodeCanonicalFactSnapshot(response)
		if err != nil {
			return canonicalmemory.Fact{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return canonicalmemory.Fact{},
				fmt.Errorf("commit Canonical Memory approval replay: %w",
					err)
		}
		return fact, nil
	}
	challengeFact, signingPayload, err := readCanonicalChallenge(
		ctx, tx, store.instanceID, command.OwnerID, challengeID, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return canonicalmemory.Fact{},
			canonicalmemory.ErrApprovalRequired
	}
	if err != nil {
		return canonicalmemory.Fact{}, err
	}
	challenge := challengeFact.Challenge
	if challengeFact.RecordRevision != 1 ||
		!challengeFact.ConsumedAt.IsZero() ||
		challenge.ApprovalID != command.Signature.ApprovalID ||
		challenge.CandidateID != command.Signature.CandidateID ||
		challenge.CandidateRevision !=
			command.ExpectedCandidateRevision ||
		challenge.MemoryID != command.Signature.MemoryID {
		return canonicalmemory.Fact{},
			canonicalmemory.ErrApprovalRequired
	}
	candidate, err := readCanonicalCandidate(
		ctx, tx, store.instanceID, command.OwnerID, candidateID, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return canonicalmemory.Fact{}, canonicalmemory.ErrNotFound
	}
	if err != nil {
		return canonicalmemory.Fact{}, err
	}
	var databaseNow time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).
		Scan(&databaseNow); err != nil {
		return canonicalmemory.Fact{},
			fmt.Errorf("read Canonical Memory approval time: %w", err)
	}
	databaseNow = databaseNow.UTC().Truncate(time.Microsecond)
	if candidate.Revision != command.ExpectedCandidateRevision ||
		candidate.Status != canonicalmemory.CandidatePending ||
		canonicalmemory.ValidatePromotion(
			candidate, challenge.ValidUntil, databaseNow) != nil {
		return canonicalmemory.Fact{}, canonicalmemory.ErrEvidence
	}
	if err := lockCanonicalMemoryIdentity(
		ctx, tx, command.Signature.MemoryID); err != nil {
		return canonicalmemory.Fact{}, err
	}
	current, err := readCanonicalMemoryProjection(
		ctx, tx, store.instanceID, command.OwnerID,
		command.Signature.MemoryID, true)
	switch {
	case challenge.ExpectedMemoryRevision == 0 &&
		errors.Is(err, pgx.ErrNoRows):
	case challenge.ExpectedMemoryRevision == 0:
		if err != nil {
			return canonicalmemory.Fact{}, err
		}
		return canonicalmemory.Fact{},
			canonicalmemory.ErrRevisionConflict
	case challenge.ExpectedMemoryRevision > 0 && err == nil:
		if current.CurrentRevision !=
			challenge.ExpectedMemoryRevision ||
			current.Namespace != challenge.Namespace ||
			current.MemoryKey != challenge.MemoryKey ||
			current.Kind != challenge.Kind {
			return canonicalmemory.Fact{},
				canonicalmemory.ErrRevisionConflict
		}
	default:
		if errors.Is(err, pgx.ErrNoRows) {
			return canonicalmemory.Fact{},
				canonicalmemory.ErrRevisionConflict
		}
		return canonicalmemory.Fact{}, err
	}
	device, err := readApprovalDevice(
		ctx, tx, challenge.SignerKeyID, true)
	if err != nil ||
		device.Device.AgentInstanceID != store.instanceID.String() ||
		device.Device.OwnerID != command.OwnerID ||
		device.Device.Status != cloudapproval.DeviceKeyActive ||
		device.Device.ValidateAt(databaseNow) != nil ||
		canonicalmemory.VerifyApproval(
			challenge, command.Signature, candidate,
			device.Device.PublicKey, databaseNow) != nil {
		return canonicalmemory.Fact{},
			canonicalmemory.ErrApprovalRequired
	}
	signatureBytes, err := base64.RawURLEncoding.DecodeString(
		command.Signature.SignatureBase64URL)
	if err != nil || len(signatureBytes) != ed25519.SignatureSize {
		return canonicalmemory.Fact{}, canonicalmemory.ErrSignature
	}
	var consumedAt time.Time
	err = tx.QueryRow(ctx, `
		UPDATE canonical_memory_approval_challenges
		SET consumed_at=clock_timestamp(),
		    record_revision=record_revision+1,
		    updated_at=clock_timestamp()
		WHERE challenge_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3
		  AND record_revision=1
		  AND consumed_at IS NULL
		  AND expires_at>clock_timestamp()
		RETURNING consumed_at`,
		challengeID, store.instanceID, command.OwnerID,
	).Scan(&consumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return canonicalmemory.Fact{},
			canonicalmemory.ErrApprovalRequired
	}
	if err != nil {
		return canonicalmemory.Fact{},
			fmt.Errorf("consume Canonical Memory challenge: %w", err)
	}
	consumedAt = consumedAt.UTC().Truncate(time.Microsecond)
	expectedSigningPayload, err := challenge.SigningPayload()
	if err != nil ||
		!bytes.Equal(signingPayload, expectedSigningPayload) {
		return canonicalmemory.Fact{}, canonicalmemory.ErrFactMismatch
	}
	var approvalCreatedAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO canonical_memory_approvals (
		    approval_id, challenge_id, agent_instance_id, owner_id,
		    candidate_id, memory_id, signer_key_id, signature,
		    signing_payload, approved_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING created_at`,
		challenge.ApprovalID, challenge.ChallengeID, store.instanceID,
		challenge.OwnerID, challenge.CandidateID, challenge.MemoryID,
		challenge.SignerKeyID, signatureBytes, signingPayload,
		consumedAt,
	).Scan(&approvalCreatedAt)
	if err != nil {
		return canonicalmemory.Fact{},
			canonicalStoreError(fmt.Errorf(
				"insert Canonical Memory approval: %w", err))
	}
	nextRevision := challenge.ExpectedMemoryRevision + 1
	var memory canonicalmemory.Memory
	if challenge.ExpectedMemoryRevision == 0 {
		memory, err = scanCanonicalMemory(tx.QueryRow(ctx, `
			INSERT INTO canonical_memories (
			    memory_id, agent_instance_id, owner_id, namespace,
			    memory_key, memory_kind, status, current_revision,
			    record_revision)
			VALUES ($1,$2,$3,$4,$5,$6,'active',1,1)
			RETURNING `+canonicalMemoryColumns,
			challenge.MemoryID, store.instanceID, challenge.OwnerID,
			challenge.Namespace, challenge.MemoryKey, challenge.Kind,
		))
	} else {
		memory, err = scanCanonicalMemory(tx.QueryRow(ctx, `
			UPDATE canonical_memories
			SET status='active',
			    current_revision=current_revision+1,
			    record_revision=record_revision+1,
			    updated_at=clock_timestamp()
			WHERE memory_id=$1
			  AND agent_instance_id=$2
			  AND owner_id=$3
			  AND current_revision=$4
			RETURNING `+canonicalMemoryColumns,
			challenge.MemoryID, store.instanceID, challenge.OwnerID,
			challenge.ExpectedMemoryRevision,
		))
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return canonicalmemory.Fact{},
			canonicalmemory.ErrRevisionConflict
	}
	if err != nil {
		return canonicalmemory.Fact{},
			canonicalStoreError(fmt.Errorf(
				"advance Canonical Memory projection: %w", err))
	}
	var validUntil any
	if challenge.HasValidUntil {
		validUntil = challenge.ValidUntil
	}
	revision, err := scanCanonicalRevision(tx.QueryRow(ctx, `
		INSERT INTO canonical_memory_revisions (
		    memory_id, revision, candidate_id, owner_id, namespace,
		    memory_key, memory_kind, title, statement,
		    candidate_digest, evidence_digest, valid_from,
		    valid_until, approval_id)
		VALUES (
		    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		RETURNING `+canonicalRevisionColumns,
		challenge.MemoryID, nextRevision, candidate.CandidateID,
		candidate.OwnerID, candidate.Namespace, candidate.MemoryKey,
		candidate.Kind, candidate.Title, candidate.Statement,
		candidate.CandidateDigest, candidate.EvidenceDigest,
		consumedAt, validUntil, challenge.ApprovalID,
	))
	if err != nil {
		return canonicalmemory.Fact{},
			canonicalStoreError(fmt.Errorf(
				"insert Canonical Memory revision: %w", err))
	}
	var promotedCandidateID uuid.UUID
	err = tx.QueryRow(ctx, `
		UPDATE canonical_memory_candidates
		SET status='promoted',
		    promoted_memory_id=$4,
		    promoted_memory_revision=$5,
		    revision=revision+1,
		    updated_at=clock_timestamp()
		WHERE candidate_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3
		  AND status='pending'
		  AND revision=$6
		RETURNING candidate_id`,
		candidateID, store.instanceID, command.OwnerID,
		memoryID, nextRevision, command.ExpectedCandidateRevision,
	).Scan(&promotedCandidateID)
	if errors.Is(err, pgx.ErrNoRows) {
		return canonicalmemory.Fact{}, canonicalmemory.ErrState
	}
	if err != nil {
		return canonicalmemory.Fact{},
			fmt.Errorf("promote Canonical Memory candidate: %w", err)
	}
	if promotedCandidateID != candidateID {
		return canonicalmemory.Fact{},
			canonicalmemory.ErrFactMismatch
	}
	if err := appendCanonicalMemoryEvent(
		ctx, tx, store.instanceID, memory, revision,
		"promoted", "user_approval", challenge.ApprovalID, "",
		consumedAt,
	); err != nil {
		return canonicalmemory.Fact{}, err
	}
	fact := canonicalmemory.Fact{Memory: memory, Revision: revision}
	if fact.Validate() != nil ||
		revision.Revision != nextRevision ||
		approvalCreatedAt.IsZero() {
		return canonicalmemory.Fact{},
			canonicalmemory.ErrFactMismatch
	}
	if err := setScopedIdempotencyResponse(
		ctx, tx, caller, approveMemoryOperation,
		command.IdempotencyKey,
		canonicalFactSnapshot{
			SchemaVersion: canonicalSnapshotSchemaV1,
			Fact:          fact,
		},
	); err != nil {
		return canonicalmemory.Fact{}, canonicalStoreError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return canonicalmemory.Fact{},
			fmt.Errorf("commit Canonical Memory approval: %w", err)
	}
	return fact, nil
}

func (store *Store) RejectCandidate(
	ctx context.Context,
	scope task.MutationScope,
	command canonicalmemory.RejectCommand,
) (canonicalmemory.Candidate, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return canonicalmemory.Candidate{}, canonicalStoreError(err)
	}
	if err := command.Validate(); err != nil {
		return canonicalmemory.Candidate{}, err
	}
	requestDigest, err := command.Digest()
	if err != nil {
		return canonicalmemory.Candidate{}, err
	}
	candidateID, _ := uuid.Parse(command.CandidateID)
	tx, err := store.pool.BeginTx(ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return canonicalmemory.Candidate{},
			fmt.Errorf("begin Canonical Memory rejection: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	replay, _, response, err := claimScopedIdempotency(
		ctx, tx, caller, rejectMemoryCandidateOperation,
		command.IdempotencyKey, requestDigest[:], candidateID)
	if err != nil {
		return canonicalmemory.Candidate{}, canonicalStoreError(err)
	}
	if replay {
		candidate, err := decodeCanonicalCandidateSnapshot(response)
		if err != nil {
			return canonicalmemory.Candidate{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return canonicalmemory.Candidate{},
				fmt.Errorf("commit Canonical Memory rejection replay: %w",
					err)
		}
		return candidate, nil
	}
	current, err := readCanonicalCandidate(
		ctx, tx, store.instanceID, command.OwnerID, candidateID, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return canonicalmemory.Candidate{}, canonicalmemory.ErrNotFound
	}
	if err != nil {
		return canonicalmemory.Candidate{}, err
	}
	if current.Status != canonicalmemory.CandidatePending ||
		current.Revision != command.ExpectedRevision {
		return canonicalmemory.Candidate{},
			canonicalmemory.ErrRevisionConflict
	}
	candidate, err := scanCanonicalCandidate(tx.QueryRow(ctx, `
		UPDATE canonical_memory_candidates
		SET status='rejected',
		    rejection_reason=$4,
		    revision=revision+1,
		    updated_at=clock_timestamp()
		WHERE candidate_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3
		  AND status='pending'
		  AND revision=$5
		RETURNING `+canonicalCandidateColumns,
		candidateID, store.instanceID, command.OwnerID,
		command.ReasonCode, command.ExpectedRevision,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return canonicalmemory.Candidate{},
			canonicalmemory.ErrRevisionConflict
	}
	if err != nil {
		return canonicalmemory.Candidate{},
			canonicalStoreError(fmt.Errorf(
				"reject Canonical Memory candidate: %w", err))
	}
	candidate.Evidence = current.Evidence
	if candidate.Validate() != nil {
		return canonicalmemory.Candidate{},
			canonicalmemory.ErrFactMismatch
	}
	if err := setScopedIdempotencyResponse(
		ctx, tx, caller, rejectMemoryCandidateOperation,
		command.IdempotencyKey,
		canonicalCandidateSnapshot{
			SchemaVersion: canonicalSnapshotSchemaV1,
			Candidate:     candidate,
		},
	); err != nil {
		return canonicalmemory.Candidate{}, canonicalStoreError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return canonicalmemory.Candidate{},
			fmt.Errorf("commit Canonical Memory rejection: %w", err)
	}
	return candidate, nil
}

func (store *Store) RevokeMemory(
	ctx context.Context,
	scope task.MutationScope,
	command canonicalmemory.RevokeCommand,
) (canonicalmemory.Fact, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return canonicalmemory.Fact{}, canonicalStoreError(err)
	}
	if err := command.Validate(); err != nil {
		return canonicalmemory.Fact{}, err
	}
	requestDigest, err := command.Digest()
	if err != nil {
		return canonicalmemory.Fact{}, err
	}
	memoryID, _ := uuid.Parse(command.MemoryID)
	tx, err := store.pool.BeginTx(ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return canonicalmemory.Fact{},
			fmt.Errorf("begin Canonical Memory revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	replay, _, response, err := claimScopedIdempotency(
		ctx, tx, caller, revokeMemoryOperation,
		command.IdempotencyKey, requestDigest[:], memoryID)
	if err != nil {
		return canonicalmemory.Fact{}, canonicalStoreError(err)
	}
	if replay {
		fact, err := decodeCanonicalFactSnapshot(response)
		if err != nil {
			return canonicalmemory.Fact{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return canonicalmemory.Fact{},
				fmt.Errorf("commit Canonical Memory revocation replay: %w",
					err)
		}
		return fact, nil
	}
	current, err := readCanonicalMemoryProjection(
		ctx, tx, store.instanceID, command.OwnerID,
		command.MemoryID, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return canonicalmemory.Fact{}, canonicalmemory.ErrNotFound
	}
	if err != nil {
		return canonicalmemory.Fact{}, err
	}
	if current.Status != canonicalmemory.MemoryActive ||
		current.RecordRevision != command.ExpectedRecordRevision {
		return canonicalmemory.Fact{},
			canonicalmemory.ErrRevisionConflict
	}
	memory, err := scanCanonicalMemory(tx.QueryRow(ctx, `
		UPDATE canonical_memories
		SET status='revoked',
		    record_revision=record_revision+1,
		    updated_at=clock_timestamp()
		WHERE memory_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3
		  AND status='active'
		  AND record_revision=$4
		RETURNING `+canonicalMemoryColumns,
		memoryID, store.instanceID, command.OwnerID,
		command.ExpectedRecordRevision,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return canonicalmemory.Fact{},
			canonicalmemory.ErrRevisionConflict
	}
	if err != nil {
		return canonicalmemory.Fact{},
			canonicalStoreError(fmt.Errorf(
				"revoke Canonical Memory: %w", err))
	}
	revision, err := readCanonicalRevision(
		ctx, tx, memory.MemoryID, memory.CurrentRevision)
	if err != nil {
		return canonicalmemory.Fact{}, err
	}
	if err := appendCanonicalMemoryEvent(
		ctx, tx, store.instanceID, memory, revision,
		"revoked", "controller", "", command.ReasonCode,
		memory.UpdatedAt,
	); err != nil {
		return canonicalmemory.Fact{}, err
	}
	fact := canonicalmemory.Fact{Memory: memory, Revision: revision}
	if fact.Validate() != nil {
		return canonicalmemory.Fact{},
			canonicalmemory.ErrFactMismatch
	}
	if err := setScopedIdempotencyResponse(
		ctx, tx, caller, revokeMemoryOperation,
		command.IdempotencyKey,
		canonicalFactSnapshot{
			SchemaVersion: canonicalSnapshotSchemaV1,
			Fact:          fact,
		},
	); err != nil {
		return canonicalmemory.Fact{}, canonicalStoreError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return canonicalmemory.Fact{},
			fmt.Errorf("commit Canonical Memory revocation: %w", err)
	}
	return fact, nil
}

func (store *Store) GetMemory(
	ctx context.Context,
	ownerID,
	memoryID string,
) (canonicalmemory.Fact, error) {
	parsed, err := uuid.Parse(memoryID)
	if err != nil || parsed == uuid.Nil || parsed.String() != memoryID ||
		ownerID != strings.TrimSpace(ownerID) ||
		ownerID == "" || len(ownerID) > 255 {
		return canonicalmemory.Fact{}, canonicalmemory.ErrInvalid
	}
	fact, err := readCanonicalMemoryFact(
		ctx, store.pool, store.instanceID, ownerID, parsed)
	if errors.Is(err, pgx.ErrNoRows) {
		return canonicalmemory.Fact{}, canonicalmemory.ErrNotFound
	}
	if err != nil {
		return canonicalmemory.Fact{}, err
	}
	if err := store.verifyCanonicalFact(
		ctx, store.pool, fact); err != nil {
		return canonicalmemory.Fact{}, err
	}
	return fact, nil
}

func (store *Store) ListActiveMemories(
	ctx context.Context,
	query canonicalmemory.ListQuery,
) (canonicalmemory.Page, error) {
	validated, err := query.Validated()
	if err != nil {
		return canonicalmemory.Page{}, err
	}
	var after any
	if validated.AfterMemoryID != "" {
		after = validated.AfterMemoryID
	}
	rows, err := store.pool.Query(ctx, `
		SELECT memory_id
		FROM canonical_memories
		WHERE agent_instance_id=$1
		  AND owner_id=$2
		  AND namespace=$3
		  AND status='active'
		  AND ($4::uuid IS NULL OR memory_id>$4)
		ORDER BY memory_id
		LIMIT $5`,
		store.instanceID, validated.OwnerID, validated.Namespace,
		after, validated.PageSize+1,
	)
	if err != nil {
		return canonicalmemory.Page{},
			fmt.Errorf("list active Canonical Memories: %w", err)
	}
	defer rows.Close()
	ids := make([]uuid.UUID, 0, validated.PageSize+1)
	for rows.Next() {
		var memoryID uuid.UUID
		if err := rows.Scan(&memoryID); err != nil {
			return canonicalmemory.Page{},
				fmt.Errorf("scan Canonical Memory cursor: %w", err)
		}
		ids = append(ids, memoryID)
	}
	if err := rows.Err(); err != nil {
		return canonicalmemory.Page{},
			fmt.Errorf("iterate Canonical Memory cursors: %w", err)
	}
	hasMore := len(ids) > validated.PageSize
	if hasMore {
		ids = ids[:validated.PageSize]
	}
	page := canonicalmemory.Page{
		Facts: make([]canonicalmemory.Fact, 0, len(ids)),
	}
	for _, memoryID := range ids {
		fact, err := readCanonicalMemoryFact(
			ctx, store.pool, store.instanceID,
			validated.OwnerID, memoryID)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return canonicalmemory.Page{}, err
		}
		if fact.Memory.Status != canonicalmemory.MemoryActive ||
			!fact.Revision.ValidAt(validated.Now) {
			continue
		}
		if err := store.verifyCanonicalFact(
			ctx, store.pool, fact); err != nil {
			return canonicalmemory.Page{}, err
		}
		page.Facts = append(page.Facts, fact)
	}
	if hasMore && len(ids) > 0 {
		page.NextAfterMemoryID = ids[len(ids)-1].String()
	}
	return page, nil
}

const canonicalChallengeColumns = `
	challenge_id, approval_id, agent_instance_id, owner_id, candidate_id,
	candidate_revision, candidate_digest, evidence_digest, memory_id,
	expected_memory_revision, namespace, memory_key, memory_kind,
	valid_until, signer_key_id, challenge_json, signing_payload,
	issued_at, expires_at, consumed_at, record_revision, created_at,
	updated_at`

func readCanonicalChallenge(
	ctx context.Context,
	query canonicalQuery,
	instanceID uuid.UUID,
	ownerID string,
	challengeID uuid.UUID,
	lock bool,
) (canonicalmemory.ChallengeFact, []byte, error) {
	statement := `
		SELECT ` + canonicalChallengeColumns + `
		FROM canonical_memory_approval_challenges
		WHERE challenge_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3`
	if lock {
		statement += ` FOR UPDATE`
	}
	var (
		storedChallengeID, approvalID, storedAgentID uuid.UUID
		candidateID, memoryID                        uuid.UUID
		candidateRevision, expectedMemoryRevision    int64
		candidateDigest, evidenceDigest              string
		storedOwnerID, namespace, memoryKey          string
		memoryKind                                   canonicalmemory.MemoryKind
		validUntil, consumedAt                       *time.Time
		signerKeyID                                  string
		challengeJSON, signingPayload                []byte
		issuedAt, expiresAt                          time.Time
		fact                                         canonicalmemory.ChallengeFact
	)
	err := query.QueryRow(ctx, statement, challengeID, instanceID,
		ownerID).Scan(
		&storedChallengeID, &approvalID, &storedAgentID, &storedOwnerID,
		&candidateID, &candidateRevision, &candidateDigest,
		&evidenceDigest, &memoryID, &expectedMemoryRevision,
		&namespace, &memoryKey, &memoryKind, &validUntil,
		&signerKeyID, &challengeJSON, &signingPayload, &issuedAt,
		&expiresAt, &consumedAt, &fact.RecordRevision,
		&fact.CreatedAt, &fact.UpdatedAt,
	)
	if err != nil {
		return canonicalmemory.ChallengeFact{}, nil, err
	}
	if json.Unmarshal(challengeJSON, &fact.Challenge) != nil {
		return canonicalmemory.ChallengeFact{}, nil,
			canonicalmemory.ErrFactMismatch
	}
	challenge := fact.Challenge
	if challenge.ChallengeID != storedChallengeID.String() ||
		challenge.ApprovalID != approvalID.String() ||
		challenge.AgentInstanceID != storedAgentID.String() ||
		challenge.OwnerID != storedOwnerID ||
		storedOwnerID != ownerID ||
		challenge.CandidateID != candidateID.String() ||
		challenge.CandidateRevision != candidateRevision ||
		challenge.CandidateDigest != candidateDigest ||
		challenge.EvidenceDigest != evidenceDigest ||
		challenge.MemoryID != memoryID.String() ||
		challenge.ExpectedMemoryRevision != expectedMemoryRevision ||
		challenge.Namespace != namespace ||
		challenge.MemoryKey != memoryKey ||
		challenge.Kind != memoryKind ||
		challenge.SignerKeyID != signerKeyID ||
		!challenge.IssuedAt.Equal(issuedAt.UTC()) ||
		!challenge.ExpiresAt.Equal(expiresAt.UTC()) {
		return canonicalmemory.ChallengeFact{}, nil,
			canonicalmemory.ErrFactMismatch
	}
	if validUntil == nil {
		if challenge.HasValidUntil || !challenge.ValidUntil.IsZero() {
			return canonicalmemory.ChallengeFact{}, nil,
				canonicalmemory.ErrFactMismatch
		}
	} else if !challenge.HasValidUntil ||
		!challenge.ValidUntil.Equal(validUntil.UTC()) {
		return canonicalmemory.ChallengeFact{}, nil,
			canonicalmemory.ErrFactMismatch
	}
	expectedPayload, err := challenge.SigningPayload()
	if err != nil || !bytes.Equal(signingPayload, expectedPayload) {
		return canonicalmemory.ChallengeFact{}, nil,
			canonicalmemory.ErrFactMismatch
	}
	if consumedAt != nil {
		fact.ConsumedAt = consumedAt.UTC().Truncate(time.Microsecond)
	}
	fact.CreatedAt = fact.CreatedAt.UTC().Truncate(time.Microsecond)
	fact.UpdatedAt = fact.UpdatedAt.UTC().Truncate(time.Microsecond)
	if fact.Validate() != nil {
		return canonicalmemory.ChallengeFact{}, nil,
			canonicalmemory.ErrFactMismatch
	}
	return fact, append([]byte(nil), signingPayload...), nil
}

const canonicalMemoryColumns = `
	memory_id, owner_id, namespace, memory_key, memory_kind, status,
	current_revision, record_revision, created_at, updated_at`

func scanCanonicalMemory(row canonicalRow) (canonicalmemory.Memory, error) {
	var memory canonicalmemory.Memory
	var memoryID uuid.UUID
	if err := row.Scan(
		&memoryID, &memory.OwnerID, &memory.Namespace,
		&memory.MemoryKey, &memory.Kind, &memory.Status,
		&memory.CurrentRevision, &memory.RecordRevision,
		&memory.CreatedAt, &memory.UpdatedAt,
	); err != nil {
		return canonicalmemory.Memory{}, err
	}
	memory.MemoryID = memoryID.String()
	memory.CreatedAt = memory.CreatedAt.UTC().Truncate(time.Microsecond)
	memory.UpdatedAt = memory.UpdatedAt.UTC().Truncate(time.Microsecond)
	if memory.Validate() != nil {
		return canonicalmemory.Memory{}, canonicalmemory.ErrFactMismatch
	}
	return memory, nil
}

func readCanonicalMemoryProjection(
	ctx context.Context,
	query canonicalQuery,
	instanceID uuid.UUID,
	ownerID,
	memoryID string,
	lock bool,
) (canonicalmemory.Memory, error) {
	statement := `
		SELECT ` + canonicalMemoryColumns + `
		FROM canonical_memories
		WHERE memory_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3`
	if lock {
		statement += ` FOR UPDATE`
	}
	return scanCanonicalMemory(query.QueryRow(
		ctx, statement, memoryID, instanceID, ownerID))
}

const canonicalRevisionColumns = `
	memory_id, revision, candidate_id, owner_id, namespace, memory_key,
	memory_kind, title, statement, candidate_digest, evidence_digest,
	valid_from, valid_until, approval_id, created_at`

func scanCanonicalRevision(row canonicalRow) (
	canonicalmemory.Revision, error,
) {
	var (
		revision              canonicalmemory.Revision
		memoryID, candidateID uuid.UUID
		approvalID            uuid.UUID
		validUntil            *time.Time
	)
	if err := row.Scan(
		&memoryID, &revision.Revision, &candidateID,
		&revision.OwnerID, &revision.Namespace, &revision.MemoryKey,
		&revision.Kind, &revision.Title, &revision.Statement,
		&revision.CandidateDigest, &revision.EvidenceDigest,
		&revision.ValidFrom, &validUntil, &approvalID,
		&revision.CreatedAt,
	); err != nil {
		return canonicalmemory.Revision{}, err
	}
	revision.MemoryID = memoryID.String()
	revision.CandidateID = candidateID.String()
	revision.ApprovalID = approvalID.String()
	revision.ValidFrom = revision.ValidFrom.UTC().
		Truncate(time.Microsecond)
	if validUntil != nil {
		revision.ValidUntil = validUntil.UTC().
			Truncate(time.Microsecond)
	}
	revision.CreatedAt = revision.CreatedAt.UTC().
		Truncate(time.Microsecond)
	if revision.Validate() != nil {
		return canonicalmemory.Revision{},
			canonicalmemory.ErrFactMismatch
	}
	return revision, nil
}

func readCanonicalRevision(
	ctx context.Context,
	query canonicalQuery,
	memoryID string,
	revision int64,
) (canonicalmemory.Revision, error) {
	item, err := scanCanonicalRevision(query.QueryRow(ctx, `
		SELECT `+canonicalRevisionColumns+`
		FROM canonical_memory_revisions
		WHERE memory_id=$1 AND revision=$2`,
		memoryID, revision,
	))
	if err != nil {
		return canonicalmemory.Revision{}, err
	}
	return item, nil
}

func readCanonicalMemoryFact(
	ctx context.Context,
	query canonicalQuery,
	instanceID uuid.UUID,
	ownerID string,
	memoryID uuid.UUID,
) (canonicalmemory.Fact, error) {
	memory, err := scanCanonicalMemory(query.QueryRow(ctx, `
		SELECT `+canonicalMemoryColumns+`
		FROM canonical_memories
		WHERE memory_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3`,
		memoryID, instanceID, ownerID,
	))
	if err != nil {
		return canonicalmemory.Fact{}, err
	}
	revision, err := readCanonicalRevision(
		ctx, query, memory.MemoryID, memory.CurrentRevision)
	if err != nil {
		return canonicalmemory.Fact{}, err
	}
	fact := canonicalmemory.Fact{Memory: memory, Revision: revision}
	if fact.Validate() != nil {
		return canonicalmemory.Fact{}, canonicalmemory.ErrFactMismatch
	}
	return fact, nil
}

func (store *Store) verifyCanonicalFact(
	ctx context.Context,
	query canonicalQuery,
	fact canonicalmemory.Fact,
) error {
	if fact.Validate() != nil {
		return canonicalmemory.ErrFactMismatch
	}
	var (
		challengeJSON, approvalSignature, approvalPayload []byte
		approvedAt, deviceNotBefore, deviceExpiresAt      time.Time
		deviceRevokedAt                                   *time.Time
		publicKey                                         []byte
		challengeID                                       uuid.UUID
		signerKeyID                                       string
	)
	err := query.QueryRow(ctx, `
		SELECT approval.challenge_id, approval.signer_key_id,
		       approval.signature, approval.signing_payload,
		       approval.approved_at, challenge.challenge_json,
		       device.public_key, device.not_before, device.expires_at,
		       device.revoked_at
		FROM canonical_memory_approvals approval
		JOIN canonical_memory_approval_challenges challenge
		  ON challenge.challenge_id=approval.challenge_id
		JOIN cloud_approval_devices device
		  ON device.key_id=approval.signer_key_id
		WHERE approval.approval_id=$1
		  AND approval.agent_instance_id=$2
		  AND approval.owner_id=$3
		  AND approval.candidate_id=$4
		  AND approval.memory_id=$5`,
		fact.Revision.ApprovalID, store.instanceID,
		fact.Memory.OwnerID, fact.Revision.CandidateID,
		fact.Memory.MemoryID,
	).Scan(
		&challengeID, &signerKeyID, &approvalSignature,
		&approvalPayload, &approvedAt, &challengeJSON, &publicKey,
		&deviceNotBefore, &deviceExpiresAt, &deviceRevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return canonicalmemory.ErrFactMismatch
	}
	if err != nil {
		return fmt.Errorf("read Canonical Memory approval proof: %w", err)
	}
	approvedAt = approvedAt.UTC().Truncate(time.Microsecond)
	if len(publicKey) != ed25519.PublicKeySize ||
		len(approvalSignature) != ed25519.SignatureSize ||
		approvedAt.Before(deviceNotBefore.UTC()) ||
		!approvedAt.Before(deviceExpiresAt.UTC()) ||
		(deviceRevokedAt != nil &&
			!approvedAt.Before(deviceRevokedAt.UTC())) {
		return canonicalmemory.ErrFactMismatch
	}
	var challenge canonicalmemory.ChallengeV1
	if json.Unmarshal(challengeJSON, &challenge) != nil ||
		challenge.Validate() != nil ||
		challenge.ChallengeID != challengeID.String() ||
		challenge.SignerKeyID != signerKeyID ||
		challenge.ApprovalID != fact.Revision.ApprovalID ||
		challenge.CandidateID != fact.Revision.CandidateID ||
		challenge.MemoryID != fact.Memory.MemoryID ||
		challenge.CandidateDigest != fact.Revision.CandidateDigest ||
		challenge.EvidenceDigest != fact.Revision.EvidenceDigest ||
		!challenge.ValidUntil.Equal(fact.Revision.ValidUntil) ||
		!approvedAt.Equal(fact.Revision.ValidFrom) {
		return canonicalmemory.ErrFactMismatch
	}
	expectedPayload, err := challenge.SigningPayload()
	if err != nil || !bytes.Equal(expectedPayload, approvalPayload) {
		return canonicalmemory.ErrFactMismatch
	}
	candidateID, _ := uuid.Parse(fact.Revision.CandidateID)
	candidate, err := readCanonicalCandidate(
		ctx, query, store.instanceID, fact.Memory.OwnerID,
		candidateID, false)
	if err != nil {
		return canonicalmemory.ErrFactMismatch
	}
	signature := canonicalmemory.SignatureV1{
		SchemaVersion:          canonicalmemory.SignatureSchemaV1,
		ApprovalID:             challenge.ApprovalID,
		ChallengeID:            challenge.ChallengeID,
		CandidateID:            challenge.CandidateID,
		CandidateRevision:      challenge.CandidateRevision,
		CandidateDigest:        challenge.CandidateDigest,
		MemoryID:               challenge.MemoryID,
		ExpectedMemoryRevision: challenge.ExpectedMemoryRevision,
		SignerKeyID:            challenge.SignerKeyID,
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(
			approvalSignature),
	}
	if canonicalmemory.VerifyApproval(
		challenge, signature, candidate,
		ed25519.PublicKey(publicKey), approvedAt) != nil {
		return canonicalmemory.ErrFactMismatch
	}
	return nil
}

func appendCanonicalMemoryEvent(
	ctx context.Context,
	tx pgx.Tx,
	instanceID uuid.UUID,
	memory canonicalmemory.Memory,
	revision canonicalmemory.Revision,
	eventType,
	authority,
	approvalID,
	reason string,
	occurredAt time.Time,
) error {
	if memory.Validate() != nil || revision.Validate() != nil ||
		memory.MemoryID != revision.MemoryID ||
		occurredAt.IsZero() {
		return canonicalmemory.ErrInvalid
	}
	eventID := uuid.NewSHA1(instanceID, []byte(
		"dirextalk.agent.canonical-memory-event/v1\x00"+
			memory.MemoryID+"\x00"+
			fmt.Sprintf("%d", memory.RecordRevision)))
	var approval any
	if approvalID != "" {
		approval = approvalID
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO canonical_memory_events (
		    event_id, memory_id, record_revision, memory_revision,
		    event_type, authority, approval_id, reason_code,
		    occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		eventID, memory.MemoryID, memory.RecordRevision,
		memory.CurrentRevision, eventType, authority, approval, reason,
		occurredAt.UTC().Truncate(time.Microsecond),
	)
	if err != nil {
		return canonicalStoreError(fmt.Errorf(
			"append Canonical Memory event: %w", err))
	}
	return nil
}

func lockCanonicalMemoryIdentity(
	ctx context.Context,
	tx pgx.Tx,
	memoryID string,
) error {
	if _, err := tx.Exec(ctx, `
		SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"canonical-memory:"+memoryID,
	); err != nil {
		return fmt.Errorf("lock Canonical Memory identity: %w", err)
	}
	return nil
}

func decodeCanonicalEvidenceSnapshot(
	encoded []byte,
) (canonicalmemory.Evidence, error) {
	var snapshot canonicalEvidenceSnapshot
	if len(encoded) == 0 ||
		json.Unmarshal(encoded, &snapshot) != nil ||
		snapshot.SchemaVersion != canonicalSnapshotSchemaV1 ||
		snapshot.Evidence.Validate() != nil {
		return canonicalmemory.Evidence{},
			errors.New("invalid Canonical Memory evidence replay")
	}
	return snapshot.Evidence, nil
}

func decodeCanonicalCandidateSnapshot(
	encoded []byte,
) (canonicalmemory.Candidate, error) {
	var snapshot canonicalCandidateSnapshot
	if len(encoded) == 0 ||
		json.Unmarshal(encoded, &snapshot) != nil ||
		snapshot.SchemaVersion != canonicalSnapshotSchemaV1 ||
		snapshot.Candidate.Validate() != nil {
		return canonicalmemory.Candidate{},
			errors.New("invalid Canonical Memory candidate replay")
	}
	return snapshot.Candidate, nil
}

func decodeCanonicalChallengeSnapshot(
	encoded []byte,
) (canonicalmemory.ChallengeFact, error) {
	var snapshot canonicalChallengeSnapshot
	if len(encoded) == 0 ||
		json.Unmarshal(encoded, &snapshot) != nil ||
		snapshot.SchemaVersion != canonicalSnapshotSchemaV1 ||
		snapshot.Challenge.Validate() != nil {
		return canonicalmemory.ChallengeFact{},
			errors.New("invalid Canonical Memory challenge replay")
	}
	return snapshot.Challenge, nil
}

func decodeCanonicalFactSnapshot(
	encoded []byte,
) (canonicalmemory.Fact, error) {
	var snapshot canonicalFactSnapshot
	if len(encoded) == 0 ||
		json.Unmarshal(encoded, &snapshot) != nil ||
		snapshot.SchemaVersion != canonicalSnapshotSchemaV1 ||
		snapshot.Fact.Validate() != nil {
		return canonicalmemory.Fact{},
			errors.New("invalid Canonical Memory fact replay")
	}
	return snapshot.Fact, nil
}

func canonicalStoreError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, canonicalmemory.ErrInvalid) ||
		errors.Is(err, canonicalmemory.ErrNotFound) ||
		errors.Is(err, canonicalmemory.ErrRevisionConflict) ||
		errors.Is(err, canonicalmemory.ErrState) ||
		errors.Is(err, canonicalmemory.ErrEvidence) ||
		errors.Is(err, canonicalmemory.ErrApprovalRequired) ||
		errors.Is(err, canonicalmemory.ErrIdempotency) {
		return err
	}
	if errors.Is(err, task.ErrInvalidMutationScope) {
		return canonicalmemory.ErrInvalid
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "23505":
			return canonicalmemory.ErrState
		case "23503", "23514", "P0001":
			return canonicalmemory.ErrFactMismatch
		}
	}
	return err
}
