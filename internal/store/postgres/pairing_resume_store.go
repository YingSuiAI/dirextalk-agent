package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/pairing"
	"github.com/jackc/pgx/v5"
)

func (store *PairingStore) CreateResumeChallenge(ctx context.Context, mutation pairing.Mutation,
	challenge pairing.ResumeChallengeV1,
) (pairing.ResumeChallengeV1, error) {
	if ctx == nil || mutation.Validate() != nil || challenge.Validate() != nil || challenge.Scope.OwnerID != mutation.OwnerID {
		return pairing.ResumeChallengeV1{}, pairing.ErrInvalid
	}
	tx, err := store.base.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return pairing.ResumeChallengeV1{}, fmt.Errorf("begin pairing resume challenge: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replay, found, replayErr := readPairingResumeChallengeReplay(ctx, tx, store, mutation, "prepare"); replayErr != nil {
		return pairing.ResumeChallengeV1{}, replayErr
	} else if found {
		if err := tx.Commit(ctx); err != nil {
			return pairing.ResumeChallengeV1{}, fmt.Errorf("commit pairing resume challenge replay: %w", err)
		}
		return replay, nil
	}
	if err := validatePairingResumeScope(ctx, tx, store, challenge.Scope); err != nil {
		return pairing.ResumeChallengeV1{}, err
	}
	raw, err := json.Marshal(challenge)
	if err != nil {
		return pairing.ResumeChallengeV1{}, pairing.ErrInvalid
	}
	if _, err := tx.Exec(ctx, `INSERT INTO pairing_resume_challenges
		(challenge_id,approval_id,agent_instance_id,owner_id,pairing_id,signer_key_id,scope_digest,challenge_json,issued_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`,
		challenge.ChallengeID, challenge.ApprovalID, store.base.instanceID, mutation.OwnerID,
		challenge.Scope.PairingID, challenge.SignerKeyID, challenge.ScopeDigest, raw,
		challenge.IssuedAt.UTC(), challenge.ExpiresAt.UTC()); err != nil {
		return pairing.ResumeChallengeV1{}, fmt.Errorf("persist pairing resume challenge: %w", err)
	}
	stored, err := readPairingResumeChallenge(ctx, tx, store, mutation.OwnerID, challenge.ChallengeID, true)
	if err != nil {
		return pairing.ResumeChallengeV1{}, err
	}
	if stored != challenge {
		return pairing.ResumeChallengeV1{}, pairing.ErrRevisionConflict
	}
	if err := insertPairingResumeReplay(ctx, tx, store, mutation, "prepare", challenge.ChallengeID, challenge.IssuedAt); err != nil {
		return pairing.ResumeChallengeV1{}, err
	}
	replay, found, err := readPairingResumeChallengeReplay(ctx, tx, store, mutation, "prepare")
	if err != nil || !found || replay != challenge {
		if err != nil {
			return pairing.ResumeChallengeV1{}, err
		}
		return pairing.ResumeChallengeV1{}, pairing.ErrRevisionConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return pairing.ResumeChallengeV1{}, fmt.Errorf("commit pairing resume challenge: %w", err)
	}
	return challenge, nil
}

func (store *PairingStore) GetResumeChallenge(ctx context.Context, ownerID, challengeID string) (pairing.ResumeChallengeV1, error) {
	if ctx == nil || pairing.ValidateLookup(ownerID, challengeID) != nil {
		return pairing.ResumeChallengeV1{}, pairing.ErrInvalid
	}
	return readPairingResumeChallenge(ctx, store.base.pool, store, ownerID, challengeID, false)
}

func (store *PairingStore) GetResumeApproval(ctx context.Context, ownerID, challengeID string) (pairing.ResumeApprovalV1, error) {
	if ctx == nil || pairing.ValidateLookup(ownerID, challengeID) != nil {
		return pairing.ResumeApprovalV1{}, pairing.ErrInvalid
	}
	return readPairingResumeApproval(ctx, store.base.pool, store, ownerID, challengeID)
}

func (store *PairingStore) RecordResumeApproval(ctx context.Context, mutation pairing.Mutation,
	challenge pairing.ResumeChallengeV1, signature pairing.ApprovalSignatureV1, approvedAt time.Time,
) (pairing.ResumeApprovalV1, error) {
	if ctx == nil || mutation.Validate() != nil || challenge.Validate() != nil ||
		challenge.Scope.OwnerID != mutation.OwnerID || !validPairingResumeSignature(challenge, signature) ||
		approvedAt.Before(challenge.IssuedAt) || !approvedAt.Before(challenge.ExpiresAt) {
		return pairing.ResumeApprovalV1{}, pairing.ErrInvalid
	}
	tx, err := store.base.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return pairing.ResumeApprovalV1{}, fmt.Errorf("begin pairing resume approval: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replay, found, replayErr := readPairingResumeApprovalReplay(ctx, tx, store, mutation); replayErr != nil {
		return pairing.ResumeApprovalV1{}, replayErr
	} else if found {
		if err := tx.Commit(ctx); err != nil {
			return pairing.ResumeApprovalV1{}, fmt.Errorf("commit pairing resume approval replay: %w", err)
		}
		return replay, nil
	}
	stored, err := readPairingResumeChallenge(ctx, tx, store, mutation.OwnerID, challenge.ChallengeID, true)
	if err != nil {
		return pairing.ResumeApprovalV1{}, err
	}
	if stored != challenge {
		return pairing.ResumeApprovalV1{}, pairing.ErrRevisionConflict
	}
	if err := validatePairingResumeScope(ctx, tx, store, challenge.Scope); err != nil {
		return pairing.ResumeApprovalV1{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO pairing_resume_approvals
		(approval_id,challenge_id,agent_instance_id,owner_id,signer_key_id,signature,approved_at,revision)
		VALUES($1,$2,$3,$4,$5,$6,$7,1) ON CONFLICT DO NOTHING`,
		challenge.ApprovalID, challenge.ChallengeID, store.base.instanceID, mutation.OwnerID,
		signature.SignerKeyID, signature.Signature, approvedAt.UTC()); err != nil {
		return pairing.ResumeApprovalV1{}, fmt.Errorf("persist pairing resume approval: %w", err)
	}
	approval, err := readPairingResumeApproval(ctx, tx, store, mutation.OwnerID, challenge.ChallengeID)
	if err != nil {
		return pairing.ResumeApprovalV1{}, err
	}
	if !samePairingResumeApproval(approval, challenge, signature, approvedAt) {
		return pairing.ResumeApprovalV1{}, pairing.ErrRevisionConflict
	}
	if err := insertPairingResumeReplay(ctx, tx, store, mutation, "approve", challenge.ChallengeID, approvedAt); err != nil {
		return pairing.ResumeApprovalV1{}, err
	}
	replay, found, err := readPairingResumeApprovalReplay(ctx, tx, store, mutation)
	if err != nil || !found || !samePairingResumeApproval(replay, challenge, signature, approvedAt) {
		if err != nil {
			return pairing.ResumeApprovalV1{}, err
		}
		return pairing.ResumeApprovalV1{}, pairing.ErrRevisionConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return pairing.ResumeApprovalV1{}, fmt.Errorf("commit pairing resume approval: %w", err)
	}
	return approval, nil
}

const validatePairingResumeScopeSQL = `SELECT EXISTS(
		SELECT 1
		FROM pairing_sessions s
		JOIN worker_deployments d ON d.deployment_id=s.deployment_id
		JOIN cloud_launch_operations l ON l.deployment_id=d.deployment_id
		WHERE s.agent_instance_id=$1 AND s.owner_id=$2 AND s.session_id=$3 AND s.deployment_id=$4
		  AND s.plan_id=$5 AND s.connection_id=$6 AND s.task_id=$7 AND s.step_id=$8
		  AND s.recipe_digest=$9 AND s.execution_manifest_digest=$10 AND s.revision=$11
		  AND s.deployment_revision=$12
		  AND s.status IN ('payload_ready','waiting_user')
		  AND d.agent_instance_id=$1 AND d.owner_id=$2 AND d.task_id=s.task_id AND d.step_id=s.step_id AND d.revision=$12
		  AND l.agent_instance_id=$1 AND l.owner_id=$2 AND l.plan_id=s.plan_id AND l.connection_id=s.connection_id
		  AND l.task_id=s.task_id AND l.task_step_id=s.step_id
	)`

func validatePairingResumeScope(ctx context.Context, query pairingQuery, store *PairingStore, scope pairing.ResumeScopeV1) error {
	var valid bool
	err := query.QueryRow(ctx, validatePairingResumeScopeSQL, store.base.instanceID, scope.OwnerID, scope.PairingID, scope.DeploymentID, scope.PlanID,
		scope.ConnectionID, scope.TaskID, scope.StepID, scope.RecipeDigest, scope.ExecutionManifestDigest,
		scope.PairingRevision, scope.DeploymentRevision).Scan(&valid)
	if err != nil {
		return fmt.Errorf("verify pairing resume scope: %w", err)
	}
	if !valid {
		return pairing.ErrRevisionConflict
	}
	return nil
}

func readPairingResumeChallenge(ctx context.Context, query pairingQuery, store *PairingStore,
	ownerID, challengeID string, lock bool,
) (pairing.ResumeChallengeV1, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	var raw []byte
	err := query.QueryRow(ctx, `SELECT challenge_json FROM pairing_resume_challenges
		WHERE agent_instance_id=$1 AND owner_id=$2 AND challenge_id=$3`+suffix,
		store.base.instanceID, ownerID, challengeID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return pairing.ResumeChallengeV1{}, pairing.ErrNotFound
	}
	if err != nil {
		return pairing.ResumeChallengeV1{}, fmt.Errorf("read pairing resume challenge: %w", err)
	}
	var value pairing.ResumeChallengeV1
	if json.Unmarshal(raw, &value) != nil || value.Validate() != nil ||
		value.Scope.OwnerID != ownerID || value.ChallengeID != challengeID {
		return pairing.ResumeChallengeV1{}, pairing.ErrInvalid
	}
	return value, nil
}

func readPairingResumeApproval(ctx context.Context, query pairingQuery, store *PairingStore,
	ownerID, challengeID string,
) (pairing.ResumeApprovalV1, error) {
	var challengeRaw, signature []byte
	var signerKeyID string
	var approvedAt time.Time
	var revision int64
	err := query.QueryRow(ctx, `SELECT c.challenge_json,a.signer_key_id,a.signature,a.approved_at,a.revision
		FROM pairing_resume_approvals a
		JOIN pairing_resume_challenges c ON c.challenge_id=a.challenge_id AND c.approval_id=a.approval_id
		WHERE a.agent_instance_id=$1 AND a.owner_id=$2 AND a.challenge_id=$3`,
		store.base.instanceID, ownerID, challengeID).Scan(&challengeRaw, &signerKeyID, &signature, &approvedAt, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return pairing.ResumeApprovalV1{}, pairing.ErrNotFound
	}
	if err != nil {
		return pairing.ResumeApprovalV1{}, fmt.Errorf("read pairing resume approval: %w", err)
	}
	var challenge pairing.ResumeChallengeV1
	if json.Unmarshal(challengeRaw, &challenge) != nil || challenge.Validate() != nil || challenge.Scope.OwnerID != ownerID {
		return pairing.ResumeApprovalV1{}, pairing.ErrInvalid
	}
	value := pairing.ResumeApprovalV1{
		Challenge: challenge,
		Signature: pairing.ApprovalSignatureV1{
			ChallengeID: challengeID, SignerKeyID: signerKeyID, Signature: append([]byte(nil), signature...),
		},
		ApprovedAt: approvedAt,
		Revision:   revision,
	}
	if !validPairingResumeSignature(challenge, value.Signature) || revision != 1 ||
		approvedAt.Before(challenge.IssuedAt) || !approvedAt.Before(challenge.ExpiresAt) {
		return pairing.ResumeApprovalV1{}, pairing.ErrInvalid
	}
	return value, nil
}

func readPairingResumeChallengeReplay(ctx context.Context, query pairingQuery, store *PairingStore,
	mutation pairing.Mutation, operation string,
) (pairing.ResumeChallengeV1, bool, error) {
	challengeID, found, err := readPairingResumeReplay(ctx, query, store, mutation, operation)
	if err != nil || !found {
		return pairing.ResumeChallengeV1{}, found, err
	}
	value, err := readPairingResumeChallenge(ctx, query, store, mutation.OwnerID, challengeID, false)
	return value, true, err
}

func readPairingResumeApprovalReplay(ctx context.Context, query pairingQuery, store *PairingStore,
	mutation pairing.Mutation,
) (pairing.ResumeApprovalV1, bool, error) {
	challengeID, found, err := readPairingResumeReplay(ctx, query, store, mutation, "approve")
	if err != nil || !found {
		return pairing.ResumeApprovalV1{}, found, err
	}
	value, err := readPairingResumeApproval(ctx, query, store, mutation.OwnerID, challengeID)
	return value, true, err
}

func readPairingResumeReplay(ctx context.Context, query pairingQuery, store *PairingStore,
	mutation pairing.Mutation, operation string,
) (string, bool, error) {
	var challengeID, requestDigest string
	var revision int64
	err := query.QueryRow(ctx, `SELECT challenge_id,request_digest,response_revision FROM pairing_resume_replays
		WHERE agent_instance_id=$1 AND owner_id=$2 AND operation=$3 AND idempotency_key=$4`,
		store.base.instanceID, mutation.OwnerID, operation, mutation.IdempotencyKey).
		Scan(&challengeID, &requestDigest, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read pairing resume replay: %w", err)
	}
	if requestDigest != mutation.RequestDigest || revision != 1 {
		return "", false, pairing.ErrRevisionConflict
	}
	return challengeID, true, nil
}

func insertPairingResumeReplay(ctx context.Context, tx pgx.Tx, store *PairingStore, mutation pairing.Mutation,
	operation, challengeID string, at time.Time,
) error {
	if _, err := tx.Exec(ctx, `INSERT INTO pairing_resume_replays
		(agent_instance_id,owner_id,operation,idempotency_key,request_digest,challenge_id,response_revision,created_at)
		VALUES($1,$2,$3,$4,$5,$6,1,$7) ON CONFLICT DO NOTHING`,
		store.base.instanceID, mutation.OwnerID, operation, mutation.IdempotencyKey, mutation.RequestDigest,
		challengeID, at.UTC()); err != nil {
		return fmt.Errorf("persist pairing resume replay: %w", err)
	}
	return nil
}

func validPairingResumeSignature(challenge pairing.ResumeChallengeV1, signature pairing.ApprovalSignatureV1) bool {
	return signature.ChallengeID == challenge.ChallengeID && signature.SignerKeyID == challenge.SignerKeyID &&
		len(signature.Signature) == 64
}

func samePairingResumeApproval(value pairing.ResumeApprovalV1, challenge pairing.ResumeChallengeV1,
	signature pairing.ApprovalSignatureV1, approvedAt time.Time,
) bool {
	return value.Challenge == challenge && value.Signature.ChallengeID == signature.ChallengeID &&
		value.Signature.SignerKeyID == signature.SignerKeyID &&
		bytes.Equal(value.Signature.Signature, signature.Signature) &&
		value.ApprovedAt.Equal(approvedAt) && value.Revision == 1
}

var _ pairing.ChallengeRepository = (*PairingStore)(nil)
