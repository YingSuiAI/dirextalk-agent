package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const approvePlanOperation = "cloud.plan.approve"

type approvePlanSnapshot struct {
	SchemaVersion int                 `json:"schema_version"`
	Plan          CloudPlanRecord     `json:"plan"`
	Approval      CloudApprovalRecord `json:"approval"`
}

func (store *Store) ApprovePlan(ctx context.Context, scope task.MutationScope, command ApprovePlanCommand) (cloudapproval.PlanV1, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return cloudapproval.PlanV1{}, err
	}
	if err := command.validate(); err != nil {
		return cloudapproval.PlanV1{}, err
	}
	requestDigest, err := command.digest()
	if err != nil {
		return cloudapproval.PlanV1{}, err
	}
	approvalID, _ := uuid.Parse(command.Approval.ApprovalID)
	planID, _ := uuid.Parse(command.Approval.PlanID)
	quoteID, _ := uuid.Parse(command.Approval.QuoteID)
	challengeRowID := approvalChallengeID(store.instanceID, command.Approval.ChallengeID)

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return cloudapproval.PlanV1{}, fmt.Errorf("begin approve Plan: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, response, err := claimScopedIdempotency(ctx, tx, caller, approvePlanOperation, command.IdempotencyKey, requestDigest[:], approvalID)
	if err != nil {
		return cloudapproval.PlanV1{}, err
	}
	if existing {
		snapshot, err := decodeApprovePlanSnapshot(response)
		if err != nil {
			return cloudapproval.PlanV1{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return cloudapproval.PlanV1{}, fmt.Errorf("commit approval replay: %w", err)
		}
		return snapshot.Plan.Plan, nil
	}
	planRecord, err := readCloudPlan(ctx, tx, planID, true)
	if err != nil {
		return cloudapproval.PlanV1{}, err
	}
	if planRecord.Revision != command.ExpectedPlanRevision || planRecord.Plan.Status != cloudapproval.PlanReadyForConfirmation {
		return cloudapproval.PlanV1{}, ErrCloudFactRevision
	}
	quoteRecord, err := readCloudQuote(ctx, tx, quoteID, false)
	if err != nil {
		return cloudapproval.PlanV1{}, err
	}
	challengeRecord, storedChallengeRowID, err := readApprovalChallenge(ctx, tx, command.Approval.ChallengeID, true)
	if err != nil {
		return cloudapproval.PlanV1{}, err
	}
	if storedChallengeRowID != challengeRowID || challengeRecord.Challenge.Revision != command.ExpectedChallengeRevision {
		return cloudapproval.PlanV1{}, ErrCloudFactRevision
	}
	if challengeRecord.Challenge.ConsumedAt != nil {
		return cloudapproval.PlanV1{}, ErrCloudChallengeConsumed
	}
	deviceRecord, err := readApprovalDevice(ctx, tx, command.Approval.SignerKeyID, false)
	if err != nil {
		return cloudapproval.PlanV1{}, err
	}
	var approvedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&approvedAt); err != nil {
		return cloudapproval.PlanV1{}, fmt.Errorf("read approval time: %w", err)
	}
	approvedAt = approvedAt.UTC()
	// Challenge creation accepts at most 30 seconds of client/database clock
	// skew. Keep consumption inside the already-accepted challenge window while
	// still using PostgreSQL time whenever it is later.
	if approvedAt.Before(challengeRecord.Challenge.IssuedAt) {
		approvedAt = challengeRecord.Challenge.IssuedAt.UTC()
	}
	if err := deviceRecord.Device.ValidateAt(approvedAt); err != nil {
		return cloudapproval.PlanV1{}, err
	}
	if err := planRecord.Plan.ValidateQuote(quoteRecord.Quote, approvedAt); err != nil {
		return cloudapproval.PlanV1{}, err
	}
	if err := command.Approval.VerifyForPlan(deviceRecord.Device.PublicKey, planRecord.Plan, approvedAt); err != nil {
		return cloudapproval.PlanV1{}, err
	}
	if err := challengeMatchesSignedApproval(challengeRecord.Challenge, command.Approval); err != nil {
		return cloudapproval.PlanV1{}, err
	}
	if command.Approval.ExpiresAt.After(challengeRecord.Challenge.ExpiresAt) ||
		command.Approval.AgentInstanceID != store.instanceID.String() || command.Approval.OwnerID != deviceRecord.Device.OwnerID {
		return cloudapproval.PlanV1{}, ErrCloudFactScope
	}
	signingPayload, err := command.Approval.SigningPayload()
	if err != nil {
		return cloudapproval.PlanV1{}, ErrCloudFactInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(command.Approval.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return cloudapproval.PlanV1{}, ErrCloudFactInvalid
	}
	approvalJSON, err := json.Marshal(command.Approval)
	if err != nil {
		return cloudapproval.PlanV1{}, ErrCloudFactInvalid
	}
	approvalRecord := CloudApprovalRecord{Approval: command.Approval, Revision: 1, ApprovedAt: approvedAt}
	if _, err := tx.Exec(ctx, `
		INSERT INTO cloud_approvals
		    (approval_id, agent_instance_id, owner_id, plan_id, plan_revision, plan_hash,
		     quote_id, quote_digest, challenge_row_id, signer_key_id, approval_json,
		     signing_payload, signature, revision, approved_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,1,$14)`,
		approvalID, store.instanceID, command.Approval.OwnerID, planID, int64(command.Approval.PlanRevision),
		command.Approval.PlanHash, quoteID, command.Approval.QuoteDigest, challengeRowID,
		command.Approval.SignerKeyID, approvalJSON, signingPayload, signature, approvedAt,
	); err != nil {
		return cloudapproval.PlanV1{}, fmt.Errorf("insert cloud approval: %w", err)
	}
	challengeRecord.Challenge.Revision++
	challengeRecord.Challenge.ConsumedAt = &approvedAt
	if err := tx.QueryRow(ctx, `
		UPDATE cloud_approval_challenges
		SET consumed_at=$2, revision=$3, updated_at=clock_timestamp()
		WHERE challenge_row_id=$1 AND revision=$4 AND consumed_at IS NULL
		RETURNING updated_at`, challengeRowID, approvedAt, int64(challengeRecord.Challenge.Revision), int64(command.ExpectedChallengeRevision),
	).Scan(&challengeRecord.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return cloudapproval.PlanV1{}, ErrCloudFactRevision
		}
		return cloudapproval.PlanV1{}, fmt.Errorf("consume approved challenge: %w", err)
	}
	challengeRecord.UpdatedAt = challengeRecord.UpdatedAt.UTC()
	if err := appendApprovalChallengeEvent(ctx, tx, caller, challengeRowID, challengeRecord); err != nil {
		return cloudapproval.PlanV1{}, err
	}
	if err := appendCloudApprovalEvent(ctx, tx, caller, approvalID, approvalRecord); err != nil {
		return cloudapproval.PlanV1{}, err
	}

	if planRecord.Revision >= math.MaxInt64 {
		return cloudapproval.PlanV1{}, ErrCloudFactRevision
	}
	approvedPlan := planRecord.Plan
	approvedPlan.Status = cloudapproval.PlanApproved
	approvedPlan.Revision++
	approvedPlanHash, err := approvedPlan.Hash()
	if err != nil {
		return cloudapproval.PlanV1{}, ErrCloudFactInvalid
	}
	approvedPlanCBOR, err := approvedPlan.CanonicalCBOR()
	if err != nil {
		return cloudapproval.PlanV1{}, ErrCloudFactInvalid
	}
	approvedPlanJSON, err := json.Marshal(approvedPlan)
	if err != nil {
		return cloudapproval.PlanV1{}, ErrCloudFactInvalid
	}
	planRecord.Plan, planRecord.PlanHash, planRecord.Revision = approvedPlan, approvedPlanHash, approvedPlan.Revision
	if err := tx.QueryRow(ctx, `
		UPDATE cloud_plans
		SET status='approved', plan_hash=$2, plan_json=$3, plan_cbor=$4,
		    revision=$5, updated_at=clock_timestamp()
		WHERE plan_id=$1 AND revision=$6 AND status='ready_for_confirmation'
		RETURNING updated_at`, planID, approvedPlanHash, approvedPlanJSON, approvedPlanCBOR,
		int64(approvedPlan.Revision), int64(command.ExpectedPlanRevision),
	).Scan(&planRecord.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return cloudapproval.PlanV1{}, ErrCloudFactRevision
		}
		return cloudapproval.PlanV1{}, fmt.Errorf("transition approved Plan: %w", err)
	}
	planRecord.UpdatedAt = planRecord.UpdatedAt.UTC()
	if err := appendPlanEvent(ctx, tx, caller, planID, planRecord); err != nil {
		return cloudapproval.PlanV1{}, err
	}
	snapshot := approvePlanSnapshot{SchemaVersion: cloudFactSnapshotSchemaV1, Plan: planRecord, Approval: approvalRecord}
	if err := setScopedIdempotencyResponse(ctx, tx, caller, approvePlanOperation, command.IdempotencyKey, snapshot); err != nil {
		return cloudapproval.PlanV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return cloudapproval.PlanV1{}, fmt.Errorf("commit approve Plan: %w", err)
	}
	return approvedPlan, nil
}

func (store *Store) GetApproval(ctx context.Context, ownerID, approvalID string) (cloudapproval.ApprovalV1, error) {
	parsed, err := uuid.Parse(approvalID)
	if err != nil || strings.TrimSpace(ownerID) == "" {
		return cloudapproval.ApprovalV1{}, ErrCloudFactInvalid
	}
	record, err := readCloudApproval(ctx, store.pool, parsed)
	if err != nil {
		return cloudapproval.ApprovalV1{}, err
	}
	if record.Approval.OwnerID != strings.TrimSpace(ownerID) || record.Approval.AgentInstanceID != store.instanceID.String() {
		return cloudapproval.ApprovalV1{}, ErrCloudFactScope
	}
	return record.Approval, nil
}

func readCloudApproval(ctx context.Context, query cloudPlanQuerier, approvalID uuid.UUID) (CloudApprovalRecord, error) {
	var (
		agentID, planID, quoteID                    uuid.UUID
		ownerID, planHash, quoteDigest, signerKeyID string
		planRevision, revision                      int64
		approvalJSON, signingPayload, signature     []byte
		record                                      CloudApprovalRecord
	)
	if err := query.QueryRow(ctx, `
		SELECT agent_instance_id, owner_id, plan_id, plan_revision, plan_hash, quote_id,
		       quote_digest, signer_key_id, approval_json, signing_payload, signature,
		       revision, approved_at
		FROM cloud_approvals WHERE approval_id=$1`, approvalID).Scan(
		&agentID, &ownerID, &planID, &planRevision, &planHash, &quoteID, &quoteDigest,
		&signerKeyID, &approvalJSON, &signingPayload, &signature, &revision, &record.ApprovedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return CloudApprovalRecord{}, ErrCloudFactNotFound
		}
		return CloudApprovalRecord{}, fmt.Errorf("read cloud approval: %w", err)
	}
	if json.Unmarshal(approvalJSON, &record.Approval) != nil || revision != 1 || len(signature) != ed25519.SignatureSize {
		return CloudApprovalRecord{}, ErrCloudFactCorrupt
	}
	record.Revision, record.ApprovedAt = uint64(revision), record.ApprovedAt.UTC()
	if err := record.Approval.Validate(); err != nil || record.Approval.Signature == "" ||
		record.Approval.ApprovalID != approvalID.String() || record.Approval.AgentInstanceID != agentID.String() ||
		record.Approval.OwnerID != ownerID || record.Approval.PlanID != planID.String() || record.Approval.PlanRevision != uint64(planRevision) ||
		record.Approval.PlanHash != planHash || record.Approval.QuoteID != quoteID.String() ||
		record.Approval.QuoteDigest != quoteDigest || record.Approval.SignerKeyID != signerKeyID {
		return CloudApprovalRecord{}, ErrCloudFactCorrupt
	}
	actualPayload, err := record.Approval.SigningPayload()
	if err != nil || !bytes.Equal(actualPayload, signingPayload) {
		return CloudApprovalRecord{}, ErrCloudFactCorrupt
	}
	actualSignature, err := base64.RawURLEncoding.DecodeString(record.Approval.Signature)
	if err != nil || !bytes.Equal(actualSignature, signature) {
		return CloudApprovalRecord{}, ErrCloudFactCorrupt
	}
	return record, nil
}

func challengeMatchesSignedApproval(challenge cloudapproval.ChallengeV1, signed cloudapproval.ApprovalV1) error {
	if challenge.ChallengeID != signed.ChallengeID || challenge.AgentInstanceID != signed.AgentInstanceID ||
		challenge.OwnerID != signed.OwnerID || challenge.PlanID != signed.PlanID || challenge.PlanRevision != signed.PlanRevision ||
		challenge.PlanHash != signed.PlanHash || challenge.ConnectionID != signed.ConnectionID ||
		challenge.RecipeDigest != signed.RecipeDigest || challenge.QuoteID != signed.QuoteID ||
		challenge.QuoteDigest != signed.QuoteDigest || challenge.QuoteScopeDigest != signed.QuoteScopeDigest ||
		challenge.QuoteCandidateID != signed.QuoteCandidateID || challenge.SignerKeyID != signed.SignerKeyID {
		return fmt.Errorf("%w: approval does not match stored challenge", ErrCloudFactScope)
	}
	return nil
}

func decodeApprovePlanSnapshot(encoded []byte) (approvePlanSnapshot, error) {
	var snapshot approvePlanSnapshot
	if err := json.Unmarshal(encoded, &snapshot); err != nil || snapshot.SchemaVersion != cloudFactSnapshotSchemaV1 ||
		snapshot.Plan.Revision == 0 || snapshot.Approval.Revision != 1 || snapshot.Plan.Plan.Status != cloudapproval.PlanApproved {
		return approvePlanSnapshot{}, ErrCloudFactCorrupt
	}
	planHash, err := snapshot.Plan.Plan.Hash()
	if err != nil || planHash != snapshot.Plan.PlanHash || snapshot.Plan.Plan.Revision != snapshot.Plan.Revision {
		return approvePlanSnapshot{}, ErrCloudFactCorrupt
	}
	payload, err := snapshot.Approval.Approval.SigningPayload()
	if err != nil || len(payload) == 0 || snapshot.Approval.Approval.Signature == "" {
		return approvePlanSnapshot{}, ErrCloudFactCorrupt
	}
	snapshot.Plan.CreatedAt, snapshot.Plan.UpdatedAt = snapshot.Plan.CreatedAt.UTC(), snapshot.Plan.UpdatedAt.UTC()
	snapshot.Approval.ApprovedAt = snapshot.Approval.ApprovedAt.UTC()
	return snapshot, nil
}

func appendCloudApprovalEvent(ctx context.Context, tx pgx.Tx, caller idempotencyCaller, approvalID uuid.UUID, record CloudApprovalRecord) error {
	summary := struct {
		ApprovalID   string          `json:"approval_id"`
		OwnerID      string          `json:"owner_id"`
		PlanID       string          `json:"plan_id"`
		PlanRevision uint64          `json:"plan_revision"`
		PlanHash     string          `json:"plan_hash"`
		QuoteID      string          `json:"quote_id"`
		SignerKeyID  string          `json:"signer_key_id"`
		ApprovedAt   time.Time       `json:"approved_at"`
		Revision     uint64          `json:"revision"`
		Actor        cloudEventActor `json:"actor"`
	}{
		ApprovalID: record.Approval.ApprovalID, OwnerID: record.Approval.OwnerID,
		PlanID: record.Approval.PlanID, PlanRevision: record.Approval.PlanRevision,
		PlanHash: record.Approval.PlanHash, QuoteID: record.Approval.QuoteID,
		SignerKeyID: record.Approval.SignerKeyID, ApprovedAt: record.ApprovedAt.UTC(),
		Revision: record.Revision, Actor: newCloudEventActor(caller),
	}
	return appendCloudFactEvent(ctx, tx, approvalID, "cloud_approval", "cloud.approval.changed", record.Revision, summary)
}
