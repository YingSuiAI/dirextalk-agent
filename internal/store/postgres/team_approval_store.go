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

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamapproval"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	createTeamApprovalChallengeOperation = "team.approval_challenge.create"
	approveTeamPlanOperation             = "team.plan.approve"
)

type teamApprovalChallengeReplay struct {
	SchemaVersion int                         `json:"schema_version"`
	Record        TeamApprovalChallengeRecord `json:"record"`
}

type approveTeamPlanReplay struct {
	SchemaVersion int                         `json:"schema_version"`
	Plan          TeamPlanRecord              `json:"plan"`
	Challenge     TeamApprovalChallengeRecord `json:"challenge"`
	Approval      TeamApprovalRecord          `json:"approval"`
}

func (store *Store) CreateTeamApprovalChallenge(
	ctx context.Context,
	scope task.MutationScope,
	command CreateTeamApprovalChallengeCommand,
) (TeamApprovalChallengeRecord, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return TeamApprovalChallengeRecord{}, err
	}
	if err := command.validate(); err != nil {
		return TeamApprovalChallengeRecord{}, err
	}
	requestDigest, err := command.digest()
	if err != nil {
		return TeamApprovalChallengeRecord{}, err
	}
	planID, _ := uuid.Parse(command.PlanID)
	challengeID, _ := uuid.Parse(command.ChallengeID)

	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return TeamApprovalChallengeRecord{}, fmt.Errorf(
			"begin create Team approval challenge: %w",
			err,
		)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, response, err := claimScopedIdempotency(
		ctx,
		tx,
		caller,
		createTeamApprovalChallengeOperation,
		command.IdempotencyKey,
		requestDigest[:],
		challengeID,
	)
	if err != nil {
		return TeamApprovalChallengeRecord{}, err
	}
	if existing {
		record, err := decodeTeamApprovalChallengeReplay(response)
		if err != nil {
			return TeamApprovalChallengeRecord{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return TeamApprovalChallengeRecord{}, fmt.Errorf(
				"commit Team approval challenge replay: %w",
				err,
			)
		}
		return record, nil
	}

	planRecord, err := readTeamPlan(
		ctx,
		tx,
		store.instanceID,
		planID,
		command.PlanRevision,
		true,
	)
	if err != nil {
		return TeamApprovalChallengeRecord{}, err
	}
	if planRecord.Plan.OwnerID != command.OwnerID {
		return TeamApprovalChallengeRecord{}, ErrTeamFactScope
	}
	if planRecord.RecordRevision != command.ExpectedPlanRecordRevision ||
		planRecord.Status != TeamPlanReadyForConfirmation {
		return TeamApprovalChallengeRecord{}, ErrTeamFactRevision
	}
	var databaseNow time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(
		&databaseNow,
	); err != nil {
		return TeamApprovalChallengeRecord{}, fmt.Errorf(
			"read Team approval challenge time: %w",
			err,
		)
	}
	databaseNow = databaseNow.UTC()
	snapshotID, _ := uuid.Parse(planRecord.Plan.PricingSnapshotID)
	snapshotRecord, err := readTeamOfferSnapshot(
		ctx,
		tx,
		store.instanceID,
		snapshotID,
		true,
	)
	if err != nil {
		return TeamApprovalChallengeRecord{}, err
	}
	snapshot, err := snapshotRecord.Snapshot()
	if err != nil {
		return TeamApprovalChallengeRecord{}, err
	}
	if snapshotRecord.OwnerID != planRecord.Plan.OwnerID {
		return TeamApprovalChallengeRecord{}, ErrTeamFactScope
	}
	if err := snapshot.VerifyPlanPricing(
		planRecord.Plan,
		databaseNow,
	); err != nil {
		return TeamApprovalChallengeRecord{}, err
	}
	if err := verifyTeamConnectionScope(
		ctx,
		tx,
		store.instanceID,
		planRecord.Plan.OwnerID,
		planRecord.Plan.ProviderScope,
		planRecord.Plan.Region,
	); err != nil {
		return TeamApprovalChallengeRecord{}, err
	}
	deviceRecord, err := readApprovalDevice(
		ctx,
		tx,
		command.SignerKeyID,
		true,
	)
	if err != nil {
		return TeamApprovalChallengeRecord{}, ErrTeamFactScope
	}
	if err := validateTeamApprovalDevice(
		deviceRecord.Device,
		store.instanceID.String(),
		planRecord.Plan.OwnerID,
		command.SignerKeyID,
		databaseNow,
	); err != nil {
		return TeamApprovalChallengeRecord{}, err
	}
	challenge, err := teamapproval.NewChallengeV1(
		planRecord.Plan,
		store.instanceID.String(),
		command.ApprovalID,
		command.ChallengeID,
		command.SignerKeyID,
		databaseNow,
	)
	if err != nil {
		return TeamApprovalChallengeRecord{}, err
	}
	challengeJSON, err := json.Marshal(challenge)
	if err != nil {
		return TeamApprovalChallengeRecord{}, ErrTeamFactInvalid
	}
	signingPayload, err := challenge.SigningPayload()
	if err != nil {
		return TeamApprovalChallengeRecord{}, err
	}
	record := TeamApprovalChallengeRecord{
		Challenge:      challenge,
		RecordRevision: 1,
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO team_plan_approval_challenges
		    (challenge_id, approval_id, agent_instance_id, owner_id,
		     plan_id, plan_revision, plan_digest, snapshot_id, snapshot_digest,
		     signer_key_id, challenge_json, signing_payload,
		     issued_at, expires_at, record_revision)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,1)
		RETURNING created_at, updated_at`,
		challengeID,
		command.ApprovalID,
		store.instanceID,
		planRecord.Plan.OwnerID,
		planID,
		int64(planRecord.Plan.Revision),
		planRecord.PlanDigest,
		snapshotID,
		planRecord.Plan.PricingSnapshotDigest,
		command.SignerKeyID,
		challengeJSON,
		signingPayload,
		challenge.IssuedAt.UTC(),
		challenge.ExpiresAt.UTC(),
	).Scan(&record.CreatedAt, &record.UpdatedAt); err != nil {
		return TeamApprovalChallengeRecord{}, fmt.Errorf(
			"insert Team approval challenge: %w",
			err,
		)
	}
	record.CreatedAt = record.CreatedAt.UTC()
	record.UpdatedAt = record.UpdatedAt.UTC()
	if err := appendTeamApprovalChallengeEvent(
		ctx,
		tx,
		caller,
		record,
	); err != nil {
		return TeamApprovalChallengeRecord{}, err
	}
	if err := setScopedIdempotencyResponse(
		ctx,
		tx,
		caller,
		createTeamApprovalChallengeOperation,
		command.IdempotencyKey,
		teamApprovalChallengeReplay{
			SchemaVersion: teamFactSnapshotSchemaV1,
			Record:        record,
		},
	); err != nil {
		return TeamApprovalChallengeRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return TeamApprovalChallengeRecord{}, fmt.Errorf(
			"commit create Team approval challenge: %w",
			err,
		)
	}
	return record, nil
}

func (store *Store) ApproveTeamPlan(
	ctx context.Context,
	scope task.MutationScope,
	command ApproveTeamPlanCommand,
) (TeamPlanRecord, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return TeamPlanRecord{}, err
	}
	if err := command.validate(); err != nil {
		return TeamPlanRecord{}, err
	}
	requestDigest, err := command.digest()
	if err != nil {
		return TeamPlanRecord{}, err
	}
	signature := command.Signature
	approvalID, _ := uuid.Parse(signature.ApprovalID)
	challengeID, _ := uuid.Parse(signature.ChallengeID)
	planID, _ := uuid.Parse(signature.PlanID)

	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return TeamPlanRecord{}, fmt.Errorf("begin approve Team Plan: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, response, err := claimScopedIdempotency(
		ctx,
		tx,
		caller,
		approveTeamPlanOperation,
		command.IdempotencyKey,
		requestDigest[:],
		approvalID,
	)
	if err != nil {
		return TeamPlanRecord{}, err
	}
	if existing {
		replay, err := decodeApproveTeamPlanReplay(response)
		if err != nil {
			return TeamPlanRecord{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return TeamPlanRecord{}, fmt.Errorf(
				"commit Team Plan approval replay: %w",
				err,
			)
		}
		return replay.Plan, nil
	}

	challengeRecord, err := readTeamApprovalChallenge(
		ctx,
		tx,
		store.instanceID,
		challengeID,
		true,
	)
	if err != nil {
		return TeamPlanRecord{}, err
	}
	if challengeRecord.Challenge.OwnerID != command.OwnerID {
		return TeamPlanRecord{}, ErrTeamFactScope
	}
	if challengeRecord.ConsumedAt != nil {
		return TeamPlanRecord{}, ErrTeamChallengeConsumed
	}
	if challengeRecord.RecordRevision !=
		command.ExpectedChallengeRecordRevision {
		return TeamPlanRecord{}, ErrTeamFactRevision
	}
	if challengeRecord.Challenge.ApprovalID != signature.ApprovalID ||
		challengeRecord.Challenge.PlanID != signature.PlanID ||
		challengeRecord.Challenge.PlanRevision != signature.PlanRevision {
		return TeamPlanRecord{}, ErrTeamFactScope
	}
	planRecord, err := readTeamPlan(
		ctx,
		tx,
		store.instanceID,
		planID,
		signature.PlanRevision,
		true,
	)
	if err != nil {
		return TeamPlanRecord{}, err
	}
	if planRecord.Plan.OwnerID != command.OwnerID {
		return TeamPlanRecord{}, ErrTeamFactScope
	}
	if planRecord.RecordRevision != command.ExpectedPlanRecordRevision ||
		planRecord.Status != TeamPlanReadyForConfirmation {
		return TeamPlanRecord{}, ErrTeamFactRevision
	}
	var approvedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(
		&approvedAt,
	); err != nil {
		return TeamPlanRecord{}, fmt.Errorf("read Team Plan approval time: %w", err)
	}
	approvedAt = approvedAt.UTC()
	snapshotID, _ := uuid.Parse(planRecord.Plan.PricingSnapshotID)
	snapshotRecord, err := readTeamOfferSnapshot(
		ctx,
		tx,
		store.instanceID,
		snapshotID,
		true,
	)
	if err != nil {
		return TeamPlanRecord{}, err
	}
	snapshot, err := snapshotRecord.Snapshot()
	if err != nil {
		return TeamPlanRecord{}, err
	}
	if snapshotRecord.OwnerID != planRecord.Plan.OwnerID {
		return TeamPlanRecord{}, ErrTeamFactScope
	}
	if err := snapshot.VerifyPlanPricing(planRecord.Plan, approvedAt); err != nil {
		return TeamPlanRecord{}, err
	}
	if err := verifyTeamConnectionScope(
		ctx,
		tx,
		store.instanceID,
		planRecord.Plan.OwnerID,
		planRecord.Plan.ProviderScope,
		planRecord.Plan.Region,
	); err != nil {
		return TeamPlanRecord{}, err
	}
	deviceRecord, err := readApprovalDevice(
		ctx,
		tx,
		signature.SignerKeyID,
		true,
	)
	if err != nil {
		return TeamPlanRecord{}, ErrTeamFactScope
	}
	if err := validateTeamApprovalDevice(
		deviceRecord.Device,
		store.instanceID.String(),
		planRecord.Plan.OwnerID,
		signature.SignerKeyID,
		approvedAt,
	); err != nil {
		return TeamPlanRecord{}, err
	}
	if challengeRecord.Challenge.AgentInstanceID !=
		store.instanceID.String() ||
		challengeRecord.Challenge.OwnerID != planRecord.Plan.OwnerID ||
		challengeRecord.Challenge.PlanDigest != planRecord.PlanDigest {
		return TeamPlanRecord{}, ErrTeamFactScope
	}
	if err := teamapproval.Verify(
		challengeRecord.Challenge,
		signature,
		planRecord.Plan,
		deviceRecord.Device.PublicKey,
		approvedAt,
	); err != nil {
		return TeamPlanRecord{}, err
	}
	signingPayload, err := challengeRecord.Challenge.SigningPayload()
	if err != nil {
		return TeamPlanRecord{}, err
	}
	decodedSignature, _ := base64.RawURLEncoding.DecodeString(
		signature.SignatureBase64URL,
	)
	signatureJSON, err := json.Marshal(signature)
	if err != nil {
		return TeamPlanRecord{}, ErrTeamFactInvalid
	}
	approvalRecord := TeamApprovalRecord{
		Signature:  signature,
		ApprovedAt: approvedAt,
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO team_plan_approvals
		    (approval_id, challenge_id, agent_instance_id, owner_id,
		     plan_id, plan_revision, plan_digest, snapshot_id, snapshot_digest,
		     signer_key_id, signature_json, signing_payload, signature, approved_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		RETURNING created_at`,
		approvalID,
		challengeID,
		store.instanceID,
		planRecord.Plan.OwnerID,
		planID,
		int64(planRecord.Plan.Revision),
		planRecord.PlanDigest,
		snapshotID,
		planRecord.Plan.PricingSnapshotDigest,
		signature.SignerKeyID,
		signatureJSON,
		signingPayload,
		decodedSignature,
		approvedAt,
	).Scan(&approvalRecord.CreatedAt); err != nil {
		return TeamPlanRecord{}, fmt.Errorf("insert Team Plan approval: %w", err)
	}
	approvalRecord.CreatedAt = approvalRecord.CreatedAt.UTC()

	if challengeRecord.RecordRevision >= uint64(math.MaxInt64) {
		return TeamPlanRecord{}, ErrTeamFactRevision
	}
	previousChallengeRevision := challengeRecord.RecordRevision
	challengeRecord.RecordRevision++
	challengeRecord.ConsumedAt = &approvedAt
	if err := tx.QueryRow(ctx, `
		UPDATE team_plan_approval_challenges
		SET consumed_at=$2,
		    record_revision=record_revision+1,
		    updated_at=clock_timestamp()
		WHERE challenge_id=$1
		  AND record_revision=$3
		  AND consumed_at IS NULL
		RETURNING updated_at`,
		challengeID,
		approvedAt,
		int64(previousChallengeRevision),
	).Scan(&challengeRecord.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TeamPlanRecord{}, ErrTeamFactRevision
		}
		return TeamPlanRecord{}, fmt.Errorf(
			"consume Team approval challenge: %w",
			err,
		)
	}
	challengeRecord.UpdatedAt = challengeRecord.UpdatedAt.UTC()
	if err := appendTeamApprovalChallengeEvent(
		ctx,
		tx,
		caller,
		challengeRecord,
	); err != nil {
		return TeamPlanRecord{}, err
	}
	if planRecord.RecordRevision >= uint64(math.MaxInt64) {
		return TeamPlanRecord{}, ErrTeamFactRevision
	}
	previousPlanRecordRevision := planRecord.RecordRevision
	planRecord.RecordRevision++
	planRecord.Status = TeamPlanApproved
	if err := tx.QueryRow(ctx, `
		UPDATE team_plans
		SET status='approved',
		    record_revision=record_revision+1,
		    updated_at=clock_timestamp()
		WHERE plan_id=$1
		  AND plan_revision=$2
		  AND record_revision=$3
		  AND status='ready_for_confirmation'
		RETURNING updated_at`,
		planID,
		int64(planRecord.Plan.Revision),
		int64(previousPlanRecordRevision),
	).Scan(&planRecord.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TeamPlanRecord{}, ErrTeamFactRevision
		}
		return TeamPlanRecord{}, fmt.Errorf(
			"transition approved Team Plan: %w",
			err,
		)
	}
	planRecord.UpdatedAt = planRecord.UpdatedAt.UTC()
	if err := appendTeamPlanEvent(ctx, tx, caller, planRecord); err != nil {
		return TeamPlanRecord{}, err
	}
	if err := appendTeamApprovalEvent(
		ctx,
		tx,
		caller,
		planRecord,
		approvalRecord,
	); err != nil {
		return TeamPlanRecord{}, err
	}
	replay := approveTeamPlanReplay{
		SchemaVersion: teamFactSnapshotSchemaV1,
		Plan:          planRecord,
		Challenge:     challengeRecord,
		Approval:      approvalRecord,
	}
	if err := setScopedIdempotencyResponse(
		ctx,
		tx,
		caller,
		approveTeamPlanOperation,
		command.IdempotencyKey,
		replay,
	); err != nil {
		return TeamPlanRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return TeamPlanRecord{}, fmt.Errorf("commit approve Team Plan: %w", err)
	}
	return planRecord, nil
}

func (store *Store) GetTeamApprovalChallenge(
	ctx context.Context,
	ownerID,
	challengeID string,
) (TeamApprovalChallengeRecord, error) {
	parsed, err := uuid.Parse(challengeID)
	if err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != challengeID ||
		ownerID != strings.TrimSpace(ownerID) ||
		ownerID == "" {
		return TeamApprovalChallengeRecord{}, ErrTeamFactInvalid
	}
	record, err := readTeamApprovalChallenge(
		ctx,
		store.pool,
		store.instanceID,
		parsed,
		false,
	)
	if err != nil {
		return TeamApprovalChallengeRecord{}, err
	}
	if record.Challenge.OwnerID != ownerID ||
		record.Challenge.AgentInstanceID != store.instanceID.String() {
		return TeamApprovalChallengeRecord{}, ErrTeamFactScope
	}
	return record, nil
}

func (store *Store) GetTeamApproval(
	ctx context.Context,
	ownerID,
	approvalID string,
) (TeamApprovalRecord, error) {
	parsed, err := uuid.Parse(approvalID)
	if err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != approvalID ||
		ownerID != strings.TrimSpace(ownerID) ||
		ownerID == "" {
		return TeamApprovalRecord{}, ErrTeamFactInvalid
	}
	return store.getTeamApproval(ctx, ownerID, parsed)
}

func (store *Store) GetTeamApprovalForPlan(
	ctx context.Context,
	ownerID,
	planID string,
	planRevision uint64,
) (TeamApprovalRecord, error) {
	parsedPlanID, err := uuid.Parse(planID)
	if err != nil ||
		parsedPlanID == uuid.Nil ||
		parsedPlanID.String() != planID ||
		ownerID != strings.TrimSpace(ownerID) ||
		ownerID == "" ||
		planRevision == 0 ||
		planRevision > uint64(math.MaxInt64) {
		return TeamApprovalRecord{}, ErrTeamFactInvalid
	}
	var approvalID uuid.UUID
	if err := store.pool.QueryRow(ctx, `
		SELECT approval_id
		FROM team_plan_approvals
		WHERE agent_instance_id=$1
		  AND owner_id=$2
		  AND plan_id=$3
		  AND plan_revision=$4`,
		store.instanceID,
		ownerID,
		parsedPlanID,
		int64(planRevision),
	).Scan(&approvalID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TeamApprovalRecord{}, ErrTeamFactNotFound
		}
		return TeamApprovalRecord{}, fmt.Errorf(
			"read Team Plan approval binding: %w",
			err,
		)
	}
	record, err := store.getTeamApproval(ctx, ownerID, approvalID)
	if err != nil {
		return TeamApprovalRecord{}, err
	}
	if record.Signature.PlanID != planID ||
		record.Signature.PlanRevision != planRevision {
		return TeamApprovalRecord{}, ErrTeamFactCorrupt
	}
	return record, nil
}

func (store *Store) getTeamApproval(
	ctx context.Context,
	ownerID string,
	approvalID uuid.UUID,
) (TeamApprovalRecord, error) {
	record, binding, err := readTeamApproval(
		ctx,
		store.pool,
		store.instanceID,
		approvalID,
	)
	if err != nil {
		return TeamApprovalRecord{}, err
	}
	challenge, err := readTeamApprovalChallenge(
		ctx,
		store.pool,
		store.instanceID,
		binding.challengeID,
		false,
	)
	if err != nil {
		return TeamApprovalRecord{}, err
	}
	plan, err := readTeamPlan(
		ctx,
		store.pool,
		store.instanceID,
		binding.planID,
		binding.planRevision,
		false,
	)
	if err != nil {
		return TeamApprovalRecord{}, err
	}
	snapshotRecord, err := readTeamOfferSnapshot(
		ctx,
		store.pool,
		store.instanceID,
		binding.snapshotID,
		false,
	)
	if err != nil {
		return TeamApprovalRecord{}, err
	}
	snapshot, err := snapshotRecord.Snapshot()
	if err != nil {
		return TeamApprovalRecord{}, err
	}
	device, err := readApprovalDevice(
		ctx,
		store.pool,
		record.Signature.SignerKeyID,
		false,
	)
	if err != nil ||
		challenge.ConsumedAt == nil ||
		!challenge.ConsumedAt.Equal(record.ApprovedAt) ||
		binding.agentID != store.instanceID ||
		binding.ownerID != ownerID ||
		binding.planDigest != plan.PlanDigest ||
		binding.snapshotID.String() != plan.Plan.PricingSnapshotID ||
		binding.snapshotDigest != plan.Plan.PricingSnapshotDigest ||
		snapshotRecord.OwnerID != ownerID ||
		snapshot.VerifyPlanPricing(plan.Plan, plan.Plan.QuotedAt) != nil ||
		challenge.Challenge.ApprovalID != record.Signature.ApprovalID ||
		challenge.Challenge.ChallengeID != binding.challengeID.String() ||
		challenge.Challenge.PlanID != binding.planID.String() ||
		challenge.Challenge.PlanRevision != binding.planRevision ||
		challenge.Challenge.PlanDigest != binding.planDigest ||
		challenge.Challenge.PricingSnapshotID != binding.snapshotID.String() ||
		challenge.Challenge.PricingSnapshotDigest != binding.snapshotDigest ||
		device.Device.AgentInstanceID != store.instanceID.String() ||
		device.Device.OwnerID != ownerID ||
		device.Device.KeyID != record.Signature.SignerKeyID ||
		plan.Plan.OwnerID != ownerID ||
		challenge.Challenge.OwnerID != ownerID ||
		!bytes.Equal(
			binding.signingPayload,
			teamChallengePayload(challenge.Challenge),
		) ||
		teamapproval.Verify(
			challenge.Challenge,
			record.Signature,
			plan.Plan,
			device.Device.PublicKey,
			record.ApprovedAt,
		) != nil {
		return TeamApprovalRecord{}, ErrTeamFactCorrupt
	}
	return record, nil
}

type teamApprovalQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type teamApprovalBinding struct {
	challengeID    uuid.UUID
	agentID        uuid.UUID
	ownerID        string
	planID         uuid.UUID
	planRevision   uint64
	planDigest     string
	snapshotID     uuid.UUID
	snapshotDigest string
	signingPayload []byte
}

func readTeamApprovalChallenge(
	ctx context.Context,
	query teamApprovalQuerier,
	instanceID uuid.UUID,
	challengeID uuid.UUID,
	lock bool,
) (TeamApprovalChallengeRecord, error) {
	statement := `
		SELECT approval_id, agent_instance_id, owner_id,
		       plan_id, plan_revision, plan_digest,
		       snapshot_id, snapshot_digest, signer_key_id,
		       challenge_json, signing_payload,
		       issued_at, expires_at, consumed_at, record_revision,
		       created_at, updated_at
		FROM team_plan_approval_challenges
		WHERE challenge_id=$1 AND agent_instance_id=$2`
	if lock {
		statement += " FOR UPDATE"
	}
	var (
		approvalID, agentID, planID, snapshotID uuid.UUID
		ownerID, planDigest, snapshotDigest     string
		signerKeyID                             string
		challengeJSON, signingPayload           []byte
		issuedAt, expiresAt                     time.Time
		consumedAt                              *time.Time
		planRevision, recordRevision            int64
		record                                  TeamApprovalChallengeRecord
	)
	if err := query.QueryRow(
		ctx,
		statement,
		challengeID,
		instanceID,
	).Scan(
		&approvalID,
		&agentID,
		&ownerID,
		&planID,
		&planRevision,
		&planDigest,
		&snapshotID,
		&snapshotDigest,
		&signerKeyID,
		&challengeJSON,
		&signingPayload,
		&issuedAt,
		&expiresAt,
		&consumedAt,
		&recordRevision,
		&record.CreatedAt,
		&record.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TeamApprovalChallengeRecord{}, ErrTeamFactNotFound
		}
		return TeamApprovalChallengeRecord{}, fmt.Errorf(
			"read Team approval challenge: %w",
			err,
		)
	}
	if planRevision <= 0 ||
		recordRevision <= 0 ||
		json.Unmarshal(challengeJSON, &record.Challenge) != nil ||
		record.Challenge.Validate() != nil {
		return TeamApprovalChallengeRecord{}, ErrTeamFactCorrupt
	}
	record.RecordRevision = uint64(recordRevision)
	record.CreatedAt = record.CreatedAt.UTC()
	record.UpdatedAt = record.UpdatedAt.UTC()
	if consumedAt != nil {
		value := consumedAt.UTC()
		record.ConsumedAt = &value
	}
	actualPayload, err := record.Challenge.SigningPayload()
	if err != nil ||
		!bytes.Equal(actualPayload, signingPayload) ||
		record.Challenge.ApprovalID != approvalID.String() ||
		record.Challenge.ChallengeID != challengeID.String() ||
		agentID != instanceID ||
		record.Challenge.AgentInstanceID != instanceID.String() ||
		record.Challenge.OwnerID != ownerID ||
		record.Challenge.PlanID != planID.String() ||
		record.Challenge.PlanRevision != uint64(planRevision) ||
		record.Challenge.PlanDigest != planDigest ||
		record.Challenge.PricingSnapshotID != snapshotID.String() ||
		record.Challenge.PricingSnapshotDigest != snapshotDigest ||
		record.Challenge.SignerKeyID != signerKeyID ||
		!record.Challenge.IssuedAt.Equal(issuedAt.UTC()) ||
		!record.Challenge.ExpiresAt.Equal(expiresAt.UTC()) ||
		record.ConsumedAt != nil &&
			(record.ConsumedAt.Before(record.Challenge.IssuedAt) ||
				!record.ConsumedAt.Before(record.Challenge.ExpiresAt)) {
		return TeamApprovalChallengeRecord{}, ErrTeamFactCorrupt
	}
	return record, nil
}

func readTeamApproval(
	ctx context.Context,
	query teamApprovalQuerier,
	instanceID uuid.UUID,
	approvalID uuid.UUID,
) (
	TeamApprovalRecord,
	teamApprovalBinding,
	error,
) {
	var (
		challengeID, agentID, planID, snapshotID    uuid.UUID
		ownerID, planDigest, snapshotDigest         string
		signerKeyID                                 string
		signatureJSON, signingPayload, rawSignature []byte
		planRevision                                int64
		record                                      TeamApprovalRecord
		binding                                     teamApprovalBinding
	)
	if err := query.QueryRow(ctx, `
		SELECT challenge_id, agent_instance_id, owner_id,
		       plan_id, plan_revision, plan_digest,
		       snapshot_id, snapshot_digest, signer_key_id,
		       signature_json, signing_payload, signature,
		       approved_at, created_at
		FROM team_plan_approvals
		WHERE approval_id=$1 AND agent_instance_id=$2`,
		approvalID,
		instanceID,
	).Scan(
		&challengeID,
		&agentID,
		&ownerID,
		&planID,
		&planRevision,
		&planDigest,
		&snapshotID,
		&snapshotDigest,
		&signerKeyID,
		&signatureJSON,
		&signingPayload,
		&rawSignature,
		&record.ApprovedAt,
		&record.CreatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TeamApprovalRecord{}, teamApprovalBinding{},
				ErrTeamFactNotFound
		}
		return TeamApprovalRecord{}, teamApprovalBinding{}, fmt.Errorf(
			"read Team Plan approval: %w",
			err,
		)
	}
	if planRevision <= 0 ||
		json.Unmarshal(signatureJSON, &record.Signature) != nil {
		return TeamApprovalRecord{}, teamApprovalBinding{},
			ErrTeamFactCorrupt
	}
	decoded, err := base64.RawURLEncoding.DecodeString(
		record.Signature.SignatureBase64URL,
	)
	if err != nil ||
		len(rawSignature) != ed25519.SignatureSize ||
		!bytes.Equal(decoded, rawSignature) ||
		record.Signature.ApprovalID != approvalID.String() ||
		record.Signature.ChallengeID != challengeID.String() ||
		record.Signature.PlanID != planID.String() ||
		record.Signature.PlanRevision != uint64(planRevision) ||
		record.Signature.PlanDigest != planDigest ||
		record.Signature.SignerKeyID != signerKeyID ||
		agentID != instanceID ||
		ownerID == "" ||
		snapshotID == uuid.Nil ||
		!teamDigestPattern.MatchString(snapshotDigest) ||
		len(signingPayload) == 0 {
		return TeamApprovalRecord{}, teamApprovalBinding{},
			ErrTeamFactCorrupt
	}
	record.ApprovedAt = record.ApprovedAt.UTC()
	record.CreatedAt = record.CreatedAt.UTC()
	binding = teamApprovalBinding{
		challengeID:    challengeID,
		agentID:        agentID,
		ownerID:        ownerID,
		planID:         planID,
		planRevision:   uint64(planRevision),
		planDigest:     planDigest,
		snapshotID:     snapshotID,
		snapshotDigest: snapshotDigest,
		signingPayload: append([]byte(nil), signingPayload...),
	}
	return record, binding, nil
}

func teamChallengePayload(challenge teamapproval.ChallengeV1) []byte {
	payload, err := challenge.SigningPayload()
	if err != nil {
		return nil
	}
	return payload
}

func decodeTeamApprovalChallengeReplay(
	encoded []byte,
) (TeamApprovalChallengeRecord, error) {
	var replay teamApprovalChallengeReplay
	if json.Unmarshal(encoded, &replay) != nil ||
		replay.SchemaVersion != teamFactSnapshotSchemaV1 ||
		replay.Record.RecordRevision == 0 ||
		replay.Record.Challenge.Validate() != nil {
		return TeamApprovalChallengeRecord{}, ErrTeamFactCorrupt
	}
	replay.Record.CreatedAt = replay.Record.CreatedAt.UTC()
	replay.Record.UpdatedAt = replay.Record.UpdatedAt.UTC()
	if replay.Record.ConsumedAt != nil {
		value := replay.Record.ConsumedAt.UTC()
		replay.Record.ConsumedAt = &value
	}
	return replay.Record, nil
}

func decodeApproveTeamPlanReplay(
	encoded []byte,
) (approveTeamPlanReplay, error) {
	var replay approveTeamPlanReplay
	if json.Unmarshal(encoded, &replay) != nil ||
		replay.SchemaVersion != teamFactSnapshotSchemaV1 ||
		replay.Plan.Status != TeamPlanApproved ||
		replay.Challenge.ConsumedAt == nil ||
		replay.Approval.Signature.ApprovalID !=
			replay.Challenge.Challenge.ApprovalID {
		return approveTeamPlanReplay{}, ErrTeamFactCorrupt
	}
	planDigest, err := replay.Plan.Plan.Digest()
	if err != nil || planDigest != replay.Plan.PlanDigest {
		return approveTeamPlanReplay{}, ErrTeamFactCorrupt
	}
	replay.Plan.CreatedAt = replay.Plan.CreatedAt.UTC()
	replay.Plan.UpdatedAt = replay.Plan.UpdatedAt.UTC()
	replay.Challenge.CreatedAt = replay.Challenge.CreatedAt.UTC()
	replay.Challenge.UpdatedAt = replay.Challenge.UpdatedAt.UTC()
	value := replay.Challenge.ConsumedAt.UTC()
	replay.Challenge.ConsumedAt = &value
	replay.Approval.ApprovedAt = replay.Approval.ApprovedAt.UTC()
	replay.Approval.CreatedAt = replay.Approval.CreatedAt.UTC()
	return replay, nil
}

func appendTeamApprovalChallengeEvent(
	ctx context.Context,
	tx pgx.Tx,
	caller idempotencyCaller,
	record TeamApprovalChallengeRecord,
) error {
	challengeID, err := uuid.Parse(record.Challenge.ChallengeID)
	if err != nil {
		return ErrTeamFactInvalid
	}
	summary := struct {
		SchemaVersion  int             `json:"schema_version"`
		ChallengeID    string          `json:"challenge_id"`
		ApprovalID     string          `json:"approval_id"`
		OwnerID        string          `json:"owner_id"`
		PlanID         string          `json:"plan_id"`
		PlanRevision   uint64          `json:"plan_revision"`
		SignerKeyID    string          `json:"signer_key_id"`
		ExpiresAt      time.Time       `json:"expires_at"`
		Consumed       bool            `json:"consumed"`
		RecordRevision uint64          `json:"record_revision"`
		Actor          cloudEventActor `json:"actor"`
	}{
		SchemaVersion:  teamFactSnapshotSchemaV1,
		ChallengeID:    record.Challenge.ChallengeID,
		ApprovalID:     record.Challenge.ApprovalID,
		OwnerID:        record.Challenge.OwnerID,
		PlanID:         record.Challenge.PlanID,
		PlanRevision:   record.Challenge.PlanRevision,
		SignerKeyID:    record.Challenge.SignerKeyID,
		ExpiresAt:      record.Challenge.ExpiresAt.UTC(),
		Consumed:       record.ConsumedAt != nil,
		RecordRevision: record.RecordRevision,
		Actor:          newCloudEventActor(caller),
	}
	return appendCloudFactEvent(
		ctx,
		tx,
		challengeID,
		"team_plan_approval_challenge",
		"team.approval_challenge.changed",
		record.RecordRevision,
		summary,
	)
}

func appendTeamApprovalEvent(
	ctx context.Context,
	tx pgx.Tx,
	caller idempotencyCaller,
	plan TeamPlanRecord,
	approval TeamApprovalRecord,
) error {
	approvalID, err := uuid.Parse(approval.Signature.ApprovalID)
	if err != nil {
		return ErrTeamFactInvalid
	}
	summary := struct {
		SchemaVersion int             `json:"schema_version"`
		ApprovalID    string          `json:"approval_id"`
		ChallengeID   string          `json:"challenge_id"`
		OwnerID       string          `json:"owner_id"`
		PlanID        string          `json:"plan_id"`
		PlanRevision  uint64          `json:"plan_revision"`
		PlanDigest    string          `json:"plan_digest"`
		SignerKeyID   string          `json:"signer_key_id"`
		ApprovedAt    time.Time       `json:"approved_at"`
		Actor         cloudEventActor `json:"actor"`
	}{
		SchemaVersion: teamFactSnapshotSchemaV1,
		ApprovalID:    approval.Signature.ApprovalID,
		ChallengeID:   approval.Signature.ChallengeID,
		OwnerID:       plan.Plan.OwnerID,
		PlanID:        plan.Plan.PlanID,
		PlanRevision:  plan.Plan.Revision,
		PlanDigest:    plan.PlanDigest,
		SignerKeyID:   approval.Signature.SignerKeyID,
		ApprovedAt:    approval.ApprovedAt.UTC(),
		Actor:         newCloudEventActor(caller),
	}
	return appendCloudFactEvent(
		ctx,
		tx,
		approvalID,
		"team_plan_approval",
		"team.plan.approved",
		1,
		summary,
	)
}
