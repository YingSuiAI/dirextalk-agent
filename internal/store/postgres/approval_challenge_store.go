package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	createApprovalChallengeOperation  = "cloud.approval_challenge.create"
	consumeApprovalChallengeOperation = "cloud.approval_challenge.consume"
)

var challengeIDPattern = regexp.MustCompile(`^challenge_[A-Za-z0-9_-]{43}$`)

type approvalChallengeSnapshot struct {
	SchemaVersion int                     `json:"schema_version"`
	Record        ApprovalChallengeRecord `json:"record"`
}

func (store *Store) CreateApprovalChallenge(ctx context.Context, scope task.MutationScope, command CreateApprovalChallengeCommand) (cloudapproval.ChallengeV1, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	if err := command.validate(); err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	requestDigest, err := command.digest()
	if err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	agentID, _ := uuid.Parse(command.Challenge.AgentInstanceID)
	if agentID != store.instanceID {
		return cloudapproval.ChallengeV1{}, ErrCloudFactScope
	}
	challengeRowID := approvalChallengeID(store.instanceID, command.Challenge.ChallengeID)
	planID, _ := uuid.Parse(command.Challenge.PlanID)
	quoteID, _ := uuid.Parse(command.Challenge.QuoteID)
	deviceID := approvalDeviceID(store.instanceID, command.Challenge.SignerKeyID)

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return cloudapproval.ChallengeV1{}, fmt.Errorf("begin create approval challenge: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, response, err := claimScopedIdempotency(ctx, tx, caller, createApprovalChallengeOperation, command.IdempotencyKey, requestDigest[:], challengeRowID)
	if err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	if existing {
		record, err := decodeApprovalChallengeSnapshot(response)
		if err != nil {
			return cloudapproval.ChallengeV1{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return cloudapproval.ChallengeV1{}, fmt.Errorf("commit challenge replay: %w", err)
		}
		return record.Challenge, nil
	}
	planRecord, err := readCloudPlan(ctx, tx, planID, true)
	if err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	quoteRecord, err := readCloudQuote(ctx, tx, quoteID, false)
	if err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	deviceRecord, err := readApprovalDevice(ctx, tx, command.Challenge.SignerKeyID, false)
	if err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return cloudapproval.ChallengeV1{}, fmt.Errorf("read challenge creation time: %w", err)
	}
	now = now.UTC()
	if err := deviceRecord.Device.ValidateAt(now); err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	if err := planRecord.Plan.ValidateQuote(quoteRecord.Quote, now); err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	if err := challengeMatchesStoredFacts(command.Challenge, planRecord, quoteRecord, deviceRecord); err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	if now.Before(command.Challenge.IssuedAt.Add(-30*time.Second)) || !now.Before(command.Challenge.ExpiresAt) || command.Challenge.ExpiresAt.After(quoteRecord.Quote.ValidUntil) {
		return cloudapproval.ChallengeV1{}, fmt.Errorf("%w: challenge is outside current quote/device validity", ErrCloudFactInvalid)
	}
	var alreadyExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM cloud_approval_challenges WHERE challenge_id=$1)`, command.Challenge.ChallengeID).Scan(&alreadyExists); err != nil {
		return cloudapproval.ChallengeV1{}, fmt.Errorf("check challenge existence: %w", err)
	}
	if alreadyExists {
		return cloudapproval.ChallengeV1{}, ErrCloudFactRevision
	}
	record := ApprovalChallengeRecord{Challenge: command.Challenge}
	if err := tx.QueryRow(ctx, `
		INSERT INTO cloud_approval_challenges
		    (challenge_row_id, challenge_id, agent_instance_id, owner_id, plan_id, plan_revision,
		     plan_hash, connection_id, recipe_digest, quote_id, quote_digest, quote_scope_digest,
		     quote_candidate_id, device_id, signer_key_id, issued_at, expires_at, consumed_at, revision)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,NULL,$18)
		RETURNING created_at, updated_at`,
		challengeRowID, command.Challenge.ChallengeID, agentID, command.Challenge.OwnerID, planID,
		int64(command.Challenge.PlanRevision), command.Challenge.PlanHash, command.Challenge.ConnectionID,
		command.Challenge.RecipeDigest, quoteID, command.Challenge.QuoteDigest,
		command.Challenge.QuoteScopeDigest, command.Challenge.QuoteCandidateID, deviceID,
		command.Challenge.SignerKeyID, command.Challenge.IssuedAt.UTC(), command.Challenge.ExpiresAt.UTC(),
		int64(command.Challenge.Revision),
	).Scan(&record.CreatedAt, &record.UpdatedAt); err != nil {
		return cloudapproval.ChallengeV1{}, fmt.Errorf("insert approval challenge: %w", err)
	}
	record.CreatedAt, record.UpdatedAt = record.CreatedAt.UTC(), record.UpdatedAt.UTC()
	if err := appendApprovalChallengeEvent(ctx, tx, caller, challengeRowID, record); err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	if err := setScopedIdempotencyResponse(ctx, tx, caller, createApprovalChallengeOperation, command.IdempotencyKey, approvalChallengeSnapshot{SchemaVersion: cloudFactSnapshotSchemaV1, Record: record}); err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return cloudapproval.ChallengeV1{}, fmt.Errorf("commit create approval challenge: %w", err)
	}
	return record.Challenge, nil
}

func (store *Store) ConsumeApprovalChallenge(ctx context.Context, scope task.MutationScope, command ConsumeApprovalChallengeCommand) (cloudapproval.ChallengeV1, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	if err := command.validate(); err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	requestDigest, err := command.digest()
	if err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	challengeRowID := approvalChallengeID(store.instanceID, command.ChallengeID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return cloudapproval.ChallengeV1{}, fmt.Errorf("begin consume approval challenge: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, response, err := claimScopedIdempotency(ctx, tx, caller, consumeApprovalChallengeOperation, command.IdempotencyKey, requestDigest[:], challengeRowID)
	if err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	if existing {
		record, err := decodeApprovalChallengeSnapshot(response)
		if err != nil {
			return cloudapproval.ChallengeV1{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return cloudapproval.ChallengeV1{}, fmt.Errorf("commit challenge consumption replay: %w", err)
		}
		return record.Challenge, nil
	}
	record, storedRowID, err := readApprovalChallenge(ctx, tx, command.ChallengeID, true)
	if err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	if storedRowID != challengeRowID || record.Challenge.AgentInstanceID != store.instanceID.String() {
		return cloudapproval.ChallengeV1{}, ErrCloudFactScope
	}
	if record.Challenge.ConsumedAt != nil {
		return cloudapproval.ChallengeV1{}, ErrCloudChallengeConsumed
	}
	if record.Challenge.Revision != command.ExpectedRevision {
		return cloudapproval.ChallengeV1{}, ErrCloudFactRevision
	}
	consumedAt := command.ConsumedAt.UTC()
	if consumedAt.Before(record.Challenge.IssuedAt) || consumedAt.After(record.Challenge.ExpiresAt) {
		return cloudapproval.ChallengeV1{}, fmt.Errorf("%w: consumed_at is outside challenge validity", ErrCloudFactInvalid)
	}
	record.Challenge.Revision++
	record.Challenge.ConsumedAt = &consumedAt
	if err := tx.QueryRow(ctx, `
		UPDATE cloud_approval_challenges
		SET consumed_at=$2, revision=$3, updated_at=clock_timestamp()
		WHERE challenge_row_id=$1 AND revision=$4 AND consumed_at IS NULL
		RETURNING updated_at`, challengeRowID, consumedAt, int64(record.Challenge.Revision), int64(command.ExpectedRevision),
	).Scan(&record.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return cloudapproval.ChallengeV1{}, ErrCloudFactRevision
		}
		return cloudapproval.ChallengeV1{}, fmt.Errorf("consume approval challenge: %w", err)
	}
	record.UpdatedAt = record.UpdatedAt.UTC()
	if err := appendApprovalChallengeEvent(ctx, tx, caller, challengeRowID, record); err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	if err := setScopedIdempotencyResponse(ctx, tx, caller, consumeApprovalChallengeOperation, command.IdempotencyKey, approvalChallengeSnapshot{SchemaVersion: cloudFactSnapshotSchemaV1, Record: record}); err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return cloudapproval.ChallengeV1{}, fmt.Errorf("commit consume approval challenge: %w", err)
	}
	return record.Challenge, nil
}

func (store *Store) GetChallenge(ctx context.Context, challengeID string) (cloudapproval.ChallengeV1, error) {
	record, _, err := readApprovalChallenge(ctx, store.pool, challengeID, false)
	if err != nil {
		return cloudapproval.ChallengeV1{}, err
	}
	if record.Challenge.AgentInstanceID != store.instanceID.String() {
		return cloudapproval.ChallengeV1{}, ErrCloudFactScope
	}
	return record.Challenge, nil
}

type approvalChallengeQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readApprovalChallenge(ctx context.Context, query approvalChallengeQuerier, challengeID string, lock bool) (ApprovalChallengeRecord, uuid.UUID, error) {
	statement := `
		SELECT challenge_row_id, agent_instance_id, owner_id, plan_id, plan_revision, plan_hash,
		       connection_id, recipe_digest, quote_id, quote_digest, quote_scope_digest,
		       quote_candidate_id, signer_key_id, issued_at, expires_at, consumed_at,
		       revision, created_at, updated_at
		FROM cloud_approval_challenges WHERE challenge_id=$1`
	if lock {
		statement += " FOR UPDATE"
	}
	var (
		rowID, agentID, planID, quoteID uuid.UUID
		planRevision, revision          int64
		consumedAt                      *time.Time
		record                          ApprovalChallengeRecord
	)
	if err := query.QueryRow(ctx, statement, challengeID).Scan(
		&rowID, &agentID, &record.Challenge.OwnerID, &planID, &planRevision, &record.Challenge.PlanHash,
		&record.Challenge.ConnectionID, &record.Challenge.RecipeDigest, &quoteID,
		&record.Challenge.QuoteDigest, &record.Challenge.QuoteScopeDigest,
		&record.Challenge.QuoteCandidateID, &record.Challenge.SignerKeyID,
		&record.Challenge.IssuedAt, &record.Challenge.ExpiresAt, &consumedAt,
		&revision, &record.CreatedAt, &record.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ApprovalChallengeRecord{}, uuid.Nil, cloudapproval.ErrChallengeNotFound
		}
		return ApprovalChallengeRecord{}, uuid.Nil, fmt.Errorf("read approval challenge: %w", err)
	}
	record.Challenge.ChallengeID = challengeID
	record.Challenge.AgentInstanceID = agentID.String()
	record.Challenge.PlanID = planID.String()
	record.Challenge.PlanRevision = uint64(planRevision)
	record.Challenge.QuoteID = quoteID.String()
	record.Challenge.Revision = uint64(revision)
	record.Challenge.IssuedAt, record.Challenge.ExpiresAt = record.Challenge.IssuedAt.UTC(), record.Challenge.ExpiresAt.UTC()
	if consumedAt != nil {
		value := consumedAt.UTC()
		record.Challenge.ConsumedAt = &value
	}
	record.CreatedAt, record.UpdatedAt = record.CreatedAt.UTC(), record.UpdatedAt.UTC()
	if err := validateChallengeForStorage(record.Challenge); err != nil || rowID != approvalChallengeID(agentID, challengeID) {
		return ApprovalChallengeRecord{}, uuid.Nil, ErrCloudFactCorrupt
	}
	return record, rowID, nil
}

func validateChallengeForStorage(value cloudapproval.ChallengeV1) error {
	if !challengeIDPattern.MatchString(value.ChallengeID) || value.Revision == 0 || value.PlanRevision == 0 ||
		strings.TrimSpace(value.OwnerID) == "" || len(value.OwnerID) > 255 || strings.TrimSpace(value.ConnectionID) == "" || len(value.ConnectionID) > 128 ||
		strings.TrimSpace(value.SignerKeyID) == "" || len(value.SignerKeyID) > 128 {
		return fmt.Errorf("%w: challenge identifiers or revisions are invalid", ErrCloudFactInvalid)
	}
	for _, identifier := range []string{value.AgentInstanceID, value.PlanID, value.QuoteID} {
		if _, err := uuid.Parse(identifier); err != nil {
			return fmt.Errorf("%w: challenge cloud identifiers must be UUIDs", ErrCloudFactInvalid)
		}
	}
	for _, digest := range []string{value.PlanHash, value.RecipeDigest, value.QuoteDigest, value.QuoteScopeDigest} {
		if err := recipe.ValidateDigest(digest); err != nil {
			return fmt.Errorf("%w: challenge digest is invalid", ErrCloudFactInvalid)
		}
	}
	if value.QuoteCandidateID != string(cloudquote.CandidateEconomic) && value.QuoteCandidateID != string(cloudquote.CandidateRecommended) && value.QuoteCandidateID != string(cloudquote.CandidatePerformance) {
		return fmt.Errorf("%w: challenge quote candidate is invalid", ErrCloudFactInvalid)
	}
	if value.IssuedAt.IsZero() || value.ExpiresAt.IsZero() || !value.IssuedAt.Before(value.ExpiresAt) || value.ExpiresAt.Sub(value.IssuedAt) > cloudapproval.ChallengeValidity {
		return fmt.Errorf("%w: challenge validity is invalid", ErrCloudFactInvalid)
	}
	if value.ConsumedAt != nil && (value.ConsumedAt.Before(value.IssuedAt) || value.ConsumedAt.After(value.ExpiresAt)) {
		return fmt.Errorf("%w: challenge consumed_at is invalid", ErrCloudFactInvalid)
	}
	return nil
}

func challengeMatchesStoredFacts(challenge cloudapproval.ChallengeV1, plan CloudPlanRecord, quoted CloudQuoteRecord, device ApprovalDeviceRecord) error {
	if challenge.AgentInstanceID != plan.Plan.AgentInstanceID || challenge.OwnerID != plan.Plan.OwnerID ||
		challenge.PlanID != plan.Plan.PlanID || challenge.PlanRevision != plan.Plan.Revision || challenge.PlanHash != plan.PlanHash ||
		challenge.ConnectionID != plan.Plan.ConnectionID || challenge.RecipeDigest != plan.Plan.Recipe.Digest ||
		challenge.QuoteID != quoted.Quote.QuoteID || challenge.QuoteID != plan.Plan.Quote.QuoteID ||
		challenge.QuoteDigest != quoted.Digest || challenge.QuoteDigest != plan.Plan.Quote.Digest ||
		challenge.QuoteScopeDigest != plan.Plan.Quote.ScopeDigest || challenge.QuoteCandidateID != plan.Plan.Quote.CandidateID ||
		challenge.SignerKeyID != device.Device.KeyID || challenge.OwnerID != device.Device.OwnerID || challenge.AgentInstanceID != device.Device.AgentInstanceID ||
		plan.Plan.Status != cloudapproval.PlanReadyForConfirmation {
		return fmt.Errorf("%w: challenge does not bind current Plan, Quote, and device", ErrCloudFactScope)
	}
	return nil
}

func approvalChallengeID(instanceID uuid.UUID, challengeID string) uuid.UUID {
	return uuid.NewSHA1(instanceID, []byte("approval-challenge:"+challengeID))
}

func decodeApprovalChallengeSnapshot(encoded []byte) (ApprovalChallengeRecord, error) {
	var snapshot approvalChallengeSnapshot
	if err := json.Unmarshal(encoded, &snapshot); err != nil || snapshot.SchemaVersion != cloudFactSnapshotSchemaV1 {
		return ApprovalChallengeRecord{}, ErrCloudFactCorrupt
	}
	if err := validateChallengeForStorage(snapshot.Record.Challenge); err != nil {
		return ApprovalChallengeRecord{}, ErrCloudFactCorrupt
	}
	snapshot.Record.CreatedAt, snapshot.Record.UpdatedAt = snapshot.Record.CreatedAt.UTC(), snapshot.Record.UpdatedAt.UTC()
	return snapshot.Record, nil
}

func appendApprovalChallengeEvent(ctx context.Context, tx pgx.Tx, caller idempotencyCaller, rowID uuid.UUID, record ApprovalChallengeRecord) error {
	summary := struct {
		ChallengeID  string          `json:"challenge_id"`
		OwnerID      string          `json:"owner_id"`
		PlanID       string          `json:"plan_id"`
		PlanRevision uint64          `json:"plan_revision"`
		SignerKeyID  string          `json:"signer_key_id"`
		ExpiresAt    time.Time       `json:"expires_at"`
		Consumed     bool            `json:"consumed"`
		Revision     uint64          `json:"revision"`
		Actor        cloudEventActor `json:"actor"`
	}{
		ChallengeID: record.Challenge.ChallengeID, OwnerID: record.Challenge.OwnerID,
		PlanID: record.Challenge.PlanID, PlanRevision: record.Challenge.PlanRevision,
		SignerKeyID: record.Challenge.SignerKeyID, ExpiresAt: record.Challenge.ExpiresAt.UTC(),
		Consumed: record.Challenge.ConsumedAt != nil, Revision: record.Challenge.Revision,
		Actor: newCloudEventActor(caller),
	}
	return appendCloudFactEvent(ctx, tx, rowID, "approval_challenge", "cloud.approval_challenge.changed", record.Challenge.Revision, summary)
}

// ApprovalRepositoryAdapter binds caller-scoped idempotency keys to the
// narrow domain repositories used by approval.Service.
type ApprovalRepositoryAdapter struct {
	store                 *Store
	scope                 task.MutationScope
	createIdempotencyKey  string
	consumeIdempotencyKey string
}

var (
	_ cloudapproval.DeviceKeyRepository = (*ApprovalRepositoryAdapter)(nil)
	_ cloudapproval.ChallengeRepository = (*ApprovalRepositoryAdapter)(nil)
)

func NewApprovalRepositoryAdapter(store *Store, scope task.MutationScope, createIdempotencyKey, consumeIdempotencyKey string) (*ApprovalRepositoryAdapter, error) {
	if store == nil {
		return nil, fmt.Errorf("store is required")
	}
	if _, err := parseIdempotencyCaller(scope); err != nil {
		return nil, err
	}
	if err := validateCloudMutationKey(createIdempotencyKey); err != nil {
		return nil, err
	}
	if err := validateCloudMutationKey(consumeIdempotencyKey); err != nil {
		return nil, err
	}
	return &ApprovalRepositoryAdapter{store: store, scope: scope, createIdempotencyKey: createIdempotencyKey, consumeIdempotencyKey: consumeIdempotencyKey}, nil
}

func (adapter *ApprovalRepositoryAdapter) GetDeviceKey(ctx context.Context, keyID string) (cloudapproval.DeviceKeyV1, error) {
	return adapter.store.GetDeviceKey(ctx, keyID)
}

func (adapter *ApprovalRepositoryAdapter) CreateChallenge(ctx context.Context, challenge cloudapproval.ChallengeV1) error {
	_, err := adapter.store.CreateApprovalChallenge(ctx, adapter.scope, CreateApprovalChallengeCommand{
		IdempotencyKey: adapter.createIdempotencyKey, ExpectedRevision: 0, Challenge: challenge,
	})
	return err
}

func (adapter *ApprovalRepositoryAdapter) GetChallenge(ctx context.Context, challengeID string) (cloudapproval.ChallengeV1, error) {
	return adapter.store.GetChallenge(ctx, challengeID)
}

func (adapter *ApprovalRepositoryAdapter) ConsumeChallenge(ctx context.Context, challengeID string, expectedRevision uint64, consumedAt time.Time) error {
	_, err := adapter.store.ConsumeApprovalChallenge(ctx, adapter.scope, ConsumeApprovalChallengeCommand{
		IdempotencyKey: adapter.consumeIdempotencyKey, ChallengeID: challengeID,
		ExpectedRevision: expectedRevision, ConsumedAt: consumedAt,
	})
	return err
}
