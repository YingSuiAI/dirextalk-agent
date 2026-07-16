package postgres

import (
	"bytes"
	"context"
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

const createPlanOperation = "cloud.plan.create"

type cloudPlanSnapshot struct {
	SchemaVersion int             `json:"schema_version"`
	Record        CloudPlanRecord `json:"record"`
}

func (store *Store) CreatePlan(ctx context.Context, scope task.MutationScope, command CreatePlanCommand) (cloudapproval.PlanV1, error) {
	record, err := store.createPlanRecord(ctx, scope, command)
	return record.Plan, err
}

func (store *Store) createPlanRecord(ctx context.Context, scope task.MutationScope, command CreatePlanCommand) (CloudPlanRecord, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return CloudPlanRecord{}, err
	}
	if err := command.validate(); err != nil {
		return CloudPlanRecord{}, err
	}
	requestDigest, err := command.digest()
	if err != nil {
		return CloudPlanRecord{}, err
	}
	planID, _ := uuid.Parse(command.Plan.PlanID)
	quoteID, _ := uuid.Parse(command.Plan.Quote.QuoteID)
	agentID, err := uuid.Parse(command.Plan.AgentInstanceID)
	if err != nil || agentID != store.instanceID {
		return CloudPlanRecord{}, ErrCloudFactScope
	}
	if command.Plan.Revision > math.MaxInt64 {
		return CloudPlanRecord{}, ErrCloudFactInvalid
	}
	planHash, err := command.Plan.Hash()
	if err != nil {
		return CloudPlanRecord{}, fmt.Errorf("%w: hash Plan", ErrCloudFactInvalid)
	}
	planCBOR, err := command.Plan.CanonicalCBOR()
	if err != nil {
		return CloudPlanRecord{}, fmt.Errorf("%w: encode Plan CBOR", ErrCloudFactInvalid)
	}
	planJSON, err := json.Marshal(command.Plan)
	if err != nil {
		return CloudPlanRecord{}, fmt.Errorf("%w: encode Plan JSON", ErrCloudFactInvalid)
	}

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return CloudPlanRecord{}, fmt.Errorf("begin create Plan: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, response, err := claimScopedIdempotency(ctx, tx, caller, createPlanOperation, command.IdempotencyKey, requestDigest[:], planID)
	if err != nil {
		return CloudPlanRecord{}, err
	}
	if existing {
		record, err := decodeCloudPlanSnapshot(response)
		if err != nil {
			return CloudPlanRecord{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return CloudPlanRecord{}, fmt.Errorf("commit Plan replay: %w", err)
		}
		return record, nil
	}
	storedQuote, err := readCloudQuote(ctx, tx, quoteID, true)
	if err != nil {
		return CloudPlanRecord{}, err
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return CloudPlanRecord{}, fmt.Errorf("read Plan creation time: %w", err)
	}
	if err := command.Plan.ValidateQuote(storedQuote.Quote, now.UTC()); err != nil {
		return CloudPlanRecord{}, fmt.Errorf("%w: Plan does not bind stored Quote: %v", ErrCloudFactInvalid, err)
	}
	quoteAgent, quoteOwner, quoteConnection, err := quoteIdentity(storedQuote.Quote)
	if err != nil || quoteAgent != agentID || quoteOwner != command.Plan.OwnerID || quoteConnection != command.Plan.ConnectionID {
		return CloudPlanRecord{}, ErrCloudFactScope
	}
	var alreadyExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM cloud_plans WHERE plan_id=$1)`, planID).Scan(&alreadyExists); err != nil {
		return CloudPlanRecord{}, fmt.Errorf("check Plan existence: %w", err)
	}
	if alreadyExists {
		return CloudPlanRecord{}, ErrCloudFactRevision
	}
	record := CloudPlanRecord{Plan: command.Plan, PlanHash: planHash, Revision: command.Plan.Revision}
	if err := tx.QueryRow(ctx, `
		INSERT INTO cloud_plans
		    (plan_id, agent_instance_id, owner_id, connection_id, quote_id, quote_digest,
		     quote_scope_digest, plan_hash, status, plan_json, plan_cbor, revision)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING created_at, updated_at`,
		planID, agentID, command.Plan.OwnerID, command.Plan.ConnectionID, quoteID, command.Plan.Quote.Digest,
		command.Plan.Quote.ScopeDigest, planHash, command.Plan.Status, planJSON, planCBOR, int64(command.Plan.Revision),
	).Scan(&record.CreatedAt, &record.UpdatedAt); err != nil {
		return CloudPlanRecord{}, fmt.Errorf("insert Plan: %w", err)
	}
	record.CreatedAt, record.UpdatedAt = record.CreatedAt.UTC(), record.UpdatedAt.UTC()
	if err := appendPlanEvent(ctx, tx, caller, planID, record); err != nil {
		return CloudPlanRecord{}, err
	}
	if err := setScopedIdempotencyResponse(ctx, tx, caller, createPlanOperation, command.IdempotencyKey, cloudPlanSnapshot{SchemaVersion: cloudFactSnapshotSchemaV1, Record: record}); err != nil {
		return CloudPlanRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CloudPlanRecord{}, fmt.Errorf("commit create Plan: %w", err)
	}
	return record, nil
}

func (store *Store) GetPlan(ctx context.Context, ownerID, planID string) (cloudapproval.PlanV1, error) {
	parsed, err := uuid.Parse(planID)
	if err != nil || strings.TrimSpace(ownerID) == "" {
		return cloudapproval.PlanV1{}, ErrCloudFactInvalid
	}
	record, err := readCloudPlan(ctx, store.pool, parsed, false)
	if err != nil {
		return cloudapproval.PlanV1{}, err
	}
	if record.Plan.OwnerID != strings.TrimSpace(ownerID) || record.Plan.AgentInstanceID != store.instanceID.String() {
		return cloudapproval.PlanV1{}, ErrCloudFactScope
	}
	quoteID, _ := uuid.Parse(record.Plan.Quote.QuoteID)
	storedQuote, err := readCloudQuote(ctx, store.pool, quoteID, false)
	if err != nil {
		return cloudapproval.PlanV1{}, err
	}
	if err := record.Plan.ValidateQuote(storedQuote.Quote, storedQuote.Quote.QuotedAt); err != nil {
		return cloudapproval.PlanV1{}, ErrCloudFactCorrupt
	}
	return record.Plan, nil
}

type cloudPlanQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readCloudPlan(ctx context.Context, query cloudPlanQuerier, planID uuid.UUID, lock bool) (CloudPlanRecord, error) {
	statement := `
		SELECT agent_instance_id, owner_id, connection_id, quote_id, quote_digest, quote_scope_digest,
		       plan_hash, status, plan_json, plan_cbor, revision, created_at, updated_at
		FROM cloud_plans WHERE plan_id=$1`
	if lock {
		statement += " FOR UPDATE"
	}
	var (
		agentID, quoteID                                                       uuid.UUID
		ownerID, connectionID, quoteDigest, quoteScopeDigest, planHash, status string
		planJSON, planCBOR                                                     []byte
		revision                                                               int64
		record                                                                 CloudPlanRecord
	)
	if err := query.QueryRow(ctx, statement, planID).Scan(
		&agentID, &ownerID, &connectionID, &quoteID, &quoteDigest, &quoteScopeDigest,
		&planHash, &status, &planJSON, &planCBOR, &revision, &record.CreatedAt, &record.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return CloudPlanRecord{}, ErrCloudFactNotFound
		}
		return CloudPlanRecord{}, fmt.Errorf("read Plan: %w", err)
	}
	if revision <= 0 || json.Unmarshal(planJSON, &record.Plan) != nil {
		return CloudPlanRecord{}, ErrCloudFactCorrupt
	}
	record.PlanHash, record.Revision = planHash, uint64(revision)
	record.CreatedAt, record.UpdatedAt = record.CreatedAt.UTC(), record.UpdatedAt.UTC()
	if err := record.Plan.Validate(); err != nil || record.Plan.PlanID != planID.String() || record.Plan.AgentInstanceID != agentID.String() ||
		record.Plan.OwnerID != ownerID || record.Plan.ConnectionID != connectionID || record.Plan.Quote.QuoteID != quoteID.String() ||
		record.Plan.Quote.Digest != quoteDigest || record.Plan.Quote.ScopeDigest != quoteScopeDigest || string(record.Plan.Status) != status || record.Plan.Revision != uint64(revision) {
		return CloudPlanRecord{}, ErrCloudFactCorrupt
	}
	actualHash, err := record.Plan.Hash()
	if err != nil || actualHash != planHash {
		return CloudPlanRecord{}, ErrCloudFactCorrupt
	}
	actualCBOR, err := record.Plan.CanonicalCBOR()
	if err != nil || !bytes.Equal(actualCBOR, planCBOR) {
		return CloudPlanRecord{}, ErrCloudFactCorrupt
	}
	return record, nil
}

func decodeCloudPlanSnapshot(encoded []byte) (CloudPlanRecord, error) {
	var snapshot cloudPlanSnapshot
	if err := json.Unmarshal(encoded, &snapshot); err != nil || snapshot.SchemaVersion != cloudFactSnapshotSchemaV1 || snapshot.Record.Revision == 0 {
		return CloudPlanRecord{}, ErrCloudFactCorrupt
	}
	hash, err := snapshot.Record.Plan.Hash()
	if err != nil || hash != snapshot.Record.PlanHash || snapshot.Record.Plan.Revision != snapshot.Record.Revision {
		return CloudPlanRecord{}, ErrCloudFactCorrupt
	}
	snapshot.Record.CreatedAt, snapshot.Record.UpdatedAt = snapshot.Record.CreatedAt.UTC(), snapshot.Record.UpdatedAt.UTC()
	return snapshot.Record, nil
}

func appendPlanEvent(ctx context.Context, tx pgx.Tx, caller idempotencyCaller, planID uuid.UUID, record CloudPlanRecord) error {
	summary := struct {
		PlanID               string                   `json:"plan_id"`
		OwnerID              string                   `json:"owner_id"`
		Status               cloudapproval.PlanStatus `json:"status"`
		Revision             uint64                   `json:"revision"`
		PlanHash             string                   `json:"plan_hash"`
		QuoteID              string                   `json:"quote_id"`
		QuoteValidUntil      time.Time                `json:"quote_valid_until"`
		Region               string                   `json:"region"`
		InstanceType         string                   `json:"instance_type"`
		PublicExposure       bool                     `json:"public_exposure"`
		SecretReferenceCount int                      `json:"secret_reference_count"`
		Actor                cloudEventActor          `json:"actor"`
	}{
		PlanID: record.Plan.PlanID, OwnerID: record.Plan.OwnerID, Status: record.Plan.Status,
		Revision: record.Revision, PlanHash: record.PlanHash, QuoteID: record.Plan.Quote.QuoteID,
		QuoteValidUntil: record.Plan.Quote.ValidUntil.UTC(), Region: record.Plan.ResourceScope.Region,
		InstanceType: record.Plan.ResourceScope.InstanceType, PublicExposure: record.Plan.NetworkScope.PublicExposure,
		SecretReferenceCount: len(record.Plan.SecretScope), Actor: newCloudEventActor(caller),
	}
	return appendCloudFactEvent(ctx, tx, planID, "cloud_plan", "cloud.plan.changed", record.Revision, summary)
}
