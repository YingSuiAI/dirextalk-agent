package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const createQuoteOperation = "cloud.quote.create"

type cloudQuoteSnapshot struct {
	SchemaVersion int              `json:"schema_version"`
	Record        CloudQuoteRecord `json:"record"`
}

func (store *Store) CreateQuote(ctx context.Context, scope task.MutationScope, command CreateQuoteCommand) (cloudquote.QuoteV1, error) {
	record, err := store.createQuoteRecord(ctx, scope, command)
	return record.Quote, err
}

func (store *Store) createQuoteRecord(ctx context.Context, scope task.MutationScope, command CreateQuoteCommand) (CloudQuoteRecord, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return CloudQuoteRecord{}, err
	}
	if err := command.validate(); err != nil {
		return CloudQuoteRecord{}, err
	}
	requestDigest, err := command.digest()
	if err != nil {
		return CloudQuoteRecord{}, err
	}
	quoteID, _ := uuid.Parse(command.Quote.QuoteID)
	agentID, ownerID, connectionID, err := quoteIdentity(command.Quote)
	if err != nil {
		return CloudQuoteRecord{}, err
	}
	if agentID != store.instanceID {
		return CloudQuoteRecord{}, ErrCloudFactScope
	}
	quoteDigest, err := command.Quote.Digest()
	if err != nil {
		return CloudQuoteRecord{}, fmt.Errorf("%w: digest quote", ErrCloudFactInvalid)
	}
	quoteCBOR, err := command.Quote.CanonicalCBOR()
	if err != nil {
		return CloudQuoteRecord{}, fmt.Errorf("%w: encode quote CBOR", ErrCloudFactInvalid)
	}
	quoteJSON, err := json.Marshal(command.Quote)
	if err != nil {
		return CloudQuoteRecord{}, fmt.Errorf("%w: encode quote JSON", ErrCloudFactInvalid)
	}

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return CloudQuoteRecord{}, fmt.Errorf("begin create quote: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, response, err := claimScopedIdempotency(ctx, tx, caller, createQuoteOperation, command.IdempotencyKey, requestDigest[:], quoteID)
	if err != nil {
		return CloudQuoteRecord{}, err
	}
	if existing {
		record, err := decodeCloudQuoteSnapshot(response)
		if err != nil {
			return CloudQuoteRecord{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return CloudQuoteRecord{}, fmt.Errorf("commit quote replay: %w", err)
		}
		return record, nil
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return CloudQuoteRecord{}, fmt.Errorf("read quote creation time: %w", err)
	}
	now = now.UTC()
	if now.Before(command.Quote.QuotedAt.Add(-30*time.Second)) || !now.Before(command.Quote.ValidUntil) {
		return CloudQuoteRecord{}, fmt.Errorf("%w: quote is not currently valid", ErrCloudFactInvalid)
	}
	var alreadyExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM cloud_quotes WHERE quote_id=$1)`, quoteID).Scan(&alreadyExists); err != nil {
		return CloudQuoteRecord{}, fmt.Errorf("check quote existence: %w", err)
	}
	if alreadyExists {
		return CloudQuoteRecord{}, ErrCloudFactRevision
	}
	record := CloudQuoteRecord{Quote: command.Quote, Digest: quoteDigest, Revision: 1}
	if err := tx.QueryRow(ctx, `
		INSERT INTO cloud_quotes
		    (quote_id, agent_instance_id, owner_id, connection_id, quote_digest, quote_json, quote_cbor,
		     revision, quoted_at, valid_until)
		VALUES ($1,$2,$3,$4,$5,$6,$7,1,$8,$9)
		RETURNING created_at`,
		quoteID, agentID, ownerID, connectionID, quoteDigest, quoteJSON, quoteCBOR,
		command.Quote.QuotedAt.UTC(), command.Quote.ValidUntil.UTC(),
	).Scan(&record.CreatedAt); err != nil {
		return CloudQuoteRecord{}, fmt.Errorf("insert quote: %w", err)
	}
	record.CreatedAt = record.CreatedAt.UTC()
	if err := appendQuoteEvent(ctx, tx, caller, quoteID, record); err != nil {
		return CloudQuoteRecord{}, err
	}
	if err := setScopedIdempotencyResponse(ctx, tx, caller, createQuoteOperation, command.IdempotencyKey, cloudQuoteSnapshot{SchemaVersion: cloudFactSnapshotSchemaV1, Record: record}); err != nil {
		return CloudQuoteRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CloudQuoteRecord{}, fmt.Errorf("commit create quote: %w", err)
	}
	return record, nil
}

func (store *Store) GetQuote(ctx context.Context, ownerID, quoteID string) (cloudquote.QuoteV1, error) {
	parsed, err := uuid.Parse(quoteID)
	if err != nil || strings.TrimSpace(ownerID) == "" {
		return cloudquote.QuoteV1{}, ErrCloudFactInvalid
	}
	record, err := readCloudQuote(ctx, store.pool, parsed, false)
	if err != nil {
		return cloudquote.QuoteV1{}, err
	}
	storedAgent, storedOwner, _, err := quoteIdentity(record.Quote)
	if err != nil {
		return cloudquote.QuoteV1{}, err
	}
	if storedAgent != store.instanceID || storedOwner != strings.TrimSpace(ownerID) {
		return cloudquote.QuoteV1{}, ErrCloudFactScope
	}
	return record.Quote, nil
}

type cloudQuoteQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readCloudQuote(ctx context.Context, query cloudQuoteQuerier, quoteID uuid.UUID, lock bool) (CloudQuoteRecord, error) {
	statement := `
		SELECT agent_instance_id, owner_id, connection_id, quote_digest, quote_json, quote_cbor,
		       revision, quoted_at, valid_until, created_at
		FROM cloud_quotes WHERE quote_id=$1`
	if lock {
		statement += " FOR UPDATE"
	}
	var (
		agentID, storedQuoteID        uuid.UUID
		ownerID, connectionID, digest string
		quoteJSON, quoteCBOR          []byte
		revision                      int64
		quotedAt, validUntil          time.Time
		record                        CloudQuoteRecord
	)
	storedQuoteID = quoteID
	if err := query.QueryRow(ctx, statement, quoteID).Scan(
		&agentID, &ownerID, &connectionID, &digest, &quoteJSON, &quoteCBOR,
		&revision, &quotedAt, &validUntil, &record.CreatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return CloudQuoteRecord{}, ErrCloudFactNotFound
		}
		return CloudQuoteRecord{}, fmt.Errorf("read quote: %w", err)
	}
	if err := json.Unmarshal(quoteJSON, &record.Quote); err != nil {
		return CloudQuoteRecord{}, ErrCloudFactCorrupt
	}
	record.Digest, record.Revision, record.CreatedAt = digest, uint64(revision), record.CreatedAt.UTC()
	actualAgent, actualOwner, actualConnection, err := quoteIdentity(record.Quote)
	if err != nil || actualAgent != agentID || actualOwner != ownerID || actualConnection != connectionID ||
		record.Quote.QuoteID != storedQuoteID.String() || !record.Quote.QuotedAt.Equal(quotedAt) || !record.Quote.ValidUntil.Equal(validUntil) || revision != 1 {
		return CloudQuoteRecord{}, ErrCloudFactCorrupt
	}
	actualDigest, err := record.Quote.Digest()
	if err != nil || actualDigest != digest {
		return CloudQuoteRecord{}, ErrCloudFactCorrupt
	}
	actualCBOR, err := record.Quote.CanonicalCBOR()
	if err != nil || !bytes.Equal(actualCBOR, quoteCBOR) {
		return CloudQuoteRecord{}, ErrCloudFactCorrupt
	}
	return record, nil
}

func quoteIdentity(value cloudquote.QuoteV1) (uuid.UUID, string, string, error) {
	if err := value.Validate(); err != nil || len(value.Candidates) != 3 {
		return uuid.Nil, "", "", fmt.Errorf("%w: quote identity is invalid", ErrCloudFactInvalid)
	}
	scope := value.Candidates[0].Scope
	agentID, err := uuid.Parse(scope.AgentInstanceID)
	if err != nil {
		return uuid.Nil, "", "", fmt.Errorf("%w: quote agent_instance_id must be a UUID", ErrCloudFactInvalid)
	}
	return agentID, scope.OwnerID, scope.ConnectionID, nil
}

func decodeCloudQuoteSnapshot(encoded []byte) (CloudQuoteRecord, error) {
	var snapshot cloudQuoteSnapshot
	if err := json.Unmarshal(encoded, &snapshot); err != nil || snapshot.SchemaVersion != cloudFactSnapshotSchemaV1 || snapshot.Record.Revision != 1 {
		return CloudQuoteRecord{}, ErrCloudFactCorrupt
	}
	digest, err := snapshot.Record.Quote.Digest()
	if err != nil || digest != snapshot.Record.Digest {
		return CloudQuoteRecord{}, ErrCloudFactCorrupt
	}
	snapshot.Record.CreatedAt = snapshot.Record.CreatedAt.UTC()
	return snapshot.Record, nil
}

func appendQuoteEvent(ctx context.Context, tx pgx.Tx, caller idempotencyCaller, quoteID uuid.UUID, record CloudQuoteRecord) error {
	type candidateSummary struct {
		CandidateID               cloudquote.CandidateProfile `json:"candidate_id"`
		Region                    string                      `json:"region"`
		InstanceType              string                      `json:"instance_type"`
		HourlyEstimateMicros      uint64                      `json:"hourly_estimate_micros"`
		MonthlyEstimateMicros     uint64                      `json:"monthly_estimate_micros"`
		MaximumLaunchAmountMicros uint64                      `json:"maximum_launch_amount_micros"`
	}
	summary := struct {
		QuoteID    string             `json:"quote_id"`
		OwnerID    string             `json:"owner_id"`
		Currency   string             `json:"currency"`
		ValidUntil time.Time          `json:"valid_until"`
		Candidates []candidateSummary `json:"candidates"`
		Revision   uint64             `json:"revision"`
		Actor      cloudEventActor    `json:"actor"`
	}{QuoteID: record.Quote.QuoteID, Currency: record.Quote.Currency, ValidUntil: record.Quote.ValidUntil.UTC(), Revision: record.Revision, Actor: newCloudEventActor(caller)}
	for _, candidate := range record.Quote.Candidates {
		summary.OwnerID = candidate.Scope.OwnerID
		summary.Candidates = append(summary.Candidates, candidateSummary{
			CandidateID: candidate.CandidateID, Region: candidate.Scope.Resource.Region,
			InstanceType:              candidate.Scope.Resource.InstanceType,
			HourlyEstimateMicros:      candidate.HourlyEstimateMicros,
			MonthlyEstimateMicros:     candidate.MonthlyEstimateMicros,
			MaximumLaunchAmountMicros: candidate.MaximumLaunchAmountMicros,
		})
	}
	return appendCloudFactEvent(ctx, tx, quoteID, "cloud_quote", "cloud.quote.changed", record.Revision, summary)
}
