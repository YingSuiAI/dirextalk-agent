package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func appendCloudFactEvent(ctx context.Context, tx pgx.Tx, aggregateID uuid.UUID, aggregateType, eventType string, revision uint64, summary any) error {
	if revision == 0 || revision > math.MaxInt64 {
		return ErrCloudFactInvalid
	}
	encodedSummary, err := json.Marshal(summary)
	if err != nil {
		return fmt.Errorf("encode cloud event summary: %w", err)
	}
	eventID, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("generate cloud event id: %w", err)
	}
	var sequence int64
	var occurredAt time.Time
	if err := tx.QueryRow(ctx, `
		INSERT INTO task_events (event_id, event_type, aggregate_type, aggregate_id, revision, summary_json)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING seq, occurred_at`,
		eventID, eventType, aggregateType, aggregateID, int64(revision), encodedSummary,
	).Scan(&sequence, &occurredAt); err != nil {
		return fmt.Errorf("insert cloud event: %w", err)
	}
	payload := struct {
		SchemaVersion int             `json:"schema_version"`
		Seq           int64           `json:"seq"`
		EventID       string          `json:"event_id"`
		EventType     string          `json:"event_type"`
		AggregateType string          `json:"aggregate_type"`
		AggregateID   string          `json:"aggregate_id"`
		Revision      uint64          `json:"revision"`
		Summary       json.RawMessage `json:"summary"`
		OccurredAt    time.Time       `json:"occurred_at"`
	}{
		SchemaVersion: cloudFactSnapshotSchemaV1,
		Seq:           sequence,
		EventID:       eventID.String(),
		EventType:     eventType,
		AggregateType: aggregateType,
		AggregateID:   aggregateID.String(),
		Revision:      revision,
		Summary:       encodedSummary,
		OccurredAt:    occurredAt.UTC(),
	}
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode cloud outbox payload: %w", err)
	}
	outboxID, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("generate cloud outbox id: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO outbox_events (outbox_id, event_seq, topic, payload_json)
		VALUES ($1,$2,$3,$4)`, outboxID, sequence, eventType, encodedPayload); err != nil {
		return fmt.Errorf("insert cloud outbox event: %w", err)
	}
	return nil
}

type cloudEventActor struct {
	ClientID     string `json:"client_id"`
	CredentialID string `json:"credential_id"`
}

func newCloudEventActor(caller idempotencyCaller) cloudEventActor {
	return cloudEventActor{ClientID: caller.ClientID, CredentialID: caller.CredentialID.String()}
}
