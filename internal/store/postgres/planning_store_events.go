package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func appendPlanningSessionEvent(ctx context.Context, tx pgx.Tx, session planning.ResearchSession, caller idempotencyCaller, eventType string) error {
	summary := struct {
		SchemaVersion     int                        `json:"schema_version"`
		SessionID         string                     `json:"session_id"`
		OwnerID           string                     `json:"owner_id"`
		ConversationID    string                     `json:"conversation_id"`
		ConnectionID      string                     `json:"connection_id,omitempty"`
		RecipeID          string                     `json:"recipe_id"`
		RetentionPolicy   string                     `json:"retention_policy"`
		TaskID            string                     `json:"task_id,omitempty"`
		QuoteState        planning.QuoteRequestState `json:"quote_state"`
		CandidateRevision int64                      `json:"candidate_revision"`
		Revision          int64                      `json:"revision"`
		CreatedAt         time.Time                  `json:"created_at"`
		UpdatedAt         time.Time                  `json:"updated_at"`
		ActorClientID     string                     `json:"actor_client_id"`
		ActorCredentialID string                     `json:"actor_credential_id"`
	}{
		SchemaVersion: planningSnapshotSchemaV1, SessionID: session.SessionID, OwnerID: session.Binding.OwnerID,
		ConversationID: session.Binding.ConversationID, ConnectionID: session.Binding.ConnectionID,
		RecipeID: session.Binding.RecipeID, RetentionPolicy: string(session.Binding.Retention),
		TaskID: session.TaskID, QuoteState: session.QuoteState, CandidateRevision: session.CandidateRevision,
		Revision: session.Revision, CreatedAt: session.CreatedAt.UTC(), UpdatedAt: session.UpdatedAt.UTC(),
		ActorClientID: caller.ClientID, ActorCredentialID: caller.CredentialID.String(),
	}
	aggregateID, err := uuid.Parse(session.SessionID)
	if err != nil {
		return planning.ErrPersistence
	}
	return appendSanitizedPlanningEvent(ctx, tx, aggregateID, "planning_session", eventType, session.Revision, summary)
}

func appendRecipeDraftEvent(ctx context.Context, tx pgx.Tx, recipeRowID uuid.UUID, ownerID string, draft planning.RecipeDraft, caller idempotencyCaller) error {
	summary := struct {
		SchemaVersion     int    `json:"schema_version"`
		RecipeID          string `json:"recipe_id"`
		OwnerID           string `json:"owner_id"`
		Digest            string `json:"digest"`
		Maturity          string `json:"maturity"`
		Revision          int64  `json:"revision"`
		ActorClientID     string `json:"actor_client_id"`
		ActorCredentialID string `json:"actor_credential_id"`
	}{
		SchemaVersion: planningSnapshotSchemaV1, RecipeID: draft.RecipeID, OwnerID: ownerID,
		Digest: draft.Digest, Maturity: string(draft.Recipe.Maturity), Revision: draft.Revision,
		ActorClientID: caller.ClientID, ActorCredentialID: caller.CredentialID.String(),
	}
	return appendSanitizedPlanningEvent(ctx, tx, recipeRowID, "recipe_draft", "agent.recipe.changed", draft.Revision, summary)
}

func appendCandidateSetEvent(ctx context.Context, tx pgx.Tx, session planning.ResearchSession, caller idempotencyCaller) error {
	summary := struct {
		SchemaVersion     int                        `json:"schema_version"`
		SessionID         string                     `json:"session_id"`
		OwnerID           string                     `json:"owner_id"`
		ConversationID    string                     `json:"conversation_id"`
		ConnectionID      string                     `json:"connection_id,omitempty"`
		RecipeID          string                     `json:"recipe_id"`
		RetentionPolicy   string                     `json:"retention_policy"`
		QuoteState        planning.QuoteRequestState `json:"quote_state"`
		CandidateTiers    []planning.CandidateTier   `json:"candidate_tiers"`
		CandidateRevision int64                      `json:"candidate_revision"`
		Revision          int64                      `json:"revision"`
		ActorClientID     string                     `json:"actor_client_id"`
		ActorCredentialID string                     `json:"actor_credential_id"`
	}{
		SchemaVersion: planningSnapshotSchemaV1, SessionID: session.SessionID, OwnerID: session.Binding.OwnerID,
		ConversationID: session.Binding.ConversationID, ConnectionID: session.Binding.ConnectionID,
		RecipeID: session.Binding.RecipeID, RetentionPolicy: string(session.Binding.Retention),
		QuoteState: session.QuoteState, CandidateTiers: []planning.CandidateTier{planning.TierEconomy, planning.TierRecommended, planning.TierPerformance},
		CandidateRevision: session.CandidateRevision, Revision: session.Revision,
		ActorClientID: caller.ClientID, ActorCredentialID: caller.CredentialID.String(),
	}
	aggregateID, err := uuid.Parse(session.SessionID)
	if err != nil {
		return planning.ErrPersistence
	}
	return appendSanitizedPlanningEvent(ctx, tx, aggregateID, "planning_session", "agent.planning.candidates_changed", session.Revision, summary)
}

func appendSanitizedPlanningEvent(ctx context.Context, tx pgx.Tx, aggregateID uuid.UUID, aggregateType, eventType string, revision int64, summary any) error {
	encoded, err := json.Marshal(summary)
	if err != nil {
		return planning.ErrPersistence
	}
	eventID, err := uuid.NewV7()
	if err != nil {
		return planning.ErrPersistence
	}
	outboxID, err := uuid.NewV7()
	if err != nil {
		return planning.ErrPersistence
	}
	var sequence int64
	var occurredAt time.Time
	if err := tx.QueryRow(ctx, `
		INSERT INTO task_events (event_id, event_type, aggregate_type, aggregate_id, revision, summary_json)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING seq, occurred_at`,
		eventID, eventType, aggregateType, aggregateID, revision, encoded,
	).Scan(&sequence, &occurredAt); err != nil {
		return planning.ErrPersistence
	}
	payload := struct {
		SchemaVersion int             `json:"schema_version"`
		Seq           int64           `json:"seq"`
		EventID       string          `json:"event_id"`
		EventType     string          `json:"event_type"`
		AggregateType string          `json:"aggregate_type"`
		AggregateID   string          `json:"aggregate_id"`
		Revision      int64           `json:"revision"`
		Summary       json.RawMessage `json:"summary"`
		OccurredAt    time.Time       `json:"occurred_at"`
	}{planningSnapshotSchemaV1, sequence, eventID.String(), eventType, aggregateType, aggregateID.String(), revision, encoded, occurredAt.UTC()}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return planning.ErrPersistence
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO outbox_events (outbox_id, event_seq, topic, payload_json)
		VALUES ($1,$2,$3,$4)`, outboxID, sequence, eventType, payloadJSON); err != nil {
		return planning.ErrPersistence
	}
	return nil
}
