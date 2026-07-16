package postgres

import (
	"context"
	"encoding/json"

	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const savePlanningCandidatesOperation = "planning.resource_candidates.save"

type candidateSetSnapshot struct {
	SchemaVersion int                           `json:"schema_version"`
	Set           planning.ResourceCandidateSet `json:"set"`
}

func (store *Store) SaveResourceCandidates(ctx context.Context, scope task.MutationScope, command planning.SaveCandidatesCommand) (planning.ResourceCandidateSet, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return planning.ResourceCandidateSet{}, err
	}
	if err := command.Validate(); err != nil {
		return planning.ResourceCandidateSet{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return planning.ResourceCandidateSet{}, planning.ErrPersistence
	}
	defer func() { _ = tx.Rollback(ctx) }()
	session, storedCaller, _, err := lockResearchByBinding(ctx, tx, command.Binding)
	if err != nil {
		return planning.ResourceCandidateSet{}, err
	}
	if storedCaller != caller {
		return planning.ResourceCandidateSet{}, planning.ErrScopeMismatch
	}
	if session.Binding != command.Binding {
		return planning.ResourceCandidateSet{}, planning.ErrIdempotencyConflict
	}
	draft, found, err := loadRecipeDraftBySession(ctx, tx, session.SessionID)
	if err != nil {
		return planning.ResourceCandidateSet{}, err
	}
	if !found {
		return planning.ResourceCandidateSet{}, planning.ErrInvalid
	}
	if err := planning.ValidateCandidatesAgainstRecipe(command.Candidates, draft.Recipe.Requirements); err != nil {
		return planning.ResourceCandidateSet{}, err
	}
	digest := command.Digest()
	sessionID, err := uuid.Parse(session.SessionID)
	if err != nil {
		return planning.ResourceCandidateSet{}, planning.ErrPersistence
	}
	existing, _, response, err := claimScopedIdempotency(ctx, tx, caller, savePlanningCandidatesOperation, command.IdempotencyKey, digest[:], sessionID)
	if err != nil {
		return planning.ResourceCandidateSet{}, err
	}
	if existing {
		set, err := decodeCandidateSetSnapshot(response)
		if err != nil {
			return planning.ResourceCandidateSet{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return planning.ResourceCandidateSet{}, planning.ErrPersistence
		}
		return set, nil
	}
	if session.CandidateRevision != command.ExpectedRevision {
		return planning.ResourceCandidateSet{}, planning.ErrRevisionConflict
	}
	ordered := canonicalPlanningCandidates(command.Candidates)
	if _, err := tx.Exec(ctx, `DELETE FROM planning_resource_candidates WHERE session_id=$1`, session.SessionID); err != nil {
		return planning.ResourceCandidateSet{}, planning.ErrPersistence
	}
	for _, candidate := range ordered {
		encoded, err := json.Marshal(candidate)
		if err != nil {
			return planning.ResourceCandidateSet{}, planning.ErrPersistence
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO planning_resource_candidates (session_id, tier, candidate_json)
			VALUES ($1,$2,$3)`, session.SessionID, candidate.Tier, encoded); err != nil {
			return planning.ResourceCandidateSet{}, planning.ErrPersistence
		}
	}
	set := planning.ResourceCandidateSet{Candidates: ordered, QuoteState: command.QuoteState, Revision: command.ExpectedRevision + 1}
	if err := tx.QueryRow(ctx, `
		UPDATE planning_sessions
		SET quote_state=$2, candidate_revision=$3, revision=revision+1, updated_at=clock_timestamp()
		WHERE session_id=$1 RETURNING revision, updated_at`,
		session.SessionID, command.QuoteState, set.Revision,
	).Scan(&session.Revision, &session.UpdatedAt); err != nil {
		return planning.ResourceCandidateSet{}, planning.ErrPersistence
	}
	session.QuoteState = command.QuoteState
	session.CandidateRevision = set.Revision
	if err := appendCandidateSetEvent(ctx, tx, session, caller); err != nil {
		return planning.ResourceCandidateSet{}, err
	}
	if err := setScopedIdempotencyResponse(ctx, tx, caller, savePlanningCandidatesOperation, command.IdempotencyKey, candidateSetSnapshot{
		SchemaVersion: planningSnapshotSchemaV1, Set: set,
	}); err != nil {
		return planning.ResourceCandidateSet{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return planning.ResourceCandidateSet{}, planning.ErrPersistence
	}
	return set, nil
}

func decodeCandidateSetSnapshot(encoded []byte) (planning.ResourceCandidateSet, error) {
	var snapshot candidateSetSnapshot
	if err := json.Unmarshal(encoded, &snapshot); err != nil || snapshot.SchemaVersion != planningSnapshotSchemaV1 || snapshot.Set.Revision < 1 {
		return planning.ResourceCandidateSet{}, planning.ErrPersistence
	}
	if err := planning.ValidateResourceCandidates(snapshot.Set.Candidates, snapshot.Set.QuoteState); err != nil {
		return planning.ResourceCandidateSet{}, planning.ErrPersistence
	}
	return snapshot.Set, nil
}

func canonicalPlanningCandidates(candidates []planning.ResourceCandidateV1) []planning.ResourceCandidateV1 {
	byTier := make(map[planning.CandidateTier]planning.ResourceCandidateV1, len(candidates))
	for _, candidate := range candidates {
		byTier[candidate.Tier] = candidate
	}
	return []planning.ResourceCandidateV1{
		byTier[planning.TierEconomy], byTier[planning.TierRecommended], byTier[planning.TierPerformance],
	}
}
