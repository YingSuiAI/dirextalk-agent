package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	saveRecipeDraftOperation = "planning.recipe_draft.save"
	planningSnapshotSchemaV1 = 1
)

type recipeDraftSnapshot struct {
	SchemaVersion int                  `json:"schema_version"`
	Draft         planning.RecipeDraft `json:"draft"`
}

func (store *Store) SaveRecipeDraft(ctx context.Context, scope task.MutationScope, command planning.SaveRecipeDraftCommand) (planning.RecipeDraft, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return planning.RecipeDraft{}, err
	}
	if err := command.Validate(); err != nil {
		return planning.RecipeDraft{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return planning.RecipeDraft{}, planning.ErrPersistence
	}
	defer func() { _ = tx.Rollback(ctx) }()
	session, storedCaller, _, err := lockResearchByBinding(ctx, tx, command.Binding)
	if err != nil {
		return planning.RecipeDraft{}, err
	}
	if storedCaller != caller {
		return planning.RecipeDraft{}, planning.ErrScopeMismatch
	}
	if session.Binding != command.Binding {
		return planning.RecipeDraft{}, planning.ErrIdempotencyConflict
	}

	recipeRowID := uuid.NewSHA1(store.instanceID, []byte("planning-recipe\x00"+planningBindingKey(command.Binding)))
	commandDigest := command.Digest()
	existing, _, response, err := claimScopedIdempotency(ctx, tx, caller, saveRecipeDraftOperation, command.IdempotencyKey, commandDigest[:], recipeRowID)
	if err != nil {
		return planning.RecipeDraft{}, err
	}
	if existing {
		draft, err := decodeRecipeDraftSnapshot(response)
		if err != nil {
			return planning.RecipeDraft{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return planning.RecipeDraft{}, planning.ErrPersistence
		}
		return draft, nil
	}

	encodedRecipe, err := json.Marshal(command.Recipe)
	if err != nil {
		return planning.RecipeDraft{}, planning.ErrPersistence
	}
	digest, err := command.Recipe.Digest()
	if err != nil {
		return planning.RecipeDraft{}, planning.ErrInvalid
	}
	draft := planning.RecipeDraft{RecipeID: command.Recipe.RecipeID, Recipe: command.Recipe, Digest: digest}
	var currentRevision int64
	queryErr := tx.QueryRow(ctx, `
		SELECT revision FROM planning_recipe_drafts WHERE session_id=$1 FOR UPDATE`, session.SessionID).Scan(&currentRevision)
	switch {
	case errors.Is(queryErr, pgx.ErrNoRows):
		if command.ExpectedRevision != 0 {
			return planning.RecipeDraft{}, planning.ErrRevisionConflict
		}
		draft.Revision = 1
		if err := tx.QueryRow(ctx, `
			INSERT INTO planning_recipe_drafts
			    (recipe_row_id, session_id, owner_id, recipe_id, digest, recipe_json, revision)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
			RETURNING created_at, updated_at`,
			recipeRowID, session.SessionID, command.Binding.OwnerID, command.Binding.RecipeID,
			draft.Digest, encodedRecipe, draft.Revision,
		).Scan(&draft.CreatedAt, &draft.UpdatedAt); err != nil {
			return planning.RecipeDraft{}, planning.ErrPersistence
		}
	case queryErr != nil:
		return planning.RecipeDraft{}, planning.ErrPersistence
	default:
		if command.ExpectedRevision != currentRevision {
			return planning.RecipeDraft{}, planning.ErrRevisionConflict
		}
		draft.Revision = currentRevision + 1
		if err := tx.QueryRow(ctx, `
			UPDATE planning_recipe_drafts
			SET digest=$2, recipe_json=$3, revision=$4, updated_at=clock_timestamp()
			WHERE session_id=$1
			RETURNING created_at, updated_at`,
			session.SessionID, draft.Digest, encodedRecipe, draft.Revision,
		).Scan(&draft.CreatedAt, &draft.UpdatedAt); err != nil {
			return planning.RecipeDraft{}, planning.ErrPersistence
		}
	}
	draft.CreatedAt = draft.CreatedAt.UTC()
	draft.UpdatedAt = draft.UpdatedAt.UTC()
	if err := appendRecipeDraftEvent(ctx, tx, recipeRowID, command.Binding.OwnerID, draft, caller); err != nil {
		return planning.RecipeDraft{}, err
	}
	if err := setScopedIdempotencyResponse(ctx, tx, caller, saveRecipeDraftOperation, command.IdempotencyKey, recipeDraftSnapshot{
		SchemaVersion: planningSnapshotSchemaV1, Draft: draft,
	}); err != nil {
		return planning.RecipeDraft{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return planning.RecipeDraft{}, planning.ErrPersistence
	}
	return draft, nil
}

func (store *Store) GetRecipeDraft(ctx context.Context, scope task.MutationScope, binding planning.Binding) (planning.RecipeDraft, bool, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return planning.RecipeDraft{}, false, err
	}
	if err := binding.Validate(); err != nil {
		return planning.RecipeDraft{}, false, err
	}
	session, storedCaller, _, err := readResearchByBinding(ctx, store.pool, binding, false)
	if err != nil {
		return planning.RecipeDraft{}, false, err
	}
	if storedCaller.ClientID != caller.ClientID {
		return planning.RecipeDraft{}, false, planning.ErrScopeMismatch
	}
	if !session.Binding.SameSession(binding) {
		return planning.RecipeDraft{}, false, planning.ErrIdempotencyConflict
	}
	draft, found, err := loadRecipeDraftBySession(ctx, store.pool, session.SessionID)
	return draft, found, err
}

func loadRecipeDraftBySession(ctx context.Context, query planningQuerier, sessionID string) (planning.RecipeDraft, bool, error) {
	var draft planning.RecipeDraft
	var encoded []byte
	if err := query.QueryRow(ctx, `
		SELECT recipe_id, digest, recipe_json, revision, created_at, updated_at
		FROM planning_recipe_drafts WHERE session_id=$1`, sessionID).Scan(
		&draft.RecipeID, &draft.Digest, &encoded, &draft.Revision, &draft.CreatedAt, &draft.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return planning.RecipeDraft{}, false, nil
		}
		return planning.RecipeDraft{}, false, planning.ErrPersistence
	}
	if err := json.Unmarshal(encoded, &draft.Recipe); err != nil || draft.Recipe.Maturity != recipe.MaturityExperimental || draft.Recipe.RecipeID != draft.RecipeID {
		return planning.RecipeDraft{}, false, planning.ErrPersistence
	}
	if err := draft.Recipe.Validate(); err != nil {
		return planning.RecipeDraft{}, false, planning.ErrPersistence
	}
	digest, err := draft.Recipe.Digest()
	if err != nil || digest != draft.Digest || draft.Revision < 1 {
		return planning.RecipeDraft{}, false, planning.ErrPersistence
	}
	draft.CreatedAt = draft.CreatedAt.UTC()
	draft.UpdatedAt = draft.UpdatedAt.UTC()
	return draft, true, nil
}

func decodeRecipeDraftSnapshot(encoded []byte) (planning.RecipeDraft, error) {
	var snapshot recipeDraftSnapshot
	if err := json.Unmarshal(encoded, &snapshot); err != nil || snapshot.SchemaVersion != planningSnapshotSchemaV1 {
		return planning.RecipeDraft{}, planning.ErrPersistence
	}
	if snapshot.Draft.Recipe.Maturity != recipe.MaturityExperimental || snapshot.Draft.Recipe.RecipeID != snapshot.Draft.RecipeID || snapshot.Draft.Revision < 1 {
		return planning.RecipeDraft{}, planning.ErrPersistence
	}
	if err := snapshot.Draft.Recipe.Validate(); err != nil {
		return planning.RecipeDraft{}, planning.ErrPersistence
	}
	digest, err := snapshot.Draft.Recipe.Digest()
	if err != nil || digest != snapshot.Draft.Digest {
		return planning.RecipeDraft{}, planning.ErrPersistence
	}
	return snapshot.Draft, nil
}
