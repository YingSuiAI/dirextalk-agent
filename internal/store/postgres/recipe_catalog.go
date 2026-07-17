package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/jackc/pgx/v5"
)

// ResolveRecipe returns the latest validated private Recipe matching the
// exact owner, identifier, and digest selected by a quote. It never accepts a
// caller-supplied Recipe body as pricing evidence.
func (store *Store) ResolveRecipe(ctx context.Context, ownerID, recipeID, digest string) (recipe.RecipeV1, error) {
	if store == nil || strings.TrimSpace(ownerID) == "" || strings.TrimSpace(recipeID) == "" {
		return recipe.RecipeV1{}, planning.ErrInvalid
	}
	var encoded []byte
	var storedDigest string
	err := store.pool.QueryRow(ctx, `
		SELECT recipe_json, digest
		FROM planning_recipe_drafts
		WHERE owner_id=$1 AND recipe_id=$2 AND digest=$3
		ORDER BY updated_at DESC, recipe_row_id DESC
		LIMIT 1`, strings.TrimSpace(ownerID), strings.TrimSpace(recipeID), strings.TrimSpace(digest)).Scan(&encoded, &storedDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return recipe.RecipeV1{}, planning.ErrNotFound
	}
	if err != nil {
		return recipe.RecipeV1{}, planning.ErrPersistence
	}
	var value recipe.RecipeV1
	if err := json.Unmarshal(encoded, &value); err != nil || value.RecipeID != strings.TrimSpace(recipeID) || value.Maturity == "" {
		return recipe.RecipeV1{}, planning.ErrPersistence
	}
	if err := value.Validate(); err != nil {
		return recipe.RecipeV1{}, planning.ErrPersistence
	}
	computed, err := value.Digest()
	if err != nil || computed != storedDigest || computed != strings.TrimSpace(digest) {
		return recipe.RecipeV1{}, planning.ErrPersistence
	}
	return value, nil
}

// ResolveRecipeDraft returns the exact persisted Recipe revision selected by
// an approved Plan. Managed preparation signs this revision together with the
// Recipe digest so a later draft cannot be substituted during execution.
func (store *Store) ResolveRecipeDraft(ctx context.Context, ownerID, recipeID, digest string) (planning.RecipeDraft, error) {
	if store == nil || ctx == nil || strings.TrimSpace(ownerID) == "" || strings.TrimSpace(recipeID) == "" {
		return planning.RecipeDraft{}, planning.ErrInvalid
	}
	var value planning.RecipeDraft
	var encoded []byte
	err := store.pool.QueryRow(ctx, `
		SELECT recipe_json, digest, revision, created_at, updated_at
		FROM planning_recipe_drafts
		WHERE owner_id=$1 AND recipe_id=$2 AND digest=$3
		ORDER BY updated_at DESC, recipe_row_id DESC
		LIMIT 1`, strings.TrimSpace(ownerID), strings.TrimSpace(recipeID), strings.TrimSpace(digest)).
		Scan(&encoded, &value.Digest, &value.Revision, &value.CreatedAt, &value.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return planning.RecipeDraft{}, planning.ErrNotFound
	}
	if err != nil {
		return planning.RecipeDraft{}, planning.ErrPersistence
	}
	if err := json.Unmarshal(encoded, &value.Recipe); err != nil || value.Recipe.Validate() != nil ||
		value.Recipe.RecipeID != strings.TrimSpace(recipeID) || value.Revision < 1 {
		return planning.RecipeDraft{}, planning.ErrPersistence
	}
	value.RecipeID = value.Recipe.RecipeID
	computed, err := value.Recipe.Digest()
	if err != nil || computed != value.Digest || computed != strings.TrimSpace(digest) {
		return planning.RecipeDraft{}, planning.ErrPersistence
	}
	return value, nil
}
