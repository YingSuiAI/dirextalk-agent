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
