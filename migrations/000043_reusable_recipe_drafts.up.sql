ALTER TABLE planning_recipe_drafts
    DROP CONSTRAINT planning_recipe_drafts_owner_id_recipe_id_key;

CREATE INDEX planning_recipe_drafts_catalog_idx
    ON planning_recipe_drafts (owner_id, recipe_id, digest, updated_at DESC, recipe_row_id DESC);
