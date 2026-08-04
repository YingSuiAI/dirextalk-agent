package postgres

import (
	"context"
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/jackc/pgx/v5"
)

// ResolveExecutionProfile resolves the secret referenced by an immutable task
// snapshot. Non-secret fields are reconstructed from the snapshot itself, so
// profile updates cannot drift a queued task to a newer configuration.
func (s *Store) ResolveExecutionProfile(ctx context.Context, snap coretask.ModelProfileSnapshot) (coremodel.Profile, error) {
	var version uint32
	var nonce, ciphertext []byte
	if err := s.pool.QueryRow(ctx, `SELECT secret_key_version,api_key_nonce,api_key_ciphertext FROM core_model_profile_secret_revisions WHERE profile_id=$1 AND revision=$2`, snap.ProfileID, snap.Revision).Scan(&version, &nonce, &ciphertext); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coremodel.Profile{}, coremodel.ErrAPIKeyUnavailable
		}
		return coremodel.Profile{}, err
	}
	plaintext, err := s.openDurableSecret(profileRevisionDomain, snap.ProfileID, snap.Revision, "api_key", version, nonce, ciphertext)
	if err != nil {
		return coremodel.Profile{}, coremodel.ErrAPIKeyUnavailable
	}
	apiKey := string(plaintext)
	clearBytes(plaintext)
	return coremodel.Profile{ID: snap.ProfileID, Revision: snap.Revision, Provider: coremodel.ModelProvider(snap.Provider), BaseURL: snap.BaseURL, Model: snap.Model, APIKey: apiKey, APIKeyConfigured: true, SystemPrompt: snap.SystemPrompt, Temperature: snap.Temperature, TopP: snap.TopP, MaxOutputTokens: snap.MaxOutputTokens, ContextWindow: snap.ContextWindow, ReasoningEffort: snap.ReasoningEffort}, nil
}
