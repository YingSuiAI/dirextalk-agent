package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	profileCreateOp         = "model_profile.create"
	profileUpdateOp         = "model_profile.update"
	profileDeleteOp         = "model_profile.delete"
	profileTestConnectionOp = "model_profile.test_connection"
	profileSyncOp           = "model_profile.sync"
	profileSecretDomain     = "core_model_profiles"
	profileRevisionDomain   = "core_model_profile_secret_revisions"
)

func profileSecretArgs(envelope secretbox.Envelope) (any, any, any) {
	if len(envelope.Ciphertext) == 0 {
		return secretbox.KeyVersionMin, nil, nil
	}
	return envelope.KeyVersion, envelope.Nonce, envelope.Ciphertext
}

func (s *Store) sealProfileSecret(p coremodel.Profile) (secretbox.Envelope, error) {
	if p.APIKey == "" {
		return secretbox.Envelope{KeyVersion: secretbox.KeyVersionMin}, nil
	}
	plaintext := []byte(p.APIKey)
	defer clearBytes(plaintext)
	return s.sealDurableSecret(profileSecretDomain, p.ID, p.Revision, "api_key", plaintext)
}

func (s *Store) sealProfileRevisionSecret(p coremodel.Profile) (secretbox.Envelope, error) {
	if p.APIKey == "" {
		return secretbox.Envelope{}, nil
	}
	plaintext := []byte(p.APIKey)
	defer clearBytes(plaintext)
	return s.sealDurableSecret(profileRevisionDomain, p.ID, p.Revision, "api_key", plaintext)
}

func (s *Store) sealProviderSecrets(p coremodel.Profile) (secretbox.Envelope, error) {
	if len(p.ProviderSecrets) == 0 {
		return secretbox.Envelope{}, nil
	}
	plaintext, err := json.Marshal(p.ProviderSecrets)
	if err != nil {
		return secretbox.Envelope{}, err
	}
	defer clearBytes(plaintext)
	return s.sealDurableSecret(profileSecretDomain, p.ID, p.Revision, "provider_secrets", plaintext)
}

func providerSecretStatusArgs(envelope secretbox.Envelope) (any, any, any) {
	if len(envelope.Ciphertext) == 0 {
		return secretbox.KeyVersionMin, nil, nil
	}
	return envelope.KeyVersion, envelope.Nonce, envelope.Ciphertext
}

type profileSecretQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *Store) hydrateProfileSecret(ctx context.Context, query profileSecretQuery, p *coremodel.Profile) error {
	if p == nil {
		return nil
	}
	var version uint32
	var nonce, ciphertext []byte
	if err := query.QueryRow(ctx, `SELECT api_key_key_version,api_key_nonce,api_key_ciphertext FROM core_model_profiles WHERE profile_id=$1 AND revision=$2`, p.ID, p.Revision).Scan(&version, &nonce, &ciphertext); err != nil {
		return err
	}
	if len(ciphertext) == 0 {
		return nil
	}
	plaintext, err := s.openDurableSecret(profileSecretDomain, p.ID, p.Revision, "api_key", version, nonce, ciphertext)
	if err != nil {
		return err
	}
	p.APIKey = string(plaintext)
	clearBytes(plaintext)
	return nil
}

func (s *Store) hydrateProviderSecrets(ctx context.Context, query profileSecretQuery, p *coremodel.Profile) error {
	if p == nil {
		return nil
	}
	var version uint32
	var nonce, ciphertext []byte
	if err := query.QueryRow(ctx, `SELECT provider_secrets_key_version,provider_secrets_nonce,provider_secrets_ciphertext FROM core_model_profiles WHERE profile_id=$1 AND revision=$2`, p.ID, p.Revision).Scan(&version, &nonce, &ciphertext); err != nil {
		return err
	}
	if len(ciphertext) == 0 {
		p.ProviderSecrets = nil
		return nil
	}
	plaintext, err := s.openDurableSecret(profileSecretDomain, p.ID, p.Revision, "provider_secrets", version, nonce, ciphertext)
	if err != nil {
		return err
	}
	var values map[string]string
	if err := json.Unmarshal(plaintext, &values); err != nil {
		clearBytes(plaintext)
		return err
	}
	clearBytes(plaintext)
	p.ProviderSecrets = values
	p.ProviderSecretStatus = nil
	return nil
}

func (s *Store) hydrateProfileRevisionSecret(ctx context.Context, query profileSecretQuery, p *coremodel.Profile) error {
	var version uint32
	var nonce, ciphertext []byte
	if err := query.QueryRow(ctx, `SELECT secret_key_version,api_key_nonce,api_key_ciphertext FROM core_model_profile_secret_revisions WHERE profile_id=$1 AND revision=$2`, p.ID, p.Revision).Scan(&version, &nonce, &ciphertext); err != nil {
		return err
	}
	plaintext, err := s.openDurableSecret(profileRevisionDomain, p.ID, p.Revision, "api_key", version, nonce, ciphertext)
	if err != nil {
		return err
	}
	p.APIKey = string(plaintext)
	clearBytes(plaintext)
	return nil
}

func (s *Store) ReplayProfile(ctx context.Context, operation, key, digest string) (coremodel.MutationSnapshot, bool, error) {
	operation = normalizeProfileOperation(operation)
	parsed, err := uuid.Parse(key)
	if err != nil {
		return coremodel.MutationSnapshot{}, false, coremodel.ErrInvalidIdempotencyKey
	}
	if len(digest) != 64 {
		return coremodel.MutationSnapshot{}, false, coremodel.ErrInvalidProfile
	}
	var storedDigest string
	var raw []byte
	err = s.pool.QueryRow(ctx, `SELECT request_hash,response_json FROM core_mutation_replays WHERE operation=$1 AND idempotency_key=$2`, operation, parsed).Scan(&storedDigest, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return coremodel.MutationSnapshot{}, false, nil
	}
	if err != nil {
		return coremodel.MutationSnapshot{}, false, ErrProfileStoreUnavailable
	}
	if storedDigest != digest {
		return coremodel.MutationSnapshot{}, true, coremodel.ErrIdempotencyConflict
	}
	var snap coremodel.MutationSnapshot
	if json.Unmarshal(raw, &snap) != nil {
		return coremodel.MutationSnapshot{}, false, ErrProfileStoreUnavailable
	}
	snap.Replay = true
	// The digest is checked by the atomic mutation transaction. This read-only
	// helper is only an early replay fast path and never authorizes mutation.
	return snap, true, nil
}

func normalizeProfileOperation(operation string) string {
	switch operation {
	case "create":
		return profileCreateOp
	case "update":
		return profileUpdateOp
	case "delete":
		return profileDeleteOp
	default:
		return operation
	}
}

func (s *Store) CreateProfile(ctx context.Context, p coremodel.Profile, key, digest string) (coremodel.MutationSnapshot, error) {
	// Normalize the write boundary so every durable profile row has a positive
	// credential version.
	if p.CredentialVersion <= 0 {
		p.CredentialVersion = 1
	}
	p.CreatedAt = p.CreatedAt.UTC().Truncate(time.Microsecond)
	p.UpdatedAt = p.UpdatedAt.UTC().Truncate(time.Microsecond)
	return s.mutateProfile(ctx, profileCreateOp, key, digest, func(tx pgx.Tx) (coremodel.MutationSnapshot, error) {
		modalities, providerConfig, providerSecretStatus := profileMetadataJSON(p)
		envelope, sealErr := s.sealProfileSecret(p)
		if sealErr != nil {
			return coremodel.MutationSnapshot{}, sealErr
		}
		keyVersion, keyNonce, keyCipher := profileSecretArgs(envelope)
		providerEnvelope, sealErr := s.sealProviderSecrets(p)
		if sealErr != nil {
			return coremodel.MutationSnapshot{}, sealErr
		}
		providerKeyVersion, providerKeyNonce, providerKeyCipher := providerSecretStatusArgs(providerEnvelope)
		_, err := tx.Exec(ctx, `INSERT INTO core_model_profiles (profile_id,client_profile_id,display_name,provider,model_kind,input_modalities,provider_config,provider_secret_status,provider_secrets_key_version,provider_secrets_nonce,provider_secrets_ciphertext,base_url,model_name,system_prompt,api_key_configured,credential_version,api_key_key_version,api_key_nonce,api_key_ciphertext,temperature,top_p,max_output_tokens,context_window,reasoning_effort,revision,created_at,updated_at,request_dialect) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)`, p.ID, nullableClientProfileID(p.ClientProfileID), p.DisplayName, string(p.Provider), p.ModelKind, modalities, providerConfig, providerSecretStatus, providerKeyVersion, providerKeyNonce, providerKeyCipher, p.BaseURL, p.Model, p.SystemPrompt, p.APIKey != "", p.CredentialVersion, keyVersion, keyNonce, keyCipher, p.Temperature, p.TopP, p.MaxOutputTokens, p.ContextWindow, p.ReasoningEffort, p.Revision, p.CreatedAt.UTC(), p.UpdatedAt.UTC(), string(p.RequestDialect))
		if err != nil {
			return coremodel.MutationSnapshot{}, mapProfileDBError(err)
		}
		if p.APIKey != "" {
			revisionEnvelope, revisionErr := s.sealProfileRevisionSecret(p)
			if revisionErr != nil {
				return coremodel.MutationSnapshot{}, revisionErr
			}
			revisionKeyVersion, revisionKeyNonce, revisionKeyCipher := profileSecretArgs(revisionEnvelope)
			if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_secret_revisions(profile_id,revision,secret_key_version,api_key_nonce,api_key_ciphertext) VALUES($1,$2,$3,$4,$5) ON CONFLICT (profile_id,revision) DO NOTHING`, p.ID, p.Revision, revisionKeyVersion, revisionKeyNonce, revisionKeyCipher); err != nil {
				return coremodel.MutationSnapshot{}, mapProfileDBError(err)
			}
		}
		return coremodel.MutationSnapshot{Profile: p.Public()}, nil
	})
}

func (s *Store) GetProfile(ctx context.Context, id string) (coremodel.Profile, error) {
	return s.loadProfile(ctx, id, false)
}
func (s *Store) ResolveProfile(ctx context.Context, id string) (coremodel.Profile, error) {
	return s.loadProfile(ctx, id, true)
}

func (s *Store) GetProfileDefaults(ctx context.Context) (coremodel.ProfileDefaults, error) {
	var out coremodel.ProfileDefaults
	var conversation, tool, embedding, speech *string
	err := s.pool.QueryRow(ctx, `SELECT default_conversation_client_profile_id,default_tool_client_profile_id,default_embedding_client_profile_id,default_speech_client_profile_id FROM core_model_profile_defaults WHERE singleton=true`).Scan(&conversation, &tool, &embedding, &speech)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, ErrProfileStoreUnavailable
	}
	if conversation != nil {
		out.ConversationClientProfileID = *conversation
	}
	if tool != nil {
		out.ToolClientProfileID = *tool
	}
	if embedding != nil {
		out.EmbeddingClientProfileID = *embedding
	}
	if speech != nil {
		out.SpeechClientProfileID = *speech
	}
	return out, nil
}

func (s *Store) RunConnectionTest(ctx context.Context, key, digest, profileID string, test func(coremodel.Profile) coremodel.ConnectionTestResult) (coremodel.ConnectionTestResult, bool, error) {
	id, err := uuid.Parse(key)
	if err != nil {
		return coremodel.ConnectionTestResult{}, false, coremodel.ErrInvalidIdempotencyKey
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coremodel.ConnectionTestResult{}, false, ErrProfileStoreUnavailable
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, profileTestConnectionOp+":"+id.String()); err != nil {
		return coremodel.ConnectionTestResult{}, false, ErrProfileStoreUnavailable
	}
	var storedDigest string
	var raw []byte
	err = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_mutation_replays WHERE operation=$1 AND idempotency_key=$2 FOR UPDATE`, profileTestConnectionOp, id).Scan(&storedDigest, &raw)
	if err == nil {
		if storedDigest != digest {
			return coremodel.ConnectionTestResult{}, true, coremodel.ErrIdempotencyConflict
		}
		var result coremodel.ConnectionTestResult
		if json.Unmarshal(raw, &result) != nil {
			return coremodel.ConnectionTestResult{}, false, ErrProfileStoreUnavailable
		}
		if err := tx.Commit(ctx); err != nil {
			return coremodel.ConnectionTestResult{}, false, ErrProfileStoreUnavailable
		}
		return result, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return coremodel.ConnectionTestResult{}, false, ErrProfileStoreUnavailable
	}
	p, err := scanProfile(tx.QueryRow(ctx, profileSelectColumns+` FROM core_model_profiles WHERE profile_id=$1 AND deleted_at IS NULL`, profileID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coremodel.ConnectionTestResult{ErrorCode: "not_found"}, false, coremodel.ErrProfileNotFound
		}
		return coremodel.ConnectionTestResult{}, false, ErrProfileStoreUnavailable
	}
	if err := s.hydrateProfileSecret(ctx, tx, &p); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coremodel.ConnectionTestResult{ErrorCode: "not_found"}, false, coremodel.ErrProfileNotFound
		}
		return coremodel.ConnectionTestResult{}, false, ErrProfileStoreUnavailable
	}
	if err := s.hydrateProviderSecrets(ctx, tx, &p); err != nil {
		return coremodel.ConnectionTestResult{}, false, ErrProfileStoreUnavailable
	}
	result := test(p)
	encoded, err := json.Marshal(result)
	if err != nil {
		return coremodel.ConnectionTestResult{}, false, ErrProfileStoreUnavailable
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core_mutation_replays (operation,idempotency_key,request_hash,response_json) VALUES ($1,$2,$3,$4)`, profileTestConnectionOp, id, digest, encoded); err != nil {
		return coremodel.ConnectionTestResult{}, false, mapProfileDBError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return coremodel.ConnectionTestResult{}, false, ErrProfileStoreUnavailable
	}
	return result, false, nil
}

func (s *Store) ListProfiles(ctx context.Context, cursor string, limit int) ([]coremodel.Profile, string, error) {
	var after string
	if cursor != "" {
		b, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || uuid.Validate(string(b)) != nil {
			return nil, "", coremodel.ErrInvalidCursor
		}
		after = string(b)
	}
	rows, err := s.pool.Query(ctx, profileSelectColumns+` FROM core_model_profiles WHERE deleted_at IS NULL AND ($1='' OR profile_id > $1::uuid) ORDER BY profile_id LIMIT $2`, after, limit+1)
	if err != nil {
		return nil, "", ErrProfileStoreUnavailable
	}
	defer rows.Close()
	profiles := make([]coremodel.Profile, 0, limit)
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, "", ErrProfileStoreUnavailable
		}
		profiles = append(profiles, p)
		if len(profiles) > limit {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, "", ErrProfileStoreUnavailable
	}
	next := ""
	if len(profiles) > limit {
		profiles = profiles[:limit]
		next = base64.RawURLEncoding.EncodeToString([]byte(profiles[len(profiles)-1].ID))
	}
	return profiles, next, nil
}

func (s *Store) UpdateProfile(ctx context.Context, p coremodel.Profile, key, digest string, expected int64) (coremodel.MutationSnapshot, error) {
	if p.CredentialVersion <= 0 {
		p.CredentialVersion = 1
	}
	p.CreatedAt = p.CreatedAt.UTC().Truncate(time.Microsecond)
	p.UpdatedAt = p.UpdatedAt.UTC().Truncate(time.Microsecond)
	return s.mutateProfile(ctx, profileUpdateOp, key, digest, func(tx pgx.Tx) (coremodel.MutationSnapshot, error) {
		modalities, providerConfig, providerSecretStatus := profileMetadataJSON(p)
		envelope, sealErr := s.sealProfileSecret(p)
		if sealErr != nil {
			return coremodel.MutationSnapshot{}, sealErr
		}
		keyVersion, keyNonce, keyCipher := profileSecretArgs(envelope)
		providerEnvelope, sealErr := s.sealProviderSecrets(p)
		if sealErr != nil {
			return coremodel.MutationSnapshot{}, sealErr
		}
		providerKeyVersion, providerKeyNonce, providerKeyCipher := providerSecretStatusArgs(providerEnvelope)
		result, err := tx.Exec(ctx, `UPDATE core_model_profiles SET display_name=$2,provider=$3,model_kind=$4,input_modalities=$5::jsonb,provider_config=$6::jsonb,provider_secret_status=$7::jsonb,provider_secrets_key_version=$8,provider_secrets_nonce=$9,provider_secrets_ciphertext=$10,base_url=$11,model_name=$12,system_prompt=$13,api_key_configured=$14,credential_version=$15,api_key_key_version=$16,api_key_nonce=$17,api_key_ciphertext=$18,temperature=$19,top_p=$20,max_output_tokens=$21,context_window=$22,reasoning_effort=$23,revision=$24,updated_at=$25,request_dialect=$27 WHERE profile_id=$1 AND deleted_at IS NULL AND revision=$26`, p.ID, p.DisplayName, string(p.Provider), p.ModelKind, modalities, providerConfig, providerSecretStatus, providerKeyVersion, providerKeyNonce, providerKeyCipher, p.BaseURL, p.Model, p.SystemPrompt, p.APIKey != "", p.CredentialVersion, keyVersion, keyNonce, keyCipher, p.Temperature, p.TopP, p.MaxOutputTokens, p.ContextWindow, p.ReasoningEffort, p.Revision, p.UpdatedAt.UTC(), expected, string(p.RequestDialect))
		if err != nil {
			return coremodel.MutationSnapshot{}, mapProfileDBError(err)
		}
		if result.RowsAffected() == 0 {
			return coremodel.MutationSnapshot{}, s.revisionOrNotFound(ctx, tx, p.ID, expected)
		}
		if p.APIKey != "" {
			revisionEnvelope, revisionErr := s.sealProfileRevisionSecret(p)
			if revisionErr != nil {
				return coremodel.MutationSnapshot{}, revisionErr
			}
			revisionKeyVersion, revisionKeyNonce, revisionKeyCipher := profileSecretArgs(revisionEnvelope)
			if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_secret_revisions(profile_id,revision,secret_key_version,api_key_nonce,api_key_ciphertext) VALUES($1,$2,$3,$4,$5) ON CONFLICT (profile_id,revision) DO NOTHING`, p.ID, p.Revision, revisionKeyVersion, revisionKeyNonce, revisionKeyCipher); err != nil {
				return coremodel.MutationSnapshot{}, mapProfileDBError(err)
			}
		}
		return coremodel.MutationSnapshot{Profile: p.Public()}, nil
	})
}

func (s *Store) DeleteProfile(ctx context.Context, id, key, digest string, expected int64) (coremodel.MutationSnapshot, error) {
	return s.mutateProfile(ctx, profileDeleteOp, key, digest, func(tx pgx.Tx) (coremodel.MutationSnapshot, error) {
		p, err := scanProfile(tx.QueryRow(ctx, profileSelectColumns+` FROM core_model_profiles WHERE profile_id=$1 AND deleted_at IS NULL FOR UPDATE`, id))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return coremodel.MutationSnapshot{}, coremodel.ErrProfileNotFound
			}
			return coremodel.MutationSnapshot{}, ErrProfileStoreUnavailable
		}
		if p.Revision != expected {
			return coremodel.MutationSnapshot{}, coremodel.ErrRevisionConflict
		}
		var liveFutureRef bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1
			FROM core_model_profile_active_refs ref
			LEFT JOIN core_schedules schedule ON ref.owner_kind='schedule' AND schedule.schedule_id=ref.owner_id
			WHERE ref.profile_id=$1 AND (
				ref.owner_kind='knowledge_generation' OR
				(ref.owner_kind='schedule' AND schedule.deleted_at IS NULL)
			)
		)`, id).Scan(&liveFutureRef); err != nil {
			return coremodel.MutationSnapshot{}, ErrProfileStoreUnavailable
		}
		if liveFutureRef {
			return coremodel.MutationSnapshot{}, coremodel.ErrProfileInUse
		}
		// Every model kind keeps one tombstoned profile row. Historical
		// conversations and immutable revision snapshots continue to name that
		// row, while the write-facing client id and live credentials are removed.
		if _, err := tx.Exec(ctx, `UPDATE core_model_profiles SET client_profile_id=NULL,api_key_configured=false,api_key_nonce=NULL,api_key_ciphertext=NULL,provider_secrets_nonce=NULL,provider_secrets_ciphertext=NULL,provider_secret_status='{}'::jsonb,deleted_at=clock_timestamp(),updated_at=clock_timestamp() WHERE profile_id=$1`, id); err != nil {
			return coremodel.MutationSnapshot{}, mapProfileDBError(err)
		}
		return coremodel.MutationSnapshot{Profile: p.Public(), Deleted: true}, nil
	})
}

func (s *Store) SyncProfiles(ctx context.Context, key, digest string, cmd coremodel.SyncProfileCommand) (coremodel.SyncProfileResult, error) {
	id, err := uuid.Parse(key)
	if err != nil {
		return coremodel.SyncProfileResult{}, coremodel.ErrInvalidIdempotencyKey
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coremodel.SyncProfileResult{}, ErrProfileStoreUnavailable
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, profileSyncOp+":"+id.String()); err != nil {
		return coremodel.SyncProfileResult{}, ErrProfileStoreUnavailable
	}
	var storedDigest string
	var raw []byte
	err = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_mutation_replays WHERE operation=$1 AND idempotency_key=$2 FOR UPDATE`, profileSyncOp, id).Scan(&storedDigest, &raw)
	if err == nil {
		if storedDigest != digest {
			return coremodel.SyncProfileResult{}, coremodel.ErrIdempotencyConflict
		}
		var out coremodel.SyncProfileResult
		if json.Unmarshal(raw, &out) != nil {
			return coremodel.SyncProfileResult{}, ErrProfileStoreUnavailable
		}
		out.Replay = true
		if err = tx.Commit(ctx); err != nil {
			return coremodel.SyncProfileResult{}, ErrProfileStoreUnavailable
		}
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return coremodel.SyncProfileResult{}, ErrProfileStoreUnavailable
	}
	seen := make(map[string]struct{}, len(cmd.Entries))
	out := coremodel.SyncProfileResult{DefaultConversationProfileID: cmd.DefaultConversationProfileID, DefaultToolProfileID: cmd.DefaultToolProfileID, DefaultEmbeddingProfileID: cmd.DefaultEmbeddingProfileID, DefaultSpeechProfileID: cmd.DefaultSpeechProfileID, Profiles: make([]coremodel.PublicProfile, 0, len(cmd.Entries))}
	for _, e := range cmd.Entries {
		if e.APIKey != nil && *e.APIKey == "" {
			return coremodel.SyncProfileResult{}, coremodel.ErrAPIKeyUnavailable
		}
		if _, ok := seen[e.ClientProfileID]; ok {
			return coremodel.SyncProfileResult{}, coremodel.ErrSyncConflict
		}
		seen[e.ClientProfileID] = struct{}{}
		var p coremodel.Profile
		p, err = scanProfile(tx.QueryRow(ctx, profileSelectColumns+` FROM core_model_profiles WHERE client_profile_id=$1 AND deleted_at IS NULL FOR UPDATE`, e.ClientProfileID))
		exists := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return coremodel.SyncProfileResult{}, ErrProfileStoreUnavailable
		}
		if exists {
			if p.APIKeyConfigured {
				if err = s.hydrateProfileSecret(ctx, tx, &p); err != nil {
					return coremodel.SyncProfileResult{}, ErrProfileStoreUnavailable
				}
			}
			if err = s.hydrateProviderSecrets(ctx, tx, &p); err != nil {
				return coremodel.SyncProfileResult{}, ErrProfileStoreUnavailable
			}
			if e.ExpectedRevision == nil || p.Revision != *e.ExpectedRevision {
				return coremodel.SyncProfileResult{}, coremodel.ErrRevisionConflict
			}
			previous := p
			p.DisplayName, p.Provider, p.RequestDialect, p.ModelKind, p.InputModalities, p.ProviderConfig, p.BaseURL, p.Model, p.SystemPrompt = e.DisplayName, e.Provider, e.RequestDialect, e.ModelKind, append([]string(nil), e.InputModalities...), e.ProviderConfig, e.BaseURL, e.Model, e.SystemPrompt
			if e.ProviderSecrets != nil {
				p.ProviderSecrets = e.ProviderSecrets
			}
			p.Temperature, p.TopP, p.MaxOutputTokens, p.ContextWindow, p.ReasoningEffort = e.Temperature, e.TopP, e.MaxOutputTokens, e.ContextWindow, e.ReasoningEffort
			if e.APIKey != nil {
				p.APIKey = *e.APIKey
			}
			if p.CredentialVersion <= 0 {
				p.CredentialVersion = 1
			}
			p, err = coremodel.ValidateProfile(p)
			if err != nil {
				return coremodel.SyncProfileResult{}, err
			}
			if !previous.SameConfiguration(p) {
				if previous.APIKey != p.APIKey || !equalStringMap(previous.ProviderSecrets, p.ProviderSecrets) {
					p.CredentialVersion++
				}
				p.Revision++
				p.UpdatedAt = time.Now().UTC()
				modalities, providerConfig, providerSecretStatus := profileMetadataJSON(p)
				envelope, sealErr := s.sealProfileSecret(p)
				if sealErr != nil {
					return coremodel.SyncProfileResult{}, sealErr
				}
				keyVersion, keyNonce, keyCipher := profileSecretArgs(envelope)
				providerEnvelope, sealErr := s.sealProviderSecrets(p)
				if sealErr != nil {
					return coremodel.SyncProfileResult{}, sealErr
				}
				providerKeyVersion, providerKeyNonce, providerKeyCipher := providerSecretStatusArgs(providerEnvelope)
				_, err = tx.Exec(ctx, `UPDATE core_model_profiles SET display_name=$2,provider=$3,model_kind=$4,input_modalities=$5::jsonb,provider_config=$6::jsonb,provider_secret_status=$7::jsonb,provider_secrets_key_version=$8,provider_secrets_nonce=$9,provider_secrets_ciphertext=$10,base_url=$11,model_name=$12,system_prompt=$13,api_key_configured=$14,credential_version=$15,api_key_key_version=$16,api_key_nonce=$17,api_key_ciphertext=$18,temperature=$19,top_p=$20,max_output_tokens=$21,context_window=$22,reasoning_effort=$23,revision=$24,updated_at=$25,request_dialect=$26 WHERE profile_id=$1`, p.ID, p.DisplayName, string(p.Provider), p.ModelKind, modalities, providerConfig, providerSecretStatus, providerKeyVersion, providerKeyNonce, providerKeyCipher, p.BaseURL, p.Model, p.SystemPrompt, p.APIKey != "", p.CredentialVersion, keyVersion, keyNonce, keyCipher, p.Temperature, p.TopP, p.MaxOutputTokens, p.ContextWindow, p.ReasoningEffort, p.Revision, p.UpdatedAt, string(p.RequestDialect))
				if err != nil {
					return coremodel.SyncProfileResult{}, mapProfileDBError(err)
				}
				if p.APIKey != "" {
					revisionEnvelope, revisionErr := s.sealProfileRevisionSecret(p)
					if revisionErr != nil {
						return coremodel.SyncProfileResult{}, revisionErr
					}
					revisionKeyVersion, revisionKeyNonce, revisionKeyCipher := profileSecretArgs(revisionEnvelope)
					if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_secret_revisions(profile_id,revision,secret_key_version,api_key_nonce,api_key_ciphertext) VALUES($1,$2,$3,$4,$5) ON CONFLICT (profile_id,revision) DO NOTHING`, p.ID, p.Revision, revisionKeyVersion, revisionKeyNonce, revisionKeyCipher); err != nil {
						return coremodel.SyncProfileResult{}, mapProfileDBError(err)
					}
				}
			}
		} else {
			if e.ExpectedRevision != nil {
				return coremodel.SyncProfileResult{}, coremodel.ErrRevisionConflict
			}
			profileID := deterministicSyncProfileID(e.ClientProfileID)
			var retired coremodel.Profile
			retired, err = scanProfile(tx.QueryRow(ctx, profileSelectColumns+` FROM core_model_profiles WHERE profile_id=$1 AND deleted_at IS NOT NULL FOR UPDATE`, profileID))
			retiredExists := err == nil
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return coremodel.SyncProfileResult{}, ErrProfileStoreUnavailable
			}
			if retiredExists && e.APIKey == nil {
				return coremodel.SyncProfileResult{}, coremodel.ErrAPIKeyUnavailable
			}
			now := time.Now().UTC()
			revision, credentialVersion, createdAt := int64(1), int64(1), now
			if retiredExists {
				revision = retired.Revision + 1
				credentialVersion = retired.CredentialVersion + 1
				createdAt = retired.CreatedAt
			}
			p = coremodel.Profile{ID: profileID, ClientProfileID: e.ClientProfileID, DisplayName: e.DisplayName, Provider: e.Provider, RequestDialect: e.RequestDialect, ModelKind: e.ModelKind, InputModalities: append([]string(nil), e.InputModalities...), ProviderConfig: e.ProviderConfig, ProviderSecrets: e.ProviderSecrets, BaseURL: e.BaseURL, Model: e.Model, APIKey: valueOrEmpty(e.APIKey), SystemPrompt: e.SystemPrompt, Temperature: e.Temperature, TopP: e.TopP, MaxOutputTokens: e.MaxOutputTokens, ContextWindow: e.ContextWindow, ReasoningEffort: e.ReasoningEffort, Revision: revision, CredentialVersion: credentialVersion, CreatedAt: createdAt, UpdatedAt: now}
			p, err = coremodel.ValidateProfile(p)
			if err != nil {
				return coremodel.SyncProfileResult{}, err
			}
			modalities, providerConfig, providerSecretStatus := profileMetadataJSON(p)
			envelope, sealErr := s.sealProfileSecret(p)
			if sealErr != nil {
				return coremodel.SyncProfileResult{}, sealErr
			}
			keyVersion, keyNonce, keyCipher := profileSecretArgs(envelope)
			providerEnvelope, sealErr := s.sealProviderSecrets(p)
			if sealErr != nil {
				return coremodel.SyncProfileResult{}, sealErr
			}
			providerKeyVersion, providerKeyNonce, providerKeyCipher := providerSecretStatusArgs(providerEnvelope)
			if retiredExists {
				_, err = tx.Exec(ctx, `UPDATE core_model_profiles SET client_profile_id=$2,display_name=$3,provider=$4,model_kind=$5,input_modalities=$6::jsonb,provider_config=$7::jsonb,provider_secret_status=$8::jsonb,provider_secrets_key_version=$9,provider_secrets_nonce=$10,provider_secrets_ciphertext=$11,base_url=$12,model_name=$13,system_prompt=$14,api_key_configured=$15,credential_version=$16,api_key_key_version=$17,api_key_nonce=$18,api_key_ciphertext=$19,temperature=$20,top_p=$21,max_output_tokens=$22,context_window=$23,reasoning_effort=$24,revision=$25,deleted_at=NULL,updated_at=$26,request_dialect=$27 WHERE profile_id=$1 AND deleted_at IS NOT NULL`, p.ID, p.ClientProfileID, p.DisplayName, string(p.Provider), p.ModelKind, modalities, providerConfig, providerSecretStatus, providerKeyVersion, providerKeyNonce, providerKeyCipher, p.BaseURL, p.Model, p.SystemPrompt, p.APIKey != "", p.CredentialVersion, keyVersion, keyNonce, keyCipher, p.Temperature, p.TopP, p.MaxOutputTokens, p.ContextWindow, p.ReasoningEffort, p.Revision, p.UpdatedAt, string(p.RequestDialect))
			} else {
				_, err = tx.Exec(ctx, `INSERT INTO core_model_profiles (profile_id,client_profile_id,display_name,provider,model_kind,input_modalities,provider_config,provider_secret_status,provider_secrets_key_version,provider_secrets_nonce,provider_secrets_ciphertext,base_url,model_name,system_prompt,api_key_configured,credential_version,api_key_key_version,api_key_nonce,api_key_ciphertext,temperature,top_p,max_output_tokens,context_window,reasoning_effort,revision,created_at,updated_at,request_dialect) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)`, p.ID, p.ClientProfileID, p.DisplayName, string(p.Provider), p.ModelKind, modalities, providerConfig, providerSecretStatus, providerKeyVersion, providerKeyNonce, providerKeyCipher, p.BaseURL, p.Model, p.SystemPrompt, p.APIKey != "", p.CredentialVersion, keyVersion, keyNonce, keyCipher, p.Temperature, p.TopP, p.MaxOutputTokens, p.ContextWindow, p.ReasoningEffort, p.Revision, p.CreatedAt, p.UpdatedAt, string(p.RequestDialect))
			}
			if err != nil {
				return coremodel.SyncProfileResult{}, mapProfileDBError(err)
			}
			if p.APIKey != "" {
				revisionEnvelope, revisionErr := s.sealProfileRevisionSecret(p)
				if revisionErr != nil {
					return coremodel.SyncProfileResult{}, revisionErr
				}
				revisionKeyVersion, revisionKeyNonce, revisionKeyCipher := profileSecretArgs(revisionEnvelope)
				if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_secret_revisions(profile_id,revision,secret_key_version,api_key_nonce,api_key_ciphertext) VALUES($1,$2,$3,$4,$5) ON CONFLICT (profile_id,revision) DO NOTHING`, p.ID, p.Revision, revisionKeyVersion, revisionKeyNonce, revisionKeyCipher); err != nil {
					return coremodel.SyncProfileResult{}, mapProfileDBError(err)
				}
			}
		}
		out.Profiles = append(out.Profiles, p.Public())
	}
	for _, binding := range []struct {
		value string
		kind  string
	}{
		{out.DefaultConversationProfileID, coremodel.ModelKindConversation},
		{out.DefaultToolProfileID, coremodel.ModelKindConversation},
		{out.DefaultEmbeddingProfileID, coremodel.ModelKindEmbedding},
		{out.DefaultSpeechProfileID, coremodel.ModelKindSpeech},
	} {
		if binding.value == "" {
			continue
		}
		var kind string
		if err = tx.QueryRow(ctx, `SELECT model_kind FROM core_model_profiles WHERE client_profile_id=$1 AND deleted_at IS NULL`, binding.value).Scan(&kind); errors.Is(err, pgx.ErrNoRows) {
			return coremodel.SyncProfileResult{}, coremodel.ErrProfileNotFound
		}
		if err != nil {
			return coremodel.SyncProfileResult{}, ErrProfileStoreUnavailable
		}
		if kind != binding.kind {
			return coremodel.SyncProfileResult{}, coremodel.ErrInvalidProfile
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_defaults(singleton,default_conversation_client_profile_id,default_tool_client_profile_id,default_embedding_client_profile_id,default_speech_client_profile_id,updated_at) VALUES(true,$1,$2,$3,$4,clock_timestamp()) ON CONFLICT (singleton) DO UPDATE SET default_conversation_client_profile_id=EXCLUDED.default_conversation_client_profile_id,default_tool_client_profile_id=EXCLUDED.default_tool_client_profile_id,default_embedding_client_profile_id=EXCLUDED.default_embedding_client_profile_id,default_speech_client_profile_id=EXCLUDED.default_speech_client_profile_id,updated_at=EXCLUDED.updated_at`, nullableClientProfileID(out.DefaultConversationProfileID), nullableClientProfileID(out.DefaultToolProfileID), nullableClientProfileID(out.DefaultEmbeddingProfileID), nullableClientProfileID(out.DefaultSpeechProfileID)); err != nil {
		return coremodel.SyncProfileResult{}, mapProfileDBError(err)
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return coremodel.SyncProfileResult{}, ErrProfileStoreUnavailable
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_mutation_replays(operation,idempotency_key,request_hash,response_json) VALUES($1,$2,$3,$4)`, profileSyncOp, id, digest, encoded); err != nil {
		return coremodel.SyncProfileResult{}, mapProfileDBError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return coremodel.SyncProfileResult{}, ErrProfileStoreUnavailable
	}
	return out, nil
}

func deterministicSyncProfileID(clientID string) string {
	return coremodel.SyncProfileID(clientID)
}

func (s *Store) mutateProfile(ctx context.Context, operation, key, digest string, apply func(pgx.Tx) (coremodel.MutationSnapshot, error)) (coremodel.MutationSnapshot, error) {
	id, err := uuid.Parse(key)
	if err != nil {
		return coremodel.MutationSnapshot{}, coremodel.ErrInvalidIdempotencyKey
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coremodel.MutationSnapshot{}, ErrProfileStoreUnavailable
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, operation+":"+id.String()); err != nil {
		return coremodel.MutationSnapshot{}, ErrProfileStoreUnavailable
	}
	var storedDigest string
	var raw []byte
	err = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_mutation_replays WHERE operation=$1 AND idempotency_key=$2 FOR UPDATE`, operation, id).Scan(&storedDigest, &raw)
	if err == nil {
		if storedDigest != digest {
			return coremodel.MutationSnapshot{}, coremodel.ErrIdempotencyConflict
		}
		var snap coremodel.MutationSnapshot
		if json.Unmarshal(raw, &snap) != nil {
			return coremodel.MutationSnapshot{}, ErrProfileStoreUnavailable
		}
		snap.Replay = true
		if err := tx.Commit(ctx); err != nil {
			return coremodel.MutationSnapshot{}, ErrProfileStoreUnavailable
		}
		return snap, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return coremodel.MutationSnapshot{}, ErrProfileStoreUnavailable
	}
	snap, err := apply(tx)
	if err != nil {
		return coremodel.MutationSnapshot{}, err
	}
	encoded, err := json.Marshal(snap)
	if err != nil {
		return coremodel.MutationSnapshot{}, ErrProfileStoreUnavailable
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core_mutation_replays (operation,idempotency_key,request_hash,response_json) VALUES ($1,$2,$3,$4)`, operation, id, digest, encoded); err != nil {
		return coremodel.MutationSnapshot{}, mapProfileDBError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return coremodel.MutationSnapshot{}, ErrProfileStoreUnavailable
	}
	return snap, nil
}

func (s *Store) loadProfile(ctx context.Context, id string, requireKey bool) (coremodel.Profile, error) {
	p, err := scanProfile(s.pool.QueryRow(ctx, profileSelectColumns+` FROM core_model_profiles WHERE profile_id=$1 AND deleted_at IS NULL`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coremodel.Profile{}, coremodel.ErrProfileNotFound
		}
		return coremodel.Profile{}, ErrProfileStoreUnavailable
	}
	if requireKey {
		if p.APIKeyConfigured {
			if err := s.hydrateProfileSecret(ctx, s.pool, &p); err != nil {
				return coremodel.Profile{}, coremodel.ErrAPIKeyUnavailable
			}
		}
		if err := s.hydrateProviderSecrets(ctx, s.pool, &p); err != nil {
			return coremodel.Profile{}, coremodel.ErrAPIKeyUnavailable
		}
		if p.APIKeyConfigured && p.APIKey == "" {
			return coremodel.Profile{}, coremodel.ErrAPIKeyUnavailable
		}
	}
	return p, nil
}

type profileScanner interface{ Scan(...any) error }

const profileSelectColumns = `SELECT profile_id,client_profile_id,display_name,provider,model_kind,input_modalities,provider_config,provider_secret_status,base_url,model_name,system_prompt,api_key_configured,credential_version,temperature,top_p,max_output_tokens,context_window,reasoning_effort,revision,created_at,updated_at,request_dialect`

func scanProfile(row profileScanner) (coremodel.Profile, error) {
	var id, clientID, name, provider, modelKind, base, model, prompt, requestDialect string
	var clientIDPtr *string
	var modalitiesJSON, providerConfigJSON, providerSecretStatusJSON []byte
	var configured bool
	var credentialVersion int64
	var temperature, topP *float64
	var max, contextWindow int
	var reasoning string
	var revision int64
	var created, updated time.Time
	if err := row.Scan(&id, &clientIDPtr, &name, &provider, &modelKind, &modalitiesJSON, &providerConfigJSON, &providerSecretStatusJSON, &base, &model, &prompt, &configured, &credentialVersion, &temperature, &topP, &max, &contextWindow, &reasoning, &revision, &created, &updated, &requestDialect); err != nil {
		return coremodel.Profile{}, err
	}
	if clientIDPtr != nil {
		clientID = *clientIDPtr
	}
	var modalities []string
	var providerConfig map[string]any
	var providerSecretStatus map[string]bool
	_ = json.Unmarshal(modalitiesJSON, &modalities)
	_ = json.Unmarshal(providerConfigJSON, &providerConfig)
	_ = json.Unmarshal(providerSecretStatusJSON, &providerSecretStatus)
	if credentialVersion <= 0 {
		credentialVersion = revision
	}
	return coremodel.Profile{ID: id, ClientProfileID: clientID, DisplayName: name, Provider: coremodel.ModelProvider(provider), RequestDialect: coremodel.RequestDialect(requestDialect), ModelKind: modelKind, InputModalities: modalities, ProviderConfig: providerConfig, ProviderSecrets: nil, ProviderSecretStatus: providerSecretStatus, BaseURL: base, Model: model, APIKey: "", APIKeyConfigured: configured, SystemPrompt: prompt, Temperature: cloneFloat(temperature), TopP: cloneFloat(topP), MaxOutputTokens: max, ContextWindow: contextWindow, ReasoningEffort: reasoning, Revision: revision, CredentialVersion: credentialVersion, CreatedAt: created.UTC(), UpdatedAt: updated.UTC()}, nil
}

func profileMetadataJSON(p coremodel.Profile) ([]byte, []byte, []byte) {
	modalities, _ := json.Marshal(p.InputModalities)
	if len(modalities) == 0 || string(modalities) == "null" {
		modalities = []byte(`[]`)
	}
	// Provider config is metadata, but clients may still nest credential-like
	// keys under arbitrary provider-specific objects. Persist only the same
	// recursively redacted projection exposed by the public profile boundary.
	providerConfig, _ := json.Marshal(p.Public().ProviderConfig)
	if len(providerConfig) == 0 || string(providerConfig) == "null" {
		providerConfig = []byte(`{}`)
	}
	status := make(map[string]bool, len(p.ProviderSecrets))
	for key, value := range p.ProviderSecrets {
		key = strings.TrimSpace(key)
		if key != "" {
			status[key] = strings.TrimSpace(value) != ""
		}
	}
	if len(status) == 0 && len(p.ProviderSecretStatus) > 0 {
		status = make(map[string]bool, len(p.ProviderSecretStatus))
		for key, value := range p.ProviderSecretStatus {
			status[key] = value
		}
	}
	providerSecretStatus, _ := json.Marshal(status)
	if len(providerSecretStatus) == 0 || string(providerSecretStatus) == "null" {
		providerSecretStatus = []byte(`{}`)
	}
	return modalities, providerConfig, providerSecretStatus
}
func cloneFloat(v *float64) *float64 {
	if v == nil {
		return nil
	}
	x := *v
	return &x
}
func nullableKey(key string) any {
	if key == "" {
		return nil
	}
	return key
}
func nullableClientProfileID(id string) any {
	if id == "" {
		return nil
	}
	return id
}

func valueOrEmpty(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func equalStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func (s *Store) revisionOrNotFound(ctx context.Context, tx pgx.Tx, id string, expected int64) error {
	var revision int64
	err := tx.QueryRow(ctx, `SELECT revision FROM core_model_profiles WHERE profile_id=$1 AND deleted_at IS NULL`, id).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return coremodel.ErrProfileNotFound
	}
	if err != nil {
		return ErrProfileStoreUnavailable
	}
	if revision != expected {
		return coremodel.ErrRevisionConflict
	}
	return coremodel.ErrRevisionConflict
}

var ErrProfileStoreUnavailable = errors.New("model profile store unavailable")

func mapProfileDBError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return coremodel.ErrProfileNotFound
	}
	return ErrProfileStoreUnavailable
}

var _ coremodel.ProfileRepository = (*Store)(nil)
