package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	profileCreateOp         = "model_profile.create"
	profileUpdateOp         = "model_profile.update"
	profileDeleteOp         = "model_profile.delete"
	profileTestConnectionOp = "model_profile.test_connection"
	profileSyncOp           = "model_profile.sync"
)

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
	p.CreatedAt = p.CreatedAt.UTC().Truncate(time.Microsecond)
	p.UpdatedAt = p.UpdatedAt.UTC().Truncate(time.Microsecond)
	return s.mutateProfile(ctx, profileCreateOp, key, digest, func(tx pgx.Tx) (coremodel.MutationSnapshot, error) {
		_, err := tx.Exec(ctx, `INSERT INTO core_model_profiles (profile_id,client_profile_id,display_name,provider,base_url,model_name,system_prompt,api_key,api_key_configured,temperature,top_p,max_output_tokens,context_window,reasoning_effort,revision,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, p.ID, nullableClientProfileID(p.ClientProfileID), p.DisplayName, string(p.Provider), p.BaseURL, p.Model, p.SystemPrompt, nullableKey(p.APIKey), p.APIKey != "", p.Temperature, p.TopP, p.MaxOutputTokens, p.ContextWindow, p.ReasoningEffort, p.Revision, p.CreatedAt.UTC(), p.UpdatedAt.UTC())
		if err != nil {
			return coremodel.MutationSnapshot{}, mapProfileDBError(err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_secret_revisions(profile_id,revision,api_key) VALUES($1,$2,$3) ON CONFLICT (profile_id,revision) DO NOTHING`, p.ID, p.Revision, p.APIKey); err != nil {
			return coremodel.MutationSnapshot{}, mapProfileDBError(err)
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
	p, err := scanProfile(tx.QueryRow(ctx, `SELECT profile_id,client_profile_id,display_name,provider,base_url,model_name,system_prompt,api_key,api_key_configured,temperature,top_p,max_output_tokens,context_window,reasoning_effort,revision,created_at,updated_at FROM core_model_profiles WHERE profile_id=$1 AND deleted_at IS NULL`, profileID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coremodel.ConnectionTestResult{ErrorCode: "not_found"}, false, coremodel.ErrProfileNotFound
		}
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
	rows, err := s.pool.Query(ctx, `SELECT profile_id,client_profile_id,display_name,provider,base_url,model_name,system_prompt,api_key,api_key_configured,temperature,top_p,max_output_tokens,context_window,reasoning_effort,revision,created_at,updated_at FROM core_model_profiles WHERE deleted_at IS NULL AND ($1='' OR profile_id > $1::uuid) ORDER BY profile_id LIMIT $2`, after, limit+1)
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
	p.CreatedAt = p.CreatedAt.UTC().Truncate(time.Microsecond)
	p.UpdatedAt = p.UpdatedAt.UTC().Truncate(time.Microsecond)
	return s.mutateProfile(ctx, profileUpdateOp, key, digest, func(tx pgx.Tx) (coremodel.MutationSnapshot, error) {
		var refs int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM core_model_profile_active_refs WHERE profile_id=$1`, p.ID).Scan(&refs); err != nil {
			return coremodel.MutationSnapshot{}, ErrProfileStoreUnavailable
		}
		if refs > 0 {
			return coremodel.MutationSnapshot{}, coremodel.ErrProfileInUse
		}
		result, err := tx.Exec(ctx, `UPDATE core_model_profiles SET display_name=$2,provider=$3,base_url=$4,model_name=$5,system_prompt=$6,api_key=$7,api_key_configured=$8,temperature=$9,top_p=$10,max_output_tokens=$11,context_window=$12,reasoning_effort=$13,revision=$14,updated_at=$15 WHERE profile_id=$1 AND deleted_at IS NULL AND revision=$16`, p.ID, p.DisplayName, string(p.Provider), p.BaseURL, p.Model, p.SystemPrompt, nullableKey(p.APIKey), p.APIKey != "", p.Temperature, p.TopP, p.MaxOutputTokens, p.ContextWindow, p.ReasoningEffort, p.Revision, p.UpdatedAt.UTC(), expected)
		if err != nil {
			return coremodel.MutationSnapshot{}, mapProfileDBError(err)
		}
		if result.RowsAffected() == 0 {
			return coremodel.MutationSnapshot{}, s.revisionOrNotFound(ctx, tx, p.ID, expected)
		}
		if p.APIKey != "" {
			if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_secret_revisions(profile_id,revision,api_key) VALUES($1,$2,$3) ON CONFLICT (profile_id,revision) DO NOTHING`, p.ID, p.Revision, p.APIKey); err != nil {
				return coremodel.MutationSnapshot{}, mapProfileDBError(err)
			}
		}
		return coremodel.MutationSnapshot{Profile: p.Public()}, nil
	})
}

func (s *Store) DeleteProfile(ctx context.Context, id, key, digest string, expected int64) (coremodel.MutationSnapshot, error) {
	return s.mutateProfile(ctx, profileDeleteOp, key, digest, func(tx pgx.Tx) (coremodel.MutationSnapshot, error) {
		p, err := scanProfile(tx.QueryRow(ctx, `SELECT profile_id,client_profile_id,display_name,provider,base_url,model_name,system_prompt,api_key,api_key_configured,temperature,top_p,max_output_tokens,context_window,reasoning_effort,revision,created_at,updated_at FROM core_model_profiles WHERE profile_id=$1 AND deleted_at IS NULL FOR UPDATE`, id))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return coremodel.MutationSnapshot{}, coremodel.ErrProfileNotFound
			}
			return coremodel.MutationSnapshot{}, ErrProfileStoreUnavailable
		}
		if p.Revision != expected {
			return coremodel.MutationSnapshot{}, coremodel.ErrRevisionConflict
		}
		var refs int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM core_model_profile_active_refs WHERE profile_id=$1`, id).Scan(&refs); err != nil {
			return coremodel.MutationSnapshot{}, ErrProfileStoreUnavailable
		}
		if refs > 0 {
			return coremodel.MutationSnapshot{}, coremodel.ErrProfileInUse
		}
		// Secret revisions are immutable task snapshot material. They may be
		// retired only when no durable task snapshot still names this profile;
		// otherwise the FK deliberately turns deletion into a conflict.
		if _, err := tx.Exec(ctx, `DELETE FROM core_model_profile_secret_revisions WHERE profile_id=$1 AND NOT EXISTS (SELECT 1 FROM core_task_execution_snapshots WHERE snapshot_json->'model'->>'profile_id'=$1::text)`, id); err != nil {
			return coremodel.MutationSnapshot{}, mapProfileDBError(err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM core_model_profiles WHERE profile_id=$1`, id); err != nil {
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
	out := coremodel.SyncProfileResult{DefaultClientProfileID: cmd.DefaultClientProfileID, Profiles: make([]coremodel.PublicProfile, 0, len(cmd.Entries))}
	for _, e := range cmd.Entries {
		if e.APIKey != nil && *e.APIKey == "" {
			return coremodel.SyncProfileResult{}, coremodel.ErrAPIKeyUnavailable
		}
		if _, ok := seen[e.ClientProfileID]; ok {
			return coremodel.SyncProfileResult{}, coremodel.ErrSyncConflict
		}
		seen[e.ClientProfileID] = struct{}{}
		var p coremodel.Profile
		p, err = scanProfile(tx.QueryRow(ctx, `SELECT profile_id,client_profile_id,display_name,provider,base_url,model_name,system_prompt,api_key,api_key_configured,temperature,top_p,max_output_tokens,context_window,reasoning_effort,revision,created_at,updated_at FROM core_model_profiles WHERE client_profile_id=$1 AND deleted_at IS NULL FOR UPDATE`, e.ClientProfileID))
		exists := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return coremodel.SyncProfileResult{}, ErrProfileStoreUnavailable
		}
		if exists {
			if e.ExpectedRevision == nil || p.Revision != *e.ExpectedRevision {
				return coremodel.SyncProfileResult{}, coremodel.ErrRevisionConflict
			}
			p.DisplayName, p.Provider, p.BaseURL, p.Model, p.SystemPrompt = e.DisplayName, e.Provider, e.BaseURL, e.Model, e.SystemPrompt
			p.Temperature, p.TopP, p.MaxOutputTokens, p.ContextWindow, p.ReasoningEffort = e.Temperature, e.TopP, e.MaxOutputTokens, e.ContextWindow, e.ReasoningEffort
			if e.APIKey != nil {
				p.APIKey = *e.APIKey
			}
			p.Revision++
			p.UpdatedAt = time.Now().UTC()
			p, err = coremodel.ValidateProfile(p)
			if err != nil {
				return coremodel.SyncProfileResult{}, err
			}
			_, err = tx.Exec(ctx, `UPDATE core_model_profiles SET display_name=$2,provider=$3,base_url=$4,model_name=$5,system_prompt=$6,api_key=$7,api_key_configured=$8,temperature=$9,top_p=$10,max_output_tokens=$11,context_window=$12,reasoning_effort=$13,revision=$14,updated_at=$15 WHERE profile_id=$1`, p.ID, p.DisplayName, string(p.Provider), p.BaseURL, p.Model, p.SystemPrompt, nullableKey(p.APIKey), p.APIKey != "", p.Temperature, p.TopP, p.MaxOutputTokens, p.ContextWindow, p.ReasoningEffort, p.Revision, p.UpdatedAt)
			if err != nil {
				return coremodel.SyncProfileResult{}, mapProfileDBError(err)
			}
			if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_secret_revisions(profile_id,revision,api_key) VALUES($1,$2,$3) ON CONFLICT (profile_id,revision) DO NOTHING`, p.ID, p.Revision, p.APIKey); err != nil {
				return coremodel.SyncProfileResult{}, mapProfileDBError(err)
			}
		} else {
			if e.ExpectedRevision != nil {
				return coremodel.SyncProfileResult{}, coremodel.ErrRevisionConflict
			}
			p = coremodel.Profile{ID: deterministicSyncProfileID(e.ClientProfileID), ClientProfileID: e.ClientProfileID, DisplayName: e.DisplayName, Provider: e.Provider, BaseURL: e.BaseURL, Model: e.Model, APIKey: valueOrEmpty(e.APIKey), SystemPrompt: e.SystemPrompt, Temperature: e.Temperature, TopP: e.TopP, MaxOutputTokens: e.MaxOutputTokens, ContextWindow: e.ContextWindow, ReasoningEffort: e.ReasoningEffort, Revision: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
			p, err = coremodel.ValidateProfile(p)
			if err != nil {
				return coremodel.SyncProfileResult{}, err
			}
			_, err = tx.Exec(ctx, `INSERT INTO core_model_profiles (profile_id,client_profile_id,display_name,provider,base_url,model_name,system_prompt,api_key,api_key_configured,temperature,top_p,max_output_tokens,context_window,reasoning_effort,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, p.ID, p.ClientProfileID, p.DisplayName, string(p.Provider), p.BaseURL, p.Model, p.SystemPrompt, nullableKey(p.APIKey), true, p.Temperature, p.TopP, p.MaxOutputTokens, p.ContextWindow, p.ReasoningEffort, p.Revision, p.CreatedAt, p.UpdatedAt)
			if err != nil {
				return coremodel.SyncProfileResult{}, mapProfileDBError(err)
			}
			if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_secret_revisions(profile_id,revision,api_key) VALUES($1,$2,$3) ON CONFLICT (profile_id,revision) DO NOTHING`, p.ID, p.Revision, p.APIKey); err != nil {
				return coremodel.SyncProfileResult{}, mapProfileDBError(err)
			}
		}
		out.Profiles = append(out.Profiles, p.Public())
	}
	if out.DefaultClientProfileID != "" {
		var exists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM core_model_profiles WHERE client_profile_id=$1 AND deleted_at IS NULL)`, out.DefaultClientProfileID).Scan(&exists); err != nil {
			return coremodel.SyncProfileResult{}, ErrProfileStoreUnavailable
		}
		if !exists {
			return coremodel.SyncProfileResult{}, coremodel.ErrProfileNotFound
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_defaults(singleton,default_client_profile_id,updated_at) VALUES(true,$1,clock_timestamp()) ON CONFLICT (singleton) DO UPDATE SET default_client_profile_id=EXCLUDED.default_client_profile_id,updated_at=EXCLUDED.updated_at`, nullableClientProfileID(out.DefaultClientProfileID)); err != nil {
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
	p, err := scanProfile(s.pool.QueryRow(ctx, `SELECT profile_id,client_profile_id,display_name,provider,base_url,model_name,system_prompt,api_key,api_key_configured,temperature,top_p,max_output_tokens,context_window,reasoning_effort,revision,created_at,updated_at FROM core_model_profiles WHERE profile_id=$1 AND deleted_at IS NULL`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coremodel.Profile{}, coremodel.ErrProfileNotFound
		}
		return coremodel.Profile{}, ErrProfileStoreUnavailable
	}
	if requireKey && p.APIKey == "" {
		return coremodel.Profile{}, coremodel.ErrAPIKeyUnavailable
	}
	return p, nil
}

type profileScanner interface{ Scan(...any) error }

func scanProfile(row profileScanner) (coremodel.Profile, error) {
	var id, clientID, name, provider, base, model, prompt string
	var clientIDPtr *string
	var key *string
	var configured bool
	var temperature, topP *float64
	var max, contextWindow int
	var reasoning string
	var revision int64
	var created, updated time.Time
	if err := row.Scan(&id, &clientIDPtr, &name, &provider, &base, &model, &prompt, &key, &configured, &temperature, &topP, &max, &contextWindow, &reasoning, &revision, &created, &updated); err != nil {
		return coremodel.Profile{}, err
	}
	if clientIDPtr != nil {
		clientID = *clientIDPtr
	}
	p := coremodel.Profile{ID: id, ClientProfileID: clientID, DisplayName: name, Provider: coremodel.ModelProvider(provider), BaseURL: base, Model: model, APIKey: "", SystemPrompt: prompt, Temperature: cloneFloat(temperature), TopP: cloneFloat(topP), MaxOutputTokens: max, ContextWindow: contextWindow, ReasoningEffort: reasoning, Revision: revision, CreatedAt: created.UTC(), UpdatedAt: updated.UTC()}
	if key != nil {
		p.APIKey = *key
	}
	return p, nil
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
