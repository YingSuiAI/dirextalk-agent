package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfig"
	"github.com/jackc/pgx/v5"
)

const systemPromptUpdateOperation = "agent.system_prompt.update"

func (s *CoreAgentConfigStore) GetSystemPrompt(ctx context.Context) (coreconfig.SystemPrompt, error) {
	var value coreconfig.SystemPrompt
	if s == nil || s.store == nil || s.store.pool == nil {
		return value, coreconfig.ErrInvalid
	}
	err := s.store.pool.QueryRow(ctx, `SELECT revision,system_prompt FROM agent_system_prompt WHERE singleton`).Scan(&value.Revision, &value.Prompt)
	if errors.Is(err, pgx.ErrNoRows) {
		return value, nil
	}
	return value, err
}

func (s *CoreAgentConfigStore) UpdateSystemPrompt(ctx context.Context, owner string, update coreconfig.SystemPromptUpdate) (coreconfig.SystemPrompt, error) {
	if s == nil || s.store == nil || s.store.pool == nil {
		return coreconfig.SystemPrompt{}, coreconfig.ErrInvalid
	}
	hash, err := update.Digest(owner)
	if err != nil {
		return coreconfig.SystemPrompt{}, err
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return coreconfig.SystemPrompt{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	// Serialize the first insert as well as subsequent writes and replay checks.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, systemPromptUpdateOperation); err != nil {
		return coreconfig.SystemPrompt{}, err
	}
	var previousHash string
	var previousJSON []byte
	err = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_mutation_replays WHERE operation=$1 AND idempotency_key=$2`, systemPromptUpdateOperation, update.IdempotencyKey).Scan(&previousHash, &previousJSON)
	if err == nil {
		if previousHash != hash {
			return coreconfig.SystemPrompt{}, coreconfig.ErrConflict
		}
		var previous coreconfig.SystemPrompt
		if err = json.Unmarshal(previousJSON, &previous); err != nil {
			return coreconfig.SystemPrompt{}, err
		}
		return previous, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return coreconfig.SystemPrompt{}, err
	}
	var revision int64
	err = tx.QueryRow(ctx, `SELECT revision FROM agent_system_prompt WHERE singleton FOR UPDATE`).Scan(&revision)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return coreconfig.SystemPrompt{}, err
	}
	if revision != update.ExpectedRevision {
		return coreconfig.SystemPrompt{}, coreconfig.ErrConflict
	}
	next := coreconfig.SystemPrompt{Revision: revision + 1, Prompt: update.Prompt}
	_, err = tx.Exec(ctx, `INSERT INTO agent_system_prompt(singleton,system_prompt,revision) VALUES(true,$1,$2) ON CONFLICT(singleton) DO UPDATE SET system_prompt=EXCLUDED.system_prompt,revision=EXCLUDED.revision`, next.Prompt, next.Revision)
	if err != nil {
		return coreconfig.SystemPrompt{}, err
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return coreconfig.SystemPrompt{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO core_mutation_replays(operation,idempotency_key,request_hash,response_json) VALUES($1,$2,$3,$4::jsonb)`, systemPromptUpdateOperation, update.IdempotencyKey, hash, raw)
	if err != nil {
		return coreconfig.SystemPrompt{}, err
	}
	return next, tx.Commit(ctx)
}
