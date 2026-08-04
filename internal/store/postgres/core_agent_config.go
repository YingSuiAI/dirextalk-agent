package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfig"
	"github.com/jackc/pgx/v5"
)

// CoreAgentConfigStore persists only Native Agent configuration. The Online
// Matrix identity is intentionally not represented here.
type CoreAgentConfigStore struct{ store *Store }

func NewCoreAgentConfigStore(store *Store) *CoreAgentConfigStore {
	return &CoreAgentConfigStore{store: store}
}

func (s *CoreAgentConfigStore) Get(ctx context.Context, owner string) (coreconfig.Config, error) {
	if s == nil || s.store == nil || s.store.pool == nil || strings.TrimSpace(owner) == "" {
		return coreconfig.Config{}, coreconfig.ErrInvalid
	}
	var raw []byte
	var revision int64
	err := s.store.pool.QueryRow(ctx, `SELECT config_json,revision FROM agent_native_configs WHERE owner_id=$1`, strings.TrimSpace(owner)).Scan(&raw, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return coreconfig.Default(), nil
	}
	if err != nil {
		return coreconfig.Config{}, fmt.Errorf("read native agent config: %w", err)
	}
	var value coreconfig.Config
	if err := json.Unmarshal(raw, &value); err != nil {
		return coreconfig.Config{}, fmt.Errorf("decode native agent config: %w", err)
	}
	value.Revision = revision
	return value.Normalize(), nil
}

func (s *CoreAgentConfigStore) Update(ctx context.Context, owner string, update coreconfig.Update) (coreconfig.Config, error) {
	owner = strings.TrimSpace(owner)
	if s == nil || s.store == nil || s.store.pool == nil || owner == "" {
		return coreconfig.Config{}, coreconfig.ErrInvalid
	}
	if err := coreconfig.ValidateUpdate(update); err != nil {
		return coreconfig.Config{}, err
	}
	digest, err := coreconfig.MutationDigest(owner, update)
	if err != nil {
		return coreconfig.Config{}, err
	}
	idempotencyKey := strings.TrimSpace(update.IdempotencyKey)
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreconfig.Config{}, fmt.Errorf("begin native agent config update: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var raw []byte
	var revision int64
	var previousKey *string
	var previousDigest []byte
	var previousResponse []byte
	err = tx.QueryRow(ctx, `SELECT config_json,revision,last_idempotency_key::text,last_request_digest,last_response_json::text FROM agent_native_configs WHERE owner_id=$1 FOR UPDATE`, owner).Scan(&raw, &revision, &previousKey, &previousDigest, &previousResponse)
	if errors.Is(err, pgx.ErrNoRows) {
		current := coreconfig.Default()
		if update.ExpectedRevision > 0 && update.ExpectedRevision != current.Revision {
			return coreconfig.Config{}, coreconfig.ErrConflict
		}
		value := coreconfig.Apply(current, update)
		value.Revision = 1
		response, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			return coreconfig.Config{}, marshalErr
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agent_native_configs(owner_id,config_json,revision,last_idempotency_key,last_request_digest,last_response_json,created_at,updated_at) VALUES($1,$2::jsonb,$3,$4,$5,$6::jsonb,clock_timestamp(),clock_timestamp())`, owner, response, value.Revision, idempotencyKey, digest[:], response); err != nil {
			return coreconfig.Config{}, fmt.Errorf("insert native agent config: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return coreconfig.Config{}, fmt.Errorf("commit native agent config: %w", err)
		}
		return value, nil
	}
	if err != nil {
		return coreconfig.Config{}, fmt.Errorf("lock native agent config: %w", err)
	}
	if previousKey != nil && *previousKey == idempotencyKey {
		if !bytesEqual(previousDigest, digest[:]) {
			return coreconfig.Config{}, coreconfig.ErrConflict
		}
		var replay coreconfig.Config
		if err := json.Unmarshal(previousResponse, &replay); err != nil {
			return coreconfig.Config{}, fmt.Errorf("decode native config replay: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return coreconfig.Config{}, err
		}
		return replay.Normalize(), nil
	}
	if update.ExpectedRevision > 0 && update.ExpectedRevision != revision {
		return coreconfig.Config{}, coreconfig.ErrConflict
	}
	var current coreconfig.Config
	if err := json.Unmarshal(raw, &current); err != nil {
		return coreconfig.Config{}, fmt.Errorf("decode native config row: %w", err)
	}
	value := coreconfig.Apply(current, update)
	value.Revision = revision + 1
	response, err := json.Marshal(value)
	if err != nil {
		return coreconfig.Config{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_native_configs SET config_json=$2::jsonb,revision=$3,last_idempotency_key=$4,last_request_digest=$5,last_response_json=$6::jsonb,updated_at=clock_timestamp() WHERE owner_id=$1`, owner, response, value.Revision, idempotencyKey, digest[:], response); err != nil {
		return coreconfig.Config{}, fmt.Errorf("update native agent config: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return coreconfig.Config{}, fmt.Errorf("commit native agent config: %w", err)
	}
	return value, nil
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
