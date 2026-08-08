package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretexttool"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CoreTextToolStore struct{ store *Store }

func NewCoreTextToolStore(store *Store) *CoreTextToolStore { return &CoreTextToolStore{store: store} }

func (s *CoreTextToolStore) Get(ctx context.Context, owner string, generation int64, now time.Time) (coretexttool.Config, error) {
	owner = strings.TrimSpace(owner)
	if s == nil || s.store == nil || !corewebIdentity(owner, generation) {
		return coretexttool.Config{}, coretexttool.ErrInvalid
	}
	if err := s.checkAdmission(ctx, owner, generation); err != nil {
		return coretexttool.Config{}, err
	}
	config, err := s.read(ctx, s.store.pool, owner, generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return coretexttool.DefaultConfig(now), nil
	}
	if err != nil {
		return coretexttool.Config{}, coretexttool.ErrRepository
	}
	return config, nil
}

func (s *CoreTextToolStore) Update(ctx context.Context, mutation coretexttool.Mutation) (coretexttool.Config, error) {
	mutation.OwnerID = strings.TrimSpace(mutation.OwnerID)
	key, err := uuid.Parse(mutation.IdempotencyKey)
	if s == nil || s.store == nil || !corewebIdentity(mutation.OwnerID, mutation.AccountGeneration) || err != nil || key == uuid.Nil || len(mutation.RequestDigest) != 64 {
		return coretexttool.Config{}, coretexttool.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coretexttool.Config{}, coretexttool.ErrRepository
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, deprovisionAdvisoryLockName); err != nil {
		return coretexttool.Config{}, coretexttool.ErrRepository
	}
	if err = checkWebSearchAdmissionTx(ctx, tx, mutation.OwnerID, mutation.AccountGeneration); err != nil {
		return coretexttool.Config{}, err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "core_text_tools/"+mutation.OwnerID+"/"+strconv.FormatInt(mutation.AccountGeneration, 10)); err != nil {
		return coretexttool.Config{}, coretexttool.ErrRepository
	}
	var storedDigest string
	var response []byte
	err = tx.QueryRow(ctx, `SELECT request_digest,response_json FROM core_text_tool_replays WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3 FOR UPDATE`, mutation.OwnerID, mutation.AccountGeneration, key).Scan(&storedDigest, &response)
	if err == nil {
		if storedDigest != mutation.RequestDigest {
			return coretexttool.Config{}, coretexttool.ErrIdempotencyConflict
		}
		var replay coretexttool.Config
		if json.Unmarshal(response, &replay) != nil || coretexttool.ValidateConfig(replay) != nil {
			return coretexttool.Config{}, coretexttool.ErrRepository
		}
		if tx.Commit(ctx) != nil {
			return coretexttool.Config{}, coretexttool.ErrRepository
		}
		return replay, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return coretexttool.Config{}, coretexttool.ErrRepository
	}
	var revision int64
	err = tx.QueryRow(ctx, `SELECT revision FROM core_text_tool_configs WHERE owner_id=$1 AND account_generation=$2 FOR UPDATE`, mutation.OwnerID, mutation.AccountGeneration).Scan(&revision)
	exists := err == nil
	if errors.Is(err, pgx.ErrNoRows) {
		revision = 0
	} else if err != nil {
		return coretexttool.Config{}, coretexttool.ErrRepository
	}
	if revision != mutation.ExpectedRevision {
		return coretexttool.Config{}, coretexttool.ErrRevisionConflict
	}
	now := mutation.Now.UTC().Truncate(time.Microsecond)
	if now.IsZero() {
		return coretexttool.Config{}, coretexttool.ErrInvalid
	}
	tools := make([]coretexttool.Tool, len(mutation.Tools))
	copy(tools, mutation.Tools)
	next := coretexttool.Config{Enabled: mutation.Enabled, Revision: revision + 1, Tools: tools, UpdatedAt: now}
	if err := coretexttool.ValidateConfig(next); err != nil {
		return coretexttool.Config{}, err
	}
	if exists {
		_, err = tx.Exec(ctx, `UPDATE core_text_tool_configs SET enabled=$3,revision=$4,updated_at=$5 WHERE owner_id=$1 AND account_generation=$2 AND revision=$6`, mutation.OwnerID, mutation.AccountGeneration, next.Enabled, next.Revision, now, revision)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO core_text_tool_configs(owner_id,account_generation,enabled,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$5)`, mutation.OwnerID, mutation.AccountGeneration, next.Enabled, next.Revision, now)
	}
	if err != nil {
		return coretexttool.Config{}, coretexttool.ErrRepository
	}
	if _, err = tx.Exec(ctx, `DELETE FROM core_text_tool_items WHERE owner_id=$1 AND account_generation=$2`, mutation.OwnerID, mutation.AccountGeneration); err != nil {
		return coretexttool.Config{}, coretexttool.ErrRepository
	}
	for _, tool := range next.Tools {
		if _, err = tx.Exec(ctx, `INSERT INTO core_text_tool_items(owner_id,account_generation,tool_id,name,system_prompt,tool_order,enabled,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8)`, mutation.OwnerID, mutation.AccountGeneration, tool.ID, tool.Name, tool.SystemPrompt, tool.Order, tool.Enabled, now); err != nil {
			return coretexttool.Config{}, coretexttool.ErrRepository
		}
	}
	response, err = json.Marshal(next)
	if err != nil {
		return coretexttool.Config{}, coretexttool.ErrRepository
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_text_tool_replays(owner_id,account_generation,idempotency_key,request_digest,response_json,created_at) VALUES($1,$2,$3,$4,$5,$6)`, mutation.OwnerID, mutation.AccountGeneration, key, mutation.RequestDigest, response, now); err != nil {
		return coretexttool.Config{}, coretexttool.ErrRepository
	}
	if err = tx.Commit(ctx); err != nil {
		return coretexttool.Config{}, coretexttool.ErrRepository
	}
	return next, nil
}

type textToolQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func (s *CoreTextToolStore) read(ctx context.Context, query textToolQuery, owner string, generation int64) (coretexttool.Config, error) {
	var out coretexttool.Config
	if err := query.QueryRow(ctx, `SELECT enabled,revision,updated_at FROM core_text_tool_configs WHERE owner_id=$1 AND account_generation=$2`, owner, generation).Scan(&out.Enabled, &out.Revision, &out.UpdatedAt); err != nil {
		return coretexttool.Config{}, err
	}
	rows, err := query.Query(ctx, `SELECT tool_id,name,system_prompt,tool_order,enabled FROM core_text_tool_items WHERE owner_id=$1 AND account_generation=$2 ORDER BY tool_order`, owner, generation)
	if err != nil {
		return coretexttool.Config{}, err
	}
	defer rows.Close()
	out.Tools = make([]coretexttool.Tool, 0)
	for rows.Next() {
		var item coretexttool.Tool
		if err := rows.Scan(&item.ID, &item.Name, &item.SystemPrompt, &item.Order, &item.Enabled); err != nil {
			return coretexttool.Config{}, err
		}
		out.Tools = append(out.Tools, item)
	}
	if rows.Err() != nil || coretexttool.ValidateConfig(out) != nil {
		return coretexttool.Config{}, coretexttool.ErrRepository
	}
	return out, nil
}

func (s *CoreTextToolStore) checkAdmission(ctx context.Context, owner string, generation int64) error {
	var fenced bool
	if err := s.store.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_account_deprovisions WHERE owner_id=$1 AND account_generation=$2)`, owner, generation).Scan(&fenced); err != nil {
		return coretexttool.ErrRepository
	}
	if fenced {
		return coretexttool.ErrRepository
	}
	return nil
}

func corewebIdentity(owner string, generation int64) bool {
	return strings.TrimSpace(owner) != "" && generation > 0
}
