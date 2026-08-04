package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func collectionConfigDigest(collection string, dimension int) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(collection) + "\x00" + formatInt(dimension)))
	return hex.EncodeToString(sum[:])
}

// KnowledgeCollectionDigest is shared by composition and persistence so the
// owner config digest does not accidentally include deployment-only endpoints.
func KnowledgeCollectionDigest(collection string, dimension int) string {
	return collectionConfigDigest(collection, dimension)
}

func formatInt(value int) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	buf := make([]byte, 0, 20)
	for value > 0 {
		buf = append(buf, byte('0'+value%10))
		value /= 10
	}
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	if negative {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}

func validateEmbeddingConfig(config coreknowledge.EmbeddingConfig) error {
	if uuid.Validate(config.EmbeddingProfileID) != nil || config.Dimension <= 0 || config.Dimension > 16384 || strings.TrimSpace(config.Collection) == "" || len(config.Collection) > 255 || config.Revision < 1 {
		return coreknowledge.ErrInvalid
	}
	if config.CollectionConfigDigest == "" {
		config.CollectionConfigDigest = collectionConfigDigest(config.Collection, config.Dimension)
	}
	if len(config.CollectionConfigDigest) != 64 {
		return coreknowledge.ErrInvalid
	}
	if _, err := hex.DecodeString(config.CollectionConfigDigest); err != nil {
		return coreknowledge.ErrInvalid
	}
	return nil
}

func (r *CoreKnowledgeStore) GetEmbeddingConfig(ctx context.Context) (coreknowledge.EmbeddingConfig, error) {
	if r == nil || r.store == nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrInvalid
	}
	return r.loadEmbeddingConfig(ctx, r.store.pool.QueryRow(ctx, `SELECT embedding_profile_id::text,dimension,collection,collection_config_digest,revision,updated_at FROM core_knowledge_embedding_config WHERE singleton=true`))
}

func (r *CoreKnowledgeStore) loadEmbeddingConfig(_ context.Context, row interface{ Scan(...any) error }) (coreknowledge.EmbeddingConfig, error) {
	var config coreknowledge.EmbeddingConfig
	if err := row.Scan(&config.EmbeddingProfileID, &config.Dimension, &config.Collection, &config.CollectionConfigDigest, &config.Revision, &config.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrNotFound
		}
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	config.UpdatedAt = config.UpdatedAt.UTC()
	if validateEmbeddingConfig(config) != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	return config, nil
}

func (r *CoreKnowledgeStore) EnsureEmbeddingConfig(ctx context.Context, config coreknowledge.EmbeddingConfig) (coreknowledge.EmbeddingConfig, error) {
	if r == nil || r.store == nil || validateEmbeddingConfig(config) != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrInvalid
	}
	digest := config.CollectionConfigDigest
	if digest == "" {
		digest = collectionConfigDigest(config.Collection, config.Dimension)
	}
	tx, err := r.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('knowledge:embedding-config',0))`); err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	now := time.Now().UTC()
	_, err = tx.Exec(ctx, `INSERT INTO core_knowledge_embedding_config(singleton,embedding_profile_id,dimension,collection,collection_config_digest,revision,updated_at) VALUES(true,$1,$2,$3,$4,1,$5) ON CONFLICT(singleton) DO NOTHING`, config.EmbeddingProfileID, config.Dimension, config.Collection, digest, now)
	if err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	value, err := r.loadEmbeddingConfig(ctx, tx.QueryRow(ctx, `SELECT embedding_profile_id::text,dimension,collection,collection_config_digest,revision,updated_at FROM core_knowledge_embedding_config WHERE singleton=true`))
	if err != nil {
		return coreknowledge.EmbeddingConfig{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	return value, nil
}

func (r *CoreKnowledgeStore) UpdateEmbeddingConfig(ctx context.Context, command coreknowledge.EmbeddingConfigCommand) (coreknowledge.EmbeddingConfig, error) {
	if r == nil || r.store == nil || uuid.Validate(command.IdempotencyKey) != nil || command.ExpectedRevision < 1 || uuid.Validate(command.EmbeddingProfileID) != nil || command.Dimension <= 0 || command.Dimension > 16384 || strings.TrimSpace(command.Collection) == "" || len(command.Collection) > 255 {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrInvalid
	}
	digest := knowledgeDigest(command)
	tx, err := r.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('knowledge:embedding-config',0))`); err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	var replayRaw []byte
	var replayHash, replayCode string
	replayErr := tx.QueryRow(ctx, `SELECT request_hash,response_json,error_code FROM core_knowledge_mutation_replays WHERE operation='embedding-config.update' AND idempotency_key=$1 FOR UPDATE`, command.IdempotencyKey).Scan(&replayHash, &replayRaw, &replayCode)
	if replayErr == nil {
		if replayHash != digest {
			return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrIdempotencyConflict
		}
		var value coreknowledge.EmbeddingConfig
		if json.Unmarshal(replayRaw, &value) != nil {
			return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
		}
		if replayCode != "" {
			return coreknowledge.EmbeddingConfig{}, knowledgeError(replayCode)
		}
		_ = tx.Commit(ctx)
		return value, nil
	}
	if !errors.Is(replayErr, pgx.ErrNoRows) {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	current, err := r.loadEmbeddingConfig(ctx, tx.QueryRow(ctx, `SELECT embedding_profile_id::text,dimension,collection,collection_config_digest,revision,updated_at FROM core_knowledge_embedding_config WHERE singleton=true FOR UPDATE`))
	if err != nil {
		return coreknowledge.EmbeddingConfig{}, err
	}
	if current.Revision != command.ExpectedRevision {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrRevisionConflict
	}
	if command.Dimension != current.Dimension || command.Collection != current.Collection || (command.CollectionConfigDigest != "" && command.CollectionConfigDigest != current.CollectionConfigDigest) {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrInvalid
	}
	now := time.Now().UTC()
	if _, err = tx.Exec(ctx, `UPDATE core_knowledge_embedding_config SET embedding_profile_id=$1,revision=revision+1,updated_at=$2 WHERE singleton=true AND revision=$3`, command.EmbeddingProfileID, now, command.ExpectedRevision); err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	current.EmbeddingProfileID = command.EmbeddingProfileID
	current.Revision++
	current.UpdatedAt = now
	raw, _ := json.Marshal(current)
	if _, err = tx.Exec(ctx, `INSERT INTO core_knowledge_mutation_replays(operation,idempotency_key,request_hash,response_json,error_code) VALUES('embedding-config.update',$1,$2,$3,'')`, command.IdempotencyKey, digest, raw); err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	return current, nil
}

var _ coreknowledge.EmbeddingConfigStore = (*CoreKnowledgeStore)(nil)
