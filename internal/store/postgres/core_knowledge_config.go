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
	if current.EmbeddingProfileID != uuid.Nil.String() && current.EmbeddingProfileID != command.EmbeddingProfileID {
		if err = r.retireEmbeddingProfileTx(ctx, tx, current.EmbeddingProfileID, now); err != nil {
			return coreknowledge.EmbeddingConfig{}, err
		}
	}
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

func (r *CoreKnowledgeStore) DisableEmbeddingProfile(ctx context.Context, profileID string) (coreknowledge.EmbeddingConfig, error) {
	if r == nil || r.store == nil || uuid.Validate(profileID) != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrInvalid
	}
	tx, err := r.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('knowledge:embedding-config',0))`); err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	current, err := r.loadEmbeddingConfig(ctx, tx.QueryRow(ctx, `SELECT embedding_profile_id::text,dimension,collection,collection_config_digest,revision,updated_at FROM core_knowledge_embedding_config WHERE singleton=true FOR UPDATE`))
	if err != nil {
		return coreknowledge.EmbeddingConfig{}, err
	}
	if current.EmbeddingProfileID == uuid.Nil.String() {
		if err = tx.Commit(ctx); err != nil {
			return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
		}
		return current, nil
	}
	if current.EmbeddingProfileID != profileID {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrRevisionConflict
	}
	now := time.Now().UTC()
	if err = r.retireEmbeddingProfileTx(ctx, tx, profileID, now); err != nil {
		return coreknowledge.EmbeddingConfig{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_knowledge_embedding_config SET embedding_profile_id=$1,revision=revision+1,updated_at=$2 WHERE singleton=true`, uuid.Nil, now); err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	current.EmbeddingProfileID = uuid.Nil.String()
	current.Revision++
	current.UpdatedAt = now
	if err = tx.Commit(ctx); err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	return current, nil
}

// retireEmbeddingProfileTx removes every executable/index binding owned by an
// old embedding profile while preserving source metadata and content. The
// caller holds the embedding-config advisory lock and commits the replacement
// binding in the same transaction, so profile deletion cannot race a still
// queryable generation.
func (r *CoreKnowledgeStore) retireEmbeddingProfileTx(ctx context.Context, tx pgx.Tx, profileID string, now time.Time) error {
	var err error
	// Fence every first-generation and replacement job before clearing the
	// binding. A worker that returns after this commit observes a canceled task
	// and the durable staging tombstone, so it cannot re-promote or leak vectors.
	if _, err = tx.Exec(ctx, `INSERT INTO core_knowledge_generation_cleanup(source_id,generation,cleanup_kind,revision,quiescent_after)
		SELECT item.value::uuid,job.generation,'canceled_staging',0,COALESCE(task.lease_expires_at,$2)
		FROM core_knowledge_index_jobs job
		JOIN core_tasks task ON task.task_id=job.task_id
		CROSS JOIN LATERAL jsonb_array_elements_text(job.source_ids) item(value)
		WHERE job.profile_id=$1 AND job.status IN ('queued','running')
		ON CONFLICT(source_id,generation) DO UPDATE SET cleanup_kind='canceled_staging',quiescent_after=GREATEST(COALESCE(core_knowledge_generation_cleanup.quiescent_after,EXCLUDED.quiescent_after),EXCLUDED.quiescent_after)`, profileID, now); err != nil {
		return coreknowledge.ErrConflict
	}
	var runningTasks int64
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM core_tasks task JOIN core_knowledge_index_jobs job ON job.task_id=task.task_id WHERE job.profile_id=$1 AND job.status IN ('queued','running') AND task.status='running'`, profileID).Scan(&runningTasks); err != nil {
		return coreknowledge.ErrConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE core_tasks task SET status='canceled',failure_code='user_canceled',failure_summary='',lease_holder='',lease_expires_at=NULL,revision=revision+1,progress_sequence=progress_sequence+1,updated_at=$2 FROM core_knowledge_index_jobs job WHERE job.task_id=task.task_id AND job.profile_id=$1 AND job.status IN ('queued','running') AND task.status IN ('queued','running')`, profileID, now); err != nil {
		return coreknowledge.ErrConflict
	}
	if runningTasks > 0 {
		if _, err = tx.Exec(ctx, `UPDATE core_task_runtime_concurrency SET running_count=GREATEST(0,running_count-$1),revision=revision+1,updated_at=$2 WHERE singleton=true`, runningTasks, now); err != nil {
			return coreknowledge.ErrConflict
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE core_knowledge_index_jobs SET status='canceled',error_code='user_canceled',error_summary='',updated_at=$2 WHERE profile_id=$1 AND status IN ('queued','running')`, profileID, now); err != nil {
		return coreknowledge.ErrConflict
	}
	// These tasks were canceled directly under the same Knowledge transaction,
	// so retire the matching task-owned model references here as well. Leaving
	// them behind would make a fully retired embedding profile appear in use.
	if _, err = tx.Exec(ctx, `DELETE FROM core_model_profile_active_refs ref USING core_knowledge_index_jobs job,core_tasks task
		WHERE ref.owner_kind='task' AND ref.owner_id=job.task_id AND ref.profile_id=$1
		AND job.profile_id=$1 AND task.task_id=job.task_id AND task.status='canceled'`, profileID); err != nil {
		return coreknowledge.ErrConflict
	}
	if _, err = tx.Exec(ctx, `DELETE FROM core_knowledge_vectors WHERE generation IN (
		SELECT generation FROM core_knowledge_index_jobs WHERE profile_id=$1
		UNION SELECT promoted_generation FROM core_knowledge_sources WHERE promoted_profile_id=$1 AND promoted_generation<>'')`, profileID); err != nil {
		return coreknowledge.ErrConflict
	}
	if _, err = tx.Exec(ctx, `DELETE FROM core_knowledge_vector_generations WHERE generation IN (
		SELECT generation FROM core_knowledge_index_jobs WHERE profile_id=$1
		UNION SELECT promoted_generation FROM core_knowledge_sources WHERE promoted_profile_id=$1 AND promoted_generation<>'')
		AND NOT EXISTS (SELECT 1 FROM core_knowledge_vectors vector WHERE vector.generation=core_knowledge_vector_generations.generation)`, profileID); err != nil {
		return coreknowledge.ErrConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE core_knowledge_sources source SET
		status=CASE WHEN source.status='indexing' THEN 'ready' ELSE source.status END,
		error_code=CASE WHEN source.status='indexing' THEN '' ELSE source.error_code END,
		promoted_generation=CASE WHEN source.promoted_profile_id=$1 THEN '' ELSE source.promoted_generation END,
		promoted_revision=CASE WHEN source.promoted_profile_id=$1 THEN 0 ELSE source.promoted_revision END,
		promoted_profile_id=CASE WHEN source.promoted_profile_id=$1 THEN NULL ELSE source.promoted_profile_id END,
		promoted_profile_revision=CASE WHEN source.promoted_profile_id=$1 THEN 0 ELSE source.promoted_profile_revision END,
		promoted_collection_config_digest=CASE WHEN source.promoted_profile_id=$1 THEN '' ELSE source.promoted_collection_config_digest END,
		updated_at=$2
		WHERE source.promoted_profile_id=$1 OR source.source_id IN (
			SELECT item.value::uuid FROM core_knowledge_index_jobs job CROSS JOIN LATERAL jsonb_array_elements_text(job.source_ids) item(value) WHERE job.profile_id=$1)`, profileID, now); err != nil {
		return coreknowledge.ErrConflict
	}
	if _, err = tx.Exec(ctx, `DELETE FROM core_model_profile_active_refs WHERE owner_kind='knowledge_generation' AND profile_id=$1`, profileID); err != nil {
		return coreknowledge.ErrConflict
	}
	if _, err = tx.Exec(ctx, `DELETE FROM core_knowledge_list_snapshots`); err != nil {
		return coreknowledge.ErrConflict
	}
	return nil
}

var _ coreknowledge.EmbeddingConfigStore = (*CoreKnowledgeStore)(nil)
