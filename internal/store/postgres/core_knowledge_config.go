package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
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
	ownerID, generation, err := r.knowledgeScope(ctx)
	if err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrInvalid
	}
	value, err := r.loadEmbeddingConfig(ctx, r.store.pool.QueryRow(ctx, `SELECT embedding_profile_id::text,dimension,collection,collection_config_digest,revision,updated_at FROM core_knowledge_embedding_config WHERE owner_id=$1 AND account_generation=$2`, ownerID, generation))
	if err == nil || !errors.Is(err, coreknowledge.ErrNotFound) {
		return value, err
	}
	if _, public := coretask.OwnerScopeFromContext(ctx); !public {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrNotFound
	}
	return r.provisionPublicEmbeddingConfig(ctx, ownerID, generation)
}

func (r *CoreKnowledgeStore) provisionPublicEmbeddingConfig(ctx context.Context, ownerID string, generation int64) (coreknowledge.EmbeddingConfig, error) {
	tx, err := r.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	defer tx.Rollback(ctx)
	lockKey := "knowledge:embedding-config:" + ownerID + ":" + strconv.FormatInt(generation, 10)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey); err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	if value, loadErr := r.loadEmbeddingConfig(ctx, tx.QueryRow(ctx, `SELECT embedding_profile_id::text,dimension,collection,collection_config_digest,revision,updated_at FROM core_knowledge_embedding_config WHERE owner_id=$1 AND account_generation=$2`, ownerID, generation)); loadErr == nil {
		if tx.Commit(ctx) != nil {
			return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
		}
		return value, nil
	} else if !errors.Is(loadErr, coreknowledge.ErrNotFound) {
		return coreknowledge.EmbeddingConfig{}, loadErr
	}
	internalOwner := internalEntityOwnerID("knowledge", r.store.instanceID.String())
	var dimension int
	var collection, configDigest string
	if err = tx.QueryRow(ctx, `SELECT dimension,collection,collection_config_digest FROM core_knowledge_embedding_config WHERE owner_id=$1 AND account_generation=1`, internalOwner).Scan(&dimension, &collection, &configDigest); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrNotFound
		}
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	var profileID string
	if err = tx.QueryRow(ctx, `SELECT profile.profile_id::text
		FROM core_model_profile_defaults defaults
		JOIN core_model_profiles profile
		  ON profile.owner_id=defaults.owner_id
		 AND profile.account_generation=defaults.account_generation
		 AND profile.client_profile_id=defaults.default_embedding_client_profile_id
		 AND profile.deleted_at IS NULL
		WHERE defaults.owner_id=$1 AND defaults.account_generation=$2`, ownerID, generation).Scan(&profileID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrNotFound
		}
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	now := time.Now().UTC()
	if _, err = tx.Exec(ctx, `INSERT INTO core_knowledge_embedding_config(singleton,owner_id,account_generation,embedding_profile_id,dimension,collection,collection_config_digest,revision,updated_at) VALUES(true,$1,$2,$3,$4,$5,$6,1,$7) ON CONFLICT(owner_id,account_generation) DO NOTHING`, ownerID, generation, profileID, dimension, collection, configDigest, now); err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	value, err := r.loadEmbeddingConfig(ctx, tx.QueryRow(ctx, `SELECT embedding_profile_id::text,dimension,collection,collection_config_digest,revision,updated_at FROM core_knowledge_embedding_config WHERE owner_id=$1 AND account_generation=$2`, ownerID, generation))
	if err != nil {
		return coreknowledge.EmbeddingConfig{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	return value, nil
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
	ownerID, generation, scopeErr := r.knowledgeScope(ctx)
	if scopeErr != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrInvalid
	}
	lockKey := "knowledge:embedding-config:" + ownerID + ":" + strconv.FormatInt(generation, 10)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey); err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	now := time.Now().UTC()
	_, err = tx.Exec(ctx, `INSERT INTO core_knowledge_embedding_config(singleton,owner_id,account_generation,embedding_profile_id,dimension,collection,collection_config_digest,revision,updated_at) VALUES(true,$1,$2,$3,$4,$5,$6,1,$7) ON CONFLICT(owner_id,account_generation) DO NOTHING`, ownerID, generation, config.EmbeddingProfileID, config.Dimension, config.Collection, digest, now)
	if err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	value, err := r.loadEmbeddingConfig(ctx, tx.QueryRow(ctx, `SELECT embedding_profile_id::text,dimension,collection,collection_config_digest,revision,updated_at FROM core_knowledge_embedding_config WHERE owner_id=$1 AND account_generation=$2`, ownerID, generation))
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
	ownerID, generation, scopeErr := r.knowledgeScope(ctx)
	if scopeErr != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrInvalid
	}
	lockKey := "knowledge:embedding-config:" + ownerID + ":" + strconv.FormatInt(generation, 10)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey); err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	replayOwnerID, replayGeneration, replayScopeErr := replayOwnerScope(ctx, "knowledge", command.IdempotencyKey)
	if replayScopeErr != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrInvalid
	}
	var replayRaw []byte
	var replayHash, replayCode string
	replayErr := tx.QueryRow(ctx, `SELECT request_hash,response_json,error_code FROM core_knowledge_mutation_replays WHERE owner_id=$1 AND account_generation=$2 AND operation='embedding-config.update' AND idempotency_key=$3 FOR UPDATE`, replayOwnerID, replayGeneration, command.IdempotencyKey).Scan(&replayHash, &replayRaw, &replayCode)
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
	current, err := r.loadEmbeddingConfig(ctx, tx.QueryRow(ctx, `SELECT embedding_profile_id::text,dimension,collection,collection_config_digest,revision,updated_at FROM core_knowledge_embedding_config WHERE owner_id=$1 AND account_generation=$2 FOR UPDATE`, ownerID, generation))
	if err != nil {
		return coreknowledge.EmbeddingConfig{}, err
	}
	if current.Revision != command.ExpectedRevision {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrRevisionConflict
	}
	if command.Dimension != current.Dimension || command.Collection != current.Collection || (command.CollectionConfigDigest != "" && command.CollectionConfigDigest != current.CollectionConfigDigest) {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrInvalid
	}
	if command.EmbeddingProfileID != current.EmbeddingProfileID {
		var active bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1
			FROM core_knowledge_index_jobs job
			JOIN core_task_scopes scope ON scope.task_id=job.task_id
			WHERE scope.owner_id=$1 AND scope.account_generation=$2
			  AND job.status IN ('queued','running')
		)`, ownerID, generation).Scan(&active); err != nil {
			return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
		}
		if active {
			return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrActiveTasks
		}
	}
	if _, public := coretask.OwnerScopeFromContext(ctx); public {
		var profileExists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM core_model_profiles WHERE profile_id=$1 AND owner_id=$2 AND account_generation=$3 AND deleted_at IS NULL)`, command.EmbeddingProfileID, ownerID, generation).Scan(&profileExists); err != nil {
			return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
		}
		if !profileExists {
			return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrNotFound
		}
	}
	now := time.Now().UTC()
	if _, err = tx.Exec(ctx, `UPDATE core_knowledge_embedding_config SET embedding_profile_id=$1,revision=revision+1,updated_at=$2 WHERE owner_id=$3 AND account_generation=$4 AND revision=$5`, command.EmbeddingProfileID, now, ownerID, generation, command.ExpectedRevision); err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	current.EmbeddingProfileID = command.EmbeddingProfileID
	current.Revision++
	current.UpdatedAt = now
	raw, _ := json.Marshal(current)
	if _, err = tx.Exec(ctx, `INSERT INTO core_knowledge_mutation_replays(owner_id,account_generation,operation,idempotency_key,request_hash,response_json,error_code) VALUES($1,$2,'embedding-config.update',$3,$4,$5,'')`, replayOwnerID, replayGeneration, command.IdempotencyKey, digest, raw); err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	return current, nil
}

var _ coreknowledge.EmbeddingConfigStore = (*CoreKnowledgeStore)(nil)
