package knowledge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const snapshotSchemaV1 = 1

const (
	operationPutConfig    = "knowledge.config.put"
	operationStartUpload  = "knowledge.attachment.start"
	operationAppendChunk  = "knowledge.attachment.append"
	operationCommitUpload = "knowledge.attachment.commit"
	operationCreateMemory = "knowledge.memory.create"
	operationDeleteSource = "knowledge.source.delete"
)

type PostgresRepository struct {
	pool       *pgxpool.Pool
	instanceID uuid.UUID
	catalog    Catalog
}

func NewPostgresRepository(pool *pgxpool.Pool, instanceID string, catalog Catalog) (*PostgresRepository, error) {
	parsed, err := uuid.Parse(instanceID)
	if pool == nil || err != nil || parsed == uuid.Nil || parsed.String() != instanceID || len(catalog.IDs()) == 0 {
		return nil, ErrInvalid
	}
	return &PostgresRepository{pool: pool, instanceID: parsed, catalog: catalog}, nil
}

func (repository *PostgresRepository) GetConfig(ctx context.Context, ownerID, bindingID string) (Config, error) {
	ownerID, bindingID = strings.TrimSpace(ownerID), strings.TrimSpace(bindingID)
	if !validOwnerID(ownerID) || (bindingID != "" && !canonicalUUID(bindingID)) {
		return Config{}, ErrInvalid
	}
	if bindingID == "" {
		return repository.getOnlyConfig(ctx, ownerID)
	}
	config, err := scanConfig(repository.pool.QueryRow(ctx, `
		SELECT owner_id, binding_id, deployment_id, managed_service_id, recipe_digest,
		       embedding_profile_id, enabled, revision, created_at, updated_at
		FROM knowledge_configs
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3`, repository.instanceID, ownerID, bindingID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Config{}, ErrNotFound
	}
	if err != nil {
		return Config{}, fmt.Errorf("read knowledge config: %w", err)
	}
	if err := validateStoredConfig(config, repository.catalog); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (repository *PostgresRepository) getOnlyConfig(ctx context.Context, ownerID string) (Config, error) {
	rows, err := repository.pool.Query(ctx, `
		SELECT owner_id, binding_id, deployment_id, managed_service_id, recipe_digest,
		       embedding_profile_id, enabled, revision, created_at, updated_at
		FROM knowledge_configs
		WHERE agent_instance_id=$1 AND owner_id=$2
		ORDER BY binding_id
		LIMIT 2`, repository.instanceID, ownerID)
	if err != nil {
		return Config{}, fmt.Errorf("resolve knowledge config: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Config{}, fmt.Errorf("resolve knowledge config: %w", err)
		}
		return Config{}, ErrNotFound
	}
	config, err := scanConfig(rows)
	if err != nil {
		return Config{}, fmt.Errorf("scan resolved knowledge config: %w", err)
	}
	if rows.Next() {
		return Config{}, ErrAmbiguousConfig
	}
	if err := rows.Err(); err != nil {
		return Config{}, fmt.Errorf("resolve knowledge config: %w", err)
	}
	if err := validateStoredConfig(config, repository.catalog); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (repository *PostgresRepository) PutConfig(ctx context.Context, scope MutationScope, command PutConfigCommand) (Config, error) {
	if err := scope.Validate(); err != nil {
		return Config{}, err
	}
	validated, err := command.Validated(repository.catalog)
	if err != nil {
		return Config{}, err
	}
	digest, err := validated.Digest()
	if err != nil {
		return Config{}, err
	}
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Config{}, fmt.Errorf("begin knowledge config mutation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	replay, response, err := claimKnowledgeMutation(ctx, tx, scope, operationPutConfig, validated.IdempotencyKey, digest[:], validated.BindingID)
	if err != nil {
		return Config{}, err
	}
	if replay {
		var snapshot configSnapshot
		if err := decodeSnapshot(response, &snapshot); err != nil {
			return Config{}, err
		}
		if err := requireNoKnowledgeLifecycleReservation(ctx, tx, repository.instanceID,
			snapshot.Config.OwnerID, snapshot.Config.BindingID); err != nil {
			return Config{}, err
		}
		if err := validateStoredConfig(snapshot.Config, repository.catalog); err != nil {
			return Config{}, errors.New("invalid knowledge config idempotency snapshot")
		}
		if err := tx.Commit(ctx); err != nil {
			return Config{}, fmt.Errorf("commit knowledge config replay: %w", err)
		}
		return snapshot.Config, nil
	}

	var config Config
	if validated.ExpectedRevision == 0 {
		config, err = scanConfig(tx.QueryRow(ctx, `
			INSERT INTO knowledge_configs (
			    agent_instance_id, owner_id, binding_id, deployment_id, managed_service_id,
			    recipe_digest, embedding_profile_id, enabled)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			RETURNING owner_id, binding_id, deployment_id, managed_service_id, recipe_digest,
			          embedding_profile_id, enabled, revision, created_at, updated_at`,
			repository.instanceID, validated.OwnerID, validated.BindingID, validated.Spec.DeploymentID,
			validated.Spec.ManagedServiceID, validated.Spec.RecipeDigest, validated.Spec.EmbeddingProfileID, validated.Spec.Enabled))
		if uniqueViolation(err) {
			return Config{}, ErrConflict
		}
	} else {
		stored, readErr := scanConfig(tx.QueryRow(ctx, `
			SELECT owner_id, binding_id, deployment_id, managed_service_id, recipe_digest,
			       embedding_profile_id, enabled, revision, created_at, updated_at
			FROM knowledge_configs
			WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3
			FOR UPDATE`, repository.instanceID, validated.OwnerID, validated.BindingID))
		if errors.Is(readErr, pgx.ErrNoRows) {
			return Config{}, ErrNotFound
		}
		if readErr != nil {
			return Config{}, fmt.Errorf("lock knowledge config: %w", readErr)
		}
		if !stored.Spec.SameIdentity(validated.Spec) {
			return Config{}, ErrImmutableConfig
		}
		if stored.Revision != validated.ExpectedRevision {
			return Config{}, ErrRevision
		}
		var lifecycleReserved bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM managed_knowledge_lifecycle_operations
			WHERE agent_instance_id=$1 AND owner_id=$2 AND knowledge_binding_id=$3
			  AND deployment_id=$4 AND managed_service_id=$5
			  AND execution_fenced_at IS NOT NULL AND reservation_released_at IS NULL
			  AND status IN ('scheduled','running')
		)`, repository.instanceID, validated.OwnerID, validated.BindingID,
			validated.Spec.DeploymentID, validated.Spec.ManagedServiceID).Scan(&lifecycleReserved); err != nil {
			return Config{}, fmt.Errorf("read knowledge lifecycle reservation: %w", err)
		}
		if lifecycleReserved {
			return Config{}, ErrState
		}
		config, err = scanConfig(tx.QueryRow(ctx, `
			UPDATE knowledge_configs
			SET enabled=$4, revision=revision+1, updated_at=clock_timestamp()
			WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3 AND revision=$5
			RETURNING owner_id, binding_id, deployment_id, managed_service_id, recipe_digest,
			          embedding_profile_id, enabled, revision, created_at, updated_at`,
			repository.instanceID, validated.OwnerID, validated.BindingID, validated.Spec.Enabled, validated.ExpectedRevision))
	}
	if err != nil {
		return Config{}, fmt.Errorf("persist knowledge config: %w", err)
	}
	if err := setKnowledgeMutationResponse(ctx, tx, scope, operationPutConfig, validated.IdempotencyKey, configSnapshot{SchemaVersion: snapshotSchemaV1, Config: config}); err != nil {
		return Config{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Config{}, fmt.Errorf("commit knowledge config: %w", err)
	}
	return config, nil
}

func (repository *PostgresRepository) ListSources(ctx context.Context, query ListSourcesQuery) (SourcePage, error) {
	validated, err := query.Validated()
	if err != nil {
		return SourcePage{}, err
	}
	if _, err := repository.GetConfig(ctx, validated.OwnerID, validated.BindingID); err != nil {
		return SourcePage{}, err
	}
	after := uuid.Nil
	if validated.AfterSourceID != "" {
		after, _ = uuid.Parse(validated.AfterSourceID)
	}
	rows, err := repository.pool.Query(ctx, `
		SELECT owner_id, binding_id, source_id, kind, status, media_type, size_bytes,
		       content_sha256, chunk_count, revision, created_at, updated_at, title, error_code
		FROM knowledge_sources
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3
		  AND status<>'deleted' AND source_id>$4
		ORDER BY source_id
		LIMIT $5`, repository.instanceID, validated.OwnerID, validated.BindingID, after, validated.PageSize+1)
	if err != nil {
		return SourcePage{}, fmt.Errorf("list knowledge sources: %w", err)
	}
	defer rows.Close()
	page := SourcePage{}
	for rows.Next() {
		source, scanErr := scanSource(rows)
		if scanErr != nil {
			return SourcePage{}, fmt.Errorf("scan knowledge source: %w", scanErr)
		}
		page.Sources = append(page.Sources, source)
	}
	if err := rows.Err(); err != nil {
		return SourcePage{}, fmt.Errorf("iterate knowledge sources: %w", err)
	}
	if len(page.Sources) > validated.PageSize {
		page.Sources = page.Sources[:validated.PageSize]
		page.NextSourceID = page.Sources[len(page.Sources)-1].SourceID
	}
	return page, nil
}

func (repository *PostgresRepository) StartAttachmentUpload(ctx context.Context, scope MutationScope, command StartAttachmentUploadCommand) (AttachmentUpload, error) {
	if err := scope.Validate(); err != nil {
		return AttachmentUpload{}, err
	}
	validated, err := command.Validated()
	if err != nil {
		return AttachmentUpload{}, err
	}
	digest, _ := commandDigest(struct {
		OwnerID                 string `json:"owner_id"`
		BindingID               string `json:"binding_id"`
		SourceID                string `json:"source_id"`
		UploadID                string `json:"upload_id"`
		MediaType               string `json:"media_type"`
		DeclaredSizeBytes       int64  `json:"declared_size_bytes"`
		ExpectedBindingRevision int64  `json:"expected_binding_revision"`
		Title                   string `json:"title"`
	}{validated.OwnerID, validated.BindingID, validated.SourceID, validated.UploadID, validated.MediaType, validated.DeclaredSizeBytes, validated.ExpectedBindingRevision, validated.Title})
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return AttachmentUpload{}, fmt.Errorf("begin knowledge upload: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	replay, response, err := claimKnowledgeMutation(ctx, tx, scope, operationStartUpload, validated.IdempotencyKey, digest[:], validated.UploadID)
	if err != nil {
		return AttachmentUpload{}, err
	}
	if replay {
		var snapshot uploadSnapshot
		if err := decodeSnapshot(response, &snapshot); err != nil {
			return AttachmentUpload{}, err
		}
		if err := requireNoKnowledgeLifecycleReservation(ctx, tx, repository.instanceID,
			snapshot.Upload.OwnerID, snapshot.Upload.BindingID); err != nil {
			return AttachmentUpload{}, err
		}
		if err := validateStoredUpload(snapshot.Upload); err != nil {
			return AttachmentUpload{}, errors.New("invalid knowledge upload idempotency snapshot")
		}
		if err := validateUploadReplayState(ctx, tx, repository.instanceID, snapshot.Upload); err != nil {
			return AttachmentUpload{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return AttachmentUpload{}, fmt.Errorf("commit knowledge upload replay: %w", err)
		}
		return snapshot.Upload, nil
	}
	if _, err := requireConfigRevision(ctx, tx, repository.instanceID, repository.catalog, validated.OwnerID, validated.BindingID, validated.ExpectedBindingRevision, true); err != nil {
		return AttachmentUpload{}, err
	}
	if err := reserveSourceIdentity(ctx, tx, repository.instanceID, validated.OwnerID, validated.BindingID, validated.SourceID); err != nil {
		return AttachmentUpload{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO knowledge_sources (
		    agent_instance_id, owner_id, binding_id, source_id, kind, status, media_type, size_bytes, title)
		VALUES ($1,$2,$3,$4,'attachment','uploading',$5,$6,$7)`, repository.instanceID, validated.OwnerID, validated.BindingID,
		validated.SourceID, validated.MediaType, validated.DeclaredSizeBytes, validated.Title); err != nil {
		if uniqueViolation(err) {
			return AttachmentUpload{}, ErrConflict
		}
		return AttachmentUpload{}, fmt.Errorf("persist knowledge attachment source: %w", err)
	}
	upload, err := scanUpload(tx.QueryRow(ctx, `
		INSERT INTO knowledge_uploads (
		    agent_instance_id, owner_id, binding_id, source_id, upload_id, status, media_type, declared_size_bytes, binding_revision)
		VALUES ($1,$2,$3,$4,$5,'receiving',$6,$7,$8)
		RETURNING owner_id, binding_id, source_id, upload_id, status, media_type,
		          declared_size_bytes, received_size_bytes, next_chunk_ordinal, revision, created_at, updated_at, binding_revision`,
		repository.instanceID, validated.OwnerID, validated.BindingID, validated.SourceID, validated.UploadID,
		validated.MediaType, validated.DeclaredSizeBytes, validated.ExpectedBindingRevision))
	if uniqueViolation(err) {
		return AttachmentUpload{}, ErrConflict
	}
	if err != nil {
		return AttachmentUpload{}, fmt.Errorf("persist knowledge upload: %w", err)
	}
	if err := setKnowledgeMutationResponse(ctx, tx, scope, operationStartUpload, validated.IdempotencyKey, uploadSnapshot{SchemaVersion: snapshotSchemaV1, Upload: upload}); err != nil {
		return AttachmentUpload{}, err
	}
	if err := advanceKnowledgeDataEpoch(ctx, tx, repository.instanceID, validated.OwnerID, validated.BindingID); err != nil {
		return AttachmentUpload{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AttachmentUpload{}, fmt.Errorf("commit knowledge upload: %w", err)
	}
	return upload, nil
}

func (repository *PostgresRepository) AppendAttachmentChunk(ctx context.Context, scope MutationScope, command AppendAttachmentChunkCommand, stage func(context.Context, AttachmentChunk) error) (AttachmentUpload, error) {
	if err := scope.Validate(); err != nil || stage == nil {
		if err != nil {
			return AttachmentUpload{}, err
		}
		return AttachmentUpload{}, ErrInvalid
	}
	validated, err := command.Validated()
	if err != nil {
		return AttachmentUpload{}, err
	}
	digest, _ := commandDigest(struct {
		OwnerID                string `json:"owner_id"`
		BindingID              string `json:"binding_id"`
		UploadID               string `json:"upload_id"`
		ExpectedUploadRevision int64  `json:"expected_upload_revision"`
		OffsetBytes            int64  `json:"offset_bytes"`
		ChunkOrdinal           int32  `json:"chunk_ordinal"`
		ChunkSize              int    `json:"chunk_size"`
		ChunkSHA256            string `json:"chunk_sha256"`
	}{validated.OwnerID, validated.BindingID, validated.UploadID, validated.ExpectedUploadRevision, validated.OffsetBytes, validated.ChunkOrdinal, len(validated.Chunk), validated.ChunkSHA256})
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return AttachmentUpload{}, fmt.Errorf("begin knowledge chunk append: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	replay, response, err := claimKnowledgeMutation(ctx, tx, scope, operationAppendChunk, validated.IdempotencyKey, digest[:], validated.UploadID)
	if err != nil {
		return AttachmentUpload{}, err
	}
	if replay {
		var snapshot uploadSnapshot
		if err := decodeSnapshot(response, &snapshot); err != nil {
			return AttachmentUpload{}, err
		}
		if err := requireNoKnowledgeLifecycleReservation(ctx, tx, repository.instanceID,
			snapshot.Upload.OwnerID, snapshot.Upload.BindingID); err != nil {
			return AttachmentUpload{}, err
		}
		if err := validateStoredUpload(snapshot.Upload); err != nil {
			return AttachmentUpload{}, errors.New("invalid knowledge upload idempotency snapshot")
		}
		if err := validateUploadReplayState(ctx, tx, repository.instanceID, snapshot.Upload); err != nil {
			return AttachmentUpload{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return AttachmentUpload{}, fmt.Errorf("commit knowledge chunk replay: %w", err)
		}
		return snapshot.Upload, nil
	}
	upload, err := lockUpload(ctx, tx, repository.instanceID, validated.OwnerID, validated.BindingID, validated.UploadID)
	if err != nil {
		return AttachmentUpload{}, err
	}
	if upload.Status != UploadReceiving {
		return AttachmentUpload{}, ErrState
	}
	if upload.Revision != validated.ExpectedUploadRevision {
		return AttachmentUpload{}, ErrRevision
	}
	config, err := requireConfigRevision(ctx, tx, repository.instanceID, repository.catalog, upload.OwnerID, upload.BindingID, upload.BindingRevision, true)
	if err != nil {
		return AttachmentUpload{}, err
	}
	if upload.ReceivedSizeBytes != validated.OffsetBytes || upload.NextChunkOrdinal != validated.ChunkOrdinal ||
		upload.ReceivedSizeBytes+int64(len(validated.Chunk)) > upload.DeclaredSizeBytes {
		return AttachmentUpload{}, ErrConflict
	}
	title, err := readSourceTitle(ctx, tx, repository.instanceID, upload.OwnerID, upload.BindingID, upload.SourceID)
	if err != nil {
		return AttachmentUpload{}, err
	}
	chunk := AttachmentChunk{
		OwnerID: upload.OwnerID, BindingID: upload.BindingID, SourceID: upload.SourceID, UploadID: upload.UploadID,
		MediaType: upload.MediaType, DeclaredSizeBytes: upload.DeclaredSizeBytes, OffsetBytes: validated.OffsetBytes,
		ChunkOrdinal: validated.ChunkOrdinal, Chunk: append([]byte(nil), validated.Chunk...), ChunkSHA256: validated.ChunkSHA256, Title: title,
		Binding: config.Spec,
	}
	if err := stage(ctx, chunk); err != nil {
		return AttachmentUpload{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO knowledge_upload_chunks (
		    agent_instance_id, owner_id, binding_id, upload_id, chunk_ordinal, offset_bytes, size_bytes, chunk_sha256)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, repository.instanceID, upload.OwnerID, upload.BindingID, upload.UploadID,
		validated.ChunkOrdinal, validated.OffsetBytes, len(validated.Chunk), validated.ChunkSHA256); err != nil {
		if uniqueViolation(err) {
			return AttachmentUpload{}, ErrConflict
		}
		return AttachmentUpload{}, fmt.Errorf("persist knowledge chunk metadata: %w", err)
	}
	upload, err = scanUpload(tx.QueryRow(ctx, `
		UPDATE knowledge_uploads
		SET received_size_bytes=received_size_bytes+$5, next_chunk_ordinal=next_chunk_ordinal+1,
		    revision=revision+1, updated_at=clock_timestamp()
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3 AND upload_id=$4
		RETURNING owner_id, binding_id, source_id, upload_id, status, media_type,
		          declared_size_bytes, received_size_bytes, next_chunk_ordinal, revision, created_at, updated_at, binding_revision`,
		repository.instanceID, upload.OwnerID, upload.BindingID, upload.UploadID, len(validated.Chunk)))
	if err != nil {
		return AttachmentUpload{}, fmt.Errorf("advance knowledge upload: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE knowledge_sources SET chunk_count=chunk_count+1, revision=revision+1, updated_at=clock_timestamp()
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3 AND source_id=$4`,
		repository.instanceID, upload.OwnerID, upload.BindingID, upload.SourceID); err != nil {
		return AttachmentUpload{}, fmt.Errorf("advance knowledge source metadata: %w", err)
	}
	if err := setKnowledgeMutationResponse(ctx, tx, scope, operationAppendChunk, validated.IdempotencyKey, uploadSnapshot{SchemaVersion: snapshotSchemaV1, Upload: upload}); err != nil {
		return AttachmentUpload{}, err
	}
	if err := advanceKnowledgeDataEpoch(ctx, tx, repository.instanceID, upload.OwnerID, upload.BindingID); err != nil {
		return AttachmentUpload{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AttachmentUpload{}, fmt.Errorf("commit knowledge chunk append: %w", err)
	}
	return upload, nil
}

func (repository *PostgresRepository) CommitAttachmentUpload(ctx context.Context, scope MutationScope, command CommitAttachmentUploadCommand, commit func(context.Context, AttachmentCommit) (ContentReceipt, error)) (AttachmentUpload, Source, error) {
	if err := scope.Validate(); err != nil || commit == nil {
		if err != nil {
			return AttachmentUpload{}, Source{}, err
		}
		return AttachmentUpload{}, Source{}, ErrInvalid
	}
	validated, err := command.Validated()
	if err != nil {
		return AttachmentUpload{}, Source{}, err
	}
	digest, _ := commandDigest(struct {
		OwnerID                string `json:"owner_id"`
		BindingID              string `json:"binding_id"`
		UploadID               string `json:"upload_id"`
		ExpectedUploadRevision int64  `json:"expected_upload_revision"`
		ContentSHA256          string `json:"content_sha256"`
	}{validated.OwnerID, validated.BindingID, validated.UploadID, validated.ExpectedUploadRevision, validated.ContentSHA256})
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return AttachmentUpload{}, Source{}, fmt.Errorf("begin knowledge upload commit: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	replay, response, err := claimKnowledgeMutation(ctx, tx, scope, operationCommitUpload, validated.IdempotencyKey, digest[:], validated.UploadID)
	if err != nil {
		return AttachmentUpload{}, Source{}, err
	}
	if replay {
		var snapshot commitSnapshot
		if err := decodeSnapshot(response, &snapshot); err != nil {
			return AttachmentUpload{}, Source{}, err
		}
		if err := requireNoKnowledgeLifecycleReservation(ctx, tx, repository.instanceID,
			snapshot.Upload.OwnerID, snapshot.Upload.BindingID); err != nil {
			return AttachmentUpload{}, Source{}, err
		}
		if validateStoredUpload(snapshot.Upload) != nil || validateStoredSource(snapshot.Source) != nil {
			return AttachmentUpload{}, Source{}, errors.New("invalid knowledge commit idempotency snapshot")
		}
		if err := validateUploadReplayState(ctx, tx, repository.instanceID, snapshot.Upload); err != nil {
			return AttachmentUpload{}, Source{}, err
		}
		if err := validateSourceReplayState(ctx, tx, repository.instanceID, snapshot.Source); err != nil {
			return AttachmentUpload{}, Source{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return AttachmentUpload{}, Source{}, fmt.Errorf("commit knowledge upload replay: %w", err)
		}
		return snapshot.Upload, snapshot.Source, nil
	}
	upload, err := lockUpload(ctx, tx, repository.instanceID, validated.OwnerID, validated.BindingID, validated.UploadID)
	if err != nil {
		return AttachmentUpload{}, Source{}, err
	}
	if upload.Status != UploadReceiving || upload.ReceivedSizeBytes != upload.DeclaredSizeBytes || upload.NextChunkOrdinal < 1 {
		return AttachmentUpload{}, Source{}, ErrState
	}
	if upload.Revision != validated.ExpectedUploadRevision {
		return AttachmentUpload{}, Source{}, ErrRevision
	}
	config, err := requireConfigRevision(ctx, tx, repository.instanceID, repository.catalog, upload.OwnerID, upload.BindingID, upload.BindingRevision, true)
	if err != nil {
		return AttachmentUpload{}, Source{}, err
	}
	title, err := readSourceTitle(ctx, tx, repository.instanceID, upload.OwnerID, upload.BindingID, upload.SourceID)
	if err != nil {
		return AttachmentUpload{}, Source{}, err
	}
	receipt, err := commit(ctx, AttachmentCommit{
		OwnerID: upload.OwnerID, BindingID: upload.BindingID, SourceID: upload.SourceID, UploadID: upload.UploadID,
		MediaType: upload.MediaType, DeclaredSizeBytes: upload.DeclaredSizeBytes, ChunkCount: upload.NextChunkOrdinal,
		ContentSHA256: validated.ContentSHA256, Title: title, Binding: config.Spec,
	})
	if err != nil {
		return AttachmentUpload{}, Source{}, err
	}
	if !receipt.valid(upload.DeclaredSizeBytes, validated.ContentSHA256) {
		return AttachmentUpload{}, Source{}, ErrInvalidBackend
	}
	upload, err = scanUpload(tx.QueryRow(ctx, `
		UPDATE knowledge_uploads SET status='committed', revision=revision+1, updated_at=clock_timestamp()
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3 AND upload_id=$4
		RETURNING owner_id, binding_id, source_id, upload_id, status, media_type,
		          declared_size_bytes, received_size_bytes, next_chunk_ordinal, revision, created_at, updated_at, binding_revision`,
		repository.instanceID, upload.OwnerID, upload.BindingID, upload.UploadID))
	if err != nil {
		return AttachmentUpload{}, Source{}, fmt.Errorf("finalize knowledge upload metadata: %w", err)
	}
	source, err := scanSource(tx.QueryRow(ctx, `
		UPDATE knowledge_sources
		SET status='ready', content_sha256=$5, backend_point_id=$6, indexed_segment_count=$7,
		    revision=revision+1, updated_at=clock_timestamp()
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3 AND source_id=$4
		RETURNING owner_id, binding_id, source_id, kind, status, media_type, size_bytes,
		          content_sha256, chunk_count, revision, created_at, updated_at, title, error_code`, repository.instanceID,
		upload.OwnerID, upload.BindingID, upload.SourceID, validated.ContentSHA256, receipt.PointID, receipt.IndexedSegmentCount))
	if err != nil {
		return AttachmentUpload{}, Source{}, fmt.Errorf("finalize knowledge source metadata: %w", err)
	}
	if err := setKnowledgeMutationResponse(ctx, tx, scope, operationCommitUpload, validated.IdempotencyKey, commitSnapshot{SchemaVersion: snapshotSchemaV1, Upload: upload, Source: source}); err != nil {
		return AttachmentUpload{}, Source{}, err
	}
	if err := advanceKnowledgeDataEpoch(ctx, tx, repository.instanceID, upload.OwnerID, upload.BindingID); err != nil {
		return AttachmentUpload{}, Source{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AttachmentUpload{}, Source{}, fmt.Errorf("commit knowledge upload completion: %w", err)
	}
	return upload, source, nil
}

func (repository *PostgresRepository) CreateMemory(ctx context.Context, scope MutationScope, command CreateMemoryCommand, store func(context.Context, MemoryContent) (ContentReceipt, error)) (Source, error) {
	if err := scope.Validate(); err != nil || store == nil {
		if err != nil {
			return Source{}, err
		}
		return Source{}, ErrInvalid
	}
	validated, err := command.Validated()
	if err != nil {
		return Source{}, err
	}
	digest, _ := commandDigest(struct {
		OwnerID                 string `json:"owner_id"`
		BindingID               string `json:"binding_id"`
		SourceID                string `json:"source_id"`
		ExpectedBindingRevision int64  `json:"expected_binding_revision"`
		SizeBytes               int    `json:"size_bytes"`
		ContentSHA256           string `json:"content_sha256"`
		Title                   string `json:"title"`
	}{validated.OwnerID, validated.BindingID, validated.SourceID, validated.ExpectedBindingRevision, len(validated.Content), validated.ContentSHA256, validated.Title})
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Source{}, fmt.Errorf("begin knowledge memory creation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	replay, response, err := claimKnowledgeMutation(ctx, tx, scope, operationCreateMemory, validated.IdempotencyKey, digest[:], validated.SourceID)
	if err != nil {
		return Source{}, err
	}
	if replay {
		var snapshot sourceSnapshot
		if err := decodeSnapshot(response, &snapshot); err != nil {
			return Source{}, err
		}
		if err := requireNoKnowledgeLifecycleReservation(ctx, tx, repository.instanceID,
			snapshot.Source.OwnerID, snapshot.Source.BindingID); err != nil {
			return Source{}, err
		}
		if err := validateStoredSource(snapshot.Source); err != nil {
			return Source{}, errors.New("invalid knowledge source idempotency snapshot")
		}
		if err := validateSourceReplayState(ctx, tx, repository.instanceID, snapshot.Source); err != nil {
			return Source{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return Source{}, fmt.Errorf("commit knowledge memory replay: %w", err)
		}
		return snapshot.Source, nil
	}
	config, err := requireConfigRevision(ctx, tx, repository.instanceID, repository.catalog, validated.OwnerID, validated.BindingID, validated.ExpectedBindingRevision, true)
	if err != nil {
		return Source{}, err
	}
	if err := reserveSourceIdentity(ctx, tx, repository.instanceID, validated.OwnerID, validated.BindingID, validated.SourceID); err != nil {
		return Source{}, err
	}
	memory := MemoryContent{OwnerID: validated.OwnerID, BindingID: validated.BindingID, SourceID: validated.SourceID,
		Content: append([]byte(nil), validated.Content...), ContentSHA256: validated.ContentSHA256, Title: validated.Title, Binding: config.Spec}
	receipt, err := store(ctx, memory)
	if err != nil {
		return Source{}, err
	}
	if !receipt.valid(int64(len(validated.Content)), validated.ContentSHA256) {
		return Source{}, ErrInvalidBackend
	}
	source, err := scanSource(tx.QueryRow(ctx, `
		INSERT INTO knowledge_sources (
		    agent_instance_id, owner_id, binding_id, source_id, kind, status, media_type,
		    size_bytes, content_sha256, backend_point_id, indexed_segment_count, chunk_count, title)
		VALUES ($1,$2,$3,$4,'memory','ready','text/plain',$5,$6,$7,$8,1,$9)
		RETURNING owner_id, binding_id, source_id, kind, status, media_type, size_bytes,
		          content_sha256, chunk_count, revision, created_at, updated_at, title, error_code`, repository.instanceID,
		validated.OwnerID, validated.BindingID, validated.SourceID, len(validated.Content), validated.ContentSHA256,
		receipt.PointID, receipt.IndexedSegmentCount, validated.Title))
	if uniqueViolation(err) {
		return Source{}, ErrConflict
	}
	if err != nil {
		return Source{}, fmt.Errorf("persist knowledge memory metadata: %w", err)
	}
	if err := setKnowledgeMutationResponse(ctx, tx, scope, operationCreateMemory, validated.IdempotencyKey, sourceSnapshot{SchemaVersion: snapshotSchemaV1, Source: source}); err != nil {
		return Source{}, err
	}
	if err := advanceKnowledgeDataEpoch(ctx, tx, repository.instanceID, validated.OwnerID, validated.BindingID); err != nil {
		return Source{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Source{}, fmt.Errorf("commit knowledge memory: %w", err)
	}
	return source, nil
}

func (repository *PostgresRepository) DeleteSource(ctx context.Context, scope MutationScope, command DeleteSourceCommand, remove func(context.Context, SourceTarget) error) (Source, error) {
	if err := scope.Validate(); err != nil || remove == nil {
		if err != nil {
			return Source{}, err
		}
		return Source{}, ErrInvalid
	}
	validated, err := command.Validated()
	if err != nil {
		return Source{}, err
	}
	digest, _ := commandDigest(validated)
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Source{}, fmt.Errorf("begin knowledge source deletion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	replay, response, err := claimKnowledgeMutation(ctx, tx, scope, operationDeleteSource, validated.IdempotencyKey, digest[:], validated.SourceID)
	if err != nil {
		return Source{}, err
	}
	if replay {
		var snapshot sourceSnapshot
		if err := decodeSnapshot(response, &snapshot); err != nil {
			return Source{}, err
		}
		if err := requireNoKnowledgeLifecycleReservation(ctx, tx, repository.instanceID,
			snapshot.Source.OwnerID, snapshot.Source.BindingID); err != nil {
			return Source{}, err
		}
		if err := validateStoredSource(snapshot.Source); err != nil {
			return Source{}, errors.New("invalid knowledge source idempotency snapshot")
		}
		if err := validateSourceReplayState(ctx, tx, repository.instanceID, snapshot.Source); err != nil {
			return Source{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return Source{}, fmt.Errorf("commit knowledge deletion replay: %w", err)
		}
		return snapshot.Source, nil
	}
	config, err := requireConfigRevision(ctx, tx, repository.instanceID, repository.catalog, validated.OwnerID, validated.BindingID, validated.ExpectedBindingRevision, false)
	if err != nil {
		return Source{}, err
	}
	source, err := scanSource(tx.QueryRow(ctx, `
		SELECT owner_id, binding_id, source_id, kind, status, media_type, size_bytes,
		       content_sha256, chunk_count, revision, created_at, updated_at, title, error_code
		FROM knowledge_sources
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3 AND source_id=$4
		FOR UPDATE`, repository.instanceID, validated.OwnerID, validated.BindingID, validated.SourceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Source{}, ErrNotFound
	}
	if err != nil {
		return Source{}, fmt.Errorf("lock knowledge source: %w", err)
	}
	if source.Revision != validated.ExpectedSourceRevision {
		return Source{}, ErrRevision
	}
	if source.Status == SourceDeleted || source.Status == SourceDeleting {
		return Source{}, ErrState
	}
	if err := remove(ctx, SourceTarget{OwnerID: source.OwnerID, BindingID: source.BindingID, SourceID: source.SourceID, Binding: config.Spec}); err != nil {
		return Source{}, err
	}
	source, err = scanSource(tx.QueryRow(ctx, `
		UPDATE knowledge_sources
		SET status='deleted', revision=revision+1, updated_at=clock_timestamp()
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3 AND source_id=$4
		RETURNING owner_id, binding_id, source_id, kind, status, media_type, size_bytes,
		          content_sha256, chunk_count, revision, created_at, updated_at, title, error_code`, repository.instanceID,
		validated.OwnerID, validated.BindingID, validated.SourceID))
	if err != nil {
		return Source{}, fmt.Errorf("delete knowledge source metadata: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE knowledge_uploads SET status='failed', revision=revision+1, updated_at=clock_timestamp()
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3 AND source_id=$4 AND status='receiving'`,
		repository.instanceID, validated.OwnerID, validated.BindingID, validated.SourceID); err != nil {
		return Source{}, fmt.Errorf("close knowledge source upload: %w", err)
	}
	if err := setKnowledgeMutationResponse(ctx, tx, scope, operationDeleteSource, validated.IdempotencyKey, sourceSnapshot{SchemaVersion: snapshotSchemaV1, Source: source}); err != nil {
		return Source{}, err
	}
	if err := advanceKnowledgeDataEpoch(ctx, tx, repository.instanceID, validated.OwnerID, validated.BindingID); err != nil {
		return Source{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Source{}, fmt.Errorf("commit knowledge source deletion: %w", err)
	}
	return source, nil
}

func (repository *PostgresRepository) ValidateSearchSources(ctx context.Context, ownerID, bindingID string, sourceIDs []string) error {
	ownerID, bindingID = strings.TrimSpace(ownerID), strings.TrimSpace(bindingID)
	if !validOwnerID(ownerID) || !canonicalUUID(bindingID) || len(sourceIDs) > MaxSearchResults {
		return ErrInvalid
	}
	if len(sourceIDs) == 0 {
		return nil
	}
	parsed := make([]uuid.UUID, 0, len(sourceIDs))
	for _, sourceID := range sourceIDs {
		if !canonicalUUID(sourceID) {
			return ErrInvalidBackend
		}
		value, _ := uuid.Parse(sourceID)
		parsed = append(parsed, value)
	}
	var count int
	if err := repository.pool.QueryRow(ctx, `
		SELECT count(*) FROM knowledge_sources
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3 AND status='ready' AND source_id=ANY($4)`,
		repository.instanceID, ownerID, bindingID, parsed).Scan(&count); err != nil {
		return fmt.Errorf("validate knowledge search sources: %w", err)
	}
	if count != len(parsed) {
		return ErrNotFound
	}
	return nil
}

func (repository *PostgresRepository) StatusFacts(ctx context.Context, ownerID, bindingID string) (StatusFacts, error) {
	ownerID, bindingID = strings.TrimSpace(ownerID), strings.TrimSpace(bindingID)
	if !validOwnerID(ownerID) || !canonicalUUID(bindingID) {
		return StatusFacts{}, ErrInvalid
	}
	var facts StatusFacts
	if err := repository.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status='ready'),
		       count(*) FILTER (WHERE status='uploading'),
		       count(*) FILTER (WHERE status='failed')
		FROM knowledge_sources
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3`,
		repository.instanceID, ownerID, bindingID).Scan(&facts.ReadySourceCount, &facts.UploadingSourceCount, &facts.FailedSourceCount); err != nil {
		return StatusFacts{}, fmt.Errorf("read knowledge status facts: %w", err)
	}
	if facts.ReadySourceCount > 0 {
		var challenge PersistenceChallenge
		err := repository.pool.QueryRow(ctx, `
			SELECT backend_point_id, source_id, size_bytes, content_sha256
			FROM knowledge_sources
			WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3 AND status='ready'
			ORDER BY source_id
			LIMIT 1`, repository.instanceID, ownerID, bindingID).Scan(
			&challenge.PointID, &challenge.SourceID, &challenge.SizeBytes, &challenge.ContentSHA256,
		)
		if err != nil {
			return StatusFacts{}, fmt.Errorf("read knowledge persistence challenge: %w", err)
		}
		if !canonicalUUID(challenge.PointID) || !canonicalUUID(challenge.SourceID) || challenge.SizeBytes < 1 || !validSHA256(challenge.ContentSHA256) {
			return StatusFacts{}, errors.New("knowledge persistence challenge is invalid")
		}
		facts.PersistenceChallenge = &challenge
	}
	return facts, nil
}

type configSnapshot struct {
	SchemaVersion int    `json:"schema_version"`
	Config        Config `json:"config"`
}
type uploadSnapshot struct {
	SchemaVersion int              `json:"schema_version"`
	Upload        AttachmentUpload `json:"upload"`
}
type sourceSnapshot struct {
	SchemaVersion int    `json:"schema_version"`
	Source        Source `json:"source"`
}
type commitSnapshot struct {
	SchemaVersion int              `json:"schema_version"`
	Upload        AttachmentUpload `json:"upload"`
	Source        Source           `json:"source"`
}

func claimKnowledgeMutation(ctx context.Context, tx pgx.Tx, scope MutationScope, operation, key string, requestHash []byte, aggregateID string) (bool, []byte, error) {
	if err := scope.Validate(); err != nil || !canonicalUUID(key) || !canonicalUUID(aggregateID) || len(requestHash) != 32 {
		return false, nil, ErrInvalid
	}
	credentialID, _ := uuid.Parse(scope.CredentialID)
	aggregateUUID, _ := uuid.Parse(aggregateID)
	result, err := tx.Exec(ctx, `
		INSERT INTO idempotency_records (
		    operation, caller_client_id, caller_credential_id, idempotency_key, request_hash, aggregate_id)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (operation, caller_client_id, caller_credential_id, idempotency_key) DO NOTHING`,
		operation, strings.TrimSpace(scope.ClientID), credentialID, key, requestHash, aggregateUUID)
	if err != nil {
		return false, nil, fmt.Errorf("claim knowledge idempotency key: %w", err)
	}
	if result.RowsAffected() == 1 {
		return false, nil, nil
	}
	var storedHash, response []byte
	var storedAggregate uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT request_hash, aggregate_id, response_json
		FROM idempotency_records
		WHERE operation=$1 AND caller_client_id=$2 AND caller_credential_id=$3 AND idempotency_key=$4
		FOR UPDATE`, operation, strings.TrimSpace(scope.ClientID), credentialID, key).Scan(&storedHash, &storedAggregate, &response); err != nil {
		return false, nil, fmt.Errorf("read knowledge idempotency key: %w", err)
	}
	if !bytes.Equal(storedHash, requestHash) || storedAggregate != aggregateUUID {
		return false, nil, ErrConflict
	}
	if len(response) == 0 {
		return false, nil, errors.New("knowledge idempotency response is unavailable")
	}
	return true, response, nil
}

func setKnowledgeMutationResponse(ctx context.Context, tx pgx.Tx, scope MutationScope, operation, key string, snapshot any) error {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return errors.New("encode knowledge idempotency response")
	}
	credentialID, _ := uuid.Parse(scope.CredentialID)
	result, err := tx.Exec(ctx, `
		UPDATE idempotency_records SET response_json=$5
		WHERE operation=$1 AND caller_client_id=$2 AND caller_credential_id=$3 AND idempotency_key=$4
		  AND response_json IS NULL`, operation, strings.TrimSpace(scope.ClientID), credentialID, key, encoded)
	if err != nil {
		return fmt.Errorf("persist knowledge idempotency response: %w", err)
	}
	if result.RowsAffected() != 1 {
		return errors.New("knowledge idempotency response already exists")
	}
	return nil
}

func decodeSnapshot(encoded []byte, target any) error {
	if err := json.Unmarshal(encoded, target); err != nil {
		return errors.New("invalid knowledge idempotency snapshot")
	}
	var schema struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(encoded, &schema); err != nil || schema.SchemaVersion != snapshotSchemaV1 {
		return errors.New("invalid knowledge idempotency snapshot")
	}
	return nil
}

func requireConfigRevision(ctx context.Context, tx pgx.Tx, instanceID uuid.UUID, catalog Catalog, ownerID, bindingID string, revision int64, requireEnabled bool) (Config, error) {
	config, err := scanConfig(tx.QueryRow(ctx, `
		SELECT owner_id, binding_id, deployment_id, managed_service_id, recipe_digest,
		       embedding_profile_id, enabled, revision, created_at, updated_at
		FROM knowledge_configs
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3
		FOR UPDATE`, instanceID, ownerID, bindingID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Config{}, ErrNotFound
	} else if err != nil {
		return Config{}, fmt.Errorf("read knowledge binding revision: %w", err)
	}
	if err := validateStoredConfig(config, catalog); err != nil {
		return Config{}, err
	}
	if config.Revision != revision {
		return Config{}, ErrRevision
	}
	if requireEnabled && !config.Spec.Enabled {
		return Config{}, ErrState
	}
	if err := rejectKnowledgeLifecycleReservation(ctx, tx, instanceID, ownerID, bindingID); err != nil {
		return Config{}, err
	}
	return config, nil
}

func requireNoKnowledgeLifecycleReservation(ctx context.Context, tx pgx.Tx, instanceID uuid.UUID, ownerID, bindingID string) error {
	var found bool
	if err := tx.QueryRow(ctx, `SELECT true FROM knowledge_configs
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3
		FOR UPDATE`, instanceID, ownerID, bindingID).Scan(&found); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("lock knowledge binding for replay: %w", err)
	}
	return rejectKnowledgeLifecycleReservation(ctx, tx, instanceID, ownerID, bindingID)
}

func rejectKnowledgeLifecycleReservation(ctx context.Context, tx pgx.Tx, instanceID uuid.UUID, ownerID, bindingID string) error {
	var lifecycleReserved bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM managed_knowledge_lifecycle_operations
		WHERE agent_instance_id=$1 AND owner_id=$2 AND knowledge_binding_id=$3
		  AND execution_fenced_at IS NOT NULL AND reservation_released_at IS NULL
		  AND status IN ('scheduled','running')
	)`, instanceID, ownerID, bindingID).Scan(&lifecycleReserved); err != nil {
		return fmt.Errorf("read knowledge lifecycle mutation reservation: %w", err)
	}
	if lifecycleReserved {
		return ErrState
	}
	return nil
}

func advanceKnowledgeDataEpoch(ctx context.Context, tx pgx.Tx, instanceID uuid.UUID, ownerID, bindingID string) error {
	tag, err := tx.Exec(ctx, `UPDATE knowledge_configs
		SET data_epoch=data_epoch+1,backend_generation_digest=NULL,updated_at=clock_timestamp()
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3`,
		instanceID, ownerID, bindingID)
	if err != nil {
		return fmt.Errorf("advance knowledge data epoch: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return nil
}

func reserveSourceIdentity(ctx context.Context, tx pgx.Tx, instanceID uuid.UUID, ownerID, bindingID, sourceID string) error {
	lockKey := "knowledge/source/" + instanceID.String() + "/" + bindingID + "/" + sourceID
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey); err != nil {
		return fmt.Errorf("lock knowledge source identity: %w", err)
	}
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1 FROM knowledge_sources
		    WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3 AND source_id=$4
		)`, instanceID, ownerID, bindingID, sourceID).Scan(&exists); err != nil {
		return fmt.Errorf("read knowledge source identity: %w", err)
	}
	if exists {
		return ErrConflict
	}
	return nil
}

func validateUploadReplayState(ctx context.Context, tx pgx.Tx, instanceID uuid.UUID, snapshot AttachmentUpload) error {
	current, err := lockUpload(ctx, tx, instanceID, snapshot.OwnerID, snapshot.BindingID, snapshot.UploadID)
	if errors.Is(err, ErrNotFound) {
		return ErrState
	}
	if err != nil {
		return err
	}
	if current.SourceID != snapshot.SourceID || current.MediaType != snapshot.MediaType ||
		current.DeclaredSizeBytes != snapshot.DeclaredSizeBytes ||
		current.ReceivedSizeBytes < snapshot.ReceivedSizeBytes ||
		current.NextChunkOrdinal < snapshot.NextChunkOrdinal || current.Revision < snapshot.Revision {
		return ErrState
	}
	if snapshot.Status == UploadCommitted && current.Status != UploadCommitted {
		return ErrState
	}
	return nil
}

func validateSourceReplayState(ctx context.Context, tx pgx.Tx, instanceID uuid.UUID, snapshot Source) error {
	current, err := scanSource(tx.QueryRow(ctx, `
		SELECT owner_id, binding_id, source_id, kind, status, media_type, size_bytes,
		       content_sha256, chunk_count, revision, created_at, updated_at, title, error_code
		FROM knowledge_sources
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3 AND source_id=$4
		FOR UPDATE`, instanceID, snapshot.OwnerID, snapshot.BindingID, snapshot.SourceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrState
	}
	if err != nil {
		return fmt.Errorf("validate knowledge source replay state: %w", err)
	}
	if current.Kind != snapshot.Kind || current.MediaType != snapshot.MediaType ||
		current.SizeBytes != snapshot.SizeBytes || current.ContentSHA256 != snapshot.ContentSHA256 ||
		current.Title != snapshot.Title || current.Revision < snapshot.Revision {
		return ErrState
	}
	if snapshot.Status == SourceDeleted && current.Status != SourceDeleted {
		return ErrState
	}
	return nil
}

func lockUpload(ctx context.Context, tx pgx.Tx, instanceID uuid.UUID, ownerID, bindingID, uploadID string) (AttachmentUpload, error) {
	upload, err := scanUpload(tx.QueryRow(ctx, `
		SELECT owner_id, binding_id, source_id, upload_id, status, media_type,
		       declared_size_bytes, received_size_bytes, next_chunk_ordinal, revision, created_at, updated_at, binding_revision
		FROM knowledge_uploads
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3 AND upload_id=$4
		FOR UPDATE`, instanceID, ownerID, bindingID, uploadID))
	if errors.Is(err, pgx.ErrNoRows) {
		return AttachmentUpload{}, ErrNotFound
	}
	if err != nil {
		return AttachmentUpload{}, fmt.Errorf("lock knowledge upload: %w", err)
	}
	return upload, nil
}

func readSourceTitle(ctx context.Context, tx pgx.Tx, instanceID uuid.UUID, ownerID, bindingID, sourceID string) (string, error) {
	var title string
	if err := tx.QueryRow(ctx, `
		SELECT title FROM knowledge_sources
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3 AND source_id=$4`,
		instanceID, ownerID, bindingID, sourceID).Scan(&title); errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	} else if err != nil {
		return "", fmt.Errorf("read knowledge source title: %w", err)
	}
	if !validSourceTitle(title) {
		return "", errors.New("stored knowledge source title is invalid")
	}
	return title, nil
}

type configScanner interface{ Scan(...any) error }

func scanConfig(scanner configScanner) (Config, error) {
	var value Config
	err := scanner.Scan(&value.OwnerID, &value.BindingID, &value.Spec.DeploymentID, &value.Spec.ManagedServiceID,
		&value.Spec.RecipeDigest, &value.Spec.EmbeddingProfileID, &value.Spec.Enabled, &value.Revision, &value.CreatedAt, &value.UpdatedAt)
	value.CreatedAt, value.UpdatedAt = value.CreatedAt.UTC(), value.UpdatedAt.UTC()
	return value, err
}

func validateStoredConfig(config Config, catalog Catalog) error {
	if !validOwnerID(config.OwnerID) || !canonicalUUID(config.BindingID) || config.Revision < 1 || config.Spec.normalized().validate(catalog) != nil ||
		config.CreatedAt.IsZero() || config.UpdatedAt.IsZero() {
		return errors.New("stored knowledge config is invalid")
	}
	return nil
}

type sourceScanner interface{ Scan(...any) error }

func scanSource(scanner sourceScanner) (Source, error) {
	var value Source
	err := scanner.Scan(&value.OwnerID, &value.BindingID, &value.SourceID, &value.Kind, &value.Status, &value.MediaType,
		&value.SizeBytes, &value.ContentSHA256, &value.ChunkCount, &value.Revision, &value.CreatedAt, &value.UpdatedAt, &value.Title, &value.ErrorCode)
	if err != nil {
		return Source{}, err
	}
	value.CreatedAt, value.UpdatedAt = value.CreatedAt.UTC(), value.UpdatedAt.UTC()
	if err := validateStoredSource(value); err != nil {
		return Source{}, err
	}
	return value, nil
}

type uploadScanner interface{ Scan(...any) error }

func scanUpload(scanner uploadScanner) (AttachmentUpload, error) {
	var value AttachmentUpload
	err := scanner.Scan(&value.OwnerID, &value.BindingID, &value.SourceID, &value.UploadID, &value.Status, &value.MediaType,
		&value.DeclaredSizeBytes, &value.ReceivedSizeBytes, &value.NextChunkOrdinal, &value.Revision, &value.CreatedAt, &value.UpdatedAt,
		&value.BindingRevision)
	if err != nil {
		return AttachmentUpload{}, err
	}
	value.CreatedAt, value.UpdatedAt = value.CreatedAt.UTC(), value.UpdatedAt.UTC()
	if err := validateStoredUpload(value); err != nil {
		return AttachmentUpload{}, err
	}
	return value, nil
}

func validateStoredSource(value Source) error {
	validKind := value.Kind == SourceAttachment || value.Kind == SourceMemory
	validStatus := value.Status == SourceUploading || value.Status == SourceReady || value.Status == SourceDeleting || value.Status == SourceDeleted || value.Status == SourceFailed
	validErrorCode := value.ErrorCode == "" || value.ErrorCode == "ingest_failed" || value.ErrorCode == "backend_unavailable" || value.ErrorCode == "invalid_content"
	mediaType, mediaErr := normalizeMediaType(value.MediaType)
	validDigest := value.ContentSHA256 == "" || validSHA256(value.ContentSHA256)
	if !validOwnerID(value.OwnerID) || !canonicalUUID(value.BindingID) || !canonicalUUID(value.SourceID) || !validKind || !validStatus ||
		mediaErr != nil || mediaType != value.MediaType || !validSourceTitle(value.Title) || value.SizeBytes < 1 || value.SizeBytes > MaxAttachmentSizeBytes ||
		!validDigest || (value.Status == SourceReady && value.ContentSHA256 == "") || value.ChunkCount < 0 || value.Revision < 1 ||
		value.CreatedAt.IsZero() || value.UpdatedAt.IsZero() || !validErrorCode {
		return errors.New("stored knowledge source is invalid")
	}
	return nil
}

func validateStoredUpload(value AttachmentUpload) error {
	validStatus := value.Status == UploadReceiving || value.Status == UploadCommitted || value.Status == UploadFailed
	mediaType, mediaErr := normalizeMediaType(value.MediaType)
	if !validOwnerID(value.OwnerID) || !canonicalUUID(value.BindingID) || !canonicalUUID(value.SourceID) || !canonicalUUID(value.UploadID) ||
		!validStatus || mediaErr != nil || mediaType != value.MediaType || value.DeclaredSizeBytes < 1 || value.DeclaredSizeBytes > MaxAttachmentSizeBytes ||
		value.ReceivedSizeBytes < 0 || value.ReceivedSizeBytes > value.DeclaredSizeBytes || value.NextChunkOrdinal < 0 || value.Revision < 1 ||
		value.BindingRevision < 1 || value.CreatedAt.IsZero() || value.UpdatedAt.IsZero() ||
		(value.Status == UploadCommitted && value.ReceivedSizeBytes != value.DeclaredSizeBytes) {
		return errors.New("stored knowledge upload is invalid")
	}
	return nil
}

func uniqueViolation(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "23505"
}
