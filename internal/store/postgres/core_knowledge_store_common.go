package postgres

// PostgreSQL persistence for the Core v1 Knowledge repository. This file owns
// shared repository wiring, replay bookkeeping, and binding resolution.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge/semantic"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// managed-file ports.

const knowledgeSnapshotTTL = 5 * time.Minute

const knowledgeMaxActiveUploads = 8

// resumableContentPort is optional. Implementations which can reopen a
// content sink after a process restart should provide it.
type resumableContentPort interface {
	Resume(context.Context, coreknowledge.UploadMetadata, int64, int32) (coreknowledge.ContentSink, error)
}

type rewindableContentSink interface {
	Rewind(context.Context, int64) error
}

type CoreKnowledgeStore struct {
	store   *Store
	content coreknowledge.StreamingContentPort
	opener  coreknowledge.ManagedFileOpener
	deleter coreknowledge.FileDeleter
	fence   coreknowledge.SourceReferenceFence
	search  coreknowledge.SearchResolver
	now     func() time.Time
	mu      sync.Mutex
	sinks   map[string]coreknowledge.ContentSink
}

type CoreKnowledgeStoreConfig struct {
	Content        coreknowledge.StreamingContentPort
	ManagedFiles   coreknowledge.ManagedFileOpener
	FileDeleter    coreknowledge.FileDeleter
	ReferenceFence coreknowledge.SourceReferenceFence
	Search         coreknowledge.SearchResolver
	Now            func() time.Time
}

func NewCoreKnowledgeStore(store *Store, cfg CoreKnowledgeStoreConfig) (*CoreKnowledgeStore, error) {
	if store == nil {
		return nil, errors.New("postgres store is required")
	}
	if cfg.Content == nil {
		return nil, errors.New("knowledge content port is required")
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &CoreKnowledgeStore{
		store: store, content: cfg.Content, opener: cfg.ManagedFiles,
		deleter: cfg.FileDeleter, fence: cfg.ReferenceFence, search: cfg.Search,
		now: now, sinks: make(map[string]coreknowledge.ContentSink),
	}, nil
}

func (r *CoreKnowledgeStore) ContentPort() coreknowledge.StreamingContentPort { return r.content }

// ResolveBindings exposes only promoted, ready source generations. A source
// being ready without a promoted revision is intentionally not searchable.
func (r *CoreKnowledgeStore) ResolveBindings(ctx context.Context, sourceIDs []string) ([]semantic.Binding, error) {
	if r == nil || r.store == nil || len(sourceIDs) > 128 {
		return nil, coreknowledge.ErrInvalid
	}
	seen := make(map[string]struct{}, len(sourceIDs))
	for _, id := range sourceIDs {
		if !coreknowledgeValidUUID(id) {
			return nil, coreknowledge.ErrInvalid
		}
		if _, ok := seen[id]; ok {
			return nil, coreknowledge.ErrInvalid
		}
		seen[id] = struct{}{}
	}
	var rows pgx.Rows
	var err error
	if len(sourceIDs) == 0 {
		rows, err = r.store.pool.Query(ctx, `SELECT source_id::text,promoted_revision,promoted_generation,promoted_profile_id::text,promoted_profile_revision,promoted_collection_config_digest FROM core_knowledge_sources WHERE status='ready' AND promoted_revision=revision AND promoted_revision > 0 ORDER BY source_id`)
	} else {
		rows, err = r.store.pool.Query(ctx, `SELECT source_id::text,promoted_revision,promoted_generation,promoted_profile_id::text,promoted_profile_revision,promoted_collection_config_digest FROM core_knowledge_sources WHERE source_id = ANY($1::uuid[]) AND status='ready' AND promoted_revision=revision AND promoted_revision > 0 ORDER BY source_id`, sourceIDs)
	}
	if err != nil {
		return nil, coreknowledge.ErrConflict
	}
	defer rows.Close()
	out := make([]semantic.Binding, 0, len(sourceIDs))
	for rows.Next() {
		var id string
		var rev int64
		var generation string
		var profileID, configDigest string
		var profileRevision int64
		if err := rows.Scan(&id, &rev, &generation, &profileID, &profileRevision, &configDigest); err != nil || rev <= 0 || generation == "" || profileID == "" || profileRevision <= 0 || len(configDigest) != 64 {
			return nil, coreknowledge.ErrConflict
		}
		out = append(out, semantic.Binding{SourceID: id, Revision: rev, Generation: generation, EmbeddingProfileID: profileID, EmbeddingProfileRevision: profileRevision, CollectionConfigDigest: configDigest})
	}
	if err := rows.Err(); err != nil {
		return nil, coreknowledge.ErrConflict
	}
	if len(sourceIDs) > 0 && len(out) != len(sourceIDs) {
		return nil, coreknowledge.ErrNotFound
	}
	return out, nil
}

func coreknowledgeValidUUID(id string) bool { _, err := uuid.Parse(id); return err == nil }

func reserveKnowledgeQuota(ctx context.Context, tx pgx.Tx, replacingSourceID string, newSize int64) error {
	if newSize < 0 || newSize > coreknowledge.MaxSourceBytes {
		return coreknowledge.ErrLimitExceeded
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('knowledge:content-quota',0))`); err != nil {
		return coreknowledge.ErrConflict
	}
	var used int64
	var replacing any
	if replacingSourceID != "" {
		replacing = replacingSourceID
	}
	if err := tx.QueryRow(ctx, `SELECT COALESCE(sum(size_bytes),0) FROM core_knowledge_sources WHERE status NOT IN ('deleting','deleted') AND ($1::uuid IS NULL OR source_id<>$1::uuid)`, replacing).Scan(&used); err != nil {
		return coreknowledge.ErrConflict
	}
	if used+newSize > coreknowledge.MaxIndexableContentBytes {
		return coreknowledge.ErrQuotaExceeded
	}
	return nil
}

func (r *CoreKnowledgeStore) QuotaStatus(ctx context.Context) (coreknowledge.QuotaStatus, error) {
	if r == nil || r.store == nil {
		return coreknowledge.QuotaStatus{}, coreknowledge.ErrInvalid
	}
	var used int64
	if err := r.store.pool.QueryRow(ctx, `SELECT COALESCE(sum(size_bytes),0) FROM core_knowledge_sources WHERE status NOT IN ('deleting','deleted')`).Scan(&used); err != nil {
		return coreknowledge.QuotaStatus{}, coreknowledge.ErrConflict
	}
	remaining := coreknowledge.MaxIndexableContentBytes - used
	if remaining < 0 {
		remaining = 0
	}
	return coreknowledge.QuotaStatus{UsedBytes: used, LimitBytes: coreknowledge.MaxIndexableContentBytes, RemainingBytes: remaining, MaxSourceBytes: coreknowledge.MaxSourceBytes}, nil
}
func (r *CoreKnowledgeStore) nowUTC() time.Time {
	if r.now == nil {
		return time.Now().UTC()
	}
	return r.now().UTC()
}

type knowledgeReplay struct {
	Source coreknowledge.Source `json:"source,omitempty"`
	Upload coreknowledge.Upload `json:"upload,omitempty"`
	Pair   *knowledgePair       `json:"pair,omitempty"`
}
type knowledgePair struct {
	Upload coreknowledge.Upload `json:"upload"`
	Source coreknowledge.Source `json:"source"`
}

func knowledgeDigest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func knowledgeError(code string) error {
	switch code {
	case "cleanup_pending":
		return coreknowledge.ErrCleanupPending
	case "checksum_mismatch":
		return coreknowledge.ErrChecksumMismatch
	case "revision_conflict":
		return coreknowledge.ErrRevisionConflict
	case "not_found":
		return coreknowledge.ErrNotFound
	case "idempotency_conflict":
		return coreknowledge.ErrIdempotencyConflict
	case "ineligible":
		return coreknowledge.ErrIneligible
	default:
		if code != "" {
			return coreknowledge.ErrConflict
		}
		return nil
	}
}
func knowledgeErrorCode(err error) string {
	switch {
	case errors.Is(err, coreknowledge.ErrCleanupPending):
		return "cleanup_pending"
	case errors.Is(err, coreknowledge.ErrChecksumMismatch):
		return "checksum_mismatch"
	case errors.Is(err, coreknowledge.ErrRevisionConflict):
		return "revision_conflict"
	case errors.Is(err, coreknowledge.ErrNotFound):
		return "not_found"
	case errors.Is(err, coreknowledge.ErrIdempotencyConflict):
		return "idempotency_conflict"
	case errors.Is(err, coreknowledge.ErrIneligible):
		return "ineligible"
	case err != nil:
		return "conflict"
	default:
		return ""
	}
}

func lockKnowledgeKey(ctx context.Context, tx pgx.Tx, operation, key string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "knowledge:"+operation+":"+key)
	return err
}

func replayKnowledge(ctx context.Context, tx pgx.Tx, operation, key, digest string, out any) (bool, error) {
	id, err := uuid.Parse(key)
	if err != nil {
		return false, coreknowledge.ErrInvalid
	}
	var stored, code string
	var raw []byte
	err = tx.QueryRow(ctx, `SELECT request_hash,response_json,error_code FROM core_knowledge_mutation_replays WHERE operation=$1 AND idempotency_key=$2 FOR UPDATE`, operation, id).Scan(&stored, &raw, &code)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, coreknowledge.ErrConflict
	}
	if stored != digest {
		return true, coreknowledge.ErrIdempotencyConflict
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		return true, coreknowledge.ErrConflict
	}
	return true, knowledgeError(code)
}

func putKnowledgeReplay(ctx context.Context, tx pgx.Tx, operation, key, digest string, value any, err error) error {
	id, parseErr := uuid.Parse(key)
	if parseErr != nil {
		return coreknowledge.ErrInvalid
	}
	raw, marshalErr := json.Marshal(value)
	if marshalErr != nil {
		return coreknowledge.ErrConflict
	}
	_, dbErr := tx.Exec(ctx, `INSERT INTO core_knowledge_mutation_replays(operation,idempotency_key,request_hash,response_json,error_code) VALUES($1,$2,$3,$4,$5)`, operation, id, digest, raw, knowledgeErrorCode(err))
	return dbErr
}

func updateKnowledgeReplay(ctx context.Context, tx pgx.Tx, operation, key string, value any, err error) error {
	id, parseErr := uuid.Parse(key)
	if parseErr != nil {
		return coreknowledge.ErrInvalid
	}
	raw, marshalErr := json.Marshal(value)
	if marshalErr != nil {
		return coreknowledge.ErrConflict
	}
	_, dbErr := tx.Exec(ctx, `UPDATE core_knowledge_mutation_replays SET response_json=$3,error_code=$4 WHERE operation=$1 AND idempotency_key=$2`, operation, id, raw, knowledgeErrorCode(err))
	return dbErr
}

func updateKnowledgeReplayHash(ctx context.Context, tx pgx.Tx, operation, key, requestHash string, value any, err error) error {
	id, parseErr := uuid.Parse(key)
	if parseErr != nil || len(requestHash) != sha256.Size*2 {
		return coreknowledge.ErrInvalid
	}
	raw, marshalErr := json.Marshal(value)
	if marshalErr != nil {
		return coreknowledge.ErrConflict
	}
	tag, dbErr := tx.Exec(ctx, `UPDATE core_knowledge_mutation_replays SET response_json=$3,error_code=$4 WHERE operation=$1 AND idempotency_key=$2 AND request_hash=$5`, operation, id, raw, knowledgeErrorCode(err), requestHash)
	if dbErr != nil {
		return dbErr
	}
	if tag.RowsAffected() != 1 {
		return coreknowledge.ErrConflict
	}
	return nil
}

type knowledgeSourceScanner interface{ Scan(...any) error }

func scanKnowledgeSource(row knowledgeSourceScanner) (coreknowledge.Source, error) {
	var s coreknowledge.Source
	var kind, status string
	var contentRef string
	if err := row.Scan(&s.ID, &kind, &status, &s.Title, &s.RelativePath, &s.Digest, &s.SizeBytes, &s.MediaType, &s.Revision, &contentRef, &s.ErrorCode, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return s, err
	}
	s.Kind, s.Status = coreknowledge.SourceKind(kind), coreknowledge.SourceStatus(status)
	s.ContentRef = contentRef
	s.CreatedAt, s.UpdatedAt = s.CreatedAt.UTC(), s.UpdatedAt.UTC()
	return s, nil
}

const knowledgeSourceSelect = `SELECT source_id,kind,status,title,relative_path,digest,size_bytes,media_type,revision,content_ref,error_code,created_at,updated_at FROM core_knowledge_sources`

var _ coreknowledge.Repository = (*CoreKnowledgeStore)(nil)
