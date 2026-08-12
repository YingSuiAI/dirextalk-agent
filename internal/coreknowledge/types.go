// Package coreknowledge defines the Core v1 knowledge contract.  It deliberately
// contains no deployment, owner, worker, cloud, or persistence-specific fields.
package coreknowledge

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalid               = errors.New("invalid knowledge request")
	ErrNotFound              = errors.New("knowledge source not found")
	ErrConflict              = errors.New("knowledge conflict")
	ErrIdempotencyConflict   = errors.New("knowledge idempotency conflict")
	ErrRevisionConflict      = errors.New("knowledge revision conflict")
	ErrChecksumMismatch      = errors.New("knowledge checksum mismatch")
	ErrPathTraversal         = errors.New("knowledge path is outside managed directory")
	ErrCleanupPending        = errors.New("knowledge file cleanup pending")
	ErrLimitExceeded         = errors.New("knowledge request exceeds limit")
	ErrQuotaExceeded         = errors.New("knowledge content quota exceeded")
	ErrIneligible            = errors.New("knowledge source is not eligible")
	ErrSourceReferenced      = errors.New("knowledge source is still referenced")
	ErrCursorConflict        = errors.New("knowledge cursor does not match query")
	ErrFilesystemUnavailable = errors.New("managed knowledge filesystem unavailable")
)

const (
	MaxIndexableContentBytes int64 = 64 << 20
	MaxSourceBytes           int64 = 16 << 20
	MaxUploadBytes           int64 = MaxSourceBytes
	MaxUploadChunkBytes      int   = 1 << 20
	MaxSnippetBytes          int   = 4096
	MaxSearchResults         int   = 100
)

type SourceKind string

const (
	SourceKindMount  SourceKind = "mount"
	SourceKindUpload SourceKind = "upload"
)

type SourceStatus string

const (
	SourceStatusUploading      SourceStatus = "uploading"
	SourceStatusReady          SourceStatus = "ready"
	SourceStatusIndexing       SourceStatus = "indexing"
	SourceStatusFailed         SourceStatus = "failed"
	SourceStatusDeleting       SourceStatus = "deleting"
	SourceStatusCleanupPending SourceStatus = "cleanup_pending"
	SourceStatusDeleted        SourceStatus = "deleted"
)

type Source struct {
	ID           string
	Kind         SourceKind
	Status       SourceStatus
	Title        string
	RelativePath string
	Digest       string
	SizeBytes    int64
	MediaType    string
	Revision     int64
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ErrorCode    string
	ContentRef   string
}

// ContentReference identifies immutable bytes finalized by the content port.
// The repository stores this bounded descriptor, never the bytes themselves.
type ContentReference struct {
	Ref       string
	Digest    string
	SizeBytes int64
}

type UploadSession struct {
	UploadID     string
	SourceID     string
	ReceivedSize int64
	NextOrdinal  int32
	Revision     int64
}

type Page struct {
	Sources       []Source
	NextPageToken string
}

type ListQuery struct {
	PageSize  int
	PageToken string
	Status    SourceStatus
	Kind      SourceKind
}

type DeleteCommand struct {
	IdempotencyKey   string
	SourceID         string
	ExpectedRevision int64
	Kind             SourceKind
}

type MountCommand struct {
	IdempotencyKey string
	SourceID       string
	Title          string
	RelativePath   string
	Digest         string
	SizeBytes      int64
	MediaType      string
	FileOpener     ManagedFileOpener
}

type UploadMetadata struct {
	IdempotencyKey string
	UploadID       string
	SourceID       string
	Title          string
	RelativePath   string
	MediaType      string
	DeclaredSize   int64
	ContentSHA256  string
}

type UploadChunk struct {
	IdempotencyKey string
	UploadID       string
	Ordinal        int32
	OffsetBytes    int64
	Data           []byte
	ChunkSHA256    string
}

type Upload struct {
	ID           string
	SourceID     string
	Status       SourceStatus
	Metadata     UploadMetadata
	ReceivedSize int64
	NextChunk    int32
	Revision     int64
	CreatedAt    time.Time
	UpdatedAt    time.Time
	Session      UploadSession
	// Replayed is an in-process receipt marker for the upload.start mutation.
	// It is deliberately excluded from persistence/public DTOs; the capability
	// adapter exposes it only on the start response so a restarted caller can
	// distinguish an exact idempotent readback from a newly-created session.
	Replayed bool `json:"-"`
}

type CommitUploadCommand struct {
	IdempotencyKey   string
	UploadID         string
	ExpectedRevision int64
	ContentSHA256    string
}

type AbortUploadCommand struct {
	IdempotencyKey   string
	UploadID         string
	ExpectedRevision int64
}

type SearchQuery struct {
	Query     string
	SourceIDs []string
	Limit     int
	PageToken string
	Kind      SourceKind
}

type SearchMatch struct {
	SourceID string  `json:"source_id"`
	ChunkRef string  `json:"chunk_ref"`
	Snippet  string  `json:"snippet"`
	Score    float64 `json:"score"`
}

// SearchPage carries the immutable embedding binding used to produce the
// page.  The binding is deliberately projected once at page level rather
// than repeated on every match.  Repositories that support opaque cursors
// must persist these values with the cursor snapshot and replay them on every
// subsequent page; callers must never resolve the current default profile
// while resuming a cursor.
type SearchProvenance struct {
	EmbeddingProfileID       string `json:"embedding_profile_id,omitempty"`
	EmbeddingProfileRevision int64  `json:"embedding_profile_revision,omitempty"`
	EmbeddingModel           string `json:"embedding_model,omitempty"`
	EmbeddingGeneration      string `json:"embedding_generation,omitempty"`
	CollectionConfigDigest   string `json:"collection_config_digest,omitempty"`
}

type SearchPage struct {
	Matches       []SearchMatch `json:"items"`
	NextPageToken string        `json:"next_cursor"`
	SearchMode    string        `json:"search_mode,omitempty"`
	SearchProvenance
}

// SearchResolver is the semantic search boundary. A durable repository may
// persist the resolver's bounded, verified matches for stable pagination, but
// must not replace semantic retrieval with a SQL substring scan.
type SearchResolver interface {
	Search(context.Context, SearchQuery) (SearchPage, error)
}

type Status struct {
	ReadyCount          int       `json:"ready_count"`
	UploadingCount      int       `json:"uploading_count"`
	IndexingCount       int       `json:"indexing_count"`
	FailedCount         int       `json:"failed_count"`
	CleanupPendingCount int       `json:"cleanup_pending_count"`
	CheckedAt           time.Time `json:"checked_at"`
}

type QuotaStatus struct {
	UsedBytes      int64 `json:"quota_used_bytes"`
	LimitBytes     int64 `json:"quota_limit_bytes"`
	RemainingBytes int64 `json:"quota_remaining_bytes"`
	MaxSourceBytes int64 `json:"max_source_bytes"`
}

type QuotaStatusReader interface {
	QuotaStatus(context.Context) (QuotaStatus, error)
}

// EmbeddingConfig is the owner-scoped semantic binding used by new index and
// search requests. Deployment-owned endpoint/content roots are deliberately
// absent; only the embedding profile may be changed at runtime in v1. The
// dimension and collection are returned for observability and are immutable
// deployment invariants.
type EmbeddingConfig struct {
	EmbeddingProfileID string `json:"embedding_profile_id"`
	// The following fields are optional repository-local provenance hints. The
	// PostgreSQL semantic resolver obtains them from the model-profile
	// authority at search time; the in-memory repository accepts them so its
	// cursor snapshots can exercise the same immutable page contract.
	EmbeddingProfileRevision int64     `json:"embedding_profile_revision,omitempty"`
	EmbeddingModel           string    `json:"embedding_model,omitempty"`
	EmbeddingGeneration      string    `json:"embedding_generation,omitempty"`
	Dimension                int       `json:"dimension"`
	Collection               string    `json:"collection"`
	CollectionConfigDigest   string    `json:"collection_config_digest"`
	Revision                 int64     `json:"revision"`
	UpdatedAt                time.Time `json:"updated_at"`
}

type EmbeddingConfigCommand struct {
	IdempotencyKey         string
	ExpectedRevision       int64
	EmbeddingProfileID     string
	Dimension              int
	Collection             string
	CollectionConfigDigest string
}

type ActiveEmbeddingBinding struct {
	ProfileID        string
	ProfileRevision  int64
	CollectionDigest string
}

type EmbeddingSourceStatus struct {
	Status           SourceStatus `json:"status"`
	Indexed          bool         `json:"embedding_indexed"`
	Stale            bool         `json:"embedding_stale"`
	Revision         int64        `json:"revision"`
	PromotedRevision int64        `json:"promoted_revision"`
}

// EmbeddingConfigReader is intentionally a narrow optional repository port so
// semantic index/search paths can resolve the current owner config for every
// request without coupling to PostgreSQL.
type EmbeddingConfigReader interface {
	GetEmbeddingConfig(context.Context) (EmbeddingConfig, error)
}

type EmbeddingConfigStore interface {
	EmbeddingConfigReader
	EnsureEmbeddingConfig(context.Context, EmbeddingConfig) (EmbeddingConfig, error)
	UpdateEmbeddingConfig(context.Context, EmbeddingConfigCommand) (EmbeddingConfig, error)
}

// EmbeddingProfileDisabler invalidates semantic search/index state for one
// exact active profile while preserving source documents.
type EmbeddingProfileDisabler interface {
	DisableEmbeddingProfile(context.Context, string) (EmbeddingConfig, error)
}

// EmbeddingStatusReader is an optional persistence projection for promoted
// vector generations. A repository that cannot prove promotion should omit
// this port; callers then remain conservative and report zero indexed vectors
// rather than inferring them from source readiness.
type EmbeddingStatusReader interface {
	EmbeddingStatus(context.Context) (indexed, stale int, err error)
}

// TaskReference is intentionally generic: the task service owns task shape and
// persistence; Knowledge only returns a stable identifier.
type TaskReference struct{ TaskID string }

type IndexRequest struct {
	SourceIDs       []string
	IdempotencyKey  string
	ExpectedBinding *ActiveEmbeddingBinding
}

type Indexer interface {
	RequestIndex(context.Context, IndexRequest) (TaskReference, error)
}

type SourceReferenceFence interface {
	AcquireDeleteFence(context.Context, string) (DeleteFenceToken, error)
	ReleaseDeleteFence(context.Context, DeleteFenceToken) error
	// ConsumeDelete validates the token and atomically runs transition with the
	// source-reference check. If it fails, transition must not be committed.
	ConsumeDelete(context.Context, DeleteFenceToken, string, int64, func() error) error
}

type DeleteFenceToken struct {
	Token    string
	SourceID string
}

// ManagedFileOpener MUST resolve beneath its configured root with openat-style
// root-bound traversal and O_NOFOLLOW (or equivalent), never lexical checks alone.
type ManagedFileOpener interface {
	OpenManaged(context.Context, string) (io.ReadCloser, error)
}

// ContentSink is the bounded adapter port for streaming upload content.
// Implementations hash and count bytes while writing; callers must compare
// Size and SHA256 against the declared metadata before committing.
type ContentSink interface {
	io.Writer
	Size() int64
	SHA256() string
	Finalize(context.Context, string, int64) (ContentReference, error)
	Abort(context.Context) error
}

type StreamingContentPort interface {
	Begin(context.Context, UploadMetadata) (ContentSink, error)
	Delete(context.Context, ContentReference) error
}

// ContentReader is optional on content ports that can safely reopen a
// finalized immutable object.
type ContentReader interface {
	OpenContent(context.Context, ContentReference) (io.ReadCloser, error)
}

type FileDeleter interface {
	Delete(context.Context, string) error
}

func validUUID(s string) bool { _, err := uuid.Parse(strings.TrimSpace(s)); return err == nil }

func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func digestBytes(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func encodeCursor(id string) string { return base64.RawURLEncoding.EncodeToString([]byte(id)) }
func decodeCursor(token string) (string, error) {
	if token == "" {
		return "", nil
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(b) == 0 {
		return "", ErrInvalid
	}
	return string(b), nil
}

type cursor struct {
	LastID     string    `json:"last_id"`
	Ordinal    int       `json:"ordinal"`
	Snapshot   time.Time `json:"snapshot"`
	SnapshotID string    `json:"snapshot_id"`
	Digest     string    `json:"digest"`
}

func encodePageCursor(c cursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodePageCursor(token string) (cursor, error) {
	if token == "" {
		return cursor{}, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return cursor{}, ErrInvalid
	}
	var c cursor
	if json.Unmarshal(b, &c) != nil || c.Snapshot.IsZero() || c.SnapshotID == "" || c.Digest == "" || c.Ordinal < 0 || (c.LastID == "" && c.Ordinal == 0) {
		return cursor{}, ErrInvalid
	}
	return c, nil
}

func validateRelativePath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" || strings.HasPrefix(path, "/") || strings.HasPrefix(path, "\\") || strings.ContainsAny(path, "\\\x00\r\n") {
		return ErrPathTraversal
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return ErrPathTraversal
		}
	}
	return nil
}

func (m MountCommand) validate() error {
	if !validUUID(m.IdempotencyKey) || (m.SourceID != "" && !validUUID(m.SourceID)) || m.SizeBytes < 0 || m.MediaType == "" {
		return ErrInvalid
	}
	if err := validateRelativePath(m.RelativePath); err != nil {
		return err
	}
	if m.Digest != "" && !validDigest(m.Digest) {
		return ErrInvalid
	}
	return nil
}
func (m UploadMetadata) validate() error {
	if !validUUID(m.IdempotencyKey) || (m.UploadID != "" && !validUUID(m.UploadID)) || (m.SourceID != "" && !validUUID(m.SourceID)) || m.DeclaredSize <= 0 || m.MediaType == "" || !validDigest(m.ContentSHA256) {
		return ErrInvalid
	}
	if m.DeclaredSize > MaxUploadBytes {
		return ErrLimitExceeded
	}
	if m.RelativePath != "" {
		if err := validateRelativePath(m.RelativePath); err != nil {
			return err
		}
	}
	return nil
}
func (c UploadChunk) validate() error {
	if !validUUID(c.IdempotencyKey) || !validUUID(c.UploadID) || c.Ordinal < 0 || c.OffsetBytes < 0 || len(c.Data) == 0 || len(c.Data) > MaxUploadChunkBytes || !validDigest(c.ChunkSHA256) || digestBytes(c.Data) != strings.ToLower(c.ChunkSHA256) {
		return ErrInvalid
	}
	return nil
}
func (c DeleteCommand) validate() error {
	if !validUUID(c.IdempotencyKey) || !validUUID(c.SourceID) || c.ExpectedRevision < 1 || c.Kind != "" && c.Kind != SourceKindMount && c.Kind != SourceKindUpload {
		return ErrInvalid
	}
	return nil
}
func (c CommitUploadCommand) validate() error {
	if !validUUID(c.IdempotencyKey) || !validUUID(c.UploadID) || c.ExpectedRevision < 1 || !validDigest(c.ContentSHA256) {
		return ErrInvalid
	}
	return nil
}
func (q ListQuery) validate() error {
	if q.PageSize < 0 || q.PageSize > 100 {
		return ErrInvalid
	}
	if q.Kind != "" && q.Kind != SourceKindMount && q.Kind != SourceKindUpload {
		return ErrInvalid
	}
	if q.Status != "" && q.Status != SourceStatusReady && q.Status != SourceStatusUploading && q.Status != SourceStatusIndexing && q.Status != SourceStatusFailed && q.Status != SourceStatusDeleting && q.Status != SourceStatusCleanupPending && q.Status != SourceStatusDeleted {
		return ErrInvalid
	}
	_, err := decodePageCursor(q.PageToken)
	return err
}
func (q SearchQuery) validate() error {
	if strings.TrimSpace(q.Query) == "" || q.Limit < 0 || q.Limit > MaxSearchResults || q.Kind != "" && q.Kind != SourceKindMount && q.Kind != SourceKindUpload {
		return ErrInvalid
	}
	if _, err := decodePageCursor(q.PageToken); err != nil {
		return err
	}
	for _, id := range q.SourceIDs {
		if !validUUID(id) {
			return ErrInvalid
		}
	}
	return nil
}
func (r TaskReference) validate() error {
	if !validUUID(r.TaskID) {
		return ErrInvalid
	}
	return nil
}
func (r UploadMetadata) String() string { return fmt.Sprintf("%s:%s", r.UploadID, r.ContentSHA256) }

// The repository adapter uses these explicit boundary validators without
// exposing the package's internal validation implementation.
func (m MountCommand) ValidateForRepository() error        { return m.validate() }
func (m UploadMetadata) ValidateForRepository() error      { return m.validate() }
func (c UploadChunk) ValidateForRepository() error         { return c.validate() }
func (c CommitUploadCommand) ValidateForRepository() error { return c.validate() }
func (c DeleteCommand) ValidateForRepository() error       { return c.validate() }
func (q ListQuery) ValidateForRepository() error           { return q.validate() }
func (q SearchQuery) ValidateForRepository() error         { return q.validate() }

func sortSources(values []Source) {
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
}
