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
	ErrIneligible            = errors.New("knowledge source is not eligible")
	ErrSourceReferenced      = errors.New("knowledge source is still referenced")
	ErrCursorConflict        = errors.New("knowledge cursor does not match query")
	ErrFilesystemUnavailable = errors.New("managed knowledge filesystem unavailable")
)

const (
	MaxUploadBytes      int64 = 64 << 20
	MaxUploadChunkBytes int   = 1 << 20
	MaxMemoryBytes      int   = 1 << 20
	MaxSnippetBytes     int   = 4096
	MaxSearchResults    int   = 100
)

type SourceKind string

const (
	SourceKindMount  SourceKind = "mount"
	SourceKindUpload SourceKind = "upload"
	SourceKindMemory SourceKind = "memory"
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

type MemoryCommand struct {
	IdempotencyKey string
	SourceID       string
	Title          string
	Content        string
	ContentSHA256  string
	MediaType      string
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
}

type SearchMatch struct {
	SourceID string
	ChunkRef string
	Snippet  string
	Score    float64
}

type SearchPage struct {
	Matches       []SearchMatch
	NextPageToken string
}

// SearchResolver is the semantic search boundary. A durable repository may
// persist the resolver's bounded, verified matches for stable pagination, but
// must not replace semantic retrieval with a SQL substring scan.
type SearchResolver interface {
	Search(context.Context, SearchQuery) (SearchPage, error)
}

type Status struct {
	ReadyCount          int
	UploadingCount      int
	IndexingCount       int
	FailedCount         int
	CleanupPendingCount int
	CheckedAt           time.Time
}

// TaskReference is intentionally generic: the task service owns task shape and
// persistence; Knowledge only returns a stable identifier.
type TaskReference struct{ TaskID string }

type IndexRequest struct {
	SourceIDs      []string
	IdempotencyKey string
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

// ContentSink is the bounded adapter port for streaming memory/upload content.
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
func (m MemoryCommand) validate() error {
	if !validUUID(m.IdempotencyKey) || (m.SourceID != "" && !validUUID(m.SourceID)) || strings.TrimSpace(m.Content) == "" || m.MediaType == "" {
		return ErrInvalid
	}
	if len([]byte(m.Content)) > MaxMemoryBytes {
		return ErrLimitExceeded
	}
	if m.ContentSHA256 != "" && !validDigest(m.ContentSHA256) {
		return ErrInvalid
	}
	return nil
}
func (m UploadMetadata) validate() error {
	if !validUUID(m.IdempotencyKey) || (m.UploadID != "" && !validUUID(m.UploadID)) || (m.SourceID != "" && !validUUID(m.SourceID)) || m.DeclaredSize <= 0 || m.DeclaredSize > MaxUploadBytes || m.MediaType == "" || !validDigest(m.ContentSHA256) {
		return ErrInvalid
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
	if !validUUID(c.IdempotencyKey) || !validUUID(c.SourceID) || c.ExpectedRevision < 1 {
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
	if q.Kind != "" && q.Kind != SourceKindMount && q.Kind != SourceKindUpload && q.Kind != SourceKindMemory {
		return ErrInvalid
	}
	if q.Status != "" && q.Status != SourceStatusReady && q.Status != SourceStatusUploading && q.Status != SourceStatusIndexing && q.Status != SourceStatusFailed && q.Status != SourceStatusDeleting && q.Status != SourceStatusCleanupPending && q.Status != SourceStatusDeleted {
		return ErrInvalid
	}
	_, err := decodePageCursor(q.PageToken)
	return err
}
func (q SearchQuery) validate() error {
	if strings.TrimSpace(q.Query) == "" || q.Limit < 0 || q.Limit > MaxSearchResults {
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
func (m MemoryCommand) ValidateForRepository() error       { return m.validate() }
func (m UploadMetadata) ValidateForRepository() error      { return m.validate() }
func (c UploadChunk) ValidateForRepository() error         { return c.validate() }
func (c CommitUploadCommand) ValidateForRepository() error { return c.validate() }
func (c DeleteCommand) ValidateForRepository() error       { return c.validate() }
func (q ListQuery) ValidateForRepository() error           { return q.validate() }
func (q SearchQuery) ValidateForRepository() error         { return q.validate() }

func sortSources(values []Source) {
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
}
