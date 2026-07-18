package knowledge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"mime"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

const (
	MaxAttachmentSizeBytes       int64 = 64 << 20
	MaxAttachmentChunkBytes            = 256 << 10
	MaxMemorySizeBytes                 = 1 << 20
	MaxSearchQueryBytes                = 16 << 10
	MaxSearchResults                   = 50
	MaxIndexedAttachmentSegments       = 32769
	MaxIndexedMemorySegments           = 512
	MaxListSourcesPageSize             = 100
	MaxSourceTitleBytes                = 255
)

var (
	ErrInvalid         = errors.New("invalid knowledge request")
	ErrInvalidCaller   = errors.New("invalid knowledge caller")
	ErrNotFound        = errors.New("knowledge entity not found")
	ErrRevision        = errors.New("knowledge revision does not match")
	ErrConflict        = idempotency.ErrConflict
	ErrState           = errors.New("knowledge entity state does not allow the operation")
	ErrUnavailable     = errors.New("knowledge backend is unavailable")
	ErrInvalidBackend  = errors.New("knowledge backend returned invalid evidence")
	ErrImmutableConfig = errors.New("knowledge binding identity is immutable")
	ErrAmbiguousConfig = errors.New("multiple knowledge bindings require an explicit binding id")
)

var chunkRefPattern = regexp.MustCompile(`^chunk:[A-Za-z0-9][A-Za-z0-9._-]{0,479}$`)

type MutationScope struct {
	ClientID     string
	CredentialID string
}

func (scope MutationScope) Validate() error {
	clientID := strings.TrimSpace(scope.ClientID)
	if clientID == "" || len(clientID) > 255 || strings.ContainsAny(clientID, "\r\n\t") || security.ContainsLikelySecret(clientID) {
		return ErrInvalidCaller
	}
	if !canonicalUUID(scope.CredentialID) {
		return ErrInvalidCaller
	}
	return nil
}

type ConfigSpec struct {
	DeploymentID       string
	ManagedServiceID   string
	RecipeDigest       string
	EmbeddingProfileID string
	Enabled            bool
}

func (spec ConfigSpec) normalized() ConfigSpec {
	spec.DeploymentID = strings.TrimSpace(spec.DeploymentID)
	spec.ManagedServiceID = strings.TrimSpace(spec.ManagedServiceID)
	spec.RecipeDigest = strings.ToLower(strings.TrimSpace(spec.RecipeDigest))
	spec.EmbeddingProfileID = strings.ToLower(strings.TrimSpace(spec.EmbeddingProfileID))
	return spec
}

func (spec ConfigSpec) validate(catalog Catalog) error {
	if !canonicalUUID(spec.DeploymentID) || !canonicalUUID(spec.ManagedServiceID) || !validSHA256(spec.RecipeDigest) || !catalog.Contains(spec.EmbeddingProfileID) {
		return ErrInvalid
	}
	for _, value := range []string{spec.DeploymentID, spec.ManagedServiceID, spec.RecipeDigest, spec.EmbeddingProfileID} {
		if security.ContainsLikelySecret(value) {
			return ErrInvalid
		}
	}
	return nil
}

func (spec ConfigSpec) SameIdentity(other ConfigSpec) bool {
	spec, other = spec.normalized(), other.normalized()
	return spec.DeploymentID == other.DeploymentID && spec.ManagedServiceID == other.ManagedServiceID &&
		spec.RecipeDigest == other.RecipeDigest && spec.EmbeddingProfileID == other.EmbeddingProfileID
}

type Config struct {
	OwnerID   string
	BindingID string
	Spec      ConfigSpec
	Revision  int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

type PutConfigCommand struct {
	IdempotencyKey   string
	OwnerID          string
	BindingID        string
	Spec             ConfigSpec
	ExpectedRevision int64
}

func (command PutConfigCommand) Validated(catalog Catalog) (PutConfigCommand, error) {
	command.OwnerID = strings.TrimSpace(command.OwnerID)
	command.BindingID = strings.TrimSpace(command.BindingID)
	command.Spec = command.Spec.normalized()
	if !canonicalUUID(command.IdempotencyKey) || !validOwnerID(command.OwnerID) || !canonicalUUID(command.BindingID) || command.ExpectedRevision < 0 || command.Spec.validate(catalog) != nil {
		return PutConfigCommand{}, ErrInvalid
	}
	return command, nil
}

func (command PutConfigCommand) Digest() ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(struct {
		OwnerID          string     `json:"owner_id"`
		BindingID        string     `json:"binding_id"`
		Spec             ConfigSpec `json:"spec"`
		ExpectedRevision int64      `json:"expected_revision"`
	}{command.OwnerID, command.BindingID, command.Spec, command.ExpectedRevision})
	if err != nil {
		return [sha256.Size]byte{}, ErrInvalid
	}
	return sha256.Sum256(encoded), nil
}

type SourceKind string

const (
	SourceAttachment SourceKind = "attachment"
	SourceMemory     SourceKind = "memory"
)

type SourceStatus string

const (
	SourceUploading SourceStatus = "uploading"
	SourceReady     SourceStatus = "ready"
	SourceDeleting  SourceStatus = "deleting"
	SourceDeleted   SourceStatus = "deleted"
	SourceFailed    SourceStatus = "failed"
)

type Source struct {
	OwnerID       string
	BindingID     string
	SourceID      string
	Kind          SourceKind
	Status        SourceStatus
	MediaType     string
	SizeBytes     int64
	ContentSHA256 string
	ChunkCount    int32
	Revision      int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
	Title         string
	ErrorCode     string
}

type ListSourcesQuery struct {
	OwnerID       string
	BindingID     string
	PageSize      int
	AfterSourceID string
}

func (query ListSourcesQuery) Validated() (ListSourcesQuery, error) {
	query.OwnerID = strings.TrimSpace(query.OwnerID)
	query.BindingID = strings.TrimSpace(query.BindingID)
	query.AfterSourceID = strings.TrimSpace(query.AfterSourceID)
	if !validOwnerID(query.OwnerID) || !canonicalUUID(query.BindingID) || query.PageSize < 0 || query.PageSize > MaxListSourcesPageSize ||
		(query.AfterSourceID != "" && !canonicalUUID(query.AfterSourceID)) {
		return ListSourcesQuery{}, ErrInvalid
	}
	if query.PageSize == 0 {
		query.PageSize = 50
	}
	return query, nil
}

type SourcePage struct {
	Sources      []Source
	NextSourceID string
}

type UploadStatus string

const (
	UploadReceiving UploadStatus = "receiving"
	UploadCommitted UploadStatus = "committed"
	UploadFailed    UploadStatus = "failed"
)

type AttachmentUpload struct {
	OwnerID           string
	BindingID         string
	SourceID          string
	UploadID          string
	Status            UploadStatus
	MediaType         string
	DeclaredSizeBytes int64
	ReceivedSizeBytes int64
	NextChunkOrdinal  int32
	Revision          int64
	CreatedAt         time.Time
	UpdatedAt         time.Time
	BindingRevision   int64
}

type StartAttachmentUploadCommand struct {
	IdempotencyKey          string
	OwnerID                 string
	BindingID               string
	SourceID                string
	UploadID                string
	MediaType               string
	DeclaredSizeBytes       int64
	ExpectedBindingRevision int64
	Title                   string
}

func (command StartAttachmentUploadCommand) Validated() (StartAttachmentUploadCommand, error) {
	command.OwnerID = strings.TrimSpace(command.OwnerID)
	command.BindingID = strings.TrimSpace(command.BindingID)
	command.SourceID = strings.TrimSpace(command.SourceID)
	command.UploadID = strings.TrimSpace(command.UploadID)
	command.Title = strings.TrimSpace(command.Title)
	mediaType, err := normalizeMediaType(command.MediaType)
	if err != nil || !canonicalUUID(command.IdempotencyKey) || !validOwnerID(command.OwnerID) || !canonicalUUID(command.BindingID) ||
		!canonicalUUID(command.SourceID) || !canonicalUUID(command.UploadID) || command.DeclaredSizeBytes < 1 || command.DeclaredSizeBytes > MaxAttachmentSizeBytes ||
		command.ExpectedBindingRevision < 1 {
		return StartAttachmentUploadCommand{}, ErrInvalid
	}
	if !validSourceTitle(command.Title) {
		return StartAttachmentUploadCommand{}, ErrInvalid
	}
	command.MediaType = mediaType
	return command, nil
}

type AttachmentChunk struct {
	OwnerID           string
	BindingID         string
	SourceID          string
	UploadID          string
	MediaType         string
	DeclaredSizeBytes int64
	OffsetBytes       int64
	ChunkOrdinal      int32
	Chunk             []byte
	ChunkSHA256       string
	Title             string
	Binding           ConfigSpec
}

type AppendAttachmentChunkCommand struct {
	IdempotencyKey         string
	OwnerID                string
	BindingID              string
	UploadID               string
	ExpectedUploadRevision int64
	OffsetBytes            int64
	ChunkOrdinal           int32
	Chunk                  []byte
	ChunkSHA256            string
}

func (command AppendAttachmentChunkCommand) Validated() (AppendAttachmentChunkCommand, error) {
	command.OwnerID = strings.TrimSpace(command.OwnerID)
	command.BindingID = strings.TrimSpace(command.BindingID)
	command.UploadID = strings.TrimSpace(command.UploadID)
	command.ChunkSHA256 = strings.ToLower(strings.TrimSpace(command.ChunkSHA256))
	if !canonicalUUID(command.IdempotencyKey) || !validOwnerID(command.OwnerID) || !canonicalUUID(command.BindingID) || !canonicalUUID(command.UploadID) ||
		command.ExpectedUploadRevision < 1 || command.OffsetBytes < 0 || command.ChunkOrdinal < 0 || command.ChunkOrdinal >= 256 || len(command.Chunk) < 1 || len(command.Chunk) > MaxAttachmentChunkBytes ||
		!validSHA256(command.ChunkSHA256) || SHA256(command.Chunk) != command.ChunkSHA256 {
		return AppendAttachmentChunkCommand{}, ErrInvalid
	}
	command.Chunk = append([]byte(nil), command.Chunk...)
	return command, nil
}

type AttachmentCommit struct {
	OwnerID           string
	BindingID         string
	SourceID          string
	UploadID          string
	MediaType         string
	DeclaredSizeBytes int64
	ChunkCount        int32
	ContentSHA256     string
	Title             string
	Binding           ConfigSpec
}

type CommitAttachmentUploadCommand struct {
	IdempotencyKey         string
	OwnerID                string
	BindingID              string
	UploadID               string
	ExpectedUploadRevision int64
	ContentSHA256          string
}

func (command CommitAttachmentUploadCommand) Validated() (CommitAttachmentUploadCommand, error) {
	command.OwnerID = strings.TrimSpace(command.OwnerID)
	command.BindingID = strings.TrimSpace(command.BindingID)
	command.UploadID = strings.TrimSpace(command.UploadID)
	command.ContentSHA256 = strings.ToLower(strings.TrimSpace(command.ContentSHA256))
	if !canonicalUUID(command.IdempotencyKey) || !validOwnerID(command.OwnerID) || !canonicalUUID(command.BindingID) || !canonicalUUID(command.UploadID) ||
		command.ExpectedUploadRevision < 1 || !validSHA256(command.ContentSHA256) {
		return CommitAttachmentUploadCommand{}, ErrInvalid
	}
	return command, nil
}

type ContentReceipt struct {
	SizeBytes           int64
	ContentSHA256       string
	PointID             string
	IndexedSegmentCount int32
}

func (receipt ContentReceipt) valid(expectedSize int64, expectedDigest string) bool {
	return receipt.SizeBytes == expectedSize && strings.ToLower(strings.TrimSpace(receipt.ContentSHA256)) == expectedDigest && validSHA256(expectedDigest) &&
		canonicalUUID(receipt.PointID) && receipt.IndexedSegmentCount > 0 && receipt.IndexedSegmentCount <= MaxIndexedAttachmentSegments
}

type MemoryContent struct {
	OwnerID       string
	BindingID     string
	SourceID      string
	Content       []byte
	ContentSHA256 string
	Title         string
	Binding       ConfigSpec
}

type CreateMemoryCommand struct {
	IdempotencyKey          string
	OwnerID                 string
	BindingID               string
	SourceID                string
	ExpectedBindingRevision int64
	Content                 []byte
	ContentSHA256           string
	Title                   string
}

func (command CreateMemoryCommand) Validated() (CreateMemoryCommand, error) {
	command.OwnerID = strings.TrimSpace(command.OwnerID)
	command.BindingID = strings.TrimSpace(command.BindingID)
	command.SourceID = strings.TrimSpace(command.SourceID)
	command.Title = strings.TrimSpace(command.Title)
	command.ContentSHA256 = strings.ToLower(strings.TrimSpace(command.ContentSHA256))
	if !canonicalUUID(command.IdempotencyKey) || !validOwnerID(command.OwnerID) || !canonicalUUID(command.BindingID) || !canonicalUUID(command.SourceID) ||
		command.ExpectedBindingRevision < 1 || len(command.Content) < 1 || len(command.Content) > MaxMemorySizeBytes || !utf8.Valid(command.Content) || bytes.IndexByte(command.Content, 0) >= 0 || !validSHA256(command.ContentSHA256) ||
		SHA256(command.Content) != command.ContentSHA256 {
		return CreateMemoryCommand{}, ErrInvalid
	}
	if !validSourceTitle(command.Title) {
		return CreateMemoryCommand{}, ErrInvalid
	}
	command.Content = append([]byte(nil), command.Content...)
	return command, nil
}

type SourceTarget struct {
	OwnerID   string
	BindingID string
	SourceID  string
	Binding   ConfigSpec
}

type DeleteSourceCommand struct {
	IdempotencyKey          string
	OwnerID                 string
	BindingID               string
	SourceID                string
	ExpectedBindingRevision int64
	ExpectedSourceRevision  int64
}

func (command DeleteSourceCommand) Validated() (DeleteSourceCommand, error) {
	command.OwnerID = strings.TrimSpace(command.OwnerID)
	command.BindingID = strings.TrimSpace(command.BindingID)
	command.SourceID = strings.TrimSpace(command.SourceID)
	if !canonicalUUID(command.IdempotencyKey) || !validOwnerID(command.OwnerID) || !canonicalUUID(command.BindingID) || !canonicalUUID(command.SourceID) ||
		command.ExpectedBindingRevision < 1 || command.ExpectedSourceRevision < 1 {
		return DeleteSourceCommand{}, ErrInvalid
	}
	return command, nil
}

type SearchQuery struct {
	OwnerID                 string
	BindingID               string
	ExpectedBindingRevision int64
	Query                   string
	Limit                   int
	SourceIDs               []string
}

func (query SearchQuery) Validated() (SearchQuery, error) {
	query.OwnerID = strings.TrimSpace(query.OwnerID)
	query.BindingID = strings.TrimSpace(query.BindingID)
	query.Query = strings.TrimSpace(query.Query)
	if !validOwnerID(query.OwnerID) || !canonicalUUID(query.BindingID) || query.ExpectedBindingRevision < 1 || query.Query == "" ||
		len(query.Query) > MaxSearchQueryBytes || query.Limit < 1 || query.Limit > MaxSearchResults || strings.ContainsRune(query.Query, '\x00') {
		return SearchQuery{}, ErrInvalid
	}
	if len(query.SourceIDs) > MaxSearchResults {
		return SearchQuery{}, ErrInvalid
	}
	seen := make(map[string]struct{}, len(query.SourceIDs))
	filtered := make([]string, 0, len(query.SourceIDs))
	for _, sourceID := range query.SourceIDs {
		sourceID = strings.TrimSpace(sourceID)
		if !canonicalUUID(sourceID) {
			return SearchQuery{}, ErrInvalid
		}
		if _, ok := seen[sourceID]; ok {
			continue
		}
		seen[sourceID] = struct{}{}
		filtered = append(filtered, sourceID)
	}
	sort.Strings(filtered)
	query.SourceIDs = filtered
	return query, nil
}

type SearchMatch struct {
	SourceID string
	ChunkRef string
	Score    float64
}

func (match SearchMatch) validate() error {
	if !canonicalUUID(match.SourceID) || !chunkRefPattern.MatchString(match.ChunkRef) || security.ContainsLikelySecret(match.ChunkRef) ||
		math.IsNaN(match.Score) || math.IsInf(match.Score, 0) || match.Score < 0 || match.Score > 1 {
		return ErrInvalidBackend
	}
	return nil
}

type SearchResult struct {
	Matches         []SearchMatch
	BindingRevision int64
}

type BackendStatus string

const (
	BackendUnavailable BackendStatus = "unavailable"
	BackendReady       BackendStatus = "ready"
	BackendDegraded    BackendStatus = "degraded"
)

type StatusFacts struct {
	ReadySourceCount     int
	UploadingSourceCount int
	FailedSourceCount    int
	PersistenceChallenge *PersistenceChallenge
}

// PersistenceChallenge is bounded metadata for one ready source. It lets the
// private Worker prove that the retained vector payload still matches
// PostgreSQL after a restart without exposing document text or adding a read
// API for backend contents.
type PersistenceChallenge struct {
	PointID       string
	SourceID      string
	SizeBytes     int64
	ContentSHA256 string
}

type Status struct {
	OwnerID              string
	BindingID            string
	Enabled              bool
	BackendStatus        BackendStatus
	ReadySourceCount     int
	UploadingSourceCount int
	FailedSourceCount    int
	BindingRevision      int64
	CheckedAt            time.Time
}

func SHA256(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil && len(decoded) == sha256.Size
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validOwnerID(value string) bool {
	return value != "" && len(value) <= 255 && !strings.ContainsAny(value, "\r\n\t\x00") && !security.ContainsLikelySecret(value)
}

func validSourceTitle(value string) bool {
	return value != "" && len(value) <= MaxSourceTitleBytes && !strings.ContainsAny(value, "\r\n\t\x00") && !security.ContainsLikelySecret(value)
}

func normalizeMediaType(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "\r\n\x00") || security.ContainsLikelySecret(value) {
		return "", ErrInvalid
	}
	mediaType, parameters, err := mime.ParseMediaType(value)
	if err != nil || len(parameters) != 0 || (mediaType != "text/plain" && mediaType != "text/markdown" && mediaType != "application/json") {
		return "", ErrInvalid
	}
	normalized := mime.FormatMediaType(strings.ToLower(mediaType), parameters)
	if normalized == "" || len(normalized) > 128 {
		return "", ErrInvalid
	}
	return normalized, nil
}

func commandDigest(value any) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("%w: could not bind mutation", ErrInvalid)
	}
	return sha256.Sum256(encoded), nil
}
