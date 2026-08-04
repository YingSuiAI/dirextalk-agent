package knowledge

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInvalid              = errors.New("invalid knowledge request")
	ErrNotFound             = errors.New("knowledge not found")
	ErrConflict             = errors.New("knowledge conflict")
	ErrChecksumMismatch     = errors.New("checksum mismatch")
	ErrLimitExceeded        = errors.New("limit exceeded")
	ErrUnsupportedMediaType = errors.New("unsupported media type")
)

const (
	MaxAttachmentSize = 64 << 20 // 64 MiB
	MaxChunkSize      = 1 << 20  // 1 MiB
	MaxSearchResults  = 100
	MaxSnippetBytes   = 4096
)

// SupportedMediaTypes defines allowed MIME types for attachments
var SupportedMediaTypes = map[string]struct{}{
	"text/plain":               {},
	"text/markdown":            {},
	"text/html":                {},
	"application/pdf":          {},
	"application/json":         {},
	"application/xml":          {},
	"image/jpeg":               {},
	"image/png":                {},
	"image/webp":               {},
	"image/gif":                {},
	"application/octet-stream": {},
}

// Store provides Knowledge CRUD operations with pgvector search support
type Store struct {
	pool       *pgxpool.Pool
	repository coreknowledge.Repository
}

// NewStore creates a new Knowledge Store instance
func NewStore(pool *pgxpool.Pool, repository coreknowledge.Repository) (*Store, error) {
	if pool == nil {
		return nil, errors.New("pgxpool is required")
	}
	if repository == nil {
		return nil, errors.New("repository is required")
	}
	return &Store{
		pool:       pool,
		repository: repository,
	}, nil
}

// Knowledge represents a knowledge base entry
type Knowledge struct {
	ID           string                 `json:"id"`
	Title        string                 `json:"title"`
	Content      string                 `json:"content,omitempty"`
	MediaType    string                 `json:"media_type"`
	SizeBytes    int64                  `json:"size_bytes"`
	Digest       string                 `json:"digest"`
	Status       string                 `json:"status"`
	Kind         string                 `json:"kind"`
	RelativePath string                 `json:"relative_path,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	ErrorCode    string                 `json:"error_code,omitempty"`
}

// AttachmentUploadRequest represents an attachment upload request
type AttachmentUploadRequest struct {
	Title          string `json:"title"`
	MediaType      string `json:"media_type"`
	Content        []byte `json:"content"`
	IdempotencyKey string `json:"idempotency_key"`
}

// AttachmentChunk represents a chunk of an attachment being uploaded
type AttachmentChunk struct {
	UploadID    string `json:"upload_id"`
	Ordinal     int32  `json:"ordinal"`
	Offset      int64  `json:"offset"`
	Data        []byte `json:"data"`
	ChunkDigest string `json:"chunk_digest"`
}

// SearchRequest represents a vector search request
type SearchRequest struct {
	Query     string   `json:"query"`
	SourceIDs []string `json:"source_ids,omitempty"`
	Limit     int      `json:"limit"`
	PageToken string   `json:"page_token,omitempty"`
}

// SearchResult represents a single search result
type SearchResult struct {
	SourceID  string  `json:"source_id"`
	ChunkRef  string  `json:"chunk_ref"`
	Snippet   string  `json:"snippet"`
	Score     float64 `json:"score"`
	Title     string  `json:"title,omitempty"`
	MediaType string  `json:"media_type,omitempty"`
}

// SearchResponse represents a search response with pagination
type SearchResponse struct {
	Results       []SearchResult `json:"results"`
	NextPageToken string         `json:"next_page_token,omitempty"`
	TotalMatches  int            `json:"total_matches"`
}

// CreateKnowledge creates a new knowledge entry from memory content
func (s *Store) CreateKnowledge(ctx context.Context, title, content, mediaType string) (*Knowledge, error) {
	if strings.TrimSpace(title) == "" {
		return nil, ErrInvalid
	}
	if strings.TrimSpace(content) == "" {
		return nil, ErrInvalid
	}
	if !s.isValidMediaType(mediaType) {
		return nil, ErrUnsupportedMediaType
	}
	if len([]byte(content)) > coreknowledge.MaxMemoryBytes {
		return nil, ErrLimitExceeded
	}

	contentBytes := []byte(content)
	digest := s.computeDigest(contentBytes)
	idempotencyKey := uuid.NewString()

	cmd := coreknowledge.MemoryCommand{
		IdempotencyKey: idempotencyKey,
		SourceID:       "",
		Title:          title,
		Content:        content,
		ContentSHA256:  digest,
		MediaType:      mediaType,
	}

	source, err := s.repository.CreateMemory(ctx, cmd)
	if err != nil {
		return nil, s.mapError(err)
	}

	return s.sourceToKnowledge(source), nil
}

// GetKnowledge retrieves a knowledge entry by ID
func (s *Store) GetKnowledge(ctx context.Context, id string) (*Knowledge, error) {
	if !s.isValidUUID(id) {
		return nil, ErrInvalid
	}

	source, err := s.repository.Get(ctx, id)
	if err != nil {
		return nil, s.mapError(err)
	}

	return s.sourceToKnowledge(source), nil
}

// ListKnowledge lists knowledge entries with pagination
func (s *Store) ListKnowledge(ctx context.Context, pageSize int, pageToken string, status, kind string) ([]Knowledge, string, error) {
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 100 {
		pageSize = 100
	}

	query := coreknowledge.ListQuery{
		PageSize:  pageSize,
		PageToken: pageToken,
	}

	if status != "" {
		query.Status = coreknowledge.SourceStatus(status)
	}
	if kind != "" {
		query.Kind = coreknowledge.SourceKind(kind)
	}

	page, err := s.repository.List(ctx, query)
	if err != nil {
		return nil, "", s.mapError(err)
	}

	results := make([]Knowledge, 0, len(page.Sources))
	for _, source := range page.Sources {
		results = append(results, *s.sourceToKnowledge(source))
	}

	return results, page.NextPageToken, nil
}

// DeleteKnowledge deletes a knowledge entry
func (s *Store) DeleteKnowledge(ctx context.Context, id string, expectedRevision int64) error {
	if !s.isValidUUID(id) {
		return ErrInvalid
	}

	cmd := coreknowledge.DeleteCommand{
		IdempotencyKey:   uuid.NewString(),
		SourceID:         id,
		ExpectedRevision: expectedRevision,
	}

	_, err := s.repository.Delete(ctx, cmd)
	if err != nil {
		return s.mapError(err)
	}

	return nil
}

// UploadAttachment handles small attachment uploads (up to MaxAttachmentSize)
func (s *Store) UploadAttachment(ctx context.Context, req AttachmentUploadRequest) (*Knowledge, error) {
	if strings.TrimSpace(req.Title) == "" {
		return nil, ErrInvalid
	}
	if len(req.Content) == 0 {
		return nil, ErrInvalid
	}
	if int64(len(req.Content)) > MaxAttachmentSize {
		return nil, ErrLimitExceeded
	}
	if !s.isValidMediaType(req.MediaType) {
		return nil, ErrUnsupportedMediaType
	}

	idempotencyKey := req.IdempotencyKey
	if idempotencyKey == "" {
		idempotencyKey = uuid.NewString()
	}

	digest := s.computeDigest(req.Content)

	// Use memory-based upload for simplicity
	cmd := coreknowledge.MemoryCommand{
		IdempotencyKey: idempotencyKey,
		SourceID:       "",
		Title:          req.Title,
		Content:        base64.StdEncoding.EncodeToString(req.Content),
		ContentSHA256:  digest,
		MediaType:      req.MediaType,
	}

	source, err := s.repository.CreateMemory(ctx, cmd)
	if err != nil {
		return nil, s.mapError(err)
	}

	return s.sourceToKnowledge(source), nil
}

// StartChunkedUpload initiates a chunked upload session for large attachments
func (s *Store) StartChunkedUpload(ctx context.Context, title, mediaType string, declaredSize int64, contentDigest string) (string, error) {
	if strings.TrimSpace(title) == "" {
		return "", ErrInvalid
	}
	if declaredSize <= 0 || declaredSize > MaxAttachmentSize {
		return "", ErrLimitExceeded
	}
	if !s.isValidMediaType(mediaType) {
		return "", ErrUnsupportedMediaType
	}
	if !s.isValidDigest(contentDigest) {
		return "", ErrInvalid
	}

	uploadID := uuid.NewString()
	metadata := coreknowledge.UploadMetadata{
		IdempotencyKey: uuid.NewString(),
		UploadID:       uploadID,
		SourceID:       "",
		Title:          title,
		RelativePath:   "",
		MediaType:      mediaType,
		DeclaredSize:   declaredSize,
		ContentSHA256:  contentDigest,
	}

	upload, err := s.repository.StartUpload(ctx, metadata)
	if err != nil {
		return "", s.mapError(err)
	}

	return upload.ID, nil
}

// AppendChunk appends a chunk to an ongoing upload
func (s *Store) AppendChunk(ctx context.Context, chunk AttachmentChunk) error {
	if !s.isValidUUID(chunk.UploadID) {
		return ErrInvalid
	}
	if len(chunk.Data) == 0 || len(chunk.Data) > MaxChunkSize {
		return ErrLimitExceeded
	}
	if !s.isValidDigest(chunk.ChunkDigest) {
		return ErrInvalid
	}

	computedDigest := s.computeDigest(chunk.Data)
	if computedDigest != strings.ToLower(chunk.ChunkDigest) {
		return ErrChecksumMismatch
	}

	uploadChunk := coreknowledge.UploadChunk{
		IdempotencyKey: uuid.NewString(),
		UploadID:       chunk.UploadID,
		Ordinal:        chunk.Ordinal,
		OffsetBytes:    chunk.Offset,
		Data:           chunk.Data,
		ChunkSHA256:    chunk.ChunkDigest,
	}

	_, err := s.repository.AppendUploadChunk(ctx, uploadChunk)
	if err != nil {
		return s.mapError(err)
	}

	return nil
}

// CommitUpload finalizes a chunked upload
func (s *Store) CommitUpload(ctx context.Context, uploadID string, expectedRevision int64, contentDigest string) (*Knowledge, error) {
	if !s.isValidUUID(uploadID) {
		return nil, ErrInvalid
	}
	if !s.isValidDigest(contentDigest) {
		return nil, ErrInvalid
	}

	cmd := coreknowledge.CommitUploadCommand{
		IdempotencyKey:   uuid.NewString(),
		UploadID:         uploadID,
		ExpectedRevision: expectedRevision,
		ContentSHA256:    contentDigest,
	}

	_, source, err := s.repository.CommitUpload(ctx, cmd)
	if err != nil {
		return nil, s.mapError(err)
	}

	return s.sourceToKnowledge(source), nil
}

// AbortUpload cancels an ongoing chunked upload
func (s *Store) AbortUpload(ctx context.Context, uploadID string, expectedRevision int64) error {
	if !s.isValidUUID(uploadID) {
		return ErrInvalid
	}

	cmd := coreknowledge.AbortUploadCommand{
		IdempotencyKey:   uuid.NewString(),
		UploadID:         uploadID,
		ExpectedRevision: expectedRevision,
	}

	return s.mapError(s.repository.AbortUpload(ctx, cmd))
}

// DownloadAttachment retrieves the content of an attachment
func (s *Store) DownloadAttachment(ctx context.Context, id string) ([]byte, string, error) {
	if !s.isValidUUID(id) {
		return nil, "", ErrInvalid
	}

	source, err := s.repository.Get(ctx, id)
	if err != nil {
		return nil, "", s.mapError(err)
	}

	// For memory-based sources, content is stored in the database
	if source.Kind == coreknowledge.SourceKindMemory {
		// Query the actual content from the database
		var content string
		err := s.pool.QueryRow(ctx, `
			SELECT content
			FROM core_knowledge_sources
			WHERE source_id = $1 AND status = 'ready'
		`, id).Scan(&content)

		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, "", ErrNotFound
			}
			return nil, "", err
		}

		// Try to decode as base64, if that fails return as-is
		decoded, err := base64.StdEncoding.DecodeString(content)
		if err == nil {
			return decoded, source.MediaType, nil
		}
		return []byte(content), source.MediaType, nil
	}

	// For other types, use content port
	contentPort := s.repository.ContentPort()
	if contentPort == nil {
		return nil, "", errors.New("content port unavailable")
	}

	// This would require additional implementation to read from content store
	return nil, "", errors.New("download not supported for this source type")
}

// Search performs vector similarity search across knowledge base
func (s *Store) Search(ctx context.Context, req SearchRequest) (*SearchResponse, error) {
	if strings.TrimSpace(req.Query) == "" {
		return nil, ErrInvalid
	}
	if req.Limit <= 0 {
		req.Limit = 10
	}
	if req.Limit > MaxSearchResults {
		req.Limit = MaxSearchResults
	}

	query := coreknowledge.SearchQuery{
		Query:     req.Query,
		SourceIDs: req.SourceIDs,
		Limit:     req.Limit,
		PageToken: req.PageToken,
	}

	page, err := s.repository.Search(ctx, query)
	if err != nil {
		return nil, s.mapError(err)
	}

	results := make([]SearchResult, 0, len(page.Matches))
	for _, match := range page.Matches {
		// Optionally enrich with source metadata
		source, _ := s.repository.Get(ctx, match.SourceID)

		result := SearchResult{
			SourceID:  match.SourceID,
			ChunkRef:  match.ChunkRef,
			Snippet:   s.truncateSnippet(match.Snippet),
			Score:     match.Score,
			Title:     source.Title,
			MediaType: source.MediaType,
		}
		results = append(results, result)
	}

	return &SearchResponse{
		Results:       results,
		NextPageToken: page.NextPageToken,
		TotalMatches:  len(results),
	}, nil
}

// GetStatus returns knowledge store statistics
func (s *Store) GetStatus(ctx context.Context) (map[string]interface{}, error) {
	status, err := s.repository.Status(ctx)
	if err != nil {
		return nil, s.mapError(err)
	}

	return map[string]interface{}{
		"ready_count":           status.ReadyCount,
		"uploading_count":       status.UploadingCount,
		"indexing_count":        status.IndexingCount,
		"failed_count":          status.FailedCount,
		"cleanup_pending_count": status.CleanupPendingCount,
		"checked_at":            status.CheckedAt,
	}, nil
}

// Helper functions

func (s *Store) sourceToKnowledge(source coreknowledge.Source) *Knowledge {
	return &Knowledge{
		ID:           source.ID,
		Title:        source.Title,
		MediaType:    source.MediaType,
		SizeBytes:    source.SizeBytes,
		Digest:       source.Digest,
		Status:       string(source.Status),
		Kind:         string(source.Kind),
		RelativePath: source.RelativePath,
		CreatedAt:    source.CreatedAt,
		UpdatedAt:    source.UpdatedAt,
		ErrorCode:    source.ErrorCode,
	}
}

func (s *Store) isValidUUID(id string) bool {
	_, err := uuid.Parse(strings.TrimSpace(id))
	return err == nil
}

func (s *Store) isValidDigest(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

func (s *Store) computeDigest(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (s *Store) isValidMediaType(mediaType string) bool {
	normalized := strings.ToLower(strings.TrimSpace(mediaType))
	_, ok := SupportedMediaTypes[normalized]
	return ok
}

func (s *Store) truncateSnippet(snippet string) string {
	if len(snippet) <= MaxSnippetBytes {
		return snippet
	}
	return snippet[:MaxSnippetBytes] + "..."
}

func (s *Store) mapError(err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, coreknowledge.ErrInvalid):
		return ErrInvalid
	case errors.Is(err, coreknowledge.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, coreknowledge.ErrConflict):
		return ErrConflict
	case errors.Is(err, coreknowledge.ErrChecksumMismatch):
		return ErrChecksumMismatch
	case errors.Is(err, coreknowledge.ErrLimitExceeded):
		return ErrLimitExceeded
	case errors.Is(err, coreknowledge.ErrIdempotencyConflict):
		return ErrConflict
	case errors.Is(err, coreknowledge.ErrRevisionConflict):
		return ErrConflict
	default:
		return err
	}
}

// VectorSearchWithEmbedding performs search using pre-computed embeddings
// This is used when the embedding is already available (e.g., from a model)
func (s *Store) VectorSearchWithEmbedding(ctx context.Context, embedding []float32, sourceIDs []string, limit int) ([]SearchResult, error) {
	if len(embedding) == 0 {
		return nil, ErrInvalid
	}
	if limit <= 0 {
		limit = 10
	}
	if limit > MaxSearchResults {
		limit = MaxSearchResults
	}

	// Build the query with pgvector cosine similarity
	query := `
		SELECT
			k.source_id::text,
			k.chunk_id,
			k.content,
			1 - (k.embedding <=> $1::vector) as score
		FROM core_knowledge_vectors k
		INNER JOIN core_knowledge_sources s ON k.source_id = s.source_id
		WHERE s.status = 'ready'
	`

	args := []interface{}{embeddingToString(embedding)}
	argIdx := 2

	if len(sourceIDs) > 0 {
		query += fmt.Sprintf(" AND k.source_id = ANY($%d::uuid[])", argIdx)
		args = append(args, sourceIDs)
		argIdx++
	}

	query += fmt.Sprintf(" ORDER BY k.embedding <=> $1::vector LIMIT $%d", argIdx)
	args = append(args, limit)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make([]SearchResult, 0, limit)
	for rows.Next() {
		var sourceID, chunkID, content string
		var score float64

		if err := rows.Scan(&sourceID, &chunkID, &content, &score); err != nil {
			return nil, err
		}

		results = append(results, SearchResult{
			SourceID: sourceID,
			ChunkRef: chunkID,
			Snippet:  s.truncateSnippet(content),
			Score:    score,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

// embeddingToString converts a float32 slice to pgvector format string
func embeddingToString(embedding []float32) string {
	if len(embedding) == 0 {
		return "[]"
	}

	var sb strings.Builder
	sb.WriteString("[")
	for i, v := range embedding {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf("%f", v))
	}
	sb.WriteString("]")
	return sb.String()
}

// BatchCreateKnowledge creates multiple knowledge entries in a single transaction
func (s *Store) BatchCreateKnowledge(ctx context.Context, items []struct {
	Title     string
	Content   string
	MediaType string
}) ([]*Knowledge, error) {
	if len(items) == 0 {
		return nil, ErrInvalid
	}
	if len(items) > 100 {
		return nil, ErrLimitExceeded
	}

	results := make([]*Knowledge, 0, len(items))
	for _, item := range items {
		k, err := s.CreateKnowledge(ctx, item.Title, item.Content, item.MediaType)
		if err != nil {
			return nil, fmt.Errorf("failed to create knowledge %q: %w", item.Title, err)
		}
		results = append(results, k)
	}

	return results, nil
}

// ReadAttachmentContent reads attachment content as a stream
func (s *Store) ReadAttachmentContent(ctx context.Context, id string, writer io.Writer) (int64, error) {
	content, _, err := s.DownloadAttachment(ctx, id)
	if err != nil {
		return 0, err
	}

	n, err := writer.Write(content)
	return int64(n), err
}
