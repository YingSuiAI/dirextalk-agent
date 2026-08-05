package coreknowledge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type mutationReplay struct {
	digest string
	value  any
	err    error
}

type uploadRecord struct {
	u    Upload
	sink ContentSink
}

type repositorySnapshot struct {
	created    time.Time
	expires    time.Time
	digest     string
	sources    []Source
	matches    []SearchMatch
	provenance SearchProvenance
}

const (
	maxActiveUploads = 8
	maxReservedBytes = 128 << 20
	snapshotTTL      = 5 * time.Minute
	maxSnapshots     = 128
)

// MemoryRepository is deterministic and concurrency-safe. Upload bytes are
// streamed directly to the configured ContentSink; only bounded metadata and
// immutable content references are retained here.
type MemoryRepository struct {
	mu              sync.Mutex
	now             func() time.Time
	opener          ManagedFileOpener
	contentPort     StreamingContentPort
	deleter         FileDeleter
	fence           SourceReferenceFence
	reservedBytes   int64
	activeUploads   int
	sources         map[string]Source
	contents        map[string]string // bounded memory-source text only
	contentRefs     map[string]ContentReference
	tags            map[string][]string
	uploads         map[string]uploadRecord
	replay          map[string]mutationReplay
	snapshots       map[string]repositorySnapshot
	embeddingConfig *EmbeddingConfig
}

func (r *MemoryRepository) GetEmbeddingConfig(_ context.Context) (EmbeddingConfig, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.embeddingConfig == nil {
		return EmbeddingConfig{}, ErrNotFound
	}
	return *r.embeddingConfig, nil
}

func (r *MemoryRepository) EnsureEmbeddingConfig(_ context.Context, config EmbeddingConfig) (EmbeddingConfig, error) {
	if !validUUID(config.EmbeddingProfileID) || config.EmbeddingProfileRevision < 0 || len(config.EmbeddingModel) > 255 || len(config.EmbeddingGeneration) > 256 || config.Dimension <= 0 || config.Dimension > 16384 || strings.TrimSpace(config.Collection) == "" || len(config.Collection) > 255 || config.Revision < 1 {
		return EmbeddingConfig{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.embeddingConfig == nil {
		config.UpdatedAt = r.nowUTC()
		r.embeddingConfig = &config
	}
	return *r.embeddingConfig, nil
}

func (r *MemoryRepository) UpdateEmbeddingConfig(_ context.Context, command EmbeddingConfigCommand) (EmbeddingConfig, error) {
	if !validUUID(command.IdempotencyKey) || command.ExpectedRevision < 1 || !validUUID(command.EmbeddingProfileID) || command.Dimension <= 0 || command.Dimension > 16384 || strings.TrimSpace(command.Collection) == "" || len(command.Collection) > 255 {
		return EmbeddingConfig{}, ErrInvalid
	}
	digest := replayDigest(command)
	r.mu.Lock()
	defer r.mu.Unlock()
	if prior, err, ok := r.replayLocked("config:"+command.IdempotencyKey, digest); ok {
		if err != nil {
			return EmbeddingConfig{}, err
		}
		value, ok := prior.(EmbeddingConfig)
		if !ok {
			return EmbeddingConfig{}, ErrConflict
		}
		return value, nil
	}
	if r.embeddingConfig == nil {
		return EmbeddingConfig{}, ErrNotFound
	}
	current := *r.embeddingConfig
	if current.Revision != command.ExpectedRevision {
		r.rememberLocked("config:"+command.IdempotencyKey, digest, EmbeddingConfig{}, ErrRevisionConflict)
		return EmbeddingConfig{}, ErrRevisionConflict
	}
	if command.Dimension != current.Dimension || command.Collection != current.Collection || (command.CollectionConfigDigest != "" && command.CollectionConfigDigest != current.CollectionConfigDigest) {
		r.rememberLocked("config:"+command.IdempotencyKey, digest, EmbeddingConfig{}, ErrInvalid)
		return EmbeddingConfig{}, ErrInvalid
	}
	current.EmbeddingProfileID = command.EmbeddingProfileID
	// The command only binds a profile identity. Any optional in-memory model
	// hints from the previous profile must be cleared rather than reused for a
	// different binding.
	current.EmbeddingProfileRevision = 0
	current.EmbeddingModel = ""
	current.EmbeddingGeneration = ""
	current.Revision++
	current.UpdatedAt = r.nowUTC()
	r.embeddingConfig = &current
	r.rememberLocked("config:"+command.IdempotencyKey, digest, current, nil)
	return current, nil
}

func NewMemoryRepository(now func() time.Time, opener ManagedFileOpener, contentPort StreamingContentPort, fence SourceReferenceFence) (*MemoryRepository, error) {
	if now == nil || opener == nil || contentPort == nil || fence == nil {
		return nil, ErrInvalid
	}
	return &MemoryRepository{
		now: now, opener: opener, contentPort: contentPort, fence: fence,
		sources: map[string]Source{}, contents: map[string]string{}, contentRefs: map[string]ContentReference{}, tags: map[string][]string{},
		uploads: map[string]uploadRecord{}, replay: map[string]mutationReplay{}, snapshots: map[string]repositorySnapshot{},
	}, nil
}

func (r *MemoryRepository) SetFileDeleter(deleter FileDeleter) {
	r.mu.Lock()
	r.deleter = deleter
	r.mu.Unlock()
}

// SetReferenceFence is retained for deterministic test wiring; nil is ignored
// so the required fence dependency can never be bypassed.
func (r *MemoryRepository) SetReferenceFence(fence SourceReferenceFence) {
	if fence != nil {
		r.mu.Lock()
		r.fence = fence
		r.mu.Unlock()
	}
}

func cloneSource(s Source) Source {
	s.Tags = append([]string(nil), s.Tags...)
	return s
}
func cloneUpload(u Upload) Upload { return u }
func replayDigest(v any) string   { b, _ := json.Marshal(v); return digestBytes(b) }
func (r *MemoryRepository) replayLocked(key, digest string) (any, error, bool) {
	x, ok := r.replay[key]
	if !ok {
		return nil, nil, false
	}
	if x.digest != digest {
		return nil, ErrIdempotencyConflict, true
	}
	return x.value, x.err, true
}
func (r *MemoryRepository) rememberLocked(key, digest string, value any, err error) {
	r.replay[key] = mutationReplay{digest: digest, value: value, err: err}
}
func (r *MemoryRepository) nowUTC() time.Time { return r.now().UTC() }

func (r *MemoryRepository) GetUpload(_ context.Context, id string) (Upload, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.uploads[id]
	if !ok {
		return Upload{}, ErrNotFound
	}
	return cloneUpload(rec.u), nil
}

func (r *MemoryRepository) CreateMount(ctx context.Context, command MountCommand) (Source, error) {
	if err := command.validate(); err != nil {
		return Source{}, err
	}
	d := replayDigest(command)
	// Exact replay is checked before invoking the filesystem callback.
	r.mu.Lock()
	if v, err, ok := r.replayLocked(command.IdempotencyKey, d); ok {
		r.mu.Unlock()
		if v == nil {
			return Source{}, err
		}
		return cloneSource(v.(Source)), err
	}
	opener := r.opener
	r.mu.Unlock()
	opened, err := opener.OpenManaged(ctx, command.RelativePath)
	if err != nil || opened == nil {
		return Source{}, ErrFilesystemUnavailable
	}
	_ = opened.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, err, ok := r.replayLocked(command.IdempotencyKey, d); ok {
		if v == nil {
			return Source{}, err
		}
		return cloneSource(v.(Source)), err
	}
	id := command.SourceID
	if id == "" {
		id = uuid.NewString()
	}
	if _, exists := r.sources[id]; exists {
		return Source{}, ErrConflict
	}
	now := r.nowUTC()
	s := Source{ID: id, Kind: SourceKindMount, Status: SourceStatusReady, Title: command.Title, RelativePath: command.RelativePath, Digest: strings.ToLower(command.Digest), SizeBytes: command.SizeBytes, MediaType: command.MediaType, Revision: 1, CreatedAt: now, UpdatedAt: now}
	r.sources[id] = s
	r.rememberLocked(command.IdempotencyKey, d, s, nil)
	return cloneSource(s), nil
}

func (r *MemoryRepository) StartUpload(ctx context.Context, metadata UploadMetadata) (Upload, error) {
	if err := metadata.validate(); err != nil {
		return Upload{}, err
	}
	d := replayDigest(metadata)
	r.mu.Lock()
	if v, err, ok := r.replayLocked(metadata.IdempotencyKey, d); ok {
		r.mu.Unlock()
		if v == nil {
			return Upload{}, err
		}
		u := cloneUpload(v.(Upload))
		u.Replayed = true
		return u, err
	}
	r.mu.Unlock()
	sink, err := r.contentPort.Begin(ctx, metadata)
	if err != nil || sink == nil {
		if err == nil {
			err = ErrConflict
		}
		return Upload{}, safeError(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.activeUploads >= maxActiveUploads || r.reservedBytes+metadata.DeclaredSize > maxReservedBytes {
		_ = sink.Abort(ctx)
		return Upload{}, ErrLimitExceeded
	}
	if v, err, ok := r.replayLocked(metadata.IdempotencyKey, d); ok {
		_ = sink.Abort(ctx)
		if v == nil {
			return Upload{}, err
		}
		u := cloneUpload(v.(Upload))
		u.Replayed = true
		return u, err
	}
	uploadID := metadata.UploadID
	if uploadID == "" {
		uploadID = uuid.NewString()
	}
	sourceID := metadata.SourceID
	if sourceID == "" {
		sourceID = uuid.NewString()
	}
	if _, exists := r.uploads[uploadID]; exists {
		_ = sink.Abort(ctx)
		return Upload{}, ErrConflict
	}
	if _, exists := r.sources[sourceID]; exists {
		_ = sink.Abort(ctx)
		return Upload{}, ErrConflict
	}
	for _, existing := range r.uploads {
		if existing.u.SourceID == sourceID {
			_ = sink.Abort(ctx)
			return Upload{}, ErrConflict
		}
	}
	now := r.nowUTC()
	u := Upload{ID: uploadID, SourceID: sourceID, Status: SourceStatusUploading, Metadata: metadata, Revision: 1, CreatedAt: now, UpdatedAt: now}
	u.Metadata.UploadID, u.Metadata.SourceID = uploadID, sourceID
	u.Session = UploadSession{UploadID: uploadID, SourceID: sourceID, Revision: 1}
	r.uploads[uploadID] = uploadRecord{u: u, sink: sink}
	r.activeUploads++
	r.reservedBytes += metadata.DeclaredSize
	r.rememberLocked(metadata.IdempotencyKey, d, u, nil)
	return cloneUpload(u), nil
}

func (r *MemoryRepository) failUploadLocked(ctx context.Context, id string, rec uploadRecord) {
	delete(r.uploads, id)
	if rec.sink != nil {
		_ = rec.sink.Abort(ctx)
	}
	r.activeUploads--
	r.reservedBytes -= rec.u.Metadata.DeclaredSize
	if r.activeUploads < 0 {
		r.activeUploads = 0
	}
	if r.reservedBytes < 0 {
		r.reservedBytes = 0
	}
}

func (r *MemoryRepository) AppendUploadChunk(ctx context.Context, chunk UploadChunk) (Upload, error) {
	if err := chunk.validate(); err != nil {
		return Upload{}, err
	}
	d := replayDigest(chunk)
	r.mu.Lock()
	if v, err, ok := r.replayLocked(chunk.IdempotencyKey, d); ok {
		r.mu.Unlock()
		if v == nil {
			return Upload{}, err
		}
		return cloneUpload(v.(Upload)), err
	}
	rec, ok := r.uploads[chunk.UploadID]
	if !ok {
		r.mu.Unlock()
		return Upload{}, ErrNotFound
	}
	u := rec.u
	if u.Status != SourceStatusUploading || chunk.Ordinal != u.NextChunk || chunk.OffsetBytes != u.ReceivedSize {
		r.mu.Unlock()
		return Upload{}, ErrRevisionConflict
	}
	if digestBytes(chunk.Data) != strings.ToLower(chunk.ChunkSHA256) {
		r.mu.Unlock()
		return Upload{}, ErrChecksumMismatch
	}
	if u.ReceivedSize+int64(len(chunk.Data)) > u.Metadata.DeclaredSize {
		r.mu.Unlock()
		return Upload{}, ErrInvalid
	}
	n, err := rec.sink.Write(chunk.Data)
	if err != nil || n != len(chunk.Data) {
		r.failUploadLocked(ctx, chunk.UploadID, rec)
		r.mu.Unlock()
		if err != nil {
			return Upload{}, safeError(err)
		}
		return Upload{}, ErrConflict
	}
	u.ReceivedSize += int64(n)
	u.NextChunk++
	u.Revision++
	u.UpdatedAt = r.nowUTC()
	u.Session = UploadSession{UploadID: u.ID, SourceID: u.SourceID, ReceivedSize: u.ReceivedSize, NextOrdinal: u.NextChunk, Revision: u.Revision}
	rec.u = u
	r.uploads[chunk.UploadID] = rec
	r.rememberLocked(chunk.IdempotencyKey, d, u, nil)
	r.mu.Unlock()
	return cloneUpload(u), nil
}

func (r *MemoryRepository) CommitUpload(ctx context.Context, command CommitUploadCommand) (Upload, Source, error) {
	if err := command.validate(); err != nil {
		return Upload{}, Source{}, err
	}
	d := replayDigest(command)
	r.mu.Lock()
	if v, err, ok := r.replayLocked(command.IdempotencyKey, d); ok {
		r.mu.Unlock()
		if v == nil {
			return Upload{}, Source{}, err
		}
		pair := v.([2]any)
		return cloneUpload(pair[0].(Upload)), cloneSource(pair[1].(Source)), err
	}
	rec, ok := r.uploads[command.UploadID]
	if !ok {
		r.mu.Unlock()
		return Upload{}, Source{}, ErrNotFound
	}
	u := rec.u
	if u.Status != SourceStatusUploading || u.Revision != command.ExpectedRevision {
		r.mu.Unlock()
		return Upload{}, Source{}, ErrRevisionConflict
	}
	if u.ReceivedSize != u.Metadata.DeclaredSize {
		r.mu.Unlock()
		return Upload{}, Source{}, ErrInvalid
	}
	if _, exists := r.sources[u.SourceID]; exists {
		r.mu.Unlock()
		return Upload{}, Source{}, ErrConflict
	}
	// Hold the repository lock while finalizing so no append can race commit.
	ref, err := rec.sink.Finalize(ctx, strings.ToLower(command.ContentSHA256), u.ReceivedSize)
	if err != nil {
		r.failUploadLocked(ctx, command.UploadID, rec)
		r.mu.Unlock()
		return Upload{}, Source{}, safeError(err)
	}
	if ref.Ref == "" || ref.SizeBytes != u.ReceivedSize || !strings.EqualFold(ref.Digest, command.ContentSHA256) || !strings.EqualFold(ref.Digest, u.Metadata.ContentSHA256) {
		r.failUploadLocked(ctx, command.UploadID, rec)
		r.mu.Unlock()
		return Upload{}, Source{}, ErrChecksumMismatch
	}
	now := r.nowUTC()
	s := Source{ID: u.SourceID, Kind: SourceKindUpload, Status: SourceStatusReady, Title: u.Metadata.Title, RelativePath: u.Metadata.RelativePath, Digest: strings.ToLower(ref.Digest), SizeBytes: ref.SizeBytes, MediaType: u.Metadata.MediaType, Revision: 1, CreatedAt: u.CreatedAt, UpdatedAt: now}
	u.Status, u.Revision, u.UpdatedAt = SourceStatusReady, u.Revision+1, now
	u.Session = UploadSession{UploadID: u.ID, SourceID: u.SourceID, ReceivedSize: u.ReceivedSize, NextOrdinal: u.NextChunk, Revision: u.Revision}
	r.uploads[command.UploadID] = uploadRecord{u: u}
	r.sources[u.SourceID] = s
	r.contentRefs[u.SourceID] = ref
	r.activeUploads--
	r.reservedBytes -= u.Metadata.DeclaredSize
	if r.activeUploads < 0 {
		r.activeUploads = 0
	}
	if r.reservedBytes < 0 {
		r.reservedBytes = 0
	}
	r.rememberLocked(command.IdempotencyKey, d, [2]any{u, s}, nil)
	r.mu.Unlock()
	return cloneUpload(u), cloneSource(s), nil
}

func (r *MemoryRepository) AbortUpload(ctx context.Context, command AbortUploadCommand) error {
	if !validUUID(command.IdempotencyKey) || !validUUID(command.UploadID) || command.ExpectedRevision < 1 {
		return ErrInvalid
	}
	d := replayDigest(command)
	r.mu.Lock()
	if _, err, ok := r.replayLocked(command.IdempotencyKey, d); ok {
		r.mu.Unlock()
		return err
	}
	rec, ok := r.uploads[command.UploadID]
	if !ok {
		r.mu.Unlock()
		return ErrNotFound
	}
	if rec.u.Status != SourceStatusUploading || rec.u.Revision != command.ExpectedRevision {
		r.mu.Unlock()
		return ErrRevisionConflict
	}
	r.failUploadLocked(ctx, command.UploadID, rec)
	r.rememberLocked(command.IdempotencyKey, d, struct{}{}, nil)
	r.mu.Unlock()
	return nil
}

func (r *MemoryRepository) CreateMemory(_ context.Context, command MemoryCommand) (Source, error) {
	command = NormalizeMemoryCommand(command)
	if err := command.validate(); err != nil {
		return Source{}, err
	}
	d := replayDigest(command)
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, err, ok := r.replayLocked(command.IdempotencyKey, d); ok {
		if v == nil {
			return Source{}, err
		}
		return cloneSource(v.(Source)), err
	}
	digest := digestBytes([]byte(command.Content))
	if command.ContentSHA256 != "" && !strings.EqualFold(command.ContentSHA256, digest) {
		return Source{}, ErrChecksumMismatch
	}
	id := command.SourceID
	if id == "" {
		id = uuid.NewString()
	}
	if _, exists := r.sources[id]; exists {
		return Source{}, ErrConflict
	}
	now := r.nowUTC()
	s := Source{ID: id, Kind: SourceKindMemory, Status: SourceStatusReady, Title: command.Title, Digest: digest, SizeBytes: int64(len(command.Content)), MediaType: command.MediaType, Revision: 1, CreatedAt: now, UpdatedAt: now, Tags: append([]string(nil), command.Tags...)}
	r.sources[id], r.contents[id] = s, command.Content
	r.tags[id] = append([]string(nil), command.Tags...)
	r.contentRefs[id] = ContentReference{Ref: id, Digest: digest, SizeBytes: int64(len(command.Content))}
	r.rememberLocked(command.IdempotencyKey, d, s, nil)
	return cloneSource(s), nil
}

func (r *MemoryRepository) UpdateMemory(_ context.Context, command UpdateMemoryCommand) (Source, error) {
	if err := command.validate(); err != nil {
		return Source{}, err
	}
	d := replayDigest(command)
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, err, ok := r.replayLocked("memory.update:"+command.IdempotencyKey, d); ok {
		if v == nil {
			return Source{}, err
		}
		return cloneSource(v.(Source)), err
	}
	s, ok := r.sources[command.SourceID]
	if !ok || s.Status == SourceStatusDeleted || s.Kind != SourceKindMemory {
		return Source{}, ErrNotFound
	}
	if s.Revision != command.ExpectedRevision {
		return Source{}, ErrRevisionConflict
	}
	digest := digestBytes([]byte(command.Content))
	if command.ContentSHA256 != "" && !strings.EqualFold(command.ContentSHA256, digest) {
		return Source{}, ErrChecksumMismatch
	}
	now := r.nowUTC()
	s.Title, s.Digest, s.SizeBytes, s.MediaType, s.Revision, s.UpdatedAt, s.Tags = command.Title, digest, int64(len([]byte(command.Content))), command.MediaType, s.Revision+1, now, append([]string(nil), command.Tags...)
	r.sources[s.ID], r.contents[s.ID] = s, command.Content
	r.tags[s.ID] = append([]string(nil), command.Tags...)
	r.contentRefs[s.ID] = ContentReference{Ref: s.ID, Digest: digest, SizeBytes: s.SizeBytes}
	r.rememberLocked("memory.update:"+command.IdempotencyKey, d, s, nil)
	return cloneSource(s), nil
}

func (r *MemoryRepository) Get(_ context.Context, id string) (Source, error) {
	if !validUUID(id) {
		return Source{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sources[id]
	if !ok || s.Status == SourceStatusDeleted {
		return Source{}, ErrNotFound
	}
	return cloneSource(s), nil
}

func (r *MemoryRepository) GetMemory(_ context.Context, id string) (Memory, error) {
	if !validUUID(id) {
		return Memory{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sources[id]
	if !ok || s.Status == SourceStatusDeleted || s.Kind != SourceKindMemory {
		return Memory{}, ErrNotFound
	}
	return memoryFromSource(s, r.contents[id], r.tags[id]), nil
}

func (r *MemoryRepository) ListMemories(ctx context.Context, q ListQuery) (MemoryPage, error) {
	q.Kind = SourceKindMemory
	page, err := r.List(ctx, q)
	if err != nil {
		return MemoryPage{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	items := make([]Memory, 0, len(page.Sources))
	for _, source := range page.Sources {
		if source.Status == SourceStatusDeleted {
			continue
		}
		items = append(items, memoryFromSource(source, r.contents[source.ID], r.tags[source.ID]))
	}
	return MemoryPage{Items: items, NextPageToken: page.NextPageToken}, nil
}

func memoryFromSource(source Source, content string, tags []string) Memory {
	return Memory{ID: source.ID, Title: source.Title, Content: content, Tags: append([]string(nil), tags...), Revision: source.Revision, CreatedAt: source.CreatedAt, UpdatedAt: source.UpdatedAt}
}

func (r *MemoryRepository) cleanupSnapshotsLocked(now time.Time) {
	for id, snap := range r.snapshots {
		if !now.Before(snap.expires) {
			delete(r.snapshots, id)
		}
	}
	for len(r.snapshots) > maxSnapshots {
		var oldestID string
		var oldest time.Time
		for id, snap := range r.snapshots {
			if oldestID == "" || snap.created.Before(oldest) {
				oldestID, oldest = id, snap.created
			}
		}
		if oldestID == "" {
			break
		}
		delete(r.snapshots, oldestID)
	}
}

func (r *MemoryRepository) List(_ context.Context, q ListQuery) (Page, error) {
	if err := q.validate(); err != nil {
		return Page{}, err
	}
	n := q.PageSize
	if n == 0 {
		n = 50
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.nowUTC()
	r.cleanupSnapshotsLocked(now)
	digest := replayDigest(struct {
		Kind   SourceKind
		Status SourceStatus
	}{q.Kind, q.Status})
	c, err := decodePageCursor(q.PageToken)
	if err != nil {
		return Page{}, err
	}
	var vals []Source
	if q.PageToken != "" {
		if c.Digest != digest {
			return Page{}, ErrCursorConflict
		}
		snap, ok := r.snapshots[c.SnapshotID]
		if !ok || snap.digest != digest || !now.Before(snap.expires) {
			return Page{}, ErrCursorConflict
		}
		vals = append([]Source(nil), snap.sources...)
	} else {
		for _, s := range r.sources {
			if (q.Status == "" || s.Status == q.Status) && (q.Kind == "" || s.Kind == q.Kind) && !s.CreatedAt.After(now) {
				vals = append(vals, cloneSource(s))
			}
		}
		sortSources(vals)
	}
	start := 0
	for start < len(vals) && vals[start].ID <= c.LastID {
		start++
	}
	end := start + n
	if end > len(vals) {
		end = len(vals)
	}
	page := Page{Sources: append([]Source(nil), vals[start:end]...)}
	if end < len(vals) {
		snapshotID := c.SnapshotID
		if snapshotID == "" {
			snapshotID = uuid.NewString()
			r.snapshots[snapshotID] = repositorySnapshot{created: now, expires: now.Add(snapshotTTL), digest: digest, sources: append([]Source(nil), vals...)}
			r.cleanupSnapshotsLocked(now)
		}
		page.NextPageToken = encodePageCursor(cursor{LastID: vals[end-1].ID, Snapshot: now, SnapshotID: snapshotID, Digest: digest})
	}
	return page, nil
}

func (r *MemoryRepository) Delete(ctx context.Context, command DeleteCommand) (Source, error) {
	if err := command.validate(); err != nil {
		return Source{}, err
	}
	d := replayDigest(command)
	r.mu.Lock()
	// Exact replay is checked before any fence/deleter callback.
	if v, replayErr, ok := r.replayLocked(command.IdempotencyKey, d); ok {
		r.mu.Unlock()
		if v == nil {
			return Source{}, replayErr
		}
		return cloneSource(v.(Source)), replayErr
	}
	s, ok := r.sources[command.SourceID]
	if !ok {
		r.mu.Unlock()
		return Source{}, ErrNotFound
	}
	if command.Kind != "" && s.Kind != command.Kind {
		r.mu.Unlock()
		return Source{}, ErrNotFound
	}
	if s.Revision != command.ExpectedRevision || s.Status == SourceStatusDeleted {
		r.mu.Unlock()
		return Source{}, ErrRevisionConflict
	}
	fence := r.fence
	r.mu.Unlock()
	token, err := fence.AcquireDeleteFence(ctx, command.SourceID)
	if err != nil {
		return Source{}, safeError(err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = fence.ReleaseDeleteFence(ctx, token)
		}
	}()
	r.mu.Lock()
	var transitioned Source
	var contentRef ContentReference
	err = fence.ConsumeDelete(ctx, token, command.SourceID, command.ExpectedRevision, func() error {
		current, exists := r.sources[command.SourceID]
		if !exists || current.Revision != command.ExpectedRevision || current.Status == SourceStatusDeleted {
			return ErrRevisionConflict
		}
		current.Status, current.Revision, current.UpdatedAt = SourceStatusDeleting, current.Revision+1, r.nowUTC()
		r.sources[current.ID] = current
		contentRef = r.contentRefs[current.ID]
		transitioned = current
		return nil
	})
	if err != nil {
		r.mu.Unlock()
		return Source{}, safeError(err)
	}
	deleter := r.deleter
	contentPort := r.contentPort
	r.mu.Unlock()
	committed = true
	var cleanupErr error
	if transitioned.Kind == SourceKindMount {
		if transitioned.RelativePath != "" && deleter != nil {
			cleanupErr = deleter.Delete(ctx, transitioned.RelativePath)
		}
	} else if contentRef.Ref != "" {
		cleanupErr = contentPort.Delete(ctx, contentRef)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if cleanupErr != nil {
		transitioned.Status, transitioned.ErrorCode, transitioned.Revision, transitioned.UpdatedAt = SourceStatusCleanupPending, "cleanup_pending", transitioned.Revision+1, r.nowUTC()
		r.sources[transitioned.ID] = transitioned
		r.rememberLocked(command.IdempotencyKey, d, transitioned, ErrCleanupPending)
		return cloneSource(transitioned), ErrCleanupPending
	}
	transitioned.Status, transitioned.Revision, transitioned.UpdatedAt = SourceStatusDeleted, transitioned.Revision+1, r.nowUTC()
	r.sources[transitioned.ID] = transitioned
	delete(r.contentRefs, transitioned.ID)
	delete(r.contents, transitioned.ID)
	r.rememberLocked(command.IdempotencyKey, d, transitioned, nil)
	return cloneSource(transitioned), nil
}

func (r *MemoryRepository) ResolveSources(_ context.Context, ids []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range ids {
		s, ok := r.sources[id]
		if !ok || s.Status == SourceStatusDeleted {
			return ErrNotFound
		}
		if s.Status != SourceStatusReady {
			return ErrIneligible
		}
	}
	return nil
}

func (r *MemoryRepository) Status(_ context.Context) (Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := Status{CheckedAt: r.nowUTC()}
	for _, s := range r.sources {
		switch s.Status {
		case SourceStatusReady:
			out.ReadyCount++
		case SourceStatusUploading:
			out.UploadingCount++
		case SourceStatusIndexing:
			out.IndexingCount++
		case SourceStatusFailed:
			out.FailedCount++
		case SourceStatusCleanupPending:
			out.CleanupPendingCount++
		}
	}
	return out, nil
}

func (r *MemoryRepository) Search(_ context.Context, q SearchQuery) (SearchPage, error) {
	if err := q.validate(); err != nil {
		return SearchPage{}, err
	}
	n := q.Limit
	if n == 0 {
		n = 20
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.nowUTC()
	r.cleanupSnapshotsLocked(now)
	selected := map[string]bool{}
	for _, id := range q.SourceIDs {
		selected[id] = true
	}
	digest := replayDigest(struct {
		Query     string
		SourceIDs []string
		Kind      SourceKind
	}{strings.ToLower(strings.TrimSpace(q.Query)), q.SourceIDs, q.Kind})
	c, err := decodePageCursor(q.PageToken)
	if err != nil {
		return SearchPage{}, err
	}
	var matches []SearchMatch
	var provenance SearchProvenance
	if q.PageToken != "" {
		if c.Digest != digest {
			return SearchPage{}, ErrCursorConflict
		}
		snap, ok := r.snapshots[c.SnapshotID]
		if !ok || snap.digest != digest || !now.Before(snap.expires) {
			return SearchPage{}, ErrCursorConflict
		}
		matches = append([]SearchMatch(nil), snap.matches...)
		provenance = snap.provenance
	} else {
		for _, id := range q.SourceIDs {
			source, ok := r.sources[id]
			if !ok {
				for _, upload := range r.uploads {
					if upload.u.SourceID == id {
						return SearchPage{}, ErrIneligible
					}
				}
				return SearchPage{}, ErrNotFound
			}
			if source.Status == SourceStatusDeleted {
				return SearchPage{}, ErrNotFound
			}
			if source.Status != SourceStatusReady {
				return SearchPage{}, ErrIneligible
			}
			if q.Kind != "" && source.Kind != q.Kind {
				return SearchPage{}, ErrNotFound
			}
		}
		needle := strings.ToLower(strings.TrimSpace(q.Query))
		for id, s := range r.sources {
			if s.Status != SourceStatusReady || s.CreatedAt.After(now) || (q.Kind != "" && s.Kind != q.Kind) || (len(selected) > 0 && !selected[id]) {
				continue
			}
			text := r.contents[id]
			if strings.Contains(strings.ToLower(text), needle) {
				if len(text) > MaxSnippetBytes {
					text = text[:MaxSnippetBytes]
				}
				matches = append(matches, SearchMatch{SourceID: id, ChunkRef: id + ":0", Snippet: text, Score: 1})
			}
		}
		sort.Slice(matches, func(i, j int) bool {
			if matches[i].Score != matches[j].Score {
				return matches[i].Score > matches[j].Score
			}
			return matches[i].SourceID < matches[j].SourceID
		})
	}
	if q.PageToken == "" && r.embeddingConfig != nil {
		// The in-memory repository has no model-profile resolver.  Its durable
		// config revision is the strongest available binding, and the same
		// value is frozen in the snapshot so a later profile rebind cannot
		// relabel an already-issued cursor.
		profileRevision := r.embeddingConfig.EmbeddingProfileRevision
		if profileRevision <= 0 {
			profileRevision = r.embeddingConfig.Revision
		}
		provenance = SearchProvenance{
			EmbeddingProfileID:       r.embeddingConfig.EmbeddingProfileID,
			EmbeddingProfileRevision: profileRevision,
			EmbeddingModel:           r.embeddingConfig.EmbeddingModel,
			EmbeddingGeneration:      r.embeddingConfig.EmbeddingGeneration,
			CollectionConfigDigest:   r.embeddingConfig.CollectionConfigDigest,
		}
	}
	start := 0
	for start < len(matches) && matches[start].SourceID <= c.LastID {
		start++
	}
	end := start + n
	if end > len(matches) {
		end = len(matches)
	}
	out := SearchPage{Matches: append([]SearchMatch(nil), matches[start:end]...), SearchProvenance: provenance}
	if end < len(matches) {
		snapshotID := c.SnapshotID
		if snapshotID == "" {
			snapshotID = uuid.NewString()
			r.snapshots[snapshotID] = repositorySnapshot{created: now, expires: now.Add(snapshotTTL), digest: digest, matches: append([]SearchMatch(nil), matches...), provenance: provenance}
			r.cleanupSnapshotsLocked(now)
		}
		out.NextPageToken = encodePageCursor(cursor{LastID: matches[end-1].SourceID, Snapshot: now, SnapshotID: snapshotID, Digest: digest})
	}
	return out, nil
}

var _ Repository = (*MemoryRepository)(nil)

func (r *MemoryRepository) ContentPort() StreamingContentPort { return r.contentPort }

// MemoryContentPort is a bounded in-memory fixture for tests. Production
// adapters should persist finalized content outside the repository process.
type MemoryContentPort struct {
	mu       sync.Mutex
	quota    int64
	used     int64
	reserved int64
	next     uint64
	objects  map[string][]byte
}

func NewMemoryContentPort(quota int64) *MemoryContentPort {
	if quota < 1 {
		quota = 1
	}
	return &MemoryContentPort{quota: quota, objects: map[string][]byte{}}
}
func (p *MemoryContentPort) Begin(_ context.Context, m UploadMetadata) (ContentSink, error) {
	if p == nil || m.DeclaredSize < 0 || m.DeclaredSize > MaxUploadBytes {
		return nil, ErrLimitExceeded
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used+p.reserved+m.DeclaredSize > p.quota {
		return nil, ErrLimitExceeded
	}
	p.reserved += m.DeclaredSize
	return &memoryContentSink{parent: p, max: m.DeclaredSize, h: sha256.New()}, nil
}
func (p *MemoryContentPort) Delete(_ context.Context, ref ContentReference) error {
	if p == nil || ref.Ref == "" {
		return ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	data, ok := p.objects[ref.Ref]
	if !ok {
		// Memory sources are bounded inline metadata in this fixture and do not
		// materialize an external object; deletion is nevertheless idempotent.
		return nil
	}
	if int64(len(data)) != ref.SizeBytes || digestBytes(data) != strings.ToLower(ref.Digest) {
		return ErrChecksumMismatch
	}
	delete(p.objects, ref.Ref)
	p.used -= int64(len(data))
	if p.used < 0 {
		p.used = 0
	}
	return nil
}

func (p *MemoryContentPort) OpenContent(_ context.Context, ref ContentReference) (io.ReadCloser, error) {
	if p == nil || ref.Ref == "" {
		return nil, ErrInvalid
	}
	p.mu.Lock()
	data, ok := p.objects[ref.Ref]
	p.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	if int64(len(data)) != ref.SizeBytes || digestBytes(data) != strings.ToLower(ref.Digest) {
		return nil, ErrChecksumMismatch
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

type memoryContentSink struct {
	parent    *MemoryContentPort
	h         hash.Hash
	data      []byte
	size, max int64
	done      bool
	ref       string
}

func (s *memoryContentSink) Write(p []byte) (int, error) {
	if s.done {
		return 0, ErrConflict
	}
	if s.size+int64(len(p)) > s.max {
		return 0, ErrLimitExceeded
	}
	s.data = append(s.data, p...)
	n, err := s.h.Write(p)
	s.size += int64(n)
	return n, err
}
func (s *memoryContentSink) Size() int64    { return s.size }
func (s *memoryContentSink) SHA256() string { return fmt.Sprintf("%x", s.h.Sum(nil)) }
func (s *memoryContentSink) Finalize(_ context.Context, expectedDigest string, expectedSize int64) (ContentReference, error) {
	if s.done || s.size != expectedSize || !strings.EqualFold(s.SHA256(), expectedDigest) {
		return ContentReference{}, ErrChecksumMismatch
	}
	s.parent.mu.Lock()
	defer s.parent.mu.Unlock()
	s.parent.reserved -= s.max
	s.parent.used += int64(len(s.data))
	s.parent.next++
	ref := fmt.Sprintf("memory-content-%d", s.parent.next)
	s.parent.objects[ref] = append([]byte(nil), s.data...)
	s.done, s.ref = true, ref
	return ContentReference{Ref: ref, Digest: s.SHA256(), SizeBytes: s.size}, nil
}
func (s *memoryContentSink) Abort(_ context.Context) error {
	s.parent.mu.Lock()
	if s.done {
		if s.ref != "" {
			if data, ok := s.parent.objects[s.ref]; ok {
				delete(s.parent.objects, s.ref)
				s.parent.used -= int64(len(data))
				if s.parent.used < 0 {
					s.parent.used = 0
				}
			}
		}
		s.parent.mu.Unlock()
		return nil
	}
	s.parent.reserved -= s.max
	if s.parent.reserved < 0 {
		s.parent.reserved = 0
	}
	s.parent.mu.Unlock()
	s.data = nil
	s.done = true
	return nil
}
