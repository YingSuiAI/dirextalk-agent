package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (r *CoreKnowledgeStore) CreateMount(ctx context.Context, command coreknowledge.MountCommand) (coreknowledge.Source, error) {
	if err := command.ValidateForRepository(); err != nil {
		return coreknowledge.Source{}, err
	}
	digest := knowledgeDigest(command)
	tx, err := r.store.pool.Begin(ctx)
	if err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	defer tx.Rollback(ctx)
	if err = lockKnowledgeKey(ctx, tx, "mount", command.IdempotencyKey); err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	var replay knowledgeReplay
	if ok, replayErr := replayKnowledge(ctx, tx, "mount", command.IdempotencyKey, digest, &replay); ok {
		if replayErr == nil {
			_ = tx.Commit(ctx)
			return replay.Source, nil
		}
		return coreknowledge.Source{}, replayErr
	}
	if r.opener == nil {
		return coreknowledge.Source{}, coreknowledge.ErrFilesystemUnavailable
	}
	file, err := r.opener.OpenManaged(ctx, command.RelativePath)
	if err != nil || file == nil {
		return coreknowledge.Source{}, coreknowledge.ErrFilesystemUnavailable
	}
	_ = file.Close()
	declaredDigest := strings.ToLower(command.Digest)
	var manifestJSON []byte
	manifestDigest := ""
	var fallbackRead bool
	if enumerator, ok := r.opener.(coreknowledge.DirectoryManifestEnumerator); ok {
		if manifest, enumErr := enumerator.EnumerateManagedDirectory(ctx, command.RelativePath, coreknowledge.DirectoryManifestLimits{}); enumErr == nil {
			manifestJSON, _ = json.Marshal(manifest)
			manifestDigest = manifest.Digest
			if declaredDigest != "" && declaredDigest != manifest.Digest {
				return coreknowledge.Source{}, coreknowledge.ErrChecksumMismatch
			}
			command.Digest, command.SizeBytes = manifest.Digest, manifest.Bytes
		}
	}
	if manifestJSON == nil {
		if f, openErr := r.opener.OpenManaged(ctx, command.RelativePath); openErr == nil {
			defer f.Close()
			data, readErr := io.ReadAll(io.LimitReader(f, coreknowledge.MaxUploadBytes+1))
			if readErr == nil && int64(len(data)) <= coreknowledge.MaxUploadBytes {
				fallbackRead = true
				h := sha256.Sum256(data)
				fileDigest := hex.EncodeToString(h[:])
				if declaredDigest != "" && declaredDigest != fileDigest {
					return coreknowledge.Source{}, coreknowledge.ErrChecksumMismatch
				}
				root := path.Dir(command.RelativePath)
				if root != "." {
					entry := coreknowledge.DirectoryManifestEntry{Path: path.Base(command.RelativePath), Digest: fileDigest, SizeBytes: int64(len(data)), MediaType: command.MediaType}
					canonical, _ := json.Marshal([]coreknowledge.DirectoryManifestEntry{entry})
					md := sha256.Sum256(canonical)
					manifest := coreknowledge.DirectoryManifest{Root: root, Revision: 1, Digest: hex.EncodeToString(md[:]), Bytes: int64(len(data)), Entries: []coreknowledge.DirectoryManifestEntry{entry}}
					manifestJSON, _ = json.Marshal(manifest)
					manifestDigest = manifest.Digest
				}
				command.Digest = fileDigest
				command.SizeBytes = int64(len(data))
			}
		}
	}
	// A directory manifest failure must not silently degrade into a ready
	// source with empty metadata (for example, a directory containing a
	// symlink or another unsupported entry). The fallback path is only valid
	// when the requested object was successfully read as a regular file.
	if manifestJSON == nil && !fallbackRead {
		return coreknowledge.Source{}, coreknowledge.ErrFilesystemUnavailable
	}
	id := command.SourceID
	if id == "" {
		id = uuid.NewString()
	}
	now := r.nowUTC()
	s := coreknowledge.Source{ID: id, Kind: coreknowledge.SourceKindMount, Status: coreknowledge.SourceStatusReady, Title: command.Title, RelativePath: command.RelativePath, Digest: strings.ToLower(command.Digest), SizeBytes: command.SizeBytes, MediaType: command.MediaType, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if manifestJSON == nil {
		manifestJSON = []byte(`{}`)
	}
	ownerID, generation, scopeErr := r.knowledgeScope(ctx)
	if scopeErr != nil {
		return coreknowledge.Source{}, coreknowledge.ErrInvalid
	}
	_, err = tx.Exec(ctx, `INSERT INTO core_knowledge_sources(source_id,kind,status,title,relative_path,digest,size_bytes,media_type,revision,directory_manifest_json,directory_manifest_digest,created_at,updated_at,owner_id,account_generation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, s.ID, s.Kind, s.Status, s.Title, s.RelativePath, s.Digest, s.SizeBytes, s.MediaType, s.Revision, manifestJSON, manifestDigest, s.CreatedAt, s.UpdatedAt, ownerID, generation)
	if err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	if err = bindKnowledgeSourceOwnerScopeTx(ctx, tx, s.ID); err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	if err = putKnowledgeReplay(ctx, tx, "mount", command.IdempotencyKey, digest, knowledgeReplay{Source: s}, nil); err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	return s, nil
}

func (r *CoreKnowledgeStore) Get(ctx context.Context, id string) (coreknowledge.Source, error) {
	if !validKnowledgeUUID(id) {
		return coreknowledge.Source{}, coreknowledge.ErrInvalid
	}
	ownerID, generation := publicOwnerScopeValues(ctx)
	s, err := scanKnowledgeSource(r.store.pool.QueryRow(ctx, knowledgeSourceSelect+` WHERE source_id=$1 AND ($2='' OR (owner_id=$2 AND account_generation=$3))`, id, ownerID, generation))
	if errors.Is(err, pgx.ErrNoRows) || s.Status == coreknowledge.SourceStatusDeleted {
		return coreknowledge.Source{}, coreknowledge.ErrNotFound
	}
	if err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	return s, nil
}

func (r *CoreKnowledgeStore) GetMemory(ctx context.Context, id string) (coreknowledge.Memory, error) {
	s, err := r.Get(ctx, id)
	if err != nil {
		return coreknowledge.Memory{}, err
	}
	if s.Kind != coreknowledge.SourceKindMemory {
		return coreknowledge.Memory{}, coreknowledge.ErrNotFound
	}
	content, err := r.readMemoryContent(ctx, s)
	if err != nil {
		return coreknowledge.Memory{}, err
	}
	return coreknowledge.Memory{ID: s.ID, Title: s.Title, Content: content, Tags: append([]string(nil), s.Tags...), Revision: s.Revision, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt}, nil
}

func (r *CoreKnowledgeStore) ListMemories(ctx context.Context, q coreknowledge.ListQuery) (coreknowledge.MemoryPage, error) {
	q.Kind = coreknowledge.SourceKindMemory
	page, err := r.List(ctx, q)
	if err != nil {
		return coreknowledge.MemoryPage{}, err
	}
	items := make([]coreknowledge.Memory, 0, len(page.Sources))
	for _, source := range page.Sources {
		// Deleted memories intentionally retain a tombstone row for exact-once
		// deletion replay, but their immutable content has already been removed.
		// A normal memory list must therefore hide the tombstone instead of
		// attempting to reopen a content reference that no longer exists.
		if source.Status == coreknowledge.SourceStatusDeleted {
			continue
		}
		content, readErr := r.readMemoryContent(ctx, source)
		if readErr != nil {
			return coreknowledge.MemoryPage{}, readErr
		}
		items = append(items, coreknowledge.Memory{ID: source.ID, Title: source.Title, Content: content, Tags: append([]string(nil), source.Tags...), Revision: source.Revision, CreatedAt: source.CreatedAt, UpdatedAt: source.UpdatedAt})
	}
	return coreknowledge.MemoryPage{Items: items, NextPageToken: page.NextPageToken}, nil
}

func (r *CoreKnowledgeStore) readMemoryContent(ctx context.Context, source coreknowledge.Source) (string, error) {
	reader, ok := r.content.(coreknowledge.ContentReader)
	if !ok || strings.TrimSpace(source.ContentRef) == "" {
		return "", coreknowledge.ErrFilesystemUnavailable
	}
	file, err := reader.OpenContent(ctx, coreknowledge.ContentReference{Ref: source.ContentRef, Digest: source.Digest, SizeBytes: source.SizeBytes})
	if err != nil || file == nil {
		return "", coreknowledge.ErrFilesystemUnavailable
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(coreknowledge.MaxMemoryBytes)+1))
	if err != nil || len(data) > coreknowledge.MaxMemoryBytes || int64(len(data)) != source.SizeBytes || !strings.EqualFold(digestBytesKnowledge(data), source.Digest) || !utf8.Valid(data) {
		return "", coreknowledge.ErrChecksumMismatch
	}
	return string(data), nil
}

type knowledgeCursor struct {
	LastID     string    `json:"last_id"`
	Ordinal    int       `json:"ordinal"`
	Snapshot   time.Time `json:"snapshot"`
	SnapshotID string    `json:"snapshot_id"`
	Digest     string    `json:"digest"`
}

func encodeKnowledgeCursor(c knowledgeCursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}
func decodeKnowledgeCursor(token string) (knowledgeCursor, error) {
	if token == "" {
		return knowledgeCursor{}, nil
	}
	b, e := base64.RawURLEncoding.DecodeString(token)
	if e != nil {
		return knowledgeCursor{}, coreknowledge.ErrInvalid
	}
	var c knowledgeCursor
	if json.Unmarshal(b, &c) != nil || c.SnapshotID == "" || c.Digest == "" || c.Snapshot.IsZero() || c.Ordinal < 0 {
		return knowledgeCursor{}, coreknowledge.ErrInvalid
	}
	if c.LastID == "" && c.Ordinal == 0 {
		// Search cursors use the stable snapshot ordinal. List cursors retain
		// their source-id boundary and always carry LastID.
		return knowledgeCursor{}, coreknowledge.ErrInvalid
	}
	return c, nil
}

func (r *CoreKnowledgeStore) List(ctx context.Context, q coreknowledge.ListQuery) (coreknowledge.Page, error) {
	if err := q.ValidateForRepository(); err != nil {
		return coreknowledge.Page{}, err
	}
	n := q.PageSize
	if n == 0 {
		n = 50
	}
	digest := knowledgeDigest(struct {
		Kind   coreknowledge.SourceKind   `json:"kind"`
		Status coreknowledge.SourceStatus `json:"status"`
	}{q.Kind, q.Status})
	c, err := decodeKnowledgeCursor(q.PageToken)
	if err != nil {
		return coreknowledge.Page{}, err
	}
	var ids []string
	now := r.nowUTC()
	var projections []coreknowledge.Source
	ownerID, generation := publicOwnerScopeValues(ctx)
	snapshotOwner, snapshotGeneration, scopeErr := r.knowledgeScope(ctx)
	if scopeErr != nil {
		return coreknowledge.Page{}, coreknowledge.ErrInvalid
	}
	if q.PageToken == "" {
		rows, e := r.store.pool.Query(ctx, knowledgeSourceSelect+` WHERE ($1='' OR kind=$1) AND ($2='' OR status=$2) AND ($3='' OR (owner_id=$3 AND account_generation=$4)) AND source_id IS NOT NULL ORDER BY source_id`, q.Kind, q.Status, ownerID, generation)
		if e != nil {
			return coreknowledge.Page{}, coreknowledge.ErrConflict
		}
		for rows.Next() {
			s, scanErr := scanKnowledgeSource(rows)
			if scanErr != nil {
				rows.Close()
				return coreknowledge.Page{}, coreknowledge.ErrConflict
			}
			ids = append(ids, s.ID)
			projections = append(projections, s)
		}
		rows.Close()
		if len(ids) == 0 {
			return coreknowledge.Page{}, nil
		}
		snapID := uuid.New()
		raw, _ := json.Marshal(ids)
		projectionRaw, _ := json.Marshal(projections)
		if _, e = r.store.pool.Exec(ctx, `INSERT INTO core_knowledge_list_snapshots(snapshot_id,owner_id,account_generation,query_digest,snapshot_at,expires_at,source_ids,search_matches) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, snapID, snapshotOwner, snapshotGeneration, digest, now, now.Add(knowledgeSnapshotTTL), raw, projectionRaw); e != nil {
			return coreknowledge.Page{}, coreknowledge.ErrConflict
		}
		c = knowledgeCursor{SnapshotID: snapID.String(), Snapshot: now, Digest: digest}
	}
	if c.Digest != digest {
		return coreknowledge.Page{}, coreknowledge.ErrCursorConflict
	}
	var raw []byte
	var projectionRaw []byte
	var snapshotAt, expires time.Time
	if err = r.store.pool.QueryRow(ctx, `SELECT source_ids,search_matches,snapshot_at,expires_at FROM core_knowledge_list_snapshots WHERE snapshot_id=$1 AND owner_id=$2 AND account_generation=$3 AND query_digest=$4`, c.SnapshotID, snapshotOwner, snapshotGeneration, digest).Scan(&raw, &projectionRaw, &snapshotAt, &expires); err != nil || !now.Before(expires) {
		return coreknowledge.Page{}, coreknowledge.ErrCursorConflict
	}
	if json.Unmarshal(raw, &ids) != nil {
		return coreknowledge.Page{}, coreknowledge.ErrCursorConflict
	}
	_ = json.Unmarshal(projectionRaw, &projections)
	start := 0
	for start < len(ids) && ids[start] <= c.LastID {
		start++
	}
	end := start + n
	if end > len(ids) {
		end = len(ids)
	}
	out := coreknowledge.Page{}
	for idx, id := range ids[start:end] {
		if start+idx < len(projections) {
			out.Sources = append(out.Sources, projections[start+idx])
			continue
		}
		s, e := r.Get(ctx, id)
		if e == nil {
			out.Sources = append(out.Sources, s)
		}
	}
	if end < len(ids) {
		out.NextPageToken = encodeKnowledgeCursor(knowledgeCursor{LastID: ids[end-1], Snapshot: snapshotAt, SnapshotID: c.SnapshotID, Digest: digest})
	}
	return out, nil
}
