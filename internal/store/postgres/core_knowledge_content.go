package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (r *CoreKnowledgeStore) StartUpload(ctx context.Context, metadata coreknowledge.UploadMetadata) (coreknowledge.Upload, error) {
	if err := metadata.ValidateForRepository(); err != nil {
		return coreknowledge.Upload{}, err
	}
	digest := knowledgeDigest(metadata)
	tx, err := r.store.pool.Begin(ctx)
	if err != nil {
		return coreknowledge.Upload{}, coreknowledge.ErrConflict
	}
	defer tx.Rollback(ctx)
	if err = lockKnowledgeKey(ctx, tx, "upload.start", metadata.IdempotencyKey); err != nil {
		return coreknowledge.Upload{}, coreknowledge.ErrConflict
	}
	// Serialize the bounded reservation ledger so concurrent uploads cannot
	// over-commit the configured per-instance quota.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('knowledge:upload-quota',0))`); err != nil {
		return coreknowledge.Upload{}, coreknowledge.ErrConflict
	}
	var replay knowledgeReplay
	if ok, replayErr := replayKnowledge(ctx, tx, "upload.start", metadata.IdempotencyKey, digest, &replay); ok {
		if replayErr == nil {
			replay.Upload.Replayed = true
			_ = tx.Commit(ctx)
			return replay.Upload, nil
		}
		return coreknowledge.Upload{}, replayErr
	}
	var active int
	var reserved int64
	if err = tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE active), COALESCE(sum(reserved_bytes) FILTER (WHERE active),0) FROM core_knowledge_upload_reservations`).Scan(&active, &reserved); err != nil {
		return coreknowledge.Upload{}, coreknowledge.ErrConflict
	}
	if active >= knowledgeMaxActiveUploads || reserved+metadata.DeclaredSize > knowledgeMaxReservedBytes {
		return coreknowledge.Upload{}, coreknowledge.ErrLimitExceeded
	}
	uploadID, sourceID := metadata.UploadID, metadata.SourceID
	if uploadID == "" {
		uploadID = uuid.NewSHA1(uuid.NameSpaceURL, []byte("dirextalk/upload/"+metadata.IdempotencyKey)).String()
	}
	if sourceID == "" {
		sourceID = uuid.NewSHA1(uuid.NameSpaceURL, []byte("dirextalk/source/"+metadata.IdempotencyKey)).String()
	}
	metadata.UploadID, metadata.SourceID = uploadID, sourceID
	sink, err := r.content.Begin(ctx, metadata)
	if err != nil || sink == nil {
		if resumable, ok := r.content.(resumableContentPort); ok {
			sink, err = resumable.Resume(ctx, metadata, 0, 0)
		}
	}
	if err != nil || sink == nil {
		return coreknowledge.Upload{}, coreknowledge.ErrConflict
	}
	now := r.nowUTC()
	metaRaw, _ := json.Marshal(metadata)
	s := coreknowledge.Source{ID: sourceID, Kind: coreknowledge.SourceKindUpload, Status: coreknowledge.SourceStatusUploading, Title: metadata.Title, RelativePath: metadata.RelativePath, Digest: strings.ToLower(metadata.ContentSHA256), SizeBytes: metadata.DeclaredSize, MediaType: metadata.MediaType, Revision: 1, CreatedAt: now, UpdatedAt: now}
	u := coreknowledge.Upload{ID: uploadID, SourceID: sourceID, Status: coreknowledge.SourceStatusUploading, Metadata: metadata, ReceivedSize: 0, NextChunk: 0, Revision: 1, CreatedAt: now, UpdatedAt: now, Session: coreknowledge.UploadSession{UploadID: uploadID, SourceID: sourceID, Revision: 1}}
	_, err = tx.Exec(ctx, `INSERT INTO core_knowledge_sources(source_id,kind,status,title,relative_path,digest,size_bytes,media_type,revision,created_at,updated_at) VALUES($1,'upload','uploading',$2,$3,$4,$5,$6,1,$7,$7)`, sourceID, s.Title, s.RelativePath, s.Digest, s.SizeBytes, s.MediaType, now)
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO core_knowledge_uploads(upload_id,source_id,metadata_json,declared_size,content_digest,status,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'uploading',$6,$6)`, uploadID, sourceID, metaRaw, metadata.DeclaredSize, strings.ToLower(metadata.ContentSHA256), now)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO core_knowledge_upload_reservations(upload_id,reserved_bytes) VALUES($1,$2)`, uploadID, metadata.DeclaredSize)
	}
	if err == nil {
		err = putKnowledgeReplay(ctx, tx, "upload.start", metadata.IdempotencyKey, digest, knowledgeReplay{Upload: u}, nil)
	}
	if err != nil {
		_ = sink.Abort(ctx)
		return coreknowledge.Upload{}, coreknowledge.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		// Commit outcome is ambiguous at the client boundary. Preserve staging
		// and let an exact idempotency replay/readback reconcile the outcome.
		_ = tx.Rollback(ctx)
		var raw []byte
		if readErr := r.store.pool.QueryRow(ctx, `SELECT response_json FROM core_knowledge_mutation_replays WHERE operation='upload.start' AND idempotency_key=$1`, uuid.MustParse(metadata.IdempotencyKey)).Scan(&raw); readErr == nil {
			var canonical knowledgeReplay
			if json.Unmarshal(raw, &canonical) == nil && canonical.Upload.ID != "" {
				canonical.Upload.Replayed = true
				r.mu.Lock()
				r.sinks[canonical.Upload.ID] = sink
				r.mu.Unlock()
				return canonical.Upload, nil
			}
		}
		return coreknowledge.Upload{}, coreknowledge.ErrConflict
	}
	r.mu.Lock()
	r.sinks[uploadID] = sink
	r.mu.Unlock()
	return u, nil
}

// GetUpload reads the durable cursor without claiming or mutating the upload.
// It is used by capability adapters when a public request omits the internal
// revision/ordinal fields; append/commit still re-check them transactionally.
func (r *CoreKnowledgeStore) GetUpload(ctx context.Context, id string) (coreknowledge.Upload, error) {
	return r.loadUpload(ctx, id)
}

func (r *CoreKnowledgeStore) loadUpload(ctx context.Context, id string) (coreknowledge.Upload, error) {
	query := `SELECT upload_id,source_id,metadata_json,status,received_size,next_ordinal,revision,created_at,updated_at FROM core_knowledge_uploads WHERE upload_id=$1`
	var u coreknowledge.Upload
	var raw []byte
	var status string
	if err := r.store.pool.QueryRow(ctx, query, id).Scan(&u.ID, &u.SourceID, &raw, &status, &u.ReceivedSize, &u.NextChunk, &u.Revision, &u.CreatedAt, &u.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return u, coreknowledge.ErrNotFound
		}
		return u, coreknowledge.ErrConflict
	}
	if json.Unmarshal(raw, &u.Metadata) != nil {
		return u, coreknowledge.ErrConflict
	}
	u.Status = coreknowledge.SourceStatus(status)
	u.CreatedAt, u.UpdatedAt = u.CreatedAt.UTC(), u.UpdatedAt.UTC()
	u.Session = coreknowledge.UploadSession{UploadID: u.ID, SourceID: u.SourceID, ReceivedSize: u.ReceivedSize, NextOrdinal: u.NextChunk, Revision: u.Revision}
	return u, nil
}

func (r *CoreKnowledgeStore) sinkFor(ctx context.Context, u coreknowledge.Upload) (coreknowledge.ContentSink, error) {
	r.mu.Lock()
	sink := r.sinks[u.ID]
	r.mu.Unlock()
	if sink != nil {
		return sink, nil
	}
	if resumed, ok := r.content.(resumableContentPort); ok {
		sink, err := resumed.Resume(ctx, u.Metadata, u.ReceivedSize, u.NextChunk)
		if err == nil && sink != nil {
			r.mu.Lock()
			r.sinks[u.ID] = sink
			r.mu.Unlock()
		}
		return sink, err
	}
	return nil, coreknowledge.ErrFilesystemUnavailable
}

func (r *CoreKnowledgeStore) AppendUploadChunk(ctx context.Context, chunk coreknowledge.UploadChunk) (coreknowledge.Upload, error) {
	if err := chunk.ValidateForRepository(); err != nil {
		return coreknowledge.Upload{}, err
	}
	digest := knowledgeDigest(chunk)
	tx, err := r.store.pool.Begin(ctx)
	if err != nil {
		return coreknowledge.Upload{}, coreknowledge.ErrConflict
	}
	defer tx.Rollback(ctx)
	if err = lockKnowledgeKey(ctx, tx, "upload.chunk", chunk.IdempotencyKey); err != nil {
		return coreknowledge.Upload{}, coreknowledge.ErrConflict
	}
	var replay knowledgeReplay
	if ok, replayErr := replayKnowledge(ctx, tx, "upload.chunk", chunk.IdempotencyKey, digest, &replay); ok {
		if replayErr == nil {
			_ = tx.Commit(ctx)
			return replay.Upload, nil
		}
		return coreknowledge.Upload{}, replayErr
	}
	u, err := r.loadUploadTx(ctx, tx, chunk.UploadID, true)
	if err != nil {
		return coreknowledge.Upload{}, err
	}
	if u.Status != coreknowledge.SourceStatusUploading || chunk.Ordinal != u.NextChunk || chunk.OffsetBytes != u.ReceivedSize {
		return coreknowledge.Upload{}, coreknowledge.ErrRevisionConflict
	}
	if u.ReceivedSize+int64(len(chunk.Data)) > u.Metadata.DeclaredSize {
		return coreknowledge.Upload{}, coreknowledge.ErrInvalid
	}
	if !strings.EqualFold(chunk.ChunkSHA256, digestBytesKnowledge(chunk.Data)) {
		return coreknowledge.Upload{}, coreknowledge.ErrChecksumMismatch
	}
	sink, err := r.sinkFor(ctx, u)
	if err != nil {
		return coreknowledge.Upload{}, coreknowledge.ErrFilesystemUnavailable
	}
	previousSize := u.ReceivedSize
	// A lost PostgreSQL commit may leave staged bytes durable while metadata
	// rolled back. Reconcile that exact prefix before replaying the chunk.
	if sink.Size() != previousSize {
		if sink.Size() < previousSize {
			return coreknowledge.Upload{}, coreknowledge.ErrFilesystemUnavailable
		}
		if rw, ok := sink.(rewindableContentSink); !ok || rw.Rewind(ctx, previousSize) != nil {
			return coreknowledge.Upload{}, coreknowledge.ErrConflict
		}
	}
	n, err := sink.Write(chunk.Data)
	if err != nil || n != len(chunk.Data) {
		if rw, ok := sink.(rewindableContentSink); ok {
			_ = rw.Rewind(ctx, previousSize)
		}
		return coreknowledge.Upload{}, coreknowledge.ErrConflict
	}
	now := r.nowUTC()
	u.ReceivedSize += int64(n)
	u.NextChunk++
	u.Revision++
	u.UpdatedAt = now
	u.Session = coreknowledge.UploadSession{UploadID: u.ID, SourceID: u.SourceID, ReceivedSize: u.ReceivedSize, NextOrdinal: u.NextChunk, Revision: u.Revision}
	_, err = tx.Exec(ctx, `INSERT INTO core_knowledge_upload_chunks(upload_id,ordinal,offset_bytes,size_bytes,chunk_digest) VALUES($1,$2,$3,$4,$5)`, u.ID, chunk.Ordinal, chunk.OffsetBytes, n, strings.ToLower(chunk.ChunkSHA256))
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE core_knowledge_uploads SET received_size=$2,next_ordinal=$3,revision=$4,updated_at=$5 WHERE upload_id=$1`, u.ID, u.ReceivedSize, u.NextChunk, u.Revision, now)
	}
	if err == nil {
		err = putKnowledgeReplay(ctx, tx, "upload.chunk", chunk.IdempotencyKey, digest, knowledgeReplay{Upload: u}, nil)
	}
	if err != nil {
		if rw, ok := sink.(rewindableContentSink); ok {
			_ = rw.Rewind(ctx, previousSize)
		} else {
			_ = sink.Abort(ctx)
		}
		return coreknowledge.Upload{}, coreknowledge.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		return coreknowledge.Upload{}, coreknowledge.ErrConflict
	}
	return u, nil
}

func digestBytesKnowledge(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func (r *CoreKnowledgeStore) CommitUpload(ctx context.Context, command coreknowledge.CommitUploadCommand) (coreknowledge.Upload, coreknowledge.Source, error) {
	if err := command.ValidateForRepository(); err != nil {
		return coreknowledge.Upload{}, coreknowledge.Source{}, err
	}
	digest := knowledgeDigest(command)
	tx, err := r.store.pool.Begin(ctx)
	if err != nil {
		return coreknowledge.Upload{}, coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	defer tx.Rollback(ctx)
	if err = lockKnowledgeKey(ctx, tx, "upload.commit", command.IdempotencyKey); err != nil {
		return coreknowledge.Upload{}, coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	var replay knowledgeReplay
	if ok, replayErr := replayKnowledge(ctx, tx, "upload.commit", command.IdempotencyKey, digest, &replay); ok {
		if replayErr == nil && replay.Pair != nil {
			_ = tx.Commit(ctx)
			return replay.Pair.Upload, replay.Pair.Source, nil
		}
		return coreknowledge.Upload{}, coreknowledge.Source{}, replayErr
	}
	u, err := r.loadUploadTx(ctx, tx, command.UploadID, true)
	if err != nil {
		return coreknowledge.Upload{}, coreknowledge.Source{}, err
	}
	if u.Status != coreknowledge.SourceStatusUploading || u.Revision != command.ExpectedRevision {
		return coreknowledge.Upload{}, coreknowledge.Source{}, coreknowledge.ErrRevisionConflict
	}
	if u.ReceivedSize != u.Metadata.DeclaredSize {
		return coreknowledge.Upload{}, coreknowledge.Source{}, coreknowledge.ErrInvalid
	}
	sink, err := r.sinkFor(ctx, u)
	if err != nil {
		return coreknowledge.Upload{}, coreknowledge.Source{}, coreknowledge.ErrFilesystemUnavailable
	}
	ref, err := sink.Finalize(ctx, strings.ToLower(command.ContentSHA256), u.ReceivedSize)
	if err != nil {
		return coreknowledge.Upload{}, coreknowledge.Source{}, coreknowledge.ErrChecksumMismatch
	}
	if ref.Ref == "" || ref.SizeBytes != u.ReceivedSize || !strings.EqualFold(ref.Digest, command.ContentSHA256) || !strings.EqualFold(ref.Digest, u.Metadata.ContentSHA256) {
		return coreknowledge.Upload{}, coreknowledge.Source{}, coreknowledge.ErrChecksumMismatch
	}
	now := r.nowUTC()
	u.Status = coreknowledge.SourceStatusReady
	u.Revision++
	u.UpdatedAt = now
	u.Session = coreknowledge.UploadSession{UploadID: u.ID, SourceID: u.SourceID, ReceivedSize: u.ReceivedSize, NextOrdinal: u.NextChunk, Revision: u.Revision}
	s, err := scanKnowledgeSource(tx.QueryRow(ctx, knowledgeSourceSelect+` WHERE source_id=$1 FOR UPDATE`, u.SourceID))
	if err != nil {
		return coreknowledge.Upload{}, coreknowledge.Source{}, coreknowledge.ErrNotFound
	}
	s.Status = coreknowledge.SourceStatusReady
	s.Revision++
	s.UpdatedAt = now
	s.Digest = strings.ToLower(ref.Digest)
	s.SizeBytes = ref.SizeBytes
	_, err = tx.Exec(ctx, `UPDATE core_knowledge_sources SET status='ready',revision=$2,updated_at=$3,digest=$4,size_bytes=$5,content_ref=$6 WHERE source_id=$1`, s.ID, s.Revision, now, s.Digest, s.SizeBytes, ref.Ref)
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE core_knowledge_uploads SET status='ready',revision=$2,updated_at=$3,content_ref=$4 WHERE upload_id=$1`, u.ID, u.Revision, now, ref.Ref)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE core_knowledge_upload_reservations SET active=false,updated_at=$2 WHERE upload_id=$1`, u.ID, now)
	}
	if err == nil {
		err = putKnowledgeReplay(ctx, tx, "upload.commit", command.IdempotencyKey, digest, knowledgeReplay{Pair: &knowledgePair{Upload: u, Source: s}}, nil)
	}
	if err != nil {
		_ = r.content.Delete(ctx, ref)
		r.mu.Lock()
		delete(r.sinks, u.ID)
		r.mu.Unlock()
		return coreknowledge.Upload{}, coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		return coreknowledge.Upload{}, coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	r.mu.Lock()
	delete(r.sinks, u.ID)
	r.mu.Unlock()
	return u, s, nil
}

func (r *CoreKnowledgeStore) AbortUpload(ctx context.Context, command coreknowledge.AbortUploadCommand) error {
	if !validKnowledgeUUID(command.IdempotencyKey) || !validKnowledgeUUID(command.UploadID) || command.ExpectedRevision < 1 {
		return coreknowledge.ErrInvalid
	}
	digest := knowledgeDigest(command)
	tx, err := r.store.pool.Begin(ctx)
	if err != nil {
		return coreknowledge.ErrConflict
	}
	defer tx.Rollback(ctx)
	if err = lockKnowledgeKey(ctx, tx, "upload.abort", command.IdempotencyKey); err != nil {
		return coreknowledge.ErrConflict
	}
	var replay knowledgeReplay
	if ok, replayErr := replayKnowledge(ctx, tx, "upload.abort", command.IdempotencyKey, digest, &replay); ok {
		if replay.Upload.ID != "" {
			_ = tx.Rollback(ctx)
			if err := r.cleanupAbortedUpload(ctx, replay.Upload); err != nil {
				return err
			}
		}
		return replayErr
	}
	u, err := r.loadUploadTx(ctx, tx, command.UploadID, true)
	if err != nil {
		return err
	}
	if u.Status != coreknowledge.SourceStatusUploading || u.Revision != command.ExpectedRevision {
		return coreknowledge.ErrRevisionConflict
	}
	now := r.nowUTC()
	_, err = tx.Exec(ctx, `UPDATE core_knowledge_uploads SET status='deleted',revision=revision+1,updated_at=$2 WHERE upload_id=$1`, u.ID, now)
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE core_knowledge_sources SET status='deleted',revision=revision+1,updated_at=$2 WHERE source_id=$1`, u.SourceID, now)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE core_knowledge_upload_reservations SET active=false,updated_at=$2 WHERE upload_id=$1`, u.ID, now)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO core_knowledge_cleanup(source_id,operation,idempotency_key,request_hash,content_ref,relative_path,attempts,last_error,next_attempt_at,updated_at) VALUES($1,'upload_abort',$2,$3,'','',0,'',$4,$4) ON CONFLICT(source_id) DO UPDATE SET operation='upload_abort',idempotency_key=EXCLUDED.idempotency_key,request_hash=EXCLUDED.request_hash,updated_at=EXCLUDED.updated_at`, u.SourceID, uuid.MustParse(command.IdempotencyKey), digest, now)
	}
	if err == nil {
		err = putKnowledgeReplay(ctx, tx, "upload.abort", command.IdempotencyKey, digest, knowledgeReplay{Upload: u}, nil)
	}
	if err != nil {
		return coreknowledge.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		return coreknowledge.ErrConflict
	}
	if err := r.cleanupAbortedUpload(ctx, u); err != nil {
		return err
	}
	return nil
}

func (r *CoreKnowledgeStore) cleanupAbortedUpload(ctx context.Context, u coreknowledge.Upload) error {
	sink, err := r.sinkFor(ctx, u)
	if err != nil {
		if errors.Is(err, coreknowledge.ErrNotFound) {
			if _, dbErr := r.store.pool.Exec(ctx, `DELETE FROM core_knowledge_cleanup WHERE source_id=$1 AND operation='upload_abort'`, u.SourceID); dbErr != nil {
				return coreknowledge.ErrCleanupPending
			}
			return nil
		}
		if errors.Is(err, coreknowledge.ErrFilesystemUnavailable) {
			return coreknowledge.ErrCleanupPending
		}
		return coreknowledge.ErrCleanupPending
	}
	if sink != nil {
		if err := sink.Abort(ctx); err != nil {
			return coreknowledge.ErrCleanupPending
		}
	}
	r.mu.Lock()
	delete(r.sinks, u.ID)
	r.mu.Unlock()
	if _, err := r.store.pool.Exec(ctx, `DELETE FROM core_knowledge_cleanup WHERE source_id=$1 AND operation='upload_abort'`, u.SourceID); err != nil {
		return coreknowledge.ErrCleanupPending
	}
	return nil
}

func (r *CoreKnowledgeStore) CreateMemory(ctx context.Context, command coreknowledge.MemoryCommand) (coreknowledge.Source, error) {
	if err := command.ValidateForRepository(); err != nil {
		return coreknowledge.Source{}, err
	}
	digest := knowledgeDigest(command)
	tx, err := r.store.pool.Begin(ctx)
	if err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	defer tx.Rollback(ctx)
	if err = lockKnowledgeKey(ctx, tx, "memory", command.IdempotencyKey); err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	var replay knowledgeReplay
	if ok, replayErr := replayKnowledge(ctx, tx, "memory", command.IdempotencyKey, digest, &replay); ok {
		if replayErr == nil {
			_ = tx.Commit(ctx)
			return replay.Source, nil
		}
		return coreknowledge.Source{}, replayErr
	}
	sourceID := command.SourceID
	if sourceID == "" {
		sourceID = uuid.NewString()
	}
	contentDigest := digestBytesKnowledge([]byte(command.Content))
	if command.ContentSHA256 != "" && !strings.EqualFold(command.ContentSHA256, contentDigest) {
		return coreknowledge.Source{}, coreknowledge.ErrChecksumMismatch
	}
	metadata := coreknowledge.UploadMetadata{UploadID: uuid.NewString(), SourceID: sourceID, Title: command.Title, RelativePath: "", MediaType: command.MediaType, DeclaredSize: int64(len([]byte(command.Content))), ContentSHA256: contentDigest}
	sink, err := r.content.Begin(ctx, metadata)
	if err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	if n, e := io.WriteString(sink, command.Content); e != nil || n != len([]byte(command.Content)) {
		_ = sink.Abort(ctx)
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	ref, err := sink.Finalize(ctx, contentDigest, metadata.DeclaredSize)
	if err != nil {
		_ = sink.Abort(ctx)
		return coreknowledge.Source{}, coreknowledge.ErrChecksumMismatch
	}
	now := r.nowUTC()
	tagsJSON := []byte("[]")
	if command.Tags != nil {
		tagsJSON, _ = json.Marshal(command.Tags)
	}
	s := coreknowledge.Source{ID: sourceID, Kind: coreknowledge.SourceKindMemory, Status: coreknowledge.SourceStatusReady, Title: command.Title, Digest: contentDigest, SizeBytes: metadata.DeclaredSize, MediaType: command.MediaType, Revision: 1, CreatedAt: now, UpdatedAt: now, Tags: append([]string(nil), command.Tags...)}
	_, err = tx.Exec(ctx, `INSERT INTO core_knowledge_sources(source_id,kind,status,title,digest,size_bytes,media_type,revision,content_ref,tags_json,created_at,updated_at) VALUES($1,'memory','ready',$2,$3,$4,$5,1,$6,$7,$8,$8)`, s.ID, s.Title, s.Digest, s.SizeBytes, s.MediaType, ref.Ref, tagsJSON, now)
	if err == nil {
		err = putKnowledgeReplay(ctx, tx, "memory", command.IdempotencyKey, digest, knowledgeReplay{Source: s}, nil)
	}
	if err != nil {
		_ = r.content.Delete(ctx, ref)
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		_ = r.content.Delete(ctx, ref)
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	return s, nil
}

func (r *CoreKnowledgeStore) UpdateMemory(ctx context.Context, command coreknowledge.UpdateMemoryCommand) (coreknowledge.Source, error) {
	if err := command.ValidateForRepository(); err != nil {
		return coreknowledge.Source{}, err
	}
	digest := knowledgeDigest(command)
	tx, err := r.store.pool.Begin(ctx)
	if err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	defer tx.Rollback(ctx)
	if err = lockKnowledgeKey(ctx, tx, "memory.update", command.IdempotencyKey); err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	var replay knowledgeReplay
	if ok, replayErr := replayKnowledge(ctx, tx, "memory.update", command.IdempotencyKey, digest, &replay); ok {
		if replayErr == nil {
			_ = tx.Commit(ctx)
			return replay.Source, nil
		}
		return coreknowledge.Source{}, replayErr
	}
	s, err := scanKnowledgeSource(tx.QueryRow(ctx, knowledgeSourceSelect+` WHERE source_id=$1 FOR UPDATE`, command.SourceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return coreknowledge.Source{}, coreknowledge.ErrNotFound
	}
	if err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	if s.Kind != coreknowledge.SourceKindMemory || s.Status == coreknowledge.SourceStatusDeleted {
		return coreknowledge.Source{}, coreknowledge.ErrNotFound
	}
	if s.Revision != command.ExpectedRevision {
		return coreknowledge.Source{}, coreknowledge.ErrRevisionConflict
	}
	oldDigest, oldSize := s.Digest, s.SizeBytes
	contentDigest := digestBytesKnowledge([]byte(command.Content))
	if command.ContentSHA256 != "" && !strings.EqualFold(command.ContentSHA256, contentDigest) {
		return coreknowledge.Source{}, coreknowledge.ErrChecksumMismatch
	}
	var oldRef string
	if err := tx.QueryRow(ctx, `SELECT content_ref FROM core_knowledge_sources WHERE source_id=$1`, s.ID).Scan(&oldRef); err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	var pendingOperation string
	if err := tx.QueryRow(ctx, `SELECT operation FROM core_knowledge_cleanup WHERE source_id=$1`, s.ID).Scan(&pendingOperation); err == nil {
		return coreknowledge.Source{}, coreknowledge.ErrCleanupPending
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	metadata := coreknowledge.UploadMetadata{IdempotencyKey: command.IdempotencyKey, UploadID: uuid.NewSHA1(uuid.NameSpaceURL, []byte("dirextalk/memory/update/"+command.IdempotencyKey)).String(), SourceID: s.ID, Title: command.Title, MediaType: command.MediaType, DeclaredSize: int64(len([]byte(command.Content))), ContentSHA256: contentDigest}
	sink, err := r.content.Begin(ctx, metadata)
	if err != nil || sink == nil {
		if resumable, ok := r.content.(resumableContentPort); ok {
			sink, err = resumable.Resume(ctx, metadata, 0, 0)
		}
	}
	if err != nil || sink == nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	if sink.Size() != metadata.DeclaredSize {
		if n, writeErr := io.WriteString(sink, command.Content); writeErr != nil || n != len([]byte(command.Content)) {
			_ = sink.Abort(ctx)
			return coreknowledge.Source{}, coreknowledge.ErrConflict
		}
	}
	ref, err := sink.Finalize(ctx, contentDigest, metadata.DeclaredSize)
	if err != nil {
		_ = sink.Abort(ctx)
		return coreknowledge.Source{}, coreknowledge.ErrChecksumMismatch
	}
	now := r.nowUTC()
	s.Tags = append([]string(nil), command.Tags...)
	s.Title, s.Digest, s.SizeBytes, s.MediaType, s.Revision, s.UpdatedAt = command.Title, contentDigest, metadata.DeclaredSize, command.MediaType, s.Revision+1, now
	s.Status = coreknowledge.SourceStatusReady
	tagsJSON := []byte("[]")
	if command.Tags != nil {
		tagsJSON, _ = json.Marshal(command.Tags)
	}
	tag, updateErr := tx.Exec(ctx, `UPDATE core_knowledge_sources SET title=$2,digest=$3,size_bytes=$4,media_type=$5,revision=$6,content_ref=$7,tags_json=$8,status='ready',updated_at=$9,error_code='' WHERE source_id=$1 AND kind='memory' AND status IN ('ready','indexing') AND revision=$10`, s.ID, s.Title, s.Digest, s.SizeBytes, s.MediaType, s.Revision, ref.Ref, tagsJSON, now, command.ExpectedRevision)
	if updateErr != nil {
		err = updateErr
	} else if tag.RowsAffected() != 1 {
		_ = r.content.Delete(ctx, ref)
		return coreknowledge.Source{}, coreknowledge.ErrRevisionConflict
	}
	if err == nil {
		if oldRef != "" && oldRef != ref.Ref {
			_, err = tx.Exec(ctx, `INSERT INTO core_knowledge_cleanup(source_id,operation,idempotency_key,request_hash,content_ref,content_digest,content_size_bytes,relative_path,attempts,last_error,next_attempt_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,'',0,'',$8,$8)`, s.ID, knowledgeMemoryReplaceCleanup, uuid.MustParse(command.IdempotencyKey), digest, oldRef, oldDigest, oldSize, now)
		}
	}
	if err == nil {
		err = putKnowledgeReplay(ctx, tx, "memory.update", command.IdempotencyKey, digest, knowledgeReplay{Source: s}, nil)
	}
	if err != nil {
		_ = r.content.Delete(ctx, ref)
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		_ = r.content.Delete(ctx, ref)
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	// Old content is immutable and no longer referenced. Cleanup is deliberately
	// best effort after the durable replacement; the durable replacement intent
	// is retried by RecoverPendingCleanup if an object-store delete is
	// temporarily unavailable.
	if oldRef != "" && oldRef != ref.Ref {
		_ = r.resumeMemoryReplacementCleanup(ctx, s.ID)
	}
	return s, nil
}

func (r *CoreKnowledgeStore) loadUploadTx(ctx context.Context, tx pgx.Tx, id string, lock bool) (coreknowledge.Upload, error) {
	query := `SELECT upload_id,source_id,metadata_json,status,received_size,next_ordinal,revision,created_at,updated_at FROM core_knowledge_uploads WHERE upload_id=$1`
	if lock {
		query += ` FOR UPDATE`
	}
	var u coreknowledge.Upload
	var raw []byte
	var status string
	if err := tx.QueryRow(ctx, query, id).Scan(&u.ID, &u.SourceID, &raw, &status, &u.ReceivedSize, &u.NextChunk, &u.Revision, &u.CreatedAt, &u.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return u, coreknowledge.ErrNotFound
		}
		return u, coreknowledge.ErrConflict
	}
	if json.Unmarshal(raw, &u.Metadata) != nil {
		return u, coreknowledge.ErrConflict
	}
	u.Status = coreknowledge.SourceStatus(status)
	u.CreatedAt, u.UpdatedAt = u.CreatedAt.UTC(), u.UpdatedAt.UTC()
	u.Session = coreknowledge.UploadSession{UploadID: u.ID, SourceID: u.SourceID, ReceivedSize: u.ReceivedSize, NextOrdinal: u.NextChunk, Revision: u.Revision}
	return u, nil
}
