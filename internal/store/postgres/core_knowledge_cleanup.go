package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const knowledgeMemoryReplaceCleanup = "memory_replace"

func (r *CoreKnowledgeStore) Delete(ctx context.Context, command coreknowledge.DeleteCommand) (coreknowledge.Source, error) {
	if err := command.ValidateForRepository(); err != nil {
		return coreknowledge.Source{}, err
	}
	digest := knowledgeDigest(command)
	tx, err := r.store.pool.Begin(ctx)
	if err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	defer tx.Rollback(ctx)
	if err = lockKnowledgeKey(ctx, tx, "delete", command.IdempotencyKey); err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	var replay knowledgeReplay
	if ok, replayErr := replayKnowledge(ctx, tx, "delete", command.IdempotencyKey, digest, &replay); ok {
		if replayErr == nil && replay.Source.Status != coreknowledge.SourceStatusDeleting && replay.Source.Status != coreknowledge.SourceStatusCleanupPending {
			_ = tx.Commit(ctx)
			return replay.Source, nil
		}
		if replay.Source.Status == coreknowledge.SourceStatusDeleting || replay.Source.Status == coreknowledge.SourceStatusCleanupPending {
			_ = tx.Rollback(ctx)
			return r.resumeKnowledgeCleanup(ctx, command, replay.Source)
		}
		return replay.Source, replayErr
	}
	s, err := scanKnowledgeSource(tx.QueryRow(ctx, knowledgeSourceSelect+` WHERE source_id=$1 FOR UPDATE`, command.SourceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return coreknowledge.Source{}, coreknowledge.ErrNotFound
	}
	if err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	if command.Kind != "" && s.Kind != command.Kind {
		return coreknowledge.Source{}, coreknowledge.ErrNotFound
	}
	if s.Status == coreknowledge.SourceStatusDeleting || s.Status == coreknowledge.SourceStatusCleanupPending {
		_ = tx.Rollback(ctx)
		return r.resumeKnowledgeCleanup(ctx, command, s)
	}
	// A memory replacement reserves the single cleanup row for the old
	// immutable object. Resolve that intent before converting the source to a
	// delete, otherwise the delete finalization could discard the replacement
	// ledger while the old object is still consuming content quota.
	var pendingOperation string
	if err := tx.QueryRow(ctx, `SELECT operation FROM core_knowledge_cleanup WHERE source_id=$1`, s.ID).Scan(&pendingOperation); err == nil {
		if pendingOperation == knowledgeMemoryReplaceCleanup {
			_ = tx.Rollback(ctx)
			if cleanupErr := r.resumeMemoryReplacementCleanup(ctx, s.ID); cleanupErr != nil {
				return s, coreknowledge.ErrCleanupPending
			}
			return r.Delete(ctx, command)
		}
		if pendingOperation != "delete" {
			return coreknowledge.Source{}, coreknowledge.ErrCleanupPending
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	if s.Revision != command.ExpectedRevision || s.Status == coreknowledge.SourceStatusDeleted {
		return coreknowledge.Source{}, coreknowledge.ErrRevisionConflict
	}
	// A source remains materially reachable while any non-deleted Task or its
	// immutable execution snapshot selects it, including terminal tasks. The
	// descriptor is released only when the owning Task is deleted.
	var inUse bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM core_tasks t
		LEFT JOIN core_task_execution_snapshots x ON x.task_id=t.task_id
		WHERE t.deleted_at IS NULL AND (
			t.knowledge_refs @> jsonb_build_array($1::text) OR
			t.attachment_refs @> jsonb_build_array($1::text) OR
			EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(x.snapshot_json->'knowledge','[]'::jsonb)) item WHERE item->>'source_id'=$1) OR
			EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(x.snapshot_json->'attachments','[]'::jsonb)) item WHERE item->>'id'=$1)
		)
	)`, s.ID).Scan(&inUse); err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	if inUse {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	var contentRef string
	if err = tx.QueryRow(ctx, `SELECT content_ref FROM core_knowledge_sources WHERE source_id=$1`, s.ID).Scan(&contentRef); err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	var promotedGeneration string
	var promotedRevision int64
	_ = tx.QueryRow(ctx, `SELECT promoted_generation,promoted_revision FROM core_knowledge_sources WHERE source_id=$1`, s.ID).Scan(&promotedGeneration, &promotedRevision)
	if promotedGeneration != "" && promotedRevision > 0 {
		if _, err = tx.Exec(ctx, `INSERT INTO core_knowledge_generation_cleanup(source_id,generation,cleanup_kind,revision) VALUES($1,$2,'promoted',$3) ON CONFLICT DO NOTHING`, s.ID, promotedGeneration, promotedRevision); err != nil {
			return coreknowledge.Source{}, coreknowledge.ErrConflict
		}
	}
	var token coreknowledge.DeleteFenceToken
	fenceCommitted := false
	defer func() {
		if r.fence != nil && token.Token != "" && !fenceCommitted {
			_ = r.fence.ReleaseDeleteFence(context.Background(), token)
		}
	}()
	if r.fence != nil {
		token, err = r.fence.AcquireDeleteFence(ctx, s.ID)
		if err != nil {
			return coreknowledge.Source{}, coreknowledge.ErrConflict
		}
	}
	transition := func() error {
		now := r.nowUTC()
		s.Status = coreknowledge.SourceStatusDeleting
		s.Revision++
		s.UpdatedAt = now
		_, e := tx.Exec(ctx, `UPDATE core_knowledge_sources SET status='deleting',revision=$2,updated_at=$3 WHERE source_id=$1 AND revision=$4`, s.ID, s.Revision, s.UpdatedAt, command.ExpectedRevision)
		if e != nil {
			return e
		}
		return nil
	}
	if r.fence != nil {
		err = r.fence.ConsumeDelete(ctx, token, s.ID, command.ExpectedRevision, transition)
	} else {
		err = transition()
	}
	if err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrRevisionConflict
	}
	// Persist cleanup intent and replay atomically with the deleting transition;
	// external cleanup starts only after this durable commit.
	if _, err = tx.Exec(ctx, `INSERT INTO core_knowledge_cleanup(source_id,operation,idempotency_key,request_hash,content_ref,relative_path,attempts,last_error,next_attempt_at,updated_at) VALUES($1,'delete',$2,$3,$4,$5,0,'',$6,$6) ON CONFLICT(source_id) DO NOTHING`, s.ID, uuid.MustParse(command.IdempotencyKey), digest, contentRef, s.RelativePath, r.nowUTC()); err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	if err = putKnowledgeReplay(ctx, tx, "delete", command.IdempotencyKey, digest, knowledgeReplay{Source: s}, coreknowledge.ErrCleanupPending); err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	fenceCommitted = true
	if r.fence != nil {
		_ = r.fence.ReleaseDeleteFence(ctx, token)
	}
	cleanupErr := error(nil)
	if s.Kind == coreknowledge.SourceKindMount {
		if r.deleter != nil && s.RelativePath != "" {
			cleanupErr = r.deleter.Delete(ctx, s.RelativePath)
		}
	} else if contentRef != "" {
		cleanupErr = r.content.Delete(ctx, coreknowledge.ContentReference{Ref: contentRef, Digest: s.Digest, SizeBytes: s.SizeBytes})
	}
	tx2, e := r.store.pool.Begin(ctx)
	if e != nil {
		return s, coreknowledge.ErrCleanupPending
	}
	defer tx2.Rollback(ctx)
	if cleanupErr != nil {
		now := r.nowUTC()
		s.Status = coreknowledge.SourceStatusCleanupPending
		s.Revision++
		s.UpdatedAt = now
		s.ErrorCode = "cleanup_pending"
		_, _ = tx2.Exec(ctx, `UPDATE core_knowledge_sources SET status='cleanup_pending',revision=$2,updated_at=$3,error_code=$4 WHERE source_id=$1`, s.ID, s.Revision, now, s.ErrorCode)
		_, _ = tx2.Exec(ctx, `INSERT INTO core_knowledge_cleanup(source_id,operation,idempotency_key,request_hash,content_ref,relative_path,attempts,last_error,next_attempt_at,updated_at) VALUES($1,'delete',$2,$3,$4,$5,1,$6,$7,$7) ON CONFLICT(source_id) DO UPDATE SET attempts=core_knowledge_cleanup.attempts+1,last_error=EXCLUDED.last_error,next_attempt_at=EXCLUDED.next_attempt_at,updated_at=EXCLUDED.updated_at`, s.ID, uuid.MustParse(command.IdempotencyKey), digest, contentRef, s.RelativePath, cleanupErr.Error(), r.nowUTC())
		_ = updateKnowledgeReplayHash(ctx, tx2, "delete", command.IdempotencyKey, digest, knowledgeReplay{Source: s}, coreknowledge.ErrCleanupPending)
		_ = tx2.Commit(ctx)
		return s, coreknowledge.ErrCleanupPending
	}
	now := r.nowUTC()
	s.Status = coreknowledge.SourceStatusDeleted
	s.Revision++
	s.UpdatedAt = now
	s.ErrorCode = ""
	_, e = tx2.Exec(ctx, `UPDATE core_knowledge_sources SET status='deleted',revision=$2,updated_at=$3,error_code='' WHERE source_id=$1`, s.ID, s.Revision, now)
	if e == nil {
		_, e = tx2.Exec(ctx, `DELETE FROM core_knowledge_cleanup WHERE source_id=$1`, s.ID)
	}
	if e == nil {
		_, e = tx2.Exec(ctx, `DELETE FROM core_model_profile_active_refs WHERE owner_kind='knowledge_generation' AND owner_id=$1`, s.ID)
	}
	if e == nil {
		e = updateKnowledgeReplayHash(ctx, tx2, "delete", command.IdempotencyKey, digest, knowledgeReplay{Source: s}, nil)
	}
	if e != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	if e = tx2.Commit(ctx); e != nil {
		return coreknowledge.Source{}, coreknowledge.ErrConflict
	}
	return s, nil
}

// resumeKnowledgeCleanup replays the durable cleanup intent after a process
// restart or an ambiguous Delete response. Finalization is a CAS on the
// deleting/cleanup_pending row and therefore safe to retry.
func (r *CoreKnowledgeStore) resumeKnowledgeCleanup(ctx context.Context, command coreknowledge.DeleteCommand, hinted coreknowledge.Source) (coreknowledge.Source, error) {
	var contentRef, relativePath, requestHash string
	var replayKey *uuid.UUID
	if err := r.store.pool.QueryRow(ctx, `SELECT content_ref,relative_path,idempotency_key,request_hash FROM core_knowledge_cleanup WHERE source_id=$1`, hinted.ID).Scan(&contentRef, &relativePath, &replayKey, &requestHash); err != nil {
		if errors.Is(err, pgx.ErrNoRows) && hinted.Status == coreknowledge.SourceStatusDeleted {
			return hinted, nil
		}
		return hinted, coreknowledge.ErrCleanupPending
	}
	var cleanupErr error
	if hinted.Kind == coreknowledge.SourceKindMount {
		if r.deleter != nil && relativePath != "" {
			cleanupErr = r.deleter.Delete(ctx, relativePath)
		}
	} else if contentRef != "" {
		cleanupErr = r.content.Delete(ctx, coreknowledge.ContentReference{Ref: contentRef, Digest: hinted.Digest, SizeBytes: hinted.SizeBytes})
	}
	tx, err := r.store.pool.Begin(ctx)
	if err != nil {
		return hinted, coreknowledge.ErrCleanupPending
	}
	defer tx.Rollback(ctx)
	current, err := scanKnowledgeSource(tx.QueryRow(ctx, knowledgeSourceSelect+` WHERE source_id=$1 FOR UPDATE`, hinted.ID))
	if err != nil {
		return hinted, coreknowledge.ErrCleanupPending
	}
	if cleanupErr != nil {
		now := r.nowUTC()
		current.Status, current.ErrorCode, current.Revision, current.UpdatedAt = coreknowledge.SourceStatusCleanupPending, "cleanup_pending", current.Revision+1, now
		var tag pgconn.CommandTag
		if tag, err = tx.Exec(ctx, `UPDATE core_knowledge_sources SET status='cleanup_pending',revision=$2,updated_at=$3,error_code=$4 WHERE source_id=$1 AND status IN ('deleting','cleanup_pending')`, current.ID, current.Revision, now, current.ErrorCode); err == nil && tag.RowsAffected() == 1 {
			_, err = tx.Exec(ctx, `UPDATE core_knowledge_cleanup SET attempts=attempts+1,last_error=$2,next_attempt_at=$3,updated_at=$3 WHERE source_id=$1`, current.ID, cleanupErr.Error(), now)
		} else if err == nil {
			return r.reloadCanonicalCleanup(ctx, current.ID)
		}
		if err == nil && replayKey != nil && requestHash != "" {
			err = updateKnowledgeReplayHash(ctx, tx, "delete", replayKey.String(), requestHash, knowledgeReplay{Source: current}, coreknowledge.ErrCleanupPending)
		}
		if err == nil {
			err = tx.Commit(ctx)
		}
		return current, coreknowledge.ErrCleanupPending
	}
	now := r.nowUTC()
	current.Status, current.ErrorCode, current.Revision, current.UpdatedAt = coreknowledge.SourceStatusDeleted, "", current.Revision+1, now
	var tag pgconn.CommandTag
	if tag, err = tx.Exec(ctx, `UPDATE core_knowledge_sources SET status='deleted',revision=$2,updated_at=$3,error_code='' WHERE source_id=$1 AND status IN ('deleting','cleanup_pending')`, current.ID, current.Revision, now); err == nil && tag.RowsAffected() == 1 {
		_, err = tx.Exec(ctx, `DELETE FROM core_knowledge_cleanup WHERE source_id=$1`, current.ID)
		if err == nil {
			_, err = tx.Exec(ctx, `DELETE FROM core_model_profile_active_refs WHERE owner_kind='knowledge_generation' AND owner_id=$1`, current.ID)
		}
	} else if err == nil {
		return r.reloadCanonicalCleanup(ctx, current.ID)
	}
	if err == nil && replayKey != nil && requestHash != "" {
		err = updateKnowledgeReplayHash(ctx, tx, "delete", replayKey.String(), requestHash, knowledgeReplay{Source: current}, nil)
	}
	if err != nil || tx.Commit(ctx) != nil {
		return current, coreknowledge.ErrCleanupPending
	}
	return current, nil
}

func (r *CoreKnowledgeStore) reloadCanonicalCleanup(ctx context.Context, sourceID string) (coreknowledge.Source, error) {
	canonical, err := scanKnowledgeSource(r.store.pool.QueryRow(ctx, knowledgeSourceSelect+` WHERE source_id=$1`, sourceID))
	if err != nil {
		return coreknowledge.Source{}, coreknowledge.ErrCleanupPending
	}
	if canonical.Status == coreknowledge.SourceStatusDeleted {
		return canonical, nil
	}
	return canonical, coreknowledge.ErrCleanupPending
}

// RecoverPendingCleanup replays every due cleanup intent. It is safe to call
// at startup and after any crash window between external cleanup and CAS.
func (r *CoreKnowledgeStore) RecoverPendingCleanup(ctx context.Context) error {
	rows, err := r.store.pool.Query(ctx, `SELECT s.source_id,c.idempotency_key FROM core_knowledge_sources s JOIN core_knowledge_cleanup c ON c.source_id=s.source_id WHERE c.operation='delete' AND s.status IN ('deleting','cleanup_pending') AND c.next_attempt_at<=clock_timestamp() ORDER BY c.next_attempt_at,s.source_id`)
	if err != nil {
		return coreknowledge.ErrConflict
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var replayKey *uuid.UUID
		if err := rows.Scan(&id, &replayKey); err != nil {
			return coreknowledge.ErrConflict
		}
		s, err := r.Get(ctx, id)
		if err != nil {
			continue
		}
		command := coreknowledge.DeleteCommand{SourceID: id}
		if replayKey != nil {
			command.IdempotencyKey = replayKey.String()
		}
		_, _ = r.resumeKnowledgeCleanup(ctx, command, s)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	memoryRows, err := r.store.pool.Query(ctx, `SELECT s.source_id FROM core_knowledge_sources s JOIN core_knowledge_cleanup c ON c.source_id=s.source_id WHERE c.operation=$1 AND s.status='ready' AND c.next_attempt_at<=clock_timestamp() ORDER BY c.next_attempt_at,s.source_id`, knowledgeMemoryReplaceCleanup)
	if err != nil {
		return coreknowledge.ErrConflict
	}
	for memoryRows.Next() {
		var sourceID string
		if err := memoryRows.Scan(&sourceID); err != nil {
			memoryRows.Close()
			return coreknowledge.ErrConflict
		}
		_ = r.resumeMemoryReplacementCleanup(ctx, sourceID)
	}
	if err := memoryRows.Err(); err != nil {
		memoryRows.Close()
		return coreknowledge.ErrConflict
	}
	memoryRows.Close()
	urows, err := r.store.pool.Query(ctx, `SELECT u.upload_id,u.source_id,u.metadata_json,u.status,u.received_size,u.next_ordinal,u.revision,u.created_at,u.updated_at FROM core_knowledge_uploads u JOIN core_knowledge_cleanup c ON c.source_id=u.source_id WHERE c.operation='upload_abort' AND c.next_attempt_at<=clock_timestamp() ORDER BY c.next_attempt_at,u.upload_id`)
	if err != nil {
		return coreknowledge.ErrConflict
	}
	defer urows.Close()
	for urows.Next() {
		var u coreknowledge.Upload
		var raw []byte
		var status string
		if err := urows.Scan(&u.ID, &u.SourceID, &raw, &status, &u.ReceivedSize, &u.NextChunk, &u.Revision, &u.CreatedAt, &u.UpdatedAt); err != nil || json.Unmarshal(raw, &u.Metadata) != nil {
			continue
		}
		u.Status = coreknowledge.SourceStatus(status)
		_ = r.cleanupAbortedUpload(ctx, u)
	}
	return urows.Err()
}

// resumeMemoryReplacementCleanup retries deletion of an immutable object that
// was replaced by a committed memory update. The metadata transaction never
// waits for this external side effect; the cleanup ledger is the durable
// retry boundary used by startup recovery and the periodic sweep.
func (r *CoreKnowledgeStore) resumeMemoryReplacementCleanup(ctx context.Context, sourceID string) error {
	if r == nil || r.store == nil || r.content == nil || strings.TrimSpace(sourceID) == "" {
		return coreknowledge.ErrInvalid
	}
	var contentRef, contentDigest string
	var contentSize int64
	if err := r.store.pool.QueryRow(ctx, `SELECT content_ref,content_digest,content_size_bytes FROM core_knowledge_cleanup WHERE source_id=$1 AND operation=$2`, sourceID, knowledgeMemoryReplaceCleanup).Scan(&contentRef, &contentDigest, &contentSize); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return coreknowledge.ErrCleanupPending
	}
	cleanupErr := r.content.Delete(ctx, coreknowledge.ContentReference{Ref: contentRef, Digest: contentDigest, SizeBytes: contentSize})
	if errors.Is(cleanupErr, coreknowledge.ErrNotFound) {
		cleanupErr = nil
	}
	tx, err := r.store.pool.Begin(ctx)
	if err != nil {
		return coreknowledge.ErrCleanupPending
	}
	defer tx.Rollback(ctx)
	if err := lockKnowledgeKey(ctx, tx, "memory.cleanup", sourceID); err != nil {
		return coreknowledge.ErrCleanupPending
	}
	if cleanupErr != nil {
		now := r.nowUTC()
		message := cleanupErr.Error()
		if len(message) > 4096 {
			message = message[:4096]
		}
		tag, updateErr := tx.Exec(ctx, `UPDATE core_knowledge_cleanup SET attempts=attempts+1,last_error=$2,next_attempt_at=$3,updated_at=$3 WHERE source_id=$1 AND operation=$4 AND content_ref=$5`, sourceID, message, now, knowledgeMemoryReplaceCleanup, contentRef)
		if updateErr != nil {
			return coreknowledge.ErrCleanupPending
		}
		if err := tx.Commit(ctx); err != nil {
			return coreknowledge.ErrCleanupPending
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		return coreknowledge.ErrCleanupPending
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core_knowledge_cleanup WHERE source_id=$1 AND operation=$2 AND content_ref=$3`, sourceID, knowledgeMemoryReplaceCleanup, contentRef); err != nil {
		return coreknowledge.ErrCleanupPending
	}
	if err := tx.Commit(ctx); err != nil {
		return coreknowledge.ErrCleanupPending
	}
	return nil
}

func (r *CoreKnowledgeStore) Status(ctx context.Context) (coreknowledge.Status, error) {
	var out coreknowledge.Status
	rows, err := r.store.pool.Query(ctx, `SELECT status,count(*) FROM core_knowledge_sources GROUP BY status`)
	if err != nil {
		return out, coreknowledge.ErrConflict
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		var n int
		_ = rows.Scan(&st, &n)
		switch coreknowledge.SourceStatus(st) {
		case coreknowledge.SourceStatusReady:
			out.ReadyCount = n
		case coreknowledge.SourceStatusUploading:
			out.UploadingCount = n
		case coreknowledge.SourceStatusIndexing:
			out.IndexingCount = n
		case coreknowledge.SourceStatusFailed:
			out.FailedCount = n
		case coreknowledge.SourceStatusCleanupPending:
			out.CleanupPendingCount = n
		}
	}
	if err = rows.Err(); err != nil {
		return out, coreknowledge.ErrConflict
	}
	out.CheckedAt = r.nowUTC()
	return out, nil
}

// EmbeddingStatus reports only promoted generations at the exact current
// source revision. Ready rows without a matching promotion remain stale;
// this projection is intentionally separate from Status so ordinary source
// readiness can never be mistaken for searchable vectors.
func (r *CoreKnowledgeStore) EmbeddingStatus(ctx context.Context) (indexed, stale int, err error) {
	if r == nil || r.store == nil || r.store.pool == nil {
		return 0, 0, coreknowledge.ErrConflict
	}
	binding, err := r.currentKnowledgeEmbeddingBinding(ctx)
	if err != nil {
		return 0, 0, err
	}
	if err = r.store.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status='ready' AND promoted_revision=revision AND revision>0 AND promoted_profile_id=$1::uuid AND promoted_profile_revision=$2 AND promoted_collection_config_digest=$3), count(*) FILTER (WHERE status='ready' AND (promoted_revision=revision AND revision>0 AND promoted_profile_id=$1::uuid AND promoted_profile_revision=$2 AND promoted_collection_config_digest=$3) IS NOT TRUE) FROM core_knowledge_sources`, binding.profileID, binding.profileRevision, binding.collectionDigest).Scan(&indexed, &stale); err != nil {
		return 0, 0, coreknowledge.ErrConflict
	}
	return indexed, stale, nil
}
