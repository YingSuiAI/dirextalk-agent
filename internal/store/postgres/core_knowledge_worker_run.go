package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge/semantic"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (w *knowledgeTaskWorker) run(ctx context.Context, task coretask.Task) coreruntime.ManagedOutcome {
	if ctx == nil || task.Spec.Kind != coretask.TaskKindKnowledgeIndex || task.Lease == nil {
		return coreruntime.ManagedOutcome{Err: coretask.ErrLeaseConflict, TerminalOwned: true}
	}
	p := task.Spec.Payload.KnowledgeIndex
	if p == nil || len(p.SourceIDs) == 0 {
		return coreruntime.ManagedOutcome{Err: coretask.ErrInvalid, TerminalOwned: true}
	}
	var generation string
	var jobID string
	var status string
	var profileRevision int64
	var configDigest string
	var jobProfileID string
	var jobSourcesRaw, jobRevisionsRaw []byte
	err := w.store.pool.QueryRow(ctx, `SELECT job_id::text,generation,status,profile_id::text,profile_revision,collection_config_digest,source_ids,expected_revisions FROM core_knowledge_index_jobs WHERE task_id=$1`, task.ID).Scan(&jobID, &generation, &status, &jobProfileID, &profileRevision, &configDigest, &jobSourcesRaw, &jobRevisionsRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return w.fail(ctx, task, "knowledge_job_not_found", "index job not found")
	}
	if err != nil {
		return coreruntime.ManagedOutcome{Err: err}
	}
	if status == "succeeded" {
		return coreruntime.ManagedOutcome{TerminalOwned: true}
	}
	if status == "canceled" || status == "failed" {
		return coreruntime.ManagedOutcome{Err: coretask.ErrConflict, TerminalOwned: true}
	}
	if configDigest != p.CollectionConfigDigest || profileRevision <= 0 {
		return w.fail(ctx, task, "knowledge_binding_stale", "index configuration changed")
	}
	var jobSources []string
	var jobRevisions []uint64
	if json.Unmarshal(jobSourcesRaw, &jobSources) != nil || json.Unmarshal(jobRevisionsRaw, &jobRevisions) != nil || jobProfileID != task.Spec.ModelProfileID || len(jobSources) != len(p.SourceIDs) || len(jobRevisions) != len(p.ExpectedSourceRevision) {
		return w.fail(ctx, task, "knowledge_binding_stale", "index job payload changed")
	}
	for i := range p.SourceIDs {
		if jobSources[i] != p.SourceIDs[i] || jobRevisions[i] != p.ExpectedSourceRevision[i] {
			return w.fail(ctx, task, "knowledge_binding_stale", "index job payload changed")
		}
	}
	var currentProfileRevision int64
	if err := w.store.pool.QueryRow(ctx, `SELECT revision FROM core_model_profiles WHERE profile_id=$1 AND deleted_at IS NULL`, task.Spec.ModelProfileID).Scan(&currentProfileRevision); err != nil || currentProfileRevision != profileRevision {
		return w.fail(ctx, task, "knowledge_profile_stale", "embedding profile changed")
	}
	if err := w.markRunning(ctx, task, jobID); err != nil {
		return coreruntime.ManagedOutcome{Err: err}
	}
	stage, ok := w.engineStore().(semantic.StagedVectorStore)
	if !ok {
		return w.fail(ctx, task, "semantic_staging_unavailable", "semantic backend does not support staging")
	}
	// Write the durable cleanup intent before the first external generation
	// mutation. A crash at any point below has a restart-visible compensator.
	if err := w.ensureStageTombstone(ctx, task.ID, generation); err != nil {
		return coreruntime.ManagedOutcome{Err: err}
	}
	if err := w.checkTaskFence(ctx, task); err != nil {
		return coreruntime.ManagedOutcome{Err: err, TerminalOwned: true}
	}
	if err := stage.EnsureGeneration(ctx, generation); err != nil {
		return w.fail(ctx, task, "semantic_stage_failed", "unable to create staging generation")
	}
	if err := w.checkTaskFence(ctx, task); err != nil {
		_ = stage.DeleteGeneration(context.Background(), generation)
		return coreruntime.ManagedOutcome{Err: err, TerminalOwned: true}
	}
	for n, sourceID := range p.SourceIDs {
		if err := ctx.Err(); err != nil {
			return coreruntime.ManagedOutcome{Err: err}
		}
		var kind, sourceStatus, rel, digest, media, contentRef string
		var revision, size int64
		var manifestRaw []byte
		var promoted int64
		err := w.store.pool.QueryRow(ctx, `SELECT kind,status,relative_path,digest,media_type,content_ref,revision,size_bytes,directory_manifest_json,promoted_revision FROM core_knowledge_sources WHERE source_id=$1`, sourceID).Scan(&kind, &sourceStatus, &rel, &digest, &media, &contentRef, &revision, &size, &manifestRaw, &promoted)
		if err != nil {
			return w.fail(ctx, task, "knowledge_source_missing", "source not found")
		}
		if sourceStatus != string(coreknowledge.SourceStatusIndexing) || revision != int64(p.ExpectedSourceRevision[n]) {
			return w.fail(ctx, task, "knowledge_source_stale", "source revision changed")
		}
		if n == 0 { /* first progress is emitted after the immutable fence checks */
		}
		if kind == string(coreknowledge.SourceKindMount) && len(manifestRaw) > 2 {
			var manifest coreknowledge.DirectoryManifest
			if json.Unmarshal(manifestRaw, &manifest) != nil {
				return w.fail(ctx, task, "knowledge_manifest_invalid", "invalid directory manifest")
			}
			verifier, vok := w.opener.(knowledgeManifestVerifier)
			if !vok || verifier == nil {
				return w.fail(ctx, task, "knowledge_filesystem_unavailable", "managed filesystem unavailable")
			}
			if err := verifier.VerifyManagedDirectoryManifest(ctx, manifest, coreknowledge.DirectoryManifestLimits{}); err != nil {
				return w.fail(ctx, task, "knowledge_source_stale", "directory changed during indexing")
			}
			for _, entry := range manifest.Entries {
				f, e := w.opener.OpenManaged(ctx, strings.TrimSuffix(manifest.Root, "/")+"/"+entry.Path)
				if e != nil {
					return w.fail(ctx, task, "knowledge_filesystem_unavailable", "unable to open mounted file")
				}
				dr := &digestReader{r: f, h: sha256.New(), max: entry.SizeBytes}
				if e = w.checkTaskFence(ctx, task); e == nil {
					e = w.engine.IndexIntoGeneration(ctx, generation, semantic.SourceDocument{ID: sourceID, Revision: revision, MediaType: entry.MediaType, Reader: dr, MaxBytes: entry.SizeBytes, ChunkPrefix: entry.Path})
				}
				if e == nil {
					e = w.checkTaskFence(ctx, task)
				}
				if e == nil {
					e = dr.digest(entry.Digest)
				}
				_ = f.Close()
				if e != nil {
					_ = stage.DeleteGeneration(context.Background(), generation)
					return w.fail(ctx, task, "knowledge_index_failed", "semantic indexing failed")
				}
			}
		} else {
			var f io.ReadCloser
			if contentRef != "" && w.content != nil {
				f, err = w.content.OpenContent(ctx, coreknowledge.ContentReference{Ref: contentRef, Digest: digest, SizeBytes: size})
			} else if kind == string(coreknowledge.SourceKindMount) && w.opener != nil {
				f, err = w.opener.OpenManaged(ctx, rel)
			} else {
				err = coreknowledge.ErrFilesystemUnavailable
			}
			if err != nil || f == nil {
				return w.fail(ctx, task, "knowledge_content_unavailable", "source content unavailable")
			}
			dr := &digestReader{r: f, h: sha256.New(), max: size}
			if err = w.checkTaskFence(ctx, task); err == nil {
				err = w.engine.IndexIntoGeneration(ctx, generation, semantic.SourceDocument{ID: sourceID, Revision: revision, MediaType: media, Reader: dr, MaxBytes: size})
			}
			if err == nil {
				err = w.checkTaskFence(ctx, task)
			}
			if err == nil && digest != "" {
				err = dr.digest(digest)
			}
			_ = f.Close()
			if err != nil {
				_ = stage.DeleteGeneration(context.Background(), generation)
				return w.fail(ctx, task, "knowledge_index_failed", "semantic indexing failed")
			}
		}
		pct := float64(n+1) * 100 / float64(len(p.SourceIDs))
		if err := w.progress(ctx, &task, fmt.Sprintf("indexed source %d/%d", n+1, len(p.SourceIDs)), pct); err != nil {
			return coreruntime.ManagedOutcome{Err: err}
		}
	}
	if err := stage.PromoteGeneration(ctx, generation, bindingsFromPayload(p, generation)); err != nil {
		return w.fail(ctx, task, "semantic_promote_failed", "semantic promotion failed")
	}
	if err := w.checkTaskFence(ctx, task); err != nil {
		_ = stage.DeleteGeneration(context.Background(), generation)
		return coreruntime.ManagedOutcome{Err: err, TerminalOwned: true}
	}
	if err := w.promote(ctx, task, jobID, generation, p.SourceIDs, p.ExpectedSourceRevision); err != nil {
		// Promotion to the vector backend precedes the durable source binding.
		// If the task fence was lost (notably cancel racing the final commit),
		// compensate both the externally promoted points and the stage. The
		// durable failure/cancel path retains cleanup intents for crash recovery.
		for i, sourceID := range p.SourceIDs {
			_ = stage.DeletePromotedGeneration(context.Background(), generation, sourceID, int64(p.ExpectedSourceRevision[i]))
		}
		_ = stage.DeleteGeneration(context.Background(), generation)
		return coreruntime.ManagedOutcome{Err: err}
	}
	_ = stage.DeleteGeneration(context.Background(), generation)
	_, _ = w.store.pool.Exec(context.Background(), `DELETE FROM core_knowledge_generation_cleanup WHERE source_id = ANY(SELECT jsonb_array_elements_text(source_ids)::uuid FROM core_knowledge_index_jobs WHERE task_id=$1) AND generation=$2 AND cleanup_kind='staging'`, task.ID, generation)
	return coreruntime.ManagedOutcome{Result: coretask.Result{Summary: "knowledge indexing complete"}, TerminalOwned: true}
}

func (w *knowledgeTaskWorker) ensureStageTombstone(ctx context.Context, taskID, generation string) error {
	_, err := w.store.pool.Exec(ctx, `INSERT INTO core_knowledge_generation_cleanup(source_id,generation,cleanup_kind,revision)
		SELECT x::uuid,$2,'staging',0 FROM core_knowledge_index_jobs j, jsonb_array_elements_text(j.source_ids) x
		WHERE j.task_id=$1 ON CONFLICT DO NOTHING`, taskID, generation)
	return err
}

// checkTaskFence is deliberately called immediately before and after every
// engine operation that can reach the staged backend. It does not erase the
// tombstone on failure; the sweeper remains the durable crash compensator.
func (w *knowledgeTaskWorker) checkTaskFence(ctx context.Context, task coretask.Task) error {
	var status, holder string
	var attempt, epoch int64
	var expiry time.Time
	err := w.store.pool.QueryRow(ctx, `SELECT status,lease_holder,attempt,lease_epoch,lease_expires_at FROM core_tasks WHERE task_id=$1`, task.ID).Scan(&status, &holder, &attempt, &epoch, &expiry)
	if err != nil || status != string(coretask.StatusRunning) || task.Lease == nil || holder != task.Lease.Holder || uint32(attempt) != task.Attempt || uint64(epoch) != task.LeaseEpoch || !expiry.After(time.Now().UTC()) {
		return coretask.ErrLeaseConflict
	}
	return nil
}

func (w *knowledgeTaskWorker) engineStore() semantic.VectorStore { return reflectStore(w.engine) }

func bindingsFromPayload(p *coretask.KnowledgeIndexTaskPayload, generation string) []semantic.Binding {
	out := make([]semantic.Binding, len(p.SourceIDs))
	for i, id := range p.SourceIDs {
		out[i] = semantic.Binding{SourceID: id, Revision: int64(p.ExpectedSourceRevision[i]), Generation: generation}
	}
	return out
}

func (w *knowledgeTaskWorker) markRunning(ctx context.Context, task coretask.Task, jobID string) error {
	tag, err := w.store.pool.Exec(ctx, `UPDATE core_knowledge_index_jobs SET status='running',updated_at=clock_timestamp() WHERE job_id=$1 AND task_id=$2 AND status IN ('queued','running')`, jobID, task.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return coretask.ErrConflict
	}
	return nil
}

func (w *knowledgeTaskWorker) progress(ctx context.Context, task *coretask.Task, message string, pct float64) error {
	f := coretask.Fence{TaskID: task.ID, Attempt: task.Attempt, LeaseEpoch: task.LeaseEpoch, ExpectedRevision: task.Revision}
	p := coretask.Progress{TaskID: task.ID, Attempt: task.Attempt, At: time.Now().UTC(), Status: coretask.StatusRunning, Phase: "indexing", Message: message, Percent: &pct}
	_, pr, err := NewCoreTaskStore(w.store).AppendProgress(ctx, coretask.ProgressCommand{Fence: f, Progress: p, ExpectedSequence: task.ProgressSequence})
	if err == nil {
		task.ProgressSequence = pr.Sequence
		task.Revision++
	}
	return err
}

func (w *knowledgeTaskWorker) promote(ctx context.Context, task coretask.Task, jobID, generation string, ids []string, revs []uint64) error {
	tx, err := w.store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	var status, holder string
	var attempt, epoch, revision, progressSeq int64
	var expires time.Time
	if err = tx.QueryRow(ctx, `SELECT status,lease_holder,attempt,lease_epoch,revision,progress_sequence,lease_expires_at FROM core_tasks WHERE task_id=$1 FOR UPDATE`, task.ID).Scan(&status, &holder, &attempt, &epoch, &revision, &progressSeq, &expires); err != nil {
		return err
	}
	if status != string(coretask.StatusRunning) || uint32(attempt) != task.Attempt || uint64(epoch) != task.LeaseEpoch || uint64(revision) != task.Revision || task.Lease == nil || holder != task.Lease.Holder || !expires.After(now) {
		return coretask.ErrLeaseConflict
	}
	var jobStatus, jobGeneration, jobProfileID string
	var jobProfileRevision int64
	var jobConfig string
	var jobTask string
	if err = tx.QueryRow(ctx, `SELECT task_id::text,status,generation,profile_id::text,profile_revision,collection_config_digest FROM core_knowledge_index_jobs WHERE job_id=$1 FOR UPDATE`, jobID).Scan(&jobTask, &jobStatus, &jobGeneration, &jobProfileID, &jobProfileRevision, &jobConfig); err != nil {
		return err
	}
	if jobTask != task.ID || jobGeneration != generation || (jobStatus != "queued" && jobStatus != "running") {
		return coretask.ErrConflict
	}
	var currentProfileRevision int64
	if err = tx.QueryRow(ctx, `SELECT revision FROM core_model_profiles WHERE profile_id=$1 AND deleted_at IS NULL`, jobProfileID).Scan(&currentProfileRevision); err != nil || currentProfileRevision != jobProfileRevision || jobConfig != task.Spec.Payload.KnowledgeIndex.CollectionConfigDigest || jobProfileID != task.Spec.ModelProfileID {
		return coretask.ErrRevisionConflict
	}
	for i, id := range ids {
		var srcStatus string
		var srcRev int64
		if err = tx.QueryRow(ctx, `SELECT status,revision FROM core_knowledge_sources WHERE source_id=$1 FOR UPDATE`, id).Scan(&srcStatus, &srcRev); err != nil {
			return err
		}
		if srcStatus != string(coreknowledge.SourceStatusIndexing) || srcRev != int64(revs[i]) {
			return coretask.ErrRevisionConflict
		}
		var oldGeneration string
		_ = tx.QueryRow(ctx, `SELECT promoted_generation FROM core_knowledge_sources WHERE source_id=$1`, id).Scan(&oldGeneration)
		if oldGeneration != "" && oldGeneration != generation {
			if _, e := tx.Exec(ctx, `INSERT INTO core_knowledge_generation_cleanup(source_id,generation) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, oldGeneration); e != nil {
				return e
			}
		}
		// The profile reference is swapped in the same transaction as the
		// source generation binding. A profile can therefore never drift while
		// a promoted vector remains queryable.
		if _, e := tx.Exec(ctx, `DELETE FROM core_model_profile_active_refs WHERE owner_kind='knowledge_generation' AND owner_id=$1`, id); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id) VALUES('knowledge_generation',$1,$2)`, id, jobProfileID); e != nil {
			return e
		}
		tag, e := tx.Exec(ctx, `UPDATE core_knowledge_sources SET status='ready',promoted_generation=$2,promoted_revision=$3,promoted_profile_id=$4,promoted_profile_revision=$5,promoted_collection_config_digest=$6,updated_at=$7 WHERE source_id=$1 AND status='indexing' AND revision=$3`, id, generation, revs[i], jobProfileID, jobProfileRevision, jobConfig, now)
		if e != nil {
			err = e
			return err
		}
		if tag.RowsAffected() != 1 {
			return coretask.ErrRevisionConflict
		}
	}
	result, _ := json.Marshal(coretask.Result{Summary: "knowledge indexing complete"})
	if _, err = tx.Exec(ctx, `UPDATE core_knowledge_index_jobs SET status='succeeded',updated_at=$2 WHERE job_id=$1`, jobID, now); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE core_tasks SET status='succeeded',result_json=$2,lease_holder='',lease_expires_at=NULL,revision=revision+1,progress_sequence=progress_sequence+1,updated_at=$3 WHERE task_id=$1 AND status='running' AND attempt=$4 AND lease_epoch=$5 AND revision=$6 AND lease_holder=$7 AND lease_expires_at>$3`, task.ID, result, now, task.Attempt, task.LeaseEpoch, task.Revision, task.Lease.Holder)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return coretask.ErrLeaseConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,result_json,occurred_at) VALUES($1,$2,$3,$4,'succeeded','completed','knowledge indexing complete',$5,$6)`, task.ID, progressSeq+1, uuid.New(), task.Attempt, result, now); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_task_runtime_concurrency SET running_count=GREATEST(0,running_count-1),revision=revision+1,updated_at=$1 WHERE singleton=true`, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (w *knowledgeTaskWorker) fail(ctx context.Context, task coretask.Task, code, summary string) coreruntime.ManagedOutcome {
	tx, err := w.store.pool.Begin(ctx)
	if err != nil {
		return coreruntime.ManagedOutcome{Err: err}
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	var status, holder string
	var attempt, epoch, revision, seq int64
	var expires time.Time
	if err = tx.QueryRow(ctx, `SELECT status,lease_holder,attempt,lease_epoch,revision,progress_sequence,lease_expires_at FROM core_tasks WHERE task_id=$1 FOR UPDATE`, task.ID).Scan(&status, &holder, &attempt, &epoch, &revision, &seq, &expires); err != nil {
		return coreruntime.ManagedOutcome{Err: err}
	}
	if status != string(coretask.StatusRunning) || uint32(attempt) != task.Attempt || uint64(epoch) != task.LeaseEpoch || uint64(revision) != task.Revision || task.Lease == nil || holder != task.Lease.Holder || !expires.After(now) {
		return coreruntime.ManagedOutcome{Err: coretask.ErrLeaseConflict}
	}
	if _, err = tx.Exec(ctx, `UPDATE core_knowledge_index_jobs SET status='failed',error_code=$2,error_summary=$3,updated_at=$4 WHERE task_id=$1 AND status IN ('queued','running')`, task.ID, code, summary, now); err != nil {
		return coreruntime.ManagedOutcome{Err: err}
	}
	_, _ = tx.Exec(ctx, `INSERT INTO core_knowledge_generation_cleanup(source_id,generation,cleanup_kind,revision) SELECT x::uuid,j.generation,'staging',0 FROM core_knowledge_index_jobs j, jsonb_array_elements_text(j.source_ids) x WHERE j.task_id=$1`, task.ID)
	if _, err = tx.Exec(ctx, `UPDATE core_knowledge_sources SET status='ready',error_code=$2,updated_at=$3 WHERE source_id IN (SELECT jsonb_array_elements_text(source_ids)::uuid FROM core_knowledge_index_jobs WHERE task_id=$1) AND status='indexing'`, task.ID, code, now); err != nil {
		return coreruntime.ManagedOutcome{Err: err}
	}
	tag, err := tx.Exec(ctx, `UPDATE core_tasks SET status='failed',failure_code=$2,failure_summary=$3,lease_holder='',lease_expires_at=NULL,revision=revision+1,progress_sequence=progress_sequence+1,updated_at=$4 WHERE task_id=$1 AND status='running' AND revision=$5 AND lease_epoch=$6 AND lease_holder=$7 AND lease_expires_at>$4`, task.ID, code, summary, now, task.Revision, task.LeaseEpoch, task.Lease.Holder)
	if err != nil {
		return coreruntime.ManagedOutcome{Err: err}
	}
	if tag.RowsAffected() != 1 {
		return coreruntime.ManagedOutcome{Err: coretask.ErrLeaseConflict}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,error_code,error_summary,occurred_at) VALUES($1,$2,$3,$4,'failed',$5,$6,$7)`, task.ID, seq+1, uuid.New(), task.Attempt, code, summary, now); err != nil {
		return coreruntime.ManagedOutcome{Err: err}
	}
	if _, err = tx.Exec(ctx, `UPDATE core_task_runtime_concurrency SET running_count=GREATEST(0,running_count-1),revision=revision+1,updated_at=$1 WHERE singleton=true`, now); err != nil {
		return coreruntime.ManagedOutcome{Err: err}
	}
	if err = tx.Commit(ctx); err != nil {
		return coreruntime.ManagedOutcome{Err: err}
	}
	return coreruntime.ManagedOutcome{Err: errors.New(summary), TerminalOwned: true}
}

// reflectStore is filled by the semantic engine's exported staging accessor.
func reflectStore(e *semantic.IndexEngine) semantic.VectorStore { return e.Store() }
