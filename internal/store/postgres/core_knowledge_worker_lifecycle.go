package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge/semantic"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/jackc/pgx/v5"
)

type KnowledgeContentOpener interface {
	OpenContent(context.Context, coreknowledge.ContentReference) (io.ReadCloser, error)
}
type knowledgeManifestVerifier interface {
	VerifyManagedDirectoryManifest(context.Context, coreknowledge.DirectoryManifest, coreknowledge.DirectoryManifestLimits) error
}
type digestReader struct {
	r   io.Reader
	h   hash.Hash
	n   int64
	max int64
}

func (d *digestReader) Read(p []byte) (int, error) {
	if d.n > d.max {
		return 0, coreknowledge.ErrLimitExceeded
	}
	if int64(len(p)) > d.max+1-d.n {
		p = p[:d.max+1-d.n]
	}
	n, e := d.r.Read(p)
	if n > 0 {
		_, _ = d.h.Write(p[:n])
		d.n += int64(n)
		if d.n > d.max {
			return n, coreknowledge.ErrLimitExceeded
		}
	}
	return n, e
}
func (d *digestReader) digest(expected string) error {
	if d.n != d.max || hex.EncodeToString(d.h.Sum(nil)) != expected {
		return coreknowledge.ErrChecksumMismatch
	}
	return nil
}

// NewKnowledgeTaskHandler returns a coreruntime-compatible handler. It owns
// terminal task transitions so the generic worker does not race a promotion.
func NewKnowledgeTaskHandler(store *Store, opener coreknowledge.ManagedFileOpener, content KnowledgeContentOpener, engine *semantic.IndexEngine) (coreruntime.TaskHandler, error) {
	if store == nil || engine == nil {
		return nil, errors.New("invalid knowledge handler dependencies")
	}
	return func(ctx context.Context, task coretask.Task) coreruntime.ManagedOutcome {
		w := &knowledgeTaskWorker{store: store, opener: opener, content: content, engine: engine}
		return w.run(ctx, task)
	}, nil
}

type knowledgeTaskWorker struct {
	store   *Store
	opener  coreknowledge.ManagedFileOpener
	content KnowledgeContentOpener
	engine  *semantic.IndexEngine
}

// SweepStaleKnowledgeStages is safe to run after restart. Terminal jobs never
// need their staging generation again; queued/running jobs are retained for
// replay by the task worker.
func SweepStaleKnowledgeStages(ctx context.Context, store *Store) error {
	if store == nil {
		return errors.New("nil postgres store")
	}
	_, err := store.pool.Exec(ctx, `DELETE FROM core_knowledge_index_stages WHERE job_id IN (SELECT job_id FROM core_knowledge_index_jobs WHERE status IN ('succeeded','failed','canceled'))`)
	return err
}

func SweepStaleKnowledgeStagesWithBackend(ctx context.Context, store *Store, backend semantic.StagedVectorStore) error {
	if store == nil || backend == nil {
		return errors.New("invalid stage sweep dependencies")
	}
	rows, err := store.pool.Query(ctx, `SELECT s.generation FROM core_knowledge_index_stages s JOIN core_knowledge_index_jobs j ON j.job_id=s.job_id WHERE j.status IN ('succeeded','failed','canceled')`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var generations []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return err
		}
		generations = append(generations, g)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, g := range generations {
		if err := backend.DeleteGeneration(ctx, g); err != nil {
			return err
		}
		if _, err := store.pool.Exec(ctx, `DELETE FROM core_knowledge_index_stages WHERE generation=$1`, g); err != nil {
			return err
		}
	}
	cleanupRows, err := store.pool.Query(ctx, `SELECT source_id::text,generation,cleanup_kind,revision,quiescent_after FROM core_knowledge_generation_cleanup`)
	if err != nil {
		return err
	}
	defer cleanupRows.Close()
	for cleanupRows.Next() {
		var source, g, kind string
		var revision int64
		var quiescentAfter *time.Time
		if err := cleanupRows.Scan(&source, &g, &kind, &revision, &quiescentAfter); err != nil {
			return err
		}
		retainTombstone := kind == "canceled_staging"
		if kind == "staging" {
			var jobStatus string
			err := store.pool.QueryRow(ctx, `SELECT status FROM core_knowledge_index_jobs WHERE generation=$1`, g).Scan(&jobStatus)
			if err == nil && (jobStatus == "queued" || jobStatus == "running") {
				continue
			}
			if err == nil && jobStatus == "canceled" {
				retainTombstone = true
			}
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		var cleanupErr error
		if kind == "promoted" {
			cleanupErr = backend.DeletePromotedGeneration(ctx, g, source, revision)
		} else {
			cleanupErr = backend.DeleteStagingGeneration(ctx, g)
		}
		if cleanupErr != nil {
			return cleanupErr
		}
		// Canceled stages have no portable vector absence readback. Retain the
		// tombstone even after a successful delete and replay it on every sweep;
		// this closes a late-upsert/crash window without trusting backend timing.
		if retainTombstone {
			if _, err := store.pool.Exec(ctx, `UPDATE core_knowledge_generation_cleanup SET last_delete_at=clock_timestamp() WHERE source_id=$1 AND generation=$2`, source, g); err != nil {
				return err
			}
			continue
		}
		if _, err := store.pool.Exec(ctx, `DELETE FROM core_knowledge_generation_cleanup WHERE source_id=$1 AND generation=$2`, source, g); err != nil {
			return err
		}
	}
	if err := cleanupRows.Err(); err != nil {
		return err
	}
	return nil
}

func CancelKnowledgeIndexTask(ctx context.Context, store *Store, taskID string) error {
	if store == nil || !coretask.ValidUUID(taskID) {
		return coretask.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	if err = cancelKnowledgeIndexTaskTx(ctx, tx, taskID, now); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_tasks SET status='canceled',failure_code='user_canceled',lease_holder='',lease_expires_at=NULL,revision=revision+1,progress_sequence=progress_sequence+1,updated_at=$2 WHERE task_id=$1 AND status IN ('queued','running')`, taskID, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// cancelKnowledgeIndexTaskTx records the knowledge-specific cancellation
// state in the caller's transaction. The generic task mutation owns the
// core_tasks terminal transition so idempotency, fencing, and event emission
// remain in one path for every task kind.
func cancelKnowledgeIndexTaskTx(ctx context.Context, tx pgx.Tx, taskID string, now time.Time) error {
	quiescentAfter := now
	if err := tx.QueryRow(ctx, `SELECT COALESCE(lease_expires_at,clock_timestamp()) FROM core_tasks WHERE task_id=$1 FOR UPDATE`, taskID).Scan(&quiescentAfter); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE core_knowledge_index_jobs SET status='canceled',error_code='user_canceled',updated_at=$2 WHERE task_id=$1 AND status IN ('queued','running')`, taskID, now); err != nil {
		return err
	}
	// Persist the tombstone before exposing cancellation. Recovery replays this
	// intent even if a blocked embedding call returns after the caller has
	// observed cancellation.
	if _, err := tx.Exec(ctx, `INSERT INTO core_knowledge_generation_cleanup(source_id,generation,cleanup_kind,revision,quiescent_after)
		SELECT x::uuid,j.generation,'canceled_staging',0,$2
		FROM core_knowledge_index_jobs j, jsonb_array_elements_text(j.source_ids) x
		WHERE j.task_id=$1
		ON CONFLICT(source_id,generation) DO UPDATE SET cleanup_kind='canceled_staging',quiescent_after=GREATEST(COALESCE(core_knowledge_generation_cleanup.quiescent_after,EXCLUDED.quiescent_after),EXCLUDED.quiescent_after)`, taskID, quiescentAfter); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE core_knowledge_sources SET status='ready',error_code='user_canceled',updated_at=$2 WHERE source_id IN (SELECT jsonb_array_elements_text(source_ids)::uuid FROM core_knowledge_index_jobs WHERE task_id=$1) AND status='indexing'`, taskID, now); err != nil {
		return err
	}
	return nil
}
