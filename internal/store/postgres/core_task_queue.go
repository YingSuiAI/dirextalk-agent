package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ClaimNextDue atomically dequeues FIFO work, reclaims expired leases, and
// converges overdue waiting-user tasks before they can reach a provider.
func (s *CoreTaskStore) ClaimNextDue(ctx context.Context, holder string, at time.Time, ttl time.Duration, max int) (coretask.Task, coretask.Lease, error) {
	if holder == "" || ttl <= 0 || max <= 0 || at.IsZero() {
		return coretask.Task{}, coretask.Lease{}, coretask.ErrInvalid
	}
	tx, e := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return coretask.Task{}, coretask.Lease{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `INSERT INTO core_task_runtime_concurrency(singleton,max_concurrent) VALUES(true,$1) ON CONFLICT(singleton) DO UPDATE SET max_concurrent=EXCLUDED.max_concurrent`, max); e != nil {
		return coretask.Task{}, coretask.Lease{}, e
	}
	var running int
	if e = tx.QueryRow(ctx, `SELECT running_count FROM core_task_runtime_concurrency WHERE singleton=true FOR UPDATE`).Scan(&running); e != nil {
		return coretask.Task{}, coretask.Lease{}, e
	}
	var id string
	e = tx.QueryRow(ctx, `SELECT task_id FROM core_tasks WHERE deleted_at IS NULL AND ((status='running' AND lease_expires_at <= $1) OR (status='queued' AND available_at <= $1) OR (status='waiting_user' AND execution_deadline_at IS NOT NULL AND execution_deadline_at <= $1)) ORDER BY CASE WHEN status='running' THEN 0 WHEN status='waiting_user' THEN 1 ELSE 2 END, available_at,created_at,task_id FOR UPDATE SKIP LOCKED LIMIT 1`, at.UTC()).Scan(&id)
	if errors.Is(e, pgx.ErrNoRows) {
		return coretask.Task{}, coretask.Lease{}, coretask.ErrNotFound
	}
	if e != nil {
		return coretask.Task{}, coretask.Lease{}, e
	}
	t, e := s.taskTx(ctx, tx, id, false)
	if e != nil {
		return coretask.Task{}, coretask.Lease{}, e
	}
	if t.Status == coretask.StatusQueued && running >= max {
		return coretask.Task{}, coretask.Lease{}, coretask.ErrNotFound
	}
	if t.ExecutionDeadlineAt != nil && !at.UTC().Before(*t.ExecutionDeadlineAt) {
		if _, e = tx.Exec(ctx, `UPDATE core_tasks SET status='failed',attempt=GREATEST(attempt,1),failure_code='task_timed_out',failure_summary='task timed out',lease_holder='',lease_expires_at=NULL,revision=revision+1,updated_at=$2 WHERE task_id=$1`, id, at.UTC()); e != nil {
			return coretask.Task{}, coretask.Lease{}, e
		}
		if e = terminalizeConfirmationForTaskTx(ctx, tx, id, "task_timed_out", at.UTC()); e != nil {
			return coretask.Task{}, coretask.Lease{}, e
		}
		if t.Status == coretask.StatusRunning {
			if _, e = tx.Exec(ctx, `UPDATE core_task_runtime_concurrency SET running_count=GREATEST(0,running_count-1),revision=revision+1,updated_at=$1 WHERE singleton=true`, at.UTC()); e != nil {
				return coretask.Task{}, coretask.Lease{}, e
			}
		}
		if _, e = tx.Exec(ctx, `UPDATE core_tasks SET progress_sequence=progress_sequence+1 WHERE task_id=$1`, id); e != nil {
			return coretask.Task{}, coretask.Lease{}, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,error_code,error_summary,occurred_at) SELECT task_id,progress_sequence,$2,attempt,'failed','task_timed_out','task timed out',$3 FROM core_tasks WHERE task_id=$1`, id, uuid.New(), at.UTC()); e != nil {
			return coretask.Task{}, coretask.Lease{}, e
		}
		if e = tx.Commit(ctx); e != nil {
			return coretask.Task{}, coretask.Lease{}, e
		}
		return coretask.Task{}, coretask.Lease{}, coretask.ErrNotFound
	}
	epoch := t.LeaseEpoch + 1
	attempt := t.Attempt
	if attempt == 0 {
		attempt = 1
	}
	expires := at.UTC().Add(ttl)
	if t.Status == coretask.StatusQueued {
		if _, e = tx.Exec(ctx, `UPDATE core_task_runtime_concurrency SET running_count=running_count+1,revision=revision+1,updated_at=$1 WHERE singleton=true`, at.UTC()); e != nil {
			return coretask.Task{}, coretask.Lease{}, e
		}
	}
	if _, e = tx.Exec(ctx, `UPDATE core_tasks SET status='running',attempt=$2,lease_epoch=$3,lease_holder=$4,lease_expires_at=$5,execution_started_at=CASE WHEN timeout_seconds=0 THEN NULL ELSE COALESCE(execution_started_at,$6) END,execution_deadline_at=CASE WHEN timeout_seconds=0 THEN NULL ELSE COALESCE(execution_deadline_at,$6 + make_interval(secs => timeout_seconds)) END,revision=revision+1,updated_at=$6 WHERE task_id=$1`, id, attempt, epoch, holder, expires, at.UTC()); e != nil {
		return coretask.Task{}, coretask.Lease{}, e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) SELECT task_id,progress_sequence+1,$2,attempt,'running','claimed','task claimed',$3 FROM core_tasks WHERE task_id=$1`, id, uuid.New(), at.UTC()); e != nil {
		return coretask.Task{}, coretask.Lease{}, e
	}
	if _, e = tx.Exec(ctx, `UPDATE core_tasks SET progress_sequence=progress_sequence+1 WHERE task_id=$1`, id); e != nil {
		return coretask.Task{}, coretask.Lease{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return coretask.Task{}, coretask.Lease{}, e
	}
	t, e = s.GetTask(ctx, id)
	if e != nil {
		return t, coretask.Lease{}, e
	}
	return t, *t.Lease, nil
}

func (s *CoreTaskStore) RenewLease(ctx context.Context, c coretask.RenewLeaseCommand) (coretask.Lease, error) {
	if c.LeaseTTL <= 0 || c.At.IsZero() {
		return coretask.Lease{}, coretask.ErrInvalid
	}
	expires := c.At.UTC().Add(c.LeaseTTL)
	tag, e := s.store.pool.Exec(ctx, `UPDATE core_tasks SET lease_expires_at=$1,updated_at=$2 WHERE task_id=$3 AND status='running' AND attempt=$4 AND lease_epoch=$5 AND lease_holder=$6 AND lease_expires_at>$2`, expires, c.At.UTC(), c.TaskID, c.Attempt, c.LeaseEpoch, c.Holder)
	if e != nil {
		return coretask.Lease{}, e
	}
	if tag.RowsAffected() != 1 {
		return coretask.Lease{}, coretask.ErrLeaseConflict
	}
	return coretask.Lease{TaskID: c.TaskID, Attempt: c.Attempt, Epoch: c.LeaseEpoch, Holder: c.Holder, ExpiresAt: expires}, nil
}

func (s *CoreTaskStore) CompleteTask(ctx context.Context, c coretask.CompleteCommand) (coretask.Task, error) {
	if c.Result.Validate() != nil {
		return coretask.Task{}, coretask.ErrInvalid
	}
	raw, _ := json.Marshal(c.Result)
	return s.coreTerminal(ctx, c.Fence, c.At, "succeeded", raw, "", "")
}
func (s *CoreTaskStore) FailTask(ctx context.Context, c coretask.FailCommand) error {
	_, e := s.coreTerminal(ctx, c.Fence, c.At, "failed", nil, c.ErrorCode, c.ErrorSummary)
	return e
}
func (s *CoreTaskStore) TimeoutTask(ctx context.Context, c coretask.TimeoutCommand) error {
	_, e := s.coreTerminal(ctx, c.Fence, c.At, "failed", nil, "task_timed_out", "task timed out")
	return e
}
func (s *CoreTaskStore) coreTerminal(ctx context.Context, f coretask.Fence, at time.Time, status string, result []byte, code, summary string) (coretask.Task, error) {
	tx, e := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return coretask.Task{}, e
	}
	defer tx.Rollback(ctx)
	tag, e := tx.Exec(ctx, `UPDATE core_tasks SET status=$1,result_json=$2,failure_code=$3,failure_summary=$4,lease_holder='',lease_expires_at=NULL,revision=revision+1,updated_at=$5 WHERE task_id=$6 AND status='running' AND attempt=$7 AND lease_epoch=$8 AND revision=$9 AND lease_expires_at>$5`, status, result, code, summary, at.UTC(), f.TaskID, f.Attempt, f.LeaseEpoch, f.ExpectedRevision)
	if e != nil {
		return coretask.Task{}, e
	}
	if tag.RowsAffected() != 1 {
		return coretask.Task{}, coretask.ErrLeaseConflict
	}
	if code == "task_timed_out" {
		if e = terminalizeConfirmationForTaskTx(ctx, tx, f.TaskID, code, at.UTC()); e != nil {
			return coretask.Task{}, e
		}
	}
	if _, e = tx.Exec(ctx, `UPDATE core_task_runtime_concurrency SET running_count=GREATEST(0,running_count-1),revision=revision+1,updated_at=$1 WHERE singleton=true`, at.UTC()); e != nil {
		return coretask.Task{}, e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,error_code,error_summary,result_json,occurred_at) SELECT task_id,progress_sequence+1,$2,attempt,$3,$4,$5,$6,$7 FROM core_tasks WHERE task_id=$1`, f.TaskID, uuid.New(), status, code, summary, result, at.UTC()); e != nil {
		return coretask.Task{}, e
	}
	if _, e = tx.Exec(ctx, `UPDATE core_tasks SET progress_sequence=progress_sequence+1 WHERE task_id=$1`, f.TaskID); e != nil {
		return coretask.Task{}, e
	}
	t, e := s.taskTx(ctx, tx, f.TaskID, false)
	if e != nil {
		return coretask.Task{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return coretask.Task{}, e
	}
	return t, nil
}

func (s *CoreTaskStore) AppendProgress(ctx context.Context, c coretask.ProgressCommand) (coretask.Task, coretask.Progress, error) {
	if c.Fence.TaskID == "" || c.ExpectedSequence == 0 || c.Progress.Sequence != 0 {
		return coretask.Task{}, coretask.Progress{}, coretask.ErrInvalid
	}
	if c.Progress.TaskID != c.TaskID || c.Progress.Attempt != c.Attempt || c.Progress.Status != coretask.StatusRunning || c.Progress.At.IsZero() {
		return coretask.Task{}, coretask.Progress{}, coretask.ErrInvalid
	}
	tx, e := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return coretask.Task{}, coretask.Progress{}, e
	}
	defer tx.Rollback(ctx)
	current, e := s.taskTxLocked(ctx, tx, c.TaskID, false)
	if e != nil {
		return coretask.Task{}, coretask.Progress{}, e
	}
	candidate := c
	candidate.Progress.Sequence = c.ExpectedSequence + 1
	if e = coretask.ValidateProgress(current, candidate); e != nil {
		return coretask.Task{}, coretask.Progress{}, e
	}
	var sequence int64
	e = tx.QueryRow(ctx, `UPDATE core_tasks SET progress_sequence=progress_sequence+1,revision=revision+1,updated_at=$1 WHERE task_id=$2 AND status='running' AND attempt=$3 AND lease_epoch=$4 AND revision=$5 AND progress_sequence=$6 AND lease_expires_at>$1 RETURNING progress_sequence`, c.Progress.At.UTC(), c.TaskID, c.Attempt, c.LeaseEpoch, c.ExpectedRevision, c.ExpectedSequence).Scan(&sequence)
	if errors.Is(e, pgx.ErrNoRows) {
		return coretask.Task{}, coretask.Progress{}, coretask.ErrLeaseConflict
	}
	if e != nil {
		return coretask.Task{}, coretask.Progress{}, e
	}
	p := c.Progress
	p.Sequence = uint64(sequence)
	p.EventID = uuid.NewString()
	if _, e = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,percent,result_json,error_code,error_summary,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, p.TaskID, p.Sequence, p.EventID, p.Attempt, string(p.Status), p.Phase, p.Message, p.Percent, p.ResultJSON, p.ErrorCode, p.ErrorSummary, p.At.UTC()); e != nil {
		return coretask.Task{}, coretask.Progress{}, e
	}
	t, e := s.taskTx(ctx, tx, p.TaskID, false)
	if e != nil {
		return t, p, e
	}
	if e = tx.Commit(ctx); e != nil {
		return t, p, e
	}
	return t, p, nil
}

func (s *CoreTaskStore) ListProgress(ctx context.Context, id string, after uint64, limit int) ([]coretask.Progress, string, error) {
	if !coretask.ValidUUID(id) || limit <= 0 || limit > 200 {
		return nil, "", coretask.ErrInvalid
	}
	rows, e := s.store.pool.Query(ctx, `SELECT sequence,event_id::text,attempt,status,phase,progress_message,percent,result_json,error_code,error_summary,occurred_at FROM core_task_events WHERE task_id=$1 AND sequence>$2 ORDER BY sequence LIMIT $3`, id, after, limit+1)
	if e != nil {
		return nil, "", e
	}
	defer rows.Close()
	out := []coretask.Progress{}
	for rows.Next() {
		var p coretask.Progress
		var status string
		if e = rows.Scan(&p.Sequence, &p.EventID, &p.Attempt, &status, &p.Phase, &p.Message, &p.Percent, &p.ResultJSON, &p.ErrorCode, &p.ErrorSummary, &p.At); e != nil {
			return nil, "", e
		}
		p.TaskID = id
		p.Status = coretask.Status(status)
		p.At = p.At.UTC()
		out = append(out, p)
	}
	if e = rows.Err(); e != nil {
		return nil, "", e
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d", out[len(out)-1].Sequence)))
	}
	return out, next, nil
}

func (s *CoreTaskStore) WatchProgress(ctx context.Context, id string, after uint64) (<-chan coretask.Progress, error) {
	events, err := s.WatchProgressWithErrors(ctx, id, after)
	if err != nil {
		return nil, err
	}
	out := make(chan coretask.Progress)
	go func() {
		defer close(out)
		for event := range events {
			if event.Progress == nil {
				return
			}
			select {
			case out <- *event.Progress:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

func (s *CoreTaskStore) WatchProgressWithErrors(ctx context.Context, id string, after uint64) (<-chan coretask.ProgressStreamEvent, error) {
	if !coretask.ValidUUID(id) {
		return nil, coretask.ErrInvalid
	}
	out := make(chan coretask.ProgressStreamEvent)
	go func() {
		defer close(out)
		cursor := after
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			events, _, err := s.ListProgress(ctx, id, cursor, 200)
			if err != nil {
				select {
				case out <- coretask.ProgressStreamEvent{Err: err}:
				case <-ctx.Done():
				}
				return
			}
			for _, event := range events {
				cursor = event.Sequence
				select {
				case out <- coretask.ProgressStreamEvent{Progress: &event}:
				case <-ctx.Done():
					return
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	return out, nil
}

func (s *CoreTaskStore) CancelTask(ctx context.Context, c coretask.CancelCommand) (coretask.Task, error) {
	if !coretask.ValidUUID(c.TaskID) || c.Mutation.ValidateExpectedRevision() != nil || c.At.IsZero() {
		return coretask.Task{}, coretask.ErrInvalid
	}
	return s.mutateTask(ctx, coreTaskCancelOp, c.Mutation, func(tx pgx.Tx) (coretask.Task, error) {
		t, e := s.taskTx(ctx, tx, c.TaskID, false)
		if e != nil {
			return coretask.Task{}, e
		}
		if t.Revision != c.Mutation.ExpectedRevision {
			return coretask.Task{}, coretask.ErrRevisionConflict
		}
		if t.Status == coretask.StatusSucceeded || t.Status == coretask.StatusFailed || t.Status == coretask.StatusCanceled {
			return coretask.Task{}, coretask.ErrTerminal
		}
		running := t.Status == coretask.StatusRunning
		if running && t.Spec.Kind == coretask.TaskKindWorkload {
			return coretask.Task{}, coretask.ErrDispatchStarted
		}
		epoch := t.LeaseEpoch
		if running {
			epoch++
		}
		if t.Spec.Kind == coretask.TaskKindKnowledgeIndex {
			// Knowledge cancellation must persist the job/source reset and the
			// canceled-stage tombstone in this same mutation transaction. The
			// generic task transition below remains the sole owner of task
			// idempotency, fencing, concurrency, and event bookkeeping.
			if e = cancelKnowledgeIndexTaskTx(ctx, tx, c.TaskID, c.At.UTC()); e != nil {
				return coretask.Task{}, e
			}
		}
		tag, e := tx.Exec(ctx, `UPDATE core_tasks SET status='canceled',failure_code='user_canceled',failure_summary=$1,lease_epoch=$2,lease_holder='',lease_expires_at=NULL,revision=revision+1,updated_at=$3 WHERE task_id=$4 AND revision=$5`, c.Reason, epoch, c.At.UTC(), c.TaskID, c.Mutation.ExpectedRevision)
		if e != nil || tag.RowsAffected() != 1 {
			if e != nil {
				return coretask.Task{}, e
			}
			return coretask.Task{}, coretask.ErrRevisionConflict
		}
		if e = terminalizeConfirmationForTaskTx(ctx, tx, c.TaskID, "task_canceled", c.At.UTC()); e != nil {
			return coretask.Task{}, e
		}
		if running {
			if _, e = tx.Exec(ctx, `UPDATE core_task_runtime_concurrency SET running_count=GREATEST(0,running_count-1),revision=revision+1,updated_at=$1 WHERE singleton=true`, c.At.UTC()); e != nil {
				return coretask.Task{}, e
			}
		}
		if _, e = tx.Exec(ctx, `UPDATE core_tasks SET progress_sequence=progress_sequence+1 WHERE task_id=$1`, c.TaskID); e != nil {
			return coretask.Task{}, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,error_code,error_summary,occurred_at) SELECT task_id,progress_sequence,$2,attempt,'canceled','user_canceled',$3,$4 FROM core_tasks WHERE task_id=$1`, c.TaskID, uuid.New(), c.Reason, c.At.UTC()); e != nil {
			return coretask.Task{}, e
		}
		return s.taskTx(ctx, tx, c.TaskID, false)
	})
}
func (s *CoreTaskStore) RetryTask(ctx context.Context, c coretask.RetryCommand) (coretask.Task, error) {
	if c.Validate() != nil {
		return coretask.Task{}, coretask.ErrInvalid
	}
	return s.mutateTask(ctx, coreTaskRetryOp, c.Mutation, func(tx pgx.Tx) (coretask.Task, error) {
		orig, e := s.taskTx(ctx, tx, c.TaskID, false)
		if e != nil {
			return coretask.Task{}, e
		}
		next, e := coretask.RetryTask(orig, coretask.RetryRequest{TaskID: c.TaskID, IdempotencyKey: c.Mutation.IdempotencyKey, RequestDigest: c.Mutation.RequestDigest, ExpectedRevision: c.Mutation.ExpectedRevision, At: c.At.UTC()})
		if e != nil {
			return coretask.Task{}, e
		}
		if orig.Spec.Kind != coretask.TaskKindAgent || orig.Snapshot == nil {
			return coretask.Task{}, coretask.ErrConflict
		}
		raw, _ := json.Marshal(orig.Snapshot)
		att, ext, know := coreTaskJSONBytes(next.Spec.AttachmentRefs), coreTaskJSONBytes(next.Spec.Extensions), coreTaskJSONBytes(next.Spec.KnowledgeRefs)
		payload, _ := json.Marshal(next.Spec.Payload)
		if _, e = tx.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,conversation_id,model_profile_id,create_idempotency_key,attachment_refs,extensions_json,knowledge_refs,timeout_seconds,status,progress_sequence,available_at,retry_of_task_id,revision,created_at,updated_at,task_kind,payload_json) VALUES($1,$2,NULLIF($3,'')::uuid,NULLIF($4,'')::uuid,$5,$6,$7,$8,$9,'queued',1,$10,$11,1,$12,$12,$13,$14)`, next.ID, next.Spec.Goal, next.Spec.ConversationID, next.Spec.ModelProfileID, next.Spec.IdempotencyKey, att, ext, know, next.Spec.TimeoutSeconds, next.Spec.AvailableAt, next.RetryOfTaskID, c.At.UTC(), string(next.Spec.Kind), payload); e != nil {
			return coretask.Task{}, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO core_task_execution_snapshots(task_id,snapshot_json,snapshot_digest) VALUES($1,$2,$3)`, next.ID, raw, orig.Snapshot.Digest); e != nil {
			return coretask.Task{}, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id) VALUES('task',$1,$2)`, next.ID, next.Spec.ModelProfileID); e != nil {
			return coretask.Task{}, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) VALUES($1,1,$2,0,'queued','created','retry queued',$3)`, next.ID, uuid.New(), c.At.UTC()); e != nil {
			return coretask.Task{}, e
		}
		return s.taskTx(ctx, tx, next.ID, false)
	})
}
func (s *CoreTaskStore) WaitTask(ctx context.Context, c coretask.WaitUserCommand) error {
	if c.At.IsZero() || c.Reason == "" {
		return coretask.ErrInvalid
	}
	tx, e := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	tag, e := tx.Exec(ctx, `UPDATE core_tasks SET status='waiting_user',lease_holder='',lease_expires_at=NULL,revision=revision+1,updated_at=$1 WHERE task_id=$2 AND status='running' AND attempt=$3 AND lease_epoch=$4 AND revision=$5 AND lease_expires_at>$1`, c.At.UTC(), c.TaskID, c.Attempt, c.LeaseEpoch, c.ExpectedRevision)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return coretask.ErrLeaseConflict
	}
	if _, e = tx.Exec(ctx, `UPDATE core_task_runtime_concurrency SET running_count=GREATEST(0,running_count-1),revision=revision+1,updated_at=$1 WHERE singleton=true`, c.At.UTC()); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE core_tasks SET progress_sequence=progress_sequence+1 WHERE task_id=$1`, c.TaskID); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) SELECT task_id,progress_sequence,$2,attempt,'waiting_user','waiting_user',$3,$4 FROM core_tasks WHERE task_id=$1`, c.TaskID, uuid.New(), c.Reason, c.At.UTC()); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *CoreTaskStore) ResumeTask(ctx context.Context, c coretask.ResumeCommand) error {
	if !coretask.ValidUUID(c.TaskID) || c.ExpectedRevision == 0 {
		return coretask.ErrInvalid
	}
	at := time.Now().UTC()
	tx, e := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	tag, e := tx.Exec(ctx, `UPDATE core_tasks SET status='queued',available_at=$1,lease_holder='',lease_expires_at=NULL,revision=revision+1,progress_sequence=progress_sequence+1,updated_at=$1 WHERE task_id=$2 AND status='waiting_user' AND revision=$3`, at, c.TaskID, c.ExpectedRevision)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return coretask.ErrRevisionConflict
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) SELECT task_id,progress_sequence,$2,attempt,'queued','resumed','task resumed',$3 FROM core_tasks WHERE task_id=$1`, c.TaskID, uuid.New(), at); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
