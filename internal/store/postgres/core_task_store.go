package postgres

// PostgreSQL implementation of the Core v1 Task boundary. It owns durable
// task mutations and row decoding; queue, terminal, and watch operations live
// in cohesive companion files in this package.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	coreTaskCreateOp = "create"
	coreTaskDeleteOp = "delete"
	coreTaskCancelOp = "cancel"
	coreTaskRetryOp  = "retry"
)

type CoreTaskStore struct{ store *Store }

func NewCoreTaskStore(store *Store) *CoreTaskStore { return &CoreTaskStore{store: store} }

func (s *CoreTaskStore) LookupMutation(ctx context.Context, operation, key string) (coretask.MutationRecord, error) {
	var digest string
	var response []byte
	var created time.Time
	err := s.store.pool.QueryRow(ctx, `SELECT request_hash,response_json,created_at FROM core_task_replays WHERE operation=$1 AND idempotency_key=$2`, operation, key).Scan(&digest, &response, &created)
	if errors.Is(err, pgx.ErrNoRows) {
		return coretask.MutationRecord{}, coretask.ErrNotFound
	}
	if err != nil {
		return coretask.MutationRecord{}, err
	}
	return coretask.MutationRecord{Operation: operation, IdempotencyKey: key, Digest: digest, Response: response, CreatedAt: created.UTC()}, nil
}
func (s *CoreTaskStore) CommitMutation(ctx context.Context, r coretask.MutationRecord) (coretask.MutationRecord, error) {
	if r.Validate() != nil {
		return coretask.MutationRecord{}, coretask.ErrInvalid
	}
	_, err := s.store.pool.Exec(ctx, `INSERT INTO core_task_replays(operation,idempotency_key,request_hash,response_json,created_at) VALUES($1,$2,$3,$4,$5)`, r.Operation, r.IdempotencyKey, r.Digest, r.Response, r.CreatedAt.UTC())
	if err != nil {
		return coretask.MutationRecord{}, err
	}
	return r, nil
}

func (s *CoreTaskStore) CreateTask(ctx context.Context, c coretask.CreateTaskCommand) (coretask.Task, error) {
	if c.Validate() != nil {
		return coretask.Task{}, coretask.ErrInvalid
	}
	return s.mutateTask(ctx, coreTaskCreateOp, c.Mutation, func(tx pgx.Tx) (coretask.Task, error) {
		return s.createTaskTx(ctx, tx, c.Spec, string(coretask.StatusQueued))
	})
}

// createTaskTx is shared by ordinary task creation and confirmation-bound
// extension execution. The caller owns the transaction and chooses the
// initial status; waiting_user is never visible as queued to the scheduler.
func (s *CoreTaskStore) createTaskTx(ctx context.Context, tx pgx.Tx, rawSpec coretask.TaskSpec, status string) (coretask.Task, error) {
	spec, err := rawSpec.Normalize()
	if err != nil || (status != string(coretask.StatusQueued) && status != string(coretask.StatusWaitingUser)) {
		return coretask.Task{}, coretask.ErrInvalid
	}
	at := spec.AvailableAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	id := coreTaskID(spec.IdempotencyKey)
	att, ext, know := coreTaskJSONBytes(spec.AttachmentRefs), coreTaskJSONBytes(spec.Extensions), coreTaskJSONBytes(spec.KnowledgeRefs)
	payload, _ := json.Marshal(spec.Payload)
	snapshot, err := resolveTaskSnapshotTx(ctx, tx, spec)
	if err != nil {
		return coretask.Task{}, err
	}
	snapshotRaw, _ := json.Marshal(snapshot)
	now := time.Now().UTC()
	_, err = tx.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,conversation_id,model_profile_id,create_idempotency_key,attachment_refs,extensions_json,knowledge_refs,timeout_seconds,status,progress_sequence,available_at,revision,created_at,updated_at,task_kind,payload_json) VALUES($1,$2,NULLIF($3,'')::uuid,NULLIF($4,'')::uuid,$5,$6,$7,$8,$9,$10,1,$11,1,$12,$12,$13,$14)`, id, spec.Goal, spec.ConversationID, spec.ModelProfileID, spec.IdempotencyKey, att, ext, know, spec.TimeoutSeconds, status, at.UTC(), now, string(spec.Kind), payload)
	if err != nil {
		return coretask.Task{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_execution_snapshots(task_id,snapshot_json,snapshot_digest) VALUES($1,$2,$3)`, id, snapshotRaw, snapshot.Digest); err != nil {
		return coretask.Task{}, err
	}
	if spec.Kind == coretask.TaskKindAgent {
		if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id) VALUES('task',$1,$2)`, id, spec.ModelProfileID); err != nil {
			return coretask.Task{}, err
		}
	}
	phase, message := "created", "task queued"
	if status == string(coretask.StatusWaitingUser) {
		phase, message = "confirmation", "waiting for owner confirmation"
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) VALUES($1,1,$2,0,$3,$4,$5,$6)`, id, uuid.New(), status, phase, message, now); err != nil {
		return coretask.Task{}, err
	}
	return s.taskTx(ctx, tx, id, false)
}

func (s *CoreTaskStore) GetTask(ctx context.Context, id string) (coretask.Task, error) {
	if !coretask.ValidUUID(id) {
		return coretask.Task{}, coretask.ErrInvalid
	}
	return s.taskRow(ctx, s.store.pool.QueryRow(ctx, taskSelect+` WHERE task_id=$1 AND deleted_at IS NULL`, id))
}
func (s *CoreTaskStore) ListTasks(ctx context.Context, q coretask.TaskListQuery) ([]coretask.Task, string, error) {
	if q.Limit <= 0 || q.Limit > 200 {
		return nil, "", coretask.ErrInvalid
	}
	var cursor string
	if q.Cursor != "" {
		b, e := base64.RawURLEncoding.DecodeString(q.Cursor)
		if e != nil || uuid.Validate(string(b)) != nil {
			return nil, "", coretask.ErrInvalid
		}
		cursor = string(b)
	}
	rows, e := s.store.pool.Query(ctx, taskSelect+` WHERE ($1 OR deleted_at IS NULL) AND ($2='' OR status=$2) AND ($3='' OR task_id>$3::uuid) ORDER BY task_id LIMIT $4`, q.IncludeDeleted, coreTaskStatusString(q.Status), cursor, q.Limit+1)
	if e != nil {
		return nil, "", e
	}
	defer rows.Close()
	out := []coretask.Task{}
	for rows.Next() {
		t, e := scanCoreTask(rows)
		if e != nil {
			return nil, "", e
		}
		out = append(out, t)
	}
	if e = rows.Err(); e != nil {
		return nil, "", e
	}
	next := ""
	if len(out) > q.Limit {
		out = out[:q.Limit]
		next = base64.RawURLEncoding.EncodeToString([]byte(out[len(out)-1].ID))
	}
	return out, next, nil
}

func (s *CoreTaskStore) DeleteTask(ctx context.Context, c coretask.DeleteTaskCommand) (coretask.DeletedTaskResponse, error) {
	if !coretask.ValidUUID(c.TaskID) || c.Mutation.ValidateExpectedRevision() != nil || c.At.IsZero() {
		return coretask.DeletedTaskResponse{}, coretask.ErrInvalid
	}
	var result coretask.DeletedTaskResponse
	raw, err := s.mutateRaw(ctx, coreTaskDeleteOp, c.Mutation, func(tx pgx.Tx) (json.RawMessage, error) {
		t, e := s.taskTxLocked(ctx, tx, c.TaskID, true)
		if e != nil {
			return nil, e
		}
		if t.Status == coretask.StatusRunning || (t.Status != coretask.StatusSucceeded && t.Status != coretask.StatusFailed && t.Status != coretask.StatusCanceled) {
			return nil, coretask.ErrConflict
		}
		if t.Revision != c.Mutation.ExpectedRevision {
			return nil, coretask.ErrRevisionConflict
		}
		if tag, updateErr := tx.Exec(ctx, `UPDATE core_tasks SET deleted_at=$2,updated_at=$2,revision=revision+1 WHERE task_id=$1 AND revision=$3 AND deleted_at IS NULL`, c.TaskID, c.At.UTC(), c.Mutation.ExpectedRevision); updateErr != nil || tag.RowsAffected() != 1 {
			if updateErr != nil {
				return nil, updateErr
			}
			return nil, coretask.ErrRevisionConflict
		}
		if _, e = tx.Exec(ctx, `DELETE FROM core_model_profile_active_refs WHERE owner_kind='task' AND owner_id=$1`, c.TaskID); e != nil {
			return nil, e
		}
		result = coretask.DeletedTaskResponse{TaskID: c.TaskID, DeletedAt: c.At.UTC(), Revision: t.Revision + 1, Tombstone: true}
		return json.Marshal(result)
	})
	if err == nil && result.TaskID == "" {
		err = json.Unmarshal(raw, &result)
	}
	return result, err
}

func (s *CoreTaskStore) mutateTask(ctx context.Context, op string, m coretask.MutationCommand, apply func(pgx.Tx) (coretask.Task, error)) (coretask.Task, error) {
	var out coretask.Task
	raw, err := s.mutateRaw(ctx, op, m, func(tx pgx.Tx) (json.RawMessage, error) {
		t, e := apply(tx)
		if e != nil {
			return nil, e
		}
		out = t
		return json.Marshal(t)
	})
	if err == nil && out.ID == "" {
		if e := json.Unmarshal(raw, &out); e != nil {
			return coretask.Task{}, e
		}
	}
	return out, err
}
func (s *CoreTaskStore) mutateRaw(ctx context.Context, op string, m coretask.MutationCommand, apply func(pgx.Tx) (json.RawMessage, error)) (json.RawMessage, error) {
	if m.Validate() != nil {
		return nil, coretask.ErrInvalid
	}
	tx, e := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "core_task:"+op+":"+m.IdempotencyKey); e != nil {
		return nil, e
	}
	var d string
	var raw json.RawMessage
	e = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_task_replays WHERE operation=$1 AND idempotency_key=$2 FOR UPDATE`, op, m.IdempotencyKey).Scan(&d, &raw)
	if e == nil {
		if d != m.RequestDigest {
			return nil, coretask.ErrConflict
		}
		if e = tx.Commit(ctx); e != nil {
			return nil, e
		}
		return raw, nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return nil, e
	}
	raw, e = apply(tx)
	if e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_task_replays(operation,idempotency_key,request_hash,response_json) VALUES($1,$2,$3,$4)`, op, m.IdempotencyKey, m.RequestDigest, raw); e != nil {
		return nil, e
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	return raw, nil
}

const taskSelect = `SELECT task_id,goal,COALESCE(conversation_id::text,''),COALESCE(model_profile_id::text,''),create_idempotency_key,attachment_refs,extensions_json,knowledge_refs,timeout_seconds,status,attempt,progress_sequence,lease_epoch,lease_holder,lease_expires_at,available_at,execution_started_at,execution_deadline_at,COALESCE(retry_of_task_id::text,''),result_json,failure_code,failure_summary,revision,created_at,updated_at,deleted_at,task_kind,payload_json,COALESCE((SELECT snapshot_json FROM core_task_execution_snapshots x WHERE x.task_id=core_tasks.task_id),'{}'::jsonb) FROM core_tasks`

type coreTaskScanner interface{ Scan(...any) error }

func (s *CoreTaskStore) taskRow(ctx context.Context, r coreTaskScanner) (coretask.Task, error) {
	return scanCoreTask(r)
}
func (s *CoreTaskStore) taskTx(ctx context.Context, tx pgx.Tx, id string, includeDeleted bool) (coretask.Task, error) {
	where := ` WHERE task_id=$1`
	if !includeDeleted {
		where += ` AND deleted_at IS NULL`
	}
	return s.taskRow(ctx, tx.QueryRow(ctx, taskSelect+where, id))
}
func (s *CoreTaskStore) taskTxLocked(ctx context.Context, tx pgx.Tx, id string, includeDeleted bool) (coretask.Task, error) {
	where := ` WHERE task_id=$1`
	if !includeDeleted {
		where += ` AND deleted_at IS NULL`
	}
	return s.taskRow(ctx, tx.QueryRow(ctx, taskSelect+where+` FOR UPDATE`, id))
}
func scanCoreTask(r coreTaskScanner) (coretask.Task, error) {
	var t coretask.Task
	var conv, model, status, holder, retry, code, summary string
	var att, ext, know, payload []byte
	var kind string
	var result []byte
	var snapshotRaw []byte
	var lease, started, deadline *time.Time
	var rev, seq, epoch int64
	var attempt int32
	var deleted *time.Time
	e := r.Scan(&t.ID, &t.Spec.Goal, &conv, &model, &t.Spec.IdempotencyKey, &att, &ext, &know, &t.Spec.TimeoutSeconds, &status, &attempt, &seq, &epoch, &holder, &lease, &t.AvailableAt, &started, &deadline, &retry, &result, &code, &summary, &rev, &t.CreatedAt, &t.UpdatedAt, &deleted, &kind, &payload, &snapshotRaw)
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return t, coretask.ErrNotFound
		}
		return t, e
	}
	t.Spec.ConversationID, t.Spec.ModelProfileID, t.Spec.Kind = conv, model, coretask.TaskKind(kind)
	if t.Spec.Kind == "" {
		t.Spec.Kind = coretask.TaskKindAgent
	}
	if len(payload) > 0 {
		if e := json.Unmarshal(payload, &t.Spec.Payload); e != nil {
			return t, coretask.ErrInvalid
		}
	}
	if len(snapshotRaw) > 2 {
		var snapshot coretask.ExecutionSnapshot
		if e := json.Unmarshal(snapshotRaw, &snapshot); e != nil || snapshot.Validate() != nil {
			return t, coretask.ErrInvalid
		}
		t.Snapshot = &snapshot
	}
	t.Status, t.Attempt, t.ProgressSequence, t.LeaseEpoch, t.Revision, t.RetryOfTaskID, t.FailureCode, t.FailureSummary, t.DeletedAt = coretask.Status(status), uint32(attempt), uint64(seq), uint64(epoch), uint64(rev), retry, code, summary, deleted
	_ = json.Unmarshal(att, &t.Spec.AttachmentRefs)
	_ = json.Unmarshal(ext, &t.Spec.Extensions)
	_ = json.Unmarshal(know, &t.Spec.KnowledgeRefs)
	if _, e := t.Spec.Normalize(); e != nil {
		return t, coretask.ErrInvalid
	}
	if len(result) > 0 {
		var v coretask.Result
		if json.Unmarshal(result, &v) == nil {
			t.Result = &v
		}
	}
	if lease != nil {
		t.Lease = &coretask.Lease{TaskID: t.ID, Attempt: t.Attempt, Epoch: t.LeaseEpoch, Holder: holder, ExpiresAt: lease.UTC()}
	}
	if started != nil {
		x := started.UTC()
		t.ExecutionStartedAt = &x
	}
	if deadline != nil {
		x := deadline.UTC()
		t.ExecutionDeadlineAt = &x
	}
	t.CreatedAt, t.UpdatedAt, t.AvailableAt = t.CreatedAt.UTC(), t.UpdatedAt.UTC(), t.AvailableAt.UTC()
	if t.DeletedAt != nil {
		x := t.DeletedAt.UTC()
		t.DeletedAt = &x
	}
	return t, nil
}
func coreTaskID(key string) string { return coretaskDeterministic("task:" + key) }
func coretaskDeterministic(seed string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(seed)).String()
}
func coreTaskJSONBytes(v any) []byte { b, _ := json.Marshal(v); return b }
func coreTaskStatusString(s *coretask.Status) string {
	if s == nil {
		return ""
	}
	return string(*s)
}
