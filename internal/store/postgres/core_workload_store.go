package postgres

// The workload adapter keeps the provider boundary free of SQL and mirrors
// the MemoryStore transaction shape. Provider execution is intentionally not
// implemented here; this store only persists immutable plans, fences, events,
// and terminal read-back.
import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type CoreWorkloadStore struct{ store *Store }

func (s *CoreWorkloadStore) CancelOperation(ctx context.Context, id, key string, expected uint64) (coreworkload.Operation, error) {
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreworkload.Operation{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, `workload_cancel:`+key); err != nil {
		return coreworkload.Operation{}, err
	}
	cancelHash := coreworkload.CancelInputDigest(id, expected)
	var replayHash string
	var replayRaw []byte
	if err = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_workload_idempotency WHERE owner_id=$1 AND operation='cancel' AND idempotency_key=$2 FOR UPDATE`, s.store.instanceID, key).Scan(&replayHash, &replayRaw); err == nil {
		if replayHash != cancelHash {
			return coreworkload.Operation{}, coreworkload.ErrConflict
		}
		var replay coreworkload.Operation
		if json.Unmarshal(replayRaw, &replay) != nil {
			return coreworkload.Operation{}, coreworkload.ErrInvalid
		}
		if err = tx.Commit(ctx); err != nil {
			return coreworkload.Operation{}, err
		}
		return replay, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return coreworkload.Operation{}, err
	}
	var op coreworkload.Operation
	var status string
	var kind, target string
	if err = tx.QueryRow(ctx, `SELECT operation_id::text,workload_id::text,plan_id::text,operation,plan_revision,plan_digest,target_kind,task_id::text,confirmation_id::text,status,revision,created_at,updated_at,dispatch_state,COALESCE(dispatch_claim::text,'') FROM core_workload_operations WHERE owner_id=$1 AND operation_id=$2 FOR UPDATE`, s.store.instanceID, id).Scan(&op.ID, &op.WorkloadID, &op.PlanID, &kind, &op.PlanRevision, &op.PlanDigest, &target, &op.TaskID, &op.ConfirmationID, &status, &op.Revision, &op.CreatedAt, &op.UpdatedAt, &op.DispatchState, &op.DispatchClaim); err != nil {
		return op, coreworkload.ErrNotFound
	}
	op.Kind, op.TargetKind, op.Status = coreworkload.OperationKind(kind), coreworkload.TargetKind(target), coreworkload.OperationStatus(status)
	if op.Revision != expected {
		return op, coreworkload.ErrRevisionConflict
	}
	var taskStatus, confirmationState string
	if err = tx.QueryRow(ctx, `SELECT status FROM core_tasks WHERE task_id=$1 FOR UPDATE`, op.TaskID).Scan(&taskStatus); err != nil {
		return op, coreworkload.ErrConflict
	}
	if err = tx.QueryRow(ctx, `SELECT state FROM core_confirmations WHERE confirmation_id=$1 FOR UPDATE`, op.ConfirmationID).Scan(&confirmationState); err != nil {
		return op, coreworkload.ErrConflict
	}
	if op.Status != coreworkload.OperationWaitingUser || op.DispatchState != "prepared" || op.DispatchClaim != "" || taskStatus != "waiting_user" || (confirmationState != "pending" && confirmationState != "confirmed") {
		return op, coreworkload.ErrConflict
	}
	now := time.Now().UTC()
	confirmation, err := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, op.ConfirmationID))
	if err != nil {
		return op, err
	}
	if _, err = terminalizeWorkloadBeforeDispatchTx(ctx, tx, s.store.instanceID, confirmation, "rejected", "canceled", "canceled", "user_canceled", "canceled", now); err != nil {
		return op, err
	}
	op.Status = coreworkload.OperationCanceled
	op.Revision++
	op.UpdatedAt = now
	replayRaw, _ = json.Marshal(op)
	if _, err = tx.Exec(ctx, `INSERT INTO core_workload_idempotency(owner_id,operation,idempotency_key,request_hash,operation_id,response_json) VALUES($1,'cancel',$2,$3,$4,$5)`, s.store.instanceID, key, cancelHash, op.ID, replayRaw); err != nil {
		return op, err
	}
	if err = tx.Commit(ctx); err != nil {
		return op, err
	}
	return op, nil
}

func (s *CoreWorkloadStore) RenewDispatchLease(ctx context.Context, id, claim string, epoch uint64) (coreworkload.Operation, error) {
	now := time.Now().UTC()
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreworkload.Operation{}, err
	}
	defer tx.Rollback(ctx)
	var taskID string
	if err = tx.QueryRow(ctx, `SELECT task_id::text FROM core_workload_operations WHERE owner_id=$1 AND operation_id=$2 AND dispatch_claim=$3::uuid AND dispatch_epoch=$4 AND status='running' AND dispatch_lease_until>$5 FOR UPDATE`, s.store.instanceID, id, claim, epoch, now).Scan(&taskID); err != nil {
		return coreworkload.Operation{}, coreworkload.ErrRevisionConflict
	}
	var leaseUntil time.Time
	if err = tx.QueryRow(ctx, `SELECT lease_expires_at FROM core_tasks WHERE task_id=$1 AND status='running' AND lease_holder='workload-handler' AND lease_epoch=$2 AND lease_expires_at>$3 FOR UPDATE`, taskID, epoch, now).Scan(&leaseUntil); err != nil {
		return coreworkload.Operation{}, coreworkload.ErrRevisionConflict
	}
	expires := now.Add(30 * time.Second)
	if _, err = tx.Exec(ctx, `UPDATE core_tasks SET lease_expires_at=$2,revision=revision+1,updated_at=$2 WHERE task_id=$1`, taskID, expires); err != nil {
		return coreworkload.Operation{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_workload_operations SET dispatch_lease_until=$5,revision=revision+1,updated_at=$5 WHERE owner_id=$1 AND operation_id=$2 AND dispatch_claim=$3::uuid AND dispatch_epoch=$4`, s.store.instanceID, id, claim, epoch, expires); err != nil {
		return coreworkload.Operation{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreworkload.Operation{}, err
	}
	return s.GetOperation(ctx, id)
}

func mustJSONWorkload(v any) []byte { b, _ := json.Marshal(v); return b }

func NewCoreWorkloadStore(s *Store) *CoreWorkloadStore { return &CoreWorkloadStore{store: s} }

func (s *CoreWorkloadStore) CreatePlan(ctx context.Context, in coreworkload.PlanInput) (coreworkload.Plan, error) {
	if s == nil || s.store == nil || !coreworkload.ValidUUID(in.IdempotencyKey) {
		return coreworkload.Plan{}, coreworkload.ErrInvalid
	}
	p := coreworkload.Plan{ID: uuid.New().String(), Revision: 1, Summary: in.Summary, Artifact: in.Artifact, Source: in.Source, CommandSteps: in.CommandSteps, ImageDigest: in.ImageDigest, ImageURI: in.ImageURI, TargetKind: in.TargetKind, Target: in.Target, NetworkGrants: in.NetworkGrants, SecretGrants: in.SecretGrants, SecretGrantRefs: in.SecretGrantRefs, ResourceLimits: in.ResourceLimits, ExpiresAt: in.ExpiresAt.UTC(), CreatedAt: time.Now().UTC()}
	n, e := p.Normalize()
	if e != nil {
		return coreworkload.Plan{}, e
	}
	raw, _ := json.Marshal(n)
	var existingRaw []byte
	var existingHash string
	var ledgerResponse []byte
	if e = s.store.pool.QueryRow(ctx, `SELECT request_hash,response_json FROM core_workload_idempotency WHERE owner_id=$1 AND operation='plan' AND idempotency_key=$2`, s.store.instanceID, in.IdempotencyKey).Scan(&existingHash, &ledgerResponse); e == nil {
		if existingHash != coreworkload.PlanInputDigest(n) {
			return coreworkload.Plan{}, coreworkload.ErrConflict
		}
		var replay coreworkload.Plan
		if json.Unmarshal(ledgerResponse, &replay) != nil {
			return coreworkload.Plan{}, coreworkload.ErrInvalid
		}
		return replay, nil
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return coreworkload.Plan{}, e
	}
	if e = s.store.pool.QueryRow(ctx, `SELECT create_request_hash,plan_json FROM core_workload_plans WHERE owner_id=$1 AND create_idempotency_key=$2`, s.store.instanceID, in.IdempotencyKey).Scan(&existingHash, &existingRaw); e == nil {
		var existing coreworkload.Plan
		if e := json.Unmarshal(existingRaw, &existing); e != nil {
			return coreworkload.Plan{}, coreworkload.ErrInvalid
		}
		if existingHash != coreworkload.PlanInputDigest(n) {
			return coreworkload.Plan{}, coreworkload.ErrConflict
		}
		return existing, nil
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return coreworkload.Plan{}, e
	}
	_, e = s.store.pool.Exec(ctx, `INSERT INTO core_workload_plans(plan_id,owner_id,create_idempotency_key,create_request_hash,revision,digest,summary,plan_json,target_kind,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(owner_id,digest) DO NOTHING`, n.ID, s.store.instanceID, in.IdempotencyKey, coreworkload.PlanInputDigest(n), n.Revision, n.Digest, n.Summary, raw, string(n.TargetKind), n.ExpiresAt, n.CreatedAt)
	if e != nil {
		if pgErr, ok := e.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			return coreworkload.Plan{}, coreworkload.ErrConflict
		}
		return coreworkload.Plan{}, e
	}
	if e != nil {
		return coreworkload.Plan{}, e
	}
	if e = s.store.pool.QueryRow(ctx, `SELECT plan_json FROM core_workload_plans WHERE owner_id=$1 AND digest=$2`, s.store.instanceID, n.Digest).Scan(&existingRaw); e == nil {
		var existing coreworkload.Plan
		if e := json.Unmarshal(existingRaw, &existing); e != nil {
			return coreworkload.Plan{}, coreworkload.ErrInvalid
		}
		replayRaw, marshalErr := json.Marshal(existing)
		if marshalErr != nil {
			return coreworkload.Plan{}, marshalErr
		}
		if _, e = s.store.pool.Exec(ctx, `INSERT INTO core_workload_idempotency(owner_id,operation,idempotency_key,request_hash,plan_id,response_json) VALUES($1,'plan',$2,$3,$4,$5) ON CONFLICT DO NOTHING`, s.store.instanceID, in.IdempotencyKey, coreworkload.PlanInputDigest(n), existing.ID, replayRaw); e != nil {
			return coreworkload.Plan{}, e
		}
		return existing, nil
	}
	responseRaw, marshalErr := json.Marshal(n)
	if marshalErr != nil {
		return coreworkload.Plan{}, marshalErr
	}
	if _, e = s.store.pool.Exec(ctx, `INSERT INTO core_workload_idempotency(owner_id,operation,idempotency_key,request_hash,plan_id,response_json) VALUES($1,'plan',$2,$3,$4,$5) ON CONFLICT DO NOTHING`, s.store.instanceID, in.IdempotencyKey, coreworkload.PlanInputDigest(n), n.ID, responseRaw); e != nil {
		return coreworkload.Plan{}, e
	}
	return n, nil
}
func (s *CoreWorkloadStore) GetPlan(ctx context.Context, id string) (coreworkload.Plan, error) {
	var raw []byte
	var p coreworkload.Plan
	if e := s.store.pool.QueryRow(ctx, `SELECT plan_json FROM core_workload_plans WHERE owner_id=$1 AND plan_id=$2`, s.store.instanceID, id).Scan(&raw); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return p, coreworkload.ErrNotFound
		}
		return p, e
	}
	if e := json.Unmarshal(raw, &p); e != nil {
		return p, e
	}
	return p, nil
}
func (s *CoreWorkloadStore) GetWorkload(ctx context.Context, id string) (coreworkload.Workload, error) {
	var w coreworkload.Workload
	var target, state string
	var actualRaw []byte
	err := s.store.pool.QueryRow(ctx, `SELECT workload_id::text,revision,plan_id::text,plan_digest,target_kind,state,updated_at,actual_snapshot_json FROM core_workloads WHERE owner_id=$1 AND workload_id=$2`, s.store.instanceID, id).Scan(&w.ID, &w.Revision, &w.PlanID, &w.PlanDigest, &target, &state, &w.UpdatedAt, &actualRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return w, coreworkload.ErrNotFound
	}
	if err != nil {
		return w, err
	}
	w.TargetKind, w.State = coreworkload.TargetKind(target), state
	var actual coreworkload.ActualSnapshot
	if json.Unmarshal(actualRaw, &actual) == nil {
		w.Identity = actual.Identity
		w.Actual = actual
	}
	return w, nil
}
func (s *CoreWorkloadStore) ListWorkloads(ctx context.Context, limit int, cursor string) ([]coreworkload.Workload, string, error) {
	if limit <= 0 || limit > 200 {
		return nil, "", coreworkload.ErrInvalid
	}
	rows, err := s.store.pool.Query(ctx, `SELECT workload_id::text,revision,plan_id::text,plan_digest,target_kind,state,updated_at,actual_snapshot_json FROM core_workloads WHERE owner_id=$1 AND ($2='' OR workload_id>$2::uuid) ORDER BY workload_id LIMIT $3`, s.store.instanceID, cursor, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := []coreworkload.Workload{}
	for rows.Next() {
		var w coreworkload.Workload
		var target, state string
		var actualRaw []byte
		if err = rows.Scan(&w.ID, &w.Revision, &w.PlanID, &w.PlanDigest, &target, &state, &w.UpdatedAt, &actualRaw); err != nil {
			return nil, "", err
		}
		w.TargetKind, w.State = coreworkload.TargetKind(target), state
		var actual coreworkload.ActualSnapshot
		if json.Unmarshal(actualRaw, &actual) == nil {
			w.Identity = actual.Identity
			w.Actual = actual
		}
		out = append(out, w)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		next = out[limit-1].ID
		out = out[:limit]
	}
	return out, next, nil
}
func (s *CoreWorkloadStore) getPlanTx(ctx context.Context, tx pgx.Tx, id string) (coreworkload.Plan, error) {
	var raw []byte
	var p coreworkload.Plan
	if err := tx.QueryRow(ctx, `SELECT plan_json FROM core_workload_plans WHERE owner_id=$1 AND plan_id=$2`, s.store.instanceID, id).Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return p, coreworkload.ErrNotFound
		}
		return p, err
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, coreworkload.ErrInvalid
	}
	return p, nil
}
func (s *CoreWorkloadStore) ListPlans(ctx context.Context, limit int, cursor string) ([]coreworkload.Plan, string, error) {
	if limit <= 0 || limit > 200 {
		return nil, "", coreworkload.ErrInvalid
	}
	rows, e := s.store.pool.Query(ctx, `SELECT plan_json FROM core_workload_plans WHERE owner_id=$1 AND ($2='' OR plan_id>$2::uuid) ORDER BY plan_id LIMIT $3`, s.store.instanceID, cursor, limit+1)
	if e != nil {
		return nil, "", e
	}
	defer rows.Close()
	out := []coreworkload.Plan{}
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			return nil, "", e
		}
		var p coreworkload.Plan
		if e = json.Unmarshal(raw, &p); e != nil {
			return nil, "", e
		}
		out = append(out, p)
	}
	if e = rows.Err(); e != nil {
		return nil, "", e
	}
	next := ""
	if len(out) > limit {
		next = out[limit-1].ID
		out = out[:limit]
	}
	return out, next, nil
}
func (s *CoreWorkloadStore) GetOperation(ctx context.Context, id string) (coreworkload.Operation, error) {
	var o coreworkload.Operation
	var kind, target, status string
	err := s.store.pool.QueryRow(ctx, `SELECT operation_id::text,workload_id::text,plan_id::text,operation,plan_revision,plan_digest,target_kind,task_id::text,confirmation_id::text,status,revision,failure_code,failure_summary,created_at,updated_at,dispatch_state,dispatch_attempt,dispatch_epoch,COALESCE(dispatch_claim::text,''),COALESCE(dispatch_lease_until,'epoch'::timestamptz),completion_fingerprint FROM core_workload_operations WHERE owner_id=$1 AND operation_id=$2`, s.store.instanceID, id).Scan(&o.ID, &o.WorkloadID, &o.PlanID, &kind, &o.PlanRevision, &o.PlanDigest, &target, &o.TaskID, &o.ConfirmationID, &status, &o.Revision, &o.FailureCode, &o.FailureSummary, &o.CreatedAt, &o.UpdatedAt, &o.DispatchState, &o.DispatchAttempt, &o.DispatchEpoch, &o.DispatchClaim, &o.DispatchLeaseUntil, &o.CompletionFingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return o, coreworkload.ErrNotFound
	}
	if err != nil {
		return o, err
	}
	o.Kind = coreworkload.OperationKind(kind)
	o.TargetKind = coreworkload.TargetKind(target)
	o.Status = coreworkload.OperationStatus(status)
	return o, nil
}
func (s *CoreWorkloadStore) ListEvents(ctx context.Context, id string, after uint64) ([]coreworkload.Event, error) {
	rows, err := s.store.pool.Query(ctx, `SELECT e.operation_id::text,e.sequence,e.kind,e.status,e.message,COALESCE(e.readback_json,'{}'::jsonb),e.at FROM core_workload_events e JOIN core_workload_operations o ON o.owner_id=e.owner_id AND o.operation_id=e.operation_id WHERE e.owner_id=$1 AND o.owner_id=$1 AND e.operation_id=$2 AND e.sequence>$3 ORDER BY e.sequence`, s.store.instanceID, id, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []coreworkload.Event{}
	for rows.Next() {
		var e coreworkload.Event
		var st string
		if err = rows.Scan(&e.OperationID, &e.Sequence, &e.Kind, &st, &e.Message, &e.Readback, &e.At); err != nil {
			return nil, err
		}
		e.Status = coreworkload.OperationStatus(st)
		out = append(out, e)
	}
	return out, rows.Err()
}
func (s *CoreWorkloadStore) RequestOperation(ctx context.Context, c coreworkload.RequestCommand) (coreworkload.RequestResult, error) {
	if s == nil || s.store == nil || !coreworkload.ValidUUID(c.PlanID) || !coreworkload.ValidUUID(c.IdempotencyKey) || (c.WorkloadID != "" && !coreworkload.ValidUUID(c.WorkloadID)) || (c.Kind != coreworkload.OperationApply && c.Kind != coreworkload.OperationDestroy) {
		return coreworkload.RequestResult{}, coreworkload.ErrInvalid
	}
	requestHash := coreworkload.RequestInputDigest(c)
	if c.ExpiresAt.IsZero() {
		c.ExpiresAt = time.Now().UTC().Add(24 * time.Hour)
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreworkload.RequestResult{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, `core_workload_request:`+c.IdempotencyKey); err != nil {
		return coreworkload.RequestResult{}, err
	}
	var ledgerHash string
	var ledgerRaw []byte
	if err = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_workload_idempotency WHERE owner_id=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE`, s.store.instanceID, "request_"+string(c.Kind), c.IdempotencyKey).Scan(&ledgerHash, &ledgerRaw); err == nil {
		if ledgerHash != requestHash {
			return coreworkload.RequestResult{}, coreworkload.ErrConflict
		}
		var replay coreworkload.RequestResult
		if json.Unmarshal(ledgerRaw, &replay) != nil {
			return coreworkload.RequestResult{}, coreworkload.ErrInvalid
		}
		if err = tx.Commit(ctx); err != nil {
			return coreworkload.RequestResult{}, err
		}
		return replay, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return coreworkload.RequestResult{}, err
	}
	var p coreworkload.Plan
	var pRaw []byte
	if err = tx.QueryRow(ctx, `SELECT plan_id::text,revision,digest,plan_json FROM core_workload_plans WHERE owner_id=$1 AND plan_id=$2`, s.store.instanceID, c.PlanID).Scan(&p.ID, &p.Revision, &p.Digest, &pRaw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coreworkload.RequestResult{}, coreworkload.ErrNotFound
		}
		return coreworkload.RequestResult{}, err
	}
	if json.Unmarshal(pRaw, &p) != nil {
		return coreworkload.RequestResult{}, coreworkload.ErrInvalid
	}
	now := time.Now().UTC()
	if !p.ExpiresAt.After(now) || !c.ExpiresAt.After(now) {
		return coreworkload.RequestResult{}, coreworkload.ErrInvalid
	}
	wid := c.WorkloadID
	if wid == "" {
		wid = uuid.New().String()
	}
	var workloadState, workloadPlanID, workloadDigest, workloadTarget string
	workloadExists := false
	if c.Kind == coreworkload.OperationDestroy {
		if err = tx.QueryRow(ctx, `SELECT state,plan_id::text,plan_digest,target_kind FROM core_workloads WHERE owner_id=$1 AND workload_id=$2 FOR UPDATE`, s.store.instanceID, wid).Scan(&workloadState, &workloadPlanID, &workloadDigest, &workloadTarget); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return coreworkload.RequestResult{}, coreworkload.ErrNotFound
			}
			return coreworkload.RequestResult{}, err
		}
		if workloadState != "ready" || workloadPlanID != p.ID || workloadDigest != p.Digest || workloadTarget != string(p.TargetKind) {
			return coreworkload.RequestResult{}, coreworkload.ErrConflict
		}
	} else {
		if err = tx.QueryRow(ctx, `SELECT state,plan_id::text,plan_digest,target_kind FROM core_workloads WHERE owner_id=$1 AND workload_id=$2 FOR UPDATE`, s.store.instanceID, wid).Scan(&workloadState, &workloadPlanID, &workloadDigest, &workloadTarget); err == nil {
			workloadExists = true
			if workloadState != "destroyed" && workloadState != "ready" && workloadState != "failed" {
				return coreworkload.RequestResult{}, coreworkload.ErrConflict
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return coreworkload.RequestResult{}, err
		}
	}
	opID, taskID, confID := uuid.New().String(), uuid.New().String(), uuid.New().String()
	payload := coretask.WorkloadTaskPayload{WorkloadID: wid, PlanID: p.ID, OperationID: opID, PlanRevision: p.Revision, PlanDigest: p.Digest, TargetKind: string(p.TargetKind), ConfirmationID: confID, ExecutionSnapshot: mustJSONWorkload(p)}
	spec := coretask.TaskSpec{Kind: coretask.TaskKindWorkload, Payload: coretask.TaskPayload{Workload: &payload}, Goal: "workload " + string(c.Kind), IdempotencyKey: uuid.New().String(), AvailableAt: now}
	specRaw, err := json.Marshal(spec.Payload)
	if err != nil {
		return coreworkload.RequestResult{}, err
	}
	// The requested task event below owns sequence 1, so the row's durable
	// progress cursor must start at 1 as well. Terminal transitions then write
	// exactly one next event at progress_sequence+1.
	if _, err = tx.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,conversation_id,model_profile_id,create_idempotency_key,attachment_refs,extensions_json,knowledge_refs,timeout_seconds,status,attempt,progress_sequence,available_at,revision,created_at,updated_at,task_kind,payload_json) VALUES($1,$2,NULL,NULL,$3,'[]','[]','[]',0,'waiting_user',1,1,$4,1,$4,$4,'workload',$5)`, taskID, spec.Goal, spec.IdempotencyKey, now, specRaw); err != nil {
		return coreworkload.RequestResult{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) VALUES($1,1,$2,1,'waiting_user','confirmation','waiting for owner confirmation',$3)`, taskID, uuid.New(), now); err != nil {
		return coreworkload.RequestResult{}, err
	}
	binding := coreworkload.BindingForOperation(p, wid, c.Kind)
	bindingRaw, err := json.Marshal(binding)
	if err != nil {
		return coreworkload.RequestResult{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmations(confirmation_id,operation_domain,target_id,target_revision,binding_json,task_id,state,revision,created_at,updated_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,'pending',1,$7,$7,$8)`, confID, binding.OperationDomain, wid, p.Revision, bindingRaw, taskID, now, c.ExpiresAt.UTC()); err != nil {
		return coreworkload.RequestResult{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_target_bindings(confirmation_id,binding_json,updated_at) VALUES($1,$2,$3)`, confID, bindingRaw, now); err != nil {
		return coreworkload.RequestResult{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_current_bindings(operation_domain,target_id,target_revision,binding_json,updated_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(operation_domain,target_id) DO UPDATE SET target_revision=EXCLUDED.target_revision,binding_json=EXCLUDED.binding_json,updated_at=EXCLUDED.updated_at`, binding.OperationDomain, wid, p.Revision, bindingRaw, now); err != nil {
		return coreworkload.RequestResult{}, err
	}
	op := coreworkload.Operation{ID: opID, WorkloadID: wid, PlanID: p.ID, Kind: c.Kind, PlanRevision: p.Revision, PlanDigest: p.Digest, TargetKind: p.TargetKind, TaskID: taskID, ConfirmationID: confID, Status: coreworkload.OperationWaitingUser, Revision: 1, CreatedAt: now, UpdatedAt: now}
	op.DispatchState = "prepared"
	if _, err = tx.Exec(ctx, `INSERT INTO core_workload_operations(operation_id,owner_id,workload_id,plan_id,operation,plan_revision,plan_digest,target_kind,task_id,confirmation_id,status,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'waiting_user',1,$11,$11)`, op.ID, s.store.instanceID, op.WorkloadID, op.PlanID, string(op.Kind), op.PlanRevision, op.PlanDigest, string(op.TargetKind), op.TaskID, op.ConfirmationID, now); err != nil {
		return coreworkload.RequestResult{}, err
	}
	if c.Kind == coreworkload.OperationApply {
		_ = workloadExists // existing actual snapshots remain unchanged until verified completion
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_workload_events(owner_id,operation_id,sequence,kind,status,message,at) VALUES($1,$2,1,'requested','waiting_user','waiting for owner confirmation',$3)`, s.store.instanceID, op.ID, now); err != nil {
		return coreworkload.RequestResult{}, err
	}
	task := coretask.Task{ID: taskID, Spec: spec, Status: coretask.StatusWaitingUser, Attempt: 1, Revision: 1, CreatedAt: now, UpdatedAt: now, AvailableAt: now}
	conf := coreconfirmation.Confirmation{ConfirmationID: confID, Binding: binding, TaskID: taskID, State: coreconfirmation.StatePending, Revision: 1, CreatedAt: now, UpdatedAt: now, ExpiresAt: c.ExpiresAt.UTC()}
	result := coreworkload.RequestResult{Operation: op, Task: task, Confirmation: conf}
	response, err := json.Marshal(result)
	if err != nil {
		return coreworkload.RequestResult{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_workload_idempotency(owner_id,operation,idempotency_key,request_hash,plan_id,operation_id,response_json) VALUES($1,$2,$3,$4,$5,$6,$7)`, s.store.instanceID, "request_"+string(c.Kind), c.IdempotencyKey, requestHash, p.ID, op.ID, response); err != nil {
		return coreworkload.RequestResult{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreworkload.RequestResult{}, err
	}
	return result, nil
}
func (s *CoreWorkloadStore) Confirm(ctx context.Context, id string, expected int64) (coreconfirmation.Confirmation, error) {
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreconfirmation.Confirmation{}, err
	}
	defer tx.Rollback(ctx)
	var c coreconfirmation.Confirmation
	var state string
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT c.confirmation_id::text,c.binding_json,c.task_id::text,c.state,c.revision,c.created_at,c.updated_at,c.expires_at,c.terminal_reason,c.terminal_code,c.terminal_note FROM core_confirmations c JOIN core_workload_operations o ON o.confirmation_id=c.confirmation_id WHERE o.owner_id=$1 AND c.confirmation_id=$2 FOR UPDATE OF c,o`, s.store.instanceID, id).Scan(&c.ConfirmationID, &raw, &c.TaskID, &state, &c.Revision, &c.CreatedAt, &c.UpdatedAt, &c.ExpiresAt, &c.TerminalReason, &c.TerminalCode, &c.TerminalNote); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c, coreworkload.ErrNotFound
		}
		return c, err
	}
	if err := json.Unmarshal(raw, &c.Binding); err != nil {
		return c, coreworkload.ErrInvalid
	}
	c.State = coreconfirmation.State(state)
	if c.Revision != expected {
		return c, coreworkload.ErrRevisionConflict
	}
	if c.State != coreconfirmation.StatePending {
		if err := tx.Commit(ctx); err != nil {
			return c, err
		}
		return c, nil
	}
	if tag, err := tx.Exec(ctx, `UPDATE core_confirmations AS c SET state='confirmed',revision=c.revision+1,updated_at=clock_timestamp() FROM core_workload_operations o WHERE o.owner_id=$1 AND o.confirmation_id=c.confirmation_id AND c.confirmation_id=$2 AND c.revision=$3 AND o.status='waiting_user' AND o.dispatch_state='prepared' AND o.dispatch_claim IS NULL`, s.store.instanceID, id, expected); err != nil {
		return c, err
	} else if tag.RowsAffected() != 1 {
		return c, coreworkload.ErrRevisionConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return c, err
	}
	c.State = coreconfirmation.StateConfirmed
	c.Revision++
	return c, nil
}
func (s *CoreWorkloadStore) Consume(ctx context.Context, id, confirmationID, digest string, expected uint64) (coreworkload.Operation, coretask.Task, error) {
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreworkload.Operation{}, coretask.Task{}, err
	}
	defer tx.Rollback(ctx)
	var op coreworkload.Operation
	var kind, target, status string
	if err = tx.QueryRow(ctx, `SELECT operation_id::text,workload_id::text,plan_id::text,operation,plan_revision,plan_digest,target_kind,task_id::text,confirmation_id::text,status,revision,created_at,updated_at,dispatch_state,dispatch_attempt,dispatch_epoch,COALESCE(dispatch_claim::text,''),COALESCE(dispatch_lease_until,'epoch'::timestamptz) FROM core_workload_operations WHERE owner_id=$1 AND operation_id=$2 FOR UPDATE`, s.store.instanceID, id).Scan(&op.ID, &op.WorkloadID, &op.PlanID, &kind, &op.PlanRevision, &op.PlanDigest, &target, &op.TaskID, &op.ConfirmationID, &status, &op.Revision, &op.CreatedAt, &op.UpdatedAt, &op.DispatchState, &op.DispatchAttempt, &op.DispatchEpoch, &op.DispatchClaim, &op.DispatchLeaseUntil); err != nil {
		return op, coretask.Task{}, coreworkload.ErrNotFound
	}
	op.Kind = coreworkload.OperationKind(kind)
	op.TargetKind = coreworkload.TargetKind(target)
	op.Status = coreworkload.OperationStatus(status)
	var cstate string
	var crev int64
	var expiresAt time.Time
	if err = tx.QueryRow(ctx, `SELECT state,revision,expires_at FROM core_confirmations WHERE confirmation_id=$1 FOR UPDATE`, confirmationID).Scan(&cstate, &crev, &expiresAt); err != nil {
		return op, coretask.Task{}, err
	}
	var bindingRaw []byte
	if err = tx.QueryRow(ctx, `SELECT binding_json FROM core_confirmations WHERE confirmation_id=$1`, confirmationID).Scan(&bindingRaw); err != nil {
		return op, coretask.Task{}, err
	}
	var actual coreconfirmation.Binding
	if err := json.Unmarshal(bindingRaw, &actual); err != nil {
		return op, coretask.Task{}, coreworkload.ErrInvalid
	}
	plan, pe := s.getPlanTx(ctx, tx, op.PlanID)
	if pe != nil {
		return op, coretask.Task{}, pe
	}
	expectedBinding := coreworkload.BindingForOperation(plan, op.WorkloadID, op.Kind)
	var currentRaw []byte
	if err = tx.QueryRow(ctx, `SELECT binding_json FROM core_confirmation_current_bindings WHERE operation_domain=$1 AND target_id=$2`, actual.OperationDomain, op.WorkloadID).Scan(&currentRaw); err != nil {
		return op, coretask.Task{}, coreworkload.ErrStale
	}
	var current coreconfirmation.Binding
	if err := json.Unmarshal(currentRaw, &current); err != nil {
		return op, coretask.Task{}, coreworkload.ErrInvalid
	}
	if op.ConfirmationID != confirmationID || op.PlanDigest != digest || op.Revision != expected || cstate != "confirmed" || !expiresAt.After(time.Now().UTC()) || !actual.Equal(expectedBinding) || !current.Equal(expectedBinding) {
		return op, coretask.Task{}, coreworkload.ErrRevisionConflict
	}
	now := time.Now().UTC()
	if _, err = tx.Exec(ctx, `UPDATE core_confirmations SET state='consumed',revision=revision+1,updated_at=$2 WHERE confirmation_id=$1`, confirmationID, now); err != nil {
		return op, coretask.Task{}, err
	}
	claim := uuid.New()
	tag, execErr := tx.Exec(ctx, `UPDATE core_workload_operations SET status='running',dispatch_state='dispatched',dispatch_attempt=dispatch_attempt+1,dispatch_epoch=dispatch_epoch+1,dispatch_claim=$3,dispatch_lease_until=$5,revision=revision+1,updated_at=$4 WHERE owner_id=$1 AND operation_id=$2 AND status='waiting_user' AND dispatch_state='prepared'`, s.store.instanceID, id, claim, now, now.Add(30*time.Second))
	if execErr != nil {
		return op, coretask.Task{}, execErr
	}
	if tag.RowsAffected() != 1 {
		return op, coretask.Task{}, coreworkload.ErrRevisionConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE core_tasks SET status='running',attempt=1,lease_epoch=1,lease_holder='workload-handler',lease_expires_at=$2,revision=revision+1,updated_at=$2 WHERE task_id=$1`, op.TaskID, now.Add(time.Hour)); err != nil {
		return op, coretask.Task{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_workload_events(owner_id,operation_id,sequence,kind,status,at) SELECT $1,$2,COALESCE(MAX(sequence),0)+1,'consumed','running',$3 FROM core_workload_events WHERE owner_id=$1 AND operation_id=$2`, s.store.instanceID, id, now); err != nil {
		return op, coretask.Task{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return op, coretask.Task{}, err
	}
	op.Status = coreworkload.OperationRunning
	op.Revision++
	op.UpdatedAt = now
	op.DispatchState = "dispatched"
	op.DispatchAttempt++
	op.DispatchEpoch++
	op.DispatchClaim = claim.String()
	op.DispatchLeaseUntil = now.Add(30 * time.Second)
	return op, coretask.Task{ID: op.TaskID, Status: coretask.StatusRunning, Revision: 2, Attempt: 1, LeaseEpoch: 1, Lease: &coretask.Lease{TaskID: op.TaskID, Attempt: 1, Epoch: 1, Holder: "workload-handler", ExpiresAt: now.Add(time.Hour)}}, nil
}
func (s *CoreWorkloadStore) AppendEvent(ctx context.Context, id string, e coreworkload.Event) (coreworkload.Event, error) {
	if !coreworkload.ValidUUID(id) {
		return coreworkload.Event{}, coreworkload.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return e, err
	}
	defer tx.Rollback(ctx)
	if err = tx.QueryRow(ctx, `SELECT operation_id FROM core_workload_operations WHERE owner_id=$1 AND operation_id=$2 FOR UPDATE`, s.store.instanceID, id).Scan(new(string)); err != nil {
		return e, err
	}
	var seq uint64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM core_workload_events WHERE owner_id=$1 AND operation_id=$2`, s.store.instanceID, id).Scan(&seq); err != nil {
		return e, err
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	e.OperationID = id
	e.Sequence = seq
	if _, err := tx.Exec(ctx, `INSERT INTO core_workload_events(owner_id,operation_id,sequence,kind,status,message,readback_json,at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, s.store.instanceID, id, seq, e.Kind, string(e.Status), e.Message, e.Readback, e.At); err != nil {
		return coreworkload.Event{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreworkload.Event{}, err
	}
	return e, nil
}
func (s *CoreWorkloadStore) CompleteDispatch(ctx context.Context, id, taskID, claim string, epoch uint64, code string, readback coreworkload.Readback, summary string) (coreworkload.Operation, coretask.Task, error) {
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreworkload.Operation{}, coretask.Task{}, err
	}
	defer tx.Rollback(ctx)
	var op coreworkload.Operation
	var kind, target, statusNow string
	err = tx.QueryRow(ctx, `SELECT operation_id::text,workload_id::text,plan_id::text,operation,plan_revision,plan_digest,target_kind,task_id::text,confirmation_id::text,status,revision,created_at,updated_at,failure_code,failure_summary,dispatch_state,dispatch_attempt,dispatch_epoch,COALESCE(dispatch_claim::text,''),COALESCE(dispatch_lease_until,'epoch'::timestamptz),completion_fingerprint FROM core_workload_operations WHERE owner_id=$1 AND operation_id=$2 FOR UPDATE`, s.store.instanceID, id).Scan(&op.ID, &op.WorkloadID, &op.PlanID, &kind, &op.PlanRevision, &op.PlanDigest, &target, &op.TaskID, &op.ConfirmationID, &statusNow, &op.Revision, &op.CreatedAt, &op.UpdatedAt, &op.FailureCode, &op.FailureSummary, &op.DispatchState, &op.DispatchAttempt, &op.DispatchEpoch, &op.DispatchClaim, &op.DispatchLeaseUntil, &op.CompletionFingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return op, coretask.Task{}, coreworkload.ErrNotFound
	}
	if err != nil {
		return op, coretask.Task{}, err
	}
	op.Kind = coreworkload.OperationKind(kind)
	op.TargetKind = coreworkload.TargetKind(target)
	op.Status = coreworkload.OperationStatus(statusNow)
	if op.TaskID != taskID {
		return op, coretask.Task{}, coreworkload.ErrRevisionConflict
	}
	var taskRevision int64
	var taskStatus, holder string
	var leaseEpoch int64
	var taskLeaseUntil *time.Time
	var taskAttempt int
	var resultRaw []byte
	var failureCode, failureSummary string
	if err = tx.QueryRow(ctx, `SELECT revision,status,lease_holder,lease_epoch,lease_expires_at,attempt,result_json,failure_code,failure_summary FROM core_tasks WHERE task_id=$1 FOR UPDATE`, taskID).Scan(&taskRevision, &taskStatus, &holder, &leaseEpoch, &taskLeaseUntil, &taskAttempt, &resultRaw, &failureCode, &failureSummary); err != nil {
		return op, coretask.Task{}, err
	}
	fingerprint := coreworkload.CompletionFingerprint(code, readback)
	if op.Status != coreworkload.OperationRunning {
		if claim == "" || claim != op.DispatchClaim || epoch != op.DispatchEpoch || fingerprint != op.CompletionFingerprint || (op.Status != coreworkload.OperationSucceeded && op.Status != coreworkload.OperationFailed && op.Status != coreworkload.OperationUncertain) {
			return op, coretask.Task{}, coreworkload.ErrRevisionConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return op, coretask.Task{}, err
		}
		// Replay must use precisely the same authoritative post-commit loader as
		// first completion.  Even equivalent in-transaction scans can differ in
		// NULL/empty and driver-owned nested representations.
		fullTask, loadErr := NewCoreTaskStore(s.store).GetTask(ctx, taskID)
		if loadErr != nil {
			return op, coretask.Task{}, loadErr
		}
		return op, fullTask, nil
	}
	if claim == "" || claim != op.DispatchClaim || epoch != op.DispatchEpoch || !op.DispatchLeaseUntil.After(time.Now().UTC()) || taskStatus != "running" || holder != "workload-handler" || leaseEpoch != int64(epoch) || taskLeaseUntil == nil || !taskLeaseUntil.After(time.Now().UTC()) {
		return op, coretask.Task{}, coreworkload.ErrRevisionConflict
	}
	now := time.Now().UTC()
	readback = coreworkload.SanitizeReadback(readback)
	if code == "" {
		plan, planErr := s.getPlanTx(ctx, tx, op.PlanID)
		if planErr != nil || plan.Digest != op.PlanDigest || plan.Revision != op.PlanRevision || readback.WorkloadID != op.WorkloadID || readback.TargetKind != op.TargetKind || readback.Identity.Validate(op.TargetKind) != nil || !workloadTargetIdentityEqual(readback.Identity, plan.Target.Identity, op.TargetKind) || (op.Kind == coreworkload.OperationApply && readback.State != "ready") || (op.Kind == coreworkload.OperationDestroy && readback.State != "destroyed") {
			return op, coretask.Task{}, coreworkload.ErrRevisionConflict
		}
	}
	if readback.Digest == "" {
		readback.Digest = coreworkload.ReadbackDigest(readback)
	}
	rb, err := json.Marshal(readback)
	if err != nil {
		return op, coretask.Task{}, err
	}
	status := "succeeded"
	if code != "" {
		status = "failed"
		if code == "provider_uncertain" {
			status = "uncertain"
		}
	}
	dispatchState := "terminal"
	if status == "uncertain" {
		dispatchState = "uncertain"
	}
	safeCode, safeSummary := coreworkload.SafeFailure(code, summary)
	tag, err := tx.Exec(ctx, `UPDATE core_workload_operations SET status=$3,dispatch_state=$4,dispatch_lease_until=NULL,dispatch_error=$5,completion_fingerprint=$6,completion_result_json=$7,revision=revision+1,failure_code=$8,failure_summary=$9,updated_at=$10 WHERE owner_id=$1 AND operation_id=$2 AND status='running' AND revision=$11 AND dispatch_claim=$12::uuid AND dispatch_epoch=$13 AND dispatch_lease_until>$14`, s.store.instanceID, id, status, dispatchState, safeSummary, fingerprint, rb, safeCode, safeSummary, now, op.Revision, claim, epoch, now)
	if err != nil {
		return op, coretask.Task{}, err
	}
	if tag.RowsAffected() != 1 {
		return op, coretask.Task{}, coreworkload.ErrRevisionConflict
	}
	if status == "succeeded" {
		var taskTag pgconn.CommandTag
		taskTag, err = tx.Exec(ctx, `UPDATE core_tasks SET status='succeeded',result_json=$2,revision=revision+1,lease_holder='',lease_epoch=0,lease_expires_at=NULL,updated_at=$3 WHERE task_id=$1 AND revision=$4 AND (status='running' OR (status='failed' AND failure_code='provider_uncertain'))`, taskID, rb, now, taskRevision)
		if err != nil {
			return op, coretask.Task{}, err
		}
		if taskTag.RowsAffected() != 1 {
			return op, coretask.Task{}, coreworkload.ErrRevisionConflict
		}
	} else {
		var taskTag pgconn.CommandTag
		taskTag, err = tx.Exec(ctx, `UPDATE core_tasks SET status='failed',failure_code=$2,failure_summary=$3,revision=revision+1,lease_holder='',lease_epoch=0,lease_expires_at=NULL,updated_at=$4 WHERE task_id=$1 AND revision=$5 AND (status='running' OR (status='failed' AND failure_code='provider_uncertain'))`, taskID, safeCode, safeSummary, now, taskRevision)
		if err != nil {
			return op, coretask.Task{}, err
		}
		if taskTag.RowsAffected() != 1 {
			return op, coretask.Task{}, coreworkload.ErrRevisionConflict
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_workload_events(owner_id,operation_id,sequence,kind,status,message,readback_json,at) SELECT $1,$2,COALESCE(MAX(sequence),0)+1,'terminal',$3,$4,$5,$6 FROM core_workload_events WHERE owner_id=$1 AND operation_id=$2`, s.store.instanceID, id, status, safeSummary, rb, now); err != nil {
		return op, coretask.Task{}, err
	}
	state := "failed"
	if status == "uncertain" {
		state = "uncertain"
	}
	if status == "succeeded" {
		if op.Kind == coreworkload.OperationDestroy {
			state = "destroyed"
		} else {
			state = "ready"
		}
	}
	actualRaw, marshalErr := json.Marshal(coreworkload.ActualSnapshot{WorkloadID: op.WorkloadID, Revision: uint64(op.Revision), State: state, Identity: readback.Identity, AppliedPlanID: op.PlanID, AppliedPlanDigest: op.PlanDigest, ReadbackDigest: readback.Digest, ProviderVersion: readback.ProviderVersion, ObservedAt: readback.At, UpdatedAt: now})
	if marshalErr != nil {
		return op, coretask.Task{}, marshalErr
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_workloads(workload_id,owner_id,revision,plan_id,plan_digest,target_kind,state,actual_snapshot_json,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8) ON CONFLICT(owner_id,workload_id) DO UPDATE SET revision=core_workloads.revision+1,plan_id=EXCLUDED.plan_id,plan_digest=EXCLUDED.plan_digest,target_kind=EXCLUDED.target_kind,state=EXCLUDED.state,actual_snapshot_json=EXCLUDED.actual_snapshot_json,updated_at=EXCLUDED.updated_at`, op.WorkloadID, s.store.instanceID, op.PlanID, op.PlanDigest, string(op.TargetKind), state, actualRaw, now); err != nil {
		return op, coretask.Task{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_confirmations SET consumed_released=true,updated_at=$2 WHERE confirmation_id=$1 AND state='consumed'`, op.ConfirmationID, now); err != nil {
		return op, coretask.Task{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return op, coretask.Task{}, err
	}
	// Return the same normalized projections as the replay path.  In
	// particular this includes DB-owned lease, timestamps, result and updated
	// revision fields; constructing a partial value here made first completion
	// observably differ from its idempotent replay.
	completed, getErr := s.GetOperation(ctx, id)
	if getErr != nil {
		return coreworkload.Operation{}, coretask.Task{}, getErr
	}
	terminalTask, getErr := NewCoreTaskStore(s.store).GetTask(ctx, taskID)
	if getErr != nil {
		return coreworkload.Operation{}, coretask.Task{}, getErr
	}
	return completed, terminalTask, nil
}

func workloadTargetIdentityEqual(actual, desired coreworkload.TargetIdentity, kind coreworkload.TargetKind) bool {
	if actual.Kind == "" {
		actual.Kind = kind
	}
	if desired.Kind == "" {
		desired.Kind = kind
	}
	return actual == desired
}

// RecoverClaim fences an already dispatched operation for read-only
// reconciliation. A recovery claim never increments dispatch_attempt and is
// serialized with Complete by the operation row lock.
func (s *CoreWorkloadStore) RecoverClaim(ctx context.Context, id, requestedClaim string) (coreworkload.Operation, error) {
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreworkload.Operation{}, err
	}
	defer tx.Rollback(ctx)
	var op coreworkload.Operation
	var kind, target, status string
	if err = tx.QueryRow(ctx, `SELECT operation_id::text,workload_id::text,plan_id::text,operation,plan_revision,plan_digest,target_kind,task_id::text,confirmation_id::text,status,revision,created_at,updated_at,dispatch_state,dispatch_attempt,dispatch_epoch,COALESCE(dispatch_claim::text,''),COALESCE(dispatch_lease_until,'epoch'::timestamptz) FROM core_workload_operations WHERE owner_id=$1 AND operation_id=$2 FOR UPDATE`, s.store.instanceID, id).Scan(&op.ID, &op.WorkloadID, &op.PlanID, &kind, &op.PlanRevision, &op.PlanDigest, &target, &op.TaskID, &op.ConfirmationID, &status, &op.Revision, &op.CreatedAt, &op.UpdatedAt, &op.DispatchState, &op.DispatchAttempt, &op.DispatchEpoch, &op.DispatchClaim, &op.DispatchLeaseUntil); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return op, coreworkload.ErrNotFound
		}
		return op, err
	}
	op.Kind, op.TargetKind, op.Status = coreworkload.OperationKind(kind), coreworkload.TargetKind(target), coreworkload.OperationStatus(status)
	now := time.Now().UTC()
	if requestedClaim != "" && requestedClaim == op.DispatchClaim && op.DispatchLeaseUntil.After(now) && op.DispatchState != "dispatched" {
		return op, nil
	}
	if op.Status == coreworkload.OperationRunning && op.DispatchState == "dispatched" && op.DispatchClaim != "" && op.DispatchLeaseUntil.After(now) {
		return op, coreworkload.ErrRevisionConflict
	}
	if op.Status == coreworkload.OperationRunning && op.DispatchState == "uncertain" && op.DispatchClaim != "" && op.DispatchLeaseUntil.After(now) {
		return op, coreworkload.ErrRevisionConflict
	}
	if op.Status != coreworkload.OperationRunning || (op.DispatchState != "dispatched" && op.DispatchState != "uncertain") {
		return op, nil
	}
	claim := uuid.New()
	tag, err := tx.Exec(ctx, `UPDATE core_workload_operations SET dispatch_state='uncertain',dispatch_claim=$3,dispatch_lease_until=$4,dispatch_epoch=dispatch_epoch+1,revision=revision+1,updated_at=clock_timestamp() WHERE owner_id=$1 AND operation_id=$2 AND ((status='running' AND dispatch_state='dispatched') OR (status='running' AND dispatch_state='uncertain' AND dispatch_lease_until <= $5) OR (status='uncertain' AND dispatch_state='uncertain' AND (COALESCE(dispatch_claim::text,'')='' OR dispatch_lease_until <= $5))) AND revision=$6`, s.store.instanceID, id, claim, now.Add(30*time.Second), now, op.Revision)
	if err != nil {
		return op, err
	}
	if tag.RowsAffected() != 1 {
		return op, coreworkload.ErrRevisionConflict
	}
	// The generic task lease is a second live fence.  A recovery claimant must
	// advance it in the same transaction and to the exact operation epoch;
	// otherwise CompleteDispatch can accept neither the new claimant nor reject
	// the stale one deterministically.
	taskTag, err := tx.Exec(ctx, `UPDATE core_tasks SET attempt=$2,lease_epoch=$3,lease_holder='workload-handler',lease_expires_at=$4,revision=revision+1,updated_at=$5 WHERE task_id=$1 AND status='running' AND lease_holder='workload-handler'`, op.TaskID, op.DispatchAttempt, op.DispatchEpoch+1, now.Add(30*time.Second), now)
	if err != nil {
		return op, err
	}
	if taskTag.RowsAffected() != 1 {
		return op, coreworkload.ErrRevisionConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_workload_events(owner_id,operation_id,sequence,kind,status,message,at) SELECT $1,$2,COALESCE(MAX(sequence),0)+1,'recovery_claim','running','read-only recovery claimed dispatch fence',$3 FROM core_workload_events WHERE owner_id=$1 AND operation_id=$2`, s.store.instanceID, id, now); err != nil {
		return op, err
	}
	if err = tx.Commit(ctx); err != nil {
		return op, err
	}
	op.DispatchState, op.DispatchEpoch, op.DispatchClaim, op.DispatchLeaseUntil, op.Revision, op.UpdatedAt = "uncertain", op.DispatchEpoch+1, claim.String(), now.Add(30*time.Second), op.Revision+1, now
	return op, nil
}
