package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *CoreConfirmationStore) Request(ctx context.Context, c coreconfirmation.RequestCommand) (coreconfirmation.Confirmation, error) {
	b, e := c.Binding.Normalize()
	if e != nil || c.ExpiresAt.IsZero() || !c.ExpiresAt.After(c.At.UTC()) {
		return coreconfirmation.Confirmation{}, coreconfirmation.ErrInvalid
	}
	tx, e := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return coreconfirmation.Confirmation{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, `confirmation:request:`+c.IdempotencyKey); e != nil {
		return coreconfirmation.Confirmation{}, e
	}
	if old, ok, e := s.replay(ctx, tx, "request", c.IdempotencyKey, c.RequestDigest); ok || e != nil {
		return old, e
	}
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, `confirmation:target:`+b.OperationDomain+":"+b.TargetID); e != nil {
		return coreconfirmation.Confirmation{}, e
	}
	var currentRaw []byte
	if e = tx.QueryRow(ctx, `SELECT binding_json FROM core_confirmation_current_bindings WHERE operation_domain=$1 AND target_id=$2 FOR UPDATE`, b.OperationDomain, b.TargetID).Scan(&currentRaw); e != nil {
		return coreconfirmation.Confirmation{}, coreconfirmation.ErrBindingUnavailable
	}
	var current coreconfirmation.Binding
	if json.Unmarshal(currentRaw, &current) != nil || !b.Equal(current) {
		return coreconfirmation.Confirmation{}, coreconfirmation.ErrStale
	}
	var taskStatus string
	if e = tx.QueryRow(ctx, `SELECT status FROM core_tasks WHERE task_id=$1 FOR UPDATE`, c.TaskID).Scan(&taskStatus); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return coreconfirmation.Confirmation{}, coreconfirmation.ErrNotFound
		}
		return coreconfirmation.Confirmation{}, e
	}
	if taskStatus != "waiting_user" {
		return coreconfirmation.Confirmation{}, coreconfirmation.ErrConflict
	}
	var n int
	if e = tx.QueryRow(ctx, `SELECT count(*) FROM core_confirmations WHERE operation_domain=$1 AND target_id=$2 AND (state IN ('pending','confirmed') OR (state='consumed' AND consumed_released=false))`, b.OperationDomain, b.TargetID).Scan(&n); e != nil {
		return coreconfirmation.Confirmation{}, e
	}
	if n > 0 {
		return coreconfirmation.Confirmation{}, coreconfirmation.ErrConflict
	}
	now := c.At.UTC()
	id := uuid.New()
	raw, e := bindingJSON(b)
	if e != nil {
		return coreconfirmation.Confirmation{}, coreconfirmation.ErrInvalid
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_confirmations(confirmation_id,operation_domain,target_id,target_revision,binding_json,task_id,state,revision,created_at,updated_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,'pending',1,$7,$7,$8)`, id, b.OperationDomain, b.TargetID, b.TargetRevision, raw, c.TaskID, now, c.ExpiresAt.UTC()); e != nil {
		return coreconfirmation.Confirmation{}, e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_confirmation_target_bindings(confirmation_id,binding_json) VALUES($1,$2)`, id, raw); e != nil {
		return coreconfirmation.Confirmation{}, e
	}
	c2 := coreconfirmation.Confirmation{ConfirmationID: id.String(), Binding: b, TaskID: c.TaskID, State: coreconfirmation.StatePending, Revision: 1, CreatedAt: now, UpdatedAt: now, ExpiresAt: c.ExpiresAt.UTC()}
	if e = s.putReplay(ctx, tx, "request", c.IdempotencyKey, c.RequestDigest, c2); e != nil {
		return coreconfirmation.Confirmation{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return coreconfirmation.Confirmation{}, e
	}
	return c2, nil
}
func (s *CoreConfirmationStore) Get(ctx context.Context, id string) (coreconfirmation.Confirmation, error) {
	c, e := scanConfirmation(s.store.pool.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1`, id))
	if errors.Is(e, pgx.ErrNoRows) {
		e = coreconfirmation.ErrNotFound
	}
	return c, e
}
func (s *CoreConfirmationStore) List(ctx context.Context, q coreconfirmation.ListQuery) (coreconfirmation.Page, error) {
	lim := q.PageSize
	if lim == 0 {
		lim = 50
	}
	if lim < 0 || lim > 100 {
		return coreconfirmation.Page{}, coreconfirmation.ErrInvalid
	}
	states := make([]string, 0, len(q.States))
	for _, st := range q.States {
		states = append(states, string(st))
	}
	sort.Strings(states)
	filter := q.Domain + "\x00" + q.TargetID + "\x00" + strings.Join(states, ",")
	var ct time.Time
	var cid string
	if q.PageToken != "" {
		raw, e := base64.RawURLEncoding.DecodeString(q.PageToken)
		if e != nil {
			return coreconfirmation.Page{}, coreconfirmation.ErrInvalid
		}
		var cur struct{ Filter, Time, ID string }
		if json.Unmarshal(raw, &cur) != nil || cur.Filter != filter || cur.Time == "" || cur.ID == "" {
			return coreconfirmation.Page{}, coreconfirmation.ErrInvalid
		}
		ct, _ = time.Parse(time.RFC3339Nano, cur.Time)
		cid = cur.ID
		if ct.IsZero() {
			return coreconfirmation.Page{}, coreconfirmation.ErrInvalid
		}
	}
	where := []string{"TRUE"}
	args := []any{}
	add := func(sql string, v any) { args = append(args, v); where = append(where, fmt.Sprintf(sql, len(args))) }
	if q.Domain != "" {
		add("operation_domain=$%d", q.Domain)
	}
	if q.TargetID != "" {
		add("target_id=$%d", q.TargetID)
	}
	if len(states) > 0 {
		ph := make([]string, len(states))
		for i, st := range states {
			args = append(args, st)
			ph[i] = fmt.Sprintf("$%d", len(args))
		}
		where = append(where, "state IN ("+strings.Join(ph, ",")+")")
	}
	if !ct.IsZero() {
		args = append(args, ct, cid)
		where = append(where, fmt.Sprintf("(created_at,confirmation_id) > ($%d,$%d)", len(args)-1, len(args)))
	}
	rows, e := s.store.pool.Query(ctx, confirmationSelect+` WHERE `+strings.Join(where, " AND ")+` ORDER BY created_at,confirmation_id LIMIT `+fmt.Sprint(lim+1), args...)
	if e != nil {
		return coreconfirmation.Page{}, e
	}
	defer rows.Close()
	out := []coreconfirmation.Confirmation{}
	for rows.Next() {
		c, e := scanConfirmation(rows)
		if e != nil {
			return coreconfirmation.Page{}, e
		}
		out = append(out, c)
	}
	if e = rows.Err(); e != nil {
		return coreconfirmation.Page{}, e
	}
	next := ""
	if len(out) > lim {
		last := out[lim-1]
		out = out[:lim]
		b, _ := json.Marshal(struct{ Filter, Time, ID string }{filter, last.CreatedAt.Format(time.RFC3339Nano), last.ConfirmationID})
		next = base64.RawURLEncoding.EncodeToString(b)
	}
	return coreconfirmation.Page{Confirmations: out, NextPageToken: next}, nil
}

func (s *CoreConfirmationStore) Confirm(ctx context.Context, c coreconfirmation.ConfirmCommand) (coreconfirmation.Confirmation, error) {
	tx, e := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return coreconfirmation.Confirmation{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, `confirmation:confirm:`+c.IdempotencyKey); e != nil {
		return coreconfirmation.Confirmation{}, e
	}
	if old, ok, e := s.replay(ctx, tx, "confirm", c.IdempotencyKey, c.RequestDigest); ok || e != nil {
		if !ok || e != nil || old.State != coreconfirmation.StateConfirmed {
			return old, e
		}
		// A confirmation replay is valid only while the durable confirmation
		// still owns the confirmed state. Task cancellation can compensate a
		// previously confirmed confirmation after its replay was written; in
		// that case returning the old success would resurrect terminal work.
		var state coreconfirmation.State
		if e = tx.QueryRow(ctx, `SELECT state FROM core_confirmations WHERE confirmation_id=$1 FOR UPDATE`, old.ConfirmationID).Scan(&state); e != nil {
			return old, e
		}
		if state != coreconfirmation.StateConfirmed {
			return old, coreconfirmation.ErrConflict
		}
		return old, nil
	}
	cur, e := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1`, c.ConfirmationID))
	if errors.Is(e, pgx.ErrNoRows) {
		return cur, coreconfirmation.ErrNotFound
	}
	if e != nil {
		return cur, e
	}
	var ts string
	var deadline *time.Time
	if e = tx.QueryRow(ctx, `SELECT status,execution_deadline_at FROM core_tasks WHERE task_id=$1 FOR UPDATE`, cur.TaskID).Scan(&ts, &deadline); e != nil {
		return cur, coreconfirmation.ErrNotFound
	}
	cur, e = scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, c.ConfirmationID))
	if e != nil {
		return cur, e
	}
	if cur.Revision != c.ExpectedRevision {
		return cur, coreconfirmation.ErrRevisionConflict
	}
	if cur.State != coreconfirmation.StatePending {
		return cur, coreconfirmation.ErrConflict
	}
	if deadline != nil && !deadline.After(c.At.UTC()) {
		return s.expireReplay(ctx, tx, cur, "confirm", c, "task_timed_out")
	}
	if !cur.ExpiresAt.After(c.At.UTC()) {
		return s.expireReplay(ctx, tx, cur, "confirm", c, coreconfirmation.ReasonExpired)
	}
	if ts != "waiting_user" {
		return cur, coreconfirmation.ErrConflict
	}
	matches, bindingErr := confirmationBindingMatchesTx(ctx, tx, cur, c.ResolveBinding, c.At)
	if bindingErr != nil {
		return cur, bindingErr
	}
	if !matches {
		return s.staleAndReplay(ctx, tx, cur, "confirm", c.IdempotencyKey, c.RequestDigest, c.At.UTC())
	}
	if _, e = tx.Exec(ctx, `UPDATE core_confirmations SET state='confirmed',revision=revision+1,updated_at=$2 WHERE confirmation_id=$1`, c.ConfirmationID, c.At.UTC()); e != nil {
		return cur, e
	}
	// Workload confirmations are consumed by the fenced Workload handler;
	// confirming only changes approval state and must not enqueue or execute.
	if !strings.HasPrefix(cur.Binding.OperationDomain, "workload:") {
		if _, e = tx.Exec(ctx, `UPDATE core_tasks SET status='queued',available_at=$2,revision=revision+1,progress_sequence=progress_sequence+1,updated_at=$2 WHERE task_id=$1 AND status='waiting_user'`, cur.TaskID, c.At.UTC()); e != nil {
			return cur, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) SELECT task_id,progress_sequence,$2,attempt,'queued','confirmation_confirmed','confirmation confirmed',$3 FROM core_tasks WHERE task_id=$1`, cur.TaskID, uuid.New(), c.At.UTC()); e != nil {
			return cur, e
		}
	}
	if e = projectAWSConfirmationTx(ctx, tx, cur, "running", "confirmed", "", "", "confirmed", c.At.UTC()); e != nil {
		return cur, e
	}
	cur.State, cur.Revision, cur.UpdatedAt = coreconfirmation.StateConfirmed, cur.Revision+1, c.At.UTC()
	if e = s.putReplay(ctx, tx, "confirm", c.IdempotencyKey, c.RequestDigest, cur); e != nil {
		return cur, e
	}
	if e = tx.Commit(ctx); e != nil {
		return cur, e
	}
	return cur, nil
}
func (s *CoreConfirmationStore) Reject(ctx context.Context, c coreconfirmation.RejectCommand) (coreconfirmation.Confirmation, error) {
	tx, e := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return coreconfirmation.Confirmation{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, `confirmation:reject:`+c.IdempotencyKey); e != nil {
		return coreconfirmation.Confirmation{}, e
	}
	if old, ok, e := s.replay(ctx, tx, "reject", c.IdempotencyKey, c.RequestDigest); ok || e != nil {
		return old, e
	}
	cur, e := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1`, c.ConfirmationID))
	if errors.Is(e, pgx.ErrNoRows) {
		return cur, coreconfirmation.ErrNotFound
	}
	if e != nil {
		return cur, e
	}
	var ts string
	var deadline *time.Time
	if e = tx.QueryRow(ctx, `SELECT status,execution_deadline_at FROM core_tasks WHERE task_id=$1 FOR UPDATE`, cur.TaskID).Scan(&ts, &deadline); e != nil {
		return cur, coreconfirmation.ErrNotFound
	}
	cur, e = scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, c.ConfirmationID))
	if e != nil {
		return cur, e
	}
	if cur.Revision != c.ExpectedRevision {
		return cur, coreconfirmation.ErrRevisionConflict
	}
	if cur.State != coreconfirmation.StatePending {
		return cur, coreconfirmation.ErrConflict
	}
	if deadline != nil && !deadline.After(c.At.UTC()) {
		return s.expireReplay(ctx, tx, cur, "reject", c, "task_timed_out")
	}
	if ts != "waiting_user" {
		return cur, coreconfirmation.ErrConflict
	}
	if strings.HasPrefix(cur.Binding.OperationDomain, "workload:") {
		cur, e = terminalizeWorkloadBeforeDispatchTx(ctx, tx, s.store.instanceID, cur, "rejected", "rejected", "canceled", "user_rejected", strings.TrimSpace(c.Reason), c.At.UTC())
		if e != nil {
			return cur, e
		}
		if e = s.putReplay(ctx, tx, "reject", c.IdempotencyKey, c.RequestDigest, cur); e != nil {
			return cur, e
		}
		if e = tx.Commit(ctx); e != nil {
			return cur, e
		}
		return cur, nil
	}
	if _, e = tx.Exec(ctx, `UPDATE core_confirmations SET state='rejected',revision=revision+1,updated_at=$2,terminal_code='user_rejected',terminal_reason='user_rejected',terminal_note=$3 WHERE confirmation_id=$1`, c.ConfirmationID, c.At.UTC(), strings.TrimSpace(c.Reason)); e != nil {
		return cur, e
	}
	if _, e = tx.Exec(ctx, `UPDATE core_tasks SET status='canceled',attempt=GREATEST(attempt,1),failure_code='user_rejected',revision=revision+1,updated_at=$2 WHERE task_id=$1 AND status='waiting_user'`, cur.TaskID, c.At.UTC()); e != nil {
		return cur, e
	}
	if _, e = tx.Exec(ctx, `UPDATE core_tasks SET progress_sequence=progress_sequence+1 WHERE task_id=$1`, cur.TaskID); e != nil {
		return cur, e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,error_code,occurred_at) SELECT task_id,progress_sequence,$2,attempt,'canceled','confirmation_rejected','confirmation rejected','user_rejected',$3 FROM core_tasks WHERE task_id=$1`, cur.TaskID, uuid.New(), c.At.UTC()); e != nil {
		return cur, e
	}
	if e = terminalizeConversationToolTx(ctx, tx, cur, "denied", coreconfirmation.ReasonUserRejected, c.At.UTC()); e != nil {
		return cur, e
	}
	if cur.Binding.OperationDomain == "extension" {
		if e = rollbackExtensionLifecycleTx(ctx, tx, cur.ConfirmationID); e != nil {
			return cur, e
		}
	}
	if e = projectAWSConfirmationTx(ctx, tx, cur, "canceled", "canceled", coreconfirmation.ReasonUserRejected, coreconfirmation.ReasonUserRejected, coreconfirmation.ReasonUserRejected, c.At.UTC()); e != nil {
		return cur, e
	}
	cur.State, cur.Revision, cur.UpdatedAt, cur.TerminalCode, cur.TerminalReason = coreconfirmation.StateRejected, cur.Revision+1, c.At.UTC(), coreconfirmation.ReasonUserRejected, coreconfirmation.ReasonUserRejected
	if e = s.putReplay(ctx, tx, "reject", c.IdempotencyKey, c.RequestDigest, cur); e != nil {
		return cur, e
	}
	if e = tx.Commit(ctx); e != nil {
		return cur, e
	}
	return cur, nil
}
func (s *CoreConfirmationStore) expireReplay(ctx context.Context, tx pgx.Tx, cur coreconfirmation.Confirmation, op string, c any, reason string) (coreconfirmation.Confirmation, error) {
	var key string
	var dig coreconfirmation.Digest
	var at time.Time
	switch x := c.(type) {
	case coreconfirmation.ConfirmCommand:
		key, dig, at = x.IdempotencyKey, x.RequestDigest, x.At.UTC()
	case coreconfirmation.RejectCommand:
		key, dig, at = x.IdempotencyKey, x.RequestDigest, x.At.UTC()
	}
	var e error
	cur, e = terminalizeExpiredTx(ctx, tx, s.store.instanceID, cur, at, reason)
	if e != nil {
		return cur, e
	}
	if e = s.putReplay(ctx, tx, op, key, dig, cur); e != nil {
		return cur, e
	}
	if e = tx.Commit(ctx); e != nil {
		return cur, e
	}
	return cur, coreconfirmation.ErrExpired
}

func (s *CoreConfirmationStore) Consume(ctx context.Context, c coreconfirmation.ConsumeCommand) (coreconfirmation.Confirmation, error) {
	tx, e := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return coreconfirmation.Confirmation{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, `confirmation:consume:`+c.IdempotencyKey); e != nil {
		return coreconfirmation.Confirmation{}, e
	}
	if old, ok, e := s.replay(ctx, tx, "consume", c.IdempotencyKey, c.RequestDigest); ok || e != nil {
		return old, e
	}
	cur, e := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1`, c.ConfirmationID))
	if errors.Is(e, pgx.ErrNoRows) {
		return cur, coreconfirmation.ErrNotFound
	}
	if e != nil {
		return cur, e
	}
	var status string
	var attempt int
	var epoch, rev int64
	var leaseExp *time.Time
	if e = tx.QueryRow(ctx, `SELECT status,attempt,lease_epoch,revision,lease_expires_at FROM core_tasks WHERE task_id=$1 FOR UPDATE`, c.TaskID).Scan(&status, &attempt, &epoch, &rev, &leaseExp); e != nil {
		return cur, coreconfirmation.ErrTaskFenceConflict
	}
	cur, e = scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, c.ConfirmationID))
	if e != nil {
		return cur, e
	}
	if cur.State != coreconfirmation.StateConfirmed || cur.Revision != c.ExpectedRevision || cur.TaskID != c.TaskID {
		return cur, coreconfirmation.ErrTaskFenceConflict
	}
	if !cur.ExpiresAt.After(c.At.UTC()) {
		cur, e = terminalizeExpiredTx(ctx, tx, s.store.instanceID, cur, c.At.UTC(), coreconfirmation.ReasonExpired)
		if e != nil {
			return cur, e
		}
		if e = s.putReplay(ctx, tx, "consume", c.IdempotencyKey, c.RequestDigest, cur); e != nil {
			return cur, e
		}
		if e = tx.Commit(ctx); e != nil {
			return cur, e
		}
		return cur, coreconfirmation.ErrExpired
	}
	if status != "running" || attempt != int(c.Attempt) || epoch != int64(c.LeaseEpoch) || rev != c.ExpectedTaskRevision || leaseExp == nil || !leaseExp.After(c.At.UTC()) {
		return cur, coreconfirmation.ErrTaskFenceConflict
	}
	matches, bindingErr := confirmationBindingMatchesTx(ctx, tx, cur, c.ResolveBinding, c.At)
	if bindingErr != nil {
		return cur, bindingErr
	}
	if !matches {
		return s.staleAndReplay(ctx, tx, cur, "consume", c.IdempotencyKey, c.RequestDigest, c.At.UTC())
	}
	if _, e = tx.Exec(ctx, `UPDATE core_confirmations SET state='consumed',revision=revision+1,updated_at=$2 WHERE confirmation_id=$1`, c.ConfirmationID, c.At.UTC()); e != nil {
		return cur, e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_confirmation_reservations(confirmation_id,task_id,acquired_attempt,acquired_lease_epoch,task_revision,active) VALUES($1,$2,$3,$4,$5,true) ON CONFLICT (confirmation_id) DO UPDATE SET active=true,task_id=EXCLUDED.task_id,acquired_attempt=EXCLUDED.acquired_attempt,acquired_lease_epoch=EXCLUDED.acquired_lease_epoch,task_revision=EXCLUDED.task_revision`, c.ConfirmationID, c.TaskID, c.Attempt, c.LeaseEpoch, c.ExpectedTaskRevision); e != nil {
		return cur, e
	}
	cur.State, cur.Revision, cur.UpdatedAt = coreconfirmation.StateConsumed, cur.Revision+1, c.At.UTC()
	if e = s.putReplay(ctx, tx, "consume", c.IdempotencyKey, c.RequestDigest, cur); e != nil {
		return cur, e
	}
	if e = tx.Commit(ctx); e != nil {
		return cur, e
	}
	return cur, nil
}
func (s *CoreConfirmationStore) Expire(ctx context.Context, c coreconfirmation.ExpireCommand) (coreconfirmation.Confirmation, error) {
	tx, e := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return coreconfirmation.Confirmation{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, `confirmation:expire:`+c.IdempotencyKey); e != nil {
		return coreconfirmation.Confirmation{}, e
	}
	if old, ok, e := s.replay(ctx, tx, "expire", c.IdempotencyKey, c.RequestDigest); ok || e != nil {
		return old, e
	}
	cur, e := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, c.ConfirmationID))
	if errors.Is(e, pgx.ErrNoRows) {
		return cur, coreconfirmation.ErrNotFound
	}
	if e != nil {
		return cur, e
	}
	if cur.Revision != c.ExpectedRevision || (cur.State != coreconfirmation.StatePending && cur.State != coreconfirmation.StateConfirmed) {
		return cur, coreconfirmation.ErrConflict
	}
	cur, e = terminalizeExpiredTx(ctx, tx, s.store.instanceID, cur, c.At.UTC(), c.Reason)
	if e != nil {
		return cur, e
	}
	if e = s.putReplay(ctx, tx, "expire", c.IdempotencyKey, c.RequestDigest, cur); e != nil {
		return cur, e
	}
	if e = tx.Commit(ctx); e != nil {
		return cur, e
	}
	return cur, nil
}
func (s *CoreConfirmationStore) ReleaseReservation(ctx context.Context, c coreconfirmation.ReleaseReservationCommand) (coreconfirmation.Confirmation, error) {
	tx, e := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return coreconfirmation.Confirmation{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, `confirmation:release:`+c.IdempotencyKey); e != nil {
		return coreconfirmation.Confirmation{}, e
	}
	if old, ok, e := s.replay(ctx, tx, "release", c.IdempotencyKey, c.RequestDigest); ok || e != nil {
		return old, e
	}
	cur, e := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, c.ConfirmationID))
	if errors.Is(e, pgx.ErrNoRows) {
		return cur, coreconfirmation.ErrNotFound
	}
	if e != nil {
		return cur, e
	}
	var taskID string
	var aa int
	var ae, trev int64
	var active bool
	if e = tx.QueryRow(ctx, `SELECT task_id,acquired_attempt,acquired_lease_epoch,task_revision,active FROM core_confirmation_reservations WHERE confirmation_id=$1 FOR UPDATE`, c.ConfirmationID).Scan(&taskID, &aa, &ae, &trev, &active); e != nil || cur.State != coreconfirmation.StateConsumed || !active || taskID != c.TaskID || aa != int(c.AcquiredAttempt) || ae != int64(c.AcquiredLeaseEpoch) || trev != c.ExpectedTaskRevision {
		return cur, coreconfirmation.ErrConflict
	}
	var ts string
	var ta int
	var te, tr int64
	if e = tx.QueryRow(ctx, `SELECT status,attempt,lease_epoch,revision FROM core_tasks WHERE task_id=$1 FOR UPDATE`, c.TaskID).Scan(&ts, &ta, &te, &tr); e != nil {
		return cur, coreconfirmation.ErrTaskFenceConflict
	}
	if ta != int(c.TerminalAttempt) || te != int64(c.TerminalLeaseEpoch) || tr < c.ExpectedTaskRevision || (ts != "succeeded" && ts != "failed" && ts != "canceled") {
		return cur, coreconfirmation.ErrTaskFenceConflict
	}
	if _, e = tx.Exec(ctx, `UPDATE core_confirmation_reservations SET active=false WHERE confirmation_id=$1`, c.ConfirmationID); e != nil {
		return cur, e
	}
	if _, e = tx.Exec(ctx, `UPDATE core_confirmations SET consumed_released=true,revision=revision+1,updated_at=clock_timestamp() WHERE confirmation_id=$1 AND state='consumed'`, c.ConfirmationID); e != nil {
		return cur, e
	}
	cur.Revision++
	if e = s.putReplay(ctx, tx, "release", c.IdempotencyKey, c.RequestDigest, cur); e != nil {
		return cur, e
	}
	if e = tx.Commit(ctx); e != nil {
		return cur, e
	}
	return cur, nil
}
