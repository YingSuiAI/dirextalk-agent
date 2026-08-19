package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CoreScheduleStore persists schedules, replay records, and occurrences in the
// same transaction boundary as their Core Tasks.
type CoreScheduleStore struct{ store *Store }

// LookupScheduleMutation is the read-before-patch replay gate used by RPC
// adapters. It returns the persisted response even when the live schedule was
// subsequently deleted.
func (s *CoreScheduleStore) LookupScheduleMutation(ctx context.Context, operation, key, digest string) (coretask.Schedule, bool, error) {
	var storedDigest string
	var raw []byte
	err := s.store.pool.QueryRow(ctx, `SELECT request_hash,response_json FROM core_schedule_replays WHERE operation=$1 AND idempotency_key=$2`, operation, key).Scan(&storedDigest, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return coretask.Schedule{}, false, coretask.ErrNotFound
	}
	if err != nil {
		return coretask.Schedule{}, false, err
	}
	if storedDigest != digest {
		return coretask.Schedule{}, false, coretask.ErrConflict
	}
	var schedule coretask.Schedule
	if json.Unmarshal(raw, &schedule) != nil {
		return coretask.Schedule{}, false, coretask.ErrInvalid
	}
	return schedule, true, nil
}

func NewCoreScheduleStore(s *Store) *CoreScheduleStore { return &CoreScheduleStore{store: s} }

func lockLiveScheduleProfileTx(ctx context.Context, tx pgx.Tx, profileID string) error {
	if profileID == "" {
		return nil
	}
	var lockedID string
	err := tx.QueryRow(ctx, `SELECT profile_id::text FROM core_model_profiles WHERE profile_id=$1 AND deleted_at IS NULL FOR SHARE`, profileID).Scan(&lockedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return coretask.ErrNotFound
	}
	if err != nil {
		return err
	}
	if lockedID != profileID {
		return coretask.ErrConflict
	}
	return nil
}

func (s *CoreScheduleStore) FindOccurrence(ctx context.Context, scheduleID, triggerKey string) (coretask.Occurrence, error) {
	if !coretask.ValidUUID(scheduleID) || !coretask.ValidUUID(triggerKey) {
		return coretask.Occurrence{}, coretask.ErrInvalid
	}
	var out coretask.Occurrence
	err := s.store.pool.QueryRow(ctx, `SELECT occurrence_id,schedule_id,scheduled_for,trigger_key,task_id,created_at FROM core_schedule_occurrences WHERE schedule_id=$1 AND trigger_key=$2`, scheduleID, triggerKey).Scan(&out.ID, &out.ScheduleID, &out.ScheduledFor, &out.TriggerKey, &out.TaskID, &out.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return coretask.Occurrence{}, coretask.ErrNotFound
	}
	if err != nil {
		return coretask.Occurrence{}, err
	}
	return out, nil
}

func (s *CoreScheduleStore) CreateOccurrence(ctx context.Context, schedule coretask.Schedule, command coretask.TriggerNowCommand, occurrence coretask.Occurrence) (coretask.Occurrence, error) {
	if schedule.Validate() != nil || !coretask.ValidUUID(command.ScheduleID) || !coretask.ValidUUID(command.IdempotencyKey) || occurrence.Validate() != nil || occurrence.ScheduleID != schedule.ID {
		return coretask.Occurrence{}, coretask.ErrInvalid
	}
	template, _ := json.Marshal(schedule.Spec)
	_, err := s.store.pool.Exec(ctx, `INSERT INTO core_schedule_occurrences(occurrence_id,schedule_id,scheduled_for,trigger_key,task_id,spec_snapshot_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (occurrence_id) DO NOTHING`, occurrence.ID, occurrence.ScheduleID, occurrence.ScheduledFor.UTC(), occurrence.TriggerKey, occurrence.TaskID, template, occurrence.CreatedAt.UTC())
	if err != nil {
		return coretask.Occurrence{}, coretask.ErrConflict
	}
	return occurrence, nil
}

func (s *CoreScheduleStore) GetOccurrence(ctx context.Context, id string) (coretask.Occurrence, error) {
	if !coretask.ValidUUID(id) {
		return coretask.Occurrence{}, coretask.ErrInvalid
	}
	var out coretask.Occurrence
	err := s.store.pool.QueryRow(ctx, `SELECT occurrence_id,schedule_id,scheduled_for,trigger_key,task_id,created_at FROM core_schedule_occurrences WHERE occurrence_id=$1`, id).Scan(&out.ID, &out.ScheduleID, &out.ScheduledFor, &out.TriggerKey, &out.TaskID, &out.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return coretask.Occurrence{}, coretask.ErrNotFound
	}
	if err != nil {
		return coretask.Occurrence{}, err
	}
	return out, nil
}

type occurrenceReader interface {
	ListOccurrences(context.Context, string, string, int) ([]coretask.Occurrence, string, error)
	GetOccurrence(context.Context, string) (coretask.Occurrence, error)
}

type scheduleOutputCursor struct {
	ScheduledFor string `json:"scheduled_for"`
	OccurrenceID string `json:"occurrence_id"`
}

// ListScheduleOutputs reads the occurrence order and authoritative Task state
// in one query. The descending tuple cursor is stable when multiple
// occurrences share the same scheduled time.
func (s *CoreScheduleStore) ListScheduleOutputs(ctx context.Context, scheduleID, token string, limit int) ([]coretask.ScheduleOutput, string, error) {
	if !coretask.ValidUUID(scheduleID) || limit <= 0 || limit > 200 || len(token) > 4096 {
		return nil, "", coretask.ErrInvalid
	}
	var before time.Time
	var beforeID string
	if token != "" {
		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			return nil, "", coretask.ErrInvalid
		}
		var cursor scheduleOutputCursor
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&cursor) != nil || decoder.Decode(&struct{}{}) == nil || cursor.ScheduledFor == "" || !coretask.ValidUUID(cursor.OccurrenceID) {
			return nil, "", coretask.ErrInvalid
		}
		before, err = time.Parse(time.RFC3339Nano, cursor.ScheduledFor)
		if err != nil || before.Location() != time.UTC || before.Format(time.RFC3339Nano) != cursor.ScheduledFor {
			return nil, "", coretask.ErrInvalid
		}
		beforeID = cursor.OccurrenceID
	}
	rows, err := s.store.pool.Query(ctx, `
		SELECT o.occurrence_id,o.schedule_id,o.task_id,o.scheduled_for,
		       t.status,t.result_json,COALESCE(t.failure_code,''),COALESCE(t.failure_summary,''),t.created_at,t.updated_at
		FROM core_schedule_occurrences o
		JOIN core_tasks t ON t.task_id=o.task_id
		WHERE o.schedule_id=$1
		  AND ($2::timestamptz IS NULL OR (o.scheduled_for,o.occurrence_id)<($2,$3::uuid))
		ORDER BY o.scheduled_for DESC,o.occurrence_id DESC
		LIMIT $4`, scheduleID, nullableScheduleTime(before), nullableScheduleUUID(beforeID), limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	outputs := make([]coretask.ScheduleOutput, 0, limit+1)
	for rows.Next() {
		var output coretask.ScheduleOutput
		var status string
		var resultRaw []byte
		if err := rows.Scan(&output.OccurrenceID, &output.ScheduleID, &output.TaskID, &output.ScheduledFor,
			&status, &resultRaw, &output.FailureCode, &output.FailureSummary, &output.CreatedAt, &output.UpdatedAt); err != nil {
			return nil, "", err
		}
		output.Status = coretask.Status(status)
		output.ScheduledFor, output.CreatedAt, output.UpdatedAt = output.ScheduledFor.UTC(), output.CreatedAt.UTC(), output.UpdatedAt.UTC()
		if len(resultRaw) != 0 {
			var result coretask.Result
			if json.Unmarshal(resultRaw, &result) != nil {
				return nil, "", coretask.ErrInvalid
			}
			output.Result = &result
		}
		if output.Validate() != nil {
			return nil, "", coretask.ErrInvalid
		}
		outputs = append(outputs, output)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(outputs) > limit {
		last := outputs[limit-1]
		outputs = outputs[:limit]
		raw, _ := json.Marshal(scheduleOutputCursor{ScheduledFor: last.ScheduledFor.Format(time.RFC3339Nano), OccurrenceID: last.OccurrenceID})
		next = base64.RawURLEncoding.EncodeToString(raw)
	}
	return outputs, next, nil
}

func (s *CoreScheduleStore) ListOccurrences(ctx context.Context, scheduleID, token string, limit int) ([]coretask.Occurrence, string, error) {
	if !coretask.ValidUUID(scheduleID) || limit <= 0 || limit > 200 {
		return nil, "", coretask.ErrInvalid
	}
	var after time.Time
	var afterID string
	if token != "" {
		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			return nil, "", coretask.ErrInvalid
		}
		var cursor struct{ Time, ID string }
		if json.Unmarshal(raw, &cursor) != nil || cursor.Time == "" || !coretask.ValidUUID(cursor.ID) {
			return nil, "", coretask.ErrInvalid
		}
		after, err = time.Parse(time.RFC3339Nano, cursor.Time)
		if err != nil {
			return nil, "", coretask.ErrInvalid
		}
		afterID = cursor.ID
	}
	rows, err := s.store.pool.Query(ctx, `SELECT occurrence_id,schedule_id,scheduled_for,COALESCE(trigger_key::text,''),task_id,created_at FROM core_schedule_occurrences WHERE schedule_id=$1 AND ($2::timestamptz IS NULL OR (scheduled_for,occurrence_id)>($2,$3::uuid)) ORDER BY scheduled_for,occurrence_id LIMIT $4`, scheduleID, nullableScheduleTime(after), nullableScheduleUUID(afterID), limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := make([]coretask.Occurrence, 0, limit+1)
	for rows.Next() {
		var value coretask.Occurrence
		if err := rows.Scan(&value.ID, &value.ScheduleID, &value.ScheduledFor, &value.TriggerKey, &value.TaskID, &value.CreatedAt); err != nil {
			return nil, "", err
		}
		out = append(out, value)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		last := out[limit-1]
		out = out[:limit]
		raw, _ := json.Marshal(struct{ Time, ID string }{last.ScheduledFor.UTC().Format(time.RFC3339Nano), last.ID})
		next = base64.RawURLEncoding.EncodeToString(raw)
	}
	return out, next, nil
}

func nullableScheduleTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func nullableScheduleUUID(value string) any {
	if value == "" {
		return nil
	}
	return uuid.MustParse(value)
}

// MaterializeNextDue locks exactly one due schedule. The occurrence and its
// task are committed with the cursor so crash recovery can safely retry. The
// returned boolean is false when no schedule was due; callers can use it to
// drain all due schedules without conflating an empty queue with an error.
func (s *CoreScheduleStore) MaterializeNextDue(ctx context.Context, now time.Time, calc coretask.CronCalculator) (bool, error) {
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var id string
	err = tx.QueryRow(ctx, `SELECT schedule_id FROM core_schedules WHERE deleted_at IS NULL AND paused=false AND next_run_at <= $1 ORDER BY next_run_at,schedule_id FOR UPDATE SKIP LOCKED LIMIT 1`, now.UTC()).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			return false, err
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	schedule, err := s.coreScheduleTx(ctx, tx, id, false)
	if err != nil {
		return false, err
	}
	due := schedule.NextRunAt.UTC()
	if schedule.Cron != "" {
		for {
			next, e := calc.Next(due, schedule.Cron, schedule.Timezone)
			if e != nil {
				return false, e
			}
			if next.After(now.UTC()) {
				break
			}
			due = next.UTC()
		}
	}
	occID := coretaskDeterministic(schedule.ID + ":scheduled:" + due.Format(time.RFC3339Nano))
	taskID := coretaskDeterministic(occID + ":task")
	spec, err := schedule.Spec.Materialize(coretaskDeterministic(occID+":idempotency"), due)
	if err != nil {
		return false, err
	}
	tpl, _ := json.Marshal(schedule.Spec)
	att, ext, know := coreTaskJSONBytes(spec.AttachmentRefs), coreTaskJSONBytes(spec.Extensions), coreTaskJSONBytes(spec.KnowledgeRefs)
	payload, _ := json.Marshal(spec.Payload)
	snapshot, err := resolveTaskSnapshotTx(ctx, tx, spec)
	if err != nil {
		return false, err
	}
	snapshotRaw, _ := json.Marshal(snapshot)
	if _, err = tx.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,conversation_id,model_profile_id,create_idempotency_key,attachment_refs,extensions_json,knowledge_refs,timeout_seconds,status,progress_sequence,available_at,revision,created_at,updated_at,task_kind,payload_json) VALUES($1,$2,NULLIF($3,'')::uuid,NULLIF($4,'')::uuid,$5,$6,$7,$8,$9,'queued',1,$10,1,$11,$11,$12,$13)`, taskID, spec.Goal, spec.ConversationID, spec.ModelProfileID, spec.IdempotencyKey, att, ext, know, spec.TimeoutSeconds, due, now.UTC(), string(spec.Kind), payload); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_execution_snapshots(task_id,snapshot_json,snapshot_digest) VALUES($1,$2,$3)`, taskID, snapshotRaw, snapshot.Digest); err != nil {
		return false, err
	}
	if spec.Kind == coretask.TaskKindAgent {
		if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id) VALUES('task',$1,$2)`, taskID, spec.ModelProfileID); err != nil {
			return false, err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_schedule_occurrences(occurrence_id,schedule_id,scheduled_for,task_id,spec_snapshot_json,created_at) VALUES($1,$2,$3,$4,$5,$6)`, occID, schedule.ID, due, taskID, tpl, now.UTC()); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) VALUES($1,1,$2,0,'queued','created','scheduled task queued',$3)`, taskID, uuid.New(), now.UTC()); err != nil {
		return false, err
	}
	var next any
	if schedule.RunAt == nil {
		n, e := calc.Next(due, schedule.Cron, schedule.Timezone)
		if e != nil {
			return false, e
		}
		next = n.UTC()
	}
	if _, err = tx.Exec(ctx, `UPDATE core_schedules SET last_scheduled_for=$2,next_run_at=$3,revision=revision+1,updated_at=$4 WHERE schedule_id=$1`, schedule.ID, due, next, now.UTC()); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (s *CoreScheduleStore) CreateSchedule(ctx context.Context, c coretask.CreateScheduleCommand) (coretask.Schedule, error) {
	if c.Validate() != nil {
		return coretask.Schedule{}, coretask.ErrInvalid
	}
	return s.coreScheduleMutate(ctx, "create", c.Mutation, func(tx pgx.Tx) (coretask.Schedule, error) {
		v, _ := c.Schedule.Normalize()
		if err := lockLiveScheduleProfileTx(ctx, tx, v.Spec.ModelProfileID); err != nil {
			return coretask.Schedule{}, err
		}
		if v.NextRunAt.IsZero() {
			if v.RunAt != nil {
				v.NextRunAt = v.RunAt.UTC()
			} else {
				var e error
				v.NextRunAt, e = coretask.NextCron(v.CreatedAt, v.Cron, v.Timezone)
				if e != nil {
					return coretask.Schedule{}, e
				}
			}
		}
		tpl, _ := json.Marshal(v.Spec)
		_, e := tx.Exec(ctx, `INSERT INTO core_schedules(schedule_id,name,task_template,run_at,cron,timezone,paused,next_run_at,last_scheduled_for,revision,created_at,updated_at) VALUES($1,$2,$3,$4,NULLIF($5,''),$6,$7,$8,NULLIF($9,'epoch'::timestamptz),$10,$11,$11)`, v.ID, v.Name, tpl, v.RunAt, v.Cron, v.Timezone, v.Paused, coreScheduleNullableTime(v.NextRunAt), coreScheduleNullableTime(v.LastScheduledFor), v.Revision, v.CreatedAt.UTC())
		if e != nil {
			return coretask.Schedule{}, e
		}
		if v.Spec.ModelProfileID != "" {
			if _, e = tx.Exec(ctx, `INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id) VALUES('schedule',$1,$2)`, v.ID, v.Spec.ModelProfileID); e != nil {
				return coretask.Schedule{}, e
			}
		}
		return v, nil
	})
}
func (s *CoreScheduleStore) GetSchedule(ctx context.Context, id string) (coretask.Schedule, error) {
	return s.coreScheduleRow(ctx, s.store.pool.QueryRow(ctx, coreScheduleSelect+` WHERE schedule_id=$1 AND deleted_at IS NULL`, id))
}
func (s *CoreScheduleStore) ListSchedules(ctx context.Context, cursor string, limit int) ([]coretask.Schedule, string, error) {
	if limit <= 0 || limit > 200 {
		return nil, "", coretask.ErrInvalid
	}
	after := ""
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || !coretask.ValidUUID(string(raw)) {
			return nil, "", coretask.ErrInvalid
		}
		after = string(raw)
	}
	rows, err := s.store.pool.Query(ctx, coreScheduleSelect+` WHERE deleted_at IS NULL AND ($1='' OR schedule_id>$1::uuid) ORDER BY schedule_id LIMIT $2`, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := []coretask.Schedule{}
	for rows.Next() {
		value, err := s.coreScheduleRow(ctx, rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, value)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = base64.RawURLEncoding.EncodeToString([]byte(out[len(out)-1].ID))
	}
	return out, next, nil
}
func (s *CoreScheduleStore) UpdateSchedule(ctx context.Context, c coretask.UpdateScheduleCommand) (coretask.Schedule, error) {
	if c.Validate() != nil {
		return coretask.Schedule{}, coretask.ErrInvalid
	}
	return s.coreScheduleMutate(ctx, "update", c.Mutation, func(tx pgx.Tx) (coretask.Schedule, error) {
		old, err := s.coreScheduleTxLocked(ctx, tx, c.Schedule.ID, false)
		if err != nil {
			return old, err
		}
		if old.Revision != c.Mutation.ExpectedRevision {
			return old, coretask.ErrRevisionConflict
		}
		value, _ := c.Schedule.Normalize()
		if err = lockLiveScheduleProfileTx(ctx, tx, value.Spec.ModelProfileID); err != nil {
			return old, err
		}
		// A trigger-changing update owns a fresh cursor. Paused schedules retain
		// that future cursor; enabled recurring schedules never persist NULL.
		triggerKindChanged := (old.RunAt == nil) != (value.RunAt == nil)
		triggerChanged := triggerKindChanged || (value.RunAt != nil && !sameScheduleRunAt(old.RunAt, value.RunAt)) || (value.RunAt == nil && (old.Cron != value.Cron || old.Timezone != value.Timezone))
		if triggerChanged {
			if value.RunAt != nil {
				value.NextRunAt = value.RunAt.UTC()
			} else {
				value.NextRunAt, err = coretask.NextCron(value.UpdatedAt, value.Cron, value.Timezone)
				if err != nil {
					return old, err
				}
			}
		}
		template, _ := json.Marshal(value.Spec)
		tag, err := tx.Exec(ctx, `UPDATE core_schedules SET name=$2,task_template=$3,run_at=$4,cron=NULLIF($5,''),timezone=$6,paused=$7,next_run_at=$8,last_scheduled_for=$9,revision=revision+1,updated_at=$10 WHERE schedule_id=$1 AND revision=$11`, value.ID, value.Name, template, value.RunAt, value.Cron, value.Timezone, value.Paused, coreScheduleNullableTime(value.NextRunAt), coreScheduleNullableTime(value.LastScheduledFor), value.UpdatedAt.UTC(), c.Mutation.ExpectedRevision)
		if err != nil || tag.RowsAffected() != 1 {
			if err == nil {
				err = coretask.ErrRevisionConflict
			}
			return old, err
		}
		if old.Spec.ModelProfileID != value.Spec.ModelProfileID {
			if _, err = tx.Exec(ctx, `DELETE FROM core_model_profile_active_refs WHERE owner_kind='schedule' AND owner_id=$1`, value.ID); err != nil {
				return old, err
			}
			if value.Spec.ModelProfileID != "" {
				if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id) VALUES('schedule',$1,$2)`, value.ID, value.Spec.ModelProfileID); err != nil {
					return old, err
				}
			}
		}
		value.Revision = old.Revision + 1
		return value, nil
	})
}
func (s *CoreScheduleStore) PauseSchedule(ctx context.Context, c coretask.ScheduleMutationCommand) (coretask.Schedule, error) {
	return s.coreScheduleState(ctx, "pause", c, true)
}
func (s *CoreScheduleStore) ResumeSchedule(ctx context.Context, c coretask.ScheduleMutationCommand) (coretask.Schedule, error) {
	return s.coreScheduleState(ctx, "resume", c, false)
}
func (s *CoreScheduleStore) DeleteSchedule(ctx context.Context, c coretask.ScheduleMutationCommand) (coretask.Schedule, error) {
	if c.Validate() != nil {
		return coretask.Schedule{}, coretask.ErrInvalid
	}
	return s.coreScheduleMutate(ctx, "delete", c.Mutation, func(tx pgx.Tx) (coretask.Schedule, error) {
		v, e := s.coreScheduleTxLocked(ctx, tx, c.ScheduleID, true)
		if e != nil {
			return v, e
		}
		if v.Revision != c.Mutation.ExpectedRevision {
			return v, coretask.ErrRevisionConflict
		}
		tag, e := tx.Exec(ctx, `UPDATE core_schedules SET deleted_at=$2,revision=revision+1,updated_at=$2 WHERE schedule_id=$1 AND revision=$3 AND deleted_at IS NULL`, c.ScheduleID, c.At.UTC(), c.Mutation.ExpectedRevision)
		if e != nil || tag.RowsAffected() != 1 {
			if e == nil {
				e = coretask.ErrRevisionConflict
			}
			return v, e
		}
		if _, e = tx.Exec(ctx, `DELETE FROM core_model_profile_active_refs WHERE owner_kind='schedule' AND owner_id=$1`, c.ScheduleID); e != nil {
			return v, e
		}
		v.Deleted = true
		v.Revision++
		v.UpdatedAt = c.At.UTC()
		return v, nil
	})
}
func (s *CoreScheduleStore) coreScheduleState(ctx context.Context, op string, c coretask.ScheduleMutationCommand, paused bool) (coretask.Schedule, error) {
	if c.Validate() != nil {
		return coretask.Schedule{}, coretask.ErrInvalid
	}
	return s.coreScheduleMutate(ctx, op, c.Mutation, func(tx pgx.Tx) (coretask.Schedule, error) {
		v, e := s.coreScheduleTxLocked(ctx, tx, c.ScheduleID, false)
		if e != nil {
			return v, e
		}
		if v.Revision != c.Mutation.ExpectedRevision {
			return v, coretask.ErrRevisionConflict
		}
		tag, e := tx.Exec(ctx, `UPDATE core_schedules SET paused=$1,revision=revision+1,updated_at=$2 WHERE schedule_id=$3 AND revision=$4`, paused, c.At.UTC(), c.ScheduleID, c.Mutation.ExpectedRevision)
		if e != nil || tag.RowsAffected() != 1 {
			if e == nil {
				e = coretask.ErrRevisionConflict
			}
			return v, e
		}
		v.Paused = paused
		v.Revision++
		v.UpdatedAt = c.At.UTC()
		return v, nil
	})
}
func (s *CoreScheduleStore) TriggerNow(ctx context.Context, c coretask.TriggerScheduleCommand) (coretask.Schedule, coretask.Occurrence, coretask.Task, error) {
	if c.Validate() != nil {
		return coretask.Schedule{}, coretask.Occurrence{}, coretask.Task{}, coretask.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coretask.Schedule{}, coretask.Occurrence{}, coretask.Task{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "core_schedule:trigger_now:"+c.Mutation.IdempotencyKey); err != nil {
		return coretask.Schedule{}, coretask.Occurrence{}, coretask.Task{}, err
	}
	var digest string
	var replay []byte
	err = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_schedule_replays WHERE operation='trigger_now' AND idempotency_key=$1 FOR UPDATE`, c.Mutation.IdempotencyKey).Scan(&digest, &replay)
	if err == nil {
		if digest != c.Mutation.RequestDigest {
			return coretask.Schedule{}, coretask.Occurrence{}, coretask.Task{}, coretask.ErrConflict
		}
		var value struct {
			Schedule   coretask.Schedule   `json:"schedule"`
			Occurrence coretask.Occurrence `json:"occurrence"`
			Task       coretask.Task       `json:"task"`
		}
		if json.Unmarshal(replay, &value) != nil {
			return coretask.Schedule{}, coretask.Occurrence{}, coretask.Task{}, coretask.ErrInvalid
		}
		value.Schedule.Replayed = true
		if err = tx.Commit(ctx); err != nil {
			return coretask.Schedule{}, coretask.Occurrence{}, coretask.Task{}, err
		}
		return value.Schedule, value.Occurrence, value.Task, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return coretask.Schedule{}, coretask.Occurrence{}, coretask.Task{}, err
	}
	schedule, err := s.coreScheduleTx(ctx, tx, c.ScheduleID, false)
	if err != nil {
		return coretask.Schedule{}, coretask.Occurrence{}, coretask.Task{}, err
	}
	if schedule.Paused {
		return coretask.Schedule{}, coretask.Occurrence{}, coretask.Task{}, coretask.ErrConflict
	}
	occ, err := coretask.TriggerNow(schedule, coretask.TriggerNowCommand{ScheduleID: c.ScheduleID, IdempotencyKey: c.Mutation.IdempotencyKey, At: c.At.UTC()})
	if err != nil {
		return coretask.Schedule{}, coretask.Occurrence{}, coretask.Task{}, err
	}
	spec, err := coretask.MaterializeOccurrence(schedule, occ)
	if err != nil {
		return coretask.Schedule{}, coretask.Occurrence{}, coretask.Task{}, err
	}
	att, ext, know := coreTaskJSONBytes(spec.AttachmentRefs), coreTaskJSONBytes(spec.Extensions), coreTaskJSONBytes(spec.KnowledgeRefs)
	payload, _ := json.Marshal(spec.Payload)
	snapshot, err := resolveTaskSnapshotTx(ctx, tx, spec)
	if err != nil {
		return coretask.Schedule{}, coretask.Occurrence{}, coretask.Task{}, err
	}
	snapshotRaw, _ := json.Marshal(snapshot)
	_, err = tx.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,conversation_id,model_profile_id,create_idempotency_key,attachment_refs,extensions_json,knowledge_refs,timeout_seconds,status,progress_sequence,available_at,revision,created_at,updated_at,task_kind,payload_json) VALUES($1,$2,NULLIF($3,'')::uuid,NULLIF($4,'')::uuid,$5,$6,$7,$8,$9,'queued',1,$10,1,$11,$11,$12,$13)`, occ.TaskID, spec.Goal, spec.ConversationID, spec.ModelProfileID, spec.IdempotencyKey, att, ext, know, spec.TimeoutSeconds, occ.ScheduledFor, c.At.UTC(), string(spec.Kind), payload)
	if err != nil {
		return coretask.Schedule{}, coretask.Occurrence{}, coretask.Task{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_execution_snapshots(task_id,snapshot_json,snapshot_digest) VALUES($1,$2,$3)`, occ.TaskID, snapshotRaw, snapshot.Digest); err != nil {
		return coretask.Schedule{}, coretask.Occurrence{}, coretask.Task{}, err
	}
	if spec.Kind == coretask.TaskKindAgent {
		if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id) VALUES('task',$1,$2)`, occ.TaskID, spec.ModelProfileID); err != nil {
			return coretask.Schedule{}, coretask.Occurrence{}, coretask.Task{}, err
		}
	}
	template, _ := json.Marshal(schedule.Spec)
	if _, err = tx.Exec(ctx, `INSERT INTO core_schedule_occurrences(occurrence_id,schedule_id,scheduled_for,trigger_key,task_id,spec_snapshot_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, occ.ID, occ.ScheduleID, occ.ScheduledFor, occ.TriggerKey, occ.TaskID, template, c.At.UTC()); err != nil {
		return coretask.Schedule{}, coretask.Occurrence{}, coretask.Task{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) VALUES($1,1,$2,0,'queued','created','scheduled task queued',$3)`, occ.TaskID, uuid.New(), c.At.UTC()); err != nil {
		return coretask.Schedule{}, coretask.Occurrence{}, coretask.Task{}, err
	}
	task, err := (&CoreTaskStore{store: s.store}).taskTx(ctx, tx, occ.TaskID, false)
	if err != nil {
		return schedule, occ, coretask.Task{}, err
	}
	raw, _ := json.Marshal(struct {
		Schedule   coretask.Schedule   `json:"schedule"`
		Occurrence coretask.Occurrence `json:"occurrence"`
		Task       coretask.Task       `json:"task"`
	}{schedule, occ, task})
	if _, err = tx.Exec(ctx, `INSERT INTO core_schedule_replays(operation,idempotency_key,schedule_id,request_hash,response_json) VALUES('trigger_now',$1,$2,$3,$4)`, c.Mutation.IdempotencyKey, c.ScheduleID, c.Mutation.RequestDigest, raw); err != nil {
		return schedule, occ, task, err
	}
	if err = tx.Commit(ctx); err != nil {
		return schedule, occ, task, err
	}
	return schedule, occ, task, nil
}

func (s *CoreScheduleStore) coreScheduleMutate(ctx context.Context, op string, m coretask.MutationCommand, apply func(pgx.Tx) (coretask.Schedule, error)) (coretask.Schedule, error) {
	if m.Validate() != nil {
		return coretask.Schedule{}, coretask.ErrInvalid
	}
	tx, e := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return coretask.Schedule{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "core_schedule:"+op+":"+m.IdempotencyKey); e != nil {
		return coretask.Schedule{}, e
	}
	var d string
	var raw []byte
	e = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_schedule_replays WHERE operation=$1 AND idempotency_key=$2 FOR UPDATE`, op, m.IdempotencyKey).Scan(&d, &raw)
	if e == nil {
		if d != m.RequestDigest {
			return coretask.Schedule{}, coretask.ErrConflict
		}
		var v coretask.Schedule
		if json.Unmarshal(raw, &v) != nil {
			return v, e
		}
		v.Replayed = true
		if e = tx.Commit(ctx); e != nil {
			return v, e
		}
		return v, nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return coretask.Schedule{}, e
	}
	v, e := apply(tx)
	if e != nil {
		return v, e
	}
	raw, e = json.Marshal(v)
	if e != nil {
		return v, e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_schedule_replays(operation,idempotency_key,schedule_id,request_hash,response_json) VALUES($1,$2,$3,$4,$5)`, op, m.IdempotencyKey, v.ID, m.RequestDigest, raw); e != nil {
		return v, e
	}
	if e = tx.Commit(ctx); e != nil {
		return v, e
	}
	return v, nil
}

const coreScheduleSelect = `SELECT schedule_id,name,task_template,run_at,COALESCE(cron,''),timezone,paused,next_run_at,last_scheduled_for,revision,created_at,updated_at,deleted_at FROM core_schedules`

type coreScheduleScanner interface{ Scan(...any) error }

func (s *CoreScheduleStore) coreScheduleRow(ctx context.Context, r coreScheduleScanner) (coretask.Schedule, error) {
	var v coretask.Schedule
	var tpl []byte
	var run, next, last, del *time.Time
	var rev int64
	e := r.Scan(&v.ID, &v.Name, &tpl, &run, &v.Cron, &v.Timezone, &v.Paused, &next, &last, &rev, &v.CreatedAt, &v.UpdatedAt, &del)
	if errors.Is(e, pgx.ErrNoRows) {
		return v, coretask.ErrNotFound
	}
	if e != nil {
		return v, e
	}
	if json.Unmarshal(tpl, &v.Spec) != nil {
		return v, coretask.ErrInvalid
	}
	v.RunAt = run
	v.NextRunAt = coreScheduleDerefTime(next)
	v.LastScheduledFor = coreScheduleDerefTime(last)
	v.Revision = uint64(rev)
	v.Deleted = del != nil
	v.CreatedAt = v.CreatedAt.UTC()
	v.UpdatedAt = v.UpdatedAt.UTC()
	return v, nil
}
func (s *CoreScheduleStore) coreScheduleTx(ctx context.Context, tx pgx.Tx, id string, deleted bool) (coretask.Schedule, error) {
	q := coreScheduleSelect + ` WHERE schedule_id=$1`
	if !deleted {
		q += ` AND deleted_at IS NULL`
	}
	return s.coreScheduleRow(ctx, tx.QueryRow(ctx, q, id))
}
func (s *CoreScheduleStore) coreScheduleTxLocked(ctx context.Context, tx pgx.Tx, id string, deleted bool) (coretask.Schedule, error) {
	q := coreScheduleSelect + ` WHERE schedule_id=$1`
	if !deleted {
		q += ` AND deleted_at IS NULL`
	}
	return s.coreScheduleRow(ctx, tx.QueryRow(ctx, q+` FOR UPDATE`, id))
}
func coreScheduleNullableTime(v time.Time) any {
	if v.IsZero() {
		return nil
	}
	return v.UTC()
}
func coreScheduleDerefTime(v *time.Time) time.Time {
	if v == nil {
		return time.Time{}
	}
	return v.UTC()
}
func sameScheduleRunAt(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}
