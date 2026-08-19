package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/jackc/pgx/v5"
)

// CommitConversationSchedule is the only write path for the schedule
// intrinsic. The schedule, replay receipt, transcript messages, completed
// turn, and done event share one PostgreSQL transaction.
func (s *CoreConversationStore) CommitConversationSchedule(ctx context.Context, command core.ConversationScheduleCommand) (coretask.Schedule, error) {
	command.Response.Message.CreatedAt = command.Response.Message.CreatedAt.UTC().Truncate(time.Microsecond)
	if bindTurnResponseIdentity(&command.Response, command.Lease.Turn.ID) != nil || command.Validate() != nil {
		return coretask.Schedule{}, core.ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coretask.Schedule{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "core_conversation_schedule:create:"+command.Mutation.IdempotencyKey); err != nil {
		return coretask.Schedule{}, err
	}
	var storedDigest string
	var replayRaw []byte
	err = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_schedule_replays WHERE operation='create' AND idempotency_key=$1 FOR UPDATE`, command.Mutation.IdempotencyKey).Scan(&storedDigest, &replayRaw)
	if err == nil {
		if storedDigest != command.Mutation.RequestDigest {
			return coretask.Schedule{}, coretask.ErrConflict
		}
		var replay coretask.Schedule
		if json.Unmarshal(replayRaw, &replay) != nil || replay.Validate() != nil || replay.ID != command.Schedule.ID {
			return coretask.Schedule{}, coretask.ErrInvalid
		}
		var turn core.Turn
		if err = s.scanTurn(ctx, tx, command.Lease.Turn.ID, &turn); err != nil || turn.State != core.TurnCompleted || turn.RequestID != command.Lease.Turn.RequestID ||
			turn.OwnerID != command.Lease.Turn.OwnerID || turn.AccountGeneration != command.Lease.Turn.AccountGeneration || turn.Response == nil || !reflect.DeepEqual(*turn.Response, command.Response) {
			return coretask.Schedule{}, coretask.ErrConflict
		}
		replay.Replayed = true
		if err = tx.Commit(ctx); err != nil {
			return coretask.Schedule{}, err
		}
		return replay, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return coretask.Schedule{}, err
	}
	schedule, err := command.Schedule.Normalize()
	if err != nil {
		return coretask.Schedule{}, coretask.ErrInvalid
	}
	if schedule.NextRunAt.IsZero() {
		if schedule.RunAt != nil {
			schedule.NextRunAt = schedule.RunAt.UTC()
		} else if schedule.NextRunAt, err = coretask.NextCron(schedule.CreatedAt, schedule.Cron, schedule.Timezone); err != nil {
			return coretask.Schedule{}, coretask.ErrInvalid
		}
	}
	if err = lockLiveScheduleProfileTx(ctx, tx, schedule.Spec.ModelProfileID); err != nil {
		return coretask.Schedule{}, err
	}
	templateRaw, _ := json.Marshal(schedule.Spec)
	if _, err = tx.Exec(ctx, `INSERT INTO core_schedules(schedule_id,name,task_template,run_at,cron,timezone,paused,next_run_at,last_scheduled_for,revision,created_at,updated_at) VALUES($1,$2,$3,$4,NULLIF($5,''),$6,false,$7,NULL,$8,$9,$9)`, schedule.ID, schedule.Name, templateRaw, schedule.RunAt, schedule.Cron, schedule.Timezone, schedule.NextRunAt, schedule.Revision, schedule.CreatedAt); err != nil {
		return coretask.Schedule{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id) VALUES('schedule',$1,$2)`, schedule.ID, schedule.Spec.ModelProfileID); err != nil {
		return coretask.Schedule{}, err
	}
	replayRaw, _ = json.Marshal(schedule)
	if _, err = tx.Exec(ctx, `INSERT INTO core_schedule_replays(operation,idempotency_key,schedule_id,request_hash,response_json) VALUES('create',$1,$2,$3,$4)`, command.Mutation.IdempotencyKey, schedule.ID, command.Mutation.RequestDigest, replayRaw); err != nil {
		return coretask.Schedule{}, err
	}
	if err = s.commitTurnTx(ctx, tx, command.Lease, command.Response); err != nil {
		return coretask.Schedule{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coretask.Schedule{}, err
	}
	return schedule, nil
}

var _ core.ConversationScheduleStore = (*CoreConversationStore)(nil)
