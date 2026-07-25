package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *CoreTaskStore) PrepareModelRound(ctx context.Context, c coretask.ModelRoundCommand) (coretask.ModelRoundLedger, error) {
	if c.At.IsZero() || len(c.InputDigest) != 64 || c.Round >= coretask.MaxAgentRounds {
		return coretask.ModelRoundLedger{}, coretask.ErrInvalid
	}
	return s.modelRoundMutation(ctx, c.Fence, c.Round, c.At.UTC(), func(tx pgx.Tx, now time.Time) (coretask.ModelRoundLedger, error) {
		if _, err := tx.Exec(ctx, `INSERT INTO core_task_model_rounds(task_id,attempt,round,lease_epoch,task_revision,input_digest,state) VALUES($1,$2,$3,$4,$5,$6,'prepared')`, c.TaskID, c.Attempt, c.Round, c.LeaseEpoch, c.ExpectedRevision, c.InputDigest); err != nil {
			return coretask.ModelRoundLedger{}, mapLedgerError(err)
		}
		return s.modelRoundTx(ctx, tx, c.TaskID, c.Attempt, c.Round)
	})
}
func (s *CoreTaskStore) MarkModelDispatched(ctx context.Context, c coretask.ModelRoundCommand) (coretask.ModelRoundLedger, error) {
	if c.At.IsZero() || c.Round >= coretask.MaxAgentRounds {
		return coretask.ModelRoundLedger{}, coretask.ErrInvalid
	}
	return s.modelRoundMutation(ctx, c.Fence, c.Round, c.At.UTC(), func(tx pgx.Tx, now time.Time) (coretask.ModelRoundLedger, error) {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM core_task_model_rounds WHERE task_id=$1 AND attempt=$2 AND round=$3 FOR UPDATE`, c.TaskID, c.Attempt, c.Round).Scan(&state); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return coretask.ModelRoundLedger{}, coretask.ErrNotFound
			}
			return coretask.ModelRoundLedger{}, err
		}
		if state != "prepared" {
			return coretask.ModelRoundLedger{}, coretask.ErrLedgerConflict
		}
		if _, err := tx.Exec(ctx, `UPDATE core_task_model_rounds SET state='dispatched',task_revision=$4,updated_at=$5 WHERE task_id=$1 AND attempt=$2 AND round=$3`, c.TaskID, c.Attempt, c.Round, c.ExpectedRevision, now); err != nil {
			return coretask.ModelRoundLedger{}, err
		}
		return s.modelRoundTx(ctx, tx, c.TaskID, c.Attempt, c.Round)
	})
}
func (s *CoreTaskStore) CompleteModelRound(ctx context.Context, c coretask.ModelResponseCommand) (coretask.ModelRoundLedger, error) {
	if c.At.IsZero() || c.Round >= coretask.MaxAgentRounds || len(c.Response) == 0 || !json.Valid(c.Response) {
		return coretask.ModelRoundLedger{}, coretask.ErrInvalid
	}
	return s.modelRoundMutation(ctx, c.Fence, c.Round, c.At.UTC(), func(tx pgx.Tx, now time.Time) (coretask.ModelRoundLedger, error) {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM core_task_model_rounds WHERE task_id=$1 AND attempt=$2 AND round=$3 FOR UPDATE`, c.TaskID, c.Attempt, c.Round).Scan(&state); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return coretask.ModelRoundLedger{}, coretask.ErrNotFound
			}
			return coretask.ModelRoundLedger{}, err
		}
		if state != "dispatched" {
			return coretask.ModelRoundLedger{}, coretask.ErrLedgerConflict
		}
		if _, err := tx.Exec(ctx, `UPDATE core_task_model_rounds SET state='completed',task_revision=$4,response_json=$5,updated_at=$6 WHERE task_id=$1 AND attempt=$2 AND round=$3`, c.TaskID, c.Attempt, c.Round, c.ExpectedRevision, c.Response, now); err != nil {
			return coretask.ModelRoundLedger{}, err
		}
		return s.modelRoundTx(ctx, tx, c.TaskID, c.Attempt, c.Round)
	})
}

func (s *CoreTaskStore) MarkModelUncertain(ctx context.Context, c coretask.ModelUncertainCommand) (coretask.ModelRoundLedger, error) {
	if c.At.IsZero() || c.Round >= coretask.MaxAgentRounds || strings.TrimSpace(c.ErrorCode) == "" || strings.TrimSpace(c.ErrorSummary) == "" {
		return coretask.ModelRoundLedger{}, coretask.ErrInvalid
	}
	return s.modelRoundMutation(ctx, c.Fence, c.Round, c.At.UTC(), func(tx pgx.Tx, now time.Time) (coretask.ModelRoundLedger, error) {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM core_task_model_rounds WHERE task_id=$1 AND attempt=$2 AND round=$3 FOR UPDATE`, c.TaskID, c.Attempt, c.Round).Scan(&state); err != nil {
			return coretask.ModelRoundLedger{}, err
		}
		if state != string(coretask.ModelRoundDispatched) {
			return coretask.ModelRoundLedger{}, coretask.ErrLedgerConflict
		}
		if _, err := tx.Exec(ctx, `UPDATE core_task_model_rounds SET state='uncertain',task_revision=$4,error_code=$5,error_summary=$6,updated_at=$7 WHERE task_id=$1 AND attempt=$2 AND round=$3`, c.TaskID, c.Attempt, c.Round, c.ExpectedRevision, c.ErrorCode, c.ErrorSummary, now); err != nil {
			return coretask.ModelRoundLedger{}, err
		}
		return s.modelRoundTx(ctx, tx, c.TaskID, c.Attempt, c.Round)
	})
}
func (s *CoreTaskStore) modelRoundMutation(ctx context.Context, f coretask.Fence, round uint32, at time.Time, apply func(pgx.Tx, time.Time) (coretask.ModelRoundLedger, error)) (coretask.ModelRoundLedger, error) {
	if !coretask.ValidUUID(f.TaskID) || f.Attempt == 0 || f.LeaseEpoch == 0 || f.ExpectedRevision == 0 {
		return coretask.ModelRoundLedger{}, coretask.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coretask.ModelRoundLedger{}, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE core_tasks SET revision=revision+1,updated_at=$1 WHERE task_id=$2 AND status='running' AND attempt=$3 AND lease_epoch=$4 AND revision=$5 AND lease_expires_at>$1`, at, f.TaskID, f.Attempt, f.LeaseEpoch, f.ExpectedRevision)
	if err != nil {
		return coretask.ModelRoundLedger{}, err
	}
	if tag.RowsAffected() != 1 {
		return coretask.ModelRoundLedger{}, coretask.ErrLeaseConflict
	}
	// UPDATE is the lease/revision CAS. A stale epoch or revision never reaches
	// the ledger mutation.
	// pgx command tags are checked directly because no row means a stale fence.
	value, err := apply(tx, at)
	if err != nil {
		return coretask.ModelRoundLedger{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_tasks SET progress_sequence=progress_sequence+1 WHERE task_id=$1`, f.TaskID); err != nil {
		return coretask.ModelRoundLedger{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) SELECT task_id,progress_sequence,$2,attempt,'running','model_round',$3,$4 FROM core_tasks WHERE task_id=$1`, f.TaskID, uuid.New(), "model round durable ledger: "+string(value.State), at); err != nil {
		return coretask.ModelRoundLedger{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coretask.ModelRoundLedger{}, err
	}
	return value, nil
}
func (s *CoreTaskStore) modelRoundTx(ctx context.Context, tx rowQuerier, taskID string, attempt, round uint32) (coretask.ModelRoundLedger, error) {
	var m coretask.ModelRoundLedger
	var state string
	var response []byte
	if err := tx.QueryRow(ctx, `SELECT task_id::text,attempt,round,lease_epoch,task_revision,input_digest,state,response_json,error_code,error_summary,created_at,updated_at FROM core_task_model_rounds WHERE task_id=$1 AND attempt=$2 AND round=$3`, taskID, attempt, round).Scan(&m.TaskID, &m.Attempt, &m.Round, &m.LeaseEpoch, &m.TaskRevision, &m.InputDigest, &state, &response, &m.ErrorCode, &m.ErrorSummary, &m.CreatedAt, &m.UpdatedAt); err != nil {
		return m, err
	}
	m.State = coretask.ModelRoundState(state)
	m.Response = response
	m.CreatedAt = m.CreatedAt.UTC()
	m.UpdatedAt = m.UpdatedAt.UTC()
	return m, nil
}

func (s *CoreTaskStore) PrepareToolCall(ctx context.Context, c coretask.ToolCallCommand) (coretask.ToolCallLedger, error) {
	if c.At.IsZero() || c.Round >= coretask.MaxAgentRounds || len(c.ToolDigest) != 64 || len(c.ArgumentsDigest) != 64 || c.CallID == "" {
		return coretask.ToolCallLedger{}, coretask.ErrInvalid
	}
	return s.toolMutation(ctx, c.Fence, c.Round, c.CallID, c.At.UTC(), func(tx pgx.Tx, now time.Time) (coretask.ToolCallLedger, error) {
		if _, err := tx.Exec(ctx, `INSERT INTO core_task_tool_calls(task_id,attempt,round,call_id,lease_epoch,task_revision,tool_digest,arguments_digest,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'prepared')`, c.TaskID, c.Attempt, c.Round, c.CallID, c.LeaseEpoch, c.ExpectedRevision, c.ToolDigest, c.ArgumentsDigest); err != nil {
			return coretask.ToolCallLedger{}, mapLedgerError(err)
		}
		return s.toolTx(ctx, tx, c.TaskID, c.Attempt, c.Round, c.CallID)
	})
}
func (s *CoreTaskStore) MarkToolDispatched(ctx context.Context, c coretask.ToolCallCommand) (coretask.ToolCallLedger, error) {
	if c.At.IsZero() {
		return coretask.ToolCallLedger{}, coretask.ErrInvalid
	}
	return s.toolMutation(ctx, c.Fence, c.Round, c.CallID, c.At.UTC(), func(tx pgx.Tx, now time.Time) (coretask.ToolCallLedger, error) {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM core_task_tool_calls WHERE task_id=$1 AND attempt=$2 AND round=$3 AND call_id=$4 FOR UPDATE`, c.TaskID, c.Attempt, c.Round, c.CallID).Scan(&state); err != nil {
			return coretask.ToolCallLedger{}, err
		}
		if state != "prepared" {
			return coretask.ToolCallLedger{}, coretask.ErrLedgerConflict
		}
		if _, err := tx.Exec(ctx, `UPDATE core_task_tool_calls SET state='dispatched',task_revision=$5,updated_at=$6 WHERE task_id=$1 AND attempt=$2 AND round=$3 AND call_id=$4`, c.TaskID, c.Attempt, c.Round, c.CallID, c.ExpectedRevision, now); err != nil {
			return coretask.ToolCallLedger{}, err
		}
		return s.toolTx(ctx, tx, c.TaskID, c.Attempt, c.Round, c.CallID)
	})
}
func (s *CoreTaskStore) CompleteToolCall(ctx context.Context, c coretask.ToolResultCommand) (coretask.ToolCallLedger, error) {
	if c.At.IsZero() || len(c.Result) == 0 || !json.Valid(c.Result) {
		return coretask.ToolCallLedger{}, coretask.ErrInvalid
	}
	return s.toolMutation(ctx, c.Fence, c.Round, c.CallID, c.At.UTC(), func(tx pgx.Tx, now time.Time) (coretask.ToolCallLedger, error) {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM core_task_tool_calls WHERE task_id=$1 AND attempt=$2 AND round=$3 AND call_id=$4 FOR UPDATE`, c.TaskID, c.Attempt, c.Round, c.CallID).Scan(&state); err != nil {
			return coretask.ToolCallLedger{}, err
		}
		if state != "dispatched" {
			return coretask.ToolCallLedger{}, coretask.ErrLedgerConflict
		}
		if _, err := tx.Exec(ctx, `UPDATE core_task_tool_calls SET state='completed',task_revision=$5,result_json=$6,updated_at=$7 WHERE task_id=$1 AND attempt=$2 AND round=$3 AND call_id=$4`, c.TaskID, c.Attempt, c.Round, c.CallID, c.ExpectedRevision, c.Result, now); err != nil {
			return coretask.ToolCallLedger{}, err
		}
		return s.toolTx(ctx, tx, c.TaskID, c.Attempt, c.Round, c.CallID)
	})
}
func (s *CoreTaskStore) MarkToolUncertain(ctx context.Context, c coretask.ToolUncertainCommand) (coretask.ToolCallLedger, error) {
	if c.At.IsZero() || c.ErrorCode == "" || c.ErrorSummary == "" {
		return coretask.ToolCallLedger{}, coretask.ErrInvalid
	}
	return s.toolMutation(ctx, c.Fence, c.Round, c.CallID, c.At.UTC(), func(tx pgx.Tx, now time.Time) (coretask.ToolCallLedger, error) {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM core_task_tool_calls WHERE task_id=$1 AND attempt=$2 AND round=$3 AND call_id=$4 FOR UPDATE`, c.TaskID, c.Attempt, c.Round, c.CallID).Scan(&state); err != nil {
			return coretask.ToolCallLedger{}, err
		}
		if state != "dispatched" {
			return coretask.ToolCallLedger{}, coretask.ErrLedgerConflict
		}
		if _, err := tx.Exec(ctx, `UPDATE core_task_tool_calls SET state='uncertain',task_revision=$5,error_code=$6,error_summary=$7,updated_at=$8 WHERE task_id=$1 AND attempt=$2 AND round=$3 AND call_id=$4`, c.TaskID, c.Attempt, c.Round, c.CallID, c.ExpectedRevision, c.ErrorCode, c.ErrorSummary, now); err != nil {
			return coretask.ToolCallLedger{}, err
		}
		return s.toolTx(ctx, tx, c.TaskID, c.Attempt, c.Round, c.CallID)
	})
}
func (s *CoreTaskStore) toolMutation(ctx context.Context, f coretask.Fence, round uint32, callID string, at time.Time, apply func(pgx.Tx, time.Time) (coretask.ToolCallLedger, error)) (coretask.ToolCallLedger, error) {
	if !coretask.ValidUUID(f.TaskID) || f.Attempt == 0 || f.LeaseEpoch == 0 || f.ExpectedRevision == 0 || round >= coretask.MaxAgentRounds || callID == "" {
		return coretask.ToolCallLedger{}, coretask.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coretask.ToolCallLedger{}, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE core_tasks SET revision=revision+1,updated_at=$1 WHERE task_id=$2 AND status='running' AND attempt=$3 AND lease_epoch=$4 AND revision=$5 AND lease_expires_at>$1`, at, f.TaskID, f.Attempt, f.LeaseEpoch, f.ExpectedRevision)
	if err != nil {
		return coretask.ToolCallLedger{}, err
	}
	if tag.RowsAffected() != 1 {
		return coretask.ToolCallLedger{}, coretask.ErrLeaseConflict
	}
	v, err := apply(tx, at)
	if err != nil {
		return coretask.ToolCallLedger{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_tasks SET progress_sequence=progress_sequence+1 WHERE task_id=$1`, f.TaskID); err != nil {
		return coretask.ToolCallLedger{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,error_code,error_summary,occurred_at) SELECT task_id,progress_sequence,$2,attempt,'running','tool_call',$3,$4,$5,$6 FROM core_tasks WHERE task_id=$1`, f.TaskID, uuid.New(), "tool call durable ledger: "+string(v.State), v.ErrorCode, v.ErrorSummary, at); err != nil {
		return coretask.ToolCallLedger{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coretask.ToolCallLedger{}, err
	}
	return v, nil
}
func (s *CoreTaskStore) toolTx(ctx context.Context, tx rowQuerier, taskID string, attempt, round uint32, callID string) (coretask.ToolCallLedger, error) {
	var t coretask.ToolCallLedger
	var state string
	var result []byte
	if err := tx.QueryRow(ctx, `SELECT task_id::text,attempt,round,call_id,lease_epoch,task_revision,tool_digest,arguments_digest,state,result_json,error_code,error_summary,created_at,updated_at FROM core_task_tool_calls WHERE task_id=$1 AND attempt=$2 AND round=$3 AND call_id=$4`, taskID, attempt, round, callID).Scan(&t.TaskID, &t.Attempt, &t.Round, &t.CallID, &t.LeaseEpoch, &t.TaskRevision, &t.ToolDigest, &t.ArgumentsDigest, &state, &result, &t.ErrorCode, &t.ErrorSummary, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return t, err
	}
	t.State = coretask.ToolCallState(state)
	t.Result = result
	t.CreatedAt = t.CreatedAt.UTC()
	t.UpdatedAt = t.UpdatedAt.UTC()
	return t, nil
}
func (s *CoreTaskStore) GetModelRound(ctx context.Context, taskID string, attempt, round uint32) (coretask.ModelRoundLedger, error) {
	return s.modelRoundTx(ctx, s.store.pool, taskID, attempt, round)
}
func (s *CoreTaskStore) GetToolCall(ctx context.Context, taskID string, attempt, round uint32, callID string) (coretask.ToolCallLedger, error) {
	return s.toolTx(ctx, s.store.pool, taskID, attempt, round, callID)
}

func mapLedgerError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return coretask.ErrLedgerConflict
	}
	return err
}
