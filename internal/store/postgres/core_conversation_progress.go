package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/jackc/pgx/v5"
)

// recordConversationProgressTx persists the trusted observation beside the
// tool-result event in the caller's transaction. The latest durable steer
// sequence is the reset boundary, so restart and lease transfer preserve the
// exact same three-observation window.
func recordConversationProgressTx(ctx context.Context, tx pgx.Tx, turnID, callID string, result core.ToolResult, eventSequence int64, now time.Time) (bool, error) {
	observation, structured, err := core.ProgressObservationForToolResult(result)
	if err != nil || !structured {
		return false, err
	}
	var existingDigest string
	var existingCount int
	err = tx.QueryRow(ctx, `SELECT effective_digest,consecutive_count FROM core_conversation_progress_observations WHERE turn_id=$1 AND call_id=$2`, turnID, callID).Scan(&existingDigest, &existingCount)
	if err == nil {
		if existingDigest != observation.EffectiveDigest || existingCount < 1 || existingCount > 3 {
			return false, core.ErrConflict
		}
		return existingCount >= 3, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	var steerSequence int64
	if err = tx.QueryRow(ctx, `SELECT COALESCE(MAX(sequence),0) FROM core_conversation_turn_events WHERE turn_id=$1 AND kind=$2`, turnID, string(core.TurnEventSteered)).Scan(&steerSequence); err != nil {
		return false, err
	}
	consecutive := 1
	var previousDigest string
	var previousCount int
	err = tx.QueryRow(ctx, `SELECT effective_digest,consecutive_count FROM core_conversation_progress_observations WHERE turn_id=$1 AND steer_sequence=$2 ORDER BY event_sequence DESC LIMIT 1`, turnID, steerSequence).Scan(&previousDigest, &previousCount)
	if err == nil {
		if previousCount < 1 || previousCount > 3 {
			return false, core.ErrConflict
		}
		if previousDigest == observation.EffectiveDigest {
			consecutive = previousCount + 1
			if consecutive > 3 {
				consecutive = 3
			}
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	raw, _ := json.Marshal(observation)
	if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_progress_observations(turn_id,call_id,event_sequence,steer_sequence,observation_json,effective_digest,consecutive_count,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, turnID, callID, eventSequence, steerSequence, raw, observation.EffectiveDigest, consecutive, now); err != nil {
		return false, err
	}
	return consecutive >= 3, nil
}

func failTurnNoProgressTx(ctx context.Context, tx pgx.Tx, turn core.Turn, dispatchRaw []byte, lastSequence int64, now time.Time) error {
	command, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET state='failed',revision=revision+1,terminal_code=$2,terminal_summary=$3,dispatch_result_json=$4,lease_id=NULL,lease_expires_at=NULL,updated_at=$5 WHERE turn_id=$1 AND state IN ('running','accepted','waiting_confirmation')`, turn.ID, core.AgentStalledNoProgressCode, core.AgentStalledNoProgressSummary, dispatchRaw, now)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return core.ErrConflict
	}
	if err = insertTurnEventTx(ctx, tx, turn.ID, lastSequence+1, core.TurnEvent{Kind: core.TurnEventError, ErrorCode: core.AgentStalledNoProgressCode, ErrorSummary: core.AgentStalledNoProgressSummary}, now); err != nil {
		return err
	}
	return failedTurnTranscriptTx(ctx, tx, turn, core.AgentStalledNoProgressCode, core.AgentStalledNoProgressSummary, now)
}
