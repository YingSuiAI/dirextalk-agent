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
// exact same semantic-cycle window.
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
	rows, err := tx.Query(ctx, `SELECT effective_digest FROM core_conversation_progress_observations WHERE turn_id=$1 AND steer_sequence=$2 ORDER BY event_sequence DESC LIMIT 11`, turnID, steerSequence)
	if err != nil {
		return false, err
	}
	var reversed []string
	for rows.Next() {
		var value string
		if err = rows.Scan(&value); err != nil {
			rows.Close()
			return false, err
		}
		reversed = append(reversed, value)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	rows.Close()
	digests := make([]string, 0, len(reversed)+1)
	for index := len(reversed) - 1; index >= 0; index-- {
		digests = append(digests, reversed[index])
	}
	digests = append(digests, observation.EffectiveDigest)
	repetitions := semanticCycleRepetitions(digests, 4, 3)
	raw, _ := json.Marshal(observation)
	if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_progress_observations(turn_id,call_id,event_sequence,steer_sequence,observation_json,effective_digest,consecutive_count,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, turnID, callID, eventSequence, steerSequence, raw, observation.EffectiveDigest, repetitions, now); err != nil {
		return false, err
	}
	return repetitions >= 3, nil
}

func semanticCycleRepetitions(values []string, maxCycleLength, maxRepetitions int) int {
	best := 1
	for cycleLength := 1; cycleLength <= maxCycleLength; cycleLength++ {
		for repetitions := 2; repetitions <= maxRepetitions; repetitions++ {
			needed := cycleLength * repetitions
			if len(values) < needed {
				break
			}
			start := len(values) - needed
			matched := true
			for index := start + cycleLength; index < len(values); index++ {
				if values[index] != values[start+(index-start)%cycleLength] {
					matched = false
					break
				}
			}
			if matched && repetitions > best {
				best = repetitions
			}
		}
	}
	return best
}

func prepareTurnNoProgressFinalizationTx(ctx context.Context, tx pgx.Tx, turn core.Turn, lastSequence int64, now time.Time) error {
	intent := core.NewTurnFinalizationIntent(core.TurnFinalizationToolLoop)
	if turn.RuntimeSnapshot == nil || intent.Validate() != nil {
		return core.ErrConflict
	}
	inserted, err := tx.Exec(ctx, `INSERT INTO core_conversation_turn_finalizations(turn_id,owner_id,account_generation,turn_revision,intent_version,reason,created_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (turn_id,turn_revision) DO NOTHING`, turn.ID, turn.OwnerID, turn.AccountGeneration, turn.Revision, intent.Version, string(intent.Reason), now)
	if err != nil {
		return err
	}
	if inserted.RowsAffected() != 1 {
		return core.ErrConflict
	}
	command, err := tx.Exec(ctx, `UPDATE core_conversation_turns SET state='accepted',dispatch_state='',dispatch_result_json=NULL,last_sequence=$3,lease_id=NULL,lease_expires_at=NULL,updated_at=$4 WHERE turn_id=$1 AND revision=$2 AND state IN ('running','accepted','waiting_confirmation')`, turn.ID, turn.Revision, lastSequence, now)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return core.ErrConflict
	}
	return nil
}
