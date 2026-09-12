package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/jackc/pgx/v5"
)

// LoadGroupSummary returns the derived rolling summary for one shared group.
func (s *CoreConversationStore) LoadGroupSummary(ctx context.Context, roomID, ownerID string, generation uint64) (core.GroupRollingSummary, bool, error) {
	summary := core.GroupRollingSummary{}
	if s == nil || s.Store == nil || strings.TrimSpace(roomID) == "" || strings.TrimSpace(ownerID) == "" || generation == 0 {
		return summary, false, core.ErrInvalid
	}
	var revision, coveredThrough int64
	var messageCount int64
	err := s.pool.QueryRow(ctx, `SELECT owner_id, account_generation, binding_revision, covered_through_ts, message_count, summary
		FROM core_group_summaries WHERE room_id=$1 AND owner_id=$2 AND account_generation=$3`,
		roomID, ownerID, int64(generation)).Scan(&summary.OwnerID, &generation, &revision, &coveredThrough, &messageCount, &summary.Summary)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.GroupRollingSummary{}, false, nil
	}
	if err != nil {
		return core.GroupRollingSummary{}, false, err
	}
	summary.RoomID = roomID
	summary.AccountGeneration = generation
	summary.BindingRevision = revision
	summary.CoveredThroughTS = coveredThrough
	summary.MessageCount = int(messageCount)
	return summary, true, nil
}

// SaveGroupSummary upserts one group digest. The background sweep is the only
// writer, so a stale revision simply overwrites the previous digest.
func (s *CoreConversationStore) SaveGroupSummary(ctx context.Context, summary core.GroupRollingSummary) error {
	if s == nil || s.Store == nil || strings.TrimSpace(summary.RoomID) == "" || strings.TrimSpace(summary.OwnerID) == "" ||
		summary.AccountGeneration == 0 || summary.BindingRevision <= 0 || summary.CoveredThroughTS < 0 {
		return core.ErrInvalid
	}
	if len([]rune(summary.Summary)) > core.GroupSummaryMaxRunes*2 {
		return core.ErrInvalid
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO core_group_summaries(room_id,owner_id,account_generation,binding_revision,covered_through_ts,message_count,summary,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT(room_id) DO UPDATE SET owner_id=EXCLUDED.owner_id,account_generation=EXCLUDED.account_generation,
		binding_revision=EXCLUDED.binding_revision,covered_through_ts=EXCLUDED.covered_through_ts,
		message_count=EXCLUDED.message_count,summary=EXCLUDED.summary,updated_at=EXCLUDED.updated_at`,
		summary.RoomID, summary.OwnerID, int64(summary.AccountGeneration), summary.BindingRevision,
		summary.CoveredThroughTS, int64(summary.MessageCount), summary.Summary, time.Now().UTC())
	return err
}
