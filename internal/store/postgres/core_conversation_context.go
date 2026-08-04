package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/jackc/pgx/v5"
)

// CompressConversationContext stores the model-facing context offset and
// bounded summary in one transaction with the conversation revision and
// idempotency replay.  Transcript rows are never deleted.
func (s *CoreConversationStore) CompressConversationContext(ctx context.Context, id, summary string, offset, expected uint64, requestID string) (core.Conversation, error) {
	if s == nil || s.pool == nil || !coreUUID(id) || !coreUUID(requestID) || expected == 0 || len(summary) > core.MaxSummaryBytes || !utf8Valid(summary) || offset > uint64(^uint64(0)>>1) {
		return core.Conversation{}, core.ErrInvalid
	}
	digest := contextDigestPG(id, summary, offset, expected)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.Conversation{}, err
	}
	defer tx.Rollback(ctx)
	var stored string
	var replay []byte
	if err = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_mutation_replays WHERE operation='conversation.context.compress' AND idempotency_key=$1`, requestID).Scan(&stored, &replay); err == nil {
		if stored != digest {
			return core.Conversation{}, core.ErrConflict
		}
		var out core.Conversation
		if json.Unmarshal(replay, &out) != nil {
			return core.Conversation{}, core.ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return core.Conversation{}, err
		}
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return core.Conversation{}, err
	}
	var out core.Conversation
	var deleted *time.Time
	var existingSummary string
	var existingOffset int64
	if err = tx.QueryRow(ctx, `SELECT c.conversation_id,c.title,c.revision,c.created_at,c.updated_at,c.deleted_at,COALESCE(x.summary,''),COALESCE(x.message_offset,0) FROM core_conversations c LEFT JOIN core_conversation_contexts x ON x.conversation_id=c.conversation_id WHERE c.conversation_id=$1 FOR UPDATE`, id).Scan(&out.ID, &out.Title, &out.Revision, &out.CreatedAt, &out.UpdatedAt, &deleted, &existingSummary, &existingOffset); err != nil {
		return core.Conversation{}, core.ErrConflict
	}
	if deleted != nil || existingOffset < 0 || out.Revision != expected {
		return core.Conversation{}, core.ErrConflict
	}
	var messageCount int64
	if err = tx.QueryRow(ctx, `SELECT COUNT(*) FROM core_messages WHERE conversation_id=$1`, id).Scan(&messageCount); err != nil {
		return core.Conversation{}, err
	}
	if offset > uint64(messageCount) {
		return core.Conversation{}, core.ErrInvalid
	}
	now := time.Now().UTC()
	changed := existingSummary != summary || uint64(existingOffset) != offset
	if changed {
		if _, err = tx.Exec(ctx, `UPDATE core_conversations SET revision=revision+1,updated_at=$2 WHERE conversation_id=$1 AND revision=$3 AND deleted_at IS NULL`, id, now, expected); err != nil {
			return core.Conversation{}, err
		}
		out.Revision++
		out.UpdatedAt = now
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_contexts(conversation_id,summary,message_offset,updated_at) VALUES($1,$2,$3,$4) ON CONFLICT(conversation_id) DO UPDATE SET summary=$2,message_offset=$3,updated_at=$4`, id, summary, int64(offset), now); err != nil {
		return core.Conversation{}, err
	}
	out.DeletedAt = deleted
	out.Summary, out.ContextMessageOffset = summary, offset
	raw, _ := json.Marshal(out)
	if _, err = tx.Exec(ctx, `INSERT INTO core_mutation_replays(operation,idempotency_key,request_hash,response_json) VALUES('conversation.context.compress',$1,$2,$3)`, requestID, digest, raw); err != nil {
		return core.Conversation{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.Conversation{}, err
	}
	return out, nil
}

func contextDigestPG(id, summary string, offset, expected uint64) string {
	value := fmt.Sprintf("%s:%d:%d:%s", id, expected, offset, summary)
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

func utf8Valid(value string) bool {
	return utf8.ValidString(value)
}
