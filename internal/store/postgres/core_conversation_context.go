package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/jackc/pgx/v5"
)

// CompressConversationContext stores the model-facing context offset and
// bounded summary in one transaction with the conversation revision and
// idempotency replay.  Transcript rows are never deleted.
func (s *CoreConversationStore) CompressConversationContext(ctx context.Context, id, summary string, working core.WorkingContext, expectedProtectedDigest string, offset, expected uint64, requestID string) (core.Conversation, error) {
	if s == nil || s.pool == nil || !coreUUID(id) || !coreUUID(requestID) || expected == 0 || len(summary) > core.MaxSummaryBytes || !utf8Valid(summary) ||
		working.Validate() != nil || !validSHA256PG(expectedProtectedDigest) || offset > uint64(^uint64(0)>>1) {
		return core.Conversation{}, core.ErrInvalid
	}
	workingRaw, _ := json.Marshal(working)
	protectedDigest := working.ProtectedDigest()
	digest := contextDigestPG(id, summary, workingRaw, expectedProtectedDigest, protectedDigest, offset, expected)
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
		out.WorkingContext = working.Snapshot()
		out.WorkingContextProtectedDigest = protectedDigest
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
	var existingWorkingRaw []byte
	var existingProtectedDigest *string
	// Lock the authoritative conversation before reading its optional context.
	// PostgreSQL rejects FOR UPDATE on the nullable side of an outer join, and
	// every context writer follows this conversation-then-context lock order.
	if err = tx.QueryRow(ctx, `SELECT conversation_id,title,revision,created_at,updated_at,deleted_at FROM core_conversations WHERE conversation_id=$1 FOR UPDATE`, id).Scan(&out.ID, &out.Title, &out.Revision, &out.CreatedAt, &out.UpdatedAt, &deleted); err != nil {
		return core.Conversation{}, core.ErrConflict
	}
	contextErr := tx.QueryRow(ctx, `SELECT summary,message_offset,working_context_json,protected_digest FROM core_conversation_contexts WHERE conversation_id=$1 FOR UPDATE`, id).Scan(&existingSummary, &existingOffset, &existingWorkingRaw, &existingProtectedDigest)
	if contextErr != nil && !errors.Is(contextErr, pgx.ErrNoRows) {
		return core.Conversation{}, contextErr
	}
	existingWorking := core.NewWorkingContext()
	storedProtectedDigest := existingWorking.ProtectedDigest()
	if len(existingWorkingRaw) != 0 {
		if json.Unmarshal(existingWorkingRaw, &existingWorking) != nil || existingProtectedDigest == nil {
			return core.Conversation{}, core.ErrConflict
		}
		storedProtectedDigest = *existingProtectedDigest
	} else if existingProtectedDigest != nil {
		return core.Conversation{}, core.ErrConflict
	}
	if existingWorking.Validate() != nil || existingWorking.ProtectedDigest() != storedProtectedDigest {
		return core.Conversation{}, core.ErrConflict
	}
	if deleted != nil || existingOffset < 0 || out.Revision != expected || storedProtectedDigest != expectedProtectedDigest {
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
	changed := existingSummary != summary || uint64(existingOffset) != offset || !reflect.DeepEqual(existingWorking, working) || storedProtectedDigest != protectedDigest
	if changed {
		if _, err = tx.Exec(ctx, `UPDATE core_conversations SET revision=revision+1,updated_at=$2 WHERE conversation_id=$1 AND revision=$3 AND deleted_at IS NULL`, id, now, expected); err != nil {
			return core.Conversation{}, err
		}
		out.Revision++
		out.UpdatedAt = now
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_conversation_contexts(conversation_id,summary,message_offset,working_context_version,working_context_json,protected_digest,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(conversation_id) DO UPDATE SET summary=$2,message_offset=$3,working_context_version=$4,working_context_json=$5,protected_digest=$6,updated_at=$7`, id, summary, int64(offset), core.WorkingContextVersion, workingRaw, protectedDigest, now); err != nil {
		return core.Conversation{}, err
	}
	out.DeletedAt = deleted
	out.Summary, out.WorkingContext, out.WorkingContextProtectedDigest, out.ContextMessageOffset = summary, working, protectedDigest, offset
	raw, _ := json.Marshal(out)
	if _, err = tx.Exec(ctx, `INSERT INTO core_mutation_replays(operation,idempotency_key,request_hash,response_json) VALUES('conversation.context.compress',$1,$2,$3)`, requestID, digest, raw); err != nil {
		return core.Conversation{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.Conversation{}, err
	}
	return out, nil
}

func contextDigestPG(id, summary string, workingRaw []byte, expectedProtectedDigest, protectedDigest string, offset, expected uint64) string {
	value := fmt.Sprintf("%s:%d:%d:%s:%s:%s:%s", id, expected, offset, summary, string(workingRaw), expectedProtectedDigest, protectedDigest)
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

func validSHA256PG(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func utf8Valid(value string) bool {
	return utf8.ValidString(value)
}
