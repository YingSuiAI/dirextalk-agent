package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/corememory"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CoreMemoryStore struct {
	store *Store
	now   func() time.Time
}

func NewCoreMemoryStore(store *Store, now func() time.Time) (*CoreMemoryStore, error) {
	if store == nil {
		return nil, corememory.ErrInvalid
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &CoreMemoryStore{store: store, now: now}, nil
}

func (r *CoreMemoryStore) Get(ctx context.Context, key corememory.SlotKey) (corememory.Slot, error) {
	if r == nil || r.store == nil || key.Validate() != nil {
		return corememory.Slot{}, corememory.ErrInvalid
	}
	key = key.Normalize()
	row := r.store.pool.QueryRow(ctx, canonicalMemorySelect+` WHERE scope=$1 AND canonical_key=$2 AND COALESCE(conversation_id,'00000000-0000-0000-0000-000000000000'::uuid)=COALESCE(NULLIF($3,'')::uuid,'00000000-0000-0000-0000-000000000000'::uuid)`, key.Scope, key.CanonicalKey, key.ConversationID)
	value, err := scanCanonicalMemory(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return corememory.Slot{}, corememory.ErrNotFound
	}
	if err != nil {
		return corememory.Slot{}, corememory.ErrConflict
	}
	return value, nil
}

func (r *CoreMemoryStore) List(ctx context.Context, scope corememory.Scope, conversationID string, includeDeleted bool, limit int) ([]corememory.Slot, error) {
	key := corememory.SlotKey{Scope: scope, CanonicalKey: "goal.list", ConversationID: strings.TrimSpace(conversationID)}
	if r == nil || r.store == nil || key.Validate() != nil || limit < 1 || limit > 100 {
		return nil, corememory.ErrInvalid
	}
	rows, err := r.store.pool.Query(ctx, canonicalMemorySelect+` WHERE scope=$1 AND COALESCE(conversation_id,'00000000-0000-0000-0000-000000000000'::uuid)=COALESCE(NULLIF($2,'')::uuid,'00000000-0000-0000-0000-000000000000'::uuid) AND ($3 OR state='active') ORDER BY updated_at DESC,memory_id LIMIT $4`, scope, key.ConversationID, includeDeleted, limit)
	if err != nil {
		return nil, corememory.ErrConflict
	}
	defer rows.Close()
	out := make([]corememory.Slot, 0, limit)
	for rows.Next() {
		value, scanErr := scanCanonicalMemory(rows)
		if scanErr != nil {
			return nil, corememory.ErrConflict
		}
		out = append(out, value)
	}
	if rows.Err() != nil {
		return nil, corememory.ErrConflict
	}
	return out, nil
}

func (r *CoreMemoryStore) Apply(ctx context.Context, command corememory.ApplyCommand) (corememory.Slot, error) {
	if r == nil || r.store == nil {
		return corememory.Slot{}, corememory.ErrInvalid
	}
	command = command.Normalize()
	requestDigest, err := command.RequestDigest()
	if err != nil {
		return corememory.Slot{}, err
	}
	tx, err := r.store.pool.Begin(ctx)
	if err != nil {
		return corememory.Slot{}, corememory.ErrConflict
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, canonicalMemoryLockKey(command.Slot)); err != nil {
		return corememory.Slot{}, corememory.ErrConflict
	}
	var replayDigest string
	var replayJSON []byte
	err = tx.QueryRow(ctx, `SELECT request_digest,response_json FROM core_memory_revisions WHERE idempotency_key=$1 FOR UPDATE`, command.IdempotencyKey).Scan(&replayDigest, &replayJSON)
	if err == nil {
		if replayDigest != requestDigest {
			return corememory.Slot{}, corememory.ErrIdempotencyConflict
		}
		var replay corememory.Slot
		if json.Unmarshal(replayJSON, &replay) != nil {
			return corememory.Slot{}, corememory.ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return corememory.Slot{}, corememory.ErrConflict
		}
		return replay, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return corememory.Slot{}, corememory.ErrConflict
	}

	if command.SourceConversationID != "" {
		var exists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM core_conversation_turns WHERE turn_id=$1 AND conversation_id=$2)`, command.SourceTurnID, command.SourceConversationID).Scan(&exists); err != nil || !exists {
			return corememory.Slot{}, corememory.ErrConflict
		}
	}
	if command.Action == corememory.ChangeCreate || command.Action == corememory.ChangeUpdate {
		var kind, status, sourceDigest string
		var sourceRevision int64
		if err = tx.QueryRow(ctx, `SELECT kind,status,digest,revision FROM core_knowledge_sources WHERE source_id=$1`, command.SourceID).Scan(&kind, &status, &sourceDigest, &sourceRevision); err != nil || kind != "memory" || (status != "ready" && status != "indexing") || sourceDigest != command.TextDigest || sourceRevision != command.SourceRevision {
			return corememory.Slot{}, corememory.ErrConflict
		}
	}

	current, getErr := scanCanonicalMemory(tx.QueryRow(ctx, canonicalMemorySelect+` WHERE scope=$1 AND canonical_key=$2 AND COALESCE(conversation_id,'00000000-0000-0000-0000-000000000000'::uuid)=COALESCE(NULLIF($3,'')::uuid,'00000000-0000-0000-0000-000000000000'::uuid) FOR UPDATE`, command.Slot.Scope, command.Slot.CanonicalKey, command.Slot.ConversationID))
	if getErr != nil && !errors.Is(getErr, pgx.ErrNoRows) {
		return corememory.Slot{}, corememory.ErrConflict
	}
	// PostgreSQL timestamptz persists microseconds. Canonicalize before both
	// returning and storing the receipt so restart readback is byte-equivalent.
	now := r.now().UTC().Truncate(time.Microsecond)
	var next corememory.Slot
	switch command.Action {
	case corememory.ChangeCreate:
		if getErr == nil {
			return corememory.Slot{}, corememory.ErrRevisionConflict
		}
		next = slotFromCommand(command, uuid.NewSHA1(uuid.NameSpaceURL, []byte("dirextalk/canonical-memory/"+command.IdempotencyKey)).String(), 1, false, now, now)
		_, err = tx.Exec(ctx, `INSERT INTO core_memory_slots(memory_id,scope,canonical_key,conversation_id,memory_type,sensitivity,state,current_revision,current_source_id,current_source_revision,current_text_digest,confidence,importance,candidate_schema_version,policy_version,source_conversation_id,source_turn_id,created_at,updated_at) VALUES($1,$2,$3,NULLIF($4,'')::uuid,$5,$6,'active',1,$7,$8,$9,$10,$11,$12,$13,NULLIF($14,'')::uuid,NULLIF($15,'')::uuid,$16,$16)`, next.ID, next.Scope, next.CanonicalKey, next.ConversationID, next.Type, next.Sensitivity, next.CurrentSourceID, next.CurrentSourceRevision, next.CurrentTextDigest, next.Confidence, next.Importance, next.CandidateSchemaVersion, next.PolicyVersion, next.SourceConversationID, next.SourceTurnID, now)
	case corememory.ChangeUpdate:
		if errors.Is(getErr, pgx.ErrNoRows) || current.Deleted || current.Revision != command.ExpectedRevision {
			return corememory.Slot{}, corememory.ErrRevisionConflict
		}
		next = slotFromCommand(command, current.ID, current.Revision+1, false, current.CreatedAt, now)
		var tag pgconnCommandTag
		tag, err = execCanonicalMemoryUpdate(ctx, tx, next, current.Revision)
		if err == nil && tag.RowsAffected() != 1 {
			return corememory.Slot{}, corememory.ErrRevisionConflict
		}
	case corememory.ChangeDelete:
		if errors.Is(getErr, pgx.ErrNoRows) || current.Deleted || current.Revision != command.ExpectedRevision {
			return corememory.Slot{}, corememory.ErrRevisionConflict
		}
		next = current
		next.Revision, next.Deleted, next.CurrentSourceID, next.CurrentSourceRevision, next.CurrentTextDigest = current.Revision+1, true, "", 0, ""
		next.SourceConversationID, next.SourceTurnID, next.UpdatedAt = command.SourceConversationID, command.SourceTurnID, now
		tag, updateErr := tx.Exec(ctx, `UPDATE core_memory_slots SET state='deleted',current_revision=$2,current_source_id=NULL,current_source_revision=0,current_text_digest='',source_conversation_id=NULLIF($3,'')::uuid,source_turn_id=NULLIF($4,'')::uuid,updated_at=$5 WHERE memory_id=$1 AND state='active' AND current_revision=$6`, next.ID, next.Revision, next.SourceConversationID, next.SourceTurnID, now, current.Revision)
		err = updateErr
		if err == nil && tag.RowsAffected() != 1 {
			return corememory.Slot{}, corememory.ErrRevisionConflict
		}
	default:
		return corememory.Slot{}, corememory.ErrInvalid
	}
	if err != nil {
		return corememory.Slot{}, corememory.ErrConflict
	}
	responseJSON, err := json.Marshal(next)
	if err != nil {
		return corememory.Slot{}, corememory.ErrConflict
	}
	_, err = tx.Exec(ctx, `INSERT INTO core_memory_revisions(memory_id,revision,action,source_id,source_revision,text_digest,memory_type,sensitivity,confidence,importance,candidate_schema_version,policy_version,source_conversation_id,source_turn_id,idempotency_key,request_digest,response_json,created_at) VALUES($1,$2,$3,NULLIF($4,'')::uuid,$5,$6,$7,$8,$9,$10,$11,$12,NULLIF($13,'')::uuid,NULLIF($14,'')::uuid,$15,$16,$17,$18)`, next.ID, next.Revision, command.Action, next.CurrentSourceID, next.CurrentSourceRevision, next.CurrentTextDigest, next.Type, next.Sensitivity, next.Confidence, next.Importance, next.CandidateSchemaVersion, next.PolicyVersion, next.SourceConversationID, next.SourceTurnID, command.IdempotencyKey, requestDigest, responseJSON, now)
	if err != nil {
		return corememory.Slot{}, corememory.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		return corememory.Slot{}, corememory.ErrConflict
	}
	return next, nil
}

// pgconnCommandTag keeps the helper signature independent from the concrete
// pgx connection while retaining the single affected-row fence.
type pgconnCommandTag interface{ RowsAffected() int64 }

func execCanonicalMemoryUpdate(ctx context.Context, tx pgx.Tx, next corememory.Slot, expected int64) (pgconnCommandTag, error) {
	return tx.Exec(ctx, `UPDATE core_memory_slots SET memory_type=$2,sensitivity=$3,state='active',current_revision=$4,current_source_id=$5,current_source_revision=$6,current_text_digest=$7,confidence=$8,importance=$9,candidate_schema_version=$10,policy_version=$11,source_conversation_id=NULLIF($12,'')::uuid,source_turn_id=NULLIF($13,'')::uuid,updated_at=$14 WHERE memory_id=$1 AND state='active' AND current_revision=$15`, next.ID, next.Type, next.Sensitivity, next.Revision, next.CurrentSourceID, next.CurrentSourceRevision, next.CurrentTextDigest, next.Confidence, next.Importance, next.CandidateSchemaVersion, next.PolicyVersion, next.SourceConversationID, next.SourceTurnID, next.UpdatedAt, expected)
}

func slotFromCommand(command corememory.ApplyCommand, id string, revision int64, deleted bool, createdAt, updatedAt time.Time) corememory.Slot {
	return corememory.Slot{ID: id, SlotKey: command.Slot, Type: command.Type, Sensitivity: command.Sensitivity, CurrentSourceID: command.SourceID, CurrentSourceRevision: command.SourceRevision, CurrentTextDigest: command.TextDigest, Revision: revision, Deleted: deleted, Confidence: command.Confidence, Importance: command.Importance, CandidateSchemaVersion: command.CandidateSchemaVersion, PolicyVersion: command.PolicyVersion, SourceConversationID: command.SourceConversationID, SourceTurnID: command.SourceTurnID, CreatedAt: createdAt.UTC(), UpdatedAt: updatedAt.UTC()}
}

func canonicalMemoryLockKey(key corememory.SlotKey) string {
	key = key.Normalize()
	return "canonical-memory:" + string(key.Scope) + ":" + key.ConversationID + ":" + key.CanonicalKey
}

type canonicalMemoryScanner interface{ Scan(...any) error }

func scanCanonicalMemory(row canonicalMemoryScanner) (corememory.Slot, error) {
	var value corememory.Slot
	var state string
	err := row.Scan(&value.ID, &value.Scope, &value.CanonicalKey, &value.ConversationID, &value.Type, &value.Sensitivity, &state, &value.Revision, &value.CurrentSourceID, &value.CurrentSourceRevision, &value.CurrentTextDigest, &value.Confidence, &value.Importance, &value.CandidateSchemaVersion, &value.PolicyVersion, &value.SourceConversationID, &value.SourceTurnID, &value.CreatedAt, &value.UpdatedAt)
	if err != nil {
		return value, err
	}
	value.Deleted = state == "deleted"
	value.CreatedAt, value.UpdatedAt = value.CreatedAt.UTC(), value.UpdatedAt.UTC()
	return value, nil
}

const canonicalMemorySelect = `SELECT memory_id::text,scope,canonical_key,COALESCE(conversation_id::text,''),memory_type,sensitivity,state,current_revision,COALESCE(current_source_id::text,''),current_source_revision,current_text_digest,confidence,importance,candidate_schema_version,policy_version,COALESCE(source_conversation_id::text,''),COALESCE(source_turn_id::text,''),created_at,updated_at FROM core_memory_slots`

var _ corememory.Repository = (*CoreMemoryStore)(nil)
