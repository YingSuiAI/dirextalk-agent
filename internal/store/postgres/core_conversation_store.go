package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CoreConversationStore struct{ *Store }

func NewCoreConversationStore(store *Store) (*CoreConversationStore, error) {
	if store == nil {
		return nil, errors.New("postgres store is required")
	}
	return &CoreConversationStore{Store: store}, nil
}

func (s *CoreConversationStore) CreateConversationMutation(ctx context.Context, c core.CreateConversationCommand) (core.ConversationMutationResponse, error) {
	if err := c.Validate(); err != nil {
		return core.ConversationMutationResponse{}, err
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return core.ConversationMutationResponse{}, e
	}
	defer tx.Rollback(ctx)
	var raw []byte
	var storedHash string
	if e = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_mutation_replays WHERE operation='conversation.create' AND idempotency_key=$1`, c.RequestID).Scan(&storedHash, &raw); e == nil {
		if storedHash != c.Fingerprint {
			return core.ConversationMutationResponse{}, core.ErrConflict
		}
		var r core.ConversationMutationResponse
		e = json.Unmarshal(raw, &r)
		r.Replayed = e == nil
		if e == nil {
			e = tx.Commit(ctx)
		}
		return r, e
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return core.ConversationMutationResponse{}, e
	}
	now := time.Now().UTC()
	conversation := c.Conversation
	conversation.CreatedAt, conversation.UpdatedAt = now, now
	if _, e = tx.Exec(ctx, `INSERT INTO core_conversations(conversation_id,title,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5)`, conversation.ID, conversation.Title, conversation.Revision, conversation.CreatedAt, conversation.UpdatedAt); e != nil {
		return core.ConversationMutationResponse{}, e
	}
	r := core.ConversationMutationResponse{Conversation: conversation, RequestID: c.RequestID}
	raw, _ = json.Marshal(r)
	if _, e = tx.Exec(ctx, `INSERT INTO core_mutation_replays(operation,idempotency_key,request_hash,response_json) VALUES('conversation.create',$1,$2,$3)`, c.RequestID, c.Fingerprint, raw); e != nil {
		return core.ConversationMutationResponse{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return core.ConversationMutationResponse{}, e
	}
	return r, nil
}

func (s *CoreConversationStore) DeleteConversationMutation(ctx context.Context, c core.DeleteConversationCommand) (core.ConversationMutationResponse, error) {
	if err := c.Validate(); err != nil {
		return core.ConversationMutationResponse{}, err
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return core.ConversationMutationResponse{}, e
	}
	defer tx.Rollback(ctx)
	var raw []byte
	var storedHash string
	if e = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_mutation_replays WHERE operation='conversation.delete' AND idempotency_key=$1`, c.RequestID).Scan(&storedHash, &raw); e == nil {
		if storedHash != c.Fingerprint {
			return core.ConversationMutationResponse{}, core.ErrConflict
		}
		var r core.ConversationMutationResponse
		e = json.Unmarshal(raw, &r)
		r.Replayed = e == nil
		if e == nil {
			e = tx.Commit(ctx)
		}
		return r, e
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return core.ConversationMutationResponse{}, e
	}
	var conv core.Conversation
	var del *time.Time
	if e = tx.QueryRow(ctx, `SELECT conversation_id,title,revision,created_at,updated_at,deleted_at FROM core_conversations WHERE conversation_id=$1`, c.ConversationID).Scan(&conv.ID, &conv.Title, &conv.Revision, &conv.CreatedAt, &conv.UpdatedAt, &del); e != nil {
		return core.ConversationMutationResponse{}, e
	}
	if conv.Revision != c.ExpectedRevision {
		return core.ConversationMutationResponse{}, core.ErrConflict
	}
	now := time.Now().UTC()
	result, e := tx.Exec(ctx, `UPDATE core_conversations SET revision=revision+1,updated_at=$2,deleted_at=$2 WHERE conversation_id=$1 AND revision=$3 AND deleted_at IS NULL`, c.ConversationID, now, c.ExpectedRevision)
	if e != nil {
		return core.ConversationMutationResponse{}, e
	}
	if result.RowsAffected() != 1 {
		return core.ConversationMutationResponse{}, core.ErrConflict
	}
	conv.Revision++
	conv.UpdatedAt = now
	conv.DeletedAt = &now
	r := core.ConversationMutationResponse{Conversation: conv, RequestID: c.RequestID, Deleted: true}
	raw, _ = json.Marshal(r)
	if _, e = tx.Exec(ctx, `INSERT INTO core_mutation_replays(operation,idempotency_key,request_hash,response_json) VALUES('conversation.delete',$1,$2,$3)`, c.RequestID, c.Fingerprint, raw); e != nil {
		return core.ConversationMutationResponse{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return core.ConversationMutationResponse{}, e
	}
	return r, nil
}

func (s *CoreConversationStore) RenameConversationMutation(ctx context.Context, id, title string, expected uint64, requestID string) (core.ConversationMutationResponse, error) {
	_, parseErr := uuid.Parse(id)
	_, requestErr := uuid.Parse(requestID)
	if parseErr != nil || requestErr != nil || expected == 0 || len(title) > 512 {
		return core.ConversationMutationResponse{}, core.ErrInvalid
	}
	digest := digestRenamePG(id, title, expected)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.ConversationMutationResponse{}, err
	}
	defer tx.Rollback(ctx)
	var stored string
	var replay []byte
	err = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_mutation_replays WHERE operation='conversation.rename' AND idempotency_key=$1`, requestID).Scan(&stored, &replay)
	if err == nil {
		if stored != digest {
			return core.ConversationMutationResponse{}, core.ErrConflict
		}
		var out core.ConversationMutationResponse
		if json.Unmarshal(replay, &out) != nil {
			return core.ConversationMutationResponse{}, core.ErrConflict
		}
		out.Replayed = true
		if err = tx.Commit(ctx); err != nil {
			return core.ConversationMutationResponse{}, err
		}
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return core.ConversationMutationResponse{}, err
	}
	var conversation core.Conversation
	var deleted *time.Time
	if err = tx.QueryRow(ctx, `SELECT conversation_id,title,revision,created_at,updated_at,deleted_at FROM core_conversations WHERE conversation_id=$1 FOR UPDATE`, id).Scan(&conversation.ID, &conversation.Title, &conversation.Revision, &conversation.CreatedAt, &conversation.UpdatedAt, &deleted); err != nil {
		return core.ConversationMutationResponse{}, core.ErrConflict
	}
	conversation.DeletedAt = deleted
	if deleted != nil || conversation.Revision != expected {
		return core.ConversationMutationResponse{}, core.ErrConflict
	}
	now := time.Now().UTC()
	if tag, updateErr := tx.Exec(ctx, `UPDATE core_conversations SET title=$2,revision=revision+1,updated_at=$3 WHERE conversation_id=$1 AND revision=$4 AND deleted_at IS NULL`, id, title, now, expected); updateErr != nil || tag.RowsAffected() != 1 {
		if updateErr != nil {
			return core.ConversationMutationResponse{}, updateErr
		}
		return core.ConversationMutationResponse{}, core.ErrConflict
	}
	conversation.Title, conversation.Revision, conversation.UpdatedAt = title, expected+1, now
	out := core.ConversationMutationResponse{Conversation: conversation, RequestID: requestID}
	replay, _ = json.Marshal(out)
	if _, err = tx.Exec(ctx, `INSERT INTO core_mutation_replays(operation,idempotency_key,request_hash,response_json) VALUES('conversation.rename',$1,$2,$3)`, requestID, digest, replay); err != nil {
		return core.ConversationMutationResponse{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.ConversationMutationResponse{}, err
	}
	return out, nil
}

func digestRenamePG(id, title string, revision uint64) string {
	return sha256hexPG([]byte(fmt.Sprintf("%s:%d:%s", id, revision, title)))
}

func (s *CoreConversationStore) CreateConversation(ctx context.Context, c core.Conversation, key string) error {
	_, e := s.CreateConversationMutation(ctx, core.CreateConversationCommand{RequestID: key, Conversation: c, Fingerprint: digestConversationPG(c)})
	return e
}
func (s *CoreConversationStore) DeleteConversation(ctx context.Context, id string, rev uint64) error {
	key := uuid.NewSHA1(uuid.NameSpaceOID, []byte("delete:"+id))
	_, e := s.DeleteConversationMutation(ctx, core.DeleteConversationCommand{RequestID: key.String(), ConversationID: id, ExpectedRevision: rev, Fingerprint: digestDeletePG(id, rev)})
	return e
}
func digestConversationPG(c core.Conversation) string {
	b, _ := json.Marshal(struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		Revision uint64 `json:"revision"`
	}{c.ID, c.Title, c.Revision})
	return sha256hexPG(b)
}
func digestDeletePG(id string, r uint64) string {
	return sha256hexPG([]byte(fmt.Sprintf("%s:%d", id, r)))
}
func sha256hexPG(b []byte) string { h := sha256.Sum256(b); return fmt.Sprintf("%x", h[:]) }
func nullableUUIDPG(s string) any {
	if s == "" {
		return nil
	}
	id, e := uuid.Parse(s)
	if e != nil {
		return nil
	}
	return id
}
func extensionJSONPG(exts []core.ExtensionSelection) ([]byte, error) {
	if exts == nil {
		exts = []core.ExtensionSelection{}
	}
	return json.Marshal(exts)
}
func stringArrayJSONPG(values []string) ([]byte, error) {
	if values == nil {
		values = []string{}
	}
	return json.Marshal(values)
}

func (s *CoreConversationStore) LoadConversation(ctx context.Context, id string) (core.Conversation, error) {
	var c core.Conversation
	var del *time.Time
	var summary string
	var offset int64
	if e := s.pool.QueryRow(ctx, `SELECT c.conversation_id,c.title,c.revision,c.created_at,c.updated_at,c.deleted_at,COALESCE(x.summary,''),COALESCE(x.message_offset,0) FROM core_conversations c LEFT JOIN core_conversation_contexts x ON x.conversation_id=c.conversation_id WHERE c.conversation_id=$1`, id).Scan(&c.ID, &c.Title, &c.Revision, &c.CreatedAt, &c.UpdatedAt, &del, &summary, &offset); e != nil {
		return c, core.ErrConflict
	}
	c.DeletedAt = del
	if offset < 0 {
		return c, core.ErrConflict
	}
	c.Summary, c.ContextMessageOffset = summary, uint64(offset)
	rows, e := s.pool.Query(ctx, `SELECT message_id,role,content,model_profile_id,created_at,payload_json,related_task_ids,tool_summaries FROM core_messages WHERE conversation_id=$1 ORDER BY sequence`, id)
	if e != nil {
		return c, e
	}
	defer rows.Close()
	for rows.Next() {
		var m core.Message
		var prof *uuid.UUID
		var payload, tasks, sums []byte
		if e = rows.Scan(&m.ID, &m.Role, &m.Content, &prof, &m.CreatedAt, &payload, &tasks, &sums); e != nil {
			return c, e
		}
		if prof != nil {
			m.ModelProfileID = prof.String()
		}
		_ = json.Unmarshal(tasks, &m.RelatedTaskIDs)
		_ = json.Unmarshal(sums, &m.ToolSummaries)
		c.Messages = append(c.Messages, m)
	}
	for i := range c.Messages {
		var persisted core.Message
		var payload []byte
		_ = s.pool.QueryRow(ctx, `SELECT payload_json FROM core_messages WHERE message_id=$1`, c.Messages[i].ID).Scan(&payload)
		_ = json.Unmarshal(payload, &persisted)
		executionIDs := make(map[string]string, len(persisted.ToolCalls))
		for _, call := range persisted.ToolCalls {
			executionIDs[call.ID] = call.ExecutionID
		}
		rows2, e := s.pool.Query(ctx, `SELECT tool_call_id,tool_name,arguments_json FROM core_message_tool_calls WHERE message_id=$1 ORDER BY call_index`, c.Messages[i].ID)
		if e != nil {
			return c, e
		}
		for rows2.Next() {
			var call core.ToolCall
			var args []byte
			if e = rows2.Scan(&call.ID, &call.Name, &args); e != nil {
				rows2.Close()
				return c, e
			}
			call.Arguments = string(args)
			call.ExecutionID = executionIDs[call.ID]
			c.Messages[i].ToolCalls = append(c.Messages[i].ToolCalls, call)
		}
		rows2.Close()
		rows3, e := s.pool.Query(ctx, `SELECT tool_call_id,result_json FROM core_message_tool_results WHERE message_id=$1 ORDER BY result_index`, c.Messages[i].ID)
		if e != nil {
			return c, e
		}
		for rows3.Next() {
			var r core.ToolResult
			var raw []byte
			if e = rows3.Scan(&r.CallID, &raw); e != nil {
				rows3.Close()
				return c, e
			}
			_ = json.Unmarshal(raw, &r)
			c.Messages[i].ToolResults = append(c.Messages[i].ToolResults, r)
		}
		rows3.Close()
	}
	return c, nil
}
func (s *CoreConversationStore) SaveConversation(context.Context, core.Conversation, uint64) error {
	return errors.New("conversation save requires chat completion")
}
func (s *CoreConversationStore) ListConversations(ctx context.Context, token string, limit int) ([]core.Conversation, string, error) {
	if limit <= 0 {
		return nil, "", core.ErrInvalid
	}
	var rows pgx.Rows
	var e error
	if strings.TrimSpace(token) == "" {
		rows, e = s.pool.Query(ctx, `SELECT c.conversation_id,c.title,c.revision,c.created_at,c.updated_at,c.deleted_at,COALESCE(x.summary,''),COALESCE(x.message_offset,0) FROM core_conversations c LEFT JOIN core_conversation_contexts x ON x.conversation_id=c.conversation_id WHERE c.deleted_at IS NULL ORDER BY c.updated_at DESC,c.conversation_id LIMIT $1`, limit)
	} else {
		parts := strings.SplitN(token, "|", 2)
		if len(parts) != 2 {
			return nil, "", core.ErrInvalid
		}
		ct, pe := time.Parse(time.RFC3339Nano, parts[0])
		if pe != nil || !coreUUID(parts[1]) {
			return nil, "", core.ErrInvalid
		}
		rows, e = s.pool.Query(ctx, `SELECT c.conversation_id,c.title,c.revision,c.created_at,c.updated_at,c.deleted_at,COALESCE(x.summary,''),COALESCE(x.message_offset,0) FROM core_conversations c LEFT JOIN core_conversation_contexts x ON x.conversation_id=c.conversation_id WHERE c.deleted_at IS NULL AND (c.updated_at < $1 OR (c.updated_at = $1 AND c.conversation_id > $2)) ORDER BY c.updated_at DESC,c.conversation_id ASC LIMIT $3`, ct, parts[1], limit)
	}
	if e != nil {
		return nil, "", e
	}
	defer rows.Close()
	var out []core.Conversation
	for rows.Next() {
		var c core.Conversation
		var d *time.Time
		var summary string
		var offset int64
		if e = rows.Scan(&c.ID, &c.Title, &c.Revision, &c.CreatedAt, &c.UpdatedAt, &d, &summary, &offset); e != nil {
			return nil, "", e
		}
		if offset < 0 {
			return nil, "", core.ErrConflict
		}
		c.Summary, c.ContextMessageOffset = summary, uint64(offset)
		out = append(out, c)
	}
	next := ""
	if len(out) == limit {
		last := out[len(out)-1]
		next = last.UpdatedAt.Format(time.RFC3339Nano) + "|" + last.ID
	}
	return out, next, nil
}
func coreUUID(value string) bool {
	id, e := uuid.Parse(value)
	return e == nil && strings.ToLower(value) == id.String()
}
