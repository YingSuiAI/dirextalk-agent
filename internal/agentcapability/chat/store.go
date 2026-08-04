package chat

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound            = errors.New("conversation not found")
	ErrDeleted             = errors.New("conversation is deleted")
	ErrRevisionConflict    = errors.New("revision conflict")
	ErrIdempotencyConflict = errors.New("idempotency conflict")
	ErrInvalidCursor       = errors.New("invalid cursor")
	ErrInvalidInput        = errors.New("invalid input")
)

// Store manages conversation and message persistence
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new Store instance
func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, fmt.Errorf("pgxpool is required")
	}
	return &Store{pool: pool}, nil
}

// ConversationRecord represents a conversation record with full database fields
type ConversationRecord struct {
	ID             string
	OwnerID        string
	Title          string
	Revision       int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastMessageAt  *time.Time
	MessageCount   int
	SystemPrompt   string
	ModelConfig    map[string]interface{}
	Metadata       map[string]interface{}
	IdempotencyKey string
	Deleted        bool
}

// Message represents a conversation message
type Message struct {
	ID             string
	ConversationID string
	Role           string
	Content        string
	ToolCalls      []map[string]interface{}
	CreatedAt      time.Time
	Metadata       map[string]interface{}
}

// CreateConversation creates a new conversation with idempotency support
func (s *Store) CreateConversation(ctx context.Context, ownerID, conversationID, title, idempotencyKey string) (ConversationRecord, bool, error) {
	if strings.TrimSpace(ownerID) == "" || strings.TrimSpace(conversationID) == "" || strings.TrimSpace(idempotencyKey) == "" {
		return ConversationRecord{}, false, ErrInvalidInput
	}

	digest := requestDigest(ownerID, conversationID, title, idempotencyKey)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ConversationRecord{}, false, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Check idempotency
	var existingConvID, existingDigest string
	err = tx.QueryRow(ctx, `
		SELECT id, metadata->>'digest'
		FROM conversations
		WHERE owner_id = $1 AND idempotency_key = $2
	`, ownerID, idempotencyKey).Scan(&existingConvID, &existingDigest)

	if err == nil {
		// Found existing record
		if existingDigest != digest {
			return ConversationRecord{}, false, ErrIdempotencyConflict
		}
		// Return existing conversation
		var conv ConversationRecord
		err = s.getConversationTx(ctx, tx, ownerID, existingConvID, &conv)
		if err != nil {
			return ConversationRecord{}, false, fmt.Errorf("get existing conversation: %w", err)
		}
		return conv, true, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return ConversationRecord{}, false, fmt.Errorf("check idempotency: %w", err)
	}

	// Create new conversation
	now := time.Now().UTC()
	metadata := map[string]interface{}{"digest": digest}
	metadataJSON, _ := json.Marshal(metadata)

	conv := ConversationRecord{
		ID:             conversationID,
		OwnerID:        ownerID,
		Title:          title,
		Revision:       1,
		CreatedAt:      now,
		UpdatedAt:      now,
		MessageCount:   0,
		IdempotencyKey: idempotencyKey,
		Deleted:        false,
		Metadata:       metadata,
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO conversations (
			id, owner_id, title, revision, created_at, updated_at,
			message_count, idempotency_key, deleted, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, conv.ID, conv.OwnerID, conv.Title, conv.Revision, conv.CreatedAt, conv.UpdatedAt,
		conv.MessageCount, conv.IdempotencyKey, conv.Deleted, metadataJSON)

	if err != nil {
		return ConversationRecord{}, false, fmt.Errorf("insert conversation: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return ConversationRecord{}, false, fmt.Errorf("commit transaction: %w", err)
	}

	return conv, false, nil
}

// ListConversations returns a paginated list of conversations for an owner
func (s *Store) ListConversations(ctx context.Context, ownerID string, limit int, cursor string) ([]ConversationRecord, string, error) {
	if strings.TrimSpace(ownerID) == "" {
		return nil, "", ErrInvalidInput
	}

	if limit <= 0 || limit > 100 {
		limit = 20
	}

	var cursorTime time.Time
	if cursor != "" {
		var err error
		cursorTime, err = time.Parse(time.RFC3339Nano, cursor)
		if err != nil {
			return nil, "", ErrInvalidCursor
		}
	}

	query := `
		SELECT id, owner_id, title, revision, created_at, updated_at,
			   last_message_at, message_count, system_prompt, model_config,
			   metadata, idempotency_key, deleted
		FROM conversations
		WHERE owner_id = $1 AND deleted = false
	`
	args := []interface{}{ownerID}

	if !cursorTime.IsZero() {
		query += ` AND (last_message_at < $2 OR (last_message_at IS NULL AND created_at < $2))`
		args = append(args, cursorTime)
	}

	query += ` ORDER BY COALESCE(last_message_at, created_at) DESC LIMIT $` + strconv.Itoa(len(args)+1)
	args = append(args, limit+1)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, "", fmt.Errorf("query conversations: %w", err)
	}
	defer rows.Close()

	conversations := make([]ConversationRecord, 0, limit)
	for rows.Next() {
		var conv ConversationRecord
		var modelConfigJSON, metadataJSON []byte

		err := rows.Scan(
			&conv.ID, &conv.OwnerID, &conv.Title, &conv.Revision, &conv.CreatedAt, &conv.UpdatedAt,
			&conv.LastMessageAt, &conv.MessageCount, &conv.SystemPrompt, &modelConfigJSON,
			&metadataJSON, &conv.IdempotencyKey, &conv.Deleted,
		)
		if err != nil {
			return nil, "", fmt.Errorf("scan conversation: %w", err)
		}

		if modelConfigJSON != nil {
			json.Unmarshal(modelConfigJSON, &conv.ModelConfig)
		}
		if metadataJSON != nil {
			json.Unmarshal(metadataJSON, &conv.Metadata)
		}

		conversations = append(conversations, conv)
	}

	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("iterate conversations: %w", err)
	}

	// Check if there are more results
	nextCursor := ""
	if len(conversations) > limit {
		conversations = conversations[:limit]
		lastConv := conversations[len(conversations)-1]
		if lastConv.LastMessageAt != nil {
			nextCursor = lastConv.LastMessageAt.Format(time.RFC3339Nano)
		} else {
			nextCursor = lastConv.CreatedAt.Format(time.RFC3339Nano)
		}
	}

	return conversations, nextCursor, nil
}

// GetConversation retrieves a conversation with optional messages
func (s *Store) GetConversation(ctx context.Context, ownerID, conversationID string, messageLimit int, messageCursor string) (ConversationRecord, []Message, string, error) {
	if strings.TrimSpace(ownerID) == "" || strings.TrimSpace(conversationID) == "" {
		return ConversationRecord{}, nil, "", ErrInvalidInput
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ConversationRecord{}, nil, "", fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var conv ConversationRecord
	err = s.getConversationTx(ctx, tx, ownerID, conversationID, &conv)
	if err != nil {
		return ConversationRecord{}, nil, "", err
	}

	if conv.Deleted {
		return conv, nil, "", ErrDeleted
	}

	// Get messages if requested
	var messages []Message
	var nextCursor string
	if messageLimit > 0 {
		messages, nextCursor, err = s.getMessagesTx(ctx, tx, conversationID, messageLimit, messageCursor)
		if err != nil {
			return ConversationRecord{}, nil, "", fmt.Errorf("get messages: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return ConversationRecord{}, nil, "", fmt.Errorf("commit transaction: %w", err)
	}

	return conv, messages, nextCursor, nil
}

// AddMessage adds a message to a conversation
func (s *Store) AddMessage(ctx context.Context, ownerID, conversationID, messageID, role, content string, toolCalls []map[string]interface{}, metadata map[string]interface{}) (Message, error) {
	if strings.TrimSpace(ownerID) == "" || strings.TrimSpace(conversationID) == "" || strings.TrimSpace(messageID) == "" {
		return Message{}, ErrInvalidInput
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Message{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Verify conversation exists and is not deleted
	var exists bool
	var deleted bool
	err = tx.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM conversations WHERE id = $1 AND owner_id = $2),
		       COALESCE((SELECT deleted FROM conversations WHERE id = $1 AND owner_id = $2), true)
	`, conversationID, ownerID).Scan(&exists, &deleted)

	if err != nil {
		return Message{}, fmt.Errorf("check conversation: %w", err)
	}
	if !exists {
		return Message{}, ErrNotFound
	}
	if deleted {
		return Message{}, ErrDeleted
	}

	// Insert message
	now := time.Now().UTC()
	msg := Message{
		ID:             messageID,
		ConversationID: conversationID,
		Role:           role,
		Content:        content,
		ToolCalls:      toolCalls,
		CreatedAt:      now,
		Metadata:       metadata,
	}

	var toolCallsJSON, metadataJSON []byte
	if toolCalls != nil {
		toolCallsJSON, _ = json.Marshal(toolCalls)
	}
	if metadata != nil {
		metadataJSON, _ = json.Marshal(metadata)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO conversation_messages (id, conversation_id, role, content, tool_calls, created_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, msg.ID, msg.ConversationID, msg.Role, msg.Content, toolCallsJSON, msg.CreatedAt, metadataJSON)

	if err != nil {
		return Message{}, fmt.Errorf("insert message: %w", err)
	}

	// Update conversation stats
	_, err = tx.Exec(ctx, `
		UPDATE conversations
		SET last_message_at = $1,
		    message_count = message_count + 1,
		    updated_at = $1,
		    revision = revision + 1
		WHERE id = $2 AND owner_id = $3
	`, now, conversationID, ownerID)

	if err != nil {
		return Message{}, fmt.Errorf("update conversation: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Message{}, fmt.Errorf("commit transaction: %w", err)
	}

	return msg, nil
}

// GetMessages retrieves messages for a conversation
func (s *Store) GetMessages(ctx context.Context, ownerID, conversationID string, limit int, cursor string) ([]Message, string, error) {
	if strings.TrimSpace(ownerID) == "" || strings.TrimSpace(conversationID) == "" {
		return nil, "", ErrInvalidInput
	}

	// Verify conversation exists and belongs to owner
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM conversations WHERE id = $1 AND owner_id = $2)
	`, conversationID, ownerID).Scan(&exists)

	if err != nil {
		return nil, "", fmt.Errorf("check conversation: %w", err)
	}
	if !exists {
		return nil, "", ErrNotFound
	}

	return s.getMessagesTx(ctx, s.pool, conversationID, limit, cursor)
}

// DeleteConversation soft-deletes a conversation with optimistic locking
func (s *Store) DeleteConversation(ctx context.Context, ownerID, conversationID string, expectedRevision int64, idempotencyKey string) (ConversationRecord, bool, error) {
	if strings.TrimSpace(ownerID) == "" || strings.TrimSpace(conversationID) == "" || strings.TrimSpace(idempotencyKey) == "" {
		return ConversationRecord{}, false, ErrInvalidInput
	}
	if expectedRevision <= 0 {
		return ConversationRecord{}, false, ErrInvalidInput
	}

	digest := requestDigest(ownerID, conversationID, "delete", idempotencyKey, strconv.FormatInt(expectedRevision, 10))

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ConversationRecord{}, false, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Check idempotency
	var existingDigest string
	var alreadyDeleted bool
	err = tx.QueryRow(ctx, `
		SELECT metadata->>'delete_digest', deleted
		FROM conversations
		WHERE id = $1 AND owner_id = $2
	`, conversationID, ownerID).Scan(&existingDigest, &alreadyDeleted)

	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ConversationRecord{}, false, fmt.Errorf("check idempotency: %w", err)
	}

	if existingDigest == digest && alreadyDeleted {
		// Already processed this idempotency key
		var conv ConversationRecord
		err = s.getConversationTx(ctx, tx, ownerID, conversationID, &conv)
		if err != nil {
			return ConversationRecord{}, false, err
		}
		return conv, true, nil
	}

	// Get current conversation
	var conv ConversationRecord
	err = s.getConversationTx(ctx, tx, ownerID, conversationID, &conv)
	if err != nil {
		return ConversationRecord{}, false, err
	}

	// Check revision
	if conv.Revision != expectedRevision {
		return conv, false, ErrRevisionConflict
	}

	// Update metadata with delete digest
	if conv.Metadata == nil {
		conv.Metadata = make(map[string]interface{})
	}
	conv.Metadata["delete_digest"] = digest
	metadataJSON, _ := json.Marshal(conv.Metadata)

	// Soft delete
	now := time.Now().UTC()
	_, err = tx.Exec(ctx, `
		UPDATE conversations
		SET deleted = true,
		    revision = revision + 1,
		    updated_at = $1,
		    metadata = $2
		WHERE id = $3 AND owner_id = $4 AND revision = $5
	`, now, metadataJSON, conversationID, ownerID, expectedRevision)

	if err != nil {
		return ConversationRecord{}, false, fmt.Errorf("delete conversation: %w", err)
	}

	// Reload updated conversation
	err = s.getConversationTx(ctx, tx, ownerID, conversationID, &conv)
	if err != nil {
		return ConversationRecord{}, false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return ConversationRecord{}, false, fmt.Errorf("commit transaction: %w", err)
	}

	return conv, false, nil
}

// Helper functions

func (s *Store) getConversationTx(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...interface{}) pgx.Row
}, ownerID, conversationID string, conv *ConversationRecord) error {
	var modelConfigJSON, metadataJSON []byte

	err := q.QueryRow(ctx, `
		SELECT id, owner_id, title, revision, created_at, updated_at,
		       last_message_at, message_count, system_prompt, model_config,
		       metadata, idempotency_key, deleted
		FROM conversations
		WHERE id = $1 AND owner_id = $2
	`, conversationID, ownerID).Scan(
		&conv.ID, &conv.OwnerID, &conv.Title, &conv.Revision, &conv.CreatedAt, &conv.UpdatedAt,
		&conv.LastMessageAt, &conv.MessageCount, &conv.SystemPrompt, &modelConfigJSON,
		&metadataJSON, &conv.IdempotencyKey, &conv.Deleted,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("query conversation: %w", err)
	}

	if modelConfigJSON != nil {
		json.Unmarshal(modelConfigJSON, &conv.ModelConfig)
	}
	if metadataJSON != nil {
		json.Unmarshal(metadataJSON, &conv.Metadata)
	}

	return nil
}

func (s *Store) getMessagesTx(ctx context.Context, q interface {
	Query(context.Context, string, ...interface{}) (pgx.Rows, error)
}, conversationID string, limit int, cursor string) ([]Message, string, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	query := `
		SELECT id, conversation_id, role, content, tool_calls, created_at, metadata
		FROM conversation_messages
		WHERE conversation_id = $1
	`
	args := []interface{}{conversationID}

	if cursor != "" {
		cursorTime, err := time.Parse(time.RFC3339Nano, cursor)
		if err != nil {
			return nil, "", ErrInvalidCursor
		}
		query += ` AND created_at < $2`
		args = append(args, cursorTime)
	}

	query += ` ORDER BY created_at DESC LIMIT $` + strconv.Itoa(len(args)+1)
	args = append(args, limit+1)

	rows, err := q.Query(ctx, query, args...)
	if err != nil {
		return nil, "", fmt.Errorf("query messages: %w", err)
	}
	defer rows.Close()

	messages := make([]Message, 0, limit)
	for rows.Next() {
		var msg Message
		var toolCallsJSON, metadataJSON []byte

		err := rows.Scan(&msg.ID, &msg.ConversationID, &msg.Role, &msg.Content, &toolCallsJSON, &msg.CreatedAt, &metadataJSON)
		if err != nil {
			return nil, "", fmt.Errorf("scan message: %w", err)
		}

		if toolCallsJSON != nil {
			json.Unmarshal(toolCallsJSON, &msg.ToolCalls)
		}
		if metadataJSON != nil {
			json.Unmarshal(metadataJSON, &msg.Metadata)
		}

		messages = append(messages, msg)
	}

	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("iterate messages: %w", err)
	}

	// Check if there are more results
	nextCursor := ""
	if len(messages) > limit {
		messages = messages[:limit]
		lastMsg := messages[len(messages)-1]
		nextCursor = lastMsg.CreatedAt.Format(time.RFC3339Nano)
	}

	return messages, nextCursor, nil
}

func requestDigest(parts ...string) string {
	h := sha256.New()
	for i, part := range parts {
		if i > 0 {
			h.Write([]byte("\x00"))
		}
		h.Write([]byte(part))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
