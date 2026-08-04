package chat

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Store manages conversation persistence
type Store struct {
	db *sql.DB
}

// NewStore creates a new conversation store
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// Conversation represents a chat conversation
type Conversation struct {
	ID                string
	OwnerID           string
	Title             string
	Revision          int64
	CreatedAt         time.Time
	UpdatedAt         time.Time
	LastMessageAt     *time.Time
	MessageCount      int
	SystemPrompt      string
	ModelConfig       map[string]interface{}
	Metadata          map[string]interface{}
}

// Message represents a single message in a conversation
type Message struct {
	ID             string
	ConversationID string
	Role           string // user, assistant, system
	Content        string
	ToolCalls      []map[string]interface{}
	CreatedAt      time.Time
	Metadata       map[string]interface{}
}

// CreateConversation creates a new conversation
func (s *Store) CreateConversation(ctx context.Context, ownerID, title string, idempotencyKey string) (*Conversation, bool, error) {
	// Check idempotency
	existing, err := s.getByIdempotencyKey(ctx, ownerID, idempotencyKey)
	if err == nil && existing != nil {
		return existing, true, nil // replayed
	}

	conv := &Conversation{
		ID:        generateConversationID(),
		OwnerID:   ownerID,
		Title:     title,
		Revision:  1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	query := `
		INSERT INTO conversations (id, owner_id, title, revision, created_at, updated_at, idempotency_key)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err = s.db.ExecContext(ctx, query,
		conv.ID, conv.OwnerID, conv.Title, conv.Revision,
		conv.CreatedAt, conv.UpdatedAt, idempotencyKey)
	if err != nil {
		return nil, false, err
	}

	return conv, false, nil
}

// ListConversations lists conversations for an owner
func (s *Store) ListConversations(ctx context.Context, ownerID string, limit, offset int) ([]*Conversation, error) {
	query := `
		SELECT id, owner_id, title, revision, created_at, updated_at, last_message_at, message_count
		FROM conversations
		WHERE owner_id = $1
		ORDER BY COALESCE(last_message_at, created_at) DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := s.db.QueryContext(ctx, query, ownerID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var conversations []*Conversation
	for rows.Next() {
		conv := &Conversation{}
		var lastMessageAt sql.NullTime
		err := rows.Scan(
			&conv.ID, &conv.OwnerID, &conv.Title, &conv.Revision,
			&conv.CreatedAt, &conv.UpdatedAt, &lastMessageAt, &conv.MessageCount,
		)
		if err != nil {
			return nil, err
		}
		if lastMessageAt.Valid {
			conv.LastMessageAt = &lastMessageAt.Time
		}
		conversations = append(conversations, conv)
	}

	return conversations, nil
}

// GetConversation retrieves a conversation by ID
func (s *Store) GetConversation(ctx context.Context, ownerID, conversationID string) (*Conversation, error) {
	query := `
		SELECT id, owner_id, title, revision, created_at, updated_at,
		       last_message_at, message_count, system_prompt, model_config, metadata
		FROM conversations
		WHERE id = $1 AND owner_id = $2
	`

	conv := &Conversation{}
	var lastMessageAt sql.NullTime
	var modelConfigJSON, metadataJSON []byte

	err := s.db.QueryRowContext(ctx, query, conversationID, ownerID).Scan(
		&conv.ID, &conv.OwnerID, &conv.Title, &conv.Revision,
		&conv.CreatedAt, &conv.UpdatedAt, &lastMessageAt, &conv.MessageCount,
		&conv.SystemPrompt, &modelConfigJSON, &metadataJSON,
	)
	if err != nil {
		return nil, err
	}

	if lastMessageAt.Valid {
		conv.LastMessageAt = &lastMessageAt.Time
	}
	if len(modelConfigJSON) > 0 {
		json.Unmarshal(modelConfigJSON, &conv.ModelConfig)
	}
	if len(metadataJSON) > 0 {
		json.Unmarshal(metadataJSON, &conv.Metadata)
	}

	return conv, nil
}

// AddMessage adds a message to a conversation
func (s *Store) AddMessage(ctx context.Context, msg *Message) error {
	toolCallsJSON, _ := json.Marshal(msg.ToolCalls)
	metadataJSON, _ := json.Marshal(msg.Metadata)

	query := `
		INSERT INTO conversation_messages
		(id, conversation_id, role, content, tool_calls, created_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := s.db.ExecContext(ctx, query,
		msg.ID, msg.ConversationID, msg.Role, msg.Content,
		toolCallsJSON, msg.CreatedAt, metadataJSON)
	if err != nil {
		return err
	}

	// Update conversation stats
	updateQuery := `
		UPDATE conversations
		SET message_count = message_count + 1,
		    last_message_at = $1,
		    updated_at = $1,
		    revision = revision + 1
		WHERE id = $2
	`
	_, err = s.db.ExecContext(ctx, updateQuery, msg.CreatedAt, msg.ConversationID)
	return err
}

// GetMessages retrieves messages for a conversation
func (s *Store) GetMessages(ctx context.Context, conversationID string, limit int) ([]*Message, error) {
	query := `
		SELECT id, conversation_id, role, content, tool_calls, created_at, metadata
		FROM conversation_messages
		WHERE conversation_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := s.db.QueryContext(ctx, query, conversationID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		msg := &Message{}
		var toolCallsJSON, metadataJSON []byte

		err := rows.Scan(
			&msg.ID, &msg.ConversationID, &msg.Role, &msg.Content,
			&toolCallsJSON, &msg.CreatedAt, &metadataJSON,
		)
		if err != nil {
			return nil, err
		}

		if len(toolCallsJSON) > 0 {
			json.Unmarshal(toolCallsJSON, &msg.ToolCalls)
		}
		if len(metadataJSON) > 0 {
			json.Unmarshal(metadataJSON, &msg.Metadata)
		}

		messages = append(messages, msg)
	}

	// Reverse to chronological order
	for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
		messages[i], messages[j] = messages[j], messages[i]
	}

	return messages, nil
}

// DeleteConversation deletes a conversation
func (s *Store) DeleteConversation(ctx context.Context, ownerID, conversationID string, expectedRevision int64, idempotencyKey string) (*Conversation, bool, error) {
	// Check idempotency
	existing, err := s.getDeletedByIdempotencyKey(ctx, ownerID, idempotencyKey)
	if err == nil && existing != nil {
		return existing, true, nil
	}

	// Get current conversation
	conv, err := s.GetConversation(ctx, ownerID, conversationID)
	if err != nil {
		return nil, false, err
	}

	// Check revision
	if conv.Revision != expectedRevision {
		return nil, false, fmt.Errorf("revision mismatch: expected %d, got %d", expectedRevision, conv.Revision)
	}

	// Delete messages first
	_, err = s.db.ExecContext(ctx, "DELETE FROM conversation_messages WHERE conversation_id = $1", conversationID)
	if err != nil {
		return nil, false, err
	}

	// Delete conversation
	_, err = s.db.ExecContext(ctx, "DELETE FROM conversations WHERE id = $1 AND owner_id = $2", conversationID, ownerID)
	if err != nil {
		return nil, false, err
	}

	// Record deletion idempotency
	s.recordDeletion(ctx, ownerID, idempotencyKey, conv)

	return conv, false, nil
}

func (s *Store) getByIdempotencyKey(ctx context.Context, ownerID, key string) (*Conversation, error) {
	// TODO: Implement idempotency table lookup
	return nil, sql.ErrNoRows
}

func (s *Store) getDeletedByIdempotencyKey(ctx context.Context, ownerID, key string) (*Conversation, error) {
	// TODO: Implement
	return nil, sql.ErrNoRows
}

func (s *Store) recordDeletion(ctx context.Context, ownerID, key string, conv *Conversation) {
	// TODO: Record in idempotency table
}

func generateConversationID() string {
	return fmt.Sprintf("conv_%d", time.Now().UnixNano())
}
