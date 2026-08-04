package knowledge

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// KnowledgeItem represents a knowledge base entry
type KnowledgeItem struct {
	ID          string
	OwnerID     string
	Title       string
	Content     string
	ContentType string
	Embedding   []float32
	Metadata    map[string]interface{}
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Attachment represents a file attachment
type Attachment struct {
	ID             string
	OwnerID        string
	ConversationID string
	Filename       string
	ContentType    string
	SizeBytes      int64
	StoragePath    string
	CreatedAt      time.Time
	Metadata       map[string]interface{}
}

// KnowledgeStore manages knowledge and attachments
type KnowledgeStore struct {
	db *sql.DB
}

func NewKnowledgeStore(db *sql.DB) *KnowledgeStore {
	return &KnowledgeStore{db: db}
}

// AddKnowledge adds knowledge to the database
func (s *KnowledgeStore) AddKnowledge(ctx context.Context, item *KnowledgeItem) error {
	query := `
		INSERT INTO agent_knowledge (id, owner_id, title, content, content_type, embedding, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	metadataJSON, _ := json.Marshal(item.Metadata)
	_, err := s.db.ExecContext(ctx, query,
		item.ID, item.OwnerID, item.Title, item.Content, item.ContentType,
		item.Embedding, metadataJSON, item.CreatedAt, item.UpdatedAt)
	return err
}

// SearchKnowledge searches knowledge base with vector similarity
func (s *KnowledgeStore) SearchKnowledge(ctx context.Context, ownerID string, query string, limit int) ([]*KnowledgeItem, error) {
	// TODO: Implement vector search with embeddings
	sqlQuery := `
		SELECT id, owner_id, title, content, content_type, metadata, created_at, updated_at
		FROM agent_knowledge
		WHERE owner_id = $1 AND content LIKE $2
		ORDER BY created_at DESC
		LIMIT $3
	`

	rows, err := s.db.QueryContext(ctx, sqlQuery, ownerID, "%"+query+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []*KnowledgeItem
	for rows.Next() {
		item := &KnowledgeItem{}
		var metadataJSON []byte
		err := rows.Scan(&item.ID, &item.OwnerID, &item.Title, &item.Content,
			&item.ContentType, &metadataJSON, &item.CreatedAt, &item.UpdatedAt)
		if err != nil {
			return nil, err
		}
		if len(metadataJSON) > 0 {
			json.Unmarshal(metadataJSON, &item.Metadata)
		}
		items = append(items, item)
	}

	return items, nil
}

// UploadAttachment stores an attachment
func (s *KnowledgeStore) UploadAttachment(ctx context.Context, att *Attachment) error {
	query := `
		INSERT INTO agent_attachments (id, owner_id, conversation_id, filename, content_type, size_bytes, storage_path, created_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	metadataJSON, _ := json.Marshal(att.Metadata)
	_, err := s.db.ExecContext(ctx, query,
		att.ID, att.OwnerID, att.ConversationID, att.Filename, att.ContentType,
		att.SizeBytes, att.StoragePath, att.CreatedAt, metadataJSON)
	return err
}

// ListAttachments lists attachments for a conversation
func (s *KnowledgeStore) ListAttachments(ctx context.Context, ownerID, conversationID string) ([]*Attachment, error) {
	query := `
		SELECT id, owner_id, conversation_id, filename, content_type, size_bytes, storage_path, created_at, metadata
		FROM agent_attachments
		WHERE owner_id = $1 AND conversation_id = $2
		ORDER BY created_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query, ownerID, conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attachments []*Attachment
	for rows.Next() {
		att := &Attachment{}
		var metadataJSON []byte
		err := rows.Scan(&att.ID, &att.OwnerID, &att.ConversationID, &att.Filename,
			&att.ContentType, &att.SizeBytes, &att.StoragePath, &att.CreatedAt, &metadataJSON)
		if err != nil {
			return nil, err
		}
		if len(metadataJSON) > 0 {
			json.Unmarshal(metadataJSON, &att.Metadata)
		}
		attachments = append(attachments, att)
	}

	return attachments, nil
}

// HandleOperation handles knowledge operations
func (c *Capability) HandleOperation(ctx context.Context, operationID string, inputJSON []byte) ([]byte, error) {
	store := NewKnowledgeStore(nil) // TODO: Pass real DB

	switch operationID {
	case "upload_attachment":
		var att Attachment
		if err := json.Unmarshal(inputJSON, &att); err != nil {
			return nil, err
		}
		att.CreatedAt = time.Now()
		if err := store.UploadAttachment(ctx, &att); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]interface{}{"attachment_id": att.ID})

	case "search_knowledge":
		var req struct {
			Query string `json:"query"`
			Limit int    `json:"limit"`
		}
		if err := json.Unmarshal(inputJSON, &req); err != nil {
			return nil, err
		}
		if req.Limit == 0 {
			req.Limit = 10
		}
		items, err := store.SearchKnowledge(ctx, "owner", req.Query, req.Limit)
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]interface{}{"items": items})

	default:
		return nil, nil
	}
}
