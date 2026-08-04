package chat

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

// Capability implements the agent.chat.v1 capability
type Capability struct {
	runtime *Runtime
}

// NewCapability creates a new chat capability
func NewCapability() *Capability {
	return &Capability{
		runtime: NewRuntime(),
	}
}

// Descriptor returns the capability descriptor
func (c *Capability) Descriptor() *capv1.CapabilityDescriptor {
	return &capv1.CapabilityDescriptor{
		CapabilityId:    "agent.chat.v1",
		SemanticVersion: "1.0.0",
		ProtocolVersion: 1,
		DisplayName:     "Chat",
		Description:     "Native Agent conversation and chat capabilities",
		Readiness:       true,
		Operations: []*capv1.OperationDescriptor{
			{
				OperationId:   "create_conversation",
				DisplayName:   "Create Conversation",
				Description:   "Create a new conversation",
				OperationType: capv1.OperationType_OPERATION_TYPE_MUTATION,
				Audience:      []capv1.Audience{capv1.Audience_AUDIENCE_FLUTTER_CLIENT},
				RiskLevel:     capv1.RiskLevel_RISK_LEVEL_SAFE,
				RequiredScopes: []string{"agent:chat:write"},
				InputSchemaJson: `{
					"type": "object",
					"properties": {
						"title": {"type": "string"},
						"initial_message": {"type": "string"}
					}
				}`,
			},
			{
				OperationId:   "send_message",
				DisplayName:   "Send Message",
				Description:   "Send a message and get streaming response",
				OperationType: capv1.OperationType_OPERATION_TYPE_MUTATION,
				Audience:      []capv1.Audience{capv1.Audience_AUDIENCE_FLUTTER_CLIENT},
				RiskLevel:     capv1.RiskLevel_RISK_LEVEL_ELEVATED,
				RequiredScopes: []string{"agent:chat:write"},
				InputSchemaJson: `{
					"type": "object",
					"properties": {
						"conversation_id": {"type": "string"},
						"message": {"type": "string"},
						"model_config": {"type": "object"}
					},
					"required": ["conversation_id", "message"]
				}`,
			},
			{
				OperationId:   "list_conversations",
				DisplayName:   "List Conversations",
				Description:   "List all conversations",
				OperationType: capv1.OperationType_OPERATION_TYPE_READ,
				Audience:      []capv1.Audience{capv1.Audience_AUDIENCE_FLUTTER_CLIENT},
				RiskLevel:     capv1.RiskLevel_RISK_LEVEL_SAFE,
				RequiredScopes: []string{"agent:chat:read"},
				InputSchemaJson: `{
					"type": "object",
					"properties": {
						"limit": {"type": "integer"},
						"offset": {"type": "integer"}
					}
				}`,
			},
		},
	}
}

// HandleOperation handles an operation request
func (c *Capability) HandleOperation(ctx context.Context, req *OperationRequest) (*OperationResponse, error) {
	switch req.OperationID {
	case "create_conversation":
		return c.createConversation(ctx, req)
	case "send_message":
		return c.sendMessage(ctx, req)
	case "list_conversations":
		return c.listConversations(ctx, req)
	case "get_conversation":
		return c.getConversation(ctx, req)
	case "delete_conversation":
		return c.deleteConversation(ctx, req)
	case "rename_conversation":
		return c.renameConversation(ctx, req)
	default:
		return nil, ErrOperationNotFound
	}
}

type OperationRequest struct {
	OperationID string
	InputJSON   []byte
	OwnerID     string
}

type OperationResponse struct {
	ResultJSON []byte
	Error      error
}

var ErrOperationNotFound = fmt.Errorf("operation not found")

func (c *Capability) createConversation(ctx context.Context, req *OperationRequest) (*OperationResponse, error) {
	var input struct {
		Title          string `json:"title"`
		InitialMessage string `json:"initial_message"`
	}
	if err := json.Unmarshal(req.InputJSON, &input); err != nil {
		return nil, err
	}

	// Create conversation in database
	conv := &Conversation{
		ID:        generateID(),
		OwnerID:   req.OwnerID,
		Title:     input.Title,
		CreatedAt: time.Now(),
	}

	result, _ := json.Marshal(map[string]interface{}{
		"conversation_id": conv.ID,
		"title":           conv.Title,
		"created_at":      conv.CreatedAt,
	})

	return &OperationResponse{ResultJSON: result}, nil
}

func (c *Capability) sendMessage(ctx context.Context, req *OperationRequest) (*OperationResponse, error) {
	// TODO: Implement streaming message handling
	return nil, nil
}

func (c *Capability) listConversations(ctx context.Context, req *OperationRequest) (*OperationResponse, error) {
	var input struct {
		Limit  int `json:"limit"`
		Offset int `json:"offset"`
	}
	if err := json.Unmarshal(req.InputJSON, &input); err != nil {
		return nil, err
	}
	if input.Limit == 0 {
		input.Limit = 20
	}

	store := NewStore(nil) // TODO: Pass real DB
	conversations, err := store.ListConversations(ctx, req.OwnerID, input.Limit, input.Offset)
	if err != nil {
		return nil, err
	}

	result, _ := json.Marshal(map[string]interface{}{
		"conversations": conversations,
	})
	return &OperationResponse{ResultJSON: result}, nil
}

func (c *Capability) getConversation(ctx context.Context, req *OperationRequest) (*OperationResponse, error) {
	var input struct {
		ConversationID string `json:"conversation_id"`
	}
	if err := json.Unmarshal(req.InputJSON, &input); err != nil {
		return nil, err
	}

	store := NewStore(nil)
	conv, err := store.GetConversation(ctx, req.OwnerID, input.ConversationID)
	if err != nil {
		return nil, err
	}

	// Get messages
	messages, err := store.GetMessages(ctx, input.ConversationID, 100)
	if err != nil {
		return nil, err
	}

	result, _ := json.Marshal(map[string]interface{}{
		"conversation": conv,
		"messages":     messages,
	})
	return &OperationResponse{ResultJSON: result}, nil
}

func (c *Capability) deleteConversation(ctx context.Context, req *OperationRequest) (*OperationResponse, error) {
	var input struct {
		ConversationID   string `json:"conversation_id"`
		ExpectedRevision int64  `json:"expected_revision"`
		IdempotencyKey   string `json:"idempotency_key"`
	}
	if err := json.Unmarshal(req.InputJSON, &input); err != nil {
		return nil, err
	}

	store := NewStore(nil)
	conv, replayed, err := store.DeleteConversation(ctx, req.OwnerID, input.ConversationID, input.ExpectedRevision, input.IdempotencyKey)
	if err != nil {
		return nil, err
	}

	result, _ := json.Marshal(map[string]interface{}{
		"conversation": conv,
		"replayed":     replayed,
	})
	return &OperationResponse{ResultJSON: result}, nil
}

func (c *Capability) renameConversation(ctx context.Context, req *OperationRequest) (*OperationResponse, error) {
	var input struct {
		ConversationID string `json:"conversation_id"`
		Title          string `json:"title"`
	}
	if err := json.Unmarshal(req.InputJSON, &input); err != nil {
		return nil, err
	}

	// TODO: Implement in Store
	result, _ := json.Marshal(map[string]interface{}{
		"conversation_id": input.ConversationID,
		"title":           input.Title,
	})
	return &OperationResponse{ResultJSON: result}, nil
}

type Conversation struct {
	ID        string
	OwnerID   string
	Title     string
	CreatedAt time.Time
}

func generateID() string {
	return "conv_" + time.Now().Format("20060102150405")
}
