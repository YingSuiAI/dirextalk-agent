package chat

import (
	"context"
	"encoding/json"
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

var ErrOperationNotFound = capv1.ErrorCode_ERROR_CODE_NOT_FOUND

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
	// TODO: Implement list conversations
	return nil, nil
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
