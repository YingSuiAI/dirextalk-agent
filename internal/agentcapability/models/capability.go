package models

import (
	"context"
	"encoding/json"
	"fmt"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

// Capability implements the agent.models.v1 capability
type Capability struct{}

// NewCapability creates a new models capability
func NewCapability() *Capability {
	return &Capability{}
}

// Descriptor returns the capability descriptor
func (c *Capability) Descriptor() *capv1.CapabilityDescriptor {
	return &capv1.CapabilityDescriptor{
		CapabilityId:    "agent.models.v1",
		SemanticVersion: "1.0.0",
		ProtocolVersion: 1,
		DisplayName:     "Model Profiles",
		Description:     "Model configuration and profile management",
		Readiness:       true,
		Operations: []*capv1.OperationDescriptor{
			{
				OperationId:   "list_models",
				DisplayName:   "List Models",
				Description:   "List available model profiles",
				OperationType: capv1.OperationType_OPERATION_TYPE_READ,
				Audience:      []capv1.Audience{capv1.Audience_AUDIENCE_UNSPECIFIED},
				RiskLevel:     capv1.RiskLevel_RISK_LEVEL_SAFE,
				RequiredScopes: []string{"agent:models:read"},
			},
			{
				OperationId:   "get_model",
				DisplayName:   "Get Model",
				Description:   "Get a specific model profile",
				OperationType: capv1.OperationType_OPERATION_TYPE_READ,
				Audience:      []capv1.Audience{capv1.Audience_AUDIENCE_UNSPECIFIED},
				RiskLevel:     capv1.RiskLevel_RISK_LEVEL_SAFE,
				RequiredScopes: []string{"agent:models:read"},
			},
			{
				OperationId:   "update_model_config",
				DisplayName:   "Update Model Config",
				Description:   "Update model configuration",
				OperationType: capv1.OperationType_OPERATION_TYPE_MUTATION,
				Audience:      []capv1.Audience{capv1.Audience_AUDIENCE_UNSPECIFIED},
				RiskLevel:     capv1.RiskLevel_RISK_LEVEL_SAFE,
				RequiredScopes: []string{"agent:models:write"},
			},
		},
	}
}

// HandleOperation handles an operation request
func (c *Capability) HandleOperation(ctx context.Context, operationID string, inputJSON []byte) ([]byte, error) {
	switch operationID {
	case "list_models":
		return c.listModels(ctx)
	case "get_model":
		return c.getModel(ctx, inputJSON)
	case "update_model_config":
		return c.updateModelConfig(ctx, inputJSON)
	default:
		return nil, fmt.Errorf("operation not found")
	}
}

func (c *Capability) listModels(ctx context.Context) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"models": []interface{}{},
	})
}

func (c *Capability) getModel(ctx context.Context, inputJSON []byte) ([]byte, error) {
	return nil, nil
}

func (c *Capability) updateModelConfig(ctx context.Context, inputJSON []byte) ([]byte, error) {
	return nil, nil
}
