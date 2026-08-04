package echo

import (
	"context"
	"encoding/json"
	"time"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

// Capability implements a simple echo capability for testing
type Capability struct{}

// NewCapability creates a new echo capability
func NewCapability() *Capability {
	return &Capability{}
}

// Descriptor returns the capability descriptor
func (c *Capability) Descriptor() *capv1.CapabilityDescriptor {
	return &capv1.CapabilityDescriptor{
		CapabilityId:    "agent.echo.v1",
		SemanticVersion: "1.0.0",
		ProtocolVersion: 1,
		DisplayName:     "Echo",
		Description:     "Echo test capability for testing and debugging",
		Readiness:       true,
		Operations: []*capv1.OperationDescriptor{
			{
				OperationId:   "echo",
				DisplayName:   "Echo",
				Description:   "Echo back the input",
				OperationType: capv1.OperationType_OPERATION_TYPE_READ,
				Audience:      []capv1.Audience{capv1.Audience_AUDIENCE_UNSPECIFIED},
				RiskLevel:     capv1.RiskLevel_RISK_LEVEL_SAFE,
				RequiredScopes: []string{},
				InputSchemaJson: `{
					"type": "object",
					"properties": {
						"message": {"type": "string"}
					}
				}`,
			},
		},
	}
}

// HandleOperation handles an echo operation
func (c *Capability) HandleOperation(ctx context.Context, operationID string, inputJSON []byte) ([]byte, error) {
	if operationID != "echo" {
		return nil, nil
	}

	var input map[string]interface{}
	if len(inputJSON) > 0 {
		json.Unmarshal(inputJSON, &input)
	}

	output := map[string]interface{}{
		"echo":      input,
		"timestamp": time.Now().Unix(),
		"received":  len(inputJSON),
	}

	return json.Marshal(output)
}
