package skills

import (
	"context"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

// Capability implements the agent.skills.v1 capability
type Capability struct{}

func NewCapability() *Capability {
	return &Capability{}
}

func (c *Capability) Descriptor() *capv1.CapabilityDescriptor {
	return &capv1.CapabilityDescriptor{
		CapabilityId:    "agent.skills.v1",
		SemanticVersion: "1.0.0",
		ProtocolVersion: 1,
		DisplayName:     "Skills & MCP",
		Description:     "Skills and MCP server management",
		Readiness:       true,
		Operations: []*capv1.OperationDescriptor{
			{
				OperationId:     "list_skills",
				DisplayName:     "List Skills",
				OperationType:   capv1.OperationType_OPERATION_TYPE_READ,
				Audience:        []capv1.Audience{capv1.Audience_AUDIENCE_UNSPECIFIED},
				RiskLevel:       capv1.RiskLevel_RISK_LEVEL_SAFE,
				RequiredScopes:  []string{"agent:skills:read"},
			},
			{
				OperationId:     "invoke_skill",
				DisplayName:     "Invoke Skill",
				OperationType:   capv1.OperationType_OPERATION_TYPE_MUTATION,
				Audience:        []capv1.Audience{capv1.Audience_AUDIENCE_NATIVE_AGENT},
				RiskLevel:       capv1.RiskLevel_RISK_LEVEL_SAFE,
				RequiredScopes:  []string{"agent:skills:execute"},
			},
		},
	}
}

func (c *Capability) HandleOperation(ctx context.Context, operationID string, inputJSON []byte) ([]byte, error) {
	// TODO: Migrate from native_agent skills
	return nil, nil
}
