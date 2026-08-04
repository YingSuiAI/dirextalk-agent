package knowledge

import (
	"context"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

// Capability implements the agent.knowledge.v1 capability
type Capability struct{}

func NewCapability() *Capability {
	return &Capability{}
}

func (c *Capability) Descriptor() *capv1.CapabilityDescriptor {
	return &capv1.CapabilityDescriptor{
		CapabilityId:    "agent.knowledge.v1",
		SemanticVersion: "1.0.0",
		ProtocolVersion: 1,
		DisplayName:     "Knowledge & Attachments",
		Description:     "Knowledge base and attachment management",
		Readiness:       true,
		Operations: []*capv1.OperationDescriptor{
			{
				OperationId:     "upload_attachment",
				DisplayName:     "Upload Attachment",
				OperationType:   capv1.OperationType_OPERATION_TYPE_MUTATION,
				Audience:        []capv1.Audience{capv1.Audience_AUDIENCE_FLUTTER_CLIENT},
				RiskLevel:       capv1.RiskLevel_RISK_LEVEL_ELEVATED,
				RequiredScopes:  []string{"agent:knowledge:write"},
			},
			{
				OperationId:     "search_knowledge",
				DisplayName:     "Search Knowledge",
				OperationType:   capv1.OperationType_OPERATION_TYPE_READ,
				Audience:        []capv1.Audience{capv1.Audience_AUDIENCE_NATIVE_AGENT},
				RiskLevel:       capv1.RiskLevel_RISK_LEVEL_SAFE,
				RequiredScopes:  []string{"agent:knowledge:read"},
			},
		},
	}
}

func (c *Capability) HandleOperation(ctx context.Context, operationID string, inputJSON []byte) ([]byte, error) {
	// TODO: Migrate from coreknowledge package
	return nil, nil
}
