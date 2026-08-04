package tasks

import (
	"context"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

// Capability implements the agent.tasks.v1 capability
type Capability struct{}

func NewCapability() *Capability {
	return &Capability{}
}

func (c *Capability) Descriptor() *capv1.CapabilityDescriptor {
	return &capv1.CapabilityDescriptor{
		CapabilityId:    "agent.tasks.v1",
		SemanticVersion: "1.0.0",
		ProtocolVersion: 1,
		DisplayName:     "Tasks & Schedules",
		Description:     "Task and schedule management",
		Readiness:       true,
		Operations: []*capv1.OperationDescriptor{
			{
				OperationId:     "create_task",
				DisplayName:     "Create Task",
				OperationType:   capv1.OperationType_OPERATION_TYPE_MUTATION,
				Audience:        []capv1.Audience{capv1.Audience_AUDIENCE_UNSPECIFIED},
				RiskLevel:       capv1.RiskLevel_RISK_LEVEL_SAFE,
				RequiredScopes:  []string{"agent:tasks:write"},
			},
			{
				OperationId:     "list_tasks",
				DisplayName:     "List Tasks",
				OperationType:   capv1.OperationType_OPERATION_TYPE_READ,
				Audience:        []capv1.Audience{capv1.Audience_AUDIENCE_UNSPECIFIED},
				RiskLevel:       capv1.RiskLevel_RISK_LEVEL_SAFE,
				RequiredScopes:  []string{"agent:tasks:read"},
			},
		},
	}
}

func (c *Capability) HandleOperation(ctx context.Context, operationID string, inputJSON []byte) ([]byte, error) {
	// TODO: Migrate from coretask package
	return nil, nil
}
