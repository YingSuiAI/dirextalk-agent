package agentcapability

import (
	"context"
	"fmt"

	"github.com/YingSuiAI/dirextalk-agent/internal/corememory"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

const (
	memoryConfigResultSchema = `{"additionalProperties":false,"properties":{"embedding_configured":{"type":"boolean"},"embedding_model":{"type":"string"},"embedding_profile_id":{"format":"uuid","type":"string"},"enabled":{"type":"boolean"},"revision":{"minimum":0,"type":"integer"},"updated_at":{"format":"date-time","type":"string"}},"required":["enabled","embedding_configured","revision"],"type":"object"}`
	memoryUpdateInputSchema  = `{"additionalProperties":false,"properties":{"enabled":{"type":"boolean"},"expected_revision":{"minimum":0,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"}},"required":["idempotency_key","expected_revision","enabled"],"type":"object"}`
	memoryStatusResultSchema = `{"additionalProperties":false,"properties":{"active_fact_count":{"minimum":0,"type":"integer"},"embedding_configured":{"type":"boolean"},"embedding_model":{"type":"string"},"embedding_profile_id":{"format":"uuid","type":"string"},"enabled":{"type":"boolean"},"facts":{"items":{"additionalProperties":false,"properties":{"confidence":{"maximum":1,"minimum":0,"type":"number"},"id":{"format":"uuid","type":"string"},"kind":{"enum":["identity","preference","relationship","goal","constraint","context","fact"],"type":"string"},"last_confirmed_at":{"format":"date-time","type":"string"},"predicate":{"type":"string"},"subject":{"enum":["user"],"type":"string"},"valid_from":{"format":"date-time","type":"string"},"value":{"type":"string"}},"required":["id","subject","predicate","value","kind","confidence","valid_from","last_confirmed_at"],"type":"object"},"type":"array"},"failed_observation_count":{"minimum":0,"type":"integer"},"pending_observation_count":{"minimum":0,"type":"integer"},"revision":{"minimum":0,"type":"integer"},"timeline":{"items":{"additionalProperties":false,"properties":{"effective_at":{"format":"date-time","type":"string"},"kind":{"enum":["added","confirmed","replaced","retracted"],"type":"string"},"observed_at":{"format":"date-time","type":"string"},"summary":{"type":"string"}},"required":["kind","summary","effective_at","observed_at"],"type":"object"},"type":"array"},"timeline_event_count":{"minimum":0,"type":"integer"},"updated_at":{"format":"date-time","type":"string"}},"required":["enabled","embedding_configured","revision","active_fact_count","timeline_event_count","pending_observation_count","failed_observation_count","facts","timeline"],"type":"object"}`
)

type coreMemoryCapability struct{ service *corememory.Service }

func NewCoreMemoryCapability(service *corememory.Service) Capability {
	return &coreMemoryCapability{service: service}
}

func (c *coreMemoryCapability) Descriptor() *capv1.CapabilityDescriptor {
	descriptor := capabilityDescriptor("agent.memory.v1", "Conversation Memory", "Agent-owned automatic user facts, conflict timeline, and memory controls", []capabilityOperation{
		{ID: "get_config", DisplayName: "Get memory config", Description: "Read automatic conversation-memory configuration.", Type: capv1.OperationType_OPERATION_TYPE_READ, Scope: "agent:memory:read", InputSchema: emptyObjectSchema, ResultSchema: memoryConfigResultSchema},
		{ID: "update_config", DisplayName: "Update memory config", Description: "Enable or disable automatic conversation memory.", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:memory:write", InputSchema: memoryUpdateInputSchema, ResultSchema: memoryConfigResultSchema},
		{ID: "status", DisplayName: "Get memory status", Description: "Read current user facts and recent conflict history.", Type: capv1.OperationType_OPERATION_TYPE_READ, Scope: "agent:memory:read", InputSchema: emptyObjectSchema, ResultSchema: memoryStatusResultSchema},
	})
	for _, operation := range descriptor.Operations {
		operation.Audience = []capv1.Audience{capv1.Audience_AUDIENCE_OWNER_CLIENT}
	}
	return descriptor
}

func (c *coreMemoryCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	if c == nil || c.service == nil {
		return nil, corememory.ErrRepository
	}
	if err := requireCapabilityIdentity(ctx); err != nil {
		return nil, err
	}
	switch operationID {
	case "get_config":
		if err := requireEmptyObject(raw); err != nil {
			return nil, err
		}
		return marshalResult(c.service.GetConfig(ctx))
	case "status":
		if err := requireEmptyObject(raw); err != nil {
			return nil, err
		}
		return marshalResult(c.service.Status(ctx))
	case "update_config":
		var request struct {
			IdempotencyKey   string `json:"idempotency_key"`
			ExpectedRevision *int64 `json:"expected_revision"`
			Enabled          *bool  `json:"enabled"`
		}
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, err
		}
		if request.ExpectedRevision == nil || request.Enabled == nil {
			return nil, corememory.ErrInvalid
		}
		return marshalResult(c.service.UpdateConfig(ctx, corememory.UpdateConfigCommand{IdempotencyKey: request.IdempotencyKey, ExpectedRevision: *request.ExpectedRevision, Enabled: *request.Enabled}))
	default:
		return nil, fmt.Errorf("unknown memory operation %q", operationID)
	}
}
