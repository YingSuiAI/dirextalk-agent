package agentcapability

import (
	"context"
	"fmt"
	"strings"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretexttool"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

const (
	textToolGetInputSchema      = `{"additionalProperties":false,"properties":{},"type":"object"}`
	textToolUpdateInputSchema   = `{"additionalProperties":false,"properties":{"enabled":{"type":"boolean"},"expected_revision":{"minimum":0,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"},"tools":{"items":{"additionalProperties":false,"properties":{"enabled":{"type":"boolean"},"name":{"maxLength":64,"minLength":1,"type":"string"},"order":{"minimum":0,"type":"integer"},"system_prompt":{"maxLength":16384,"minLength":1,"type":"string"},"tool_id":{"anyOf":[{"enum":["translation","summary","explanation","search"],"type":"string"},{"format":"uuid","type":"string"}]}},"required":["tool_id","name","system_prompt","order","enabled"],"type":"object"},"maxItems":32,"type":"array"}},"required":["idempotency_key","expected_revision","enabled","tools"],"type":"object"}`
	textToolConfigResultSchema  = `{"additionalProperties":false,"properties":{"enabled":{"type":"boolean"},"revision":{"minimum":0,"type":"integer"},"tools":{"items":{"additionalProperties":false,"properties":{"enabled":{"type":"boolean"},"name":{"maxLength":64,"minLength":1,"type":"string"},"order":{"minimum":0,"type":"integer"},"system_prompt":{"maxLength":16384,"minLength":1,"type":"string"},"tool_id":{"anyOf":[{"enum":["translation","summary","explanation","search"],"type":"string"},{"format":"uuid","type":"string"}]}},"required":["tool_id","name","system_prompt","order","enabled"],"type":"object"},"maxItems":32,"type":"array"},"updated_at":{"format":"date-time","type":"string"}},"required":["enabled","revision","tools","updated_at"],"type":"object"}`
	textToolExecuteInputSchema  = `{"additionalProperties":false,"properties":{"selected_text":{"maxLength":65536,"minLength":1,"type":"string"},"tool_id":{"anyOf":[{"enum":["translation","summary","explanation","search"],"type":"string"},{"format":"uuid","type":"string"}]}},"required":["tool_id","selected_text"],"type":"object"}`
	textToolExecuteResultSchema = `{"additionalProperties":false,"properties":{"output":{"maxLength":65536,"minLength":1,"type":"string"},"sources":{"items":{"additionalProperties":false,"properties":{"snippet":{"maxLength":4096,"type":"string"},"title":{"maxLength":512,"minLength":1,"type":"string"},"url":{"maxLength":8192,"minLength":1,"type":"string"}},"required":["title","url","snippet"],"type":"object"},"maxItems":5,"type":"array"},"tool_id":{"anyOf":[{"enum":["translation","summary","explanation","search"],"type":"string"},{"format":"uuid","type":"string"}]}},"required":["tool_id","output","sources"],"type":"object"}`
)

// execute is a MUTATION so the shared Capability ledger retains its bounded
// public result/event JSON. The ledger stores request_json as {}, so selected
// text is never durable; restart recovery marks pending/running execution
// uncertain and never invokes this handler automatically.
type coreTextToolCapability struct{ service *coretexttool.Service }

func NewCoreTextToolCapability(service *coretexttool.Service) Capability {
	return &coreTextToolCapability{service: service}
}

func (c *coreTextToolCapability) Descriptor() *capv1.CapabilityDescriptor {
	descriptor := capabilityDescriptor("agent.text_tools.v1", "Text Tools", "Agent-owned configurable one-shot text transforms", []capabilityOperation{
		{ID: "get_config", DisplayName: "Get text tools", Description: "Read text-tool configuration.", Type: capv1.OperationType_OPERATION_TYPE_READ, Scope: "agent:text_tools:read", InputSchema: textToolGetInputSchema, ResultSchema: textToolConfigResultSchema},
		{ID: "update_config", DisplayName: "Update text tools", Description: "Replace text-tool configuration.", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:text_tools:write", InputSchema: textToolUpdateInputSchema, ResultSchema: textToolConfigResultSchema},
		{ID: "execute", DisplayName: "Execute text tool", Description: "Run a one-shot text transform without conversation persistence.", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:text_tools:execute", InputSchema: textToolExecuteInputSchema, ResultSchema: textToolExecuteResultSchema},
	})
	for _, operation := range descriptor.Operations {
		operation.Audience = []capv1.Audience{capv1.Audience_AUDIENCE_OWNER_CLIENT}
		if operation.OperationId == "execute" {
			operation.TimeoutClass = "medium"
			operation.MaxRequestSizeBytes = 128 << 10
		}
	}
	return descriptor
}

func (c *coreTextToolCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	if c == nil || c.service == nil {
		return nil, coretexttool.ErrRepository
	}
	if err := requireCapabilityIdentity(ctx); err != nil {
		return nil, err
	}
	permission, _ := capabilityclient.PermissionFromContext(ctx)
	owner, generation := strings.TrimSpace(permission.GetAuthenticatedOwnerId()), permission.GetAccountGeneration()
	switch operationID {
	case "get_config":
		if err := requireEmptyObject(raw); err != nil {
			return nil, err
		}
		value, err := c.service.Get(ctx, owner, generation)
		return marshalResult(value, err)
	case "update_config":
		var request struct {
			IdempotencyKey   string               `json:"idempotency_key"`
			ExpectedRevision *int64               `json:"expected_revision"`
			Enabled          *bool                `json:"enabled"`
			Tools            *[]coretexttool.Tool `json:"tools"`
		}
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, err
		}
		if request.ExpectedRevision == nil || request.Enabled == nil || request.Tools == nil {
			return nil, coretexttool.ErrInvalid
		}
		value, err := c.service.Update(ctx, coretexttool.UpdateCommand{OwnerID: owner, AccountGeneration: generation, IdempotencyKey: request.IdempotencyKey, ExpectedRevision: *request.ExpectedRevision, Enabled: *request.Enabled, Tools: *request.Tools})
		return marshalResult(value, err)
	case "execute":
		var request struct {
			ToolID       string `json:"tool_id"`
			SelectedText string `json:"selected_text"`
		}
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, err
		}
		value, err := c.service.Execute(ctx, coretexttool.ExecuteCommand{OwnerID: owner, AccountGeneration: generation, ToolID: request.ToolID, SelectedText: request.SelectedText})
		return marshalResult(value, err)
	default:
		return nil, fmt.Errorf("unknown text tool operation %q", operationID)
	}
}
