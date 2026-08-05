package agentcapability

import (
	"context"
	"fmt"
	"strings"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/corewebsearch"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

const (
	webSearchConfigSchema     = `{"additionalProperties":false,"properties":{"api_key_configured":{"type":"boolean"},"api_key_hint":{"type":"string"},"enabled":{"type":"boolean"},"provider":{"enum":["tavily"],"type":"string"},"revision":{"minimum":0,"type":"integer"},"tested_at":{"format":"date-time","type":"string"},"updated_at":{"format":"date-time","type":"string"}},"required":["enabled","provider","api_key_configured","revision"],"type":"object"}`
	webSearchUpdateSchema     = `{"additionalProperties":false,"properties":{"api_key":{"maxLength":4096,"minLength":1,"type":"string","writeOnly":true},"api_key_clear":{"type":"boolean"},"enabled":{"type":"boolean"},"expected_revision":{"minimum":0,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"},"provider":{"enum":["tavily"],"type":"string"}},"required":["idempotency_key","expected_revision"],"type":"object"}`
	webSearchTestResultSchema = `{"additionalProperties":false,"properties":{"api_key_configured":{"type":"boolean"},"enabled":{"type":"boolean"},"ok":{"type":"boolean"},"provider":{"enum":["tavily"],"type":"string"},"result_count":{"minimum":0,"type":"integer"},"revision":{"minimum":1,"type":"integer"},"tested_at":{"format":"date-time","type":"string"}},"required":["ok","provider","result_count","tested_at","enabled","api_key_configured","revision"],"type":"object"}`
)

type coreWebSearchCapability struct {
	service *corewebsearch.Service
}

func NewCoreWebSearchCapability(service *corewebsearch.Service) Capability {
	return &coreWebSearchCapability{service: service}
}

func (c *coreWebSearchCapability) Descriptor() *capv1.CapabilityDescriptor {
	return capabilityDescriptor("agent.web_search.v1", "Web Search", "Agent-owned encrypted web search configuration and Tavily connectivity", []capabilityOperation{
		{ID: "get_config", DisplayName: "Get web search config", Description: "Read the non-secret Web Search configuration.", Type: capv1.OperationType_OPERATION_TYPE_READ, Scope: "agent:web_search:read", InputSchema: emptyObjectSchema, ResultSchema: webSearchConfigSchema},
		{ID: "update_config", DisplayName: "Update web search config", Description: "Update Web Search configuration and its write-only credential.", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:web_search:write", InputSchema: webSearchUpdateSchema, ResultSchema: webSearchConfigSchema},
		{ID: "test", DisplayName: "Test web search", Description: "Test the stored Web Search credential.", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:web_search:write", InputSchema: emptyObjectSchema, ResultSchema: webSearchTestResultSchema},
	})
}

func (c *coreWebSearchCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	if c == nil || c.service == nil {
		return nil, corewebsearch.ErrRepository
	}
	if err := requireCapabilityIdentity(ctx); err != nil {
		return nil, err
	}
	permission, _ := capabilityclient.PermissionFromContext(ctx)
	ownerID := strings.TrimSpace(permission.GetAuthenticatedOwnerId())
	accountGeneration := permission.GetAccountGeneration()
	switch operationID {
	case "get_config":
		if err := requireEmptyObject(raw); err != nil {
			return nil, err
		}
		value, err := c.service.Get(ctx, ownerID, accountGeneration)
		return marshalResult(value, err)
	case "update_config":
		var request struct {
			IdempotencyKey   string  `json:"idempotency_key"`
			ExpectedRevision int64   `json:"expected_revision"`
			Enabled          *bool   `json:"enabled,omitempty"`
			Provider         *string `json:"provider,omitempty"`
			APIKey           *string `json:"api_key,omitempty"`
			APIKeyClear      bool    `json:"api_key_clear,omitempty"`
		}
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, err
		}
		var provider *corewebsearch.Provider
		if request.Provider != nil {
			value := corewebsearch.Provider(strings.ToLower(strings.TrimSpace(*request.Provider)))
			provider = &value
		}
		value, err := c.service.Update(ctx, corewebsearch.UpdateCommand{
			OwnerID: ownerID, AccountGeneration: accountGeneration, IdempotencyKey: request.IdempotencyKey, ExpectedRevision: request.ExpectedRevision,
			Enabled: request.Enabled, Provider: provider, APIKey: request.APIKey, APIKeyClear: request.APIKeyClear,
		})
		return marshalResult(value, err)
	case "test":
		if err := requireEmptyObject(raw); err != nil {
			return nil, err
		}
		value, err := c.service.Test(ctx, ownerID, accountGeneration)
		return marshalResult(value, err)
	default:
		return nil, fmt.Errorf("unknown web search operation %q", operationID)
	}
}
