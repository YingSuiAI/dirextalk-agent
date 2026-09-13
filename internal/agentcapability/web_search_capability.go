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
	webSearchGroupResetSchema = `{"additionalProperties":false,"properties":{"idempotency_key":{"format":"uuid","type":"string"},"room_id":{"maxLength":1024,"minLength":2,"type":"string"}},"required":["idempotency_key","room_id"],"type":"object"}`
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
		{ID: "reset_group_config", DisplayName: "Reset group web search", Description: "Remove one group's own Web Search configuration so that group inherits the owner's provider again.", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:web_search:write", InputSchema: webSearchGroupResetSchema, ResultSchema: webSearchConfigSchema},
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
		scope, err := webSearchScopeFromRequest(ownerID, accountGeneration, raw)
		if err != nil {
			return nil, err
		}
		value, err := c.service.Get(ctx, scope)
		return marshalResult(value, err)
	case "update_config":
		var request struct {
			RoomID           string  `json:"room_id,omitempty"`
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
			Scope:   webSearchScope(ownerID, accountGeneration, request.RoomID),
			OwnerID: ownerID, AccountGeneration: accountGeneration, IdempotencyKey: request.IdempotencyKey, ExpectedRevision: request.ExpectedRevision,
			Enabled: request.Enabled, Provider: provider, APIKey: request.APIKey, APIKeyClear: request.APIKeyClear,
		})
		return marshalResult(value, err)
	case "test":
		scope, err := webSearchScopeFromRequest(ownerID, accountGeneration, raw)
		if err != nil {
			return nil, err
		}
		value, err := c.service.Test(ctx, scope)
		return marshalResult(value, err)
	case "reset_group_config":
		var request struct {
			RoomID         string `json:"room_id"`
			IdempotencyKey string `json:"idempotency_key"`
		}
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, err
		}
		if strings.TrimSpace(request.RoomID) == "" {
			return nil, corewebsearch.ErrInvalid
		}
		if err := c.service.ResetGroupScope(ctx, webSearchScope(ownerID, accountGeneration, request.RoomID), request.IdempotencyKey); err != nil {
			return nil, err
		}
		value, err := c.service.Get(ctx, webSearchScope(ownerID, accountGeneration, request.RoomID))
		return marshalResult(value, err)
	default:
		return nil, fmt.Errorf("unknown web search operation %q", operationID)
	}
}

// webSearchScope maps an optional room_id onto the credential scope. The owner
// configures both scopes; a group scope is never selected by a model or by a
// group member.
func webSearchScope(ownerID string, accountGeneration int64, roomID string) corewebsearch.Scope {
	if strings.TrimSpace(roomID) == "" {
		return corewebsearch.PersonalScope(ownerID, accountGeneration)
	}
	return corewebsearch.GroupScope(ownerID, accountGeneration, strings.TrimSpace(roomID))
}

// webSearchScopeFromRequest accepts either an empty object (personal scope) or
// one with an optional room_id (that group's scope).
func webSearchScopeFromRequest(ownerID string, accountGeneration int64, raw []byte) (corewebsearch.Scope, error) {
	var request struct {
		RoomID string `json:"room_id,omitempty"`
	}
	if err := decodeStrictObject(raw, &request); err != nil {
		return corewebsearch.Scope{}, err
	}
	return webSearchScope(ownerID, accountGeneration, request.RoomID), nil
}
