package agentcapability

import (
	"context"
	"fmt"
	"strings"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/corestaticsite"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

const (
	staticSiteListInputSchema    = `{"additionalProperties":false,"properties":{"page_size":{"maximum":100,"minimum":1,"type":"integer"},"page_token":{"maxLength":4096,"type":"string"}},"type":"object"}`
	staticSiteReleaseSchema      = `{"additionalProperties":false,"properties":{"conversation_id":{"format":"uuid","type":"string"},"created_at":{"format":"date-time","type":"string"},"public_path":{"type":"string"},"public_url":{"format":"uri","type":"string"},"release_id":{"format":"uuid","type":"string"},"site_id":{"format":"uuid","type":"string"},"size_bytes":{"maximum":196608,"minimum":1,"type":"integer"}},"required":["site_id","release_id","conversation_id","public_url","public_path","size_bytes","created_at"],"type":"object"}`
	staticSiteListResultSchema   = `{"additionalProperties":false,"properties":{"next_page_token":{"type":"string"},"releases":{"items":` + staticSiteReleaseSchema + `,"type":"array"}},"required":["releases","next_page_token"],"type":"object"}`
	staticSiteDeleteInputSchema  = `{"additionalProperties":false,"properties":{"idempotency_key":{"format":"uuid","type":"string"},"release_id":{"format":"uuid","type":"string"}},"required":["release_id","idempotency_key"],"type":"object"}`
	staticSiteDeleteResultSchema = `{"additionalProperties":false,"properties":{"deleted":{"const":true,"type":"boolean"},"release_id":{"format":"uuid","type":"string"},"replayed":{"type":"boolean"}},"required":["release_id","deleted","replayed"],"type":"object"}`
)

type coreStaticSiteCapability struct{ service *corestaticsite.Service }

func NewCoreStaticSiteCapability(service *corestaticsite.Service) Capability {
	return &coreStaticSiteCapability{service: service}
}

func (c *coreStaticSiteCapability) Descriptor() *capv1.CapabilityDescriptor {
	descriptor := capabilityDescriptor("agent.static_sites.v1", "Static Sites", "Agent-owned single-page static-site releases", []capabilityOperation{
		{ID: "list_releases", DisplayName: "List static sites", Description: "List the owner's published static-site releases.", Type: capv1.OperationType_OPERATION_TYPE_READ, Scope: "agent:static_sites:read", InputSchema: staticSiteListInputSchema, ResultSchema: staticSiteListResultSchema},
		{ID: "delete_release", DisplayName: "Delete static site", Description: "Delete one exact static-site release.", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:static_sites:write", InputSchema: staticSiteDeleteInputSchema, ResultSchema: staticSiteDeleteResultSchema},
	})
	for _, operation := range descriptor.Operations {
		operation.Audience = []capv1.Audience{capv1.Audience_AUDIENCE_OWNER_CLIENT}
	}
	return descriptor
}

func (c *coreStaticSiteCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	if c == nil || c.service == nil {
		return nil, corestaticsite.ErrRepository
	}
	permission, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || permission == nil {
		return nil, corestaticsite.ErrInvalid
	}
	authority := corestaticsite.Authority{OwnerID: strings.TrimSpace(permission.GetAuthenticatedOwnerId()), AccountGeneration: permission.GetAccountGeneration()}
	if authority.Validate() != nil {
		return nil, corestaticsite.ErrInvalid
	}
	switch operationID {
	case "list_releases":
		var request struct {
			PageSize  int    `json:"page_size"`
			PageToken string `json:"page_token"`
		}
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, err
		}
		page, err := c.service.List(ctx, authority, corestaticsite.ListQuery{PageSize: request.PageSize, PageToken: request.PageToken})
		return marshalResult(map[string]any{"releases": page.Releases, "next_page_token": page.NextPageToken}, err)
	case "delete_release":
		var request struct {
			ReleaseID      string `json:"release_id"`
			IdempotencyKey string `json:"idempotency_key"`
		}
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, err
		}
		return marshalResult(c.service.Delete(ctx, authority, request.ReleaseID, request.IdempotencyKey))
	default:
		return nil, fmt.Errorf("unknown static-site operation %q", operationID)
	}
}
