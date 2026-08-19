package agentcapability

import (
	"context"
	"fmt"
	"strings"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreserver"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

const (
	serverSchema              = `{"additionalProperties":true,"properties":{"address":{"type":"string"},"artifact_count":{"minimum":0,"type":"integer"},"busy":{"type":"boolean"},"busy_reason":{"type":"string"},"can_destroy":{"type":"boolean"},"created_at":{"format":"date-time","type":"string"},"name":{"type":"string"},"region":{"type":"string"},"server_id":{"format":"uuid","type":"string"},"server_kind":{"enum":["primary","worker"],"type":"string"},"status":{"type":"string"}},"required":["server_id","server_kind","name","status","artifact_count","can_destroy","busy","created_at"],"type":"object"}`
	artifactSchema            = `{"additionalProperties":true,"properties":{"account_generation":{"minimum":1,"type":"integer"},"artifact_id":{"format":"uuid","type":"string"},"artifact_kind":{"enum":["system_service","static_page","execution_file","deployed_service"],"type":"string"},"created_at":{"format":"date-time","type":"string"},"deletion_state":{"type":"string"},"domain":{"type":"string"},"execution_id":{"format":"uuid","type":"string"},"health":{"type":"string"},"media_type":{"type":"string"},"metadata":{"type":"object"},"name":{"type":"string"},"port":{"type":"integer"},"public_ipv4":{"type":"string"},"public_url":{"type":"string"},"record_kind":{"type":"string"},"server_id":{"format":"uuid","type":"string"},"server_kind":{"type":"string"},"size_bytes":{"minimum":0,"type":"integer"},"source_id":{"type":"string"},"source_kind":{"type":"string"},"status":{"type":"string"},"updated_at":{"format":"date-time","type":"string"}},"required":["artifact_id","account_generation","server_id","server_kind","artifact_kind","source_kind","source_id","name","status","metadata","deletion_state","created_at","updated_at"],"type":"object"}`
	serverIDInputSchema       = `{"additionalProperties":false,"properties":{"server_id":{"format":"uuid","type":"string"}},"required":["server_id"],"type":"object"}`
	listArtifactsInputSchema  = `{"additionalProperties":false,"properties":{"page_size":{"maximum":100,"minimum":1,"type":"integer"},"page_token":{"maxLength":4096,"type":"string"},"server_id":{"format":"uuid","type":"string"}},"required":["server_id","page_size"],"type":"object"}`
	deleteArtifactInputSchema = `{"additionalProperties":false,"properties":{"artifact_id":{"format":"uuid","type":"string"},"idempotency_key":{"format":"uuid","type":"string"}},"required":["artifact_id","idempotency_key"],"type":"object"}`
	destroyServerInputSchema  = `{"additionalProperties":false,"properties":{"confirmation":{"const":"destroy_server","type":"string"},"idempotency_key":{"format":"uuid","type":"string"},"server_id":{"format":"uuid","type":"string"}},"required":["server_id","idempotency_key","confirmation"],"type":"object"}`
)

type coreServerCapability struct{ service *coreserver.Service }

func NewCoreServerCapability(service *coreserver.Service) Capability {
	return &coreServerCapability{service: service}
}

func (c *coreServerCapability) Descriptor() *capv1.CapabilityDescriptor {
	d := capabilityDescriptor("agent.servers.v1", "Servers and Artifacts", "Unified owner server and artifact inventory", []capabilityOperation{
		{ID: "list_servers", DisplayName: "List servers", Type: capv1.OperationType_OPERATION_TYPE_READ, Scope: "agent:servers:read", InputSchema: emptyObjectSchema, ResultSchema: `{"additionalProperties":false,"properties":{"servers":{"items":` + serverSchema + `,"type":"array"}},"required":["servers"],"type":"object"}`},
		{ID: "get_server", DisplayName: "Get server", Type: capv1.OperationType_OPERATION_TYPE_READ, Scope: "agent:servers:read", InputSchema: serverIDInputSchema, ResultSchema: `{"additionalProperties":false,"properties":{"server":` + serverSchema + `},"required":["server"],"type":"object"}`},
		{ID: "list_artifacts", DisplayName: "List artifacts", Type: capv1.OperationType_OPERATION_TYPE_READ, Scope: "agent:servers:read", InputSchema: listArtifactsInputSchema, ResultSchema: `{"additionalProperties":false,"properties":{"artifacts":{"items":` + artifactSchema + `,"type":"array"},"next_page_token":{"type":"string"}},"required":["artifacts","next_page_token"],"type":"object"}`},
		{ID: "delete_artifact", DisplayName: "Delete artifact", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:servers:write", Risk: capv1.RiskLevel_RISK_LEVEL_MEDIUM, InputSchema: deleteArtifactInputSchema, ResultSchema: `{"additionalProperties":false,"properties":{"artifact_id":{"format":"uuid","type":"string"},"deleted":{"const":true,"type":"boolean"}},"required":["artifact_id","deleted"],"type":"object"}`},
		{ID: "destroy_server", DisplayName: "Destroy server", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:servers:destroy", Risk: capv1.RiskLevel_RISK_LEVEL_HIGH, InputSchema: destroyServerInputSchema, ResultSchema: `{"additionalProperties":false,"properties":{"destroyed":{"const":true,"type":"boolean"},"server_id":{"format":"uuid","type":"string"}},"required":["server_id","destroyed"],"type":"object"}`},
	})
	for _, operation := range d.Operations {
		operation.Audience = []capv1.Audience{capv1.Audience_AUDIENCE_OWNER_CLIENT}
		if operation.OperationId == "destroy_server" {
			operation.TimeoutClass = "long"
		}
	}
	return d
}

func (c *coreServerCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	if c == nil || c.service == nil {
		return nil, coreserver.ErrInvalid
	}
	permission, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || permission == nil || permission.GetAccountGeneration() <= 0 {
		return nil, coreserver.ErrInvalid
	}
	authority := coreserver.Authority{OwnerID: strings.TrimSpace(permission.GetAuthenticatedOwnerId()), AccountGeneration: uint64(permission.GetAccountGeneration())}
	if !authority.Valid() {
		return nil, coreserver.ErrInvalid
	}
	switch operationID {
	case "list_servers":
		var request struct{}
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, err
		}
		servers, err := c.service.ListServers(ctx, authority)
		return marshalResult(map[string]any{"servers": servers}, err)
	case "get_server":
		var request struct {
			ServerID string `json:"server_id"`
		}
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, err
		}
		server, err := c.service.GetServer(ctx, authority, request.ServerID)
		return marshalResult(map[string]any{"server": server}, err)
	case "list_artifacts":
		var request struct {
			ServerID  string `json:"server_id"`
			PageSize  int    `json:"page_size"`
			PageToken string `json:"page_token"`
		}
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, err
		}
		page, err := c.service.ListArtifacts(ctx, authority, request.ServerID, request.PageSize, request.PageToken)
		return marshalResult(map[string]any{"artifacts": page.Artifacts, "next_page_token": page.NextPageToken}, err)
	case "delete_artifact":
		var request struct {
			ArtifactID     string `json:"artifact_id"`
			IdempotencyKey string `json:"idempotency_key"`
		}
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, err
		}
		err := c.service.DeleteArtifact(ctx, authority, request.ArtifactID, request.IdempotencyKey)
		return marshalResult(map[string]any{"artifact_id": request.ArtifactID, "deleted": true}, err)
	case "destroy_server":
		var request struct {
			ServerID       string `json:"server_id"`
			IdempotencyKey string `json:"idempotency_key"`
			Confirmation   string `json:"confirmation"`
		}
		if err := decodeStrictObject(raw, &request); err != nil || request.Confirmation != "destroy_server" {
			return nil, coreserver.ErrInvalid
		}
		err := c.service.DestroyServer(ctx, authority, request.ServerID, request.IdempotencyKey)
		return marshalResult(map[string]any{"server_id": request.ServerID, "destroyed": true}, err)
	default:
		return nil, fmt.Errorf("unknown server operation %q", operationID)
	}
}
