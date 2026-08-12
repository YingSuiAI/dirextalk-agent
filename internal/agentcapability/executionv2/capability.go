// Package executionv2 adapts the Agent-owned execution-plan/v2 service to the
// neutral Capability API.  Message Server maps its frozen action names to the
// operation IDs below; no business-server database or HTTP endpoint is used.
package executionv2

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

type Capability struct{ service *coreexecutionv2.Service }

func NewCapability(service *coreexecutionv2.Service) (*Capability, error) {
	if service == nil {
		return nil, coreexecutionv2.ErrInvalid
	}
	return &Capability{service: service}, nil
}

// Service exposes the domain for composition tests and typed Core adapters.
func (c *Capability) Service() *coreexecutionv2.Service {
	if c == nil {
		return nil
	}
	return c.service
}

var operationActions = []struct{ action, operation string }{
	{"agent.execution.v2.projects.analyze", "projects_analyze"}, {"agent.execution.v2.analyses.get", "analyses_get"},
	{"agent.execution.v2.targets.list", "targets_list"}, {"agent.execution.v2.targets.get", "targets_get"}, {"agent.execution.v2.targets.import", "targets_import"}, {"agent.execution.v2.targets.reserve", "targets_reserve"}, {"agent.execution.v2.targets.observe", "targets_observe"},
	{"agent.execution.v2.plans.create", "plans_create"}, {"agent.execution.v2.plans.revise", "plans_revise"}, {"agent.execution.v2.plans.get", "plans_get"}, {"agent.execution.v2.plans.list", "plans_list"},
	{"agent.execution.v2.deployments.list", "deployments_list"}, {"agent.execution.v2.deployments.get", "deployments_get"}, {"agent.execution.v2.deployments.events", "deployments_events"},
	{"agent.execution.v2.runs.create", "runs_create"}, {"agent.execution.v2.runs.get", "runs_get"}, {"agent.execution.v2.runs.list", "runs_list"}, {"agent.execution.v2.runs.cancel", "runs_cancel"}, {"agent.execution.v2.runs.retry", "runs_retry"}, {"agent.execution.v2.runs.events", "runs_events"},
	{"agent.execution.v2.artifacts.get", "artifacts_get"}, {"agent.execution.v2.artifacts.download", "artifacts_download"}, {"agent.execution.v2.service_bindings.list", "service_bindings_list"}, {"agent.execution.v2.service_bindings.get", "service_bindings_get"}, {"agent.execution.v2.service_bindings.invoke", "service_bindings_invoke"},
	{"agent.execution.v2.secrets.create", "secrets_create"}, {"agent.execution.v2.secrets.get", "secrets_get"}, {"agent.execution.v2.secrets.list", "secrets_list"}, {"agent.execution.v2.secrets.revoke", "secrets_revoke"},
}

func (c *Capability) Descriptor() *capv1.CapabilityDescriptor {
	ready := c != nil && c.service != nil && c.service.ReadyForPublication()
	reason := ""
	if c != nil && c.service != nil {
		reason = c.service.ReadinessReason()
		if ready {
			reason = "configured; exact AWS readiness probe is deferred until the first explicit provider action"
		}
	}
	descriptor := &capv1.CapabilityDescriptor{CapabilityId: coreexecutionv2.CapabilityID, SemanticVersion: coreexecutionv2.SemanticVersion, ProtocolVersion: 1, DisplayName: "Execution Plan v2", Description: "Agent-owned immutable analysis, planning, deployment and AWS execution control", Readiness: ready, ReadinessReason: reason}
	for _, item := range operationActions {
		// The neutral catalog may be composed as Cloud-only, Generic-only, or
		// both. Advertise only operations whose exact route is ready; a known
		// but unconfigured mutation must never appear callable in the catalog.
		if !ready || !c.service.ActionReady(item.action) {
			continue
		}
		inputSchema := inputSchema(item.action)
		inputDigest := sha256.Sum256([]byte(inputSchema))
		resultSchema := resultSchema(item.action)
		resultDigest := sha256.Sum256([]byte(resultSchema))
		typ := capv1.OperationType_OPERATION_TYPE_MUTATION
		risk := capv1.RiskLevel_RISK_LEVEL_HIGH
		if isRead(item.action) {
			typ, risk = capv1.OperationType_OPERATION_TYPE_READ, capv1.RiskLevel_RISK_LEVEL_SAFE
		}
		descriptor.Operations = append(descriptor.Operations, &capv1.OperationDescriptor{OperationId: item.operation, DisplayName: item.operation, Description: item.action, OperationType: typ, Audience: []capv1.Audience{capv1.Audience_AUDIENCE_OWNER_CLIENT, capv1.Audience_AUDIENCE_NATIVE_AGENT}, RiskLevel: risk, RequiredScopes: []string{"agent.execution.v2"}, InputSchemaJson: inputSchema, InputSchemaDigest: inputDigest[:], ResultSchemaJson: resultSchema, ResultSchemaDigest: resultDigest[:], MaxRequestSizeBytes: 1 << 20, TimeoutClass: "long"})
	}
	return descriptor
}

func inputSchema(action string) string {
	fields := map[string][]string{
		"agent.execution.v2.projects.analyze": {"project_id", "source", "idempotency_key"},
		"agent.execution.v2.analyses.get":     {"analysis_id"},
		"agent.execution.v2.targets.list":     {"page_size", "page_token"},
		"agent.execution.v2.targets.get":      {"target_id", "revision"},
		"agent.execution.v2.targets.import":   {"credential_id", "credential_revision", "instance_id", "idempotency_key"},
		"agent.execution.v2.targets.reserve":  {"credential_id", "credential_revision", "instance_type", "volume_gib", "idempotency_key"},
		"agent.execution.v2.targets.observe":  {"target_id", "target_revision", "idempotency_key"},
		"agent.execution.v2.plans.create":     {"project_id", "analysis_id", "intent", "recipe_id", "target_id", "target_revision", "purpose", "ai_configuration", "idempotency_key"},
		"agent.execution.v2.plans.revise":     {"plan_id", "intent", "recipe_id", "target_id", "target_revision", "purpose", "ai_configuration", "idempotency_key", "expected_revision"},
		"agent.execution.v2.plans.get":        {"record_kind", "plan_id", "revision"}, "agent.execution.v2.plans.list": {"record_kind", "page_size", "page_token"},
		"agent.execution.v2.deployments.list": {"project_id", "page_size", "page_token"}, "agent.execution.v2.deployments.get": {"deployment_id"}, "agent.execution.v2.deployments.events": {"deployment_id", "after_sequence", "limit"},
		"agent.execution.v2.runs.create": {"plan_id", "plan_revision", "operation", "trigger_kind", "rollback_of_run_id", "idempotency_key"}, "agent.execution.v2.runs.get": {"record_kind", "run_id"}, "agent.execution.v2.runs.list": {"record_kind", "project_id", "deployment_id", "page_size", "page_token"}, "agent.execution.v2.runs.cancel": {"record_kind", "run_id", "idempotency_key", "expected_revision"}, "agent.execution.v2.runs.retry": {"run_id", "idempotency_key", "expected_revision"}, "agent.execution.v2.runs.events": {"record_kind", "run_id", "after_sequence", "limit"},
		"agent.execution.v2.artifacts.get": {"record_kind", "artifact_id"}, "agent.execution.v2.artifacts.download": {"record_kind", "artifact_id", "offset_bytes", "max_chunk_bytes"}, "agent.execution.v2.service_bindings.list": {"project_id", "page_size", "page_token"}, "agent.execution.v2.service_bindings.get": {"binding_id"}, "agent.execution.v2.service_bindings.invoke": {"binding_id", "operation", "idempotency_key", "expected_revision", "input"},
		"agent.execution.v2.secrets.create": {"provider", "purpose", "value", "idempotency_key"}, "agent.execution.v2.secrets.get": {"secret_ref", "revision"}, "agent.execution.v2.secrets.list": {"page_size", "page_token"}, "agent.execution.v2.secrets.revoke": {"secret_ref", "expected_revision", "idempotency_key"},
	}
	properties := map[string]any{}
	for _, field := range fields[action] {
		properties[field] = map[string]string{"type": "string"}
	}
	if _, ok := properties["record_kind"]; ok {
		properties["record_kind"] = map[string]any{"enum": []string{coreexecutionv2.RecordKindCloudWorker}, "type": "string"}
	}
	// Numeric and object fields are represented explicitly so generic clients
	// can construct requests without relying on the implementation decoder.
	for _, field := range []string{"page_size", "revision", "credential_revision", "volume_gib", "target_revision", "expected_revision", "plan_revision", "after_sequence", "limit", "offset_bytes", "max_chunk_bytes"} {
		if _, ok := properties[field]; ok {
			properties[field] = map[string]string{"type": "integer"}
		}
	}
	if _, ok := properties["offset_bytes"]; ok {
		properties["offset_bytes"] = map[string]any{"type": "integer", "minimum": 0, "maximum": coreexecutionv2.MaxCloudWorkerArtifactDownloadOffsetBytes}
	}
	if _, ok := properties["max_chunk_bytes"]; ok {
		properties["max_chunk_bytes"] = map[string]any{"type": "integer", "minimum": 1, "maximum": coreexecutionv2.MaxCloudWorkerArtifactDownloadChunkBytes}
	}
	for _, field := range []string{"source", "ai_configuration", "input"} {
		if _, ok := properties[field]; ok {
			properties[field] = map[string]string{"type": "object"}
		}
	}
	if _, ok := properties["states"]; ok {
		properties["states"] = map[string]string{"type": "array"}
	}
	required := map[string][]string{
		"agent.execution.v2.projects.analyze": {"project_id", "source", "idempotency_key"}, "agent.execution.v2.analyses.get": {"analysis_id"}, "agent.execution.v2.targets.get": {"target_id"}, "agent.execution.v2.targets.import": {"credential_id", "credential_revision", "instance_id", "idempotency_key"}, "agent.execution.v2.targets.reserve": {"credential_id", "credential_revision", "instance_type", "volume_gib", "idempotency_key"}, "agent.execution.v2.targets.observe": {"target_id", "target_revision", "idempotency_key"},
		"agent.execution.v2.plans.create": {"project_id", "analysis_id", "intent", "recipe_id", "target_id", "target_revision", "purpose", "idempotency_key"}, "agent.execution.v2.plans.revise": {"plan_id", "intent", "recipe_id", "target_id", "target_revision", "purpose", "idempotency_key", "expected_revision"}, "agent.execution.v2.plans.get": {"plan_id"}, "agent.execution.v2.deployments.get": {"deployment_id"}, "agent.execution.v2.deployments.events": {"deployment_id"}, "agent.execution.v2.runs.create": {"plan_id", "plan_revision", "operation", "idempotency_key"}, "agent.execution.v2.runs.get": {"run_id"}, "agent.execution.v2.runs.cancel": {"run_id", "idempotency_key", "expected_revision"}, "agent.execution.v2.runs.retry": {"run_id", "idempotency_key", "expected_revision"}, "agent.execution.v2.runs.events": {"run_id"}, "agent.execution.v2.artifacts.get": {"artifact_id"}, "agent.execution.v2.artifacts.download": {"record_kind", "artifact_id", "offset_bytes", "max_chunk_bytes"}, "agent.execution.v2.service_bindings.get": {"binding_id"}, "agent.execution.v2.service_bindings.invoke": {"binding_id", "operation", "idempotency_key", "expected_revision", "input"}, "agent.execution.v2.secrets.create": {"provider", "purpose", "value", "idempotency_key"}, "agent.execution.v2.secrets.get": {"secret_ref"}, "agent.execution.v2.secrets.revoke": {"secret_ref", "expected_revision", "idempotency_key"},
	}
	schema := map[string]any{"additionalProperties": false, "properties": properties, "type": "object"}
	if values := required[action]; len(values) > 0 {
		schema["required"] = values
	}
	raw, _ := json.Marshal(schema)
	return string(raw)
}

func resultSchema(action string) string {
	if action != "agent.execution.v2.artifacts.download" {
		return `{"type":"object","additionalProperties":true}`
	}
	properties := map[string]any{
		"owner_id":           map[string]any{"type": "string"},
		"account_generation": map[string]any{"type": "integer", "minimum": 1},
		"artifact_id":        map[string]any{"type": "string"},
		"execution_id":       map[string]any{"type": "string"},
		"offset_bytes":       map[string]any{"type": "integer", "minimum": 0},
		"data_base64":        map[string]any{"type": "string"},
		"chunk_sha256":       map[string]any{"type": "string"},
		"artifact_sha256":    map[string]any{"type": "string"},
		"size_bytes":         map[string]any{"type": "integer", "minimum": 1},
		"next_offset_bytes":  map[string]any{"type": "integer", "minimum": 1},
		"eof":                map[string]any{"type": "boolean"},
	}
	required := []string{"owner_id", "account_generation", "artifact_id", "execution_id", "offset_bytes", "data_base64", "chunk_sha256", "artifact_sha256", "size_bytes", "next_offset_bytes", "eof"}
	raw, _ := json.Marshal(map[string]any{"additionalProperties": false, "properties": properties, "required": required, "type": "object"})
	return string(raw)
}

func isRead(action string) bool {
	switch action {
	case "agent.execution.v2.analyses.get", "agent.execution.v2.targets.list", "agent.execution.v2.targets.get", "agent.execution.v2.plans.get", "agent.execution.v2.plans.list", "agent.execution.v2.deployments.list", "agent.execution.v2.deployments.get", "agent.execution.v2.deployments.events", "agent.execution.v2.runs.get", "agent.execution.v2.runs.list", "agent.execution.v2.runs.events", "agent.execution.v2.artifacts.get", "agent.execution.v2.artifacts.download", "agent.execution.v2.service_bindings.list", "agent.execution.v2.service_bindings.get", "agent.execution.v2.secrets.get", "agent.execution.v2.secrets.list":
		return true
	default:
		return false
	}
}

func actionForOperation(operation string) (string, bool) {
	for _, item := range operationActions {
		if item.operation == operation {
			return item.action, true
		}
	}
	return "", false
}

func authorityFromContext(ctx context.Context) (coreexecutionv2.Authority, error) {
	permission, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || permission == nil || strings.TrimSpace(permission.GetAuthenticatedOwnerId()) == "" || permission.GetAccountGeneration() <= 0 {
		return coreexecutionv2.Authority{}, fmt.Errorf("%w: authenticated owner and account generation are required", coreexecutionv2.ErrInvalid)
	}
	return coreexecutionv2.Authority{OwnerID: strings.TrimSpace(permission.GetAuthenticatedOwnerId()), AccountGeneration: uint64(permission.GetAccountGeneration())}, nil
}

func (c *Capability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	if c == nil || c.service == nil {
		return nil, coreexecutionv2.ErrNotReady
	}
	action, ok := actionForOperation(operationID)
	if !ok {
		return nil, coreexecutionv2.ErrUnsupported
	}
	var input map[string]any
	if len(raw) != 0 {
		if err := json.Unmarshal(raw, &input); err != nil {
			return nil, coreexecutionv2.ErrInvalid
		}
	}
	authority, err := authorityFromContext(ctx)
	if err != nil {
		return nil, err
	}
	result, err := c.service.HandleWithAuthority(ctx, authority, action, input)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}

// HandleAsOwner is a narrow non-transport hook for unit tests and the typed
// Core adapter. Production capability RPCs should use HandleOperation so the
// owner always comes from the authenticated PermissionContext.
func (c *Capability) HandleAsOwner(ctx context.Context, owner, action string, input map[string]any) (map[string]any, error) {
	if c == nil || c.service == nil {
		return nil, coreexecutionv2.ErrNotReady
	}
	return c.service.Handle(ctx, owner, action, input)
}

// HandleAsAuthority is the non-transport hook for composition and focused
// tests that need to exercise the account-generation-fenced Cloud Worker
// route. Production capability RPCs derive this authority from the signed
// PermissionContext in HandleOperation.
func (c *Capability) HandleAsAuthority(ctx context.Context, authority coreexecutionv2.Authority, action string, input map[string]any) (map[string]any, error) {
	if c == nil || c.service == nil {
		return nil, coreexecutionv2.ErrNotReady
	}
	return c.service.HandleWithAuthority(ctx, authority, action, input)
}
