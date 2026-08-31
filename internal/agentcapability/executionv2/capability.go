// Package executionv2 adapts the Agent-owned execution-plan/v2 service to the
// neutral Capability API. The scoped Agent HTTP catalog exposes the
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
	{"agent.execution.v2.plans.get", "plans_get"},
	{"agent.execution.v2.plans.list", "plans_list"},
	{"agent.execution.v2.runs.get", "runs_get"},
	{"agent.execution.v2.runs.list", "runs_list"},
	{"agent.execution.v2.runs.cancel", "runs_cancel"},
	{"agent.execution.v2.runs.events", "runs_events"},
	{"agent.execution.v2.artifacts.get", "artifacts_get"},
	{"agent.execution.v2.artifacts.download", "artifacts_download"},
	{"agent.execution.v2.artifacts.delete", "artifacts_delete"},
}

func (c *Capability) Descriptor() *capv1.CapabilityDescriptor {
	ready := c != nil && c.service != nil && c.service.ReadyForPublication()
	reason := ""
	if c != nil && c.service != nil {
		reason = c.service.ReadinessReason()
	}
	descriptor := &capv1.CapabilityDescriptor{CapabilityId: coreexecutionv2.CapabilityID, SemanticVersion: coreexecutionv2.SemanticVersion, ProtocolVersion: 1, DisplayName: "Cloud Worker Execution", Description: "Agent-owned Cloud Worker plans, runs, events and artifacts", Readiness: ready, ReadinessReason: reason}
	for _, item := range operationActions {
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
		"agent.execution.v2.plans.get": {"record_kind", "plan_id", "revision"}, "agent.execution.v2.plans.list": {"record_kind", "page_size", "page_token"},
		"agent.execution.v2.runs.get": {"record_kind", "run_id"}, "agent.execution.v2.runs.list": {"record_kind", "page_size", "page_token"}, "agent.execution.v2.runs.cancel": {"record_kind", "run_id", "idempotency_key", "expected_revision"}, "agent.execution.v2.runs.events": {"record_kind", "run_id", "after_sequence", "limit"},
		"agent.execution.v2.artifacts.get": {"record_kind", "artifact_id"}, "agent.execution.v2.artifacts.download": {"record_kind", "artifact_id", "offset_bytes", "max_chunk_bytes"}, "agent.execution.v2.artifacts.delete": {"record_kind", "artifact_id", "idempotency_key"},
	}
	properties := map[string]any{}
	for _, field := range fields[action] {
		properties[field] = map[string]string{"type": "string"}
	}
	if _, ok := properties["record_kind"]; ok {
		recordKinds := []string{coreexecutionv2.RecordKindCloudWorker}
		if isArtifactAction(action) {
			recordKinds = append(recordKinds, coreexecutionv2.RecordKindLocalSandbox)
		}
		properties["record_kind"] = map[string]any{"enum": recordKinds, "type": "string"}
	}
	for _, field := range []string{"page_size", "revision", "expected_revision", "after_sequence", "limit", "offset_bytes", "max_chunk_bytes"} {
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
	required := map[string][]string{
		"agent.execution.v2.plans.get": {"record_kind", "plan_id"}, "agent.execution.v2.plans.list": {"record_kind"},
		"agent.execution.v2.runs.get": {"record_kind", "run_id"}, "agent.execution.v2.runs.list": {"record_kind"}, "agent.execution.v2.runs.cancel": {"record_kind", "run_id", "idempotency_key", "expected_revision"}, "agent.execution.v2.runs.events": {"record_kind", "run_id"},
		"agent.execution.v2.artifacts.get": {"record_kind", "artifact_id"}, "agent.execution.v2.artifacts.download": {"record_kind", "artifact_id", "offset_bytes", "max_chunk_bytes"}, "agent.execution.v2.artifacts.delete": {"record_kind", "artifact_id", "idempotency_key"},
	}
	schema := map[string]any{"additionalProperties": false, "properties": properties, "type": "object"}
	if values := required[action]; len(values) > 0 {
		schema["required"] = values
	}
	raw, _ := json.Marshal(schema)
	return string(raw)
}

func resultSchema(action string) string {
	var properties map[string]any
	switch action {
	case "agent.execution.v2.plans.get":
		properties = map[string]any{"plan": cloudWorkerResultObject(cloudWorkerPlanResultProperties())}
	case "agent.execution.v2.plans.list":
		properties = map[string]any{
			"plans":           map[string]any{"items": cloudWorkerResultObject(cloudWorkerPlanResultProperties()), "type": "array"},
			"next_page_token": map[string]any{"type": "string"},
		}
	case "agent.execution.v2.runs.get", "agent.execution.v2.runs.cancel":
		properties = map[string]any{"run": cloudWorkerResultObject(cloudWorkerRunResultProperties())}
	case "agent.execution.v2.runs.list":
		properties = map[string]any{
			"runs":            map[string]any{"items": cloudWorkerResultObject(cloudWorkerRunResultProperties()), "type": "array"},
			"next_page_token": map[string]any{"type": "string"},
		}
	case "agent.execution.v2.runs.events":
		properties = map[string]any{
			"events":        map[string]any{"items": map[string]any{"type": "object", "additionalProperties": true}, "type": "array"},
			"next_sequence": map[string]any{"type": "integer"}, "history_truncated": map[string]any{"type": "boolean"},
		}
	case "agent.execution.v2.artifacts.get":
		properties = map[string]any{"artifact": map[string]any{"type": "object", "additionalProperties": true}}
	case "agent.execution.v2.artifacts.delete":
		return artifactDeleteResultSchema()
	case "agent.execution.v2.artifacts.download":
		return artifactDownloadResultSchema()
	default:
		return `{"type":"object","additionalProperties":true}`
	}
	raw, _ := json.Marshal(map[string]any{"additionalProperties": true, "properties": properties, "type": "object"})
	return string(raw)
}

func artifactDeleteResultSchema() string {
	properties := map[string]any{
		"artifact": map[string]any{"type": "object", "additionalProperties": true},
		"deleted":  map[string]any{"const": true, "type": "boolean"},
	}
	raw, _ := json.Marshal(map[string]any{
		"additionalProperties": false,
		"properties":           properties,
		"required":             []string{"artifact", "deleted"},
		"type":                 "object",
	})
	return string(raw)
}

func cloudWorkerResultObject(properties map[string]any) map[string]any {
	return map[string]any{"additionalProperties": true, "properties": properties, "type": "object"}
}

func cloudWorkerPlanResultProperties() map[string]any {
	stringField := func() map[string]any { return map[string]any{"type": "string"} }
	integerField := func() map[string]any { return map[string]any{"type": "integer"} }
	return map[string]any{
		"owner_id": stringField(), "account_generation": integerField(), "plan_id": stringField(), "revision": integerField(),
		"status": stringField(), "execution_id": stringField(), "task_id": stringField(), "confirmation_id": stringField(),
		"conversation_id": stringField(), "turn_id": stringField(), "objective_summary": stringField(), "proposal_reason": stringField(),
		"persistent_worker_reuse": map[string]any{"type": "boolean"}, "workspace_mode": stringField(),
		"aws": cloudWorkerResultObject(map[string]any{"account_id": stringField(), "region": stringField()}),
		"compute": cloudWorkerResultObject(map[string]any{
			"instance_type": stringField(), "accelerator_type": stringField(), "vcpu": integerField(), "memory_gib": integerField(),
			"volume_gib": integerField(), "volume_type": stringField(),
			"volume_iops": integerField(), "volume_throughput_mib": integerField(),
		}),
		"limits": cloudWorkerResultObject(map[string]any{"max_runtime_seconds": integerField()}),
		"quote": cloudWorkerResultObject(map[string]any{
			"amount_micros": integerField(), "compute_micros_per_hour": integerField(),
			"currency": stringField(), "source_time": stringField(), "expires_at": stringField(),
			"maximum_authorized_cost_micros": integerField(),
		}),
		"created_at": stringField(), "updated_at": stringField(),
	}
}

func cloudWorkerRunResultProperties() map[string]any {
	stringField := func() map[string]any { return map[string]any{"type": "string"} }
	integerField := func() map[string]any { return map[string]any{"type": "integer"} }
	return map[string]any{
		"owner_id": stringField(), "account_generation": integerField(), "run_id": stringField(), "execution_id": stringField(),
		"plan_id": stringField(), "plan_revision": integerField(), "task_id": stringField(), "confirmation_id": stringField(),
		"conversation_id": stringField(), "turn_id": stringField(), "status": stringField(), "revision": integerField(),
		"worker_id": stringField(), "persistent_worker": map[string]any{"type": "boolean"},
		"artifact_ids": map[string]any{"items": stringField(), "type": "array"},
		"failure_code": stringField(), "failure_summary": stringField(), "created_at": stringField(), "updated_at": stringField(),
	}
}

func artifactDownloadResultSchema() string {
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
	case "agent.execution.v2.plans.get", "agent.execution.v2.plans.list", "agent.execution.v2.runs.get", "agent.execution.v2.runs.list", "agent.execution.v2.runs.events", "agent.execution.v2.artifacts.get", "agent.execution.v2.artifacts.download":
		return true
	default:
		return false
	}
}

func isArtifactAction(action string) bool {
	return action == "agent.execution.v2.artifacts.get" || action == "agent.execution.v2.artifacts.download" || action == "agent.execution.v2.artifacts.delete"
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
