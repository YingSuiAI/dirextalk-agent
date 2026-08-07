package executionv2

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

func fullyReadyTypedPorts() coreexecutionv2.TypedPorts {
	return coreexecutionv2.TypedPorts{
		Analyze: func(context.Context, string, coreexecutionv2.AnalyzeRequest) (map[string]any, error) {
			return map[string]any{}, nil
		},
		ImportTarget: func(context.Context, string, coreexecutionv2.TargetImportRequest) (map[string]any, error) {
			return map[string]any{}, nil
		},
		ReserveTarget: func(context.Context, string, coreexecutionv2.TargetReserveRequest) (map[string]any, error) {
			return map[string]any{}, nil
		},
		Observe: func(context.Context, string, coreexecutionv2.TargetObserveRequest) (map[string]any, error) {
			return map[string]any{}, nil
		},
		Invoke: func(context.Context, string, coreexecutionv2.InvokeRequest) (map[string]any, error) {
			return map[string]any{}, nil
		},
		Reconcile: func(context.Context, string, coreexecutionv2.ReconcileRequest) (map[string]any, error) {
			return map[string]any{}, nil
		},
		Ready: func() bool { return true },
	}
}

type capabilityCloudWorkerPort struct{}

func (capabilityCloudWorkerPort) GetPlan(context.Context, coreexecutionv2.CloudWorkerPlanGetRequest) (coreexecutionv2.CloudWorkerObject, error) {
	return coreexecutionv2.CloudWorkerObject{}, nil
}
func (capabilityCloudWorkerPort) ListPlans(context.Context, coreexecutionv2.CloudWorkerListRequest) (coreexecutionv2.CloudWorkerPage, error) {
	return coreexecutionv2.CloudWorkerPage{}, nil
}
func (capabilityCloudWorkerPort) GetRun(context.Context, coreexecutionv2.CloudWorkerRunGetRequest) (coreexecutionv2.CloudWorkerObject, error) {
	return coreexecutionv2.CloudWorkerObject{}, nil
}
func (capabilityCloudWorkerPort) ListRuns(context.Context, coreexecutionv2.CloudWorkerListRequest) (coreexecutionv2.CloudWorkerPage, error) {
	return coreexecutionv2.CloudWorkerPage{}, nil
}
func (capabilityCloudWorkerPort) CancelRun(context.Context, coreexecutionv2.CloudWorkerRunCancelRequest) (coreexecutionv2.CloudWorkerObject, error) {
	return coreexecutionv2.CloudWorkerObject{}, nil
}
func (capabilityCloudWorkerPort) RunEvents(context.Context, coreexecutionv2.CloudWorkerRunEventsRequest) (coreexecutionv2.CloudWorkerEventPage, error) {
	return coreexecutionv2.CloudWorkerEventPage{}, nil
}
func (capabilityCloudWorkerPort) GetArtifact(context.Context, coreexecutionv2.CloudWorkerArtifactGetRequest) (coreexecutionv2.CloudWorkerObject, error) {
	return coreexecutionv2.CloudWorkerObject{}, nil
}
func (capabilityCloudWorkerPort) DownloadArtifact(context.Context, coreexecutionv2.CloudWorkerArtifactDownloadRequest) (coreexecutionv2.CloudWorkerArtifactChunk, error) {
	return coreexecutionv2.CloudWorkerArtifactChunk{}, nil
}

func TestDescriptorMatchesMessageServerBindingOperations(t *testing.T) {
	store := coreexecutionv2.NewMemoryStore()
	domain, err := coreexecutionv2.NewService(coreexecutionv2.Config{Store: store, Typed: fullyReadyTypedPorts()})
	if err != nil {
		t.Fatal(err)
	}
	capability, err := NewCapability(domain)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := capability.Descriptor()
	if descriptor.GetCapabilityId() != "agent.execution.v2" || len(descriptor.GetOperations()) != 28 {
		t.Fatalf("descriptor=%s operations=%d", descriptor.GetCapabilityId(), len(descriptor.GetOperations()))
	}
	wantRecordKind := map[string]bool{"plans_get": true, "plans_list": true, "runs_get": true, "runs_list": true, "runs_cancel": true, "runs_events": true, "artifacts_get": true}
	for _, operation := range descriptor.GetOperations() {
		if operation.GetInputSchemaDigest() == nil || operation.GetResultSchemaDigest() == nil {
			t.Fatalf("operation %s missing schema digest", operation.GetOperationId())
		}
		if wantRecordKind[operation.GetOperationId()] {
			var schema map[string]any
			if err := json.Unmarshal([]byte(operation.GetInputSchemaJson()), &schema); err != nil {
				t.Fatal(err)
			}
			properties, _ := schema["properties"].(map[string]any)
			recordKind, _ := properties["record_kind"].(map[string]any)
			enum, _ := recordKind["enum"].([]any)
			if recordKind["type"] != "string" || len(enum) != 1 || enum[0] != coreexecutionv2.RecordKindCloudWorker {
				t.Fatalf("operation %s record_kind schema=%v", operation.GetOperationId(), recordKind)
			}
			delete(wantRecordKind, operation.GetOperationId())
		}
	}
	if len(wantRecordKind) != 0 {
		t.Fatalf("record_kind operations missing: %v", wantRecordKind)
	}
}

func TestExecutionV2RunCreateRetryPublishedWithoutRemovedAliases(t *testing.T) {
	store := coreexecutionv2.NewMemoryStore()
	domain, err := coreexecutionv2.NewService(coreexecutionv2.Config{Store: store, Typed: fullyReadyTypedPorts()})
	if err != nil {
		t.Fatal(err)
	}
	capability, err := NewCapability(domain)
	if err != nil {
		t.Fatal(err)
	}
	published := map[string]bool{}
	for _, operation := range capability.Descriptor().GetOperations() {
		published[operation.GetOperationId()] = true
	}
	for _, operation := range []string{"runs_create", "runs_retry"} {
		if !published[operation] {
			t.Fatalf("required durable operation %s is not published", operation)
		}
	}
	for _, operation := range []string{"runs_reconcile", "confirmations_get", "confirmations_list", "confirmations_confirm", "confirmations_reject"} {
		if published[operation] {
			t.Fatalf("removed operation %s is still published", operation)
		}
		if _, err := capability.HandleOperation(context.Background(), operation, []byte(`{}`)); !errors.Is(err, coreexecutionv2.ErrUnsupported) {
			t.Fatalf("removed operation %s err=%v", operation, err)
		}
	}
}

func TestDescriptorPublishesOnlyReadyOperationRoutes(t *testing.T) {
	tests := []struct {
		name    string
		config  coreexecutionv2.Config
		present []string
		absent  []string
	}{
		{
			name: "generic analyze only",
			config: coreexecutionv2.Config{Store: coreexecutionv2.NewMemoryStore(), Typed: coreexecutionv2.TypedPorts{
				Analyze: func(context.Context, string, coreexecutionv2.AnalyzeRequest) (map[string]any, error) {
					return map[string]any{}, nil
				},
				Ready: func() bool { return true },
			}},
			present: []string{"projects_analyze", "plans_get", "runs_get"},
			absent:  []string{"targets_import", "targets_reserve", "targets_observe", "service_bindings_invoke", "runs_create", "runs_retry"},
		},
		{
			name:    "cloud only",
			config:  coreexecutionv2.Config{Store: coreexecutionv2.NewMemoryStore(), CloudWorker: capabilityCloudWorkerPort{}},
			present: []string{"plans_get", "plans_list", "runs_get", "runs_list", "runs_cancel", "runs_events", "artifacts_get", "artifacts_download"},
			absent:  []string{"projects_analyze", "targets_import", "targets_reserve", "targets_observe", "service_bindings_invoke", "runs_create", "runs_retry"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			domain, err := coreexecutionv2.NewService(test.config)
			if err != nil {
				t.Fatal(err)
			}
			capability, err := NewCapability(domain)
			if err != nil {
				t.Fatal(err)
			}
			descriptor := capability.Descriptor()
			if !descriptor.GetReadiness() {
				t.Fatalf("descriptor not ready: %s", descriptor.GetReadinessReason())
			}
			published := map[string]bool{}
			for _, operation := range descriptor.GetOperations() {
				published[operation.GetOperationId()] = true
			}
			for _, operation := range test.present {
				if !published[operation] {
					t.Fatalf("ready operation %s was omitted: %v", operation, published)
				}
			}
			for _, operation := range test.absent {
				if published[operation] {
					t.Fatalf("unready operation %s was advertised", operation)
				}
			}
		})
	}
}

func TestArtifactDownloadDescriptorSchemaIsStrictAndPinned(t *testing.T) {
	domain, err := coreexecutionv2.NewService(coreexecutionv2.Config{
		Store: coreexecutionv2.NewMemoryStore(), CloudWorker: capabilityCloudWorkerPort{},
	})
	if err != nil {
		t.Fatal(err)
	}
	capability, err := NewCapability(domain)
	if err != nil {
		t.Fatal(err)
	}
	var operation *capv1.OperationDescriptor
	for _, candidate := range capability.Descriptor().GetOperations() {
		if candidate.GetOperationId() == "artifacts_download" {
			operation = candidate
			break
		}
	}
	if operation == nil {
		t.Fatal("artifacts_download is not published by the ready Cloud Worker route")
	}
	const input = `{"additionalProperties":false,"properties":{"artifact_id":{"type":"string"},"max_chunk_bytes":{"maximum":524288,"minimum":1,"type":"integer"},"offset_bytes":{"maximum":8388607,"minimum":0,"type":"integer"},"record_kind":{"enum":["cloud_worker"],"type":"string"}},"required":["record_kind","artifact_id","offset_bytes","max_chunk_bytes"],"type":"object"}`
	const result = `{"additionalProperties":false,"properties":{"account_generation":{"minimum":1,"type":"integer"},"artifact_id":{"type":"string"},"artifact_sha256":{"type":"string"},"chunk_sha256":{"type":"string"},"data_base64":{"type":"string"},"eof":{"type":"boolean"},"execution_id":{"type":"string"},"next_offset_bytes":{"minimum":1,"type":"integer"},"offset_bytes":{"minimum":0,"type":"integer"},"owner_id":{"type":"string"},"size_bytes":{"minimum":1,"type":"integer"}},"required":["owner_id","account_generation","artifact_id","execution_id","offset_bytes","data_base64","chunk_sha256","artifact_sha256","size_bytes","next_offset_bytes","eof"],"type":"object"}`
	if operation.GetInputSchemaJson() != input || operation.GetResultSchemaJson() != result {
		t.Fatalf("schema drift\ninput=%s\nresult=%s", operation.GetInputSchemaJson(), operation.GetResultSchemaJson())
	}
	if got := hex.EncodeToString(operation.GetInputSchemaDigest()); got != "1f89699ab07b14d135619ee5f6b2ffd0d8d0821fb8f1ba236662814c0586706c" {
		t.Fatalf("input digest=%s", got)
	}
	if got := hex.EncodeToString(operation.GetResultSchemaDigest()); got != "6ea5feead715aa50feeff464e6da618564f9b6e422025c94743faf173478689d" {
		t.Fatalf("result digest=%s", got)
	}
	if operation.GetOperationType() != capv1.OperationType_OPERATION_TYPE_READ || operation.GetRiskLevel() != capv1.RiskLevel_RISK_LEVEL_SAFE {
		t.Fatalf("download classification type=%s risk=%s", operation.GetOperationType(), operation.GetRiskLevel())
	}
}

func TestCapabilityDerivesOwnerFromAuthenticatedPermission(t *testing.T) {
	domain, err := coreexecutionv2.NewService(coreexecutionv2.Config{Store: coreexecutionv2.NewMemoryStore(), Typed: coreexecutionv2.TypedPorts{Analyze: func(context.Context, string, coreexecutionv2.AnalyzeRequest) (map[string]any, error) {
		return map[string]any{"analysis_id": "22222222-2222-4222-8222-222222222222", "status": "ready"}, nil
	}, Ready: func() bool { return true }}})
	if err != nil {
		t.Fatal(err)
	}
	capability, _ := NewCapability(domain)
	input := map[string]any{"project_id": "11111111-1111-4111-8111-111111111111", "source": map[string]any{"kind": "git_https", "location": "https://github.com/example/repo", "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "immutable": true}, "idempotency_key": "22222222-2222-4222-8222-222222222222"}
	raw, _ := json.Marshal(input)
	ctx := capabilityclient.WithCallContext(context.Background(), &capv1.CallContext{}, &capv1.PermissionContext{AuthenticatedOwnerId: "@owner:example.test", AccountGeneration: 1})
	result, err := capability.HandleOperation(ctx, "projects_analyze", raw)
	if err != nil {
		t.Fatal(err)
	}
	var output map[string]any
	if err := json.Unmarshal(result, &output); err != nil {
		t.Fatal(err)
	}
	if output["analysis"].(map[string]any)["owner_id"] != "@owner:example.test" {
		t.Fatalf("owner=%v", output)
	}
	if _, err := capability.HandleOperation(context.Background(), "projects_analyze", raw); err == nil {
		t.Fatal("ownerless capability call succeeded")
	}
}

func TestNoProviderCapabilityIsNotReadyAndNotPublished(t *testing.T) {
	domain, err := coreexecutionv2.NewService(coreexecutionv2.Config{Store: coreexecutionv2.NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	capability, err := NewCapability(domain)
	if err != nil {
		t.Fatal(err)
	}
	if capability.Descriptor().GetReadiness() {
		t.Fatal("execution.v2 is ready without any typed provider route")
	}
	if capability.Descriptor().GetReadinessReason() == "" {
		t.Fatal("missing precise unavailable reason")
	}
	if len(capability.Descriptor().GetOperations()) != 0 {
		t.Fatalf("unready capability advertised %d operations", len(capability.Descriptor().GetOperations()))
	}
	if _, err := capability.HandleAsOwner(context.Background(), "@owner:example.test", "agent.execution.v2.projects.analyze", map[string]any{"project_id": "11111111-1111-4111-8111-111111111111", "source": map[string]any{"kind": "git_https", "location": "https://github.com/example/repo", "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "immutable": true}, "idempotency_key": "22222222-2222-4222-8222-222222222222"}); !errors.Is(err, coreexecutionv2.ErrMissingPort) {
		t.Fatalf("unavailable action err=%v, want ErrMissingPort", err)
	}
}
