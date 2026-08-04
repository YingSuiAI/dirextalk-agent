package executionv2

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

func TestDescriptorMatchesMessageServerBindingOperations(t *testing.T) {
	store := coreexecutionv2.NewMemoryStore()
	domain, err := coreexecutionv2.NewService(coreexecutionv2.Config{Store: store, Typed: coreexecutionv2.TypedPorts{Analyze: func(context.Context, string, coreexecutionv2.AnalyzeRequest) (map[string]any, error) {
		return map[string]any{"analysis_id": "22222222-2222-4222-8222-222222222222", "status": "ready"}, nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	capability, err := NewCapability(domain)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := capability.Descriptor()
	if descriptor.GetCapabilityId() != "agent.execution.v2" || len(descriptor.GetOperations()) != 33 {
		t.Fatalf("descriptor=%s operations=%d", descriptor.GetCapabilityId(), len(descriptor.GetOperations()))
	}
	for _, operation := range descriptor.GetOperations() {
		if operation.GetInputSchemaDigest() == nil || operation.GetResultSchemaDigest() == nil {
			t.Fatalf("operation %s missing schema digest", operation.GetOperationId())
		}
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
	ctx := capabilityclient.WithCallContext(context.Background(), &capv1.CallContext{}, &capv1.PermissionContext{AuthenticatedOwnerId: "@owner:example.test"})
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
	if _, err := capability.HandleAsOwner(context.Background(), "@owner:example.test", "agent.execution.v2.projects.analyze", map[string]any{"project_id": "11111111-1111-4111-8111-111111111111", "source": map[string]any{"kind": "git_https", "location": "https://github.com/example/repo", "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "immutable": true}, "idempotency_key": "22222222-2222-4222-8222-222222222222"}); !errors.Is(err, coreexecutionv2.ErrMissingPort) {
		t.Fatalf("unavailable action err=%v, want ErrMissingPort", err)
	}
}
