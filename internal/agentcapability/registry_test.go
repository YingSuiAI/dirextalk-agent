package agentcapability

import (
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
)

func TestNewRegistryIsEmptyUntilExplicitlyComposed(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	if descriptors := r.List(); len(descriptors) != 0 {
		t.Fatalf("uncomposed registry published %d capabilities", len(descriptors))
	}
}

func TestCoreRegistryDoesNotPublishUnboundOrLegacyCapabilities(t *testing.T) {
	r := NewCoreRegistry(CoreBindings{})
	if _, ok := r.Get("agent.chat.v1"); ok {
		t.Fatal("unbound chat capability was published")
	}
	if _, ok := r.Get("agent.models.v1"); ok {
		t.Fatal("unbound model capability was published")
	}
	if _, ok := r.Get("agent.tasks.v1"); ok {
		t.Fatal("unbound task capability was published")
	}
	if _, ok := r.Get("agent.knowledge.v1"); ok {
		t.Fatal("unbound knowledge capability was published")
	}
	for _, descriptor := range r.List() {
		for _, operation := range descriptor.GetOperations() {
			text := strings.ToLower(operation.GetDescription() + " " + operation.GetDisplayName())
			if strings.Contains(text, "not implemented") {
				t.Fatalf("production descriptor advertises an unimplemented operation: %s/%s", descriptor.GetCapabilityId(), operation.GetOperationId())
			}
		}
	}
}

func TestCoreRegistryDoesNotPublishExecutionV2WithoutTypedProvider(t *testing.T) {
	domain, err := coreexecutionv2.NewService(coreexecutionv2.Config{Store: coreexecutionv2.NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	r := NewCoreRegistry(CoreBindings{ExecutionV2: domain})
	if _, ok := r.Get(coreexecutionv2.CapabilityID); ok {
		t.Fatal("execution.v2 published without a typed provider readiness proof")
	}
}
