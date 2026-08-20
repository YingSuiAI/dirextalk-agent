package agentcapability

import (
	"testing"

	agentdatav2 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/agent/data/v2"
)

func TestServerCapabilityUsesGeneratedAgentDataScopes(t *testing.T) {
	descriptor := (&coreServerCapability{}).Descriptor()
	want := map[string]agentdatav2.AgentDataScope{
		"list_servers":    agentdatav2.AgentDataScopeAgentServersRead,
		"get_server":      agentdatav2.AgentDataScopeAgentServersRead,
		"list_artifacts":  agentdatav2.AgentDataScopeAgentServersRead,
		"delete_artifact": agentdatav2.AgentDataScopeAgentServersWrite,
		"destroy_server":  agentdatav2.AgentDataScopeAgentServersDestroy,
	}
	if len(descriptor.GetOperations()) != len(want) {
		t.Fatalf("server operation count = %d, want %d", len(descriptor.GetOperations()), len(want))
	}
	for _, operation := range descriptor.GetOperations() {
		expected, ok := want[operation.GetOperationId()]
		if !ok {
			t.Fatalf("unexpected server operation %q", operation.GetOperationId())
		}
		if scopes := operation.GetRequiredScopes(); len(scopes) != 1 || scopes[0] != string(expected) {
			t.Fatalf("%s scopes = %v, want %q", operation.GetOperationId(), scopes, expected)
		}
	}
}
