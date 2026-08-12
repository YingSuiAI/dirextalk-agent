package agentcapability

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
)

func TestCurrentCapabilityDescriptorsDoNotPublishHistoricalAliases(t *testing.T) {
	tests := []struct {
		capability Capability
		forbidden  []string
	}{
		{capability: NewInfoCapability(InfoProviderFunc{}), forbidden: []string{"get_status"}},
		{capability: (&coreExtensionCapability{}), forbidden: []string{"enable_skill", "disable_skill", "enable_mcp", "disable_mcp", "skills_enable", "skills_disable", "mcp_enable", "mcp_disable"}},
		{capability: (&coreAWSCapability{}), forbidden: []string{"get_change_status"}},
		{capability: (&coreModelCapability{}), forbidden: []string{"create_model", "update_model"}},
		{capability: NewConfigCapability(nil), forbidden: []string{"propose_patch"}},
	}
	for _, test := range tests {
		published := map[string]bool{}
		for _, operation := range test.capability.Descriptor().GetOperations() {
			published[operation.GetOperationId()] = true
		}
		for _, operation := range test.forbidden {
			if published[operation] {
				t.Errorf("%s still publishes historical operation %q", test.capability.Descriptor().GetCapabilityId(), operation)
			}
		}
	}
}

func TestCurrentCapabilitySchemasContainOnlyCanonicalFieldNames(t *testing.T) {
	tests := []struct {
		capabilityID string
		operation    string
		canonical    []string
		forbidden    []string
	}{
		{capabilityID: "agent.chat.v1", operation: "list_conversations", canonical: []string{"page_size"}, forbidden: []string{"limit"}},
		{capabilityID: "agent.models.v1", operation: "list_models", canonical: []string{"page_size"}, forbidden: []string{"limit"}},
		{capabilityID: "agent.knowledge.v1", operation: "update_config", canonical: []string{"embedding_profile_id"}, forbidden: []string{"profile_id"}},
		{capabilityID: "agent.knowledge.v1", operation: "start_upload", canonical: []string{"declared_size", "media_type"}, forbidden: []string{"size", "mime_type"}},
		{capabilityID: "agent.knowledge.v1", operation: "append_upload_chunk", canonical: []string{"offset_bytes"}, forbidden: []string{"offset"}},
		{capabilityID: "agent.knowledge.v1", operation: "commit_upload", canonical: []string{"expected_revision"}},
		{capabilityID: "agent.knowledge.v1", operation: "list_sources", canonical: []string{"page_size"}, forbidden: []string{"limit"}},
		{capabilityID: "agent.tasks.v1", operation: "list_tasks", canonical: []string{"page_size"}, forbidden: []string{"limit"}},
		{capabilityID: "agent.confirmations.v1", operation: "list", canonical: []string{"page_size"}, forbidden: []string{"limit"}},
		{capabilityID: "agent.skills.v1", operation: "discover_skill", canonical: []string{"page_size"}, forbidden: []string{"limit"}},
		{capabilityID: "agent.skills.v1", operation: "list_mcp", canonical: []string{"page_size"}, forbidden: []string{"limit"}},
	}
	for _, test := range tests {
		schemaText := operationInputSchema(test.capabilityID, test.operation)
		var schema struct {
			AdditionalProperties bool                       `json:"additionalProperties"`
			Properties           map[string]json.RawMessage `json:"properties"`
			Required             []string                   `json:"required"`
		}
		if err := json.Unmarshal([]byte(schemaText), &schema); err != nil {
			t.Fatalf("decode %s/%s schema: %v", test.capabilityID, test.operation, err)
		}
		if schema.AdditionalProperties {
			t.Errorf("%s/%s schema is not closed: %s", test.capabilityID, test.operation, schemaText)
		}
		for _, field := range test.canonical {
			if _, ok := schema.Properties[field]; !ok {
				t.Errorf("%s/%s omits canonical field %q: %s", test.capabilityID, test.operation, field, schemaText)
			}
		}
		for _, field := range test.forbidden {
			if _, ok := schema.Properties[field]; ok {
				t.Errorf("%s/%s retains historical field %q: %s", test.capabilityID, test.operation, field, schemaText)
			}
		}
		if test.operation == "commit_upload" && !containsString(schema.Required, "expected_revision") {
			t.Errorf("commit_upload does not require expected_revision: %s", schemaText)
		}
	}
}

func TestCurrentCapabilityHandlersDoNotInterpretHistoricalAliases(t *testing.T) {
	chat := &coreChatCapability{}
	if _, err := chat.HandleOperation(context.Background(), "create_conversation", []byte(`{"conversation_id":"11111111-1111-4111-8111-111111111111","request_id":"22222222-2222-4222-8222-222222222222"}`)); !errors.Is(err, coreconversation.ErrInvalid) {
		t.Fatalf("request_id was accepted as idempotency_key: %v", err)
	}
	if got := pageSize(map[string]json.RawMessage{"limit": json.RawMessage(`99`)}, 50); got != 50 {
		t.Fatalf("limit was accepted as page_size: %d", got)
	}
	extension := &coreExtensionCapability{}
	for _, operation := range []string{"enable_skill", "disable_skill", "enable_mcp", "disable_mcp", "skills_enable", "skills_disable", "mcp_enable", "mcp_disable"} {
		if _, err := extension.HandleOperation(context.Background(), operation, []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "unknown") {
			t.Errorf("historical extension operation %q was not rejected: %v", operation, err)
		}
	}
}
