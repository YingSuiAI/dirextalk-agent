package coretask

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestScheduledConversationSnapshotAdmission(t *testing.T) {
	message := scheduledSnapshot(ExtensionMCP, "message-mcp", "mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_list")
	message.VersionID = "message-config-1"
	message.ReadOnly = true

	spec := scheduledAgentSpec(message)
	normalized, err := spec.Normalize()
	if err != nil {
		t.Fatalf("normalize supported snapshots: %v", err)
	}
	if got := len(normalized.Payload.Agent.ScheduledConversation.ExtensionSnapshots); got != 1 {
		t.Fatalf("snapshot count=%d", got)
	}

	ordinary := spec
	ordinary.Payload.Agent.ScheduledConversation = nil
	if _, err := ordinary.Normalize(); err != nil {
		t.Fatalf("ordinary Agent payload was rejected: %v", err)
	}
}

func TestScheduledCapabilityBindingsAreClosedAndExact(t *testing.T) {
	tests := []struct {
		capability ScheduledCapability
		sources    []string
		tools      [][]string
	}{
		{capability: ScheduledCapabilityScheduledNote},
		{capability: ScheduledCapabilityChatSummary, sources: []string{"message-mcp"}, tools: [][]string{{"mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_list"}}},
		{capability: ScheduledCapabilityWebResearch, sources: []string{"builtin:web_search:tavily"}, tools: [][]string{{"web_search"}}},
		{capability: ScheduledCapabilityRoomMessage, sources: []string{"message-mcp"}, tools: [][]string{{"mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_send"}}},
		{capability: ScheduledCapabilityContactReport, sources: []string{"message-mcp"}, tools: [][]string{{"mcp__message__dirextalk_contacts_list", "mcp__message__dirextalk_contacts_search"}}},
		{capability: ScheduledCapabilityRoomMemberReport, sources: []string{"message-mcp"}, tools: [][]string{{"mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_room_members_list"}}},
		{capability: ScheduledCapabilityChannelDigest, sources: []string{"message-mcp"}, tools: [][]string{{"mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_channel_posts_list", "mcp__message__dirextalk_channel_comments_list"}}},
		{capability: ScheduledCapabilityChatSummaryDelivery, sources: []string{"message-mcp"}, tools: [][]string{{"mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_list", "mcp__message__dirextalk_messages_send"}}},
		{capability: ScheduledCapabilityWebDigestDelivery, sources: []string{"builtin:web_search:tavily", "message-mcp"}, tools: [][]string{{"web_search"}, {"mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_send"}}},
	}
	for _, test := range tests {
		t.Run(string(test.capability), func(t *testing.T) {
			bindings, err := test.capability.RequiredBindings()
			if err != nil || len(bindings) != len(test.sources) {
				t.Fatalf("bindings=%+v err=%v", bindings, err)
			}
			for index, binding := range bindings {
				providerNames := make([]string, 0, len(binding.Tools))
				for _, tool := range binding.Tools {
					providerNames = append(providerNames, tool.ProviderName)
					if tool.LogicalName == "" {
						t.Fatalf("binding[%d] has empty logical tool: %+v", index, binding)
					}
				}
				if binding.Source != test.sources[index] || !reflect.DeepEqual(providerNames, test.tools[index]) {
					t.Fatalf("binding[%d]=%+v", index, binding)
				}
			}
		})
	}
	if _, err := ScheduledCapability("arbitrary").RequiredBindings(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown capability err=%v", err)
	}
}

func TestScheduledConversationSnapshotFailsClosed(t *testing.T) {
	base := scheduledSnapshot(ExtensionMCP, "message-mcp", "mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_list")
	base.VersionID = "message-config-1"
	base.ReadOnly = true

	tests := []struct {
		name      string
		snapshots []ScheduledExtensionSnapshot
		want      error
	}{
		{name: "product capability", snapshots: []ScheduledExtensionSnapshot{func() ScheduledExtensionSnapshot { value := base; value.Source = "product-capability"; return value }()}, want: ErrInvalid},
		{name: "semantic knowledge", snapshots: []ScheduledExtensionSnapshot{func() ScheduledExtensionSnapshot {
			value := base
			value.Source = "builtin:knowledge:semantic"
			return value
		}()}, want: ErrInvalid},
		{name: "unknown synthetic", snapshots: []ScheduledExtensionSnapshot{func() ScheduledExtensionSnapshot {
			value := base
			value.Source = "builtin:unknown"
			value.VersionID = uuid.NewString()
			value.InstallationRevision = 1
			return value
		}()}, want: ErrInvalid},
		{name: "snapshot drift", snapshots: []ScheduledExtensionSnapshot{func() ScheduledExtensionSnapshot {
			value := base
			value.ContentDigest = strings.Repeat("f", 64)
			return value
		}()}, want: ErrInvalid},
		{name: "duplicate tool", snapshots: []ScheduledExtensionSnapshot{base, func() ScheduledExtensionSnapshot {
			value := base
			value.Selection.ID = uuid.NewString()
			value.InstallationID = value.Selection.ID
			return value
		}()}, want: ErrConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := scheduledAgentSpec(test.snapshots...).Normalize()
			if !errors.Is(err, test.want) {
				t.Fatalf("err=%v, want %v", err, test.want)
			}
		})
	}
}

func TestScheduledConversationCapabilityFailsClosed(t *testing.T) {
	chat := scheduledSnapshot(ExtensionMCP, "message-mcp", "mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_list")
	chat.VersionID = "message-config-1"
	chat.ReadOnly = true
	web := scheduledSnapshot(ExtensionMCP, "builtin:web_search:tavily", "web_search")
	web.VersionID = "web-config-1"
	web.ReadOnly = true
	extraTool := chat
	extraTool.Selection.AllowedTools = append(extraTool.Selection.AllowedTools, "mcp__message__dirextalk_messages_send")
	extraTool.ToolNames = append(extraTool.ToolNames, "mcp__message__dirextalk_messages_send")
	scheduledNoteWithTool := chat
	tests := []struct {
		name       string
		capability ScheduledCapability
		snapshots  []ScheduledExtensionSnapshot
	}{
		{name: "missing capability", snapshots: []ScheduledExtensionSnapshot{chat}},
		{name: "unknown capability", capability: "installed_workflow", snapshots: []ScheduledExtensionSnapshot{chat}},
		{name: "missing exact tool", capability: ScheduledCapabilityRoomMessage, snapshots: []ScheduledExtensionSnapshot{chat}},
		{name: "unrelated snapshot", capability: ScheduledCapabilityChatSummary, snapshots: []ScheduledExtensionSnapshot{chat, web}},
		{name: "extra source tool", capability: ScheduledCapabilityChatSummary, snapshots: []ScheduledExtensionSnapshot{extraTool}},
		{name: "scheduled note with tool", capability: ScheduledCapabilityScheduledNote, snapshots: []ScheduledExtensionSnapshot{scheduledNoteWithTool}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := scheduledAgentSpec(test.snapshots...)
			spec.Payload.Agent.ScheduledConversation.Capability = test.capability
			if _, err := spec.Normalize(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestScheduledConversationCapabilitiesAdmitOnlyTheirExactSnapshot(t *testing.T) {
	tests := []struct {
		capability ScheduledCapability
		source     string
		tools      []string
	}{
		{capability: ScheduledCapabilityScheduledNote},
		{capability: ScheduledCapabilityChatSummary, source: "message-mcp", tools: []string{"mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_list"}},
		{capability: ScheduledCapabilityWebResearch, source: "builtin:web_search:tavily", tools: []string{"web_search"}},
		{capability: ScheduledCapabilityRoomMessage, source: "message-mcp", tools: []string{"mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_send"}},
		{capability: ScheduledCapabilityContactReport, source: "message-mcp", tools: []string{"mcp__message__dirextalk_contacts_list", "mcp__message__dirextalk_contacts_search"}},
		{capability: ScheduledCapabilityRoomMemberReport, source: "message-mcp", tools: []string{"mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_room_members_list"}},
		{capability: ScheduledCapabilityChannelDigest, source: "message-mcp", tools: []string{"mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_channel_posts_list", "mcp__message__dirextalk_channel_comments_list"}},
		{capability: ScheduledCapabilityChatSummaryDelivery, source: "message-mcp", tools: []string{"mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_list", "mcp__message__dirextalk_messages_send"}},
	}
	for _, test := range tests {
		t.Run(string(test.capability), func(t *testing.T) {
			var snapshots []ScheduledExtensionSnapshot
			if test.source == "" {
				snapshots = []ScheduledExtensionSnapshot{}
			} else {
				snapshot := scheduledSnapshot(ExtensionMCP, test.source, test.tools...)
				snapshot.VersionID = "message-config-1"
				if test.source == "builtin:web_search:tavily" {
					snapshot.VersionID = "web-config-1"
				}
				snapshot.ReadOnly = true
				snapshots = []ScheduledExtensionSnapshot{snapshot}
			}
			spec := scheduledAgentSpec(snapshots...)
			spec.Payload.Agent.ScheduledConversation.Capability = test.capability
			normalized, err := spec.Normalize()
			if err != nil || normalized.Payload.Agent.ScheduledConversation.Validate() != nil {
				t.Fatalf("normalize err=%v origin=%+v", err, normalized.Payload.Agent.ScheduledConversation)
			}
		})
	}
}

func TestWebDigestDeliveryRequiresExactOrderedMultiSourceClosure(t *testing.T) {
	web := scheduledSnapshot(ExtensionMCP, "builtin:web_search:tavily", "web_search")
	web.VersionID, web.ReadOnly = "web-config-1", true
	message := scheduledSnapshot(ExtensionMCP, "message-mcp", "mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_send")
	message.VersionID, message.ReadOnly = "message-config-1", true
	valid := scheduledAgentSpec(message, web)
	valid.Payload.Agent.ScheduledConversation.Capability = ScheduledCapabilityWebDigestDelivery
	normalized, err := valid.Normalize()
	if err != nil {
		t.Fatalf("normalize multi-source delivery: %v", err)
	}
	origin := normalized.Payload.Agent.ScheduledConversation
	if len(origin.ExtensionSnapshots) != 2 || origin.ExtensionSnapshots[0].Source != "builtin:web_search:tavily" || origin.ExtensionSnapshots[1].Source != "message-mcp" || origin.Validate() != nil {
		t.Fatalf("ordered origin=%+v", origin)
	}
	extraTool := message
	extraTool.Selection.AllowedTools = append(extraTool.Selection.AllowedTools, "mcp__message__dirextalk_messages_list")
	extraTool.ToolNames = append(extraTool.ToolNames, "mcp__message__dirextalk_messages_list")
	extraSource := scheduledSnapshot(ExtensionSkill, "registry")
	extraSource.InstallationRevision = 1
	tests := []struct {
		name      string
		snapshots []ScheduledExtensionSnapshot
	}{
		{name: "missing web source", snapshots: []ScheduledExtensionSnapshot{message}},
		{name: "missing message source", snapshots: []ScheduledExtensionSnapshot{web}},
		{name: "extra message tool", snapshots: []ScheduledExtensionSnapshot{web, extraTool}},
		{name: "extra source", snapshots: []ScheduledExtensionSnapshot{web, message, extraSource}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := scheduledAgentSpec(test.snapshots...)
			spec.Payload.Agent.ScheduledConversation.Capability = ScheduledCapabilityWebDigestDelivery
			if _, err := spec.Normalize(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestScheduledConversationOriginRequiresCanonicalTimezone(t *testing.T) {
	normalized, err := scheduledAgentSpec(scheduledChatSummarySnapshotForTask()).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	valid := normalized.Payload.Agent.ScheduledConversation
	if valid.Validate() != nil {
		t.Fatalf("valid origin=%+v", valid)
	}
	for _, timezone := range []string{"", " UTC", "UTC ", "Mars/Olympus", string([]byte{0xff})} {
		candidate := *valid
		candidate.Timezone = timezone
		if candidate.Validate() == nil {
			t.Fatalf("timezone %q was accepted", timezone)
		}
	}
	nilSnapshots := *valid
	nilSnapshots.ExtensionSnapshots = nil
	if nilSnapshots.Validate() == nil {
		t.Fatal("null extension snapshot collection was accepted")
	}
}

func scheduledAgentSpec(snapshots ...ScheduledExtensionSnapshot) TaskSpec {
	return TaskSpec{
		Kind: TaskKindAgent, Goal: "summarize messages", ConversationID: uuid.NewString(), ModelProfileID: uuid.NewString(),
		IdempotencyKey: uuid.NewString(),
		Payload: TaskPayload{Agent: &AgentTaskPayload{
			OwnerID: "@owner:example.test", AccountGeneration: 7,
			ScheduledConversation: &ScheduledConversationOrigin{Capability: ScheduledCapabilityChatSummary, Timezone: "UTC", ExtensionSnapshots: snapshots},
		}},
	}
}

func scheduledChatSummarySnapshotForTask() ScheduledExtensionSnapshot {
	message := scheduledSnapshot(ExtensionMCP, "message-mcp", "mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_list")
	message.VersionID = "message-config-1"
	message.ReadOnly = true
	return message
}

func scheduledSnapshot(kind ExtensionKind, source string, tools ...string) ScheduledExtensionSnapshot {
	id := uuid.NewString()
	digest := strings.Repeat("a", 64)
	return ScheduledExtensionSnapshot{
		Selection:      ExtensionSelection{Kind: kind, ID: id, Version: "1.0.0", Digest: digest, AllowedTools: append([]string(nil), tools...)},
		InstallationID: id, VersionID: uuid.NewString(), Source: source, ContentDigest: digest,
		ArtifactDigest: strings.Repeat("b", 64), ToolSchemaDigest: strings.Repeat("c", 64), ToolNames: append([]string(nil), tools...),
	}
}
