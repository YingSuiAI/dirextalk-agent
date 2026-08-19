package coretask

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestScheduledConversationSnapshotAdmission(t *testing.T) {
	message := scheduledSnapshot(ExtensionMCP, "message-mcp", "mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_list")
	message.VersionID = "message-config-1"
	message.ReadOnly = true
	web := scheduledSnapshot(ExtensionMCP, "builtin:web_search:tavily", "web_search")
	web.VersionID = "web-config-1"
	web.ReadOnly = true
	installed := scheduledSnapshot(ExtensionSkill, "github")
	installed.VersionID = uuid.NewString()
	installed.InstallationRevision = 3
	installed.SkillInstructions = "Use the pinned workflow."

	spec := scheduledAgentSpec(message, web, installed)
	normalized, err := spec.Normalize()
	if err != nil {
		t.Fatalf("normalize supported snapshots: %v", err)
	}
	if got := len(normalized.Payload.Agent.ScheduledConversation.ExtensionSnapshots); got != 3 {
		t.Fatalf("snapshot count=%d", got)
	}

	ordinary := spec
	ordinary.Payload.Agent.ScheduledConversation = nil
	if _, err := ordinary.Normalize(); err != nil {
		t.Fatalf("ordinary Agent payload was rejected: %v", err)
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
	tests := []struct {
		name       string
		capability ScheduledCapability
		snapshots  []ScheduledExtensionSnapshot
	}{
		{name: "missing capability", snapshots: []ScheduledExtensionSnapshot{chat}},
		{name: "unknown capability", capability: "installed_workflow", snapshots: []ScheduledExtensionSnapshot{chat}},
		{name: "missing exact tool", capability: ScheduledCapabilityRoomMessage, snapshots: []ScheduledExtensionSnapshot{chat}},
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

func scheduledAgentSpec(snapshots ...ScheduledExtensionSnapshot) TaskSpec {
	return TaskSpec{
		Kind: TaskKindAgent, Goal: "summarize messages", ConversationID: uuid.NewString(), ModelProfileID: uuid.NewString(),
		IdempotencyKey: uuid.NewString(),
		Payload: TaskPayload{Agent: &AgentTaskPayload{
			OwnerID: "@owner:example.test", AccountGeneration: 7,
			ScheduledConversation: &ScheduledConversationOrigin{Capability: ScheduledCapabilityChatSummary, ExtensionSnapshots: snapshots},
		}},
	}
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
