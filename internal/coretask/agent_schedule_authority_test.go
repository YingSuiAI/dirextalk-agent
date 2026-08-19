package coretask

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAgentScheduleAuthorityPayloadIsMinimalAndSurvivesMaterialization(t *testing.T) {
	conversationID, profileID := uuid.NewString(), uuid.NewString()
	template := TaskTemplate{
		Kind:    TaskKindAgent,
		Payload: TaskPayload{Agent: &AgentTaskPayload{OwnerID: "  @owner:example.test  ", AccountGeneration: 7}},
		Goal:    "scheduled goal", ConversationID: conversationID, ModelProfileID: profileID,
	}
	normalized, err := template.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Payload.Agent == nil || normalized.Payload.Agent.OwnerID != "@owner:example.test" || normalized.Payload.Agent.AccountGeneration != 7 {
		t.Fatalf("authority=%+v", normalized.Payload.Agent)
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		t.Fatal(err)
	}
	jsonText := string(raw)
	if !strings.Contains(jsonText, `"payload":{"agent":{"owner_id":"@owner:example.test","account_generation":7}}`) || strings.Contains(jsonText, "credential") || strings.Contains(jsonText, "attachment_refs") || strings.Contains(jsonText, "knowledge_refs") || strings.Contains(jsonText, "extensions") {
		t.Fatalf("unexpected persisted template JSON: %s", jsonText)
	}
	spec, err := normalized.Materialize(uuid.NewString(), time.Now().UTC())
	if err != nil || spec.Payload.Agent == nil || spec.Payload.Agent.OwnerID != "@owner:example.test" || spec.Payload.Agent.AccountGeneration != 7 {
		t.Fatalf("materialized=%+v err=%v", spec, err)
	}
}

func TestAgentScheduleAuthorityPayloadRejectsMissingOrMixedAuthority(t *testing.T) {
	base := TaskSpec{Kind: TaskKindAgent, Goal: "goal", ConversationID: uuid.NewString(), ModelProfileID: uuid.NewString(), IdempotencyKey: uuid.NewString(), AvailableAt: time.Now().UTC()}
	for _, payload := range []TaskPayload{
		{Agent: &AgentTaskPayload{}},
		{Agent: &AgentTaskPayload{OwnerID: "owner", AccountGeneration: 1}, Workload: &WorkloadTaskPayload{}},
	} {
		candidate := base
		candidate.Payload = payload
		if _, err := candidate.Normalize(); err == nil {
			t.Fatalf("payload unexpectedly accepted: %+v", payload)
		}
	}
}

func TestNativeScheduledTemplateDefersModelButMaterializedTaskRequiresExactProfile(t *testing.T) {
	template := TaskTemplate{
		Kind: TaskKindAgent,
		Payload: TaskPayload{Agent: &AgentTaskPayload{
			OwnerID: "@owner:example.test", AccountGeneration: 7,
			ScheduledConversation: &ScheduledConversationOrigin{
				Capability: ScheduledCapabilityScheduledNote, Timezone: "UTC", ExtensionSnapshots: []ScheduledExtensionSnapshot{},
			},
		}},
		Goal: "scheduled goal", ConversationID: uuid.NewString(),
	}
	normalized, err := template.Normalize()
	if err != nil || normalized.ModelProfileID != "" {
		t.Fatalf("dynamic template=%+v err=%v", normalized, err)
	}
	if _, err = normalized.Materialize(uuid.NewString(), time.Now().UTC()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unresolved template materialized without a model: %v", err)
	}
	ordinary := TaskSpec{
		Kind: TaskKindAgent, Payload: normalized.Payload, Goal: normalized.Goal, ConversationID: normalized.ConversationID,
		IdempotencyKey: uuid.NewString(), AvailableAt: time.Now().UTC(),
	}
	if _, err = ordinary.Normalize(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ordinary task accepted an empty model profile: %v", err)
	}
	resolved := normalized
	resolved.ModelProfileID = uuid.NewString()
	if _, err = resolved.Materialize(uuid.NewString(), time.Now().UTC()); err != nil {
		t.Fatalf("resolved occurrence did not materialize: %v", err)
	}
}
