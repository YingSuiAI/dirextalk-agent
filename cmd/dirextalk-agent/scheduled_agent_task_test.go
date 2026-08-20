package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

func TestScheduledAgentTaskUsesDeterministicNativeTurnAndReturnsMarkdownOnly(t *testing.T) {
	profileID := uuid.NewString()
	resolver := &scheduledProfileStub{profile: coremodel.Profile{
		ID: profileID, DisplayName: "scheduled", Provider: coremodel.ProviderOpenAICompatible,
		RequestDialect: coremodel.DialectOpenAICompatibleChatV1, ModelKind: coremodel.ModelKindConversation,
		BaseURL: "https://model.invalid/v1", Model: "test", APIKey: "secret", Revision: 4, CredentialVersion: 4,
	}}
	conversation := &scheduledConversationStub{turns: make(map[string]coreconversation.Turn), markdown: "# Daily summary\n\n- One item"}
	task := scheduledTaskFixture(profileID)
	handler := scheduledAgentTaskHandler(conversation, resolver)

	first := handler(context.Background(), task)
	second := handler(context.Background(), task)
	if first.Err != nil || second.Err != nil || first.Result.Text != conversation.markdown || second.Result.Text != conversation.markdown {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	if len(first.Result.JSON) != 0 || first.Result.Summary != "" || len(first.Result.Files) != 0 {
		t.Fatalf("result leaked non-Markdown fields: %+v", first.Result)
	}
	if conversation.creates != 1 || conversation.starts != 2 || conversation.gets != 0 {
		t.Fatalf("creates=%d starts=%d gets=%d", conversation.creates, conversation.starts, conversation.gets)
	}
	wantRequestID := scheduledAgentUUID("scheduled-agent-request:" + task.ID)
	wantTurnID := scheduledAgentUUID("scheduled-agent-turn:" + task.ID)
	wantPrompt, err := scheduledAgentPrompt(task.Spec.Goal, task.AvailableAt, task.Spec.Payload.Agent.ScheduledConversation.Timezone, task.Spec.Payload.Agent.ScheduledConversation.Capability)
	if err != nil {
		t.Fatal(err)
	}
	command := conversation.commands[0]
	if command.RequestID != wantRequestID || command.TurnID != wantTurnID || command.ConversationID != task.Spec.ConversationID ||
		command.Prompt != wantPrompt || command.OwnerID != task.Spec.Payload.Agent.OwnerID ||
		command.AccountGeneration != task.Spec.Payload.Agent.AccountGeneration || command.IntrinsicPolicy != coreconversation.TurnIntrinsicPolicyNone ||
		command.ExecutionMode != coreconversation.TurnExecutionScheduled || len(command.ExtensionSnapshots) != 1 ||
		command.ExtensionSnapshots[0].Source != "message-mcp" || len(command.ExtensionSnapshots[0].ToolNames) != 2 || command.ExtensionSnapshots[0].ToolNames[0] != "mcp__message__dirextalk_messages_list" {
		t.Fatalf("start command=%+v", command)
	}
	if conversation.commands[1].Prompt != wantPrompt || conversation.commands[1].Fingerprint() != command.Fingerprint() ||
		!strings.Contains(wantPrompt, "Authoritative occurrence UTC: 2026-08-19T01:00:00Z") ||
		!strings.Contains(wantPrompt, "Authoritative occurrence local time: 2026-08-19T09:00:00+08:00") ||
		!strings.Contains(wantPrompt, "Scheduled capability: chat_summary") ||
		!strings.Contains(wantPrompt, "mcp__message__dirextalk_messages_list at most once") ||
		!strings.Contains(wantPrompt, "only nonempty final Markdown text") ||
		!strings.HasSuffix(wantPrompt, "Scheduled goal:\n"+task.Spec.Goal) {
		t.Fatalf("scheduled prompt is not deterministic and occurrence-anchored: %q", wantPrompt)
	}
	assertScheduledAuthority(t, resolver.ctx, task)
	assertScheduledAuthority(t, conversation.ctxs[0], task)
	if call, ok := capabilityclient.CallContextFromContext(conversation.ctxs[0]); ok || call != nil {
		t.Fatalf("scheduled execution fabricated Product call context=%+v", call)
	}
}

func TestScheduledTurnOutcomeRejectsNonSuccessTerminalStates(t *testing.T) {
	tests := []struct {
		name string
		turn coreconversation.Turn
	}{
		{name: "failed", turn: coreconversation.Turn{State: coreconversation.TurnFailed, TerminalSummary: "provider unavailable"}},
		{name: "canceled", turn: coreconversation.Turn{State: coreconversation.TurnCanceled}},
		{name: "invalid completed response", turn: coreconversation.Turn{State: coreconversation.TurnCompleted}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outcome, terminal := scheduledTurnOutcome(test.turn)
			if !terminal || outcome.Err == nil || outcome.Result.Text != "" {
				t.Fatalf("outcome=%+v terminal=%v", outcome, terminal)
			}
		})
	}
}

func TestScheduledAgentTaskFailsClosedOnTurnIdentityDrift(t *testing.T) {
	profileID := uuid.NewString()
	resolver := &scheduledProfileStub{profile: coremodel.Profile{ID: profileID, DisplayName: "scheduled", Provider: coremodel.ProviderOpenAICompatible,
		RequestDialect: coremodel.DialectOpenAICompatibleChatV1, ModelKind: coremodel.ModelKindConversation,
		BaseURL: "https://model.invalid/v1", Model: "test", APIKey: "secret", Revision: 4, CredentialVersion: 4}}
	conversation := &scheduledConversationStub{turns: make(map[string]coreconversation.Turn), markdown: "ok", driftOwner: true}
	outcome := scheduledAgentTaskHandler(conversation, resolver)(context.Background(), scheduledTaskFixture(profileID))
	if !errors.Is(outcome.Err, coreconversation.ErrConflict) {
		t.Fatalf("outcome=%+v", outcome)
	}
}

func TestScheduledAgentTaskRejectsMissingCredentialVersionBeforeStartingTurn(t *testing.T) {
	profileID := uuid.NewString()
	resolver := &scheduledProfileStub{profile: coremodel.Profile{
		ID: profileID, DisplayName: "scheduled", Provider: coremodel.ProviderOpenAICompatible,
		RequestDialect: coremodel.DialectOpenAICompatibleChatV1, ModelKind: coremodel.ModelKindConversation,
		BaseURL: "https://model.invalid/v1", Model: "test", APIKey: "secret", Revision: 9,
		CredentialVersion: 0,
	}}
	conversation := &scheduledConversationStub{turns: make(map[string]coreconversation.Turn), markdown: "valid markdown"}
	task := scheduledTaskFixture(profileID)
	task.Snapshot.Model.Revision = 9
	task.Snapshot.Model.CredentialVersion = 3
	outcome := scheduledAgentTaskHandler(conversation, resolver)(context.Background(), task)
	if !errors.Is(outcome.Err, coreruntime.ErrScheduledSnapshotInvalid) || len(conversation.commands) != 0 {
		t.Fatalf("outcome=%+v commands=%+v", outcome, conversation.commands)
	}
}

func TestScheduledAgentTaskRejectsCapabilitySnapshotExpansionBeforeStartingTurn(t *testing.T) {
	profileID := uuid.NewString()
	resolver := &scheduledProfileStub{profile: coremodel.Profile{
		ID: profileID, DisplayName: "scheduled", Provider: coremodel.ProviderOpenAICompatible,
		RequestDialect: coremodel.DialectOpenAICompatibleChatV1, ModelKind: coremodel.ModelKindConversation,
		BaseURL: "https://model.invalid/v1", Model: "test", APIKey: "secret", Revision: 4, CredentialVersion: 4,
	}}
	conversation := &scheduledConversationStub{turns: make(map[string]coreconversation.Turn), markdown: "must not run"}
	task := scheduledTaskFixture(profileID)
	origin := task.Spec.Payload.Agent.ScheduledConversation
	origin.ExtensionSnapshots[0].Selection.AllowedTools = append(origin.ExtensionSnapshots[0].Selection.AllowedTools, "mcp__message__dirextalk_messages_send")
	origin.ExtensionSnapshots[0].ToolNames = append(origin.ExtensionSnapshots[0].ToolNames, "mcp__message__dirextalk_messages_send")

	outcome := scheduledAgentTaskHandler(conversation, resolver)(context.Background(), task)
	if !errors.Is(outcome.Err, coreruntime.ErrScheduledSnapshotInvalid) || conversation.starts != 0 || resolver.ctx != nil {
		t.Fatalf("outcome=%+v starts=%d resolver_called=%v", outcome, conversation.starts, resolver.ctx != nil)
	}
}

func TestScheduledAgentTaskClassifiesTurnAdmissionWithoutLeakingProviderError(t *testing.T) {
	profileID := uuid.NewString()
	resolver := &scheduledProfileStub{profile: coremodel.Profile{
		ID: profileID, DisplayName: "scheduled", Provider: coremodel.ProviderOpenAICompatible,
		RequestDialect: coremodel.DialectOpenAICompatibleChatV1, ModelKind: coremodel.ModelKindConversation,
		BaseURL: "https://model.invalid/v1", Model: "test", APIKey: "secret", Revision: 4, CredentialVersion: 4,
	}}
	conversation := &scheduledConversationStub{turns: make(map[string]coreconversation.Turn), startErr: errors.New("provider-secret-sentinel")}
	outcome := scheduledAgentTaskHandler(conversation, resolver)(context.Background(), scheduledTaskFixture(profileID))
	if outcome.Err != coreruntime.ErrScheduledTurnAdmission || strings.Contains(outcome.Err.Error(), "sentinel") {
		t.Fatalf("unsafe admission classification: %v", outcome.Err)
	}
}

func TestScheduledAgentTaskPinsScheduledNoteToNoToolsOrIntrinsics(t *testing.T) {
	profileID := uuid.NewString()
	resolver := &scheduledProfileStub{profile: coremodel.Profile{
		ID: profileID, DisplayName: "scheduled", Provider: coremodel.ProviderOpenAICompatible,
		RequestDialect: coremodel.DialectOpenAICompatibleChatV1, ModelKind: coremodel.ModelKindConversation,
		BaseURL: "https://model.invalid/v1", Model: "test", APIKey: "secret", Revision: 4, CredentialVersion: 4,
	}}
	conversation := &scheduledConversationStub{turns: make(map[string]coreconversation.Turn), markdown: "记得喝水"}
	task := scheduledTaskFixture(profileID)
	task.Spec.Payload.Agent.ScheduledConversation.Capability = coretask.ScheduledCapabilityScheduledNote
	task.Spec.Payload.Agent.ScheduledConversation.ExtensionSnapshots = []coretask.ScheduledExtensionSnapshot{}

	outcome := scheduledAgentTaskHandler(conversation, resolver)(context.Background(), task)
	if outcome.Err != nil || outcome.Result.Text != "记得喝水" || len(conversation.commands) != 1 {
		t.Fatalf("outcome=%+v commands=%+v", outcome, conversation.commands)
	}
	command := conversation.commands[0]
	if !command.ExtensionSnapshotsPinned || command.ExtensionSnapshots == nil || len(command.ExtensionSnapshots) != 0 || command.IntrinsicPolicy != coreconversation.TurnIntrinsicPolicyNone {
		t.Fatalf("scheduled note runtime was not pinned empty: %+v", command)
	}
	if !strings.Contains(command.Prompt, "self-contained Markdown generated from the scheduled goal") ||
		!strings.Contains(command.Prompt, "do not summarize or claim facts from Matrix rooms") {
		t.Fatalf("scheduled note scope guidance missing: %q", command.Prompt)
	}
}

func TestScheduledAgentTaskPinsOrderedWebDigestDeliverySources(t *testing.T) {
	profileID := uuid.NewString()
	resolver := &scheduledProfileStub{profile: coremodel.Profile{
		ID: profileID, DisplayName: "scheduled", Provider: coremodel.ProviderOpenAICompatible,
		RequestDialect: coremodel.DialectOpenAICompatibleChatV1, ModelKind: coremodel.ModelKindConversation,
		BaseURL: "https://model.invalid/v1", Model: "test", APIKey: "secret", Revision: 4, CredentialVersion: 4,
	}}
	conversation := &scheduledConversationStub{turns: make(map[string]coreconversation.Turn), markdown: "# Web digest\n\nSent to the room."}
	task := scheduledTaskFixture(profileID)
	origin := task.Spec.Payload.Agent.ScheduledConversation
	origin.Capability = coretask.ScheduledCapabilityWebDigestDelivery
	message := origin.ExtensionSnapshots[0]
	message.Selection.AllowedTools = []string{"mcp__message__dirextalk_messages_send", "mcp__message__dirextalk_rooms_search"}
	message.ToolNames = append([]string(nil), message.Selection.AllowedTools...)
	webID := uuid.NewString()
	webDigest := strings.Repeat("d", 64)
	web := coretask.ScheduledExtensionSnapshot{
		Selection:      coretask.ExtensionSelection{Kind: coretask.ExtensionMCP, ID: webID, Version: "web-config-1", Digest: webDigest, AllowedTools: []string{"web_search"}},
		InstallationID: webID, VersionID: "web-config-1", Source: "builtin:web_search:tavily", ContentDigest: webDigest,
		ArtifactDigest: strings.Repeat("e", 64), ToolSchemaDigest: strings.Repeat("f", 64), ToolNames: []string{"web_search"}, ReadOnly: true,
	}
	origin.ExtensionSnapshots = []coretask.ScheduledExtensionSnapshot{web, message}

	outcome := scheduledAgentTaskHandler(conversation, resolver)(context.Background(), task)
	if outcome.Err != nil || outcome.Result.Text != conversation.markdown || len(conversation.commands) != 1 {
		t.Fatalf("outcome=%+v commands=%+v", outcome, conversation.commands)
	}
	command := conversation.commands[0]
	if len(command.ExtensionSnapshots) != 2 || command.ExtensionSnapshots[0].Source != "builtin:web_search:tavily" || command.ExtensionSnapshots[1].Source != "message-mcp" ||
		len(command.ExtensionSnapshots[0].ToolNames) != 1 || command.ExtensionSnapshots[0].ToolNames[0] != "web_search" ||
		len(command.ExtensionSnapshots[1].ToolNames) != 2 || command.ExtensionSnapshots[1].ToolNames[0] != "mcp__message__dirextalk_messages_send" ||
		command.IntrinsicPolicy != coreconversation.TurnIntrinsicPolicyNone || !command.ExtensionSnapshotsPinned {
		t.Fatalf("ordered scheduled runtime=%+v", command)
	}
}

func TestScheduledAgentPromptRejectsMissingOccurrenceAuthority(t *testing.T) {
	for _, test := range []struct {
		name     string
		at       time.Time
		timezone string
	}{
		{name: "zero occurrence", timezone: "UTC"},
		{name: "non UTC occurrence", at: time.Date(2026, 8, 19, 9, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60)), timezone: "Asia/Shanghai"},
		{name: "missing timezone", at: time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC)},
		{name: "invalid timezone", at: time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC), timezone: "Mars/Olympus"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := scheduledAgentPrompt("goal", test.at, test.timezone, coretask.ScheduledCapabilityChatSummary); !errors.Is(err, coretask.ErrInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestScheduledCapabilityExecutionGuidanceConvergesSinglePassWorkflows(t *testing.T) {
	tests := []struct {
		name       string
		capability coretask.ScheduledCapability
		ordered    []string
	}{
		{
			name:       "chat summary",
			capability: coretask.ScheduledCapabilityChatSummary,
			ordered: []string{
				"exact room ID", "skip mcp__message__dirextalk_rooms_search", "otherwise call it at most once",
				"mcp__message__dirextalk_messages_list at most once", "Do not claim there are no messages", "completed successfully and returned no messages",
				"immediately synthesize", "call no more tools",
			},
		},
		{
			name:       "web research",
			capability: coretask.ScheduledCapabilityWebResearch,
			ordered: []string{
				"web_search exactly once", "one focused query", "bounded max_results", "synthesize the research", "call no more tools",
				"Every source citation", "[descriptive title](https://...)", "never a bare URL",
			},
		},
		{
			name:       "chat summary delivery",
			capability: coretask.ScheduledCapabilityChatSummaryDelivery,
			ordered: []string{
				"mcp__message__dirextalk_messages_list at most once", "Do not claim there are no messages", "completed successfully and returned no messages",
				"Synthesize the summary", "mcp__message__dirextalk_messages_send exactly once", "call no more tools",
			},
		},
		{
			name:       "web digest delivery",
			capability: coretask.ScheduledCapabilityWebDigestDelivery,
			ordered: []string{
				"web_search exactly once", "synthesize the digest", "Every source citation", "[descriptive title](https://...)", "never a bare URL",
				"exact room ID", "mcp__message__dirextalk_messages_send exactly once",
				"unknown completion", "report the delivery status", "call no more tools",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			guidance, err := scheduledCapabilityExecutionGuidance(test.capability)
			if err != nil {
				t.Fatal(err)
			}
			assertOrderedScheduledGuidance(t, guidance, test.ordered)
			if !strings.Contains(guidance, "must not issue a second model tool call") ||
				!strings.Contains(guidance, "instead of searching or sending again") ||
				!strings.Contains(guidance, "Never claim external data is absent unless") {
				t.Fatalf("guidance lacks common single-pass rule: %q", guidance)
			}
		})
	}
	if _, err := scheduledCapabilityExecutionGuidance(coretask.ScheduledCapability("unknown")); !errors.Is(err, coretask.ErrInvalid) {
		t.Fatalf("invalid capability err=%v", err)
	}
}

func assertOrderedScheduledGuidance(t *testing.T, guidance string, fragments []string) {
	t.Helper()
	offset := 0
	for _, fragment := range fragments {
		index := strings.Index(guidance[offset:], fragment)
		if index < 0 {
			t.Fatalf("guidance missing ordered fragment %q after byte %d: %q", fragment, offset, guidance)
		}
		offset += index + len(fragment)
	}
}

type scheduledProfileStub struct {
	profile coremodel.Profile
	ctx     context.Context
}

func (s *scheduledProfileStub) ResolveExecutionProfile(ctx context.Context, _ coretask.ModelProfileSnapshot) (coremodel.Profile, error) {
	s.ctx = ctx
	return s.profile, nil
}

type scheduledConversationStub struct {
	turns      map[string]coreconversation.Turn
	commands   []coreconversation.TurnStartCommand
	ctxs       []context.Context
	markdown   string
	starts     int
	creates    int
	gets       int
	driftOwner bool
	startErr   error
}

func (s *scheduledConversationStub) StartTurn(ctx context.Context, command coreconversation.TurnStartCommand) (coreconversation.Turn, error) {
	s.starts++
	s.commands = append(s.commands, command)
	s.ctxs = append(s.ctxs, ctx)
	if s.startErr != nil {
		return coreconversation.Turn{}, s.startErr
	}
	if err := command.Validate(); err != nil {
		return coreconversation.Turn{}, err
	}
	if existing, ok := s.turns[command.RequestID]; ok {
		return existing, nil
	}
	s.creates++
	owner := command.OwnerID
	if s.driftOwner {
		owner = "@replacement:example.test"
	}
	turn := coreconversation.Turn{
		ID: command.TurnID, RequestID: command.RequestID, OwnerID: owner, AccountGeneration: command.AccountGeneration,
		ConversationID: command.ConversationID, Prompt: command.Prompt, ProfileID: command.ProfileID, State: coreconversation.TurnCompleted,
	}
	turn.Response = &coreconversation.ChatResponse{
		RequestID: command.RequestID, ConversationID: command.ConversationID, Done: true, ModelProfileID: command.ProfileID,
		Message: coreconversation.Message{ID: uuid.NewString(), Role: coreconversation.RoleAssistant, Content: s.markdown, CreatedAt: time.Now().UTC(), ModelProfileID: command.ProfileID},
	}
	s.turns[command.RequestID] = turn
	return turn, nil
}

func (s *scheduledConversationStub) GetTurn(_ context.Context, id string) (coreconversation.Turn, error) {
	s.gets++
	for _, turn := range s.turns {
		if turn.ID == id {
			return turn, nil
		}
	}
	return coreconversation.Turn{}, coreconversation.ErrConflict
}

func (*scheduledConversationStub) CancelTurn(context.Context, coreconversation.TurnCancelCommand) (coreconversation.Turn, error) {
	return coreconversation.Turn{}, nil
}

func scheduledTaskFixture(profileID string) coretask.Task {
	toolID := uuid.NewString()
	digest := strings.Repeat("a", 64)
	return coretask.Task{
		ID:          uuid.NewString(),
		AvailableAt: time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC),
		Spec: coretask.TaskSpec{
			Kind: coretask.TaskKindAgent, Goal: "summarize the room", ConversationID: uuid.NewString(), ModelProfileID: profileID,
			Payload: coretask.TaskPayload{Agent: &coretask.AgentTaskPayload{
				OwnerID: "@owner:example.test", AccountGeneration: 7,
				ScheduledConversation: &coretask.ScheduledConversationOrigin{Capability: coretask.ScheduledCapabilityChatSummary, Timezone: "Asia/Shanghai", ExtensionSnapshots: []coretask.ScheduledExtensionSnapshot{{
					Selection:      coretask.ExtensionSelection{Kind: coretask.ExtensionMCP, ID: toolID, Version: "1", Digest: digest, AllowedTools: []string{"mcp__message__dirextalk_messages_list", "mcp__message__dirextalk_rooms_search"}},
					InstallationID: toolID, VersionID: "message-config-1", Source: "message-mcp", ContentDigest: digest,
					ArtifactDigest: strings.Repeat("b", 64), ToolSchemaDigest: strings.Repeat("c", 64), ToolNames: []string{"mcp__message__dirextalk_messages_list", "mcp__message__dirextalk_rooms_search"}, ReadOnly: true,
				}}},
			}},
		},
		Snapshot: &coretask.ExecutionSnapshot{Model: coretask.ModelProfileSnapshot{
			ProfileID: profileID, Revision: 4, CredentialVersion: 4,
			Provider: string(coremodel.ProviderOpenAICompatible), RequestDialect: string(coremodel.DialectOpenAICompatibleChatV1), ModelKind: coremodel.ModelKindConversation,
		}},
	}
}

func assertScheduledAuthority(t *testing.T, ctx context.Context, task coretask.Task) {
	t.Helper()
	permission, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || permission.GetAuthenticatedOwnerId() != task.Spec.Payload.Agent.OwnerID ||
		permission.GetAccountGeneration() != int64(task.Spec.Payload.Agent.AccountGeneration) ||
		len(permission.GetGrantedScopes()) != 0 || len(permission.GetCapabilityGrant()) != 0 || len(permission.GetRootRequestDigest()) != 0 {
		t.Fatalf("permission=%+v", permission)
	}
}
