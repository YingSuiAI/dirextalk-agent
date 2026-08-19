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
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

func TestScheduledAgentTaskUsesDeterministicNativeTurnAndReturnsMarkdownOnly(t *testing.T) {
	profileID := uuid.NewString()
	resolver := &scheduledProfileStub{profile: coremodel.Profile{
		ID: profileID, DisplayName: "scheduled", Provider: coremodel.ProviderOpenAICompatible,
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
	command := conversation.commands[0]
	if command.RequestID != wantRequestID || command.TurnID != wantTurnID || command.ConversationID != task.Spec.ConversationID ||
		command.Prompt != task.Spec.Goal || command.OwnerID != task.Spec.Payload.Agent.OwnerID ||
		command.AccountGeneration != task.Spec.Payload.Agent.AccountGeneration || len(command.ExtensionSnapshots) != 1 ||
		command.ExtensionSnapshots[0].Source != "message-mcp" || len(command.ExtensionSnapshots[0].ToolNames) != 2 || command.ExtensionSnapshots[0].ToolNames[0] != "mcp__message__dirextalk_messages_list" {
		t.Fatalf("start command=%+v", command)
	}
	assertScheduledAuthority(t, resolver.ctx, task)
	assertScheduledAuthority(t, conversation.ctxs[0], task)
	call, ok := capabilityclient.CallContextFromContext(conversation.ctxs[0])
	if !ok || call.GetChainId() != scheduledAgentUUID("scheduled-agent-chain:"+task.ID) ||
		call.GetRootOperationId() != scheduledAgentUUID("scheduled-agent-root-operation:"+task.ID) || call.GetRoute() != "scheduled-agent" {
		t.Fatalf("call context=%+v", call)
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
	resolver := &scheduledProfileStub{profile: coremodel.Profile{ID: profileID, DisplayName: "scheduled", Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://model.invalid/v1", Model: "test", APIKey: "secret", Revision: 4}}
	conversation := &scheduledConversationStub{turns: make(map[string]coreconversation.Turn), markdown: "ok", driftOwner: true}
	outcome := scheduledAgentTaskHandler(conversation, resolver)(context.Background(), scheduledTaskFixture(profileID))
	if !errors.Is(outcome.Err, coreconversation.ErrConflict) {
		t.Fatalf("outcome=%+v", outcome)
	}
}

func TestScheduledAgentTaskDefaultsCredentialVersionFromPinnedRevision(t *testing.T) {
	profileID := uuid.NewString()
	resolver := &scheduledProfileStub{profile: coremodel.Profile{
		ID: profileID, DisplayName: "scheduled", Provider: coremodel.ProviderOpenAICompatible,
		BaseURL: "https://model.invalid/v1", Model: "test", APIKey: "secret", Revision: 9,
		// ResolveExecutionProfile reconstructs historical task profiles without
		// setting CredentialVersion; SnapshotFromProfile must pin it to Revision.
		CredentialVersion: 0,
	}}
	conversation := &scheduledConversationStub{turns: make(map[string]coreconversation.Turn), markdown: "valid markdown"}
	task := scheduledTaskFixture(profileID)
	task.Snapshot.Model.Revision = 9
	outcome := scheduledAgentTaskHandler(conversation, resolver)(context.Background(), task)
	if outcome.Err != nil || outcome.Result.Text != "valid markdown" || len(conversation.commands) != 1 {
		t.Fatalf("outcome=%+v commands=%+v", outcome, conversation.commands)
	}
	command := conversation.commands[0]
	if command.ExpectedCredentialVersion != 9 || command.ProfileSnapshot.CredentialVersion != 9 || command.ProfileSnapshot.Validate() != nil || !command.ExtensionSnapshotsPinned {
		t.Fatalf("invalid reconstructed snapshot: command=%+v", command)
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
}

func (s *scheduledConversationStub) StartTurn(ctx context.Context, command coreconversation.TurnStartCommand) (coreconversation.Turn, error) {
	s.starts++
	s.commands = append(s.commands, command)
	s.ctxs = append(s.ctxs, ctx)
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
		ID: uuid.NewString(),
		Spec: coretask.TaskSpec{
			Kind: coretask.TaskKindAgent, Goal: "summarize the room", ConversationID: uuid.NewString(), ModelProfileID: profileID,
			Payload: coretask.TaskPayload{Agent: &coretask.AgentTaskPayload{
				OwnerID: "@owner:example.test", AccountGeneration: 7,
				ScheduledConversation: &coretask.ScheduledConversationOrigin{Capability: coretask.ScheduledCapabilityChatSummary, ExtensionSnapshots: []coretask.ScheduledExtensionSnapshot{{
					Selection:      coretask.ExtensionSelection{Kind: coretask.ExtensionMCP, ID: toolID, Version: "1", Digest: digest, AllowedTools: []string{"mcp__message__dirextalk_messages_list", "mcp__message__dirextalk_rooms_search"}},
					InstallationID: toolID, VersionID: "message-config-1", Source: "message-mcp", ContentDigest: digest,
					ArtifactDigest: strings.Repeat("b", 64), ToolSchemaDigest: strings.Repeat("c", 64), ToolNames: []string{"mcp__message__dirextalk_messages_list", "mcp__message__dirextalk_rooms_search"}, ReadOnly: true,
				}}},
			}},
		},
		Snapshot: &coretask.ExecutionSnapshot{Model: coretask.ModelProfileSnapshot{ProfileID: profileID, Revision: 4}},
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
