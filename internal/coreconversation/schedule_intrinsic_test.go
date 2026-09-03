package coreconversation

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type conversationScheduleStoreStub struct {
	commands []ConversationScheduleCommand
	err      error
}

type scheduleCapableTurnStore struct {
	*replayTurnStore
	*conversationScheduleStoreStub
}

type executingScheduleTurnStore struct {
	*readOnlyTurnStore
	*conversationScheduleStoreStub
}

type correctingScheduleModel struct {
	calls    []ToolCall
	requests []ModelRunRequest
}

type intrinsicOrderCorrectionModel struct {
	invalid   []ToolCall
	corrected ToolCall
	repeat    bool
	requests  []ModelRunRequest
}

func (m *intrinsicOrderCorrectionModel) Run(_ context.Context, request ModelRunRequest) (ModelRunResult, error) {
	m.requests = append(m.requests, request)
	if len(request.Intrinsics) == 0 && len(request.Extensions) == 0 {
		return ModelRunResult{Done: true, Message: Message{
			ID: uuid.NewString(), Role: RoleAssistant,
			Content: "## Schedule not created\n\nThe tool-call order remained invalid, so no schedule was created.", CreatedAt: time.Now().UTC(),
		}}, nil
	}
	ordinaryRound := 0
	for _, previous := range m.requests {
		if len(previous.Intrinsics) != 0 || len(previous.Extensions) != 0 {
			ordinaryRound++
		}
	}
	calls := m.invalid
	if ordinaryRound > 1 && !m.repeat {
		calls = []ToolCall{m.corrected}
	} else if ordinaryRound > 1 {
		calls = append([]ToolCall(nil), m.invalid...)
		for index := range calls {
			calls[index].ID = uuid.NewString()
		}
	}
	message := Message{ID: uuid.NewString(), Role: RoleAssistant, ToolCalls: append([]ToolCall(nil), calls...), CreatedAt: time.Now().UTC()}
	return ModelRunResult{Message: message, ToolCalls: append([]ToolCall(nil), calls...)}, nil
}

func (m *intrinsicOrderCorrectionModel) Stream(ctx context.Context, request ModelRunRequest, _ func(ModelDelta) error) (ModelRunResult, error) {
	return m.Run(ctx, request)
}

func (m *correctingScheduleModel) Run(_ context.Context, request ModelRunRequest) (ModelRunResult, error) {
	m.requests = append(m.requests, request)
	call := m.calls[len(m.requests)-1]
	message := Message{ID: uuid.NewString(), Role: RoleAssistant, ToolCalls: []ToolCall{call}, CreatedAt: time.Now().UTC()}
	return ModelRunResult{Message: message, ToolCalls: []ToolCall{call}}, nil
}

func (m *correctingScheduleModel) Stream(ctx context.Context, request ModelRunRequest, _ func(ModelDelta) error) (ModelRunResult, error) {
	return m.Run(ctx, request)
}

func (s *conversationScheduleStoreStub) CommitConversationSchedule(_ context.Context, command ConversationScheduleCommand) (coretask.Schedule, error) {
	if s.err != nil {
		return coretask.Schedule{}, s.err
	}
	s.commands = append(s.commands, command)
	return command.Schedule, nil
}

func scheduleIntrinsicLease() TurnLease {
	revision := uint64(4)
	createdAt := time.Date(2026, 8, 8, 1, 2, 3, 0, time.UTC)
	return TurnLease{
		Turn: Turn{
			ID: uuid.NewString(), RequestID: uuid.NewString(), OwnerID: "@owner:example.test", AccountGeneration: 9,
			ConversationID: uuid.NewString(), ProfileID: uuid.NewString(), ExpectedRevision: &revision, Revision: 2, State: TurnRunning, CreatedAt: createdAt, UpdatedAt: createdAt,
			ExtensionSnapshots: []ExtensionExecutionSnapshot{scheduleChatSummarySnapshot()},
		},
		LeaseID: uuid.NewString(), Epoch: 3, ExpiresAt: time.Now().UTC().Add(time.Minute),
	}
}

func scheduleChatSummarySnapshot() ExtensionExecutionSnapshot {
	id := uuid.NewString()
	digest := strings.Repeat("a", 64)
	tools := []string{"mcp__message__dirextalk_messages_list", "mcp__message__dirextalk_rooms_search"}
	return ExtensionExecutionSnapshot{
		Selection:      ExtensionSelection{Kind: ExtensionMCP, ID: id, Version: "message-config-1", Digest: digest, AllowedTools: append([]string(nil), tools...)},
		InstallationID: id, VersionID: "message-config-1", Source: "message-mcp", ContentDigest: digest,
		ArtifactDigest: strings.Repeat("b", 64), ToolSchemaDigest: strings.Repeat("c", 64), ToolNames: append([]string(nil), tools...), ReadOnly: true,
	}
}

func scheduleExtensionResolver(snapshot ExtensionExecutionSnapshot) ExtensionResolver {
	tools := make([]coremodel.Tool, 0, len(snapshot.ToolNames))
	for _, name := range snapshot.ToolNames {
		tools = append(tools, coremodel.Tool{Name: name, InputSchema: map[string]any{"type": "object"}})
	}
	return extensionResolverFunc(func(context.Context, []ExtensionSelection) ([]ResolvedExtension, error) {
		return []ResolvedExtension{{Selection: snapshot.Selection, Snapshot: snapshot, Tools: tools, Execute: func(context.Context, ToolExecutionRequest) (ToolResult, error) {
			return ToolResult{}, errors.New("unexpected scheduled capability tool execution")
		}}}, nil
	})
}

func scheduleSyntheticSnapshot(source string, tools ...string) ExtensionExecutionSnapshot {
	id := uuid.NewString()
	digest := strings.Repeat("d", 64)
	version := "message-config-1"
	if source == "builtin:web_search:tavily" {
		version = "web-config-1"
	}
	return ExtensionExecutionSnapshot{
		Selection:      ExtensionSelection{Kind: ExtensionMCP, ID: id, Version: version, Digest: digest, AllowedTools: append([]string(nil), tools...)},
		InstallationID: id, VersionID: version, Source: source, ContentDigest: digest,
		ArtifactDigest: strings.Repeat("e", 64), ToolSchemaDigest: strings.Repeat("f", 64), ToolNames: append([]string(nil), tools...), ReadOnly: true,
	}
}

func TestScheduleIntrinsicCapabilitySchemaAndAvailabilityGate(t *testing.T) {
	lease := scheduleIntrinsicLease()
	intrinsic := scheduleIntrinsic(&conversationScheduleStoreStub{}, lease)
	properties, ok := intrinsic.Tool.InputSchema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema properties=%#v", intrinsic.Tool.InputSchema["properties"])
	}
	capabilitySchema, ok := properties["capability"].(map[string]any)
	nameSchema, nameOK := properties["name"].(map[string]any)
	capabilityDescription, descriptionOK := capabilitySchema["description"].(string)
	if !ok || !nameOK || len(capabilitySchema["enum"].([]any)) != 9 || !strings.Contains(nameSchema["description"].(string), "only schedule card title") ||
		!strings.Contains(intrinsic.Tool.Description, "closed supported capability") || !strings.Contains(intrinsic.Tool.Description, "refuse every other") ||
		!strings.Contains(intrinsic.Tool.Description, "does not promise a push notification") || !strings.Contains(intrinsic.Tool.Description, "never blindly retry an unknown outcome") ||
		!strings.Contains(intrinsic.Tool.Description, "does not create a channel post") || !descriptionOK ||
		strings.Count(intrinsic.Tool.Description, scheduledCapabilitySelectionGuidance) != 1 ||
		strings.Count(capabilityDescription, scheduledCapabilitySelectionGuidance) != 1 ||
		!strings.HasSuffix(scheduleCreateGuidance, scheduledCapabilitySelectionGuidance) {
		t.Fatalf("schedule intrinsic schema=%#v description=%q", intrinsic.Tool.InputSchema, intrinsic.Tool.Description)
	}
	for _, fragment := range []string{
		"scheduled_note is only for self-contained text", "MUST NOT summarize or claim facts from Matrix rooms", "MUST use chat_summary",
		"chat_summary_delivery only when the user explicitly asks to send", "Web-source-only summary MUST use web_research",
		"Web search followed by a Matrix room send MUST use web_digest_delivery", "Never claim external data is absent without successfully executing",
	} {
		if !strings.Contains(scheduledCapabilitySelectionGuidance, fragment) {
			t.Fatalf("capability selection guidance missing %q: %q", fragment, scheduledCapabilitySelectionGuidance)
		}
	}

	tests := []struct {
		name       string
		capability string
		snapshots  []ExtensionExecutionSnapshot
		want       coretask.ScheduledCapability
		wantSource string
		wantTools  []string
	}{
		{name: "scheduled note", capability: "scheduled_note", want: coretask.ScheduledCapabilityScheduledNote},
		{name: "chat summary", capability: "chat_summary", snapshots: []ExtensionExecutionSnapshot{scheduleSyntheticSnapshot("message-mcp", "mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_list")}, want: coretask.ScheduledCapabilityChatSummary, wantSource: "message-mcp", wantTools: []string{"mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_list"}},
		{name: "web research", capability: "web_research", snapshots: []ExtensionExecutionSnapshot{scheduleSyntheticSnapshot("builtin:web_search:tavily", "web_search")}, want: coretask.ScheduledCapabilityWebResearch, wantSource: "builtin:web_search:tavily", wantTools: []string{"web_search"}},
		{name: "room message", capability: "room_message", snapshots: []ExtensionExecutionSnapshot{scheduleSyntheticSnapshot("message-mcp", "mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_send")}, want: coretask.ScheduledCapabilityRoomMessage, wantSource: "message-mcp", wantTools: []string{"mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_send"}},
		{name: "contact report", capability: "contact_report", snapshots: []ExtensionExecutionSnapshot{scheduleSyntheticSnapshot("message-mcp", "mcp__message__dirextalk_contacts_list", "mcp__message__dirextalk_contacts_search")}, want: coretask.ScheduledCapabilityContactReport, wantSource: "message-mcp", wantTools: []string{"mcp__message__dirextalk_contacts_list", "mcp__message__dirextalk_contacts_search"}},
		{name: "room member report", capability: "room_member_report", snapshots: []ExtensionExecutionSnapshot{scheduleSyntheticSnapshot("message-mcp", "mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_room_members_list")}, want: coretask.ScheduledCapabilityRoomMemberReport, wantSource: "message-mcp", wantTools: []string{"mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_room_members_list"}},
		{name: "channel digest", capability: "channel_digest", snapshots: []ExtensionExecutionSnapshot{scheduleSyntheticSnapshot("message-mcp", "mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_channel_posts_list", "mcp__message__dirextalk_channel_comments_list")}, want: coretask.ScheduledCapabilityChannelDigest, wantSource: "message-mcp", wantTools: []string{"mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_channel_posts_list", "mcp__message__dirextalk_channel_comments_list"}},
		{name: "chat summary delivery", capability: "chat_summary_delivery", snapshots: []ExtensionExecutionSnapshot{scheduleSyntheticSnapshot("message-mcp", "mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_list", "mcp__message__dirextalk_messages_send")}, want: coretask.ScheduledCapabilityChatSummaryDelivery, wantSource: "message-mcp", wantTools: []string{"mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_list", "mcp__message__dirextalk_messages_send"}},
	}
	webDigestSnapshots := []ExtensionExecutionSnapshot{
		scheduleSyntheticSnapshot("message-mcp", "mcp__message__dirextalk_contacts_list", "mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_send"),
		scheduleSyntheticSnapshot("builtin:web_search:tavily", "web_search"),
	}
	t.Run("web digest delivery", func(t *testing.T) {
		candidate := scheduleIntrinsicLease()
		candidate.Turn.ExtensionSnapshots = webDigestSnapshots
		store := &conversationScheduleStoreStub{}
		err := executeScheduleForTest(t, store, candidate, uuid.NewString(), map[string]any{
			"name": "web digest delivery", "goal": "research and send a Matrix message to the room", "capability": "web_digest_delivery", "run_at": "2026-08-09T00:00:00Z",
		})
		if err != nil || len(store.commands) != 1 {
			t.Fatalf("commands=%+v err=%v", store.commands, err)
		}
		origin := store.commands[0].Schedule.Spec.Payload.Agent.ScheduledConversation
		if origin.Capability != coretask.ScheduledCapabilityWebDigestDelivery || len(origin.ExtensionSnapshots) != 2 ||
			origin.ExtensionSnapshots[0].Source != "builtin:web_search:tavily" || !reflect.DeepEqual(origin.ExtensionSnapshots[0].ToolNames, []string{"web_search"}) ||
			origin.ExtensionSnapshots[1].Source != "message-mcp" || !reflect.DeepEqual(origin.ExtensionSnapshots[1].ToolNames, []string{"mcp__message__dirextalk_messages_send", "mcp__message__dirextalk_rooms_search"}) {
			t.Fatalf("multi-source origin=%+v", origin)
		}
	})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := scheduleIntrinsicLease()
			candidate.Turn.ExtensionSnapshots = test.snapshots
			store := &conversationScheduleStoreStub{}
			err := executeScheduleForTest(t, store, candidate, uuid.NewString(), map[string]any{
				"name": test.name, "goal": "perform workflow", "capability": test.capability, "run_at": "2026-08-09T00:00:00Z",
			})
			if err != nil || len(store.commands) != 1 {
				t.Fatalf("commands=%+v err=%v", store.commands, err)
			}
			origin := store.commands[0].Schedule.Spec.Payload.Agent.ScheduledConversation
			if origin.Capability != test.want || origin.Timezone != "UTC" || origin.ExtensionSnapshots == nil {
				t.Fatalf("origin=%+v", origin)
			}
			if test.wantSource == "" {
				if len(origin.ExtensionSnapshots) != 0 {
					t.Fatalf("zero-tool origin=%+v", origin)
				}
				return
			}
			wantTools := append([]string(nil), test.wantTools...)
			sort.Strings(wantTools)
			if len(origin.ExtensionSnapshots) != 1 || origin.ExtensionSnapshots[0].Source != test.wantSource || !reflect.DeepEqual(origin.ExtensionSnapshots[0].ToolNames, wantTools) || !reflect.DeepEqual(origin.ExtensionSnapshots[0].Selection.AllowedTools, wantTools) {
				t.Fatalf("origin=%+v", origin)
			}
		})
	}

	rejections := []struct {
		name       string
		capability string
		snapshots  []ExtensionExecutionSnapshot
	}{
		{name: "unknown capability", capability: "installed_workflow", snapshots: []ExtensionExecutionSnapshot{scheduleChatSummarySnapshot()}},
		{name: "chat summary missing exact search", capability: "chat_summary", snapshots: []ExtensionExecutionSnapshot{scheduleSyntheticSnapshot("message-mcp", "mcp__message__dirextalk_messages_list")}},
		{name: "web research wrong source", capability: "web_research", snapshots: []ExtensionExecutionSnapshot{scheduleSyntheticSnapshot("message-mcp", "mcp__message__web_search")}},
		{name: "room message missing send", capability: "room_message", snapshots: []ExtensionExecutionSnapshot{scheduleSyntheticSnapshot("message-mcp", "mcp__message__dirextalk_rooms_search")}},
		{name: "contact report missing search", capability: "contact_report", snapshots: []ExtensionExecutionSnapshot{scheduleSyntheticSnapshot("message-mcp", "mcp__message__dirextalk_contacts_list")}},
		{name: "room member report missing members", capability: "room_member_report", snapshots: []ExtensionExecutionSnapshot{scheduleSyntheticSnapshot("message-mcp", "mcp__message__dirextalk_rooms_search")}},
		{name: "channel digest missing comments", capability: "channel_digest", snapshots: []ExtensionExecutionSnapshot{scheduleSyntheticSnapshot("message-mcp", "mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_channel_posts_list")}},
		{name: "chat summary delivery missing send", capability: "chat_summary_delivery", snapshots: []ExtensionExecutionSnapshot{scheduleSyntheticSnapshot("message-mcp", "mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_list")}},
		{name: "web digest delivery missing web source", capability: "web_digest_delivery", snapshots: []ExtensionExecutionSnapshot{scheduleSyntheticSnapshot("message-mcp", "mcp__message__dirextalk_rooms_search", "mcp__message__dirextalk_messages_send")}},
		{name: "web digest delivery missing message source", capability: "web_digest_delivery", snapshots: []ExtensionExecutionSnapshot{scheduleSyntheticSnapshot("builtin:web_search:tavily", "web_search")}},
	}
	for _, test := range rejections {
		t.Run(test.name, func(t *testing.T) {
			candidate := scheduleIntrinsicLease()
			candidate.Turn.ExtensionSnapshots = test.snapshots
			store := &conversationScheduleStoreStub{}
			err := executeScheduleForTest(t, store, candidate, uuid.NewString(), map[string]any{
				"name": test.name, "goal": "perform workflow", "capability": test.capability, "run_at": "2026-08-09T00:00:00Z",
			})
			var correction IntrinsicCorrectionError
			if !errors.Is(err, ErrInvalid) || !errors.As(err, &correction) || strings.TrimSpace(correction.IntrinsicCorrection()) == "" || len(store.commands) != 0 {
				t.Fatalf("commands=%+v err=%v correction=%q", store.commands, err, func() string {
					if correction == nil {
						return ""
					}
					return correction.IntrinsicCorrection()
				}())
			}
		})
	}
}

func executeScheduleForTest(t *testing.T, store *conversationScheduleStoreStub, lease TurnLease, callID string, arguments map[string]any) error {
	t.Helper()
	conversationRevision := uint64(1)
	if lease.Turn.ExpectedRevision != nil {
		conversationRevision = *lease.Turn.ExpectedRevision
	}
	return executeScheduleForTestAtRevision(t, store, lease, callID, arguments, conversationRevision)
}

func executeScheduleForTestAtRevision(t *testing.T, store *conversationScheduleStoreStub, lease TurnLease, callID string, arguments map[string]any, conversationRevision uint64) error {
	t.Helper()
	raw, err := json.Marshal(arguments)
	if err != nil {
		t.Fatal(err)
	}
	intrinsic := scheduleIntrinsic(store, lease)
	result, err := intrinsic.Execute(context.Background(), IntrinsicExecutionRequest{
		Lease:                lease,
		Call:                 ToolCall{ID: callID, Name: coremodel.IntrinsicScheduleCreateToolName, Arguments: string(raw)},
		CanonicalArguments:   raw,
		ConversationRevision: conversationRevision,
	})
	if err == nil && !result.TurnCommitted {
		t.Fatal("schedule intrinsic returned success without committing the turn")
	}
	return err
}

func TestScheduleIntrinsicUsesLoadedRevisionWhenClientCASIsOmitted(t *testing.T) {
	lease := scheduleIntrinsicLease()
	lease.Turn.ExpectedRevision = nil
	store := &conversationScheduleStoreStub{}
	arguments := map[string]any{
		"name": "existing conversation", "goal": "send reminder", "capability": "chat_summary", "run_at": "2026-08-09T02:03:04Z",
	}
	if err := executeScheduleForTestAtRevision(t, store, lease, "call-existing", arguments, 5); err != nil {
		t.Fatalf("execute schedule intrinsic: %v", err)
	}
	if len(store.commands) != 1 || store.commands[0].Response.Revision != 6 {
		t.Fatalf("response=%+v", store.commands)
	}
	if err := executeScheduleForTestAtRevision(t, store, lease, "call-invalid", arguments, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero conversation revision err=%v", err)
	}
}

func TestScheduleIntrinsicUsesRenewedTurnLease(t *testing.T) {
	bound := scheduleIntrinsicLease()
	renewed := bound
	renewed.Epoch++
	renewed.ExpiresAt = renewed.ExpiresAt.Add(time.Minute)
	store := &conversationScheduleStoreStub{}
	raw := json.RawMessage(`{"name":"每日纳斯达克行情总结","goal":"生成并发布每日行情页面","capability":"chat_summary","cron":"30 21 * * *","timezone":"Asia/Shanghai","timeout_seconds":600}`)
	result, err := scheduleIntrinsic(store, bound).Execute(context.Background(), IntrinsicExecutionRequest{
		Lease: renewed,
		Call: ToolCall{
			ID: uuid.NewString(), Name: coremodel.IntrinsicScheduleCreateToolName, Arguments: string(raw),
		},
		CanonicalArguments: raw, ConversationRevision: 5,
	})
	if err != nil || !result.TurnCommitted {
		t.Fatalf("renewed lease rejected: result=%+v err=%v", result, err)
	}
	if len(store.commands) != 1 || store.commands[0].Lease.Epoch != renewed.Epoch {
		t.Fatalf("schedule committed under stale lease: commands=%+v", store.commands)
	}
}

func TestExecuteTurnPassesLoadedConversationRevisionToScheduleIntrinsic(t *testing.T) {
	profile := testTurnSnapshot()
	conversationID := uuid.NewString()
	base := newFakeStore()
	base.conv[conversationID] = Conversation{
		ID: conversationID, Revision: 5,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	turn := Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(),
		OwnerID: "@owner:example.test", AccountGeneration: 9,
		ConversationID: conversationID, Prompt: "schedule this", ProfileID: profile.ProfileID,
		ProfileSnapshot: profile, ProfileSnapshotDigest: profile.Digest(),
		State: TurnAccepted, Revision: 1, LastSequence: 1, CreatedAt: time.Now().UTC(),
		ExtensionSnapshots: []ExtensionExecutionSnapshot{scheduleChatSummarySnapshot()},
	}
	turnStore := &readOnlyTurnStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: turn},
		events:                []TurnEvent{{TurnID: turn.ID, Sequence: 1, Kind: TurnEventAccepted, CreatedAt: turn.CreatedAt}},
	}
	scheduleStore := &conversationScheduleStoreStub{}
	store := &executingScheduleTurnStore{readOnlyTurnStore: turnStore, conversationScheduleStoreStub: scheduleStore}
	call := ToolCall{
		ID: uuid.NewString(), Name: coremodel.IntrinsicScheduleCreateToolName,
		Arguments: `{"name":"existing conversation","goal":"send reminder","capability":"chat_summary","run_at":"2026-08-09T02:03:04Z"}`,
	}
	model := &twoRoundReadOnlyModel{call: call}
	service, err := NewService(store, model, scheduleExtensionResolver(turn.ExtensionSnapshots[0]), snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) {
		return profile, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	bindCurrentTestTurnRuntime(t, service, turnStore)
	service.executeTurn(context.Background(), turn.ID)
	if len(scheduleStore.commands) != 1 || scheduleStore.commands[0].Response.Revision != 6 || turnStore.failedCode != "" {
		t.Fatalf("commands=%+v failed=%q", scheduleStore.commands, turnStore.failedCode)
	}
}

func TestExecuteTurnReturnsInvalidScheduleArgumentsToModel(t *testing.T) {
	profile := testTurnSnapshot()
	conversationID := uuid.NewString()
	base := newFakeStore()
	base.conv[conversationID] = Conversation{ID: conversationID, Revision: 5, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	turn := Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), OwnerID: "@owner:example.test", AccountGeneration: 9,
		ConversationID: conversationID, Prompt: "schedule this", ProfileID: profile.ProfileID,
		ProfileSnapshot: profile, ProfileSnapshotDigest: profile.Digest(), State: TurnAccepted, Revision: 1,
		LastSequence: 1, CreatedAt: time.Now().UTC(), ExtensionSnapshots: []ExtensionExecutionSnapshot{scheduleChatSummarySnapshot()},
	}
	turnStore := &readOnlyTurnStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: turn},
		events:                []TurnEvent{{TurnID: turn.ID, Sequence: 1, Kind: TurnEventAccepted, CreatedAt: turn.CreatedAt}},
	}
	scheduleStore := &conversationScheduleStoreStub{}
	store := &executingScheduleTurnStore{readOnlyTurnStore: turnStore, conversationScheduleStoreStub: scheduleStore}
	model := &correctingScheduleModel{calls: []ToolCall{
		{ID: uuid.NewString(), Name: coremodel.IntrinsicScheduleCreateToolName, Arguments: `{"name":"daily","goal":"publish summary","capability":"chat_summary","cron":"30 21 * * * *","timezone":"Asia/Shanghai","timeout_seconds":600}`},
		{ID: uuid.NewString(), Name: coremodel.IntrinsicScheduleCreateToolName, Arguments: `{"name":"daily","goal":"publish summary","capability":"chat_summary","cron":"30 21 * * *","timezone":"Asia/Shanghai","timeout_seconds":600}`},
	}}
	service, err := NewService(store, model, scheduleExtensionResolver(turn.ExtensionSnapshots[0]), snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return profile, nil }))
	if err != nil {
		t.Fatal(err)
	}
	bindCurrentTestTurnRuntime(t, service, turnStore)
	service.executeTurn(context.Background(), turn.ID)
	if len(scheduleStore.commands) != 0 || turnStore.turn.State != TurnAccepted || turnStore.failedCode != "" {
		t.Fatalf("invalid arguments terminated turn: commands=%+v turn=%+v failed=%q", scheduleStore.commands, turnStore.turn, turnStore.failedCode)
	}
	service.executeTurn(context.Background(), turn.ID)
	if len(scheduleStore.commands) != 1 || scheduleStore.commands[0].Schedule.Cron != "30 21 * * *" || turnStore.failedCode != "" {
		t.Fatalf("corrected call not committed: commands=%+v failed=%q", scheduleStore.commands, turnStore.failedCode)
	}
	if len(model.requests) != 2 || !conversationContainsToolError(model.requests[1].Conversation, coremodel.IntrinsicScheduleCreateToolName) {
		t.Fatalf("corrected model round did not receive tool error: requests=%+v", model.requests)
	}
}

func TestIntrinsicOrderViolationUsesOneCorrectionThenCommitsScheduleOnce(t *testing.T) {
	profile := testTurnSnapshot()
	conversationID := uuid.NewString()
	base := newFakeStore()
	base.conv[conversationID] = Conversation{ID: conversationID, Revision: 5, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	turn := Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), OwnerID: "@owner:example.test", AccountGeneration: 9,
		ConversationID: conversationID, Prompt: "每天九点总结群聊消息", ProfileID: profile.ProfileID,
		ProfileSnapshot: profile, ProfileSnapshotDigest: profile.Digest(), State: TurnAccepted, Revision: 1,
		LastSequence: 1, CreatedAt: time.Now().UTC(), ExtensionSnapshots: []ExtensionExecutionSnapshot{scheduleChatSummarySnapshot()},
	}
	turnStore := &readOnlyTurnStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: turn},
		events:                []TurnEvent{{TurnID: turn.ID, Sequence: 1, Kind: TurnEventAccepted, CreatedAt: turn.CreatedAt}},
	}
	scheduleStore := &conversationScheduleStoreStub{}
	store := &executingScheduleTurnStore{readOnlyTurnStore: turnStore, conversationScheduleStoreStub: scheduleStore}
	invalidSchedule := ToolCall{ID: uuid.NewString(), Name: coremodel.IntrinsicScheduleCreateToolName, Arguments: `{"name":"每日群聊总结","goal":"总结群聊消息","capability":"chat_summary","cron":"0 9 * * *","timezone":"Asia/Shanghai"}`}
	trailingRead := ToolCall{ID: uuid.NewString(), Name: "mcp__message__dirextalk_rooms_search", Arguments: `{"query":"群聊"}`}
	correctedSchedule := invalidSchedule
	correctedSchedule.ID = uuid.NewString()
	model := &intrinsicOrderCorrectionModel{invalid: []ToolCall{invalidSchedule, trailingRead}, corrected: correctedSchedule}
	service, err := NewService(store, model, scheduleExtensionResolver(turn.ExtensionSnapshots[0]), snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return profile, nil }))
	if err != nil {
		t.Fatal(err)
	}
	bindCurrentTestTurnRuntime(t, service, turnStore)

	service.executeTurn(context.Background(), turn.ID)
	if turnStore.failedCode != "" || len(scheduleStore.commands) != 0 || turnStore.turn.State != TurnAccepted {
		t.Fatalf("invalid batch was not held for correction: failed=%q commands=%d turn=%+v", turnStore.failedCode, len(scheduleStore.commands), turnStore.turn)
	}
	var correction *ToolResult
	for _, event := range turnStore.events {
		if event.ToolResult != nil && event.ToolResult.CallID == invalidSchedule.ID {
			copy := *event.ToolResult
			correction = &copy
		}
	}
	if correction == nil || correction.Outcome != ToolOutcomeInvalid || correction.Retry.ValidationCorrections != 1 ||
		!strings.Contains(correction.Summary, "Core intrinsic tool must be the final call in a model round") {
		t.Fatalf("precise bounded correction missing: %+v events=%+v", correction, turnStore.events)
	}

	service.executeTurn(context.Background(), turn.ID)
	if turnStore.failedCode != "" || len(scheduleStore.commands) != 1 || len(model.requests) != 2 {
		t.Fatalf("corrected schedule did not commit once: failed=%q commands=%+v requests=%d", turnStore.failedCode, scheduleStore.commands, len(model.requests))
	}
	response := scheduleStore.commands[0].Response
	if !response.Done || strings.TrimSpace(response.Message.Content) == "" || strings.Contains(response.Message.Content, "{\"") {
		t.Fatalf("schedule response is not concise Markdown: %+v", response)
	}
}

func TestRepeatedIntrinsicOrderViolationFinalizesUsefulMarkdown(t *testing.T) {
	profile := testTurnSnapshot()
	conversationID := uuid.NewString()
	base := newFakeStore()
	base.conv[conversationID] = Conversation{ID: conversationID, Revision: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	turn := Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), OwnerID: "@owner:example.test", AccountGeneration: 9,
		ConversationID: conversationID, Prompt: "每天九点提醒我", ProfileID: profile.ProfileID,
		ProfileSnapshot: profile, ProfileSnapshotDigest: profile.Digest(), State: TurnAccepted, Revision: 1,
		LastSequence: 1, CreatedAt: time.Now().UTC(), ExtensionSnapshots: []ExtensionExecutionSnapshot{scheduleChatSummarySnapshot()},
	}
	turnStore := &readOnlyTurnStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: turn},
		events:                []TurnEvent{{TurnID: turn.ID, Sequence: 1, Kind: TurnEventAccepted, CreatedAt: turn.CreatedAt}},
	}
	scheduleStore := &conversationScheduleStoreStub{}
	store := &executingScheduleTurnStore{readOnlyTurnStore: turnStore, conversationScheduleStoreStub: scheduleStore}
	scheduleCall := ToolCall{ID: uuid.NewString(), Name: coremodel.IntrinsicScheduleCreateToolName, Arguments: `{"name":"每日提醒","goal":"提醒用户","capability":"chat_summary","cron":"0 9 * * *","timezone":"Asia/Shanghai"}`}
	trailingRead := ToolCall{ID: uuid.NewString(), Name: "mcp__message__dirextalk_rooms_search", Arguments: `{"query":"群聊"}`}
	model := &intrinsicOrderCorrectionModel{invalid: []ToolCall{scheduleCall, trailingRead}, repeat: true}
	service, err := NewService(store, model, scheduleExtensionResolver(turn.ExtensionSnapshots[0]), snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return profile, nil }))
	if err != nil {
		t.Fatal(err)
	}
	bindCurrentTestTurnRuntime(t, service, turnStore)
	for attempt := 0; attempt < 3 && turnStore.turn.State != TurnCompleted; attempt++ {
		service.executeTurn(context.Background(), turn.ID)
	}
	if turnStore.failedCode != "" || turnStore.turn.State != TurnCompleted || turnStore.turn.Response == nil || len(scheduleStore.commands) != 0 {
		t.Fatalf("repeated violation did not finalize safely: failed=%q turn=%+v commands=%+v", turnStore.failedCode, turnStore.turn, scheduleStore.commands)
	}
	content := turnStore.turn.Response.Message.Content
	if !strings.HasPrefix(content, "## Schedule not created") || strings.Contains(content, "Error (") || strings.Contains(content, `{"`) {
		t.Fatalf("unsafe terminal output=%q", content)
	}
	if turnStore.finalization == nil || turnStore.finalization.Reason != TurnFinalizationToolOutcome {
		t.Fatalf("finalization=%+v", turnStore.finalization)
	}
}

func conversationContainsToolError(conversation Conversation, toolName string) bool {
	for _, message := range conversation.Messages {
		for _, result := range message.ToolResults {
			if result.ToolName == toolName && result.IsError && strings.Contains(result.Content, "correct") {
				return true
			}
		}
	}
	return false
}

func TestScheduleIntrinsicInjectsTurnAuthorityAndUsesDeterministicIdentity(t *testing.T) {
	lease := scheduleIntrinsicLease()
	store := &conversationScheduleStoreStub{}
	arguments := map[string]any{
		"name": "daily summary", "goal": "summarize the conversation", "capability": "chat_summary", "cron": "0 9 * * *", "timezone": "Asia/Shanghai", "timeout_seconds": 120,
	}
	if err := executeScheduleForTest(t, store, lease, "call-1", arguments); err != nil {
		t.Fatalf("execute schedule intrinsic: %v", err)
	}
	if err := executeScheduleForTest(t, store, lease, "call-1", arguments); err != nil {
		t.Fatalf("replay schedule intrinsic: %v", err)
	}
	if len(store.commands) != 2 {
		t.Fatalf("commands=%d", len(store.commands))
	}
	first, second := store.commands[0], store.commands[1]
	if first.Schedule.ID != second.Schedule.ID || first.Mutation.IdempotencyKey != second.Mutation.IdempotencyKey || first.Mutation.RequestDigest != second.Mutation.RequestDigest {
		t.Fatalf("intrinsic identity was not deterministic: first=%+v second=%+v", first.Mutation, second.Mutation)
	}
	template := first.Schedule.Spec
	if template.Kind != coretask.TaskKindAgent || template.ConversationID != lease.Turn.ConversationID || template.ModelProfileID != "" ||
		template.Goal != "summarize the conversation" || template.TimeoutSeconds != 120 || len(template.AttachmentRefs) != 0 || len(template.Extensions) != 0 || len(template.KnowledgeRefs) != 0 ||
		template.Payload.Agent == nil || template.Payload.Agent.OwnerID != lease.Turn.OwnerID || template.Payload.Agent.AccountGeneration != lease.Turn.AccountGeneration || template.Payload.Agent.ScheduledConversation == nil {
		t.Fatalf("untrusted schedule template: %+v", template)
	}
	if first.Lease.Turn.OwnerID != lease.Turn.OwnerID || first.Lease.Turn.AccountGeneration != lease.Turn.AccountGeneration || first.Response.Revision != 5 || first.Response.ConversationID != lease.Turn.ConversationID || first.Response.ModelProfileID != lease.Turn.ProfileID {
		t.Fatalf("turn authority was not injected: %+v", first)
	}
}

func TestScheduleIntrinsicPersistsOnlyCapabilityTools(t *testing.T) {
	lease := scheduleIntrinsicLease()
	installedID, installedVersionID := uuid.NewString(), uuid.NewString()
	messageID, webID := uuid.NewString(), uuid.NewString()
	digestA, digestB, digestC := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	lease.Turn.ExtensionSnapshots = []ExtensionExecutionSnapshot{
		{
			Selection: ExtensionSelection{Kind: ExtensionMCP, ID: messageID, Version: "1.0.0", Digest: digestA, AllowedTools: []string{
				"mcp__message__dirextalk_contacts_list", "mcp__message__dirextalk_messages_list", "mcp__message__dirextalk_messages_send", "mcp__message__dirextalk_rooms_search",
			}},
			InstallationID: messageID, VersionID: "1.0.0",
			Source: "message-mcp", ContentDigest: digestA, ArtifactDigest: digestB, ToolSchemaDigest: digestC,
			ToolNames: []string{
				"mcp__message__dirextalk_contacts_list", "mcp__message__dirextalk_messages_list", "mcp__message__dirextalk_messages_send", "mcp__message__dirextalk_rooms_search",
			}, ReadOnly: true,
		},
		{
			Selection:      ExtensionSelection{Kind: ExtensionMCP, ID: webID, Version: "config-2", Digest: digestB, AllowedTools: []string{"web_search"}},
			InstallationID: webID, VersionID: "config-2",
			Source: "builtin:web_search:tavily", ContentDigest: digestB, ArtifactDigest: digestC, ToolSchemaDigest: digestA,
			ToolNames: []string{"web_search"}, ReadOnly: true,
		},
		{
			Selection:      ExtensionSelection{Kind: ExtensionSkill, ID: installedID, Version: "1.2.3", Digest: digestC},
			InstallationID: installedID, VersionID: installedVersionID, InstallationRevision: 4, Source: "registry",
			ContentDigest: digestC, ArtifactDigest: digestA, SkillInstructions: "Use the installed workflow.",
		},
		{
			Selection: ExtensionSelection{Kind: ExtensionMCP, ID: uuid.NewString(), Version: "1.0.0", Digest: digestA, AllowedTools: []string{"product_rooms_list"}},
			Source:    "product-capability", ContentDigest: digestA, ArtifactDigest: digestB, ToolNames: []string{"product_rooms_list"}, ReadOnly: true,
		},
		{
			Selection: ExtensionSelection{Kind: ExtensionKnowledge, ID: uuid.NewString(), Version: "1.0.0", Digest: digestA, AllowedTools: []string{"knowledge_search"}},
			Source:    "builtin:knowledge:semantic", ContentDigest: digestA, ArtifactDigest: digestB, ToolNames: []string{"knowledge_search"}, ReadOnly: true,
		},
	}
	store := &conversationScheduleStoreStub{}
	if err := executeScheduleForTest(t, store, lease, uuid.NewString(), map[string]any{
		"name": "daily", "goal": "summarize messages", "capability": "chat_summary", "cron": "0 9 * * *", "timezone": "Asia/Shanghai",
	}); err != nil {
		t.Fatalf("execute schedule intrinsic: %v", err)
	}
	origin := store.commands[0].Schedule.Spec.Payload.Agent.ScheduledConversation
	if origin == nil || origin.Capability != coretask.ScheduledCapabilityChatSummary || len(origin.ExtensionSnapshots) != 1 {
		t.Fatalf("scheduled origin=%+v", origin)
	}
	snapshot := origin.ExtensionSnapshots[0]
	wantTools := []string{"mcp__message__dirextalk_messages_list", "mcp__message__dirextalk_rooms_search"}
	if snapshot.Source != "message-mcp" || !reflect.DeepEqual(snapshot.ToolNames, wantTools) || !reflect.DeepEqual(snapshot.Selection.AllowedTools, wantTools) || snapshot.SkillInstructions != "" {
		t.Fatalf("scheduled capability snapshot=%+v", snapshot)
	}
}

func TestServiceComposesScheduleWithConfiguredCoreIntrinsics(t *testing.T) {
	lease := scheduleIntrinsicLease()
	store := &scheduleCapableTurnStore{replayTurnStore: &replayTurnStore{}, conversationScheduleStoreStub: &conversationScheduleStoreStub{}}
	service := &Service{turns: store}
	service.SetIntrinsicResolver(intrinsicResolverFunc(func(context.Context, TurnLease) ([]ResolvedIntrinsic, error) {
		return []ResolvedIntrinsic{{Tool: coremodel.Tool{Name: coremodel.IntrinsicCloudWorkerProposeToolName, InputSchema: map[string]any{"type": "object"}}, Execute: func(context.Context, IntrinsicExecutionRequest) (IntrinsicExecutionResult, error) {
			return IntrinsicExecutionResult{TurnCommitted: true}, nil
		}}}, nil
	}))
	tools, err := service.resolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(tools) != 2 || tools[0].Tool.Name != coremodel.IntrinsicScheduleCreateToolName || tools[1].Tool.Name != coremodel.IntrinsicCloudWorkerProposeToolName {
		t.Fatalf("tools=%+v err=%v", tools, err)
	}
}

func TestScheduleIntrinsicAcceptsOneTimeTriggerAndRejectsForgedOrAmbiguousInput(t *testing.T) {
	lease := scheduleIntrinsicLease()
	store := &conversationScheduleStoreStub{}
	if err := executeScheduleForTest(t, store, lease, "call-once", map[string]any{
		"name": "once", "goal": "send reminder", "capability": "chat_summary", "run_at": "2026-08-09T02:03:04+08:00",
	}); err != nil {
		t.Fatalf("one-time schedule: %v", err)
	}
	if got := store.commands[0].Schedule.RunAt; got == nil || !got.Equal(time.Date(2026, 8, 8, 18, 3, 4, 0, time.UTC)) {
		t.Fatalf("run_at=%v", got)
	}
	oneTimeOrigin := store.commands[0].Schedule.Spec.Payload.Agent.ScheduledConversation
	if store.commands[0].Schedule.Timezone != "UTC" || oneTimeOrigin.Timezone != "UTC" {
		t.Fatalf("one-time timezone schedule=%q origin=%q", store.commands[0].Schedule.Timezone, oneTimeOrigin.Timezone)
	}
	cronStore := &conversationScheduleStoreStub{}
	if err := executeScheduleForTest(t, cronStore, lease, "call-cron", map[string]any{
		"name": "daily", "goal": "summary", "capability": "chat_summary", "cron": "0 9 * * *", "timezone": "Asia/Shanghai",
	}); err != nil {
		t.Fatalf("cron schedule: %v", err)
	}
	cronOrigin := cronStore.commands[0].Schedule.Spec.Payload.Agent.ScheduledConversation
	if cronStore.commands[0].Schedule.Timezone != "Asia/Shanghai" || cronOrigin.Timezone != "Asia/Shanghai" {
		t.Fatalf("cron timezone schedule=%q origin=%q", cronStore.commands[0].Schedule.Timezone, cronOrigin.Timezone)
	}
	cases := []map[string]any{
		{"name": "forged", "goal": "x", "capability": "chat_summary", "run_at": "2026-08-09T00:00:00Z", "owner_id": "attacker"},
		{"name": "ambiguous", "goal": "x", "capability": "chat_summary", "run_at": "2026-08-09T00:00:00Z", "cron": "0 9 * * *", "timezone": "UTC"},
		{"name": "missing zone", "goal": "x", "capability": "chat_summary", "cron": "0 9 * * *"},
		{"name": "bad zone", "goal": "x", "capability": "chat_summary", "cron": "0 9 * * *", "timezone": "Mars/Olympus"},
		{"name": "refs", "goal": "x", "capability": "chat_summary", "run_at": "2026-08-09T00:00:00Z", "attachment_refs": []string{uuid.NewString()}},
	}
	for index, arguments := range cases {
		if err := executeScheduleForTest(t, store, lease, "bad-"+string(rune('a'+index)), arguments); !errors.Is(err, ErrInvalid) {
			t.Fatalf("case %d err=%v", index, err)
		}
	}
}

func TestScheduleIntrinsicStoreFailureDoesNotReportCommittedTurn(t *testing.T) {
	lease := scheduleIntrinsicLease()
	store := &conversationScheduleStoreStub{err: errors.New("persistence unavailable")}
	if err := executeScheduleForTest(t, store, lease, "call-1", map[string]any{
		"name": "once", "goal": "send reminder", "capability": "chat_summary", "run_at": "2026-08-09T00:00:00Z",
	}); err == nil {
		t.Fatal("store failure was ignored")
	}
}

func TestIntrinsicFailureClassificationIsSpecificAndRedacted(t *testing.T) {
	lease := scheduleIntrinsicLease()
	invalidErr := executeScheduleForTest(t, &conversationScheduleStoreStub{}, lease, "call-invalid", map[string]any{
		"name": "invalid", "goal": "send reminder", "capability": "chat_summary", "cron": "not a cron", "timezone": "UTC",
	})
	summary := intrinsicTerminalFailure(coremodel.IntrinsicScheduleCreateToolName, invalidErr)
	if summary != "Core intrinsic arguments are invalid" {
		t.Fatalf("invalid classification summary=%q err=%v", summary, invalidErr)
	}
	summary = intrinsicTerminalFailure(coremodel.IntrinsicCloudWorkerProposeToolName, ErrInvalid)
	if summary != "Core intrinsic arguments are invalid" {
		t.Fatalf("invalid Worker arguments classification summary=%q", summary)
	}
	summary = intrinsicTerminalFailure(coremodel.IntrinsicCloudWorkerProposeToolName, errors.New("private AWS provider detail"))
	if summary != "AWS Worker proposal could not be created" || strings.Contains(summary, "private") {
		t.Fatalf("Worker proposal classification summary=%q", summary)
	}

	privateErr := errors.New("database unavailable: private connection detail")
	persistenceErr := executeScheduleForTest(t, &conversationScheduleStoreStub{err: privateErr}, lease, "call-persistence", map[string]any{
		"name": "once", "goal": "send reminder", "capability": "chat_summary", "run_at": "2026-08-09T00:00:00Z",
	})
	summary = intrinsicTerminalFailure(coremodel.IntrinsicScheduleCreateToolName, persistenceErr)
	if summary != "Schedule could not be saved" || strings.Contains(summary, "private") {
		t.Fatalf("persistence classification summary=%q err=%v", summary, persistenceErr)
	}
}
