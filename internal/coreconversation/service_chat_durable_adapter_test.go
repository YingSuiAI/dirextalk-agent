package coreconversation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type durableAdapterProfile struct{}

func (durableAdapterProfile) ResolveProfileSnapshot(_ context.Context, id string) (coremodel.ExecutionSnapshot, error) {
	return coremodel.ExecutionSnapshot{
		ProfileID: id, Revision: 1, CredentialVersion: 1,
		Provider: coremodel.ProviderOpenAICompatible, RequestDialect: coremodel.DialectOpenAICompatibleChatV1,
		BaseURL: "https://example.invalid/v1", Model: "test", APIKey: "test-key",
	}, nil
}

type terminalChatAdapterStore struct {
	*publicActiveTurnStore
	state      TurnState
	code       string
	summary    string
	content    string
	startCalls int
}

func (s *terminalChatAdapterStore) GetTurnByRequestID(_ context.Context, requestID string) (Turn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.turn.RequestID == requestID {
		return s.turn, nil
	}
	return Turn{}, ErrConflict
}

func (s *terminalChatAdapterStore) StartTurnWithRuntime(_ context.Context, command TurnStartCommand, runtime TurnRuntimeSnapshot) (Turn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.startCalls++
	turn := Turn{
		ID: command.TurnID, RequestID: command.RequestID, ConversationID: command.ConversationID,
		Prompt: command.Prompt, ProfileID: command.ProfileID, ProfileSnapshot: command.ProfileSnapshot,
		ProfileSnapshotDigest: command.ProfileSnapshot.Digest(), Revision: 2, State: s.state,
		TerminalCode: s.code, TerminalSummary: s.summary, LastSequence: 2,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), RuntimeSnapshot: &runtime,
	}
	turn.RequestFingerprint = command.Fingerprint()
	if s.state == TurnCompleted {
		response := ChatResponse{
			RequestID: command.RequestID, ConversationID: command.ConversationID, Revision: 1, Done: true,
			ModelProfileID: command.ProfileID,
			Message:        Message{ID: uuid.NewString(), Role: RoleAssistant, Content: s.content, ModelProfileID: command.ProfileID, CreatedAt: time.Now().UTC()},
		}
		turn.Response = &response
	}
	s.turn = turn
	return turn, nil
}

func TestChatAndStartTurnContractsHaveNoReasoningField(t *testing.T) {
	store := &terminalChatAdapterStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: newFakeStore()},
		state:                 TurnCompleted, content: "public answer",
	}
	service, err := NewService(store, &fakeModel{}, noopExtensions{}, durableAdapterProfile{})
	if err != nil {
		t.Fatal(err)
	}
	chatCommand := command()
	turn, err := service.StartTurn(context.Background(), turnCommandFromChat(chatCommand))
	if err != nil {
		t.Fatal(err)
	}
	if turn.Response == nil || turn.Response.Message.Content != store.content {
		t.Fatalf("public StartTurn response=%+v", turn.Response)
	}
	response, err := service.Chat(context.Background(), chatCommand)
	if err != nil {
		t.Fatal(err)
	}
	if response.Message.Content != store.content {
		t.Fatalf("public Chat response=%+v", response)
	}
}

func TestStreamChatAndWatchTurnEventsContractsHaveNoReasoningField(t *testing.T) {
	profileID := uuid.NewString()
	response := ChatResponse{
		RequestID: uuid.NewString(), ConversationID: uuid.NewString(), Revision: 1, Done: true, ModelProfileID: profileID,
		Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "public answer", ModelProfileID: profileID, CreatedAt: time.Now().UTC()},
	}
	store := &streamingChatAdapterStore{
		terminalChatAdapterStore: &terminalChatAdapterStore{
			publicActiveTurnStore: &publicActiveTurnStore{fakeStore: newFakeStore()},
			state:                 TurnCompleted, content: response.Message.Content,
		},
		events: []TurnEvent{
			{Kind: TurnEventAccepted},
			{Kind: TurnEventDelta, Text: "public "},
		},
	}
	chatCommand := ChatCommand{RequestID: response.RequestID, Prompt: "answer", ProfileID: profileID, ExpectedProfileRevision: 1, ExpectedCredentialVersion: 1}
	response.ConversationID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation:"+chatCommand.RequestID)).String()
	store.events = append(store.events, TurnEvent{Kind: TurnEventDone, Response: &response})
	service, err := NewService(store, &fakeModel{}, noopExtensions{}, durableAdapterProfile{})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := service.StreamChat(context.Background(), chatCommand)
	if err != nil {
		t.Fatal(err)
	}
	var streamed []StreamEvent
	for event := range stream {
		streamed = append(streamed, event)
	}
	if len(streamed) != len(store.events) {
		t.Fatalf("streamed events=%+v", streamed)
	}
	turnID := store.turn.ID
	watched, err := service.WatchTurnEvents(context.Background(), turnID, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for range watched {
	}
}

type streamingChatAdapterStore struct {
	*terminalChatAdapterStore
	events      []TurnEvent
	cancelCalls int
}

func (s *streamingChatAdapterStore) StartTurnWithRuntime(ctx context.Context, command TurnStartCommand, runtime TurnRuntimeSnapshot) (Turn, error) {
	terminal, err := s.terminalChatAdapterStore.StartTurnWithRuntime(ctx, command, runtime)
	if err != nil {
		return Turn{}, err
	}
	for index := range s.events {
		s.events[index].TurnID = terminal.ID
		s.events[index].Sequence = int64(index + 1)
		if s.events[index].Revision == 0 {
			s.events[index].Revision = uint64(index + 1)
		}
	}
	if len(s.events) > 0 {
		s.mu.Lock()
		s.turn.LastSequence = int64(len(s.events))
		s.mu.Unlock()
	}
	accepted := terminal
	accepted.State, accepted.Response = TurnWaitingConfirmation, nil
	return accepted, nil
}

func (s *streamingChatAdapterStore) LoadTurnEvents(_ context.Context, _ string, after int64, limit int) ([]TurnEvent, error) {
	if after >= int64(len(s.events)) {
		return nil, nil
	}
	end := len(s.events)
	if limit > 0 && int(after)+limit < end {
		end = int(after) + limit
	}
	return append([]TurnEvent(nil), s.events[after:end]...), nil
}

func (s *streamingChatAdapterStore) TurnEventBounds(context.Context, string) (int64, int64, error) {
	if len(s.events) == 0 {
		return 0, 0, nil
	}
	return 1, int64(len(s.events)), nil
}

func (s *streamingChatAdapterStore) RequestTurnCancel(ctx context.Context, command TurnCancelCommand) (Turn, error) {
	s.cancelCalls++
	return s.terminalChatAdapterStore.RequestTurnCancel(ctx, command)
}

func TestChatUsesAuthoritativeDurableTurnTerminalResponse(t *testing.T) {
	store := &terminalChatAdapterStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: newFakeStore()},
		state:                 TurnCompleted, content: "durable response",
	}
	model := &fakeModel{}
	service, err := NewService(store, model, noopExtensions{}, durableAdapterProfile{})
	if err != nil {
		t.Fatal(err)
	}
	response, err := service.Chat(context.Background(), command())
	if err != nil || response.Message.Content != "durable response" || store.startCalls != 1 || model.runs != 0 {
		t.Fatalf("response=%+v err=%v durableStarts=%d legacyModelRuns=%d", response, err, store.startCalls, model.runs)
	}
}

func TestStreamChatProjectsCompletedFinalizationAsDoneMarkdown(t *testing.T) {
	const markdown = "## Completed work\n\n- Preserved durable output.\n\n## Best conclusion\n\n- Best available answer.\n\n## Incomplete items\n\n- Full synthesis unavailable.\n\n## Stop reason\n\n- `provider_timeout`: provider stopped"
	store := &terminalChatAdapterStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: newFakeStore()},
		state:                 TurnCompleted,
		code:                  modelResponseTimeoutCode,
		summary:               modelResponseTimeoutSummary,
		content:               markdown,
	}
	service, err := NewService(store, &fakeModel{}, noopExtensions{}, durableAdapterProfile{})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := service.StreamChat(context.Background(), command())
	if err != nil {
		t.Fatal(err)
	}
	var terminal StreamEvent
	for event := range stream {
		terminal = event
	}
	if terminal.Kind != EventDone || terminal.Response == nil || terminal.Response.Message.Content != markdown || terminal.ErrCode != "" || terminal.ErrSummary != "" {
		t.Fatalf("terminal=%+v", terminal)
	}
}

func TestChatSharesDurableTurnBudgetFailure(t *testing.T) {
	store := &terminalChatAdapterStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: newFakeStore()},
		state:                 TurnFailed, code: modelBudgetExhaustedCode, summary: modelBudgetExhaustedSummary,
	}
	model := &fakeModel{}
	service, err := NewService(store, model, noopExtensions{}, durableAdapterProfile{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Chat(context.Background(), command()); !errors.Is(err, ErrChatFailed) || store.startCalls != 1 || model.runs != 0 {
		t.Fatalf("err=%v durableStarts=%d legacyModelRuns=%d", err, store.startCalls, model.runs)
	}
}

func TestStreamChatSharesDurableTurnCancellation(t *testing.T) {
	store := &terminalChatAdapterStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: newFakeStore()},
		state:                 TurnCanceled, code: "canceled", summary: "turn canceled",
	}
	model := &fakeModel{}
	service, err := NewService(store, model, noopExtensions{}, durableAdapterProfile{})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := service.StreamChat(context.Background(), command())
	if err != nil {
		t.Fatal(err)
	}
	var terminal StreamEvent
	for event := range stream {
		terminal = event
	}
	if terminal.Kind != EventError || terminal.ErrCode != "canceled" || store.startCalls != 1 || model.runs != 0 {
		t.Fatalf("terminal=%+v durableStarts=%d legacyModelRuns=%d", terminal, store.startCalls, model.runs)
	}
}

func TestStreamChatRejectsInvalidDurableDonePayload(t *testing.T) {
	turn := Turn{ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: uuid.NewString(), ProfileID: uuid.NewString()}
	event := streamEventFromTurnEvent(turn, TurnEvent{Kind: TurnEventDone, Sequence: 2, Revision: 2})
	if event == nil || event.Kind != EventError || event.ErrCode != "terminal_response_invalid" || event.Response != nil {
		t.Fatalf("event=%+v", event)
	}
}

func TestStreamChatProjectsDurableTurnEventsInLedgerOrder(t *testing.T) {
	profileID := uuid.NewString()
	call := ToolCall{ID: uuid.NewString(), Name: "search", Arguments: `{}`}
	result := ToolResult{CallID: call.ID, ToolName: call.Name, Content: "found"}
	response := ChatResponse{
		RequestID: uuid.NewString(), ConversationID: uuid.NewString(), Revision: 1, Done: true, ModelProfileID: profileID,
		Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "summary", ModelProfileID: profileID, CreatedAt: time.Now().UTC()},
	}
	waiting, err := NewWaitingConfirmationTurnEvent(uuid.NewString(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	store := &streamingChatAdapterStore{
		terminalChatAdapterStore: &terminalChatAdapterStore{
			publicActiveTurnStore: &publicActiveTurnStore{fakeStore: newFakeStore()},
			state:                 TurnCompleted, content: response.Message.Content,
		},
		events: []TurnEvent{
			{Kind: TurnEventAccepted},
			{Kind: TurnEventStarted},
			{Kind: TurnEventDelta, Text: "sum"},
			{Kind: TurnEventToolCall, ToolCall: &call},
			{Kind: TurnEventToolResult, ToolResult: &result},
			waiting,
			{Kind: TurnEventWorkerStatus, ExecutionID: uuid.NewString(), Status: "running", Phase: "working"},
			{Kind: TurnEventSteered, Text: "focus", Status: "deferred_tool"},
		},
	}
	command := ChatCommand{RequestID: response.RequestID, Prompt: "summarize", ProfileID: profileID, ExpectedProfileRevision: 1, ExpectedCredentialVersion: 1}
	// The authoritative done payload must use the conversation identity derived
	// by StartTurn for a new conversation.
	response.ConversationID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation:"+command.RequestID)).String()
	store.events = append(store.events, TurnEvent{Kind: TurnEventDone, Response: &response})
	service, err := NewService(store, &fakeModel{}, noopExtensions{}, durableAdapterProfile{})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := service.StreamChat(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	var got []StreamEvent
	for event := range stream {
		got = append(got, event)
	}
	want := []StreamEventKind{EventAccepted, EventStarted, EventDelta, EventToolCall, EventToolResult, EventWaitingConfirmation, EventWorkerStatus, EventSteered, EventDone}
	if len(got) != len(want) {
		t.Fatalf("events=%+v", got)
	}
	for index := range want {
		if got[index].Kind != want[index] || got[index].TurnSequence != int64(index+1) || got[index].TurnID == "" || got[index].Revision == 0 {
			t.Fatalf("event[%d]=%+v want=%s", index, got[index], want[index])
		}
	}
	if got[5].ConfirmationID != waiting.ConfirmationID || got[6].Status != "running" || got[6].Phase != "working" || got[7].Text != "focus" {
		t.Fatalf("lifecycle projections=%+v", got[5:8])
	}
}

func TestChatReplayAfterServiceRestartUsesSameDurableTerminal(t *testing.T) {
	store := &terminalChatAdapterStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: newFakeStore()},
		state:                 TurnCompleted, content: "replayed durable response",
	}
	command := command()
	for attempt := 0; attempt < 2; attempt++ {
		model := &fakeModel{}
		service, err := NewService(store, model, noopExtensions{}, durableAdapterProfile{})
		if err != nil {
			t.Fatal(err)
		}
		response, err := service.Chat(context.Background(), command)
		if err != nil || response.Message.Content != store.content || model.runs != 0 {
			t.Fatalf("attempt=%d response=%+v err=%v modelRuns=%d", attempt, response, err, model.runs)
		}
	}
	if store.startCalls != 1 {
		t.Fatalf("durable admissions=%d", store.startCalls)
	}
}

func TestStreamChatDisconnectStopsWaitingWithoutCancelingAcceptedTurn(t *testing.T) {
	store := &streamingChatAdapterStore{
		terminalChatAdapterStore: &terminalChatAdapterStore{
			publicActiveTurnStore: &publicActiveTurnStore{fakeStore: newFakeStore()},
			state:                 TurnWaitingConfirmation,
		},
		events: []TurnEvent{{Kind: TurnEventAccepted}},
	}
	service, err := NewService(store, &fakeModel{}, noopExtensions{}, durableAdapterProfile{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stream, err := service.StreamChat(ctx, command())
	if err != nil {
		t.Fatal(err)
	}
	if event := <-stream; event.Kind != EventAccepted {
		t.Fatalf("first event=%+v", event)
	}
	cancel()
	select {
	case _, open := <-stream:
		if open {
			t.Fatal("stream remained open after disconnect")
		}
	case <-time.After(time.Second):
		t.Fatal("stream did not detach after disconnect")
	}
	if store.cancelCalls != 0 || store.turn.CancelRequested {
		t.Fatalf("disconnect canceled accepted turn: calls=%d turn=%+v", store.cancelCalls, store.turn)
	}
}
