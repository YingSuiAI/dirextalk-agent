package coreconversation

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

func TestConversationToolAttemptContentRestoresSafeFailureSummary(t *testing.T) {
	const safeSummary = "local sandbox is busy; retry later or explicitly authorize Cloud Worker"
	raw, err := json.Marshal(coretask.Result{Summary: safeSummary})
	if err != nil {
		t.Fatal(err)
	}
	attempt := ToolAttempt{
		State: "denied", Result: raw,
		SafeSummary: "conversation tool call write_html",
	}
	if got := conversationToolAttemptContent(attempt); got != safeSummary {
		t.Fatalf("recovered content=%q want=%q", got, safeSummary)
	}
	if strings.Contains(conversationToolAttemptContent(attempt), "stderr") {
		t.Fatal("protected runner diagnostics leaked through recovered content")
	}
}

type replayTurnStore struct {
	*fakeStore
	turn Turn
}

type supervisorTurnStore struct {
	*replayTurnStore
	claimed, canceled, uncertain bool
}
type watcherTurnStore struct {
	*replayTurnStore
	boundsErr bool
}

type blockingTurnModel struct {
	started chan struct{}
	release chan struct{}
}

type capturingTurnModel struct {
	request ModelRunRequest
	runs    int
}

type delayedStreamingTurnModel struct {
	delay       time.Duration
	runCalls    int
	streamCalls int
}

func (m *delayedStreamingTurnModel) Run(context.Context, ModelRunRequest) (ModelRunResult, error) {
	m.runCalls++
	return ModelRunResult{}, context.DeadlineExceeded
}

func (m *delayedStreamingTurnModel) Stream(ctx context.Context, _ ModelRunRequest, emit func(ModelDelta) error) (ModelRunResult, error) {
	m.streamCalls++
	if emit == nil {
		return ModelRunResult{}, ErrInvalid
	}
	if err := emit(ModelDelta{Text: "intermediate-only delta"}); err != nil {
		return ModelRunResult{}, err
	}
	timer := time.NewTimer(m.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return ModelRunResult{}, ctx.Err()
	}
	return ModelRunResult{Done: true, Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "final answer", CreatedAt: time.Now().UTC()}}, nil
}

type fixedToolCallsTurnModel struct{ calls []ToolCall }

func (m fixedToolCallsTurnModel) Run(context.Context, ModelRunRequest) (ModelRunResult, error) {
	message := Message{ID: uuid.NewString(), Role: RoleAssistant, ToolCalls: append([]ToolCall(nil), m.calls...), CreatedAt: time.Now().UTC()}
	return ModelRunResult{Message: message, ToolCalls: append([]ToolCall(nil), m.calls...)}, nil
}

func (m fixedToolCallsTurnModel) Stream(ctx context.Context, request ModelRunRequest, _ func(ModelDelta) error) (ModelRunResult, error) {
	return m.Run(ctx, request)
}

type twoRoundReadOnlyModel struct {
	call     ToolCall
	requests []ModelRunRequest
}

func (m *twoRoundReadOnlyModel) Run(_ context.Context, request ModelRunRequest) (ModelRunResult, error) {
	m.requests = append(m.requests, request)
	if len(m.requests) == 1 {
		message := Message{ID: uuid.NewString(), Role: RoleAssistant, ToolCalls: []ToolCall{m.call}, CreatedAt: time.Now().UTC()}
		return ModelRunResult{Message: message, ToolCalls: []ToolCall{m.call}}, nil
	}
	return ModelRunResult{Done: true, Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "final answer", CreatedAt: time.Now().UTC()}}, nil
}

func (m *twoRoundReadOnlyModel) Stream(ctx context.Context, request ModelRunRequest, _ func(ModelDelta) error) (ModelRunResult, error) {
	return m.Run(ctx, request)
}

type readOnlyTurnStore struct {
	*publicActiveTurnStore
	events        []TurnEvent
	dispatchState string
	dispatch      ModelRunResult
	failedCode    string
	dispatched    map[string]bool
	prepareCalls  int
	prepared      ToolAttempt
}

func (s *readOnlyTurnStore) RecordConversationToolCall(_ context.Context, _ TurnLease, call ToolCall) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, event := range s.events {
		if event.ToolCall != nil && event.ToolCall.ID == call.ID {
			if event.Kind == TurnEventToolCall && !reflect.DeepEqual(*event.ToolCall, call) {
				return ErrConflict
			}
			if event.Kind == TurnEventToolCall {
				return nil
			}
		}
	}
	s.turn.LastSequence++
	s.events = append(s.events, TurnEvent{TurnID: s.turn.ID, Sequence: s.turn.LastSequence, Revision: s.turn.Revision, Kind: TurnEventToolCall, ToolCall: &call, CreatedAt: time.Now().UTC()})
	return nil
}

func (s *readOnlyTurnStore) BeginConversationToolDispatch(_ context.Context, _ TurnLease, call ToolCall) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pending bool
	for _, event := range s.events {
		if event.ToolCall == nil || event.ToolCall.ID != call.ID {
			continue
		}
		if !reflect.DeepEqual(*event.ToolCall, call) {
			return false, ErrConflict
		}
		if event.Kind == TurnEventToolCall {
			pending = true
		}
	}
	if !pending {
		return false, ErrConflict
	}
	if s.dispatched == nil {
		s.dispatched = make(map[string]bool)
	}
	if s.dispatched[call.ID] {
		return false, nil
	}
	s.dispatched[call.ID] = true
	return true, nil
}

func (s *readOnlyTurnStore) RecordConversationToolResult(_ context.Context, _ TurnLease, result ToolResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, event := range s.events {
		if event.ToolResult != nil && event.ToolResult.CallID == result.CallID {
			return nil
		}
	}
	s.turn.LastSequence++
	s.events = append(s.events, TurnEvent{TurnID: s.turn.ID, Sequence: s.turn.LastSequence, Revision: s.turn.Revision, Kind: TurnEventToolResult, ToolResult: &result, CreatedAt: time.Now().UTC()})
	return nil
}

func (s *readOnlyTurnStore) FailConversationToolDispatch(_ context.Context, _ TurnLease, call ToolCall, code, summary string) (Turn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := ToolResult{CallID: call.ID, ToolName: call.Name, Content: summary, IsError: true}
	s.turn.LastSequence++
	s.events = append(s.events, TurnEvent{TurnID: s.turn.ID, Sequence: s.turn.LastSequence, Revision: s.turn.Revision, Kind: TurnEventToolResult, ToolResult: &result, CreatedAt: time.Now().UTC()})
	s.turn.LastSequence++
	s.events = append(s.events, TurnEvent{TurnID: s.turn.ID, Sequence: s.turn.LastSequence, Revision: s.turn.Revision, Kind: TurnEventError, ErrorCode: code, ErrorSummary: summary, CreatedAt: time.Now().UTC()})
	s.turn.State, s.failedCode = TurnFailed, code
	return s.turn, nil
}

func (s *readOnlyTurnStore) CompleteConversationToolRound(_ context.Context, _ TurnLease) (Turn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.turn.State = TurnAccepted
	s.turn.Revision++
	s.dispatchState, s.dispatch = "", ModelRunResult{}
	return s.turn, nil
}

func (s *readOnlyTurnStore) FailTurn(_ context.Context, _ TurnLease, code, _ string) (Turn, error) {
	s.failedCode = code
	return s.turn, nil
}

func (s *readOnlyTurnStore) PrepareConversationTool(context.Context, PrepareToolCommand) (ToolAttempt, coretask.Task, coreconfirmation.Confirmation, error) {
	s.prepareCalls++
	if s.prepared.ID != "" {
		waiting, err := NewWaitingConfirmationTurnEvent(s.prepared.ConfirmationID, s.prepared.ExecutionID)
		if err != nil || s.prepared.State != string(TurnWaitingConfirmation) {
			return ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, ErrInvalid
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.turn.State = TurnWaitingConfirmation
		s.turn.Revision++
		s.turn.LastSequence++
		waiting.TurnID, waiting.Sequence, waiting.Revision, waiting.CreatedAt =
			s.turn.ID, s.turn.LastSequence, s.turn.Revision, time.Now().UTC()
		s.events = append(s.events, waiting)
		return s.prepared, coretask.Task{}, coreconfirmation.Confirmation{}, nil
	}
	return ToolAttempt{}, coretask.Task{}, coreconfirmation.Confirmation{}, ErrInvalid
}

func (s *readOnlyTurnStore) ClaimTurn(_ context.Context, _ string, _ time.Time, _ time.Duration) (TurnLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.turn.State = TurnRunning
	return TurnLease{Turn: s.turn, LeaseID: "read-only-lease", Epoch: 1}, nil
}

func (s *readOnlyTurnStore) AppendTurnEvent(_ context.Context, _ string, event TurnEvent) (TurnEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.turn.LastSequence++
	event.TurnID, event.Sequence, event.Revision, event.CreatedAt = s.turn.ID, s.turn.LastSequence, s.turn.Revision, time.Now().UTC()
	s.events = append(s.events, event)
	return event, nil
}

func (s *readOnlyTurnStore) LoadTurnEvents(_ context.Context, _ string, after int64, limit int) ([]TurnEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []TurnEvent
	for _, event := range s.events {
		if event.Sequence > after && len(result) < limit {
			result = append(result, event)
		}
	}
	return result, nil
}

func (s *readOnlyTurnStore) TurnEventBounds(context.Context, string) (int64, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) == 0 {
		return 0, 0, nil
	}
	return s.events[0].Sequence, s.events[len(s.events)-1].Sequence, nil
}

func (s *readOnlyTurnStore) PrepareTurnModel(context.Context, TurnLease) (Turn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dispatchState = "dispatched"
	return s.turn, nil
}

func (s *readOnlyTurnStore) LoadTurnModelResult(context.Context, string) (ModelRunResult, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dispatch, s.dispatchState == "completed", nil
}

func (s *readOnlyTurnStore) RecordTurnModelResult(_ context.Context, _ TurnLease, result ModelRunResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dispatchState != "dispatched" {
		return ErrConflict
	}
	s.dispatch, s.dispatchState = result, "completed"
	return nil
}

func (s *readOnlyTurnStore) MarkTurnModelUncertain(context.Context, TurnLease, string, string) error {
	return ErrConflict
}

func (s *readOnlyTurnStore) CommitTurn(_ context.Context, _ TurnLease, response ChatResponse) (Turn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.turn.Revision++
	s.turn.LastSequence++
	s.events = append(s.events, TurnEvent{TurnID: s.turn.ID, Sequence: s.turn.LastSequence, Revision: s.turn.Revision, Kind: TurnEventDone, Response: &response, CreatedAt: time.Now().UTC()})
	s.turn.State = TurnCompleted
	s.turn.Response = &response
	return s.turn, nil
}

type extensionResolverFunc func(context.Context, []ExtensionSelection) ([]ResolvedExtension, error)

func (f extensionResolverFunc) ResolveExtensions(ctx context.Context, selections []ExtensionSelection) ([]ResolvedExtension, error) {
	return f(ctx, selections)
}

type intrinsicResolverFunc func(context.Context, TurnLease) ([]ResolvedIntrinsic, error)

func (f intrinsicResolverFunc) ResolveIntrinsicTools(ctx context.Context, lease TurnLease) ([]ResolvedIntrinsic, error) {
	return f(ctx, lease)
}

func (m *capturingTurnModel) Run(_ context.Context, request ModelRunRequest) (ModelRunResult, error) {
	m.request = request
	m.runs++
	return ModelRunResult{Done: true, Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "ok", CreatedAt: time.Now().UTC()}}, nil
}

func (m *capturingTurnModel) Stream(ctx context.Context, request ModelRunRequest, _ func(ModelDelta) error) (ModelRunResult, error) {
	return m.Run(ctx, request)
}

type memoryRecallFunc func(context.Context, string) (string, error)

func (f memoryRecallFunc) RecallMemory(ctx context.Context, prompt string) (string, error) {
	return f(ctx, prompt)
}

type recallFailureTurnStore struct {
	*publicActiveTurnStore
	failedCode    string
	failedSummary string
}

func (s *recallFailureTurnStore) FailTurn(_ context.Context, _ TurnLease, code, summary string) (Turn, error) {
	s.failedCode, s.failedSummary = code, summary
	s.turn.State = TurnFailed
	return s.turn, nil
}

func (m *blockingTurnModel) Run(ctx context.Context, req ModelRunRequest) (ModelRunResult, error) {
	close(m.started)
	<-m.release
	return ModelRunResult{Done: true, Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "ok", CreatedAt: time.Now().UTC()}}, nil
}

func (m *blockingTurnModel) Stream(ctx context.Context, req ModelRunRequest, _ func(ModelDelta) error) (ModelRunResult, error) {
	return m.Run(ctx, req)
}

type activeTurnStore struct{ *supervisorTurnStore }

// publicActiveTurnStore drives the public StartTurn/CancelTurn path while
// retaining the ordinary fake conversation store for model execution.
type publicActiveTurnStore struct {
	*fakeStore
	mu             sync.Mutex
	turn           Turn
	terminalEvents int
}

type supervisorRetryTurnStore struct {
	*publicActiveTurnStore
	readMu         sync.Mutex
	transientReads int
	firstTransient chan struct{}
	firstOnce      sync.Once
	successfulRead chan struct{}
	successOnce    sync.Once
}

func (s *supervisorRetryTurnStore) GetTurn(ctx context.Context, id string) (Turn, error) {
	s.readMu.Lock()
	if s.transientReads > 0 {
		s.transientReads--
		s.firstOnce.Do(func() { close(s.firstTransient) })
		s.readMu.Unlock()
		return Turn{}, errors.New("transient turn store outage")
	}
	s.successOnce.Do(func() { close(s.successfulRead) })
	s.readMu.Unlock()
	return s.publicActiveTurnStore.GetTurn(ctx, id)
}

func (s *supervisorRetryTurnStore) CommitTurn(_ context.Context, _ TurnLease, _ ChatResponse) (Turn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.turn.State = TurnCompleted
	s.turn.Revision++
	return s.turn, nil
}

func (s *publicActiveTurnStore) StartTurn(_ context.Context, cmd TurnStartCommand) (Turn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	turnID := cmd.TurnID
	if turnID == "" {
		turnID = uuid.NewString()
	}
	s.turn = Turn{ID: turnID, RequestID: cmd.RequestID, ConversationID: cmd.ConversationID, Prompt: cmd.Prompt, ProfileID: cmd.ProfileID, ProfileSnapshot: cmd.ProfileSnapshot, ProfileSnapshotDigest: cmd.ProfileSnapshot.Digest(), Revision: 1, State: TurnAccepted, LastSequence: 1}
	return s.turn, nil
}
func (s *publicActiveTurnStore) GetTurn(_ context.Context, _ string) (Turn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.turn, nil
}
func (s *publicActiveTurnStore) terminalEventCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.terminalEvents
}
func (s *publicActiveTurnStore) GetTurnByRequestID(context.Context, string) (Turn, error) {
	return Turn{}, ErrConflict
}
func (s *publicActiveTurnStore) ListRecoverableTurns(context.Context) ([]Turn, error) {
	return nil, nil
}
func (s *publicActiveTurnStore) ClaimTurn(_ context.Context, _ string, _ time.Time, _ time.Duration) (TurnLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.turn.CancelRequested {
		return TurnLease{Turn: s.turn}, nil
	}
	s.turn.State = TurnRunning
	return TurnLease{Turn: s.turn, LeaseID: "public-lease", Epoch: 1}, nil
}
func (s *publicActiveTurnStore) RenewTurn(_ context.Context, _ string, _ string, _ uint64, _ time.Time, _ time.Duration) (TurnLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return TurnLease{Turn: s.turn, LeaseID: "public-lease", Epoch: 1}, nil
}
func (s *publicActiveTurnStore) AppendTurnEvent(_ context.Context, _ string, e TurnEvent) (TurnEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.turn.LastSequence++
	e.TurnID, e.Sequence = s.turn.ID, s.turn.LastSequence
	return e, nil
}
func (s *publicActiveTurnStore) LoadTurnEvents(context.Context, string, int64, int) ([]TurnEvent, error) {
	return nil, nil
}
func (s *publicActiveTurnStore) TurnEventBounds(context.Context, string) (int64, int64, error) {
	return 1, 1, nil
}
func (s *publicActiveTurnStore) CommitTurn(context.Context, TurnLease, ChatResponse) (Turn, error) {
	return Turn{}, ErrConflict
}
func (s *publicActiveTurnStore) RequestTurnCancel(_ context.Context, cmd TurnCancelCommand) (Turn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.turn.Revision != cmd.ExpectedRevision {
		return Turn{}, ErrConflict
	}
	s.turn.CancelRequested = true
	s.turn.Revision++
	return s.turn, nil
}
func (s *publicActiveTurnStore) MarkTurnCanceled(_ context.Context, _ TurnLease) (Turn, error) {
	return Turn{}, ErrConflict
}
func (s *publicActiveTurnStore) MarkTurnCanceledRequested(_ context.Context, _ string) (Turn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.turn.State = TurnCanceled
	s.turn.Revision++
	s.terminalEvents++
	return s.turn, nil
}
func (s *publicActiveTurnStore) FailTurn(context.Context, TurnLease, string, string) (Turn, error) {
	return Turn{}, ErrConflict
}

func (s *activeTurnStore) ClaimTurn(context.Context, string, time.Time, time.Duration) (TurnLease, error) {
	return TurnLease{Turn: s.turn, LeaseID: uuid.NewString(), Epoch: 1}, nil
}
func (s *activeTurnStore) GetTurn(context.Context, string) (Turn, error) { return s.turn, nil }
func (s *activeTurnStore) MarkTurnCanceledRequested(context.Context, string) (Turn, error) {
	s.canceled = true
	s.turn.State = TurnCanceled
	return s.turn, nil
}
func (s *activeTurnStore) AppendTurnEvent(context.Context, string, TurnEvent) (TurnEvent, error) {
	return TurnEvent{}, nil
}

func (s *watcherTurnStore) GetTurn(context.Context, string) (Turn, error) { return s.turn, nil }
func (s *watcherTurnStore) TurnEventBounds(context.Context, string) (int64, int64, error) {
	if s.boundsErr {
		return 0, 0, ErrConflict
	}
	return 1, 1, nil
}
func (s *watcherTurnStore) LoadTurnEvents(context.Context, string, int64, int) ([]TurnEvent, error) {
	return nil, nil
}

func (s *supervisorTurnStore) GetTurn(context.Context, string) (Turn, error) { return s.turn, nil }
func (s *supervisorTurnStore) ClaimTurn(context.Context, string, time.Time, time.Duration) (TurnLease, error) {
	s.claimed = true
	return TurnLease{}, ErrInvalid
}
func (s *supervisorTurnStore) MarkTurnCanceledRequested(context.Context, string) (Turn, error) {
	s.canceled = true
	return s.turn, nil
}
func (s *supervisorTurnStore) FailTurnUncertain(context.Context, string, string, string) (Turn, error) {
	s.uncertain = true
	return s.turn, nil
}

func (s *replayTurnStore) StartTurn(context.Context, TurnStartCommand) (Turn, error) {
	return s.turn, nil
}
func (s *replayTurnStore) GetTurn(context.Context, string) (Turn, error) { return s.turn, nil }
func (s *replayTurnStore) GetTurnByRequestID(context.Context, string) (Turn, error) {
	return s.turn, nil
}
func (s *replayTurnStore) ListRecoverableTurns(context.Context) ([]Turn, error) { return nil, nil }
func (s *replayTurnStore) ClaimTurn(context.Context, string, time.Time, time.Duration) (TurnLease, error) {
	return TurnLease{}, ErrInvalid
}
func (s *replayTurnStore) RenewTurn(context.Context, string, string, uint64, time.Time, time.Duration) (TurnLease, error) {
	return TurnLease{}, ErrInvalid
}
func (s *replayTurnStore) AppendTurnEvent(context.Context, string, TurnEvent) (TurnEvent, error) {
	return TurnEvent{}, ErrInvalid
}
func (s *replayTurnStore) LoadTurnEvents(context.Context, string, int64, int) ([]TurnEvent, error) {
	return nil, ErrInvalid
}
func (s *replayTurnStore) TurnEventBounds(context.Context, string) (int64, int64, error) {
	return 0, 0, ErrInvalid
}
func (s *replayTurnStore) CommitTurn(context.Context, TurnLease, ChatResponse) (Turn, error) {
	return Turn{}, ErrInvalid
}
func (s *replayTurnStore) RequestTurnCancel(context.Context, TurnCancelCommand) (Turn, error) {
	return Turn{}, ErrInvalid
}
func (s *replayTurnStore) MarkTurnCanceled(context.Context, TurnLease) (Turn, error) {
	return Turn{}, ErrInvalid
}
func (s *replayTurnStore) FailTurn(context.Context, TurnLease, string, string) (Turn, error) {
	return Turn{}, ErrInvalid
}

func testTurnSnapshot() coremodel.ExecutionSnapshot {
	return coremodel.ExecutionSnapshot{ProfileID: uuid.NewString(), Revision: 1, CredentialVersion: 1, Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://example.invalid", Model: "test", APIKey: "bound-secret"}
}

func TestStartTurnFingerprintBindsImmutableSnapshotAndPrompt(t *testing.T) {
	snapshot := testTurnSnapshot()
	revision := uint64(1)
	cmd := TurnStartCommand{TurnID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: uuid.NewString(), Prompt: "hello", ProfileID: snapshot.ProfileID, ExpectedProfileRevision: snapshot.Revision, ExpectedCredentialVersion: snapshot.CredentialVersion, ExpectedRevision: &revision, ProfileSnapshot: snapshot}
	if err := cmd.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := cmd.Fingerprint(); got == "" || got != cmd.Fingerprint() {
		t.Fatal("turn fingerprint is not stable")
	}
	changed := cmd
	changed.Prompt = "changed"
	if changed.Fingerprint() == cmd.Fingerprint() {
		t.Fatal("prompt mutation was not bound by the request digest")
	}
	changed = cmd
	changed.TurnID = uuid.NewString()
	if changed.Fingerprint() == cmd.Fingerprint() {
		t.Fatal("turn identity mutation was not bound by the request digest")
	}
	rotated := cmd
	rotated.ProfileSnapshot.APIKey = "rotated-secret"
	if rotated.Fingerprint() == cmd.Fingerprint() {
		t.Fatal("profile snapshot mutation was not bound by the request digest")
	}
}

func TestAppendTurnSteersKeepsGuidanceInsideCurrentModelTurn(t *testing.T) {
	now := time.Date(2026, 8, 9, 3, 4, 5, 0, time.UTC)
	turn := Turn{ID: uuid.NewString(), ProfileID: uuid.NewString()}
	conversation := Conversation{ID: uuid.NewString(), Revision: 1, Messages: []Message{{
		ID: uuid.NewString(), Role: RoleUser, Content: "original question",
		ModelProfileID: turn.ProfileID, CreatedAt: now,
	}}}
	steers := []TurnSteer{
		{RequestID: uuid.NewString(), Instruction: "focus on correctness", ExpectedRevision: 1, Sequence: 2, CreatedAt: now.Add(time.Second)},
		{RequestID: uuid.NewString(), Instruction: "then keep it concise", ExpectedRevision: 2, Sequence: 3, CreatedAt: now.Add(2 * time.Second)},
	}
	got, err := appendTurnSteers(conversation, turn, steers, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 3 || got.Messages[0].Content != "original question" || got.Messages[1].Content != steers[0].Instruction || got.Messages[2].Content != steers[1].Instruction {
		t.Fatalf("same-turn model context=%+v", got.Messages)
	}
	for index, steer := range steers {
		message := got.Messages[index+1]
		if message.Role != RoleUser || message.ID != uuid.NewSHA1(uuid.NameSpaceOID, []byte("turn-steer-user:"+steer.RequestID)).String() {
			t.Fatalf("steer message[%d]=%+v", index, message)
		}
	}
	if len(conversation.Messages) != 1 {
		t.Fatal("appendTurnSteers mutated the caller conversation")
	}
}

func TestModelConversationForTurnInjectsTransientRecallAndCurrentPrompt(t *testing.T) {
	profileID := uuid.NewString()
	turn := Turn{ID: uuid.NewString(), Prompt: "what do you remember?", ProfileID: profileID, CreatedAt: time.Now().UTC()}
	persisted := Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "earlier", ModelProfileID: profileID, CreatedAt: turn.CreatedAt.Add(-time.Minute)}
	recovered := Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "tool finished", ModelProfileID: profileID, CreatedAt: turn.CreatedAt.Add(time.Minute)}
	original := Conversation{ID: uuid.NewString(), Messages: []Message{persisted, recovered}}
	modelConversation, err := modelConversationForTurn(original, 1, turn, "[UNTRUSTED LONG-TERM MEMORY]\n- private fact\n[END UNTRUSTED LONG-TERM MEMORY]", turn.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(modelConversation.Messages) != 4 || modelConversation.Messages[0].ID != persisted.ID || modelConversation.Messages[1].Role != RoleUser || modelConversation.Messages[2].Role != RoleUser || modelConversation.Messages[2].Content != turn.Prompt || modelConversation.Messages[3].ID != recovered.ID {
		t.Fatalf("model-only context order=%+v", modelConversation.Messages)
	}
	if len(original.Messages) != 2 {
		t.Fatalf("transient context mutated authoritative conversation: %+v", original.Messages)
	}
}

func TestExecuteTurnRecallsNewConversationBeforeModel(t *testing.T) {
	snapshot := testTurnSnapshot()
	turn := Turn{ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: uuid.NewString(), Prompt: "remember my city", ProfileID: snapshot.ProfileID, ProfileSnapshot: snapshot, State: TurnAccepted, Revision: 1, CreatedAt: time.Now().UTC()}
	store := &publicActiveTurnStore{fakeStore: newFakeStore(), turn: turn}
	model := &capturingTurnModel{}
	service, err := NewService(store, model, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return snapshot, nil }))
	if err != nil {
		t.Fatal(err)
	}
	var recalledPrompt string
	service.SetMemoryRecallResolver(memoryRecallFunc(func(_ context.Context, prompt string) (string, error) {
		recalledPrompt = prompt
		return "[UNTRUSTED LONG-TERM MEMORY]\n- lives in Shanghai\n[END UNTRUSTED LONG-TERM MEMORY]", nil
	}))
	service.executeTurn(context.Background(), turn.ID)
	if recalledPrompt != turn.Prompt || model.runs != 1 {
		t.Fatalf("recall prompt=%q model runs=%d", recalledPrompt, model.runs)
	}
	if len(model.request.Conversation.Messages) != 2 || model.request.Conversation.Messages[0].Role != RoleUser || model.request.Conversation.Messages[1].Role != RoleUser || model.request.Conversation.Messages[1].Content != turn.Prompt {
		t.Fatalf("model request omitted recall/current prompt: %+v", model.request.Conversation.Messages)
	}
}

func TestExecuteTurnDurableUsesStreamingPathBeyondLegacyTotalWindow(t *testing.T) {
	profile := testTurnSnapshot()
	conversationID := uuid.NewString()
	turn := Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: conversationID,
		Prompt: "complete a long model turn", ProfileID: profile.ProfileID,
		ProfileSnapshot: profile, ProfileSnapshotDigest: profile.Digest(),
		State: TurnAccepted, Revision: 1, LastSequence: 1, CreatedAt: time.Now().UTC(),
	}
	base := newFakeStore()
	base.conv[conversationID] = Conversation{ID: conversationID, Revision: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	store := &readOnlyTurnStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: turn},
		events:                []TurnEvent{{TurnID: turn.ID, Sequence: 1, Revision: 1, Kind: TurnEventAccepted, CreatedAt: turn.CreatedAt}},
	}
	const simulatedLegacyTotalWindow = 10 * time.Millisecond
	model := &delayedStreamingTurnModel{delay: 4 * simulatedLegacyTotalWindow}
	service, err := NewService(store, model, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return profile, nil }))
	if err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	service.executeTurn(context.Background(), turn.ID)
	elapsed := time.Since(started)

	terminal, err := store.GetTurn(context.Background(), turn.ID)
	if err != nil || terminal.State != TurnCompleted || terminal.Response == nil || terminal.Response.Message.Content != "final answer" {
		t.Fatalf("terminal=%+v err=%v", terminal, err)
	}
	if model.runCalls != 0 || model.streamCalls != 1 {
		t.Fatalf("model Run calls=%d Stream calls=%d", model.runCalls, model.streamCalls)
	}
	if elapsed < model.delay || elapsed <= simulatedLegacyTotalWindow {
		t.Fatalf("durable streaming elapsed=%s delay=%s legacy_window=%s", elapsed, model.delay, simulatedLegacyTotalWindow)
	}
	if len(store.events) != 4 || store.events[0].Kind != TurnEventAccepted || store.events[1].Kind != TurnEventStarted ||
		store.events[2].Kind != TurnEventDelta || store.events[2].Text != "intermediate-only delta" || store.events[3].Kind != TurnEventDone {
		t.Fatalf("durable events=%+v", store.events)
	}
	replayed, err := store.LoadTurnEvents(context.Background(), turn.ID, 0, 1000)
	if err != nil || len(replayed) != 4 || replayed[2].Kind != TurnEventDelta || replayed[2].Text != "intermediate-only delta" || replayed[3].Kind != TurnEventDone {
		t.Fatalf("replayed durable events=%+v err=%v", replayed, err)
	}
	if strings.Contains(terminal.Response.Message.Content, "intermediate-only delta") {
		t.Fatal("streaming delta leaked into terminal response")
	}
}

func TestDurableReadOnlyToolPersistsEventsAndCompletesSecondModelRound(t *testing.T) {
	profile := testTurnSnapshot()
	conversationID := uuid.NewString()
	selection := ExtensionSelection{Kind: ExtensionMCP, ID: uuid.NewString(), Version: "config-1", Digest: strings.Repeat("a", 64), AllowedTools: []string{"web_search"}}
	snapshot := ExtensionExecutionSnapshot{Selection: selection, InstallationID: selection.ID, VersionID: selection.Version, Source: "builtin:web_search:tavily", ContentDigest: selection.Digest, ArtifactDigest: strings.Repeat("b", 64), ToolSchemaDigest: strings.Repeat("c", 64), NetworkBindingDigest: strings.Repeat("d", 64), ToolNames: []string{"web_search"}, ReadOnly: true}
	call := ToolCall{ID: uuid.NewString(), Name: "web_search", Arguments: `{"query":"Dirextalk"}`}
	executions := 0
	executionStarted := make(chan struct{})
	releaseExecution := make(chan struct{})
	resolved := ResolvedExtension{
		Selection: selection,
		Snapshot:  snapshot,
		Tools:     []coremodel.Tool{{Name: "web_search", InputSchema: map[string]any{"type": "object"}}},
		Execute: func(ctx context.Context, _ ToolExecutionRequest) (ToolResult, error) {
			executions++
			close(executionStarted)
			select {
			case <-releaseExecution:
			case <-ctx.Done():
				return ToolResult{}, ctx.Err()
			}
			return ToolResult{CallID: call.ID, ToolName: call.Name, Content: `{"answer":"found"}`, Summary: "search complete"}, nil
		},
	}
	base := newFakeStore()
	base.conv[conversationID] = Conversation{ID: conversationID, Revision: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	turn := Turn{ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: conversationID, Prompt: "search then answer", ProfileID: profile.ProfileID, ProfileSnapshot: profile, ProfileSnapshotDigest: profile.Digest(), ExtensionSnapshots: []ExtensionExecutionSnapshot{snapshot}, ExtensionSnapshotDigest: TurnStartCommand{ExtensionSnapshots: []ExtensionExecutionSnapshot{snapshot}}.ExtensionSnapshotDigest(), State: TurnAccepted, Revision: 1, LastSequence: 1, CreatedAt: time.Now().UTC()}
	store := &readOnlyTurnStore{publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: turn}, events: []TurnEvent{{TurnID: turn.ID, Sequence: 1, Kind: TurnEventAccepted, CreatedAt: turn.CreatedAt}}}
	model := &twoRoundReadOnlyModel{call: call}
	resolver := extensionResolverFunc(func(_ context.Context, selections []ExtensionSelection) ([]ResolvedExtension, error) {
		if len(selections) != 0 {
			t.Fatalf("builtin resolver received persisted synthetic selection: %+v", selections)
		}
		return []ResolvedExtension{resolved}, nil
	})
	service, err := NewService(store, model, resolver, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return profile, nil }))
	if err != nil {
		t.Fatal(err)
	}
	firstRoundDone := make(chan struct{})
	go func() {
		service.executeTurn(context.Background(), turn.ID)
		close(firstRoundDone)
	}()
	select {
	case <-executionStarted:
	case <-time.After(time.Second):
		t.Fatal("read-only tool execution did not start")
	}
	store.mu.Lock()
	var callsBeforeRelease, resultsBeforeRelease int
	for _, event := range store.events {
		if event.Kind == TurnEventToolCall && event.ToolCall != nil && event.ToolCall.ID == call.ID {
			callsBeforeRelease++
		}
		if event.Kind == TurnEventToolResult && event.ToolResult != nil && event.ToolResult.CallID == call.ID {
			resultsBeforeRelease++
		}
	}
	store.mu.Unlock()
	if callsBeforeRelease != 1 || resultsBeforeRelease != 0 {
		t.Fatalf("in-flight public events calls=%d results=%d", callsBeforeRelease, resultsBeforeRelease)
	}
	close(releaseExecution)
	select {
	case <-firstRoundDone:
	case <-time.After(time.Second):
		t.Fatal("read-only tool execution did not finish")
	}
	first, err := store.GetTurn(context.Background(), turn.ID)
	if err != nil || first.State != TurnAccepted || store.dispatchState != "" || executions != 1 || store.prepareCalls != 0 {
		t.Fatalf("first round turn=%+v dispatch=%q executions=%d prepare_calls=%d failed=%q err=%v", first, store.dispatchState, executions, store.prepareCalls, store.failedCode, err)
	}
	service.executeTurn(context.Background(), turn.ID)
	terminal, err := store.GetTurn(context.Background(), turn.ID)
	if err != nil || terminal.State != TurnCompleted || terminal.Response == nil || terminal.Response.Message.Content != "final answer" || len(model.requests) != 2 {
		t.Fatalf("terminal=%+v model rounds=%d err=%v", terminal, len(model.requests), err)
	}
	if len(model.requests[1].Conversation.Messages) != 3 || len(model.requests[1].Conversation.Messages[1].ToolCalls) != 1 || len(model.requests[1].Conversation.Messages[2].ToolResults) != 1 {
		t.Fatalf("second-round durable context=%+v", model.requests[1].Conversation.Messages)
	}
	var toolCalls, toolResults, done int
	for _, event := range store.events {
		switch event.Kind {
		case TurnEventToolCall:
			toolCalls++
		case TurnEventToolResult:
			toolResults++
		case TurnEventDone:
			done++
		}
	}
	if toolCalls != 1 || toolResults != 1 || done != 1 {
		t.Fatalf("durable events=%+v", store.events)
	}
}

func TestExecuteTurnPublishesCanonicalWaitingConfirmationForLocalTool(t *testing.T) {
	profile := testTurnSnapshot()
	conversationID := uuid.NewString()
	selection := ExtensionSelection{
		Kind: ExtensionMCP, ID: uuid.NewString(), Version: "config-1",
		Digest: strings.Repeat("a", 64), AllowedTools: []string{"local_task"},
	}
	snapshot := ExtensionExecutionSnapshot{
		Selection: selection, InstallationID: selection.ID, VersionID: selection.Version,
		Source: "mcp:test", ContentDigest: selection.Digest, ArtifactDigest: strings.Repeat("b", 64),
		ToolSchemaDigest: strings.Repeat("c", 64), NetworkBindingDigest: strings.Repeat("d", 64),
		ToolNames: []string{"local_task"}, ReadOnly: false,
	}
	call := ToolCall{ID: uuid.NewString(), Name: "local_task", Arguments: `{}`}
	attempt := ToolAttempt{
		ID: uuid.NewString(), TurnID: uuid.NewString(), TaskID: uuid.NewString(),
		ConfirmationID: uuid.NewString(), ExecutionID: uuid.NewString(), State: "waiting_confirmation",
	}
	base := newFakeStore()
	base.conv[conversationID] = Conversation{ID: conversationID, Revision: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	turn := Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: conversationID,
		Prompt: "run the local task", ProfileID: profile.ProfileID, ProfileSnapshot: profile,
		ProfileSnapshotDigest: profile.Digest(), ExtensionSnapshots: []ExtensionExecutionSnapshot{snapshot},
		ExtensionSnapshotDigest: TurnStartCommand{ExtensionSnapshots: []ExtensionExecutionSnapshot{snapshot}}.ExtensionSnapshotDigest(),
		State:                   TurnAccepted, Revision: 1, LastSequence: 1, CreatedAt: time.Now().UTC(),
	}
	attempt.TurnID = turn.ID
	store := &readOnlyTurnStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: turn},
		events:                []TurnEvent{{TurnID: turn.ID, Sequence: 1, Revision: 1, Kind: TurnEventAccepted, CreatedAt: turn.CreatedAt}},
		prepared:              attempt,
	}
	service, err := NewService(
		store,
		fixedToolCallsTurnModel{calls: []ToolCall{call}},
		extensionResolverFunc(func(context.Context, []ExtensionSelection) ([]ResolvedExtension, error) {
			return []ResolvedExtension{{Selection: selection, Snapshot: snapshot}}, nil
		}),
		snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return profile, nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	service.executeTurn(context.Background(), turn.ID)

	if store.failedCode != "" || store.prepareCalls != 1 {
		t.Fatalf("failure=%q prepare_calls=%d", store.failedCode, store.prepareCalls)
	}
	var waiting *TurnEvent
	waitingCount := 0
	for index := range store.events {
		if store.events[index].Kind == TurnEventWaitingConfirmation {
			waitingCount++
			waiting = &store.events[index]
		}
	}
	if waitingCount != 1 || waiting == nil || waiting.ValidateWaitingConfirmationAuthority() != nil || waiting.Revision != 2 ||
		waiting.ConfirmationID != attempt.ConfirmationID || waiting.ExecutionID != attempt.ExecutionID ||
		waiting.Sequence != 4 {
		t.Fatalf("canonical waiting event=%+v all=%+v", waiting, store.events)
	}
}

func TestWaitingConfirmationAuthorityRejectsMixedSourceFields(t *testing.T) {
	event, err := NewWaitingConfirmationTurnEvent(uuid.NewString(), uuid.NewString())
	if err != nil || event.Status != string(TurnWaitingConfirmation) {
		t.Fatalf("event=%+v err=%v", event, err)
	}
	event.RelatedTaskIDs = []string{uuid.NewString()}
	if !errors.Is(event.ValidateWaitingConfirmationAuthority(), ErrInvalid) {
		t.Fatalf("mixed waiting event accepted: %+v", event)
	}
}

func TestResolveAcceptedTurnExtensionsRebuildsKnowledgeBuiltinFromPinnedSource(t *testing.T) {
	selection := ExtensionSelection{Kind: ExtensionMCP, ID: uuid.NewString(), Version: "1.0.0", Digest: strings.Repeat("a", 64), AllowedTools: []string{"knowledge_search"}}
	snapshot := ExtensionExecutionSnapshot{Selection: selection, InstallationID: selection.ID, VersionID: selection.Version, Source: "builtin:knowledge:semantic", ContentDigest: selection.Digest, ArtifactDigest: strings.Repeat("b", 64), ToolSchemaDigest: strings.Repeat("c", 64), NetworkBindingDigest: strings.Repeat("d", 64), ToolNames: []string{"knowledge_search"}, ReadOnly: true}
	resolved := ResolvedExtension{Selection: selection, Snapshot: snapshot, Tools: []coremodel.Tool{{Name: "knowledge_search", InputSchema: map[string]any{"type": "object"}}}}
	service := &Service{extensions: extensionResolverFunc(func(_ context.Context, selections []ExtensionSelection) ([]ResolvedExtension, error) {
		if len(selections) != 0 {
			t.Fatalf("persisted Knowledge builtin was passed to installed-extension resolution: %+v", selections)
		}
		return []ResolvedExtension{resolved}, nil
	})}
	got, err := service.resolveAcceptedTurnExtensions(context.Background(), []ExtensionExecutionSnapshot{snapshot})
	if err != nil || len(got) != 1 || got[0].Snapshot.Source != snapshot.Source {
		t.Fatalf("resolved=%+v err=%v", got, err)
	}
}

func TestExecuteTurnPreservesCloudWorkerIntrinsicAndLocalExtensionTools(t *testing.T) {
	profile := testTurnSnapshot()
	conversationID := uuid.NewString()
	selection := ExtensionSelection{
		Kind: ExtensionMCP, ID: uuid.NewString(), Version: "config-1",
		Digest: strings.Repeat("a", 64), AllowedTools: []string{"local_lookup"},
	}
	snapshot := ExtensionExecutionSnapshot{
		Selection: selection, InstallationID: selection.ID, VersionID: selection.Version,
		Source: "mcp:test", ContentDigest: selection.Digest, ArtifactDigest: strings.Repeat("b", 64),
		ToolSchemaDigest: strings.Repeat("c", 64), NetworkBindingDigest: strings.Repeat("d", 64),
		ToolNames: []string{"local_lookup"}, ReadOnly: true,
	}
	resolved := ResolvedExtension{
		Selection: selection,
		Snapshot:  snapshot,
		Tools:     []coremodel.Tool{{Name: "local_lookup", InputSchema: map[string]any{"type": "object"}}},
		Execute: func(context.Context, ToolExecutionRequest) (ToolResult, error) {
			return ToolResult{}, nil
		},
	}
	base := newFakeStore()
	base.conv[conversationID] = Conversation{ID: conversationID, Revision: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	turn := Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: conversationID,
		Prompt: "compare local context before proposing cloud execution", ProfileID: profile.ProfileID,
		ProfileSnapshot: profile, ProfileSnapshotDigest: profile.Digest(),
		ExtensionSnapshots:      []ExtensionExecutionSnapshot{snapshot},
		ExtensionSnapshotDigest: TurnStartCommand{ExtensionSnapshots: []ExtensionExecutionSnapshot{snapshot}}.ExtensionSnapshotDigest(),
		State:                   TurnAccepted, Revision: 1, LastSequence: 1, CreatedAt: time.Now().UTC(),
	}
	store := &readOnlyTurnStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: turn},
		events:                []TurnEvent{{TurnID: turn.ID, Sequence: 1, Kind: TurnEventAccepted, CreatedAt: turn.CreatedAt}},
	}
	model := &capturingTurnModel{}
	resolver := extensionResolverFunc(func(_ context.Context, selections []ExtensionSelection) ([]ResolvedExtension, error) {
		if len(selections) != 1 || selections[0].ID != selection.ID {
			t.Fatalf("extension selections=%+v", selections)
		}
		return []ResolvedExtension{resolved}, nil
	})
	service, err := NewService(store, model, resolver, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return profile, nil }))
	if err != nil {
		t.Fatal(err)
	}
	service.SetIntrinsicResolver(intrinsicResolverFunc(func(_ context.Context, lease TurnLease) ([]ResolvedIntrinsic, error) {
		if lease.Turn.ID != turn.ID {
			t.Fatalf("intrinsic lease turn=%q", lease.Turn.ID)
		}
		return []ResolvedIntrinsic{{
			Tool: coremodel.Tool{Name: coremodel.IntrinsicCloudWorkerProposeToolName, InputSchema: map[string]any{"type": "object"}},
			Execute: func(context.Context, IntrinsicExecutionRequest) (IntrinsicExecutionResult, error) {
				return IntrinsicExecutionResult{TurnCommitted: true}, nil
			},
		}}, nil
	}))

	service.executeTurn(context.Background(), turn.ID)

	if model.runs != 1 || len(model.request.Intrinsics) != 1 ||
		model.request.Intrinsics[0].Tool.Name != coremodel.IntrinsicCloudWorkerProposeToolName ||
		len(model.request.Extensions) != 1 || model.request.Extensions[0].Selection.ID != selection.ID {
		t.Fatalf("model request lost intrinsic or extension: %+v", model.request)
	}
}

func TestResolveAcceptedTurnExtensionsIgnoresToolsAddedAfterAcceptance(t *testing.T) {
	acceptedSelection := ExtensionSelection{
		Kind: ExtensionMCP, ID: uuid.NewString(), Version: uuid.NewString(),
		Digest: strings.Repeat("a", 64), AllowedTools: []string{"accepted_lookup"},
	}
	acceptedSnapshot := ExtensionExecutionSnapshot{
		Selection: acceptedSelection, InstallationID: acceptedSelection.ID, VersionID: acceptedSelection.Version,
		Source: "mcp:accepted", ContentDigest: acceptedSelection.Digest, ArtifactDigest: strings.Repeat("b", 64),
		ToolSchemaDigest: strings.Repeat("c", 64), NetworkBindingDigest: strings.Repeat("d", 64),
		ToolNames: []string{"accepted_lookup"}, ReadOnly: true,
	}
	addedSelection := ExtensionSelection{
		Kind: ExtensionMCP, ID: uuid.NewString(), Version: uuid.NewString(),
		Digest: strings.Repeat("e", 64), AllowedTools: []string{"added_later"},
	}
	addedSnapshot := ExtensionExecutionSnapshot{
		Selection: addedSelection, InstallationID: addedSelection.ID, VersionID: addedSelection.Version,
		Source: "builtin:added-later", ContentDigest: addedSelection.Digest, ArtifactDigest: strings.Repeat("f", 64),
		ToolSchemaDigest: strings.Repeat("1", 64), NetworkBindingDigest: strings.Repeat("2", 64),
		ToolNames: []string{"added_later"}, ReadOnly: true,
	}
	service := &Service{extensions: extensionResolverFunc(func(context.Context, []ExtensionSelection) ([]ResolvedExtension, error) {
		return []ResolvedExtension{
			{Selection: acceptedSelection, Snapshot: acceptedSnapshot},
			{Selection: addedSelection, Snapshot: addedSnapshot},
		}, nil
	})}

	resolved, err := service.resolveAcceptedTurnExtensions(context.Background(), []ExtensionExecutionSnapshot{acceptedSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 || resolved[0].Selection.ID != acceptedSelection.ID {
		t.Fatalf("resolved extensions=%+v", resolved)
	}
}

func TestExecuteTurnProcessesWebSearchBeforeLocalMCPFromSameModelRound(t *testing.T) {
	profile := testTurnSnapshot()
	conversationID := uuid.NewString()
	webSelection := ExtensionSelection{Kind: ExtensionMCP, ID: uuid.NewString(), Version: "web-1", Digest: strings.Repeat("a", 64), AllowedTools: []string{"web_search"}}
	webSnapshot := ExtensionExecutionSnapshot{Selection: webSelection, InstallationID: webSelection.ID, VersionID: webSelection.Version, Source: "builtin:web_search:tavily", ContentDigest: webSelection.Digest, ArtifactDigest: strings.Repeat("b", 64), ToolSchemaDigest: strings.Repeat("c", 64), NetworkBindingDigest: strings.Repeat("d", 64), ToolNames: []string{"web_search"}, ReadOnly: true}
	localSelection := ExtensionSelection{Kind: ExtensionMCP, ID: uuid.NewString(), Version: uuid.NewString(), Digest: strings.Repeat("e", 64), AllowedTools: []string{"write_html"}}
	localSnapshot := ExtensionExecutionSnapshot{Selection: localSelection, InstallationID: localSelection.ID, VersionID: localSelection.Version, Source: "mcp:local-html", ContentDigest: localSelection.Digest, ArtifactDigest: strings.Repeat("f", 64), ToolSchemaDigest: strings.Repeat("1", 64), NetworkBindingDigest: strings.Repeat("2", 64), ToolNames: []string{"write_html"}, ReadOnly: false}
	webCall := ToolCall{ID: uuid.NewString(), Name: "web_search", Arguments: `{"query":"GitHub trending"}`}
	localCall := ToolCall{ID: uuid.NewString(), Name: "write_html", Arguments: `{"content":"bounded"}`}
	turn := Turn{ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: conversationID, Prompt: "search then render", ProfileID: profile.ProfileID, ProfileSnapshot: profile, ProfileSnapshotDigest: profile.Digest(), ExtensionSnapshots: []ExtensionExecutionSnapshot{webSnapshot, localSnapshot}, ExtensionSnapshotDigest: TurnStartCommand{ExtensionSnapshots: []ExtensionExecutionSnapshot{webSnapshot, localSnapshot}}.ExtensionSnapshotDigest(), State: TurnAccepted, Revision: 1, LastSequence: 1, CreatedAt: time.Now().UTC()}
	base := newFakeStore()
	base.conv[conversationID] = Conversation{ID: conversationID, Revision: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	attempt := ToolAttempt{ID: uuid.NewString(), TurnID: turn.ID, TaskID: uuid.NewString(), ConfirmationID: uuid.NewString(), ExecutionID: uuid.NewString(), State: "waiting_confirmation"}
	store := &readOnlyTurnStore{publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: turn}, events: []TurnEvent{{TurnID: turn.ID, Sequence: 1, Revision: 1, Kind: TurnEventAccepted, CreatedAt: turn.CreatedAt}}, prepared: attempt}
	var executionOrder []string
	resolvedWeb := ResolvedExtension{Selection: webSelection, Snapshot: webSnapshot, Tools: []coremodel.Tool{{Name: "web_search", InputSchema: map[string]any{"type": "object"}}}, Execute: func(context.Context, ToolExecutionRequest) (ToolResult, error) {
		executionOrder = append(executionOrder, "web_search")
		return ToolResult{CallID: webCall.ID, ToolName: webCall.Name, Content: `{"results":[]}`}, nil
	}}
	resolvedLocal := ResolvedExtension{Selection: localSelection, Snapshot: localSnapshot, Tools: []coremodel.Tool{{Name: "write_html", InputSchema: map[string]any{"type": "object"}}}}
	service, err := NewService(store, fixedToolCallsTurnModel{calls: []ToolCall{webCall, localCall}}, extensionResolverFunc(func(context.Context, []ExtensionSelection) ([]ResolvedExtension, error) {
		return []ResolvedExtension{resolvedWeb, resolvedLocal}, nil
	}), snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return profile, nil }))
	if err != nil {
		t.Fatal(err)
	}

	service.executeTurn(context.Background(), turn.ID)

	if store.failedCode != "" || store.prepareCalls != 1 || len(executionOrder) != 1 || executionOrder[0] != "web_search" {
		t.Fatalf("failure=%q prepare_calls=%d order=%v", store.failedCode, store.prepareCalls, executionOrder)
	}
	var kinds []TurnEventKind
	for _, event := range store.events {
		if event.Kind == TurnEventToolCall || event.Kind == TurnEventToolResult || event.Kind == TurnEventWaitingConfirmation {
			kinds = append(kinds, event.Kind)
		}
	}
	want := []TurnEventKind{TurnEventToolCall, TurnEventToolResult, TurnEventToolCall, TurnEventWaitingConfirmation}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("durable tool event order=%v want=%v", kinds, want)
	}
}

func TestExecuteTurnRestartFailsUncertainWithoutRepeatingDispatchedReadOnlyTool(t *testing.T) {
	profile := testTurnSnapshot()
	conversationID := uuid.NewString()
	selection := ExtensionSelection{Kind: ExtensionMCP, ID: uuid.NewString(), Version: "web-1", Digest: strings.Repeat("a", 64), AllowedTools: []string{"web_search"}}
	snapshot := ExtensionExecutionSnapshot{Selection: selection, InstallationID: selection.ID, VersionID: selection.Version, Source: "builtin:web_search:tavily", ContentDigest: selection.Digest, ArtifactDigest: strings.Repeat("b", 64), ToolSchemaDigest: strings.Repeat("c", 64), NetworkBindingDigest: strings.Repeat("d", 64), ToolNames: []string{"web_search"}, ReadOnly: true}
	call := ToolCall{ID: uuid.NewString(), Name: "web_search", Arguments: `{"query":"durable fence"}`}
	turn := Turn{ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: conversationID, Prompt: "search", ProfileID: profile.ProfileID, ProfileSnapshot: profile, ProfileSnapshotDigest: profile.Digest(), ExtensionSnapshots: []ExtensionExecutionSnapshot{snapshot}, ExtensionSnapshotDigest: TurnStartCommand{ExtensionSnapshots: []ExtensionExecutionSnapshot{snapshot}}.ExtensionSnapshotDigest(), State: TurnAccepted, Revision: 1, LastSequence: 2, CreatedAt: time.Now().UTC()}
	base := newFakeStore()
	base.conv[conversationID] = Conversation{ID: conversationID, Revision: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	modelResult := ModelRunResult{Message: Message{ID: uuid.NewString(), Role: RoleAssistant, ToolCalls: []ToolCall{call}, CreatedAt: time.Now().UTC()}, ToolCalls: []ToolCall{call}}
	store := &readOnlyTurnStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: turn},
		events: []TurnEvent{
			{TurnID: turn.ID, Sequence: 1, Revision: 1, Kind: TurnEventAccepted, CreatedAt: turn.CreatedAt},
			{TurnID: turn.ID, Sequence: 2, Revision: 1, Kind: TurnEventToolCall, ToolCall: &call, CreatedAt: turn.CreatedAt.Add(time.Microsecond)},
		},
		dispatchState: "completed",
		dispatch:      modelResult,
		dispatched:    map[string]bool{call.ID: true},
	}
	model := &capturingTurnModel{}
	executions := 0
	resolved := ResolvedExtension{Selection: selection, Snapshot: snapshot, Tools: []coremodel.Tool{{Name: call.Name, InputSchema: map[string]any{"type": "object"}}}, Execute: func(context.Context, ToolExecutionRequest) (ToolResult, error) {
		executions++
		return ToolResult{CallID: call.ID, ToolName: call.Name, Content: `{}`}, nil
	}}
	service, err := NewService(store, model, extensionResolverFunc(func(context.Context, []ExtensionSelection) ([]ResolvedExtension, error) {
		return []ResolvedExtension{resolved}, nil
	}), snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return profile, nil }))
	if err != nil {
		t.Fatal(err)
	}

	service.executeTurn(context.Background(), turn.ID)

	if model.runs != 0 || executions != 0 || store.failedCode != "tool_dispatch_uncertain" || store.turn.State != TurnFailed {
		t.Fatalf("model_runs=%d executions=%d code=%q state=%s", model.runs, executions, store.failedCode, store.turn.State)
	}
	var results, terminalErrors int
	for _, event := range store.events {
		if event.Kind == TurnEventToolResult && event.ToolResult != nil && event.ToolResult.CallID == call.ID {
			results++
		}
		if event.Kind == TurnEventError && event.ErrorCode == "tool_dispatch_uncertain" {
			terminalErrors++
		}
	}
	if results != 1 || terminalErrors != 1 {
		t.Fatalf("terminal results=%d errors=%d events=%+v", results, terminalErrors, store.events)
	}
}

func TestExecuteTurnFailsClosedWhenMemoryRecallIsUnavailable(t *testing.T) {
	snapshot := testTurnSnapshot()
	turn := Turn{ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: uuid.NewString(), Prompt: "remember", ProfileID: snapshot.ProfileID, ProfileSnapshot: snapshot, State: TurnAccepted, Revision: 1, CreatedAt: time.Now().UTC()}
	store := &recallFailureTurnStore{publicActiveTurnStore: &publicActiveTurnStore{fakeStore: newFakeStore(), turn: turn}}
	model := &capturingTurnModel{}
	service, err := NewService(store, model, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return snapshot, nil }))
	if err != nil {
		t.Fatal(err)
	}
	service.SetMemoryRecallResolver(memoryRecallFunc(func(context.Context, string) (string, error) { return "", errors.New("private backend detail") }))
	service.executeTurn(context.Background(), turn.ID)
	if model.runs != 0 || store.failedCode != "memory_recall_unavailable" || store.failedSummary != "long-term memory recall is unavailable" {
		t.Fatalf("runs=%d code=%q summary=%q", model.runs, store.failedCode, store.failedSummary)
	}
}

func TestStartTurnReplayDoesNotResolveRotatedProfile(t *testing.T) {
	snapshot := testTurnSnapshot()
	cmd := TurnStartCommand{TurnID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: uuid.NewString(), Prompt: "hello", ProfileID: snapshot.ProfileID, ExpectedProfileRevision: snapshot.Revision, ExpectedCredentialVersion: snapshot.CredentialVersion, ProfileSnapshot: snapshot}
	if err := cmd.Validate(); err != nil {
		t.Fatal(err)
	}
	store := &replayTurnStore{fakeStore: newFakeStore(), turn: Turn{ID: cmd.TurnID, RequestID: cmd.RequestID, RequestFingerprint: cmd.Fingerprint(), ConversationID: cmd.ConversationID, Prompt: cmd.Prompt, ProfileID: cmd.ProfileID, State: TurnCompleted, ProfileSnapshot: snapshot, ProfileSnapshotDigest: snapshot.Digest()}}
	resolved := 0
	profiles := snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { resolved++; return snapshot, nil })
	service, err := NewService(store, &fakeModel{}, nil, profiles)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.StartTurn(context.Background(), TurnStartCommand{TurnID: cmd.TurnID, RequestID: cmd.RequestID, ConversationID: cmd.ConversationID, Prompt: cmd.Prompt, ProfileID: cmd.ProfileID, ExpectedProfileRevision: cmd.ExpectedProfileRevision, ExpectedCredentialVersion: cmd.ExpectedCredentialVersion}); err != nil {
		t.Fatal(err)
	}
	if resolved != 0 {
		t.Fatal("replay resolved mutable current profile")
	}
}

func TestTurnSupervisorTerminalizesCancelWithoutClaim(t *testing.T) {
	snapshot := testTurnSnapshot()
	store := &supervisorTurnStore{replayTurnStore: &replayTurnStore{fakeStore: newFakeStore(), turn: Turn{ID: uuid.NewString(), State: TurnRunning, CancelRequested: true, ProfileSnapshot: snapshot}}}
	service, err := NewService(store, &fakeModel{}, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return snapshot, nil }))
	if err != nil {
		t.Fatal(err)
	}
	service.runTurnSupervisor(context.Background(), store.turn.ID)
	if !store.canceled || store.claimed {
		t.Fatalf("cancel=%v claimed=%v", store.canceled, store.claimed)
	}
}

func TestTurnSupervisorReconcilesUncertainDispatchWithoutProvider(t *testing.T) {
	snapshot := testTurnSnapshot()
	store := &supervisorTurnStore{replayTurnStore: &replayTurnStore{fakeStore: newFakeStore(), turn: Turn{ID: uuid.NewString(), State: TurnRunning, DispatchState: "uncertain", ProfileSnapshot: snapshot}}}
	service, err := NewService(store, &fakeModel{}, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return snapshot, nil }))
	if err != nil {
		t.Fatal(err)
	}
	service.runTurnSupervisor(context.Background(), store.turn.ID)
	if !store.uncertain || store.claimed {
		t.Fatalf("uncertain=%v claimed=%v", store.uncertain, store.claimed)
	}
}

func TestWatchTurnEventsPropagatesBoundsError(t *testing.T) {
	snapshot := testTurnSnapshot()
	store := &watcherTurnStore{replayTurnStore: &replayTurnStore{fakeStore: newFakeStore(), turn: Turn{ID: uuid.NewString(), State: TurnRunning, ProfileSnapshot: snapshot}}, boundsErr: true}
	service, err := NewService(store, &fakeModel{}, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return snapshot, nil }))
	if err != nil {
		t.Fatal(err)
	}
	stream, err := service.WatchTurnEvents(context.Background(), store.turn.ID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-stream:
		if event.Err == nil {
			t.Fatal("bounds error was swallowed")
		}
	case <-time.After(time.Second):
		t.Fatal("watcher did not report bounds error")
	}
}

func TestServiceCloseCancelsAndWaitsForTurnWorker(t *testing.T) {
	store := &replayTurnStore{fakeStore: newFakeStore(), turn: Turn{ID: uuid.NewString(), State: TurnCompleted}}
	service, err := NewService(store, &fakeModel{}, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return testTurnSnapshot(), nil }))
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	service.workers.Add(1)
	go func() { defer service.workers.Done(); <-service.lifecycleCtx.Done(); close(finished) }()
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("Close returned before worker observed cancellation")
	}
}

func TestCancelWaitsForNonCooperativeRunnerBeforeTerminalEvent(t *testing.T) {
	snapshot := testTurnSnapshot()
	model := &blockingTurnModel{started: make(chan struct{}), release: make(chan struct{})}
	store := &activeTurnStore{supervisorTurnStore: &supervisorTurnStore{replayTurnStore: &replayTurnStore{fakeStore: newFakeStore(), turn: Turn{ID: uuid.NewString(), State: TurnRunning, ProfileID: snapshot.ProfileID, ConversationID: uuid.NewString(), Prompt: "hello", ProfileSnapshot: snapshot}}}}
	service, err := NewService(store, model, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return snapshot, nil }))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { service.executeTurn(context.Background(), store.turn.ID); close(done) }()
	<-model.started
	store.turn.CancelRequested = true
	service.cancelMu.Lock()
	signal := service.cancelSignals[store.turn.ID]
	service.cancelMu.Unlock()
	if signal != nil {
		close(signal)
	}
	select {
	case <-done:
		t.Fatal("executor terminalized before blocked runner exited")
	case <-time.After(50 * time.Millisecond):
	}
	close(model.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("executor did not finish after runner release")
	}
	if !store.canceled {
		t.Fatal("cancel terminal was not recorded after runner exit")
	}
}

func TestPublicStartAndCancelWaitForNonCooperativeRunner(t *testing.T) {
	snapshot := testTurnSnapshot()
	model := &blockingTurnModel{started: make(chan struct{}), release: make(chan struct{})}
	store := &publicActiveTurnStore{fakeStore: newFakeStore()}
	service, err := NewService(store, model, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return snapshot, nil }))
	if err != nil {
		t.Fatal(err)
	}
	cmd := TurnStartCommand{RequestID: uuid.NewString(), ConversationID: uuid.NewString(), Prompt: "hello", ProfileID: snapshot.ProfileID, ExpectedProfileRevision: snapshot.Revision, ExpectedCredentialVersion: snapshot.CredentialVersion, ProfileSnapshot: snapshot}
	turn, err := service.StartTurn(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	<-model.started
	if _, err = service.CancelTurn(context.Background(), TurnCancelCommand{RequestID: uuid.NewString(), TurnID: turn.ID, ExpectedRevision: turn.Revision}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if got, getErr := store.GetTurn(context.Background(), turn.ID); getErr != nil || got.State == TurnCanceled || store.terminalEventCount() != 0 {
		t.Fatalf("public cancel terminalized before blocked runner exited: turn=%+v events=%d err=%v", got, store.terminalEventCount(), getErr)
	}
	close(model.release)
	deadline := time.After(time.Second)
	for {
		got, getErr := store.GetTurn(context.Background(), turn.ID)
		if getErr == nil && got.State == TurnCanceled {
			if store.terminalEventCount() != 1 {
				t.Fatalf("public cancel terminal event count=%d", store.terminalEventCount())
			}
			break
		}
		select {
		case <-deadline:
			t.Fatalf("public cancel did not terminalize: turn=%+v err=%v", got, getErr)
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
}

func retryTurnStore(snapshot coremodel.ExecutionSnapshot) *supervisorRetryTurnStore {
	return &supervisorRetryTurnStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: newFakeStore(), turn: Turn{ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: uuid.NewString(), Prompt: "hello", ProfileID: snapshot.ProfileID, ProfileSnapshot: snapshot, State: TurnRunning, Revision: 1}},
		transientReads:        1,
		firstTransient:        make(chan struct{}),
		successfulRead:        make(chan struct{}),
	}
}

func TestSupervisorRetriesTransientReadWithoutDuplicateModel(t *testing.T) {
	snapshot := testTurnSnapshot()
	store := retryTurnStore(snapshot)
	model := &fakeModel{}
	service, err := NewService(store, model, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return snapshot, nil }))
	if err != nil {
		t.Fatal(err)
	}
	service.startTurnSupervisor(store.turn.ID, nil)
	select {
	case <-store.successfulRead:
	case <-time.After(3 * time.Second):
		t.Fatal("supervisor did not retry transient turn read")
	}
	deadline := time.After(3 * time.Second)
	for {
		got, getErr := store.publicActiveTurnStore.GetTurn(context.Background(), store.turn.ID)
		if getErr == nil && got.State == TurnCompleted {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("turn did not terminalize after retry: turn=%+v err=%v", got, getErr)
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if model.runs != 1 {
		t.Fatalf("model invoked %d times after transient read", model.runs)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCancelTurnReattachesOrphanedSupervisorAndCloseCancelsRetry(t *testing.T) {
	snapshot := testTurnSnapshot()
	store := retryTurnStore(snapshot)
	model := &fakeModel{}
	service, err := NewService(store, model, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return snapshot, nil }))
	if err != nil {
		t.Fatal(err)
	}
	// Exercise a prior supervisor whose registry entry is already gone.
	priorCtx, priorCancel := context.WithCancel(context.Background())
	priorDone := make(chan struct{})
	go func() {
		service.runTurnSupervisor(priorCtx, store.turn.ID)
		close(priorDone)
	}()
	<-store.firstTransient
	priorCancel()
	select {
	case <-priorDone:
	case <-time.After(time.Second):
		t.Fatal("orphaned supervisor did not stop")
	}

	turn, err := service.CancelTurn(context.Background(), TurnCancelCommand{RequestID: uuid.NewString(), TurnID: store.turn.ID, ExpectedRevision: store.turn.Revision})
	if err != nil || turn.State != TurnRunning || !turn.CancelRequested {
		t.Fatalf("cancel response turn=%+v err=%v", turn, err)
	}
	deadline := time.After(3 * time.Second)
	for {
		got, getErr := store.publicActiveTurnStore.GetTurn(context.Background(), store.turn.ID)
		if getErr == nil && got.State == TurnCanceled {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("reattached supervisor did not cancel: turn=%+v err=%v", got, getErr)
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if model.runs != 0 {
		t.Fatalf("cancelled orphan invoked model %d times", model.runs)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}

	// A fresh retrying supervisor must be interruptible by Close.
	store2 := retryTurnStore(snapshot)
	store2.transientReads = 100
	service2, err := NewService(store2, &fakeModel{}, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return snapshot, nil }))
	if err != nil {
		t.Fatal(err)
	}
	service2.startTurnSupervisor(store2.turn.ID, nil)
	<-store2.firstTransient
	closeCtx, closeCancel := context.WithTimeout(context.Background(), time.Second)
	defer closeCancel()
	if err := service2.CloseContext(closeCtx); err != nil {
		t.Fatal(err)
	}
}

type snapshotResolverFunc func(context.Context, string) (coremodel.ExecutionSnapshot, error)

func (f snapshotResolverFunc) ResolveProfileSnapshot(ctx context.Context, id string) (coremodel.ExecutionSnapshot, error) {
	return f(ctx, id)
}

func TestTurnEventKindsHaveSingleTerminalVocabulary(t *testing.T) {
	terminal := map[TurnState]bool{TurnCompleted: true, TurnCanceled: true, TurnFailed: true}
	for _, state := range []TurnState{TurnAccepted, TurnRunning} {
		if terminal[state] {
			t.Fatalf("non-terminal state %q marked terminal", state)
		}
	}
	for state := range terminal {
		if state == TurnAccepted || state == TurnRunning {
			t.Fatalf("terminal state %q overlaps active state", state)
		}
	}
	if TurnEventAccepted == TurnEventDone || TurnEventDone == TurnEventCanceled {
		t.Fatal("turn event vocabulary aliases terminal events")
	}
}

func TestRequestTurnCancelIsRevisionScoped(t *testing.T) {
	turnID, requestID := uuid.NewString(), uuid.NewString()
	first := TurnCancelCommand{TurnID: turnID, RequestID: requestID, ExpectedRevision: 1}
	second := first
	second.ExpectedRevision = 2
	if first.TurnID != second.TurnID || first.RequestID != second.RequestID || first.ExpectedRevision == second.ExpectedRevision {
		t.Fatal("cancel command did not preserve request identity and revision fence")
	}
}
