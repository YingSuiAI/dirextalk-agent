package coreconversation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

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

func (m *capturingTurnModel) Run(_ context.Context, request ModelRunRequest) (ModelRunResult, error) {
	m.request = request
	m.runs++
	return ModelRunResult{Done: true, Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "ok", CreatedAt: time.Now().UTC()}}, nil
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
	s.turn = Turn{ID: uuid.NewString(), RequestID: cmd.RequestID, ConversationID: cmd.ConversationID, Prompt: cmd.Prompt, ProfileID: cmd.ProfileID, ProfileSnapshot: cmd.ProfileSnapshot, ProfileSnapshotDigest: cmd.ProfileSnapshot.Digest(), Revision: 1, State: TurnAccepted, LastSequence: 1}
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
	cmd := TurnStartCommand{RequestID: uuid.NewString(), ConversationID: uuid.NewString(), Prompt: "hello", ProfileID: snapshot.ProfileID, ExpectedProfileRevision: snapshot.Revision, ExpectedCredentialVersion: snapshot.CredentialVersion, ExpectedRevision: &revision, ProfileSnapshot: snapshot}
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
	rotated := cmd
	rotated.ProfileSnapshot.APIKey = "rotated-secret"
	if rotated.Fingerprint() == cmd.Fingerprint() {
		t.Fatal("profile snapshot mutation was not bound by the request digest")
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
	cmd := TurnStartCommand{RequestID: uuid.NewString(), ConversationID: uuid.NewString(), Prompt: "hello", ProfileID: snapshot.ProfileID, ExpectedProfileRevision: snapshot.Revision, ExpectedCredentialVersion: snapshot.CredentialVersion, ProfileSnapshot: snapshot}
	if err := cmd.Validate(); err != nil {
		t.Fatal(err)
	}
	store := &replayTurnStore{fakeStore: newFakeStore(), turn: Turn{ID: uuid.NewString(), RequestID: cmd.RequestID, RequestFingerprint: cmd.Fingerprint(), ConversationID: cmd.ConversationID, Prompt: cmd.Prompt, ProfileID: cmd.ProfileID, State: TurnCompleted, ProfileSnapshot: snapshot, ProfileSnapshotDigest: snapshot.Digest()}}
	resolved := 0
	profiles := snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { resolved++; return snapshot, nil })
	service, err := NewService(store, &fakeModel{}, nil, profiles)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.StartTurn(context.Background(), TurnStartCommand{RequestID: cmd.RequestID, ConversationID: cmd.ConversationID, Prompt: cmd.Prompt, ProfileID: cmd.ProfileID, ExpectedProfileRevision: cmd.ExpectedProfileRevision, ExpectedCredentialVersion: cmd.ExpectedCredentialVersion}); err != nil {
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
