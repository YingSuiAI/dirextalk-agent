package coreconversation

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type retrySequenceModel struct {
	mu       sync.Mutex
	outcomes []retryModelOutcome
	requests []ModelRunRequest
}

type retryModelOutcome struct {
	delta *ModelDelta
	err   error
}

func (m *retrySequenceModel) Run(ctx context.Context, request ModelRunRequest) (ModelRunResult, error) {
	return m.Stream(ctx, request, nil)
}

func (m *retrySequenceModel) Stream(_ context.Context, request ModelRunRequest, emit func(ModelDelta) error) (ModelRunResult, error) {
	m.mu.Lock()
	index := len(m.requests)
	m.requests = append(m.requests, request)
	outcome := retryModelOutcome{}
	if index < len(m.outcomes) {
		outcome = m.outcomes[index]
	}
	m.mu.Unlock()
	if outcome.delta != nil && emit != nil {
		if err := emit(*outcome.delta); err != nil {
			return ModelRunResult{}, err
		}
	}
	if outcome.err != nil {
		return ModelRunResult{}, outcome.err
	}
	return ModelRunResult{Done: true, Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "ok", CreatedAt: time.Now().UTC()}}, nil
}

func (m *retrySequenceModel) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.requests)
}

type attemptTurnStore struct {
	*readOnlyTurnStore
	runtime       *TurnRuntimeSnapshot
	retryable     bool
	retryFailures []ModelAttemptFailure
	uncertain     []ModelAttemptFailure
}

type admissionFailureStore struct {
	*publicActiveTurnStore
	starts int
}

func (s *admissionFailureStore) StartTurnWithRuntime(ctx context.Context, cmd TurnStartCommand, runtime TurnRuntimeSnapshot) (Turn, error) {
	s.starts++
	return s.publicActiveTurnStore.StartTurnWithRuntime(ctx, cmd, runtime)
}

func (s *attemptTurnStore) PrepareTurnRuntimeAdmission(context.Context, TurnStartCommand) (Turn, error) {
	return s.turn, nil
}

func (s *attemptTurnStore) StartTurnWithRuntime(_ context.Context, _ TurnStartCommand, runtime TurnRuntimeSnapshot) (Turn, error) {
	s.runtime = &runtime
	s.turn.RuntimeSnapshot = &runtime
	return s.turn, nil
}

func (s *attemptTurnStore) BindTurnModelRuntime(_ context.Context, _ TurnLease, runtime TurnRuntimeSnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runtime != nil && s.runtime.Digest() != runtime.Digest() {
		return ErrTurnRuntimeIncompatible
	}
	copy := runtime
	s.runtime = &copy
	return nil
}

func (s *attemptTurnStore) ValidateTurnRuntime(_ context.Context, _ TurnLease, runtime TurnRuntimeSnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.turn.RuntimeSnapshot == nil || s.turn.RuntimeSnapshot.Digest() != runtime.Digest() {
		return ErrTurnRuntimeIncompatible
	}
	return nil
}

func (s *attemptTurnStore) MarkTurnModelRetryable(_ context.Context, _ TurnLease, failure ModelAttemptFailure) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dispatchState != "dispatched" || s.retryable || s.directive.FinalizationReason != "" || failure.Validate() != nil {
		return ErrConflict
	}
	s.retryFailures = append(s.retryFailures, failure)
	s.retryable = true
	s.turn.ModelDispatchStartedAt = time.Time{}
	return nil
}

func (s *attemptTurnStore) PrepareTurnModelRetry(context.Context, TurnLease) (Turn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.turn.RuntimeSnapshot == nil || s.turn.RuntimeSnapshot.ExecutionPolicy.Validate() != nil {
		return Turn{}, ErrTurnRuntimeIncompatible
	}
	if s.turn.ModelDispatchCount >= s.turn.RuntimeSnapshot.ExecutionPolicy.MaxModelDispatches {
		return Turn{}, ErrModelBudgetExhausted
	}
	if !s.retryable || s.directive.FinalizationReason != "" {
		return Turn{}, ErrConflict
	}
	s.retryable = false
	s.turn.ModelDispatchCount++
	s.turn.ModelDispatchStartedAt = time.Now().UTC()
	return s.turn, nil
}

func (s *attemptTurnStore) MarkTurnModelAttemptUncertain(_ context.Context, _ TurnLease, failure ModelAttemptFailure) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uncertain = append(s.uncertain, failure)
	return nil
}

func newAttemptTurnService(t *testing.T, model *retrySequenceModel) (*Service, *attemptTurnStore, Turn) {
	t.Helper()
	profile := testTurnSnapshot()
	profile.RequestDialect = coremodel.DialectOpenAICompatibleChatV1
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	conversationID := uuid.NewString()
	turn := Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: conversationID,
		Prompt: "hello", ProfileID: profile.ProfileID, ProfileSnapshot: profile, ProfileSnapshotDigest: profile.Digest(),
		State: TurnAccepted, Revision: 1, LastSequence: 1, CreatedAt: now, UpdatedAt: now,
	}
	base := newFakeStore()
	base.conv[conversationID] = Conversation{ID: conversationID, Revision: 1, CreatedAt: now, UpdatedAt: now}
	store := &attemptTurnStore{readOnlyTurnStore: &readOnlyTurnStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: turn},
		events:                []TurnEvent{{TurnID: turn.ID, Sequence: 1, Revision: 1, Kind: TurnEventAccepted, CreatedAt: now}},
	}}
	service, err := NewService(store, model, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return profile, nil }))
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	runtime, err := service.buildTurnAdmissionRuntime(context.Background(), turn, nil, "", TurnExecutionDeep, TurnConstrainedWorkflow{})
	if err != nil {
		t.Fatal(err)
	}
	turn.RuntimeSnapshot = &runtime
	store.turn = turn
	return service, store, turn
}

func TestTurnRetriesOneConnectFailureBeforeOutputAndChargesPhysicalAttempt(t *testing.T) {
	connectFailure := errors.Join(coremodel.ErrProviderUnavailable, coremodel.ErrProviderConnectFailure)
	model := &retrySequenceModel{outcomes: []retryModelOutcome{{err: connectFailure}, {}}}
	service, store, turn := newAttemptTurnService(t, model)
	service.executeTurn(context.Background(), turn.ID)
	if model.callCount() != 2 || store.turn.ModelDispatchCount != 2 || len(store.retryFailures) != 1 {
		t.Fatalf("calls=%d attempts=%d retry_failures=%+v", model.callCount(), store.turn.ModelDispatchCount, store.retryFailures)
	}
	if store.turn.State != TurnCompleted {
		t.Fatalf("turn state=%s failure=%q", store.turn.State, store.failedCode)
	}
}

func TestTurnDoesNotRetryAfterVisibleDelta(t *testing.T) {
	connectFailure := errors.Join(coremodel.ErrProviderUnavailable, coremodel.ErrProviderConnectFailure)
	for name, delta := range map[string]ModelDelta{
		"text":      {Text: "partial"},
		"tool call": {ToolCall: &ToolCall{ID: uuid.NewString(), Name: "tool", Arguments: `{}`}},
	} {
		t.Run(name, func(t *testing.T) {
			model := &retrySequenceModel{outcomes: []retryModelOutcome{{delta: &delta, err: connectFailure}, {}}}
			service, store, turn := newAttemptTurnService(t, model)
			service.executeTurn(context.Background(), turn.ID)
			if model.callCount() != 2 || store.turn.ModelDispatchCount != 2 || len(store.retryFailures) != 0 {
				t.Fatalf("calls=%d attempts=%d retry_failures=%+v", model.callCount(), store.turn.ModelDispatchCount, store.retryFailures)
			}
			if request := model.requests[1]; len(request.Intrinsics) != 0 || len(request.Extensions) != 0 || len(request.ExtensionSnapshots) != 0 {
				t.Fatalf("finalization request retained tools: %+v", request)
			}
		})
	}
}

func TestTurnRetriesAtMostOnce(t *testing.T) {
	connectFailure := errors.Join(coremodel.ErrProviderUnavailable, coremodel.ErrProviderConnectFailure)
	model := &retrySequenceModel{outcomes: []retryModelOutcome{{err: connectFailure}, {err: connectFailure}, {}}}
	service, store, turn := newAttemptTurnService(t, model)
	service.executeTurn(context.Background(), turn.ID)
	if model.callCount() != 3 || store.turn.ModelDispatchCount != 3 || len(store.retryFailures) != 1 || store.turn.State != TurnCompleted {
		t.Fatalf("calls=%d attempts=%d retry=%d uncertain=%d", model.callCount(), store.turn.ModelDispatchCount, len(store.retryFailures), len(store.uncertain))
	}
	if request := model.requests[2]; len(request.Intrinsics) != 0 || len(request.Extensions) != 0 || len(request.ExtensionSnapshots) != 0 {
		t.Fatalf("finalization request retained tools: %+v", request)
	}
}

func TestTurnRetryCannotExceedPhysicalAttemptBudget(t *testing.T) {
	connectFailure := errors.Join(coremodel.ErrProviderUnavailable, coremodel.ErrProviderConnectFailure)
	model := &retrySequenceModel{outcomes: []retryModelOutcome{{err: connectFailure}, {}}}
	service, store, turn := newAttemptTurnService(t, model)
	store.turn.ModelDispatchCount = MaxAdmittedTurnModelDispatches - 1
	service.executeTurn(context.Background(), turn.ID)
	if model.callCount() != 2 || store.turn.ModelDispatchCount != MaxAdmittedTurnModelDispatches+MaxTurnFinalizationDispatches || store.turn.State != TurnCompleted {
		t.Fatalf("calls=%d attempts=%d", model.callCount(), store.turn.ModelDispatchCount)
	}
	if request := model.requests[1]; len(request.Intrinsics) != 0 || len(request.Extensions) != 0 || len(request.ExtensionSnapshots) != 0 {
		t.Fatalf("finalization request retained tools: %+v", request)
	}
}

func TestAdmittedTurnRejectsChangedRuntimeBeforeProviderDispatch(t *testing.T) {
	model := &retrySequenceModel{}
	service, store, turn := newAttemptTurnService(t, model)
	old, err := NewTurnRuntimeSnapshot("superseded runtime", turn.ProfileSnapshot, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	store.turn.RuntimeSnapshot = &old
	service.executeTurn(context.Background(), turn.ID)
	if model.callCount() != 0 || store.failedCode != turnRuntimeIncompatibleCode || store.turn.ModelDispatchCount != 0 {
		t.Fatalf("calls=%d failure=%q attempts=%d", model.callCount(), store.failedCode, store.turn.ModelDispatchCount)
	}
}

func TestPersistedScheduledRuntimeNeverResolvesIntrinsicsDuringExecution(t *testing.T) {
	model := &retrySequenceModel{}
	service, store, turn := newAttemptTurnService(t, model)
	resolverCalls := 0
	service.SetIntrinsicResolver(intrinsicResolverFunc(func(context.Context, TurnLease) ([]ResolvedIntrinsic, error) {
		resolverCalls++
		return nil, errors.New("scheduled runtime must not resolve intrinsics")
	}))
	runtime, err := service.buildTurnAdmissionRuntime(context.Background(), turn, nil, TurnIntrinsicPolicyNone, TurnExecutionScheduled, NewScheduledTurnWorkflow(coretask.ScheduledCapabilityScheduledNote))
	if err != nil {
		t.Fatal(err)
	}
	store.turn.RuntimeSnapshot = &runtime
	service.executeTurn(context.Background(), turn.ID)
	if resolverCalls != 0 || model.callCount() != 1 || len(model.requests[0].Intrinsics) != 0 || store.failedCode != "" || store.turn.State != TurnCompleted {
		t.Fatalf("resolver_calls=%d model_calls=%d request_intrinsics=%+v failure=%q state=%s", resolverCalls, model.callCount(), model.requests[0].Intrinsics, store.failedCode, store.turn.State)
	}
}

func TestAdmissionRuntimeBuildFailureDoesNotAcceptTurn(t *testing.T) {
	profile := testTurnSnapshot()
	store := &admissionFailureStore{publicActiveTurnStore: &publicActiveTurnStore{fakeStore: newFakeStore()}}
	service, err := NewService(store, &retrySequenceModel{}, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) { return profile, nil }))
	if err != nil {
		t.Fatal(err)
	}
	service.SetIntrinsicResolver(intrinsicResolverFunc(func(context.Context, TurnLease) ([]ResolvedIntrinsic, error) {
		return nil, errors.New("runtime catalog unavailable")
	}))
	_, err = service.StartTurn(context.Background(), TurnStartCommand{
		TurnID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: uuid.NewString(),
		Prompt: "hello", ProfileID: profile.ProfileID, ExpectedProfileRevision: profile.Revision,
		ExpectedCredentialVersion: profile.CredentialVersion, ProfileSnapshot: profile,
	})
	if err == nil || store.starts != 0 || store.turn.ID != "" {
		t.Fatalf("err=%v starts=%d turn=%+v", err, store.starts, store.turn)
	}
}

func TestSameAdmittedRuntimeProducesIdenticalRequestAfterRestart(t *testing.T) {
	firstModel := &retrySequenceModel{}
	firstService, _, firstTurn := newAttemptTurnService(t, firstModel)
	firstService.executeTurn(context.Background(), firstTurn.ID)
	secondModel := &retrySequenceModel{}
	secondService, secondStore, _ := newAttemptTurnService(t, secondModel)
	secondStore.turn = firstTurn
	secondStore.publicActiveTurnStore.turn = firstTurn
	secondStore.fakeStore.conv = map[string]Conversation{firstTurn.ConversationID: {ID: firstTurn.ConversationID, Revision: 1, CreatedAt: firstTurn.CreatedAt, UpdatedAt: firstTurn.CreatedAt}}
	secondService.executeTurn(context.Background(), firstTurn.ID)
	if firstModel.callCount() != 1 || secondModel.callCount() != 1 || !reflect.DeepEqual(firstModel.requests[0], secondModel.requests[0]) {
		t.Fatalf("requests differ after restart\nfirst=%+v\nsecond=%+v", firstModel.requests, secondModel.requests)
	}
}
