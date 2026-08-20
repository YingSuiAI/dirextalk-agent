package coreconversation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type timeoutTurnModel struct {
	runCalls    int
	streamCalls int
}

type budgetBlockingTurnModel struct {
	streamCalls int
	requests    []ModelRunRequest
}

type failingTurnModel struct {
	failure     error
	runCalls    int
	streamCalls int
}

func (m *failingTurnModel) Run(context.Context, ModelRunRequest) (ModelRunResult, error) {
	m.runCalls++
	return ModelRunResult{}, errors.New("non-streaming model path must not be used")
}

func (m *failingTurnModel) Stream(context.Context, ModelRunRequest, func(ModelDelta) error) (ModelRunResult, error) {
	m.streamCalls++
	return ModelRunResult{}, m.failure
}

func (*budgetBlockingTurnModel) Run(context.Context, ModelRunRequest) (ModelRunResult, error) {
	return ModelRunResult{}, errors.New("non-streaming model path must not be used")
}

func (m *budgetBlockingTurnModel) Stream(ctx context.Context, request ModelRunRequest, _ func(ModelDelta) error) (ModelRunResult, error) {
	m.streamCalls++
	m.requests = append(m.requests, request)
	if m.streamCalls > 1 {
		return ModelRunResult{Done: true, Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "final answer", CreatedAt: time.Now().UTC()}}, nil
	}
	<-ctx.Done()
	return ModelRunResult{}, ctx.Err()
}

func (m *timeoutTurnModel) Run(context.Context, ModelRunRequest) (ModelRunResult, error) {
	m.runCalls++
	return ModelRunResult{}, errors.New("non-streaming model path must not be used")
}

func (m *timeoutTurnModel) Stream(context.Context, ModelRunRequest, func(ModelDelta) error) (ModelRunResult, error) {
	m.streamCalls++
	return ModelRunResult{}, fmt.Errorf("provider request: %w", coremodel.ErrStreamIdleTimeout)
}

type timeoutTurnStore struct {
	*readOnlyTurnStore
	uncertainCode    string
	uncertainSummary string
	failedSummary    string
}

type timeoutRecoveryStore struct {
	*supervisorTurnStore
	code    string
	summary string
}

func (s *timeoutRecoveryStore) FailTurnUncertain(_ context.Context, _ string, code, summary string) (Turn, error) {
	s.code, s.summary = code, summary
	s.turn.State = TurnFailed
	return s.turn, nil
}

func (s *timeoutTurnStore) MarkTurnModelUncertain(_ context.Context, _ TurnLease, code, summary string) error {
	s.uncertainCode, s.uncertainSummary = code, summary
	s.dispatchState = "uncertain"
	return nil
}

func (s *timeoutTurnStore) FailTurn(_ context.Context, _ TurnLease, code, summary string) (Turn, error) {
	s.failedCode, s.failedSummary = code, summary
	s.turn.State = TurnFailed
	return s.turn, nil
}

func TestExecuteTurnClassifiesProviderTimeoutWithoutReplay(t *testing.T) {
	snapshot := testTurnSnapshot()
	conversationID := uuid.NewString()
	base := newFakeStore()
	base.conv[conversationID] = Conversation{ID: conversationID, Revision: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	turn := Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: conversationID,
		Prompt: "summarize a large tool result", ProfileID: snapshot.ProfileID,
		ProfileSnapshot: snapshot, ProfileSnapshotDigest: snapshot.Digest(), State: TurnAccepted,
		Revision: 1, LastSequence: 1, CreatedAt: time.Now().UTC(),
	}
	store := &timeoutTurnStore{readOnlyTurnStore: &readOnlyTurnStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: turn},
		events:                []TurnEvent{{TurnID: turn.ID, Sequence: 1, Revision: 1, Kind: TurnEventAccepted, CreatedAt: turn.CreatedAt}},
	}}
	model := &timeoutTurnModel{}
	service, err := NewService(store, model, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) {
		return snapshot, nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	service.executeTurn(context.Background(), turn.ID)

	if store.turn.State != TurnCompleted || store.turn.Response == nil {
		t.Fatalf("terminal turn=%+v code=%q summary=%q", store.turn, store.failedCode, store.failedSummary)
	}
	assertUsefulTerminalMarkdown(t, store.turn, "")
	if store.turn.TerminalCode != modelResponseTimeoutCode || store.turn.TerminalSummary != modelResponseTimeoutSummary {
		t.Fatalf("durable finalization code=%q summary=%q", store.turn.TerminalCode, store.turn.TerminalSummary)
	}
	if model.runCalls != 0 || model.streamCalls != 2 {
		t.Fatalf("model Run calls=%d Stream calls=%d", model.runCalls, model.streamCalls)
	}
}

func TestExecuteTurnPersistsPreciseModelFailureClassification(t *testing.T) {
	for _, test := range []struct {
		name    string
		failure error
		code    string
		summary string
	}{
		{name: "invalid local request", failure: coremodel.ErrInvalidCompletionRequest, code: modelRequestInvalidCode, summary: modelRequestInvalidSummary},
		{name: "invalid provider response", failure: coremodel.ErrInvalidResponse, code: modelProviderResponseCode, summary: modelProviderResponseSummary},
		{name: "truncated provider stream", failure: coremodel.ErrStreamTruncated, code: modelProviderTruncatedCode, summary: modelProviderTruncatedSummary},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testTurnSnapshot()
			conversationID := uuid.NewString()
			base := newFakeStore()
			base.conv[conversationID] = Conversation{ID: conversationID, Revision: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
			turn := Turn{
				ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: conversationID,
				Prompt: "run model", ProfileID: snapshot.ProfileID,
				ProfileSnapshot: snapshot, ProfileSnapshotDigest: snapshot.Digest(), State: TurnAccepted,
				Revision: 1, LastSequence: 1, CreatedAt: time.Now().UTC(),
			}
			store := &timeoutTurnStore{readOnlyTurnStore: &readOnlyTurnStore{
				publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: turn},
				events:                []TurnEvent{{TurnID: turn.ID, Sequence: 1, Revision: 1, Kind: TurnEventAccepted, CreatedAt: turn.CreatedAt}},
			}}
			model := &failingTurnModel{failure: test.failure}
			service, err := NewService(store, model, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) {
				return snapshot, nil
			}))
			if err != nil {
				t.Fatal(err)
			}

			service.executeTurn(context.Background(), turn.ID)

			if store.turn.State != TurnCompleted || store.turn.Response == nil {
				t.Fatalf("terminal turn=%+v code=%q summary=%q", store.turn, store.failedCode, store.failedSummary)
			}
			assertUsefulTerminalMarkdown(t, store.turn, "")
			if store.turn.TerminalCode != test.code || store.turn.TerminalSummary != test.summary {
				t.Fatalf("durable finalization code=%q summary=%q", store.turn.TerminalCode, store.turn.TerminalSummary)
			}
			if model.runCalls != 0 || model.streamCalls != 2 {
				t.Fatalf("model Run calls=%d Stream calls=%d", model.runCalls, model.streamCalls)
			}
		})
	}
}

func TestTurnModelBudgetUsesStabilityCaps(t *testing.T) {
	if MaxTurnModelDispatches != 24 {
		t.Fatalf("model dispatch cap=%d", MaxTurnModelDispatches)
	}
	if MaxTurnModelActiveDuration != 20*time.Minute {
		t.Fatalf("model active duration cap=%s", MaxTurnModelActiveDuration)
	}
}

func TestExecuteTurnAppliesPersistedModelActiveDurationBudget(t *testing.T) {
	snapshot := testTurnSnapshot()
	conversationID := uuid.NewString()
	base := newFakeStore()
	base.conv[conversationID] = Conversation{ID: conversationID, Revision: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	turn := Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: conversationID,
		Prompt: "finish within the remaining budget", ProfileID: snapshot.ProfileID,
		ProfileSnapshot: snapshot, ProfileSnapshotDigest: snapshot.Digest(), State: TurnAccepted,
		Revision: 1, LastSequence: 1, ModelActiveDuration: MaxTurnModelActiveDuration - 20*time.Millisecond,
		CreatedAt: time.Now().UTC(),
	}
	store := &timeoutTurnStore{readOnlyTurnStore: &readOnlyTurnStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: turn},
		events:                []TurnEvent{{TurnID: turn.ID, Sequence: 1, Revision: 1, Kind: TurnEventAccepted, CreatedAt: turn.CreatedAt}},
	}}
	model := &budgetBlockingTurnModel{}
	service, err := NewService(store, model, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) {
		return snapshot, nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	service.executeTurn(context.Background(), turn.ID)

	if store.turn.State != TurnCompleted || store.turn.Response == nil {
		t.Fatalf("terminal turn=%+v code=%q summary=%q", store.turn, store.failedCode, store.failedSummary)
	}
	if store.turn.Response.Message.Content != "final answer" {
		t.Fatalf("terminal response=%q", store.turn.Response.Message.Content)
	}
	if store.turn.TerminalCode != modelBudgetExhaustedCode || store.turn.TerminalSummary != modelBudgetExhaustedSummary {
		t.Fatalf("durable finalization code=%q summary=%q", store.turn.TerminalCode, store.turn.TerminalSummary)
	}
	if model.streamCalls != 2 {
		t.Fatalf("model Stream calls=%d", model.streamCalls)
	}
	if request := model.requests[1]; len(request.Intrinsics) != 0 || len(request.Extensions) != 0 || len(request.ExtensionSnapshots) != 0 {
		t.Fatalf("finalization request retained tools: %+v", request)
	}
}

func TestModelDispatchFailureClassification(t *testing.T) {
	for _, failure := range []error{
		fmt.Errorf("wrapped: %w", coremodel.ErrInvalidCompletionRequest),
		fmt.Errorf("wrapped: %w", coremodel.ErrCompletionRequestTooLarge),
	} {
		code, summary := classifyModelDispatchFailure(failure)
		if code != modelRequestInvalidCode || summary != modelRequestInvalidSummary {
			t.Fatalf("invalid request=%v code=%q summary=%q", failure, code, summary)
		}
	}
	for _, failure := range []error{
		fmt.Errorf("wrapped: %w", context.DeadlineExceeded),
		fmt.Errorf("wrapped: %w", coremodel.ErrStreamIdleTimeout),
	} {
		code, summary := classifyModelDispatchFailure(failure)
		if code != modelResponseTimeoutCode || summary != modelResponseTimeoutSummary {
			t.Fatalf("timeout=%v code=%q summary=%q", failure, code, summary)
		}
	}
	code, summary := classifyModelDispatchFailure(errors.New("provider unavailable"))
	if code != modelDispatchUncertainCode || summary != modelDispatchUncertainSummary {
		t.Fatalf("provider code=%q summary=%q", code, summary)
	}
	for _, test := range []struct {
		failure error
		code    string
		summary string
	}{
		{failure: coremodel.ErrInvalidResponse, code: modelProviderResponseCode, summary: modelProviderResponseSummary},
		{failure: coremodel.ErrStreamTruncated, code: modelProviderTruncatedCode, summary: modelProviderTruncatedSummary},
	} {
		code, summary = classifyModelDispatchFailure(test.failure)
		if code != test.code || summary != test.summary {
			t.Fatalf("provider failure=%v code=%q summary=%q", test.failure, code, summary)
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	profile := coremodel.Profile{
		ID: uuid.NewString(), DisplayName: "test", Provider: coremodel.ProviderOpenAICompatible,
		ModelKind: coremodel.ModelKindConversation, BaseURL: server.URL, Model: "test", APIKey: "test",
		MaxOutputTokens: coremodel.DefaultConversationMaxOutputTokens, Revision: 1,
	}
	client, err := coremodel.NewClient(profile, coremodel.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	_, failure := client.Stream(context.Background(), coremodel.CompletionRequest{Messages: []coremodel.Message{{Role: coremodel.RoleUser, Content: "hello"}}})
	code, summary = classifyModelDispatchFailure(failure)
	if code != modelProviderRejectedCode || summary != modelProviderRejectedSummary {
		t.Fatalf("4xx code=%q summary=%q failure=%v", code, summary, failure)
	}
}

func TestSupervisorPreservesPersistedModelFailureClassificationWithoutReplay(t *testing.T) {
	for _, test := range []struct {
		name    string
		code    string
		summary string
	}{
		{name: "timeout", code: modelResponseTimeoutCode, summary: modelResponseTimeoutSummary},
		{name: "invalid local request", code: modelRequestInvalidCode, summary: modelRequestInvalidSummary},
		{name: "invalid provider response", code: modelProviderResponseCode, summary: modelProviderResponseSummary},
		{name: "truncated provider stream", code: modelProviderTruncatedCode, summary: modelProviderTruncatedSummary},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testTurnSnapshot()
			turn := Turn{
				ID: uuid.NewString(), State: TurnRunning, DispatchState: "uncertain",
				TerminalCode: test.code, TerminalSummary: test.summary,
			}
			store := &timeoutRecoveryStore{supervisorTurnStore: &supervisorTurnStore{replayTurnStore: &replayTurnStore{fakeStore: newFakeStore(), turn: turn}}}
			model := &timeoutTurnModel{}
			service, err := NewService(store, model, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) {
				return snapshot, nil
			}))
			if err != nil {
				t.Fatal(err)
			}

			service.runTurnSupervisor(context.Background(), turn.ID)

			if store.code != test.code || store.summary != test.summary {
				t.Fatalf("recovered code=%q summary=%q", store.code, store.summary)
			}
			if model.runCalls != 0 || model.streamCalls != 0 {
				t.Fatalf("uncertain provider dispatch replayed Run=%d Stream=%d", model.runCalls, model.streamCalls)
			}
		})
	}
}
