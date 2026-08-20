package coreconversation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type terminalResultTurnModel struct {
	result   ModelRunResult
	failure  error
	delta    string
	requests []ModelRunRequest
}

func (m *terminalResultTurnModel) Run(context.Context, ModelRunRequest) (ModelRunResult, error) {
	return ModelRunResult{}, errors.New("non-streaming model path must not be used")
}

func (m *terminalResultTurnModel) Stream(_ context.Context, request ModelRunRequest, emit func(ModelDelta) error) (ModelRunResult, error) {
	m.requests = append(m.requests, request)
	if m.delta != "" && emit != nil {
		if err := emit(ModelDelta{Text: m.delta}); err != nil {
			return ModelRunResult{}, err
		}
	}
	return m.result, m.failure
}

func assertUsefulTerminalMarkdown(t *testing.T, turn Turn, partial string) {
	t.Helper()
	if turn.State != TurnCompleted || turn.Response == nil {
		t.Fatalf("turn did not complete with a response: %+v", turn)
	}
	content := turn.Response.Message.Content
	for _, heading := range []string{"## Completed work", "## Best conclusion", "## Incomplete items", "## Stop reason"} {
		if !strings.Contains(content, heading) {
			t.Fatalf("terminal Markdown omitted %q: %q", heading, content)
		}
	}
	if partial != "" && !strings.Contains(content, partial) {
		t.Fatalf("terminal Markdown lost partial output %q: %q", partial, content)
	}
}

func newTerminalFinalizationFixture(t *testing.T, model ModelRunner) (*Service, *timeoutTurnStore, Turn) {
	t.Helper()
	snapshot := testTurnSnapshot()
	conversationID := uuid.NewString()
	createdAt := time.Now().UTC()
	base := newFakeStore()
	base.conv[conversationID] = Conversation{ID: conversationID, Revision: 1, CreatedAt: createdAt, UpdatedAt: createdAt}
	turn := Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: conversationID,
		Prompt: "produce a useful final answer", ProfileID: snapshot.ProfileID,
		ProfileSnapshot: snapshot, ProfileSnapshotDigest: snapshot.Digest(), State: TurnAccepted,
		Revision: 1, LastSequence: 1, CreatedAt: createdAt,
	}
	store := &timeoutTurnStore{readOnlyTurnStore: &readOnlyTurnStore{
		publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base, turn: turn},
		events:                []TurnEvent{{TurnID: turn.ID, Sequence: 1, Revision: 1, Kind: TurnEventAccepted, CreatedAt: createdAt}},
	}}
	service, err := NewService(store, model, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) {
		return snapshot, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	return service, store, turn
}

func TestExecuteTurnFinalizesProviderFailureAsUsefulMarkdown(t *testing.T) {
	model := &terminalResultTurnModel{failure: coremodel.ErrInvalidResponse}
	service, store, turn := newTerminalFinalizationFixture(t, model)

	service.executeTurn(context.Background(), turn.ID)

	current, err := store.GetTurn(context.Background(), turn.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertUsefulTerminalMarkdown(t, current, "")
	if len(model.requests) != 2 {
		t.Fatalf("provider attempts=%d, want one ordinary and one final attempt", len(model.requests))
	}
	if len(model.requests[1].Intrinsics) != 0 || len(model.requests[1].Extensions) != 0 || len(model.requests[1].ExtensionSnapshots) != 0 {
		t.Fatalf("final provider request retained tools: %+v", model.requests[1])
	}
}

func TestExecuteTurnFinalizesInvalidOrEmptyOutputAsUsefulMarkdown(t *testing.T) {
	for _, test := range []struct {
		name   string
		result ModelRunResult
	}{
		{name: "empty", result: ModelRunResult{Done: true}},
		{name: "invalid terminal", result: ModelRunResult{Done: true, Message: Message{Role: RoleAssistant, ReasoningContent: "reasoning only"}}},
		{name: "invalid continuation", result: ModelRunResult{Continue: true, Done: true, Message: Message{Role: RoleAssistant, Content: "invalid continuation"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			model := &terminalResultTurnModel{result: test.result}
			service, store, turn := newTerminalFinalizationFixture(t, model)

			service.executeTurn(context.Background(), turn.ID)

			current, err := store.GetTurn(context.Background(), turn.ID)
			if err != nil {
				t.Fatal(err)
			}
			assertUsefulTerminalMarkdown(t, current, "")
			if len(model.requests) != 2 {
				t.Fatalf("provider attempts=%d, want one ordinary and one final attempt", len(model.requests))
			}
			if len(model.requests[1].Intrinsics) != 0 || len(model.requests[1].Extensions) != 0 || len(model.requests[1].ExtensionSnapshots) != 0 {
				t.Fatalf("final provider request retained tools: %+v", model.requests[1])
			}
		})
	}
}

func TestExecuteTurnFinalizationFallbackPreservesPartialOutput(t *testing.T) {
	const partial = "Collected two durable facts before the provider stopped."
	model := &terminalResultTurnModel{delta: partial, failure: context.DeadlineExceeded}
	service, store, turn := newTerminalFinalizationFixture(t, model)

	service.executeTurn(context.Background(), turn.ID)

	current, err := store.GetTurn(context.Background(), turn.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertUsefulTerminalMarkdown(t, current, partial)
}

func TestExecuteTurnUsesSingleSuccessfulFinalProviderResponse(t *testing.T) {
	model := &retrySequenceModel{outcomes: []retryModelOutcome{{err: coremodel.ErrInvalidResponse}, {}}}
	service, store, turn := newTerminalFinalizationFixture(t, model)

	service.executeTurn(context.Background(), turn.ID)
	service.executeTurn(context.Background(), turn.ID)

	current, err := store.GetTurn(context.Background(), turn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.State != TurnCompleted || current.Response == nil || current.Response.Message.Content != "ok" {
		t.Fatalf("terminal turn=%+v", current)
	}
	if model.callCount() != 2 || current.ModelDispatchCount != 2 || !store.finalDispatched {
		t.Fatalf("provider calls=%d dispatch_count=%d final_dispatched=%v", model.callCount(), current.ModelDispatchCount, store.finalDispatched)
	}
	if request := model.requests[1]; len(request.Intrinsics) != 0 || len(request.Extensions) != 0 || len(request.ExtensionSnapshots) != 0 {
		t.Fatalf("finalization request retained tools: %+v", request)
	}
}

func TestExecuteTurnFinalizationHasIndependentDispatchAllowance(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Turn)
		want   uint32
		reason TurnFinalizationReason
	}{
		{
			name: "ordinary dispatch count exhausted",
			mutate: func(turn *Turn) {
				turn.ModelDispatchCount = MaxTurnModelDispatches
			},
			want:   MaxTurnModelDispatches + MaxTurnFinalizationDispatches,
			reason: TurnFinalizationModelBudget,
		},
		{
			name: "ordinary active time exhausted",
			mutate: func(turn *Turn) {
				turn.ModelDispatchCount = 7
				turn.ModelActiveDuration = MaxTurnModelActiveDuration
			},
			want:   8,
			reason: TurnFinalizationModelBudget,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			model := &terminalResultTurnModel{result: ModelRunResult{Done: true, Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "bounded final answer", CreatedAt: time.Now().UTC()}}}
			service, store, turn := newTerminalFinalizationFixture(t, model)
			test.mutate(&store.turn)

			service.executeTurn(context.Background(), turn.ID)
			service.executeTurn(context.Background(), turn.ID)

			current, err := store.GetTurn(context.Background(), turn.ID)
			if err != nil {
				t.Fatal(err)
			}
			if current.State != TurnCompleted || current.Response == nil || current.Response.Message.Content != "bounded final answer" {
				t.Fatalf("terminal turn=%+v", current)
			}
			if len(model.requests) != 1 || current.ModelDispatchCount != test.want || store.finalization == nil || store.finalization.Reason != test.reason || !store.finalDispatched {
				t.Fatalf("requests=%d dispatch_count=%d intent=%+v final_dispatched=%v", len(model.requests), current.ModelDispatchCount, store.finalization, store.finalDispatched)
			}
			if request := model.requests[0]; len(request.Intrinsics) != 0 || len(request.Extensions) != 0 || len(request.ExtensionSnapshots) != 0 {
				t.Fatalf("finalization request retained tools: %+v", request)
			}
		})
	}
}
