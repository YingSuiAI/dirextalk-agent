package coreconversation

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type timeoutTurnModel struct{ runs int }

func (m *timeoutTurnModel) Run(context.Context, ModelRunRequest) (ModelRunResult, error) {
	m.runs++
	return ModelRunResult{}, fmt.Errorf("provider request: %w", context.DeadlineExceeded)
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

	if store.turn.State != TurnFailed || store.failedCode != modelResponseTimeoutCode || store.failedSummary != modelResponseTimeoutSummary {
		t.Fatalf("terminal turn=%+v code=%q summary=%q", store.turn, store.failedCode, store.failedSummary)
	}
	if store.uncertainCode != modelResponseTimeoutCode || store.uncertainSummary != modelResponseTimeoutSummary {
		t.Fatalf("durable uncertain code=%q summary=%q", store.uncertainCode, store.uncertainSummary)
	}
	if model.runs != 1 {
		t.Fatalf("model dispatch count=%d want=1", model.runs)
	}
}

func TestModelDispatchFailureClassification(t *testing.T) {
	code, summary := classifyModelDispatchFailure(fmt.Errorf("wrapped: %w", context.DeadlineExceeded))
	if code != modelResponseTimeoutCode || summary != modelResponseTimeoutSummary {
		t.Fatalf("timeout code=%q summary=%q", code, summary)
	}
	code, summary = classifyModelDispatchFailure(errors.New("provider unavailable"))
	if code != modelDispatchUncertainCode || summary != modelDispatchUncertainSummary {
		t.Fatalf("provider code=%q summary=%q", code, summary)
	}
}

func TestSupervisorPreservesPersistedTimeoutClassificationWithoutReplay(t *testing.T) {
	snapshot := testTurnSnapshot()
	turn := Turn{
		ID: uuid.NewString(), State: TurnRunning, DispatchState: "uncertain",
		TerminalCode: modelResponseTimeoutCode, TerminalSummary: modelResponseTimeoutSummary,
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

	if store.code != modelResponseTimeoutCode || store.summary != modelResponseTimeoutSummary {
		t.Fatalf("recovered code=%q summary=%q", store.code, store.summary)
	}
	if model.runs != 0 {
		t.Fatalf("uncertain provider dispatch replayed %d times", model.runs)
	}
}
