package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type blockingAdapterModel struct{ started chan struct{} }

func (m *blockingAdapterModel) Run(ctx context.Context, request core.ModelRunRequest) (core.ModelRunResult, error) {
	return m.Stream(ctx, request, nil)
}

func (m *blockingAdapterModel) Stream(ctx context.Context, _ core.ModelRunRequest, _ func(core.ModelDelta) error) (core.ModelRunResult, error) {
	select {
	case m.started <- struct{}{}:
	case <-ctx.Done():
		return core.ModelRunResult{}, ctx.Err()
	}
	<-ctx.Done()
	return core.ModelRunResult{}, ctx.Err()
}

type prechargedBudgetStore struct{ *CoreConversationStore }

func (s *prechargedBudgetStore) StartTurnWithRuntime(ctx context.Context, command core.TurnStartCommand, runtime core.TurnRuntimeSnapshot) (core.Turn, error) {
	turn, err := s.CoreConversationStore.StartTurnWithRuntime(ctx, command, runtime)
	if err != nil {
		return core.Turn{}, err
	}
	result, err := s.pool.Exec(ctx, `UPDATE core_conversation_turns SET model_dispatch_count=$2 WHERE turn_id=$1 AND state='accepted'`, turn.ID, runtime.ExecutionPolicy.MaxModelDispatches)
	if err != nil {
		return core.Turn{}, err
	}
	if result.RowsAffected() != 1 {
		return core.Turn{}, core.ErrConflict
	}
	return s.CoreConversationStore.GetTurn(ctx, turn.ID)
}

func adapterChatCommand(snapshot coremodel.ExecutionSnapshot) core.ChatCommand {
	return core.ChatCommand{
		RequestID: uuid.NewString(), Prompt: "adapter parity", ProfileID: snapshot.ProfileID,
		ExpectedProfileRevision: snapshot.Revision, ExpectedCredentialVersion: snapshot.CredentialVersion,
	}
}

func adapterTurnCommand(command core.ChatCommand) core.TurnStartCommand {
	return core.TurnStartCommand{
		RequestID: command.RequestID, ConversationID: command.ConversationID, Prompt: command.Prompt,
		ProfileID: command.ProfileID, ExpectedProfileRevision: command.ExpectedProfileRevision,
		ExpectedCredentialVersion: command.ExpectedCredentialVersion, ExpectedRevision: command.ExpectedRevision,
	}
}

func waitAdapterTurn(t *testing.T, store *CoreConversationStore, requestID string) core.Turn {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		turn, err := store.GetTurnByRequestID(context.Background(), requestID)
		if err == nil {
			return turn
		}
		if !errors.Is(err, core.ErrConflict) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("durable turn was not accepted")
	return core.Turn{}
}

func watchAdapterTurn(t *testing.T, service *core.Service, turnID string) []core.TurnEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := service.WatchTurnEvents(ctx, turnID, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var events []core.TurnEvent
	for event := range stream {
		if event.Err != nil {
			t.Fatal(event.Err)
		}
		events = append(events, event)
	}
	return events
}

func closeAdapterService(t *testing.T, service *core.Service) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := service.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestChatStreamAndStartTurnSharePostgresCancellation(t *testing.T) {
	h := openTurnDB(t)
	snapshot := turnCommand().ProfileSnapshot
	createTestProfile(context.Background(), t, h.store.Store, snapshot.ProfileID, snapshot.Model, snapshot.APIKey)
	model := &blockingAdapterModel{started: make(chan struct{}, 1)}
	service, err := core.NewService(h.store, model, nil, integrationSnapshotResolver{snapshot: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeAdapterService(t, service) })

	for _, mode := range []string{"chat", "stream_chat", "start_turn"} {
		t.Run(mode, func(t *testing.T) {
			command := adapterChatCommand(snapshot)
			switch mode {
			case "chat":
				result := make(chan error, 1)
				go func() { _, runErr := service.Chat(context.Background(), command); result <- runErr }()
				<-model.started
				turn := waitAdapterTurn(t, h.store, command.RequestID)
				if _, err := service.CancelTurn(context.Background(), core.TurnCancelCommand{RequestID: uuid.NewString(), TurnID: turn.ID}); err != nil {
					t.Fatal(err)
				}
				if err := <-result; !errors.Is(err, core.ErrCanceled) {
					t.Fatalf("chat cancel err=%v", err)
				}
			case "stream_chat":
				stream, err := service.StreamChat(context.Background(), command)
				if err != nil {
					t.Fatal(err)
				}
				<-model.started
				turn := waitAdapterTurn(t, h.store, command.RequestID)
				if _, err = service.CancelTurn(context.Background(), core.TurnCancelCommand{RequestID: uuid.NewString(), TurnID: turn.ID}); err != nil {
					t.Fatal(err)
				}
				var canceled bool
				for event := range stream {
					canceled = canceled || event.Kind == core.EventError && event.ErrCode == "canceled"
				}
				if !canceled {
					t.Fatal("StreamChat did not project durable cancellation")
				}
			case "start_turn":
				turn, err := service.StartTurn(context.Background(), adapterTurnCommand(command))
				if err != nil {
					t.Fatal(err)
				}
				<-model.started
				if _, err = service.CancelTurn(context.Background(), core.TurnCancelCommand{RequestID: uuid.NewString(), TurnID: turn.ID}); err != nil {
					t.Fatal(err)
				}
				events := watchAdapterTurn(t, service, turn.ID)
				if len(events) == 0 || events[len(events)-1].Kind != core.TurnEventCanceled {
					t.Fatalf("events=%+v", events)
				}
			}
			turn := waitAdapterTurn(t, h.store, command.RequestID)
			if turn.State != core.TurnCanceled {
				t.Fatalf("turn=%+v", turn)
			}
		})
	}
}

func TestChatStreamAndStartTurnSharePostgresModelBudget(t *testing.T) {
	h := openTurnDB(t)
	snapshot := turnCommand().ProfileSnapshot
	createTestProfile(context.Background(), t, h.store.Store, snapshot.ProfileID, snapshot.Model, snapshot.APIKey)
	store := &prechargedBudgetStore{CoreConversationStore: h.store}
	service, err := core.NewService(store, integrationConversationRunner{}, nil, integrationSnapshotResolver{snapshot: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeAdapterService(t, service) })

	for _, mode := range []string{"chat", "stream_chat", "start_turn"} {
		t.Run(mode, func(t *testing.T) {
			command := adapterChatCommand(snapshot)
			switch mode {
			case "chat":
				if response, err := service.Chat(context.Background(), command); err != nil || !response.Done || response.Message.Content == "" {
					t.Fatalf("chat budget response=%+v err=%v", response, err)
				}
			case "stream_chat":
				stream, err := service.StreamChat(context.Background(), command)
				if err != nil {
					t.Fatal(err)
				}
				var done bool
				for event := range stream {
					done = done || event.Kind == core.EventDone && event.Response != nil && event.Response.Message.Content != ""
				}
				if !done {
					t.Fatal("StreamChat did not project budget finalization as done Markdown")
				}
			case "start_turn":
				turn, err := service.StartTurn(context.Background(), adapterTurnCommand(command))
				if err != nil {
					t.Fatal(err)
				}
				events := watchAdapterTurn(t, service, turn.ID)
				if len(events) == 0 || events[len(events)-1].Kind != core.TurnEventDone || events[len(events)-1].Response == nil || events[len(events)-1].Response.Message.Content == "" {
					t.Fatalf("events=%+v", events)
				}
			}
			turn := waitAdapterTurn(t, store.CoreConversationStore, command.RequestID)
			if turn.State != core.TurnCompleted || turn.Response == nil || turn.Response.Message.Content == "" || turn.RuntimeSnapshot == nil ||
				turn.ModelDispatchCount != turn.RuntimeSnapshot.ExecutionPolicy.MaxModelDispatches+core.MaxTurnFinalizationDispatches {
				t.Fatalf("turn=%+v", turn)
			}
		})
	}
}
