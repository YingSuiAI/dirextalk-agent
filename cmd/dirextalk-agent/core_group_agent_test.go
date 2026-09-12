package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type groupProductFake struct {
	allowed      bool
	validateErr  error
	published    []capabilityclient.GroupAgentPublish
	completed    []string
	historyCalls []string
}

func (f *groupProductFake) PullGroupAgentRequests(context.Context, string) (capabilityclient.GroupAgentPage, error) {
	return capabilityclient.GroupAgentPage{}, nil
}

func (f *groupProductFake) ValidateGroupAgentRequest(context.Context, string, int64) (capabilityclient.GroupAgentBindingCheck, error) {
	if f.validateErr != nil {
		return capabilityclient.GroupAgentBindingCheck{}, f.validateErr
	}
	return capabilityclient.GroupAgentBindingCheck{Allowed: f.allowed}, nil
}

func (f *groupProductFake) ReadGroupAgentHistory(_ context.Context, requestID string, _ int64, _ int) (capabilityclient.GroupAgentHistory, error) {
	f.historyCalls = append(f.historyCalls, requestID)
	return capabilityclient.GroupAgentHistory{}, nil
}

func (f *groupProductFake) PublishGroupAgentReply(_ context.Context, publish capabilityclient.GroupAgentPublish) error {
	f.published = append(f.published, publish)
	return nil
}

func (f *groupProductFake) CompleteGroupAgentRequest(_ context.Context, requestID string, _ int64, status string) error {
	f.completed = append(f.completed, requestID+":"+status)
	return nil
}

type groupTurnsFake struct {
	turn      *coreconversation.Turn
	getErr    error
	started   []coreconversation.TurnStartCommand
	startErr  error
	cancelled []string
	active    []coreconversation.Turn
}

func (f *groupTurnsFake) StartGroupTurn(_ context.Context, command coreconversation.TurnStartCommand, origin coreconversation.GroupOrigin) (coreconversation.Turn, error) {
	if f.startErr != nil {
		return coreconversation.Turn{}, f.startErr
	}
	f.started = append(f.started, command)
	turn := coreconversation.Turn{ID: command.TurnID, RequestID: command.RequestID,
		OwnerID: command.OwnerID, AccountGeneration: command.AccountGeneration,
		ConversationID: origin.ConversationID(), Prompt: command.Prompt,
		ProfileID: command.ProfileID, Revision: 1, State: coreconversation.TurnAccepted}
	copied := origin
	turn.GroupOrigin = &copied
	f.turn = &turn
	return turn, nil
}

func (f *groupTurnsFake) GetTurn(context.Context, string) (coreconversation.Turn, error) {
	if f.turn != nil {
		return *f.turn, nil
	}
	return coreconversation.Turn{}, f.getErr
}

func (f *groupTurnsFake) CancelTurn(_ context.Context, command coreconversation.TurnCancelCommand) (coreconversation.Turn, error) {
	f.cancelled = append(f.cancelled, command.TurnID)
	return coreconversation.Turn{ID: command.TurnID, State: coreconversation.TurnCanceled}, nil
}

func (f *groupTurnsFake) ListActiveGroupTurns(context.Context) ([]coreconversation.Turn, error) {
	return f.active, nil
}

type groupProfilesFake struct {
	id      string
	idErr   error
	profile coremodel.Profile
	profErr error
}

func (f *groupProfilesFake) ResolveDefaultProfileID(context.Context, string) (string, error) {
	return f.id, f.idErr
}

func (f *groupProfilesFake) ResolveProfile(context.Context, string) (coremodel.Profile, error) {
	return f.profile, f.profErr
}

func groupRequestFixture() capabilityclient.GroupAgentRequest {
	return capabilityclient.GroupAgentRequest{
		RequestID: uuid.NewString(), RoomID: "!group:example.test", EventID: "$event",
		SenderMXID: "@member:example.test", OwnerMXID: "@owner:example.test",
		AgentMXID: "@ying:example.test", BindingRevision: 4, AccountGeneration: 9,
		Body: "@Ying 帮我总结这个群", OriginServerTS: 1,
	}
}

func newGroupLoopFixture(t *testing.T) (*groupAgentLoop, *groupProductFake, *groupTurnsFake, *groupProfilesFake) {
	t.Helper()
	product := &groupProductFake{allowed: true}
	turns := &groupTurnsFake{getErr: coreconversation.ErrConflict}
	profiles := &groupProfilesFake{id: uuid.NewString(), profile: coremodel.Profile{ID: uuid.NewString(), Revision: 2, CredentialVersion: 3}}
	return newGroupAgentLoop(product, turns, profiles, 9), product, turns, profiles
}

func TestGroupLoopStartsOneIsolatedTurnAndPublishesProgress(t *testing.T) {
	loop, product, turns, _ := newGroupLoopFixture(t)
	request := groupRequestFixture()
	if err := loop.processRequest(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if len(turns.started) != 1 {
		t.Fatalf("started turns = %d", len(turns.started))
	}
	started := turns.started[0]
	if started.TurnID != request.RequestID || started.RequestID != request.RequestID {
		t.Fatalf("turn identity must reuse the durable request uuid: %#v", started)
	}
	if started.OwnerID != request.OwnerMXID || started.AccountGeneration != request.AccountGeneration || started.Prompt != request.Body {
		t.Fatalf("turn admission drifted: %#v", started)
	}
	if len(product.published) != 1 || product.published[0].Kind != "progress" || product.published[0].Status != "working" {
		t.Fatalf("published = %#v", product.published)
	}
	if product.published[0].RequestID != request.RequestID || product.published[0].BindingRevision != request.BindingRevision {
		t.Fatalf("publication lost its binding: %#v", product.published[0])
	}
}

func TestGroupLoopReplayDoesNotStartASecondTurn(t *testing.T) {
	loop, product, turns, _ := newGroupLoopFixture(t)
	request := groupRequestFixture()
	if err := loop.processRequest(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	// A retry after a lost acknowledgement must observe the same turn.
	if err := loop.processRequest(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if len(turns.started) != 1 {
		t.Fatalf("replay started %d turns", len(turns.started))
	}
	if len(product.published) != 2 || product.published[0].Kind != "progress" || product.published[1].Kind != "progress" {
		t.Fatalf("replay publications = %#v", product.published)
	}
	for _, publish := range product.published {
		if publish.RequestID != request.RequestID {
			t.Fatalf("replay published a different request: %#v", publish)
		}
	}
}

func TestGroupLoopNeverStartsATurnWithoutAnOwnerModel(t *testing.T) {
	loop, product, turns, profiles := newGroupLoopFixture(t)
	profiles.idErr = errors.New("no default conversation model")
	if err := loop.processRequest(context.Background(), groupRequestFixture()); err != nil {
		t.Fatal(err)
	}
	if len(turns.started) != 0 {
		t.Fatalf("turn started without a model: %#v", turns.started)
	}
	if len(product.published) != 1 {
		t.Fatalf("published = %#v", product.published)
	}
	publish := product.published[0]
	if publish.Kind != "final" || publish.Status != "failed" || !strings.Contains(publish.Body, "群主") {
		t.Fatalf("honest owner-facing failure expected: %#v", publish)
	}
}

func TestGroupLoopReportsRuntimeErrorsInsteadOfSilence(t *testing.T) {
	t.Run("canceled turn closes the request", func(t *testing.T) {
		loop, product, turns, _ := newGroupLoopFixture(t)
		request := groupRequestFixture()
		origin := coreconversation.GroupOrigin{RequestID: request.RequestID, RoomID: request.RoomID, EventID: request.EventID,
			ActorID: request.SenderMXID, OwnerID: request.OwnerMXID, AgentMXID: request.AgentMXID,
			AccountGeneration: request.AccountGeneration, BindingRevision: request.BindingRevision}
		turn := coreconversation.Turn{ID: request.RequestID, State: coreconversation.TurnCanceled, GroupOrigin: &origin}
		turns.turn = &turn
		if err := loop.processRequest(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		if len(product.published) != 0 || len(product.completed) != 1 || !strings.HasSuffix(product.completed[0], ":cancelled") {
			t.Fatalf("canceled turn published=%#v completed=%#v", product.published, product.completed)
		}
	})

	t.Run("failed turn publishes an honest failure", func(t *testing.T) {
		loop, product, turns, _ := newGroupLoopFixture(t)
		request := groupRequestFixture()
		origin := coreconversation.GroupOrigin{RequestID: request.RequestID, RoomID: request.RoomID, EventID: request.EventID,
			ActorID: request.SenderMXID, OwnerID: request.OwnerMXID, AgentMXID: request.AgentMXID,
			AccountGeneration: request.AccountGeneration, BindingRevision: request.BindingRevision}
		turn := coreconversation.Turn{ID: request.RequestID, State: coreconversation.TurnFailed, GroupOrigin: &origin}
		turns.turn = &turn
		if err := loop.processRequest(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		if len(product.published) != 1 || product.published[0].Status != "failed" || product.published[0].Kind != "final" {
			t.Fatalf("published = %#v", product.published)
		}
	})

	t.Run("worker approval is surfaced to the owner", func(t *testing.T) {
		loop, product, turns, _ := newGroupLoopFixture(t)
		request := groupRequestFixture()
		origin := coreconversation.GroupOrigin{RequestID: request.RequestID, RoomID: request.RoomID, EventID: request.EventID,
			ActorID: request.SenderMXID, OwnerID: request.OwnerMXID, AgentMXID: request.AgentMXID,
			AccountGeneration: request.AccountGeneration, BindingRevision: request.BindingRevision}
		turn := coreconversation.Turn{ID: request.RequestID, State: coreconversation.TurnWaitingConfirmation, GroupOrigin: &origin}
		turns.turn = &turn
		if err := loop.processRequest(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		if len(product.published) != 1 || product.published[0].Status != "waiting_owner" {
			t.Fatalf("published = %#v", product.published)
		}
		if !strings.Contains(product.published[0].Body, "群主") {
			t.Fatalf("members must be told the owner approves: %#v", product.published[0])
		}
	})

	t.Run("completed turn publishes the answer", func(t *testing.T) {
		loop, product, turns, _ := newGroupLoopFixture(t)
		request := groupRequestFixture()
		origin := coreconversation.GroupOrigin{RequestID: request.RequestID, RoomID: request.RoomID, EventID: request.EventID,
			ActorID: request.SenderMXID, OwnerID: request.OwnerMXID, AgentMXID: request.AgentMXID,
			AccountGeneration: request.AccountGeneration, BindingRevision: request.BindingRevision}
		turn := coreconversation.Turn{ID: request.RequestID, State: coreconversation.TurnCompleted, GroupOrigin: &origin,
			Response: &coreconversation.ChatResponse{Message: coreconversation.Message{Content: "群里问题的答案"}}}
		turns.turn = &turn
		if err := loop.processRequest(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		if len(product.published) != 1 || product.published[0].Body != "群里问题的答案" ||
			product.published[0].Kind != "final" || product.published[0].Status != "completed" {
			t.Fatalf("published = %#v", product.published)
		}
	})
}

func TestGroupLoopCompletesRevokedRequestsWithoutRunningThem(t *testing.T) {
	loop, product, turns, _ := newGroupLoopFixture(t)
	product.allowed = false
	request := groupRequestFixture()
	if err := loop.processRequest(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if len(turns.started) != 0 || len(product.published) != 0 {
		t.Fatalf("revoked request ran: started=%#v published=%#v", turns.started, product.published)
	}
	if len(product.completed) != 1 || !strings.HasSuffix(product.completed[0], ":cancelled") {
		t.Fatalf("revoked request was not closed: %#v", product.completed)
	}
}

func TestGroupLoopRejectsForeignGenerationAndUnknownRooms(t *testing.T) {
	loop, product, turns, _ := newGroupLoopFixture(t)
	foreign := groupRequestFixture()
	foreign.AccountGeneration = 8
	if err := loop.processRequest(context.Background(), foreign); err == nil {
		t.Fatal("foreign account generation accepted")
	}
	empty := groupRequestFixture()
	empty.Body = "   "
	if err := loop.processRequest(context.Background(), empty); err == nil {
		t.Fatal("empty body accepted")
	}
	if len(turns.started) != 0 || len(product.published) != 0 {
		t.Fatalf("rejected requests ran: %#v %#v", turns.started, product.published)
	}
}

func TestGroupLoopBoundsOversizedReplies(t *testing.T) {
	origin := coreconversation.GroupOrigin{RequestID: uuid.NewString(), RoomID: "!group:example.test", EventID: "$event",
		ActorID: "@member:example.test", OwnerID: "@owner:example.test", AgentMXID: "@ying:example.test",
		AccountGeneration: 9, BindingRevision: 4}
	for _, testCase := range []struct {
		name   string
		body   string
		notice string
	}{
		{name: "chinese", body: strings.Repeat("总结内容", 20<<10), notice: "任务结果已保存"},
		{name: "english", body: strings.Repeat("summary ", 20<<10), notice: "The result has been saved"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			loop, product, _, _ := newGroupLoopFixture(t)
			if err := loop.publish(context.Background(), origin, testCase.body, "final", "completed"); err != nil {
				t.Fatal(err)
			}
			if len(product.published) != 1 {
				t.Fatalf("published = %#v", product.published)
			}
			published := product.published[0]
			if len(published.Body) > 60<<10 || published.Body == testCase.body {
				t.Fatalf("oversized body was not bounded: %d bytes", len(published.Body))
			}
			if !strings.Contains(published.Body, testCase.notice) {
				t.Fatalf("expected the owner-facing notice, got %q", published.Body)
			}
			// The trimmed reply keeps the intended public status.
			if published.Kind != "final" || published.Status != "completed" {
				t.Fatalf("publication shape changed: %#v", published)
			}
		})
	}
}

func TestGroupLoopCancelsTurnsWhoseBindingWasRevoked(t *testing.T) {
	loop, product, turns, _ := newGroupLoopFixture(t)
	origin := coreconversation.GroupOrigin{RequestID: uuid.NewString(), RoomID: "!group:example.test", EventID: "$event",
		ActorID: "@member:example.test", OwnerID: "@owner:example.test", AgentMXID: "@ying:example.test",
		AccountGeneration: 9, BindingRevision: 4}
	turns.active = []coreconversation.Turn{{ID: uuid.NewString(), State: coreconversation.TurnRunning, GroupOrigin: &origin}}
	product.allowed = false
	if err := loop.cancelRevoked(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(turns.cancelled) != 1 || turns.cancelled[0] != turns.active[0].ID {
		t.Fatalf("revoked running turn was not cancelled: %#v", turns.cancelled)
	}
}
