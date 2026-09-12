package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshflow"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type groupTurnReaderFake struct {
	turn coreconversation.Turn
	err  error
}

func (f groupTurnReaderFake) GetTurn(context.Context, string) (coreconversation.Turn, error) {
	return f.turn, f.err
}

type groupGuardFake struct {
	err   error
	calls int
}

func (f *groupGuardFake) ValidateGroupOrigin(context.Context, coreconversation.GroupOrigin) error {
	f.calls++
	return f.err
}

func groupWorkerTurn(group bool) coreconversation.Turn {
	turn := coreconversation.Turn{ID: uuid.NewString(), OwnerID: "owner", AccountGeneration: 1}
	if group {
		turn.GroupOrigin = &coreconversation.GroupOrigin{RequestID: uuid.NewString(), RoomID: "!group:example.test",
			EventID: "$event", ActorID: "@member:example.test", OwnerID: "owner", AgentMXID: "@ying:example.test",
			AccountGeneration: 1, BindingRevision: 3}
	}
	return turn
}

func groupWorkerRequest(turn coreconversation.Turn) sshflow.Request {
	return sshflow.Request{OwnerID: turn.OwnerID, AccountGeneration: turn.AccountGeneration, TurnID: turn.ID}
}

func TestGroupWorkerOriginRequiresADurableTurnReader(t *testing.T) {
	executor := &sshWorkerExecutor{}
	if _, err := executor.groupWorkerOrigin(context.Background(), sshflow.Request{TurnID: uuid.NewString()}); !errors.Is(err, coreconversation.ErrGroupAuthorization) {
		t.Fatalf("missing reader returned %v", err)
	}
}

func TestGroupWorkerOriginLeavesPrivateTurnsAlone(t *testing.T) {
	turn := groupWorkerTurn(false)
	guard := &groupGuardFake{}
	executor := &sshWorkerExecutor{groupTurnReader: groupTurnReaderFake{turn: turn}, groupAuthorization: guard}
	origin, err := executor.groupWorkerOrigin(context.Background(), groupWorkerRequest(turn))
	if err != nil || origin != nil {
		t.Fatalf("private turn origin=%v err=%v", origin, err)
	}
	// A private turn must not consult the group guard at all.
	if guard.calls != 0 {
		t.Fatalf("private turn consulted the group guard %d times", guard.calls)
	}
}

func TestGroupWorkerOriginRejectsPrivatePrivilegesForGroupWork(t *testing.T) {
	turn := groupWorkerTurn(true)
	base := groupWorkerRequest(turn)
	for name, mutate := range map[string]func(*sshflow.Request){
		"github binding":  func(r *sshflow.Request) { r.GitHubBinding = &cloudworker.GitHubBinding{} },
		"retained worker": func(r *sshflow.Request) { r.ReuseOnly = true; r.ReuseWorkerID = uuid.NewString() },
		"attachments": func(r *sshflow.Request) {
			r.InputManifest = cloudworker.InputManifest{Items: []cloudworker.InputManifestItem{{SourceRef: uuid.NewString()}}}
		},
		"owner prompt": func(r *sshflow.Request) {
			r.ModelSnapshot = coremodel.ExecutionSnapshot{SystemPrompt: "private owner instructions"}
		},
		"owner mismatch": func(r *sshflow.Request) { r.OwnerID = "someone-else" },
		"generation":     func(r *sshflow.Request) { r.AccountGeneration = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			request := base
			mutate(&request)
			guard := &groupGuardFake{}
			executor := &sshWorkerExecutor{groupTurnReader: groupTurnReaderFake{turn: turn}, groupAuthorization: guard}
			if _, err := executor.groupWorkerOrigin(context.Background(), request); !errors.Is(err, coreconversation.ErrGroupAuthorization) {
				t.Fatalf("%s accepted: %v", name, err)
			}
		})
	}
}

func TestGroupWorkerOriginFailsClosedWithoutAGuardAndWhenRevoked(t *testing.T) {
	turn := groupWorkerTurn(true)
	request := groupWorkerRequest(turn)
	executor := &sshWorkerExecutor{groupTurnReader: groupTurnReaderFake{turn: turn}}
	if _, err := executor.groupWorkerOrigin(context.Background(), request); !errors.Is(err, coreconversation.ErrGroupAuthorization) {
		t.Fatalf("missing guard returned %v", err)
	}

	guard := &groupGuardFake{err: coreconversation.ErrGroupAuthorization}
	executor.groupAuthorization = guard
	if _, err := executor.groupWorkerOrigin(context.Background(), request); !errors.Is(err, coreconversation.ErrGroupAuthorization) {
		t.Fatalf("revoked binding returned %v", err)
	}
	if guard.calls == 0 {
		t.Fatal("revoked binding was not revalidated")
	}
}

func TestGroupWorkerOriginReturnsTheGroupScopeForApprovedWork(t *testing.T) {
	turn := groupWorkerTurn(true)
	guard := &groupGuardFake{}
	executor := &sshWorkerExecutor{groupTurnReader: groupTurnReaderFake{turn: turn}, groupAuthorization: guard}
	origin, err := executor.groupWorkerOrigin(context.Background(), groupWorkerRequest(turn))
	if err != nil || origin == nil || *origin != *turn.GroupOrigin {
		t.Fatalf("group turn origin=%v err=%v", origin, err)
	}
}

func TestGroupWorkerWatchCancelsTheRunWhenTheOwnerTurnsItOff(t *testing.T) {
	turn := groupWorkerTurn(true)
	guard := &groupGuardFake{}
	executor := &sshWorkerExecutor{groupTurnReader: groupTurnReaderFake{turn: turn}, groupAuthorization: guard,
		groupAuthorizationPoll: 10 * time.Millisecond}
	workCtx, stop := executor.watchGroupWorkerAuthorization(context.Background(), *turn.GroupOrigin)
	defer stop()

	select {
	case <-workCtx.Done():
		t.Fatal("authorized run was cancelled before revocation")
	case <-time.After(30 * time.Millisecond):
	}

	guard.err = coreconversation.ErrGroupAuthorization
	select {
	case <-workCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("revoked run kept going")
	}
}

func TestGroupMessageResolverRefusesPrivateContexts(t *testing.T) {
	resolver := groupMessageResolver{product: &groupProductFake{}}
	if _, err := resolver.ResolveExtensions(context.Background(), nil); !errors.Is(err, coreconversation.ErrGroupAuthorization) {
		t.Fatalf("private context reached the group history tool: %v", err)
	}
}
