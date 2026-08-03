package app

import (
	"context"
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/agent/teamtaskskill"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamreport"
	"github.com/google/uuid"
)

type teamTaskStoreStub struct {
	current       task.Task
	cancelCalls   int
	cancelCommand task.CancelCommand
	cancelScope   task.MutationScope
	raceRevision  bool
	report        teamreport.Fact
	reportFound   bool
	plan          teamorchestration.PlanFact
	planFound     bool
}

func (stub *teamTaskStoreStub) Get(
	context.Context,
	string,
) (task.Task, error) {
	return stub.current, nil
}

func (stub *teamTaskStoreStub) Cancel(
	_ context.Context,
	scope task.MutationScope,
	command task.CancelCommand,
) (task.Task, error) {
	stub.cancelCalls++
	stub.cancelScope = scope
	stub.cancelCommand = command
	if stub.raceRevision && stub.cancelCalls == 1 {
		stub.current.Revision++
		return task.Task{}, task.ErrRevisionConflict
	}
	stub.current.ExecutionStatus = task.ExecutionFinished
	stub.current.OutcomeStatus = task.OutcomeCanceled
	stub.current.Revision++
	return stub.current, nil
}

func (stub *teamTaskStoreStub) FindTeamExecutionReportByTask(
	context.Context,
	string,
	string,
) (teamreport.Fact, bool, error) {
	return stub.report, stub.reportFound, nil
}

func (stub *teamTaskStoreStub) FindTeamPlanByTask(
	context.Context,
	string,
	string,
) (teamorchestration.PlanFact, bool, error) {
	return stub.plan, stub.planFound, nil
}

func TestTeamTaskDialogueAdapterCommitsCancellationAndRetriesRevisionRace(
	t *testing.T,
) {
	t.Parallel()
	taskID := uuid.NewString()
	credentialID := uuid.NewString()
	store := &teamTaskStoreStub{
		current: task.Task{
			TaskID:          taskID,
			OwnerID:         "owner-1",
			ExecutionStatus: task.ExecutionRunning,
			OutcomeStatus:   task.OutcomePending,
			Revision:        2,
		},
		raceRevision: true,
	}
	adapter, err := newTeamTaskDialogueAdapter(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.ContextWithPrincipal(
		context.Background(),
		auth.Principal{
			ClientID:     "message-server",
			CredentialID: credentialID,
		},
	)
	idempotencyKey := uuid.NewString()
	fact, err := adapter.CancelTeamTask(
		ctx,
		teamtaskskill.CancelRequest{
			IdempotencyKey: idempotencyKey,
			OwnerID:        "owner-1",
			TaskID:         taskID,
		},
	)
	if err != nil ||
		fact.State != teamtaskskill.CancelCommitted ||
		fact.Task.ExecutionStatus != task.ExecutionFinished ||
		fact.Task.OutcomeStatus != task.OutcomeCanceled ||
		store.cancelCalls != 2 ||
		store.cancelCommand.IdempotencyKey != idempotencyKey ||
		store.cancelCommand.ExpectedRevision != 3 ||
		store.cancelCommand.TaskID != taskID ||
		store.cancelCommand.Reason == "" ||
		store.cancelScope.ClientID != "message-server" ||
		store.cancelScope.CredentialID != credentialID {
		t.Fatalf("cancel fact=%#v command=%#v calls=%d error=%v", fact, store.cancelCommand, store.cancelCalls, err)
	}
}

func TestTeamTaskDialogueAdapterMakesRepeatedCancellationAReadOnlyReplay(
	t *testing.T,
) {
	t.Parallel()
	taskID := uuid.NewString()
	store := &teamTaskStoreStub{current: task.Task{
		TaskID:          taskID,
		OwnerID:         "owner-1",
		ExecutionStatus: task.ExecutionFinished,
		OutcomeStatus:   task.OutcomeCanceled,
		Revision:        4,
	}}
	adapter, err := newTeamTaskDialogueAdapter(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.ContextWithPrincipal(
		context.Background(),
		auth.Principal{
			ClientID:     "message-server",
			CredentialID: uuid.NewString(),
		},
	)
	fact, err := adapter.CancelTeamTask(ctx, teamtaskskill.CancelRequest{
		IdempotencyKey: uuid.NewString(),
		OwnerID:        "owner-1",
		TaskID:         taskID,
	})
	if err != nil ||
		fact.State != teamtaskskill.CancelAlreadyCanceled ||
		store.cancelCalls != 0 {
		t.Fatalf("repeated cancel fact=%#v calls=%d error=%v", fact, store.cancelCalls, err)
	}
}

func TestTeamTaskDialogueAdapterRejectsForeignOwnerAndUnauthenticatedCalls(
	t *testing.T,
) {
	t.Parallel()
	taskID := uuid.NewString()
	store := &teamTaskStoreStub{current: task.Task{
		TaskID:          taskID,
		OwnerID:         "owner-2",
		ExecutionStatus: task.ExecutionRunning,
		OutcomeStatus:   task.OutcomePending,
		Revision:        1,
	}}
	adapter, err := newTeamTaskDialogueAdapter(store)
	if err != nil {
		t.Fatal(err)
	}
	request := teamtaskskill.StatusRequest{
		OwnerID: "owner-1",
		TaskID:  taskID,
	}
	if _, err := adapter.GetTeamTask(context.Background(), request); !errors.Is(err, teamtaskskill.ErrInvocationScopeMismatch) {
		t.Fatalf("unauthenticated error = %v", err)
	}
	ctx := auth.ContextWithPrincipal(
		context.Background(),
		auth.Principal{
			ClientID:     "message-server",
			CredentialID: uuid.NewString(),
		},
	)
	if _, err := adapter.GetTeamTask(ctx, request); !errors.Is(err, teamtaskskill.ErrInvocationScopeMismatch) {
		t.Fatalf("foreign owner error = %v", err)
	}
}
