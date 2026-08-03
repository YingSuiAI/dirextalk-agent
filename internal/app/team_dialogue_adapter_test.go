package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agent/teamskill"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
)

type teamDialogueTaskCreatorFunc func(
	context.Context,
	task.MutationScope,
	task.CreateCommand,
) (task.Task, error)

func (function teamDialogueTaskCreatorFunc) Create(
	ctx context.Context,
	scope task.MutationScope,
	command task.CreateCommand,
) (task.Task, error) {
	return function(ctx, scope, command)
}

func (teamDialogueTaskCreatorFunc) Get(
	context.Context,
	string,
) (task.Task, error) {
	return task.Task{}, errors.New("unexpected planning Task read")
}

func (teamDialogueTaskCreatorFunc) Cancel(
	context.Context,
	task.MutationScope,
	task.CancelCommand,
) (task.Task, error) {
	return task.Task{}, errors.New("unexpected planning Task cancellation")
}

type teamDialogueLifecycleStoreStub struct {
	created       task.Task
	current       task.Task
	createCalls   int
	cancelCalls   int
	createCommand task.CreateCommand
	cancelCommand task.CancelCommand
}

func (stub *teamDialogueLifecycleStoreStub) Create(
	_ context.Context,
	_ task.MutationScope,
	command task.CreateCommand,
) (task.Task, error) {
	stub.createCalls++
	stub.createCommand = command
	return stub.created, nil
}

func (stub *teamDialogueLifecycleStoreStub) Get(
	context.Context,
	string,
) (task.Task, error) {
	return stub.current, nil
}

func (stub *teamDialogueLifecycleStoreStub) Cancel(
	_ context.Context,
	_ task.MutationScope,
	command task.CancelCommand,
) (task.Task, error) {
	stub.cancelCalls++
	stub.cancelCommand = command
	stub.current.ExecutionStatus = task.ExecutionFinished
	stub.current.OutcomeStatus = task.OutcomeCanceled
	stub.current.Revision++
	return stub.current, nil
}

type teamDialoguePlanPreparerFunc func(
	context.Context,
	task.MutationScope,
	teamorchestration.PreparePlanRequest,
) (teamorchestration.PlanFact, error)

func (function teamDialoguePlanPreparerFunc) PreparePlan(
	ctx context.Context,
	scope task.MutationScope,
	request teamorchestration.PreparePlanRequest,
) (teamorchestration.PlanFact, error) {
	return function(ctx, scope, request)
}

func TestTeamDialogueAdapterCreatesOneDeterministicPlanningTaskAndPlan(
	t *testing.T,
) {
	t.Parallel()
	requestID := "61bf1ec0-2605-4d9a-a28c-84ec2f86b524"
	connectionID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	taskID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	credentialID := uuid.NewString()
	principal := auth.Principal{
		ClientID:     "message-server",
		CredentialID: credentialID,
	}
	ctx := auth.ContextWithPrincipal(context.Background(), principal)
	var taskCommands []task.CreateCommand
	var prepareRequests []teamorchestration.PreparePlanRequest
	var scopes []task.MutationScope
	adapter, err := newTeamDialogueAdapter(
		teamDialogueTaskCreatorFunc(func(
			_ context.Context,
			scope task.MutationScope,
			command task.CreateCommand,
		) (task.Task, error) {
			scopes = append(scopes, scope)
			taskCommands = append(taskCommands, command)
			return task.Task{
				TaskID:          taskID,
				OwnerID:         command.OwnerID,
				Goal:            command.Goal,
				RetentionPolicy: command.Retention,
				Revision:        1,
			}, nil
		}),
		teamDialoguePlanPreparerFunc(func(
			_ context.Context,
			scope task.MutationScope,
			request teamorchestration.PreparePlanRequest,
		) (teamorchestration.PlanFact, error) {
			scopes = append(scopes, scope)
			prepareRequests = append(prepareRequests, request)
			return teamorchestration.PlanFact{
				TaskID: taskID,
				Plan: teamplan.Plan{
					PlanID:    request.PlanID,
					OwnerID:   request.OwnerID,
					TaskInput: request.TaskInput,
					ProviderScope: teamplan.ProviderScope{
						ConnectionID: request.ConnectionID,
					},
				},
			}, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	proposal := teamplan.TeamProposal{
		Confidence: 90,
		Rationale:  "Use one implementation Worker.",
	}
	request := teamskill.PrepareRequest{
		RequestID:    requestID,
		OwnerID:      "owner-1",
		ConnectionID: connectionID,
		Goal:         "Implement the requested server change.",
		Proposal:     proposal,
	}
	first, err := adapter.PrepareTeamPlan(ctx, request)
	if err != nil {
		t.Fatalf("PrepareTeamPlan() error = %v", err)
	}
	second, err := adapter.PrepareTeamPlan(ctx, request)
	if err != nil {
		t.Fatalf("PrepareTeamPlan() replay error = %v", err)
	}
	if first.TaskID != taskID ||
		second.Plan.PlanID != first.Plan.PlanID ||
		len(taskCommands) != 2 ||
		len(prepareRequests) != 2 ||
		!reflect.DeepEqual(taskCommands[0], taskCommands[1]) ||
		!reflect.DeepEqual(prepareRequests[0], prepareRequests[1]) {
		t.Fatalf(
			"deterministic replay failed: tasks=%#v plans=%#v",
			taskCommands,
			prepareRequests,
		)
	}
	namespace := uuid.MustParse(requestID)
	wantTaskKey := uuid.NewSHA1(
		namespace,
		[]byte("team-plan-task-create"),
	).String()
	wantPlanID := uuid.NewSHA1(
		namespace,
		[]byte("team-plan\x00"+request.OwnerID),
	).String()
	wantPrepareKey := uuid.NewSHA1(
		namespace,
		[]byte("team-plan-prepare"),
	).String()
	goalHash := sha256.Sum256([]byte(request.Goal))
	if taskCommands[0].IdempotencyKey != wantTaskKey ||
		taskCommands[0].OwnerID != request.OwnerID ||
		taskCommands[0].Goal != request.Goal ||
		taskCommands[0].Retention != task.RetentionEphemeralAutoDestroy ||
		len(taskCommands[0].Steps) != 0 {
		t.Fatalf("Task command = %#v", taskCommands[0])
	}
	prepared := prepareRequests[0]
	if prepared.IdempotencyKey != wantPrepareKey ||
		prepared.TaskID != taskID ||
		prepared.PlanID != wantPlanID ||
		prepared.ConnectionID != connectionID ||
		prepared.Revision != 1 ||
		prepared.ExpectedPreviousRevision != 0 ||
		prepared.GoalDigest != "sha256:"+
			hex.EncodeToString(goalHash[:]) ||
		!taskinput.IsEmptyInput(prepared.TaskInput) ||
		!reflect.DeepEqual(prepared.Proposal, proposal) {
		t.Fatalf("Prepare request = %#v", prepared)
	}
	wantScope := task.MutationScope{
		ClientID:     principal.ClientID,
		CredentialID: credentialID,
	}
	for _, scope := range scopes {
		if scope != wantScope {
			t.Fatalf("mutation scope = %#v", scope)
		}
	}
}

func TestTeamDialogueAdapterRequiresAuthenticatedPrincipal(t *testing.T) {
	t.Parallel()
	calls := 0
	adapter, err := newTeamDialogueAdapter(
		teamDialogueTaskCreatorFunc(func(
			context.Context,
			task.MutationScope,
			task.CreateCommand,
		) (task.Task, error) {
			calls++
			return task.Task{}, nil
		}),
		teamDialoguePlanPreparerFunc(func(
			context.Context,
			task.MutationScope,
			teamorchestration.PreparePlanRequest,
		) (teamorchestration.PlanFact, error) {
			calls++
			return teamorchestration.PlanFact{}, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.PrepareTeamPlan(
		context.Background(),
		teamskill.PrepareRequest{
			RequestID:    uuid.NewString(),
			OwnerID:      "owner-1",
			ConnectionID: uuid.NewString(),
			Goal:         "bounded goal",
		},
	)
	if !errors.Is(err, teamskill.ErrInvocationScopeMismatch) ||
		calls != 0 {
		t.Fatalf("unauthenticated error = %v, calls=%d", err, calls)
	}
}

func TestTeamDialogueAdapterClosesOnlyStillUnplannedTask(t *testing.T) {
	t.Parallel()
	requestID := uuid.NewString()
	taskID := uuid.NewString()
	request := teamskill.PrepareRequest{
		RequestID:    requestID,
		OwnerID:      "owner-1",
		ConnectionID: uuid.NewString(),
		Goal:         "Deliver the bounded implementation task.",
	}
	planning := task.Task{
		TaskID:          taskID,
		OwnerID:         request.OwnerID,
		Goal:            request.Goal,
		ExecutionStatus: task.ExecutionPlanning,
		OutcomeStatus:   task.OutcomePending,
		RetentionPolicy: task.RetentionEphemeralAutoDestroy,
		Revision:        1,
	}
	store := &teamDialogueLifecycleStoreStub{
		created: planning,
		current: planning,
	}
	adapter, err := newTeamDialogueAdapter(
		store,
		teamDialoguePlanPreparerFunc(func(
			context.Context,
			task.MutationScope,
			teamorchestration.PreparePlanRequest,
		) (teamorchestration.PlanFact, error) {
			t.Fatal("Task closure reached Plan preparation")
			return teamorchestration.PlanFact{}, nil
		}),
	)
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
	if err := adapter.CloseUnplannedTeamTask(
		ctx,
		request,
		"no_qualified_runtime",
	); err != nil {
		t.Fatal(err)
	}
	if err := adapter.CloseUnplannedTeamTask(
		ctx,
		request,
		"no_qualified_runtime",
	); err != nil {
		t.Fatal(err)
	}
	wantCreateKey := uuid.NewSHA1(
		uuid.MustParse(requestID),
		[]byte("team-plan-task-create"),
	).String()
	wantCloseKey := uuid.NewSHA1(
		uuid.MustParse(requestID),
		[]byte("team-plan-task-close"),
	).String()
	if store.createCalls != 2 ||
		store.cancelCalls != 1 ||
		store.createCommand.IdempotencyKey != wantCreateKey ||
		store.cancelCommand.IdempotencyKey != wantCloseKey ||
		store.cancelCommand.TaskID != taskID ||
		store.cancelCommand.ExpectedRevision != 1 ||
		store.current.ExecutionStatus != task.ExecutionFinished ||
		store.current.OutcomeStatus != task.OutcomeCanceled {
		t.Fatalf(
			"create=%#v cancel=%#v current=%#v calls=%d/%d",
			store.createCommand,
			store.cancelCommand,
			store.current,
			store.createCalls,
			store.cancelCalls,
		)
	}
}

func TestTeamDialogueAdapterDoesNotCloseTaskWithPreparedPlan(t *testing.T) {
	t.Parallel()
	request := teamskill.PrepareRequest{
		RequestID:    uuid.NewString(),
		OwnerID:      "owner-1",
		ConnectionID: uuid.NewString(),
		Goal:         "Deliver the bounded implementation task.",
	}
	created := task.Task{
		TaskID:          uuid.NewString(),
		OwnerID:         request.OwnerID,
		Goal:            request.Goal,
		ExecutionStatus: task.ExecutionPlanning,
		OutcomeStatus:   task.OutcomePending,
		RetentionPolicy: task.RetentionEphemeralAutoDestroy,
		Revision:        1,
	}
	current := created
	current.ExecutionStatus = task.ExecutionAwaitingApproval
	current.Revision = 2
	store := &teamDialogueLifecycleStoreStub{
		created: created,
		current: current,
	}
	adapter, err := newTeamDialogueAdapter(
		store,
		teamDialoguePlanPreparerFunc(func(
			context.Context,
			task.MutationScope,
			teamorchestration.PreparePlanRequest,
		) (teamorchestration.PlanFact, error) {
			return teamorchestration.PlanFact{}, nil
		}),
	)
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
	if err := adapter.CloseUnplannedTeamTask(
		ctx,
		request,
		"retry_exhausted",
	); err != nil || store.cancelCalls != 0 {
		t.Fatalf("progressed Task closure error=%v calls=%d", err, store.cancelCalls)
	}
}

func TestScopedTeamProviderAppearsOnlyInTrustedCloudDialogue(
	t *testing.T,
) {
	t.Parallel()
	policy := teamplan.Policy{
		MaxWorkers:                1,
		MaxConcurrentWorkers:      1,
		MaxRoleDuration:           time.Hour,
		MaxVCPUPerWorker:          4,
		MaxMemoryMiBPerWorker:     8192,
		MaxDiskGiBPerWorker:       100,
		MaxPlanCostMicros:         10_000_000,
		SafetyMarginBasisPoints:   1000,
		FixedWorkerOverheadMicros: 1000,
		AllowedRuntimeFamilies: []teamplan.RuntimeFamily{
			teamplan.RuntimeCodex,
		},
	}
	skill, err := teamskill.New(teamskill.Dependencies{
		Policies: teamorchestration.PolicyResolverFunc(func(
			context.Context,
			string,
		) (teamplan.Policy, error) {
			return policy, nil
		}),
		Preparation: teamskill.PreparationPortFunc(func(
			context.Context,
			teamskill.PrepareRequest,
		) (teamorchestration.PlanFact, error) {
			return teamorchestration.PlanFact{}, nil
		}),
		TaskLifecycle: teamskill.PlanningTaskLifecycleFunc(func(
			context.Context,
			teamskill.PrepareRequest,
			string,
		) error {
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	provider := &scopedTeamProvider{provider: skill}
	base := runtimeapi.ToolRequest{
		RequestID:         uuid.NewString(),
		OwnerID:           "owner-1",
		ConversationID:    "conversation-1",
		LatestUserMessage: "Implement a substantial server change.",
	}
	tools, err := provider.Tools(context.Background(), base)
	if err != nil || len(tools) != 0 {
		t.Fatalf("ordinary chat tools = %#v, %v", tools, err)
	}
	base.CloudDialogue = &runtimeapi.CloudDialogueScope{
		ConnectionID: uuid.NewString(),
	}
	tools, err = provider.Tools(context.Background(), base)
	if err != nil || len(tools) != 1 ||
		tools[0].Definition.Name != teamskill.ToolPrepare {
		t.Fatalf("cloud dialogue tools = %#v, %v", tools, err)
	}
}
