package planning

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agent/cloudskill"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestCloudGoalDispatcherAdvancesFencedStagesAndAcceptsOnlyReadyThreeCandidatePlan(t *testing.T) {
	now := time.Date(2026, time.July, 17, 5, 0, 0, 0, time.UTC)
	queue, tasks, facts, output, agentID := newCloudGoalDispatcherFixture(now)
	dispatcher, err := NewCloudGoalDispatcher(agentID, queue, tasks, facts, output, CloudGoalDispatcherConfig{
		PollInterval: time.Second, LeaseDuration: 6 * time.Second, BatchSize: 8, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	for stage := 0; stage < 3; stage++ {
		if err := dispatcher.RunOnce(context.Background()); err != nil {
			t.Fatalf("RunOnce stage %d: %v", stage, err)
		}
	}
	if len(output.requests) != 3 || len(tasks.completed) != 3 {
		t.Fatalf("stage counts output=%d completed=%d", len(output.requests), len(tasks.completed))
	}
	for index, request := range output.requests {
		if request.Attempt.LeaseEpoch != 1 || request.OutputIdempotencyKey == "" ||
			request.Binding != queue.work.Session.Binding || request.Caller != queue.work.Caller || request.Goal != queue.work.Task.Goal {
			t.Fatalf("stage %d lost durable scope or lease: %#v", index, request)
		}
	}
	if queue.work.Task.ExecutionStatus != task.ExecutionFinished || queue.work.Task.OutcomeStatus != task.OutcomeSucceeded {
		t.Fatalf("Task did not finish after ready Plan read-back: %#v", queue.work.Task)
	}
	if got := tasks.completed[2].ResultRef; got != "cloud://plan/"+facts.plan.PlanID {
		t.Fatalf("final result_ref=%q", got)
	}
}

func TestCloudGoalDispatcherDoesNotCompleteStaleOutputAndRecoversWithNextLeaseEpoch(t *testing.T) {
	now := time.Date(2026, time.July, 17, 5, 0, 0, 0, time.UTC)
	queue, tasks, facts, output, agentID := newCloudGoalDispatcherFixture(now)
	output.failOnce = true
	dispatcher, err := NewCloudGoalDispatcher(agentID, queue, tasks, facts, output, CloudGoalDispatcherConfig{
		PollInterval: time.Second, LeaseDuration: 6 * time.Second, BatchSize: 8, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.RunOnce(context.Background()); !errors.Is(err, ErrCloudGoalOutputAdapterFailed) {
		t.Fatalf("first output error=%v", err)
	}
	if len(tasks.completed) != 0 || tasks.steps[0].LeaseEpoch != 1 || tasks.steps[0].ExecutionStatus != task.ExecutionRunning {
		t.Fatalf("failed output advanced Task: completed=%d step=%#v", len(tasks.completed), tasks.steps[0])
	}
	if err := dispatcher.RunOnce(context.Background()); err != nil || len(output.requests) != 1 {
		t.Fatalf("unexpired lease was redispatched: requests=%d err=%v", len(output.requests), err)
	}

	tasks.leaseExpired = true
	if err := dispatcher.RunOnce(context.Background()); err != nil {
		t.Fatalf("restart recovery: %v", err)
	}
	if len(output.requests) != 2 || output.requests[0].OutputIdempotencyKey != output.requests[1].OutputIdempotencyKey ||
		output.requests[0].Attempt.LeaseEpoch != 1 || output.requests[1].Attempt.LeaseEpoch != 2 || len(tasks.completed) != 1 {
		t.Fatalf("lease recovery output=%#v completed=%d", output.requests, len(tasks.completed))
	}
}

func TestCloudGoalDispatcherWithoutOutputAdapterLeavesQueueUntouched(t *testing.T) {
	now := time.Date(2026, time.July, 17, 5, 0, 0, 0, time.UTC)
	queue, tasks, facts, _, agentID := newCloudGoalDispatcherFixture(now)
	dispatcher, err := NewCloudGoalDispatcher(agentID, queue, tasks, facts, nil, CloudGoalDispatcherConfig{
		PollInterval: time.Second, LeaseDuration: 6 * time.Second, BatchSize: 8, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.RunOnce(context.Background()); err != nil {
		t.Fatalf("dormant RunOnce: %v", err)
	}
	if queue.listCalls != 0 || tasks.steps[0].LeaseEpoch != 0 {
		t.Fatalf("dormant dispatcher inspected or claimed work: list_calls=%d step=%#v", queue.listCalls, tasks.steps[0])
	}
	runContext, cancel := context.WithCancel(context.Background())
	cancel()
	if err := dispatcher.Run(runContext); !errors.Is(err, context.Canceled) || queue.listCalls != 0 {
		t.Fatalf("dormant Run error=%v list_calls=%d", err, queue.listCalls)
	}
}

type cloudGoalQueueFake struct {
	work       CloudGoalDispatch
	draft      RecipeDraft
	stageReady func(string, string, int64) bool
	listCalls  int
}

func (fake *cloudGoalQueueFake) ListDispatchableCloudGoals(context.Context, int) ([]CloudGoalDispatch, error) {
	fake.listCalls++
	if fake.work.Task.OutcomeStatus != task.OutcomePending {
		return nil, nil
	}
	return []CloudGoalDispatch{fake.work}, nil
}

func (fake *cloudGoalQueueFake) CloudGoalStageReady(_ context.Context, taskID, stepID string, leaseEpoch int64) (bool, error) {
	return fake.stageReady != nil && fake.stageReady(taskID, stepID, leaseEpoch), nil
}

func (fake *cloudGoalQueueFake) GetResearch(context.Context, task.MutationScope, Binding) (ResearchSession, error) {
	return fake.work.Session, nil
}

func (fake *cloudGoalQueueFake) GetRecipeDraft(context.Context, task.MutationScope, Binding) (RecipeDraft, bool, error) {
	return fake.draft, true, nil
}

type cloudGoalTaskFake struct {
	queue        *cloudGoalQueueFake
	steps        []task.Step
	active       task.Attempt
	completed    []task.CompleteStepCommand
	leaseExpired bool
}

func (fake *cloudGoalTaskFake) ListSteps(context.Context, string) ([]task.Step, error) {
	return append([]task.Step(nil), fake.steps...), nil
}

func (fake *cloudGoalTaskFake) AcquireReadyStep(_ context.Context, _ task.MutationScope, command task.AcquireReadyStepCommand) (task.Attempt, bool, error) {
	for index := range fake.steps {
		step := &fake.steps[index]
		if step.StepID != command.StepID {
			continue
		}
		if step.ExecutionStatus == task.ExecutionRunning && !fake.leaseExpired {
			return task.Attempt{}, false, nil
		}
		fake.leaseExpired = false
		step.ExecutionStatus = task.ExecutionRunning
		step.OutcomeStatus = task.OutcomePending
		step.Attempt++
		step.LeaseEpoch++
		fake.queue.work.Task.ExecutionStatus = task.ExecutionRunning
		fake.queue.work.Task.CurrentStepID = step.StepID
		fake.active = task.Attempt{
			TaskID: step.TaskID, StepID: step.StepID, Attempt: step.Attempt, LeaseEpoch: step.LeaseEpoch,
			WorkerID: command.WorkerID, LeaseExpiresAt: time.Now().Add(command.LeaseDuration),
			ExecutionStatus: task.ExecutionRunning, OutcomeStatus: task.OutcomePending,
		}
		return fake.active, true, nil
	}
	return task.Attempt{}, false, nil
}

func (fake *cloudGoalTaskFake) RenewStepLease(context.Context, task.MutationScope, task.RenewStepLeaseCommand) (task.Attempt, error) {
	return fake.active, nil
}

func (fake *cloudGoalTaskFake) CompleteStep(_ context.Context, _ task.MutationScope, command task.CompleteStepCommand) (task.Attempt, error) {
	if command.TaskID != fake.active.TaskID || command.StepID != fake.active.StepID || command.Attempt != fake.active.Attempt ||
		command.LeaseEpoch != fake.active.LeaseEpoch || command.WorkerID != fake.active.WorkerID {
		return task.Attempt{}, task.ErrStaleLease
	}
	for index := range fake.steps {
		if fake.steps[index].StepID == command.StepID {
			fake.steps[index].ExecutionStatus = task.ExecutionFinished
			fake.steps[index].OutcomeStatus = task.OutcomeSucceeded
			fake.steps[index].ResultRef = command.ResultRef
		}
	}
	fake.completed = append(fake.completed, command)
	completed := fake.active
	completed.ExecutionStatus = task.ExecutionFinished
	completed.OutcomeStatus = task.OutcomeSucceeded
	completed.ResultRef = command.ResultRef
	fake.queue.work.Task.ExecutionStatus = task.ExecutionQueued
	fake.queue.work.Task.CurrentStepID = ""
	if len(fake.completed) == len(fake.steps) {
		fake.queue.work.Task.ExecutionStatus = task.ExecutionFinished
		fake.queue.work.Task.OutcomeStatus = task.OutcomeSucceeded
	}
	return completed, nil
}

type cloudGoalOutputFake struct {
	queue    *cloudGoalQueueFake
	planID   string
	requests []CloudGoalStageRequest
	failOnce bool
}

func (fake *cloudGoalOutputFake) ExecuteCloudGoalStage(_ context.Context, request CloudGoalStageRequest) (CloudGoalStageOutput, error) {
	fake.requests = append(fake.requests, request)
	if fake.failOnce {
		fake.failOnce = false
		return CloudGoalStageOutput{}, errors.New("injected output interruption")
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	switch request.Step.Name {
	case cloudskill.StepResearchOfficialSources:
		return CloudGoalStageOutput{ResultRef: "planning://official-source-evidence/" + digest}, nil
	case cloudskill.StepDraftRecipe:
		return CloudGoalStageOutput{ResultRef: "planning://recipe/" + digest}, nil
	case cloudskill.StepPrepareResourceCandidates:
		fake.queue.work.Session.CandidateRevision = 1
		fake.queue.work.Session.Candidates = dispatcherCandidates()
		return CloudGoalStageOutput{PlanID: fake.planID}, nil
	default:
		return CloudGoalStageOutput{}, ErrCloudGoalOutputInvalid
	}
}

type cloudGoalFactsFake struct {
	plan  cloudapproval.PlanV1
	quote cloudquote.QuoteV1
}

func (fake *cloudGoalFactsFake) GetPlan(context.Context, string, string) (cloudapproval.PlanV1, error) {
	return fake.plan, nil
}

func (fake *cloudGoalFactsFake) GetQuote(context.Context, string, string) (cloudquote.QuoteV1, error) {
	return fake.quote, nil
}

func newCloudGoalDispatcherFixture(now time.Time) (*cloudGoalQueueFake, *cloudGoalTaskFake, *cloudGoalFactsFake, *cloudGoalOutputFake, string) {
	agentID, requestID, taskID, sessionID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	connectionID, planID, quoteID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	ownerID, recipeID := "owner-cloud-goal", "recipe-cloud-goal"
	binding := Binding{
		RequestID: requestID, OwnerID: ownerID, ConversationID: "cloud-goal-" + strings.ReplaceAll(requestID, "-", ""),
		ConnectionID: connectionID, RecipeID: recipeID, Retention: task.RetentionEphemeralAutoDestroy,
	}
	recipeDigest := "sha256:" + strings.Repeat("b", 64)
	queue := &cloudGoalQueueFake{work: CloudGoalDispatch{
		Session: ResearchSession{SessionID: sessionID, Binding: binding, TaskID: taskID, QuoteState: QuoteAwaitingQuote, Revision: 2},
		Task: task.Task{TaskID: taskID, OwnerID: ownerID, Goal: "Research an official knowledge service.", ExecutionStatus: task.ExecutionQueued,
			OutcomeStatus: task.OutcomePending, RetentionPolicy: task.RetentionEphemeralAutoDestroy, Revision: 1},
		Caller: task.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()},
	}, draft: RecipeDraft{RecipeID: recipeID, Digest: recipeDigest, Revision: 1}}
	definitions := cloudskill.PlanningSteps(requestID)
	taskNamespace := uuid.MustParse(taskID)
	steps := make([]task.Step, 0, len(definitions))
	for _, definition := range definitions {
		dependencies := make([]string, 0, len(definition.DependsOnStepIDs))
		for _, dependency := range definition.DependsOnStepIDs {
			dependencies = append(dependencies, uuid.NewSHA1(taskNamespace, []byte(dependency)).String())
		}
		steps = append(steps, task.Step{
			StepID: uuid.NewSHA1(taskNamespace, []byte(definition.StepID)).String(), TaskID: taskID,
			Name: definition.Name, DependsOnStepIDs: dependencies, ExecutorKind: task.ExecutorControlPlane,
			ExecutionStatus: task.ExecutionQueued, OutcomeStatus: task.OutcomePending, Revision: 1,
		})
	}
	tasks := &cloudGoalTaskFake{queue: queue, steps: steps}
	queue.stageReady = func(taskID, stepID string, leaseEpoch int64) bool {
		for _, step := range tasks.steps {
			if step.TaskID != taskID || step.StepID != stepID || step.LeaseEpoch != leaseEpoch {
				continue
			}
			return step.ExecutionStatus == task.ExecutionQueued || (step.ExecutionStatus == task.ExecutionRunning && tasks.leaseExpired)
		}
		return false
	}
	recipeBinding := cloudquote.RecipeBindingV1{RecipeID: recipeID, Digest: recipeDigest, Maturity: recipe.MaturityExperimental}
	profiles := []cloudquote.CandidateProfile{cloudquote.CandidateEconomic, cloudquote.CandidateRecommended, cloudquote.CandidatePerformance}
	quoted := cloudquote.QuoteV1{QuoteID: quoteID, QuotedAt: now, ValidUntil: now.Add(15 * time.Minute)}
	for index, profile := range profiles {
		quoted.Candidates = append(quoted.Candidates, cloudquote.CandidateV1{
			CandidateID: profile, ScopeDigest: "scope-" + string(profile),
			Scope: cloudquote.ScopeV1{
				AgentInstanceID: agentID, OwnerID: ownerID, ConnectionID: connectionID, Recipe: recipeBinding,
				Resource: cloudquote.ResourceScopeV1{CandidateID: profile, VCPU: uint32(index + 1), Architecture: recipe.ArchitectureAMD64},
			},
		})
	}
	facts := &cloudGoalFactsFake{
		quote: quoted,
		plan: cloudapproval.PlanV1{
			AgentInstanceID: agentID, OwnerID: ownerID, PlanID: planID, Revision: 1,
			Status: cloudapproval.PlanReadyForConfirmation, ConnectionID: connectionID,
			Recipe: cloudapproval.RecipeBindingV1{RecipeID: recipeID, Digest: recipeBinding.Digest, Maturity: recipe.MaturityExperimental},
			Quote: cloudapproval.QuoteBindingV1{
				QuoteID: quoteID, CandidateID: string(cloudquote.CandidateRecommended),
				ScopeDigest: "scope-" + string(cloudquote.CandidateRecommended), ValidUntil: quoted.ValidUntil,
			},
		},
	}
	output := &cloudGoalOutputFake{queue: queue, planID: planID}
	return queue, tasks, facts, output, agentID
}

func dispatcherCandidates() []ResourceCandidateV1 {
	return []ResourceCandidateV1{
		{Tier: TierEconomy, Architecture: recipe.ArchitectureAMD64, VCPU: 2, MemoryMiB: 4096, DiskGiB: 40, Rationale: "Minimum validated capacity."},
		{Tier: TierRecommended, Architecture: recipe.ArchitectureAMD64, VCPU: 4, MemoryMiB: 8192, DiskGiB: 80, Rationale: "Balanced steady-state capacity."},
		{Tier: TierPerformance, Architecture: recipe.ArchitectureAMD64, VCPU: 8, MemoryMiB: 16384, DiskGiB: 160, Rationale: "Extra workload headroom."},
	}
}
