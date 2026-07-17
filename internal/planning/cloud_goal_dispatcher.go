package planning

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agent/cloudskill"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

var (
	ErrCloudGoalDispatchInvalid     = errors.New("cloud Goal dispatch input is invalid")
	ErrCloudGoalOutputInvalid       = errors.New("cloud Goal output is invalid")
	ErrCloudGoalOutputAdapterFailed = errors.New("cloud Goal output adapter failed")
)

// CloudGoalDispatch is the de-secreted durable work item created by
// CloudControlService.CreateCloudGoal. Caller identifies the already
// authenticated service-key scope that owns the Task and planning session.
type CloudGoalDispatch struct {
	Session ResearchSession
	Task    task.Task
	Caller  task.MutationScope
}

// CloudGoalDispatchRepository owns queue discovery and the planning read-back
// used after the output adapter persists a candidate set.
type CloudGoalDispatchRepository interface {
	ListDispatchableCloudGoals(context.Context, int) ([]CloudGoalDispatch, error)
	CloudGoalStageReady(context.Context, string, string, int64) (bool, error)
	GetResearch(context.Context, task.MutationScope, Binding) (ResearchSession, error)
	GetRecipeDraft(context.Context, task.MutationScope, Binding) (RecipeDraft, bool, error)
}

type CloudGoalTaskRepository interface {
	ListSteps(context.Context, string) ([]task.Step, error)
	AcquireReadyStep(context.Context, task.MutationScope, task.AcquireReadyStepCommand) (task.Attempt, bool, error)
	RenewStepLease(context.Context, task.MutationScope, task.RenewStepLeaseCommand) (task.Attempt, error)
	SuspendStepForSecrets(context.Context, task.MutationScope, task.SuspendStepForSecretsCommand) (task.Attempt, error)
	CompleteStep(context.Context, task.MutationScope, task.CompleteStepCommand) (task.Attempt, error)
}

// CloudGoalPlanFacts is read-only. The dispatcher cannot approve a Plan or
// call any provider mutation through this boundary.
type CloudGoalPlanFacts interface {
	GetPlan(context.Context, string, string) (cloudapproval.PlanV1, error)
	GetQuote(context.Context, string, string) (cloudquote.QuoteV1, error)
}

// CloudGoalOutputAdapter is the single remaining output seam between the
// native cloud-dispatcher reasoning path and the durable control plane. An
// implementation must honor OutputIdempotencyKey and the supplied Task lease,
// persist only the requested stage, and never approve a Plan, execute shell,
// or perform an AWS mutation. The final stage must persist a real three-profile
// Quote and a ready_for_confirmation Plan before returning its Plan ID.
type CloudGoalOutputAdapter interface {
	ExecuteCloudGoalStage(context.Context, CloudGoalStageRequest) (CloudGoalStageOutput, error)
}

type CloudGoalStageRequest struct {
	Binding              Binding
	Caller               task.MutationScope
	Goal                 string
	Step                 task.Step
	Attempt              task.Attempt
	OutputIdempotencyKey string
}

type CloudGoalStageOutput struct {
	ResultRef string
	PlanID    string
}

type CloudGoalDispatcherConfig struct {
	PollInterval  time.Duration
	LeaseDuration time.Duration
	BatchSize     int
	ReportError   func(error)
	Now           func() time.Time
}

type CloudGoalDispatcher struct {
	agentInstanceID string
	queue           CloudGoalDispatchRepository
	tasks           CloudGoalTaskRepository
	facts           CloudGoalPlanFacts
	output          CloudGoalOutputAdapter
	config          CloudGoalDispatcherConfig
}

func NewCloudGoalDispatcher(
	agentInstanceID string,
	queue CloudGoalDispatchRepository,
	tasks CloudGoalTaskRepository,
	facts CloudGoalPlanFacts,
	output CloudGoalOutputAdapter,
	config CloudGoalDispatcherConfig,
) (*CloudGoalDispatcher, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || parsed == uuid.Nil || parsed.String() != agentInstanceID || queue == nil || tasks == nil || facts == nil {
		return nil, ErrCloudGoalDispatchInvalid
	}
	if config.PollInterval <= 0 || config.LeaseDuration < 5*time.Second || config.LeaseDuration > 30*time.Minute {
		return nil, ErrCloudGoalDispatchInvalid
	}
	if config.BatchSize <= 0 || config.BatchSize > 128 {
		return nil, ErrCloudGoalDispatchInvalid
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &CloudGoalDispatcher{
		agentInstanceID: parsed.String(), queue: queue, tasks: tasks, facts: facts, output: output, config: config,
	}, nil
}

func (dispatcher *CloudGoalDispatcher) RunOnce(ctx context.Context) error {
	if dispatcher == nil || ctx == nil {
		return ErrCloudGoalDispatchInvalid
	}
	// An output adapter is intentionally optional at composition time. Until a
	// provider can persist real Quotes and a ready Plan, the dispatcher must not
	// inspect the queue or reserve a Step lease.
	if dispatcher.output == nil {
		return nil
	}
	items, err := dispatcher.queue.ListDispatchableCloudGoals(ctx, dispatcher.config.BatchSize)
	if err != nil {
		return err
	}
	var result error
	for _, item := range items {
		if err := dispatcher.dispatchOne(ctx, item); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (dispatcher *CloudGoalDispatcher) Run(ctx context.Context) error {
	if dispatcher == nil || ctx == nil {
		return ErrCloudGoalDispatchInvalid
	}
	if dispatcher.output == nil {
		<-ctx.Done()
		return ctx.Err()
	}
	ticker := time.NewTicker(dispatcher.config.PollInterval)
	defer ticker.Stop()
	for {
		if err := dispatcher.RunOnce(ctx); err != nil && dispatcher.config.ReportError != nil {
			dispatcher.config.ReportError(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (dispatcher *CloudGoalDispatcher) dispatchOne(ctx context.Context, item CloudGoalDispatch) error {
	if err := validateCloudGoalDispatch(item); err != nil {
		return err
	}
	steps, err := dispatcher.tasks.ListSteps(ctx, item.Task.TaskID)
	if err != nil {
		return err
	}
	next, found, err := nextCloudGoalStage(item, steps)
	if err != nil || !found {
		return err
	}
	ready, err := dispatcher.queue.CloudGoalStageReady(ctx, item.Task.TaskID, next.StepID, next.LeaseEpoch)
	if err != nil || !ready {
		return err
	}
	workerID := deterministicCloudGoalUUID(dispatcher.agentInstanceID, item.Session.SessionID, "worker")
	nextEpoch := next.LeaseEpoch + 1
	attempt, acquired, err := dispatcher.tasks.AcquireReadyStep(ctx, item.Caller, task.AcquireReadyStepCommand{
		IdempotencyKey: deterministicCloudGoalUUID(item.Session.Binding.RequestID, next.StepID, "acquire", strconv.FormatInt(nextEpoch, 10)),
		TaskID:         item.Task.TaskID, StepID: next.StepID, WorkerID: workerID,
		ExecutorKind: task.ExecutorControlPlane, LeaseDuration: dispatcher.config.LeaseDuration,
	})
	if err != nil || !acquired {
		return err
	}
	if attempt.TaskID != item.Task.TaskID || attempt.StepID != next.StepID || attempt.WorkerID != workerID ||
		attempt.Attempt < 1 || attempt.LeaseEpoch != nextEpoch || attempt.ExecutionStatus != task.ExecutionRunning || attempt.OutcomeStatus != task.OutcomePending {
		return ErrCloudGoalDispatchInvalid
	}

	request := CloudGoalStageRequest{
		Binding: item.Session.Binding, Caller: item.Caller, Goal: item.Task.Goal, Step: next, Attempt: attempt,
		OutputIdempotencyKey: deterministicCloudGoalUUID(item.Session.Binding.RequestID, next.StepID, "output"),
	}
	output, err := dispatcher.executeWithLease(ctx, item.Caller, request)
	if err != nil {
		if errors.Is(err, ErrCloudGoalSecretsNotReady) {
			return dispatcher.suspendForServiceSecrets(ctx, item, next, attempt)
		}
		return err
	}
	resultRef, err := dispatcher.validateOutput(ctx, item, next, output)
	if err != nil {
		return err
	}
	relatedPlanID := ""
	if next.Name == cloudskill.StepPrepareResourceCandidates {
		relatedPlanID = output.PlanID
	}
	completed, err := dispatcher.tasks.CompleteStep(ctx, item.Caller, task.CompleteStepCommand{
		IdempotencyKey: deterministicCloudGoalUUID(item.Session.Binding.RequestID, next.StepID, "complete", strconv.FormatInt(attempt.LeaseEpoch, 10)),
		TaskID:         item.Task.TaskID, StepID: next.StepID, Attempt: attempt.Attempt, LeaseEpoch: attempt.LeaseEpoch,
		WorkerID: workerID, Outcome: task.OutcomeSucceeded, ResultRef: resultRef, RelatedPlanID: relatedPlanID,
	})
	if err != nil {
		return err
	}
	if completed.TaskID != attempt.TaskID || completed.StepID != attempt.StepID || completed.Attempt != attempt.Attempt ||
		completed.LeaseEpoch != attempt.LeaseEpoch || completed.WorkerID != attempt.WorkerID ||
		completed.ExecutionStatus != task.ExecutionFinished || completed.OutcomeStatus != task.OutcomeSucceeded {
		return ErrCloudGoalDispatchInvalid
	}
	return nil
}

func (dispatcher *CloudGoalDispatcher) suspendForServiceSecrets(ctx context.Context, item CloudGoalDispatch, step task.Step, attempt task.Attempt) error {
	if step.Name != cloudskill.StepPrepareResourceCandidates || attempt.TaskRevision < 1 || attempt.StepRevision < 1 || attempt.Revision < 1 {
		return ErrCloudGoalDispatchInvalid
	}
	draft, found, err := dispatcher.queue.GetRecipeDraft(ctx, item.Caller, item.Session.Binding)
	if err != nil || !found || draft.RecipeID != item.Session.Binding.RecipeID || draft.Digest == "" || len(draft.Recipe.SecretSlots) == 0 {
		return ErrCloudGoalDispatchInvalid
	}
	requirements := make([]task.SecretWaitRequirement, 0, len(draft.Recipe.SecretSlots))
	for _, slot := range draft.Recipe.SecretSlots {
		requirements = append(requirements, task.SecretWaitRequirement{Purpose: slot.Purpose, RecipeDigest: draft.Digest})
	}
	_, err = dispatcher.tasks.SuspendStepForSecrets(ctx, item.Caller, task.SuspendStepForSecretsCommand{
		IdempotencyKey: deterministicCloudGoalUUID(item.Session.Binding.RequestID, step.StepID, "wait-service-secrets", strconv.FormatInt(attempt.LeaseEpoch, 10)),
		TaskID:         item.Task.TaskID, StepID: step.StepID, Attempt: attempt.Attempt, LeaseEpoch: attempt.LeaseEpoch, WorkerID: attempt.WorkerID,
		ExpectedTaskRevision: attempt.TaskRevision, ExpectedStepRevision: attempt.StepRevision, ExpectedAttemptRevision: attempt.Revision,
		AgentInstanceID: dispatcher.agentInstanceID, Requirements: requirements,
	})
	return err
}

func (dispatcher *CloudGoalDispatcher) executeWithLease(ctx context.Context, caller task.MutationScope, request CloudGoalStageRequest) (CloudGoalStageOutput, error) {
	executionCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	renewalError := make(chan error, 1)
	go func() {
		defer close(done)
		interval := dispatcher.config.LeaseDuration / 3
		timer := time.NewTimer(interval)
		defer timer.Stop()
		var renewal int64
		for {
			select {
			case <-executionCtx.Done():
				return
			case <-timer.C:
			}
			renewal++
			attempt, err := dispatcher.tasks.RenewStepLease(executionCtx, caller, task.RenewStepLeaseCommand{
				IdempotencyKey: deterministicCloudGoalUUID(request.Binding.RequestID, request.Step.StepID, "renew", strconv.FormatInt(request.Attempt.LeaseEpoch, 10), strconv.FormatInt(renewal, 10)),
				TaskID:         request.Attempt.TaskID, StepID: request.Attempt.StepID, Attempt: request.Attempt.Attempt,
				LeaseEpoch: request.Attempt.LeaseEpoch, WorkerID: request.Attempt.WorkerID, LeaseDuration: dispatcher.config.LeaseDuration,
			})
			if err != nil || attempt.LeaseEpoch != request.Attempt.LeaseEpoch || attempt.WorkerID != request.Attempt.WorkerID {
				if err == nil {
					err = task.ErrStaleLease
				}
				renewalError <- err
				cancel()
				return
			}
			timer.Reset(interval)
		}
	}()
	output, outputErr := dispatcher.output.ExecuteCloudGoalStage(executionCtx, request)
	cancel()
	<-done
	select {
	case err := <-renewalError:
		return CloudGoalStageOutput{}, err
	default:
	}
	if outputErr != nil {
		if errors.Is(outputErr, ErrCloudGoalSecretsNotReady) {
			// dispatchOne converts this into a lease-fenced, durable waiting_user
			// transition. It is not a failed stage and never leaves a busy lease
			// behind while the user uploads the declared service secret.
			return CloudGoalStageOutput{}, ErrCloudGoalSecretsNotReady
		}
		return CloudGoalStageOutput{}, fmt.Errorf("%w", ErrCloudGoalOutputAdapterFailed)
	}
	return output, nil
}

func (dispatcher *CloudGoalDispatcher) validateOutput(ctx context.Context, item CloudGoalDispatch, step task.Step, output CloudGoalStageOutput) (string, error) {
	if output.ValidateForStage(step.Name) != nil {
		return "", ErrCloudGoalOutputInvalid
	}
	switch step.Name {
	case cloudskill.StepResearchOfficialSources, cloudskill.StepDraftRecipe:
		return output.ResultRef, nil
	case cloudskill.StepPrepareResourceCandidates:
		return dispatcher.validateReadyPlan(ctx, item, output)
	default:
		return "", ErrCloudGoalOutputInvalid
	}
}

func (dispatcher *CloudGoalDispatcher) validateReadyPlan(ctx context.Context, item CloudGoalDispatch, output CloudGoalStageOutput) (string, error) {
	planID, err := uuid.Parse(output.PlanID)
	if err != nil || planID == uuid.Nil || planID.String() != output.PlanID || output.ResultRef != "" {
		return "", ErrCloudGoalOutputInvalid
	}
	session, err := dispatcher.queue.GetResearch(ctx, item.Caller, item.Session.Binding)
	if err != nil || session.SessionID != item.Session.SessionID || session.TaskID != item.Task.TaskID ||
		session.CandidateRevision < 1 || len(session.Candidates) != 3 || ValidateResourceCandidates(session.Candidates, QuoteAwaitingQuote) != nil {
		return "", ErrCloudGoalOutputInvalid
	}
	draft, found, err := dispatcher.queue.GetRecipeDraft(ctx, item.Caller, item.Session.Binding)
	if err != nil || !found || draft.RecipeID != item.Session.Binding.RecipeID || draft.Revision < 1 {
		return "", ErrCloudGoalOutputInvalid
	}
	plan, err := dispatcher.facts.GetPlan(ctx, item.Task.OwnerID, output.PlanID)
	if err != nil || plan.PlanID != output.PlanID || plan.AgentInstanceID != dispatcher.agentInstanceID ||
		plan.OwnerID != item.Task.OwnerID || plan.ConnectionID != item.Session.Binding.ConnectionID ||
		plan.Recipe.RecipeID != item.Session.Binding.RecipeID || plan.Recipe.Digest != draft.Digest || plan.Recipe.Maturity != recipe.MaturityExperimental ||
		plan.Status != cloudapproval.PlanReadyForConfirmation || plan.Revision != 1 {
		return "", ErrCloudGoalOutputInvalid
	}
	quoted, err := dispatcher.facts.GetQuote(ctx, item.Task.OwnerID, plan.Quote.QuoteID)
	if err != nil || quoted.QuoteID != plan.Quote.QuoteID || len(quoted.Candidates) != 3 ||
		!quoted.ValidUntil.Equal(plan.Quote.ValidUntil) || !dispatcher.config.Now().UTC().Before(quoted.ValidUntil) {
		return "", ErrCloudGoalOutputInvalid
	}
	wantProfiles := []cloudquote.CandidateProfile{cloudquote.CandidateEconomic, cloudquote.CandidateRecommended, cloudquote.CandidatePerformance}
	for _, profile := range wantProfiles {
		candidate, found := quoted.Candidate(profile)
		if !found || candidate.Scope.AgentInstanceID != dispatcher.agentInstanceID || candidate.Scope.OwnerID != item.Task.OwnerID ||
			candidate.Scope.ConnectionID != item.Session.Binding.ConnectionID || candidate.Scope.Recipe.RecipeID != item.Session.Binding.RecipeID ||
			candidate.Scope.Recipe.Digest != draft.Digest || candidate.Scope.Recipe.Maturity != recipe.MaturityExperimental {
			return "", ErrCloudGoalOutputInvalid
		}
	}
	selected, found := quoted.Candidate(cloudquote.CandidateProfile(plan.Quote.CandidateID))
	if !found || selected.ScopeDigest != plan.Quote.ScopeDigest {
		return "", ErrCloudGoalOutputInvalid
	}
	return "cloud://plan/" + output.PlanID, nil
}

func validateCloudGoalDispatch(item CloudGoalDispatch) error {
	requestID, err := uuid.Parse(item.Session.Binding.RequestID)
	sessionID, sessionErr := uuid.Parse(item.Session.SessionID)
	taskID, taskErr := uuid.Parse(item.Task.TaskID)
	if err != nil || requestID == uuid.Nil || sessionErr != nil || sessionID == uuid.Nil || taskErr != nil || taskID == uuid.Nil ||
		item.Session.Binding.Validate() != nil || item.Caller.Validate() != nil || item.Session.TaskID != item.Task.TaskID ||
		item.Session.Binding.OwnerID != item.Task.OwnerID || item.Session.Binding.ConnectionID == "" ||
		item.Session.Binding.Retention != item.Task.RetentionPolicy || item.Session.QuoteState != QuoteAwaitingQuote ||
		item.Task.OutcomeStatus != task.OutcomePending || item.Task.ApprovedPlanID != "" {
		return ErrCloudGoalDispatchInvalid
	}
	wantConversation := "cloud-goal-" + strings.ReplaceAll(requestID.String(), "-", "")
	if item.Session.Binding.ConversationID != wantConversation ||
		(item.Task.ExecutionStatus != task.ExecutionPlanning && item.Task.ExecutionStatus != task.ExecutionQueued && item.Task.ExecutionStatus != task.ExecutionRunning) {
		return ErrCloudGoalDispatchInvalid
	}
	return nil
}

func nextCloudGoalStage(item CloudGoalDispatch, steps []task.Step) (task.Step, bool, error) {
	definitions := cloudskill.PlanningSteps(item.Session.Binding.RequestID)
	if len(steps) != len(definitions) {
		return task.Step{}, false, ErrCloudGoalDispatchInvalid
	}
	taskNamespace, err := uuid.Parse(item.Task.TaskID)
	if err != nil || taskNamespace == uuid.Nil {
		return task.Step{}, false, ErrCloudGoalDispatchInvalid
	}
	byID := make(map[string]task.Step, len(steps))
	for _, step := range steps {
		byID[step.StepID] = step
	}
	for _, definition := range definitions {
		stepID := uuid.NewSHA1(taskNamespace, []byte(definition.StepID)).String()
		step, found := byID[stepID]
		if !found || step.TaskID != item.Task.TaskID || step.Name != definition.Name || step.ExecutorKind != task.ExecutorControlPlane {
			return task.Step{}, false, ErrCloudGoalDispatchInvalid
		}
		dependencies := make([]string, 0, len(definition.DependsOnStepIDs))
		for _, dependency := range definition.DependsOnStepIDs {
			dependencies = append(dependencies, uuid.NewSHA1(taskNamespace, []byte(dependency)).String())
		}
		if strings.Join(step.DependsOnStepIDs, "\x00") != strings.Join(dependencies, "\x00") {
			return task.Step{}, false, ErrCloudGoalDispatchInvalid
		}
		if step.ExecutionStatus == task.ExecutionFinished {
			if step.OutcomeStatus != task.OutcomeSucceeded {
				return task.Step{}, false, ErrCloudGoalDispatchInvalid
			}
			continue
		}
		if step.OutcomeStatus != task.OutcomePending || (step.ExecutionStatus != task.ExecutionQueued && step.ExecutionStatus != task.ExecutionRunning) {
			return task.Step{}, false, ErrCloudGoalDispatchInvalid
		}
		return step, true, nil
	}
	return task.Step{}, false, ErrCloudGoalDispatchInvalid
}

func validPlanningDigestRef(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	return recipe.ValidateDigest(strings.TrimPrefix(value, prefix)) == nil
}

func deterministicCloudGoalUUID(namespace string, values ...string) string {
	parsed := uuid.MustParse(namespace)
	return uuid.NewSHA1(parsed, []byte("cloud-goal-dispatch\x00"+strings.Join(values, "\x00"))).String()
}
