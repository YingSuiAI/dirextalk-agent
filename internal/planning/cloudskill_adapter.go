package planning

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agent/cloudskill"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

type TaskRepository interface {
	Create(context.Context, task.MutationScope, task.CreateCommand) (task.Task, error)
	Get(context.Context, string) (task.Task, error)
	ListSteps(context.Context, string) ([]task.Step, error)
	AcquireReadyStep(context.Context, task.MutationScope, task.AcquireReadyStepCommand) (task.Attempt, bool, error)
	CompleteStep(context.Context, task.MutationScope, task.CompleteStepCommand) (task.Attempt, error)
}

type CloudSkillAdapter struct {
	planning Repository
	tasks    TaskRepository
}

var (
	_ cloudskill.ResearchPort    = (*CloudSkillAdapter)(nil)
	_ cloudskill.StatusPort      = (*CloudSkillAdapter)(nil)
	_ cloudskill.RecipeDraftPort = (*CloudSkillAdapter)(nil)
	_ cloudskill.PlanDraftPort   = (*CloudSkillAdapter)(nil)
)

func NewCloudSkillAdapter(repository Repository, tasks TaskRepository) (*CloudSkillAdapter, error) {
	if repository == nil || tasks == nil {
		return nil, ErrInvalid
	}
	return &CloudSkillAdapter{planning: repository, tasks: tasks}, nil
}

func (adapter *CloudSkillAdapter) CreateResearch(ctx context.Context, request cloudskill.ResearchRequest) (task.Task, error) {
	scope, err := mutationScopeFromContext(ctx)
	if err != nil {
		return task.Task{}, err
	}
	command := ResearchCommand{
		Binding: Binding{
			RequestID: request.Create.IdempotencyKey, OwnerID: request.Create.OwnerID,
			ConversationID: request.ConversationID, ConnectionID: request.ConnectionID,
			RecipeID: request.RecipeID, Retention: request.Create.Retention,
		},
		Create: request.Create,
	}
	if err := command.Validate(); err != nil {
		return task.Task{}, err
	}
	session, err := adapter.planning.ClaimResearch(ctx, scope, command)
	if err != nil {
		return task.Task{}, err
	}

	if session.TaskID == "" {
		created, createErr := adapter.tasks.Create(ctx, scope, command.Create)
		if createErr != nil {
			return task.Task{}, ErrTaskOperation
		}
		if !taskMatchesResearch(created, command) {
			return task.Task{}, ErrTaskOperation
		}
		session, err = adapter.planning.AttachResearchTask(ctx, scope, command.Binding, created.TaskID)
		if err != nil {
			// The claimed session remains durable and the task creation is itself
			// idempotent. A replay resumes attachment instead of buying or
			// creating a second unit of work.
			return task.Task{}, err
		}
		if session.TaskID != created.TaskID {
			return task.Task{}, ErrPersistence
		}
		return created, nil
	}

	// Re-enter Task.Create so the task-owned idempotency snapshot is returned
	// even if the live Task has advanced since the original Goal response.
	created, err := adapter.tasks.Create(ctx, scope, command.Create)
	if err != nil || created.TaskID != session.TaskID || !taskMatchesResearch(created, command) {
		return task.Task{}, ErrTaskOperation
	}
	return created, nil
}

func (adapter *CloudSkillAdapter) GetResearchStatus(ctx context.Context, request cloudskill.StatusRequest) (cloudskill.ResearchStatus, error) {
	scope, err := mutationScopeFromContext(ctx)
	if err != nil {
		return cloudskill.ResearchStatus{}, err
	}
	binding := bindingFromCloudSkill(request.Binding)
	session, err := adapter.planning.GetResearch(ctx, scope, binding)
	if err != nil {
		return cloudskill.ResearchStatus{}, err
	}
	if session.TaskID == "" {
		return cloudskill.ResearchStatus{}, ErrResearchPending
	}
	item, err := adapter.tasks.Get(ctx, session.TaskID)
	if err != nil || item.OwnerID != binding.OwnerID || item.RetentionPolicy != binding.Retention {
		return cloudskill.ResearchStatus{}, ErrTaskOperation
	}
	steps, err := adapter.tasks.ListSteps(ctx, session.TaskID)
	if err != nil {
		return cloudskill.ResearchStatus{}, ErrTaskOperation
	}
	return cloudskill.ResearchStatus{Task: item, Steps: steps}, nil
}

func (adapter *CloudSkillAdapter) GetRecipeDraft(ctx context.Context, request cloudskill.RecipeDraftRequest) (cloudskill.RecipeDraft, error) {
	scope, err := mutationScopeFromContext(ctx)
	if err != nil {
		return cloudskill.RecipeDraft{}, err
	}
	draft, found, err := adapter.planning.GetRecipeDraft(ctx, scope, bindingFromCloudSkill(request.Binding))
	if err != nil {
		return cloudskill.RecipeDraft{}, err
	}
	if !found {
		return cloudskill.RecipeDraft{Ready: false}, nil
	}
	return cloudskill.RecipeDraft{Ready: true, Recipe: draft.Recipe}, nil
}

func (adapter *CloudSkillAdapter) SubmitPlanDraft(ctx context.Context, request cloudskill.SubmitPlanDraftRequest) (cloudskill.SubmitPlanDraftResult, error) {
	scope, err := planDraftMutationScopeFromContext(ctx)
	if err != nil {
		return cloudskill.SubmitPlanDraftResult{}, err
	}
	binding := bindingFromCloudSkill(request.Binding)
	if err := binding.Validate(); err != nil || !validOpaqueID(request.ToolCallID, 255) ||
		request.Recipe.SchemaVersion != recipe.SchemaV1 || request.Recipe.RecipeID != binding.RecipeID ||
		request.Recipe.Maturity != recipe.MaturityExperimental || request.Recipe.ManagedAcceptance != nil {
		return cloudskill.SubmitPlanDraftResult{}, ErrInvalid
	}
	if err := request.Recipe.Validate(); err != nil {
		return cloudskill.SubmitPlanDraftResult{}, ErrInvalid
	}
	candidates := planningCandidates(request.Candidates)
	quoteState := QuoteAwaitingQuote
	if binding.ConnectionID == "" {
		quoteState = QuoteAwaitingConnection
	}
	if err := ValidateResourceCandidates(candidates, quoteState); err != nil {
		return cloudskill.SubmitPlanDraftResult{}, err
	}
	if err := ValidateCandidatesAgainstRecipe(candidates, request.Recipe.Requirements); err != nil {
		return cloudskill.SubmitPlanDraftResult{}, err
	}

	session, err := adapter.planning.GetResearch(ctx, scope, binding)
	if err != nil {
		return cloudskill.SubmitPlanDraftResult{}, err
	}
	if session.Binding != binding || session.TaskID == "" {
		return cloudskill.SubmitPlanDraftResult{}, ErrResearchPending
	}
	item, err := adapter.tasks.Get(ctx, session.TaskID)
	if err != nil || item.OwnerID != binding.OwnerID || item.RetentionPolicy != binding.Retention {
		return cloudskill.SubmitPlanDraftResult{}, ErrTaskOperation
	}
	definitions, err := validatePersistedPlanningDAG(adapter.tasks, ctx, binding.RequestID, item.TaskID)
	if err != nil {
		return cloudskill.SubmitPlanDraftResult{}, err
	}
	evidence, err := adapter.planning.BindOfficialSourceEvidence(ctx, scope, BindOfficialSourceEvidenceCommand{
		Binding: binding, TaskID: item.TaskID, Sources: request.Recipe.Sources,
	})
	if err != nil {
		return cloudskill.SubmitPlanDraftResult{}, err
	}

	workerID := deterministicSubmissionUUID(binding.RequestID, request.ToolCallID, "worker", "control-plane")
	if err := adapter.advancePlanStage(ctx, scope, request, item.TaskID, workerID, definitions[0], func() (string, error) {
		return evidence.ResultRef(), nil
	}); err != nil {
		return cloudskill.SubmitPlanDraftResult{}, err
	}

	var savedDraft RecipeDraft
	if err := adapter.advancePlanStage(ctx, scope, request, item.TaskID, workerID, definitions[1], func() (string, error) {
		existing, found, loadErr := adapter.planning.GetRecipeDraft(ctx, scope, binding)
		if loadErr != nil {
			return "", loadErr
		}
		wantedDigest, digestErr := request.Recipe.Digest()
		if digestErr != nil {
			return "", ErrInvalid
		}
		if found {
			if existing.Digest != wantedDigest || existing.Revision < 1 {
				return "", ErrIdempotencyConflict
			}
			savedDraft = existing
		} else {
			savedDraft, loadErr = adapter.planning.SaveRecipeDraft(ctx, scope, SaveRecipeDraftCommand{
				IdempotencyKey: deterministicSubmissionUUID(binding.RequestID, request.ToolCallID, cloudskill.StepDraftRecipe, "save"),
				Binding:        binding, ExpectedRevision: 0, Recipe: request.Recipe,
			})
			if loadErr != nil {
				return "", loadErr
			}
		}
		return "planning://recipe/" + savedDraft.Digest, nil
	}); err != nil {
		return cloudskill.SubmitPlanDraftResult{}, err
	}

	var savedCandidates ResourceCandidateSet
	if err := adapter.advancePlanStage(ctx, scope, request, item.TaskID, workerID, definitions[2], func() (string, error) {
		current, loadErr := adapter.planning.GetResearch(ctx, scope, binding)
		if loadErr != nil {
			return "", loadErr
		}
		if current.CandidateRevision > 0 {
			if current.QuoteState != quoteState || !slices.Equal(canonicalCandidates(current.Candidates), canonicalCandidates(candidates)) {
				return "", ErrIdempotencyConflict
			}
			savedCandidates = ResourceCandidateSet{
				Candidates: canonicalCandidates(current.Candidates), QuoteState: current.QuoteState, Revision: current.CandidateRevision,
			}
		} else {
			savedCandidates, loadErr = adapter.planning.SaveResourceCandidates(ctx, scope, SaveCandidatesCommand{
				IdempotencyKey: deterministicSubmissionUUID(binding.RequestID, request.ToolCallID, cloudskill.StepPrepareResourceCandidates, "save"),
				Binding:        binding, ExpectedRevision: 0, Candidates: candidates, QuoteState: quoteState,
			})
			if loadErr != nil {
				return "", loadErr
			}
		}
		return "planning://resource-candidates/revision/" + stringRevision(savedCandidates.Revision), nil
	}); err != nil {
		return cloudskill.SubmitPlanDraftResult{}, err
	}

	item, err = adapter.tasks.Get(ctx, item.TaskID)
	if err != nil || item.ExecutionStatus != task.ExecutionFinished || item.OutcomeStatus != task.OutcomeSucceeded || item.Revision < 1 {
		return cloudskill.SubmitPlanDraftResult{}, ErrTaskOperation
	}
	if savedDraft.Revision == 0 {
		savedDraft, _, err = adapter.planning.GetRecipeDraft(ctx, scope, binding)
		if err != nil || savedDraft.Revision < 1 {
			return cloudskill.SubmitPlanDraftResult{}, ErrPersistence
		}
	}
	if savedCandidates.Revision == 0 {
		current, loadErr := adapter.planning.GetResearch(ctx, scope, binding)
		if loadErr != nil || current.CandidateRevision < 1 {
			return cloudskill.SubmitPlanDraftResult{}, ErrPersistence
		}
		savedCandidates = ResourceCandidateSet{Candidates: canonicalCandidates(current.Candidates), QuoteState: current.QuoteState, Revision: current.CandidateRevision}
	}
	wantedDigest, digestErr := request.Recipe.Digest()
	if digestErr != nil || savedDraft.RecipeID != binding.RecipeID || savedDraft.Recipe.RecipeID != binding.RecipeID ||
		savedDraft.Recipe.Maturity != recipe.MaturityExperimental || savedDraft.Digest != wantedDigest || savedDraft.Revision < 1 {
		return cloudskill.SubmitPlanDraftResult{}, ErrPersistence
	}
	if err := savedDraft.Recipe.Validate(); err != nil {
		return cloudskill.SubmitPlanDraftResult{}, ErrPersistence
	}
	if savedCandidates.QuoteState != quoteState || savedCandidates.Revision < 1 ||
		!slices.Equal(canonicalCandidates(savedCandidates.Candidates), canonicalCandidates(candidates)) {
		return cloudskill.SubmitPlanDraftResult{}, ErrPersistence
	}
	if err := ValidateCandidatesAgainstRecipe(savedCandidates.Candidates, savedDraft.Recipe.Requirements); err != nil {
		return cloudskill.SubmitPlanDraftResult{}, ErrPersistence
	}
	return cloudskill.SubmitPlanDraftResult{
		TaskID: item.TaskID, ExecutionStatus: item.ExecutionStatus, OutcomeStatus: item.OutcomeStatus, TaskRevision: item.Revision,
		RecipeDigest: savedDraft.Digest, RecipeRevision: savedDraft.Revision,
		QuoteState: string(savedCandidates.QuoteState), CandidateRevision: savedCandidates.Revision,
		Candidates: candidateSummaries(savedCandidates.Candidates),
	}, nil
}

type persistedPlanningStep struct {
	Name   string
	StepID string
}

func validatePersistedPlanningDAG(tasks TaskRepository, ctx context.Context, requestID, taskID string) ([]persistedPlanningStep, error) {
	steps, err := tasks.ListSteps(ctx, taskID)
	if err != nil {
		return nil, ErrTaskOperation
	}
	definitions := cloudskill.PlanningSteps(requestID)
	if len(steps) != len(definitions) {
		return nil, ErrTaskOperation
	}
	taskNamespace, parseErr := uuid.Parse(taskID)
	if parseErr != nil {
		return nil, ErrTaskOperation
	}
	byID := make(map[string]task.Step, len(steps))
	for _, step := range steps {
		byID[step.StepID] = step
	}
	result := make([]persistedPlanningStep, 0, len(definitions))
	for _, definition := range definitions {
		stepID := uuid.NewSHA1(taskNamespace, []byte(definition.StepID)).String()
		step, ok := byID[stepID]
		if !ok || step.TaskID != taskID || step.Name != definition.Name || step.ExecutorKind != task.ExecutorControlPlane || step.Revision < 1 {
			return nil, ErrTaskOperation
		}
		wantDependencies := make([]string, 0, len(definition.DependsOnStepIDs))
		for _, dependency := range definition.DependsOnStepIDs {
			wantDependencies = append(wantDependencies, uuid.NewSHA1(taskNamespace, []byte(dependency)).String())
		}
		if !slices.Equal(step.DependsOnStepIDs, wantDependencies) {
			return nil, ErrTaskOperation
		}
		result = append(result, persistedPlanningStep{Name: definition.Name, StepID: stepID})
	}
	return result, nil
}

func (adapter *CloudSkillAdapter) advancePlanStage(
	ctx context.Context,
	scope task.MutationScope,
	request cloudskill.SubmitPlanDraftRequest,
	taskID, workerID string,
	stage persistedPlanningStep,
	action func() (string, error),
) error {
	steps, err := adapter.tasks.ListSteps(ctx, taskID)
	if err != nil {
		return ErrTaskOperation
	}
	for _, step := range steps {
		if step.StepID != stage.StepID {
			continue
		}
		if step.ExecutionStatus == task.ExecutionFinished {
			if step.OutcomeStatus == task.OutcomeSucceeded {
				return nil
			}
			return ErrTaskOperation
		}
		break
	}
	attempt, found, err := adapter.tasks.AcquireReadyStep(ctx, scope, task.AcquireReadyStepCommand{
		IdempotencyKey: deterministicSubmissionUUID(request.Binding.RequestID, request.ToolCallID, stage.Name, "acquire"),
		TaskID:         taskID, StepID: stage.StepID, WorkerID: workerID, ExecutorKind: task.ExecutorControlPlane, LeaseDuration: 5 * time.Minute,
	})
	if err != nil {
		return ErrTaskOperation
	}
	if !found {
		return cloudskill.ErrPlanDraftNotReady
	}
	if attempt.TaskID != taskID || attempt.StepID != stage.StepID || attempt.WorkerID != workerID || attempt.Attempt < 1 || attempt.LeaseEpoch < 1 {
		return ErrTaskOperation
	}
	resultRef, err := action()
	if err != nil {
		return err
	}
	completed, err := adapter.tasks.CompleteStep(ctx, scope, task.CompleteStepCommand{
		IdempotencyKey: deterministicSubmissionUUID(request.Binding.RequestID, request.ToolCallID, stage.Name, "complete"),
		TaskID:         taskID, StepID: attempt.StepID, Attempt: attempt.Attempt, LeaseEpoch: attempt.LeaseEpoch,
		WorkerID: workerID, Outcome: task.OutcomeSucceeded, ResultRef: resultRef,
	})
	if err != nil || completed.ExecutionStatus != task.ExecutionFinished || completed.OutcomeStatus != task.OutcomeSucceeded {
		return ErrTaskOperation
	}
	return nil
}

func planDraftMutationScopeFromContext(ctx context.Context) (task.MutationScope, error) {
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok || !principal.HasScope("runtime.write") {
		return task.MutationScope{}, ErrScopeMismatch
	}
	scope := task.MutationScope{ClientID: strings.TrimSpace(principal.ClientID), CredentialID: principal.CredentialID}
	if err := scope.Validate(); err != nil {
		return task.MutationScope{}, ErrScopeMismatch
	}
	return scope, nil
}

func deterministicSubmissionUUID(requestID, toolCallID, stage, operation string) string {
	namespace := uuid.MustParse(requestID)
	return uuid.NewSHA1(namespace, []byte("cloud-dispatcher-plan-draft\x00"+toolCallID+"\x00"+stage+"\x00"+operation)).String()
}

func planningCandidates(values []cloudskill.ResourceCandidateDraftV1) []ResourceCandidateV1 {
	result := make([]ResourceCandidateV1, 0, len(values))
	for _, value := range values {
		result = append(result, ResourceCandidateV1{
			Tier: CandidateTier(value.Tier), Architecture: value.Architecture, VCPU: value.VCPU,
			MemoryMiB: value.MemoryMiB, DiskGiB: value.DiskGiB, GPURequired: value.GPURequired,
			GPUMemoryMiB: value.GPUMemoryMiB, GPUFamily: value.GPUFamily, Rationale: value.Rationale,
		})
	}
	return result
}

func candidateSummaries(values []ResourceCandidateV1) []cloudskill.CandidateSummary {
	values = canonicalCandidates(values)
	result := make([]cloudskill.CandidateSummary, 0, len(values))
	for _, value := range values {
		result = append(result, cloudskill.CandidateSummary{
			Tier: string(value.Tier), Architecture: value.Architecture, VCPU: value.VCPU,
			MemoryMiB: value.MemoryMiB, DiskGiB: value.DiskGiB,
			GPURequired: value.GPURequired, GPUMemoryMiB: value.GPUMemoryMiB,
		})
	}
	return result
}

func stringRevision(value int64) string {
	return strconv.FormatInt(value, 10)
}

func mutationScopeFromContext(ctx context.Context) (task.MutationScope, error) {
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok {
		return task.MutationScope{}, ErrScopeMismatch
	}
	scope := task.MutationScope{ClientID: strings.TrimSpace(principal.ClientID), CredentialID: principal.CredentialID}
	if err := scope.Validate(); err != nil {
		return task.MutationScope{}, ErrScopeMismatch
	}
	return scope, nil
}

func bindingFromCloudSkill(binding cloudskill.Binding) Binding {
	return Binding{
		RequestID: binding.RequestID, OwnerID: binding.OwnerID, ConversationID: binding.ConversationID,
		ConnectionID: binding.ConnectionID, RecipeID: binding.RecipeID, Retention: binding.Retention,
	}
}

func taskMatchesResearch(item task.Task, command ResearchCommand) bool {
	return item.TaskID != "" && item.OwnerID == command.Binding.OwnerID && item.Goal == strings.TrimSpace(command.Create.Goal) &&
		item.RetentionPolicy == command.Binding.Retention && item.Revision > 0
}
