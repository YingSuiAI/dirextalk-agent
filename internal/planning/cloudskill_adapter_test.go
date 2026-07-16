package planning

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agent/cloudskill"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestCloudSkillAdapterRecoversAttachmentWithoutDuplicateTask(t *testing.T) {
	t.Parallel()
	command := validResearchCommand()
	repository := &adapterRepositoryStub{failFirstAttach: true}
	tasks := &adapterTaskStub{}
	adapter, err := NewCloudSkillAdapter(repository, tasks)
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
	request := cloudskill.ResearchRequest{
		Create: command.Create, ConversationID: command.Binding.ConversationID,
		ConnectionID: command.Binding.ConnectionID, RecipeID: command.Binding.RecipeID,
	}

	if _, err := adapter.CreateResearch(ctx, request); !errors.Is(err, ErrPersistence) {
		t.Fatalf("injected attach failure error = %v, want ErrPersistence", err)
	}
	created, err := adapter.CreateResearch(ctx, request)
	if err != nil {
		t.Fatalf("research replay failed: %v", err)
	}
	if created.TaskID == "" || repository.session.TaskID != created.TaskID || tasks.distinctCreates != 1 {
		t.Fatalf("recovery state task=%q mapped=%q distinct_creates=%d", created.TaskID, repository.session.TaskID, tasks.distinctCreates)
	}
}

func TestCloudSkillAdapterRequiresAuthenticatedPrincipal(t *testing.T) {
	t.Parallel()
	adapter, err := NewCloudSkillAdapter(&adapterRepositoryStub{}, &adapterTaskStub{})
	if err != nil {
		t.Fatal(err)
	}
	command := validResearchCommand()
	_, err = adapter.CreateResearch(context.Background(), cloudskill.ResearchRequest{
		Create: command.Create, ConversationID: command.Binding.ConversationID,
		ConnectionID: command.Binding.ConnectionID, RecipeID: command.Binding.RecipeID,
	})
	if !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("missing principal error = %v, want ErrScopeMismatch", err)
	}
}

func TestCloudSkillAdapterSubmitsThreeStepPlanDraftExactlyOnce(t *testing.T) {
	t.Parallel()

	adapter, repository, tasks, ctx, request := newPlanDraftFixture(t, false)
	first, err := adapter.SubmitPlanDraft(ctx, request)
	if err != nil {
		t.Fatalf("SubmitPlanDraft() error = %v", err)
	}
	second, err := adapter.SubmitPlanDraft(ctx, request)
	if err != nil {
		t.Fatalf("SubmitPlanDraft() replay error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("idempotent result changed: first=%#v second=%#v", first, second)
	}
	if first.ExecutionStatus != task.ExecutionFinished || first.OutcomeStatus != task.OutcomeSucceeded ||
		first.RecipeRevision != 1 || first.CandidateRevision != 1 || first.QuoteState != string(QuoteAwaitingQuote) || len(first.Candidates) != 3 {
		t.Fatalf("completed plan draft = %#v", first)
	}
	repository.mu.Lock()
	if repository.saveRecipeCalls != 1 || repository.saveCandidateCalls != 1 || repository.providerMutationCalls != 0 {
		t.Fatalf("planning writes recipe=%d candidates=%d provider=%d", repository.saveRecipeCalls, repository.saveCandidateCalls, repository.providerMutationCalls)
	}
	for _, operation := range repository.operations {
		if strings.Contains(operation, "provider") || strings.Contains(operation, "aws") || strings.Contains(operation, "credential") {
			t.Fatalf("unexpected provider-capable operation %q", operation)
		}
	}
	repository.mu.Unlock()

	tasks.mu.Lock()
	if tasks.acquireCalls != 3 || tasks.completeCalls != 3 {
		t.Fatalf("step mutations acquire=%d complete=%d, want three each", tasks.acquireCalls, tasks.completeCalls)
	}
	steps := append([]task.Step(nil), tasks.stepsByTask[first.TaskID]...)
	tasks.mu.Unlock()
	if len(steps) != 3 {
		t.Fatalf("planning step count = %d", len(steps))
	}
	for _, step := range steps {
		if step.ExecutorKind != task.ExecutorControlPlane || step.ExecutionStatus != task.ExecutionFinished || step.OutcomeStatus != task.OutcomeSucceeded {
			t.Fatalf("planning step did not finish under CONTROL_PLANE: %#v", step)
		}
	}
	if !strings.HasPrefix(steps[0].ResultRef, "planning://official-source-evidence/sha256:") {
		t.Fatalf("research result_ref is not bound evidence: %q", steps[0].ResultRef)
	}
}

func TestCloudSkillAdapterRejectsPlanDraftWithoutDurableOfficialSourceEvidence(t *testing.T) {
	t.Parallel()

	adapter, repository, tasks, ctx, request := newPlanDraftFixture(t, false)
	repository.mu.Lock()
	repository.missingEvidence = true
	repository.mu.Unlock()
	if _, err := adapter.SubmitPlanDraft(ctx, request); !errors.Is(err, ErrResearchEvidenceMissing) {
		t.Fatalf("missing evidence error = %v, want ErrResearchEvidenceMissing", err)
	}
	repository.mu.Lock()
	if repository.bindEvidenceCalls != 1 || repository.saveRecipeCalls != 0 || repository.saveCandidateCalls != 0 {
		t.Fatalf("missing evidence reached planning writes: bind=%d recipe=%d candidates=%d", repository.bindEvidenceCalls, repository.saveRecipeCalls, repository.saveCandidateCalls)
	}
	repository.mu.Unlock()
	tasks.mu.Lock()
	if tasks.acquireCalls != 0 || tasks.completeCalls != 0 {
		t.Fatalf("missing evidence advanced Task: acquire=%d complete=%d", tasks.acquireCalls, tasks.completeCalls)
	}
	tasks.mu.Unlock()
}

func TestCloudSkillAdapterRecoversAfterRecipePersistenceResponseLoss(t *testing.T) {
	t.Parallel()

	adapter, repository, tasks, ctx, request := newPlanDraftFixture(t, true)
	if _, err := adapter.SubmitPlanDraft(ctx, request); !errors.Is(err, ErrPersistence) {
		t.Fatalf("first submit error = %v, want injected ErrPersistence", err)
	}
	repository.mu.Lock()
	if !repository.draftFound || repository.saveRecipeCalls != 1 || repository.saveCandidateCalls != 0 {
		t.Fatalf("partial persistence state draft=%v recipe_calls=%d candidate_calls=%d", repository.draftFound, repository.saveRecipeCalls, repository.saveCandidateCalls)
	}
	repository.mu.Unlock()

	result, err := adapter.SubmitPlanDraft(ctx, request)
	if err != nil {
		t.Fatalf("recovered submit error = %v", err)
	}
	if result.ExecutionStatus != task.ExecutionFinished || result.OutcomeStatus != task.OutcomeSucceeded {
		t.Fatalf("recovered result = %#v", result)
	}
	repository.mu.Lock()
	if repository.saveRecipeCalls != 1 || repository.saveCandidateCalls != 1 {
		t.Fatalf("recovery duplicated persistence: recipe=%d candidates=%d", repository.saveRecipeCalls, repository.saveCandidateCalls)
	}
	repository.mu.Unlock()
	tasks.mu.Lock()
	if tasks.completeCalls != 3 {
		t.Fatalf("completed step calls = %d, want 3", tasks.completeCalls)
	}
	tasks.mu.Unlock()
}

func TestCloudSkillAdapterPlanDraftRequiresRuntimeWriteScope(t *testing.T) {
	t.Parallel()

	adapter, repository, tasks, _, request := newPlanDraftFixture(t, false)
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{
		ClientID: "message-server", CredentialID: uuid.NewString(), Scopes: map[string]struct{}{"runtime.read": {}},
	})
	if _, err := adapter.SubmitPlanDraft(ctx, request); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("read-only principal error = %v, want ErrScopeMismatch", err)
	}
	repository.mu.Lock()
	if repository.saveRecipeCalls != 0 || repository.saveCandidateCalls != 0 || repository.providerMutationCalls != 0 {
		t.Fatal("read-only principal reached a planning mutation")
	}
	repository.mu.Unlock()
	tasks.mu.Lock()
	if tasks.acquireCalls != 0 || tasks.completeCalls != 0 {
		t.Fatal("read-only principal advanced a durable task")
	}
	tasks.mu.Unlock()
}

func TestCloudSkillAdapterRejectsManagedRecipeBeforeAnyTaskMutation(t *testing.T) {
	t.Parallel()

	adapter, repository, tasks, ctx, request := newPlanDraftFixture(t, false)
	request.Recipe.Maturity = recipe.MaturityManaged
	if _, err := adapter.SubmitPlanDraft(ctx, request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("managed recipe error = %v, want ErrInvalid", err)
	}
	repository.mu.Lock()
	if repository.saveRecipeCalls != 0 || repository.saveCandidateCalls != 0 || repository.providerMutationCalls != 0 {
		t.Fatal("managed recipe reached a planning or provider mutation")
	}
	repository.mu.Unlock()
	tasks.mu.Lock()
	if tasks.acquireCalls != 0 || tasks.completeCalls != 0 {
		t.Fatal("managed recipe advanced the durable Task")
	}
	tasks.mu.Unlock()
}

func newPlanDraftFixture(t *testing.T, failAfterRecipeSave bool) (*CloudSkillAdapter, *adapterRepositoryStub, *adapterTaskStub, context.Context, cloudskill.SubmitPlanDraftRequest) {
	t.Helper()
	binding := validBinding()
	repository := &adapterRepositoryStub{failAfterRecipeSave: failAfterRecipeSave}
	tasks := &adapterTaskStub{}
	adapter, err := NewCloudSkillAdapter(repository, tasks)
	if err != nil {
		t.Fatal(err)
	}
	principal := auth.Principal{
		ClientID: "message-server", CredentialID: uuid.NewString(), Scopes: map[string]struct{}{"runtime.write": {}},
	}
	ctx := auth.ContextWithPrincipal(context.Background(), principal)
	create := task.CreateCommand{
		IdempotencyKey: binding.RequestID, OwnerID: binding.OwnerID, Goal: "Research an official knowledge node.",
		Retention: binding.Retention, Steps: cloudskill.PlanningSteps(binding.RequestID),
	}
	if _, err := adapter.CreateResearch(ctx, cloudskill.ResearchRequest{
		Create: create, ConversationID: binding.ConversationID, ConnectionID: binding.ConnectionID, RecipeID: binding.RecipeID,
	}); err != nil {
		t.Fatalf("CreateResearch() error = %v", err)
	}
	candidates := validCandidates()
	request := cloudskill.SubmitPlanDraftRequest{
		Binding: cloudskill.Binding{
			RequestID: binding.RequestID, OwnerID: binding.OwnerID, ConversationID: binding.ConversationID,
			ConnectionID: binding.ConnectionID, RecipeID: binding.RecipeID, Retention: binding.Retention,
		},
		ToolCallID: "tool-call-plan-1", Recipe: validRecipe(), Candidates: make([]cloudskill.ResourceCandidateDraftV1, 0, len(candidates)),
	}
	for _, candidate := range candidates {
		request.Candidates = append(request.Candidates, cloudskill.ResourceCandidateDraftV1{
			Tier: string(candidate.Tier), Architecture: candidate.Architecture, VCPU: candidate.VCPU,
			MemoryMiB: candidate.MemoryMiB, DiskGiB: candidate.DiskGiB, GPURequired: candidate.GPURequired,
			GPUMemoryMiB: candidate.GPUMemoryMiB, GPUFamily: candidate.GPUFamily, Rationale: candidate.Rationale,
		})
	}
	return adapter, repository, tasks, ctx, request
}

type adapterRepositoryStub struct {
	mu                    sync.Mutex
	session               ResearchSession
	caller                task.MutationScope
	failFirstAttach       bool
	draft                 RecipeDraft
	draftFound            bool
	candidateSet          ResourceCandidateSet
	saveRecipeCalls       int
	saveCandidateCalls    int
	failAfterRecipeSave   bool
	missingEvidence       bool
	bindEvidenceCalls     int
	providerMutationCalls int
	operations            []string
}

func (stub *adapterRepositoryStub) ClaimResearch(_ context.Context, scope task.MutationScope, command ResearchCommand) (ResearchSession, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.session.SessionID == "" {
		stub.caller = scope
		stub.session = ResearchSession{SessionID: uuid.NewString(), Binding: command.Binding, QuoteState: QuoteAwaitingQuote, Revision: 1}
	}
	if stub.caller != scope || stub.session.Binding != command.Binding {
		return ResearchSession{}, ErrScopeMismatch
	}
	return stub.session, nil
}

func (stub *adapterRepositoryStub) AttachResearchTask(_ context.Context, scope task.MutationScope, binding Binding, taskID string) (ResearchSession, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.caller != scope || stub.session.Binding != binding {
		return ResearchSession{}, ErrScopeMismatch
	}
	if stub.failFirstAttach {
		stub.failFirstAttach = false
		return ResearchSession{}, ErrPersistence
	}
	stub.session.TaskID = taskID
	stub.session.Revision++
	return stub.session, nil
}

func (stub *adapterRepositoryStub) GetResearch(_ context.Context, scope task.MutationScope, binding Binding) (ResearchSession, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.operations = append(stub.operations, "planning.get_research")
	if stub.caller != scope || stub.session.Binding != binding {
		return ResearchSession{}, ErrScopeMismatch
	}
	stub.session.Candidates = canonicalCandidates(stub.candidateSet.Candidates)
	stub.session.CandidateRevision = stub.candidateSet.Revision
	if stub.candidateSet.QuoteState != "" {
		stub.session.QuoteState = stub.candidateSet.QuoteState
	}
	return stub.session, nil
}

func (stub *adapterRepositoryStub) BindOfficialSourceEvidence(_ context.Context, scope task.MutationScope, command BindOfficialSourceEvidenceCommand) (OfficialSourceEvidenceSet, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.operations = append(stub.operations, "planning.bind_official_source_evidence")
	stub.bindEvidenceCalls++
	if scope != stub.caller || command.Binding != stub.session.Binding || command.TaskID != stub.session.TaskID {
		return OfficialSourceEvidenceSet{}, ErrScopeMismatch
	}
	if err := command.Validate(); err != nil {
		return OfficialSourceEvidenceSet{}, err
	}
	if stub.missingEvidence {
		return OfficialSourceEvidenceSet{}, ErrResearchEvidenceMissing
	}
	values := make([]OfficialSourceEvidence, 0, len(command.Sources))
	for index, source := range command.Sources {
		values = append(values, OfficialSourceEvidence{
			TaskID: command.TaskID, ToolCallID: "official-source-call-" + string(rune('a'+index)),
			URL: source.URL, RetrievedAt: source.RetrievedAt, ContentDigest: source.ContentDigest,
		})
	}
	return BuildOfficialSourceEvidenceSet(command.TaskID, values)
}

func (stub *adapterRepositoryStub) SaveRecipeDraft(_ context.Context, scope task.MutationScope, command SaveRecipeDraftCommand) (RecipeDraft, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.operations = append(stub.operations, "planning.save_recipe")
	if scope != stub.caller || command.Binding != stub.session.Binding {
		return RecipeDraft{}, ErrScopeMismatch
	}
	stub.saveRecipeCalls++
	if stub.draftFound {
		return stub.draft, nil
	}
	digest, err := command.Recipe.Digest()
	if err != nil {
		return RecipeDraft{}, ErrInvalid
	}
	stub.draft = RecipeDraft{RecipeID: command.Recipe.RecipeID, Recipe: command.Recipe, Digest: digest, Revision: 1}
	stub.draftFound = true
	if stub.failAfterRecipeSave {
		stub.failAfterRecipeSave = false
		return RecipeDraft{}, ErrPersistence
	}
	return stub.draft, nil
}

func (stub *adapterRepositoryStub) GetRecipeDraft(_ context.Context, scope task.MutationScope, binding Binding) (RecipeDraft, bool, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.operations = append(stub.operations, "planning.get_recipe")
	if scope != stub.caller || binding != stub.session.Binding {
		return RecipeDraft{}, false, ErrScopeMismatch
	}
	return stub.draft, stub.draftFound, nil
}

func (stub *adapterRepositoryStub) SaveResourceCandidates(_ context.Context, scope task.MutationScope, command SaveCandidatesCommand) (ResourceCandidateSet, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.operations = append(stub.operations, "planning.save_candidates")
	if scope != stub.caller || command.Binding != stub.session.Binding {
		return ResourceCandidateSet{}, ErrScopeMismatch
	}
	stub.saveCandidateCalls++
	if stub.candidateSet.Revision > 0 {
		return stub.candidateSet, nil
	}
	stub.candidateSet = ResourceCandidateSet{Candidates: canonicalCandidates(command.Candidates), QuoteState: command.QuoteState, Revision: 1}
	stub.session.Candidates = append([]ResourceCandidateV1(nil), stub.candidateSet.Candidates...)
	stub.session.CandidateRevision = 1
	stub.session.QuoteState = command.QuoteState
	return stub.candidateSet, nil
}

type adapterTaskStub struct {
	mu              sync.Mutex
	byKey           map[string]task.Task
	byID            map[string]task.Task
	stepsByTask     map[string][]task.Step
	acquiredByKey   map[string]task.Attempt
	completedByKey  map[string]task.Attempt
	distinctCreates int
	acquireCalls    int
	completeCalls   int
}

func (stub *adapterTaskStub) Create(_ context.Context, _ task.MutationScope, command task.CreateCommand) (task.Task, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.byKey == nil {
		stub.byKey = make(map[string]task.Task)
		stub.byID = make(map[string]task.Task)
		stub.stepsByTask = make(map[string][]task.Step)
		stub.acquiredByKey = make(map[string]task.Attempt)
		stub.completedByKey = make(map[string]task.Attempt)
	}
	if existing, ok := stub.byKey[command.IdempotencyKey]; ok {
		return existing, nil
	}
	stub.distinctCreates++
	created := task.Task{
		TaskID: uuid.NewString(), OwnerID: command.OwnerID, Goal: command.Goal,
		ExecutionStatus: task.ExecutionQueued, OutcomeStatus: task.OutcomePending,
		RetentionPolicy: command.Retention, Revision: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	stub.byKey[command.IdempotencyKey] = created
	stub.byID[created.TaskID] = created
	taskNamespace := uuid.MustParse(created.TaskID)
	stepIDs := make(map[string]string, len(command.Steps))
	for _, definition := range command.Steps {
		stepIDs[definition.StepID] = uuid.NewSHA1(taskNamespace, []byte(definition.StepID)).String()
	}
	for _, definition := range command.Steps {
		dependencies := make([]string, 0, len(definition.DependsOnStepIDs))
		for _, dependency := range definition.DependsOnStepIDs {
			dependencies = append(dependencies, stepIDs[dependency])
		}
		stub.stepsByTask[created.TaskID] = append(stub.stepsByTask[created.TaskID], task.Step{
			StepID: stepIDs[definition.StepID], TaskID: created.TaskID, Name: definition.Name,
			DependsOnStepIDs: dependencies, ExecutorKind: definition.ExecutorKind,
			ExecutionStatus: task.ExecutionQueued, OutcomeStatus: task.OutcomePending, Revision: 1,
		})
	}
	return created, nil
}

func (stub *adapterTaskStub) Get(_ context.Context, taskID string) (task.Task, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if item, ok := stub.byID[taskID]; ok {
		return item, nil
	}
	return task.Task{}, task.ErrNotFound
}

func (stub *adapterTaskStub) ListSteps(_ context.Context, taskID string) ([]task.Step, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	steps, ok := stub.stepsByTask[taskID]
	if !ok {
		return nil, task.ErrNotFound
	}
	return append([]task.Step(nil), steps...), nil
}

func (stub *adapterTaskStub) AcquireReadyStep(_ context.Context, _ task.MutationScope, command task.AcquireReadyStepCommand) (task.Attempt, bool, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.acquireCalls++
	if existing, ok := stub.acquiredByKey[command.IdempotencyKey]; ok {
		return existing, true, nil
	}
	steps, ok := stub.stepsByTask[command.TaskID]
	if !ok {
		return task.Attempt{}, false, task.ErrNotFound
	}
	finished := make(map[string]bool, len(steps))
	for _, step := range steps {
		finished[step.StepID] = step.ExecutionStatus == task.ExecutionFinished && step.OutcomeStatus == task.OutcomeSucceeded
	}
	for index := range steps {
		step := &steps[index]
		if step.StepID != command.StepID || step.ExecutorKind != command.ExecutorKind || step.ExecutionStatus != task.ExecutionQueued || step.OutcomeStatus != task.OutcomePending {
			continue
		}
		ready := true
		for _, dependency := range step.DependsOnStepIDs {
			ready = ready && finished[dependency]
		}
		if !ready {
			continue
		}
		step.ExecutionStatus = task.ExecutionRunning
		step.Attempt++
		step.LeaseEpoch++
		step.Revision++
		attempt := task.Attempt{
			TaskID: command.TaskID, StepID: step.StepID, Attempt: step.Attempt, LeaseEpoch: step.LeaseEpoch,
			WorkerID: command.WorkerID, ExecutionStatus: task.ExecutionRunning, OutcomeStatus: task.OutcomePending, Revision: 1,
		}
		stub.stepsByTask[command.TaskID] = steps
		stub.acquiredByKey[command.IdempotencyKey] = attempt
		item := stub.byID[command.TaskID]
		item.ExecutionStatus = task.ExecutionRunning
		item.CurrentStepID = step.StepID
		item.Revision++
		stub.byID[command.TaskID] = item
		return attempt, true, nil
	}
	return task.Attempt{}, false, nil
}

func (stub *adapterTaskStub) CompleteStep(_ context.Context, _ task.MutationScope, command task.CompleteStepCommand) (task.Attempt, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.completeCalls++
	if existing, ok := stub.completedByKey[command.IdempotencyKey]; ok {
		return existing, nil
	}
	steps, ok := stub.stepsByTask[command.TaskID]
	if !ok {
		return task.Attempt{}, task.ErrNotFound
	}
	for index := range steps {
		step := &steps[index]
		if step.StepID != command.StepID || step.ExecutionStatus != task.ExecutionRunning ||
			step.Attempt != command.Attempt || step.LeaseEpoch != command.LeaseEpoch {
			continue
		}
		step.ExecutionStatus = task.ExecutionFinished
		step.OutcomeStatus = command.Outcome
		step.ResultRef = command.ResultRef
		step.Revision++
		attempt := task.Attempt{
			TaskID: command.TaskID, StepID: command.StepID, Attempt: command.Attempt, LeaseEpoch: command.LeaseEpoch,
			WorkerID: command.WorkerID, ExecutionStatus: task.ExecutionFinished, OutcomeStatus: command.Outcome,
			ResultRef: command.ResultRef, Revision: 2,
		}
		stub.stepsByTask[command.TaskID] = steps
		stub.completedByKey[command.IdempotencyKey] = attempt
		item := stub.byID[command.TaskID]
		allFinished := true
		for _, current := range steps {
			allFinished = allFinished && current.ExecutionStatus == task.ExecutionFinished && current.OutcomeStatus == task.OutcomeSucceeded
		}
		if allFinished {
			item.ExecutionStatus = task.ExecutionFinished
			item.OutcomeStatus = task.OutcomeSucceeded
			item.CurrentStepID = ""
		} else {
			item.ExecutionStatus = task.ExecutionQueued
			item.OutcomeStatus = task.OutcomePending
			item.CurrentStepID = ""
		}
		item.Revision++
		stub.byID[command.TaskID] = item
		return attempt, nil
	}
	return task.Attempt{}, task.ErrStaleLease
}
