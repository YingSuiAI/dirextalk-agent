package cloudskill

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"time"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

const (
	ToolResearch        = "cloud_dispatcher_research"
	ToolStatus          = "cloud_dispatcher_status"
	ToolRecipeDraft     = "cloud_dispatcher_recipe_draft"
	ToolSubmitPlanDraft = "cloud_dispatcher_submit_plan_draft"

	maxModelVisibleResultBytes = 60 << 10
)

type Skill struct {
	dependencies Dependencies
}

var _ runtimeapi.ToolProvider = (*Skill)(nil)

func New(dependencies Dependencies) (*Skill, error) {
	if nilPort(dependencies.Research) || nilPort(dependencies.Status) || nilPort(dependencies.RecipeDraft) || nilPort(dependencies.PlanDraft) {
		return nil, ErrInvalidDependencies
	}
	return &Skill{dependencies: dependencies}, nil
}

// Tools implements runtime.ToolProvider. The returned closures capture the
// authenticated call scope; the model can supply only a research goal or an
// empty object for read operations.
func (skill *Skill) Tools(ctx context.Context, request runtimeapi.ToolRequest) ([]runtimeapi.Tool, error) {
	if skill == nil {
		return nil, ErrInvalidDependencies
	}
	scope, err := callScopeFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if request.OwnerID != scope.OwnerID || !validOpaqueID(request.ConversationID, 255) {
		return nil, ErrInvocationScopeMismatch
	}
	if _, err := uuid.Parse(request.RequestID); err != nil {
		return nil, ErrInvocationScopeMismatch
	}
	binding := Binding{
		RequestID:      request.RequestID,
		OwnerID:        scope.OwnerID,
		ConversationID: request.ConversationID,
		ConnectionID:   scope.ConnectionID,
		RecipeID:       scope.RecipeID,
		Retention:      scope.Retention,
	}
	state := &researchState{}

	return []runtimeapi.Tool{
		{
			Definition: modelapi.Tool{
				Name:        ToolSubmitPlanDraft,
				Description: "Submit one secret-free experimental Recipe draft and exactly three provider-neutral resource candidates after official-source research. Trusted identity, connection, retention and lifecycle state are server-bound.",
				InputSchema: submitPlanDraftInputSchema(),
			},
			Run: func(runCtx context.Context, invocation runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
				if err := validateInvocation(invocation, request, ToolSubmitPlanDraft); err != nil {
					return runtimeapi.ToolResult{}, err
				}
				submission, err := decodePlanDraft(invocation.Arguments, binding)
				if err != nil {
					return runtimeapi.ToolResult{}, err
				}
				result, err := skill.dependencies.PlanDraft.SubmitPlanDraft(runCtx, SubmitPlanDraftRequest{
					Binding: binding, ToolCallID: invocation.ToolCallID,
					Recipe: submission.recipe, Candidates: submission.candidates,
				})
				if err != nil {
					return runtimeapi.ToolResult{}, err
				}
				view, err := planDraftViewFromResult(result, binding)
				if err != nil {
					return runtimeapi.ToolResult{}, err
				}
				return encodeTaskResult(view, view.TaskID)
			},
		},
		{
			Definition: modelapi.Tool{
				Name:        ToolResearch,
				Description: "Create one durable research task for a secret-free cloud service goal. Ownership, connection, recipe and retention are already bound by the caller.",
				InputSchema: researchInputSchema(),
			},
			Run: func(runCtx context.Context, invocation runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
				if err := validateInvocation(invocation, request, ToolResearch); err != nil {
					return runtimeapi.ToolResult{}, err
				}
				goal, err := decodeGoal(invocation.Arguments)
				if err != nil {
					return runtimeapi.ToolResult{}, err
				}
				created, err := state.create(runCtx, skill.dependencies.Research, binding, goal)
				if err != nil {
					return runtimeapi.ToolResult{}, err
				}
				view := researchViewFromTask(created)
				return encodeTaskResult(view, view.TaskID)
			},
		},
		{
			Definition: modelapi.Tool{
				Name:        ToolStatus,
				Description: "Read the status of the research task bound to this request. It cannot mutate cloud resources.",
				InputSchema: emptyInputSchema(),
			},
			Run: func(runCtx context.Context, invocation runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
				if err := validateInvocation(invocation, request, ToolStatus); err != nil {
					return runtimeapi.ToolResult{}, err
				}
				if err := decodeEmpty(invocation.Arguments); err != nil {
					return runtimeapi.ToolResult{}, err
				}
				status, err := skill.dependencies.Status.GetResearchStatus(runCtx, StatusRequest{Binding: binding})
				if err != nil {
					return runtimeapi.ToolResult{}, err
				}
				view, err := statusViewFromSnapshot(status, binding)
				if err != nil {
					return runtimeapi.ToolResult{}, err
				}
				return encodeTaskResult(view, view.TaskID)
			},
		},
		{
			Definition: modelapi.Tool{
				Name:        ToolRecipeDraft,
				Description: "Read the validated experimental Recipe draft bound to this request. It cannot approve or execute the draft.",
				InputSchema: emptyInputSchema(),
			},
			Run: func(runCtx context.Context, invocation runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
				if err := validateInvocation(invocation, request, ToolRecipeDraft); err != nil {
					return runtimeapi.ToolResult{}, err
				}
				if err := decodeEmpty(invocation.Arguments); err != nil {
					return runtimeapi.ToolResult{}, err
				}
				draft, err := skill.dependencies.RecipeDraft.GetRecipeDraft(runCtx, RecipeDraftRequest{Binding: binding})
				if err != nil {
					return runtimeapi.ToolResult{}, err
				}
				view, err := recipeDraftViewFromSnapshot(draft, binding)
				if err != nil {
					return runtimeapi.ToolResult{}, err
				}
				return encodeResult(view)
			},
		},
	}, nil
}

type researchState struct {
	mu      sync.Mutex
	goal    string
	created task.Task
	hasTask bool
}

func (state *researchState) create(ctx context.Context, port ResearchPort, binding Binding, goal string) (task.Task, error) {
	command := task.CreateCommand{
		IdempotencyKey: binding.RequestID,
		OwnerID:        binding.OwnerID,
		Goal:           goal,
		Retention:      binding.Retention,
		Steps:          PlanningSteps(binding.RequestID),
	}
	if err := command.Validate(); err != nil {
		return task.Task{}, err
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	if state.goal != "" && state.goal != goal {
		return task.Task{}, ErrResearchAlreadyStarted
	}
	if state.goal == "" {
		state.goal = goal
	}
	if state.hasTask {
		return state.created, nil
	}
	created, err := port.CreateResearch(ctx, ResearchRequest{
		Create:         command,
		ConversationID: binding.ConversationID,
		ConnectionID:   binding.ConnectionID,
		RecipeID:       binding.RecipeID,
	})
	if err != nil {
		return task.Task{}, err
	}
	if !validTaskProjection(created, binding) || strings.TrimSpace(created.Goal) != goal {
		return task.Task{}, ErrInvalidPortResponse
	}
	state.created = created
	state.hasTask = true
	return created, nil
}

// PlanningSteps returns the only DAG the native cloud dispatcher may advance.
// IDs are deterministic so retries can validate persisted task identity.
func PlanningSteps(requestID string) []task.StepDefinition {
	namespace := uuid.MustParse(requestID)
	researchID := uuid.NewSHA1(namespace, []byte("research-official-sources")).String()
	recipeID := uuid.NewSHA1(namespace, []byte("draft-recipe")).String()
	candidatesID := uuid.NewSHA1(namespace, []byte("prepare-resource-candidates")).String()
	return []task.StepDefinition{
		{StepID: researchID, Name: StepResearchOfficialSources, ExecutorKind: task.ExecutorControlPlane},
		{StepID: recipeID, Name: StepDraftRecipe, ExecutorKind: task.ExecutorControlPlane, DependsOnStepIDs: []string{researchID}},
		{StepID: candidatesID, Name: StepPrepareResourceCandidates, ExecutorKind: task.ExecutorControlPlane, DependsOnStepIDs: []string{recipeID}},
	}
}

func validateInvocation(invocation runtimeapi.ToolInvocation, request runtimeapi.ToolRequest, name string) error {
	if invocation.RequestID != request.RequestID || invocation.OwnerID != request.OwnerID || invocation.ConversationID != request.ConversationID || invocation.Name != name || !validOpaqueID(strings.TrimSpace(invocation.ToolCallID), 255) {
		return ErrInvocationScopeMismatch
	}
	return nil
}

func decodeGoal(raw json.RawMessage) (string, error) {
	var input struct {
		Goal string `json:"goal"`
	}
	if err := decodeStrict(raw, &input); err != nil {
		return "", err
	}
	return strings.TrimSpace(input.Goal), nil
}

func decodeEmpty(raw json.RawMessage) error {
	return decodeStrict(raw, &struct{}{})
}

type candidateDraftInputV1 struct {
	Architecture recipe.Architecture `json:"architecture"`
	VCPU         uint32              `json:"vcpu"`
	MemoryMiB    uint64              `json:"memory_mib"`
	DiskGiB      uint64              `json:"disk_gib"`
	GPURequired  bool                `json:"gpu_required"`
	GPUMemoryMiB uint64              `json:"gpu_memory_mib,omitempty"`
	GPUFamily    string              `json:"gpu_family,omitempty"`
	Rationale    string              `json:"rationale"`
}

type planDraftInputV1 struct {
	Recipe      RecipeDraftInputV1    `json:"recipe"`
	Economy     candidateDraftInputV1 `json:"economy"`
	Recommended candidateDraftInputV1 `json:"recommended"`
	Performance candidateDraftInputV1 `json:"performance"`
}

type decodedPlanDraft struct {
	recipe     recipe.RecipeV1
	candidates []ResourceCandidateDraftV1
}

func decodePlanDraft(raw json.RawMessage, binding Binding) (decodedPlanDraft, error) {
	if security.ContainsLikelySecret(string(raw)) {
		return decodedPlanDraft{}, task.ErrRawSecret
	}
	var input planDraftInputV1
	if err := decodeStrict(raw, &input); err != nil {
		return decodedPlanDraft{}, err
	}
	boundRecipe := input.Recipe.bind(binding.RecipeID)
	if boundRecipe.SchemaVersion != recipe.SchemaV1 || boundRecipe.Maturity != recipe.MaturityExperimental || boundRecipe.ManagedAcceptance != nil {
		return decodedPlanDraft{}, ErrInvalidArguments
	}
	if err := boundRecipe.Validate(); err != nil {
		return decodedPlanDraft{}, ErrInvalidArguments
	}
	candidates := []ResourceCandidateDraftV1{
		candidateFromInput("economy", input.Economy),
		candidateFromInput("recommended", input.Recommended),
		candidateFromInput("performance", input.Performance),
	}
	if err := validateCandidateDrafts(candidates, boundRecipe.Requirements); err != nil {
		return decodedPlanDraft{}, err
	}
	return decodedPlanDraft{recipe: boundRecipe, candidates: candidates}, nil
}

func candidateFromInput(tier string, input candidateDraftInputV1) ResourceCandidateDraftV1 {
	return ResourceCandidateDraftV1{
		Tier: tier, Architecture: input.Architecture, VCPU: input.VCPU,
		MemoryMiB: input.MemoryMiB, DiskGiB: input.DiskGiB,
		GPURequired: input.GPURequired, GPUMemoryMiB: input.GPUMemoryMiB,
		GPUFamily: input.GPUFamily, Rationale: input.Rationale,
	}
}

func validateCandidateDrafts(candidates []ResourceCandidateDraftV1, requirements recipe.ResourceRequirementsV1) error {
	wantTiers := []string{"economy", "recommended", "performance"}
	if len(candidates) != len(wantTiers) {
		return ErrInvalidArguments
	}
	for index, candidate := range candidates {
		if candidate.Tier != wantTiers[index] || !recipe.ValidArchitecture(candidate.Architecture) ||
			candidate.VCPU == 0 || candidate.VCPU > 1024 || candidate.MemoryMiB == 0 ||
			candidate.MemoryMiB > 64*1024*1024 || candidate.DiskGiB == 0 || candidate.DiskGiB > 64*1024 ||
			candidate.Rationale != strings.TrimSpace(candidate.Rationale) || candidate.Rationale == "" || len(candidate.Rationale) > 512 {
			return ErrInvalidArguments
		}
		if security.ContainsLikelySecret(candidate.Rationale) || security.ContainsLikelySecret(candidate.GPUFamily) {
			return task.ErrRawSecret
		}
		if candidate.GPURequired {
			if candidate.GPUMemoryMiB == 0 || candidate.GPUFamily != strings.TrimSpace(candidate.GPUFamily) || candidate.GPUFamily == "" || len(candidate.GPUFamily) > 128 {
				return ErrInvalidArguments
			}
		} else if candidate.GPUMemoryMiB != 0 || candidate.GPUFamily != "" {
			return ErrInvalidArguments
		}
		if candidate.Architecture != requirements.Architecture || candidate.VCPU < requirements.MinVCPU ||
			candidate.MemoryMiB < requirements.MinMemoryMiB || candidate.DiskGiB < requirements.MinDiskGiB ||
			(requirements.GPURequired && (!candidate.GPURequired || candidate.GPUMemoryMiB < requirements.MinGPUMemoryMiB)) {
			return ErrInvalidArguments
		}
		if index > 0 {
			previous := candidates[index-1]
			if candidate.Architecture != previous.Architecture || candidate.VCPU < previous.VCPU ||
				candidate.MemoryMiB < previous.MemoryMiB || candidate.DiskGiB < previous.DiskGiB ||
				candidate.GPUMemoryMiB < previous.GPUMemoryMiB {
				return ErrInvalidArguments
			}
		}
	}
	return nil
}

func decodeStrict(raw json.RawMessage, destination any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage(`{}`)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidArguments
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidArguments
	}
	return nil
}

func researchInputSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"goal"},
		"properties": map[string]any{
			"goal": map[string]any{
				"type":        "string",
				"description": "Secret-free desired outcome to research.",
				"minLength":   1,
				"maxLength":   65536,
			},
		},
	}
}

func emptyInputSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties":           map[string]any{},
	}
}

func submitPlanDraftInputSchema() map[string]any {
	return schemaForType(reflect.TypeOf(planDraftInputV1{}))
}

func schemaForType(value reflect.Type) map[string]any {
	for value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if value == reflect.TypeOf(time.Time{}) {
		return map[string]any{"type": "string", "format": "date-time"}
	}
	switch value.Kind() {
	case reflect.Struct:
		properties := make(map[string]any)
		required := make([]string, 0, value.NumField())
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			if !field.IsExported() {
				continue
			}
			name, optional := jsonFieldName(field)
			if name == "" {
				continue
			}
			properties[name] = schemaForType(field.Type)
			if !optional {
				required = append(required, name)
			}
		}
		result := map[string]any{"type": "object", "additionalProperties": false, "properties": properties}
		if len(required) > 0 {
			result["required"] = required
		}
		return result
	case reflect.Slice, reflect.Array:
		return map[string]any{"type": "array", "items": schemaForType(value.Elem())}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	default:
		return map[string]any{"type": "string"}
	}
}

func jsonFieldName(field reflect.StructField) (string, bool) {
	tag := field.Tag.Get("json")
	if tag == "-" {
		return "", false
	}
	parts := strings.Split(tag, ",")
	name := parts[0]
	if name == "" {
		name = field.Name
	}
	optional := false
	for _, option := range parts[1:] {
		optional = optional || option == "omitempty"
	}
	return name, optional
}

type researchView struct {
	TaskID          string               `json:"task_id"`
	ExecutionStatus task.ExecutionStatus `json:"execution_status"`
	OutcomeStatus   task.OutcomeStatus   `json:"outcome_status"`
	Revision        int64                `json:"revision"`
}

func researchViewFromTask(value task.Task) researchView {
	return researchView{TaskID: value.TaskID, ExecutionStatus: value.ExecutionStatus, OutcomeStatus: value.OutcomeStatus, Revision: value.Revision}
}

type statusView struct {
	TaskID          string               `json:"task_id"`
	ExecutionStatus task.ExecutionStatus `json:"execution_status"`
	OutcomeStatus   task.OutcomeStatus   `json:"outcome_status"`
	CurrentStepID   string               `json:"current_step_id,omitempty"`
	Revision        int64                `json:"revision"`
	Steps           []stepView           `json:"steps"`
}

type stepView struct {
	StepID          string               `json:"step_id"`
	ExecutionStatus task.ExecutionStatus `json:"execution_status"`
	OutcomeStatus   task.OutcomeStatus   `json:"outcome_status"`
	Attempt         int32                `json:"attempt"`
	Revision        int64                `json:"revision"`
}

func statusViewFromSnapshot(snapshot ResearchStatus, binding Binding) (statusView, error) {
	if !validTaskProjection(snapshot.Task, binding) {
		return statusView{}, ErrInvalidPortResponse
	}
	if snapshot.Task.CurrentStepID != "" && !validOpaqueID(snapshot.Task.CurrentStepID, 128) {
		return statusView{}, ErrInvalidPortResponse
	}
	view := statusView{
		TaskID:          snapshot.Task.TaskID,
		ExecutionStatus: snapshot.Task.ExecutionStatus,
		OutcomeStatus:   snapshot.Task.OutcomeStatus,
		CurrentStepID:   snapshot.Task.CurrentStepID,
		Revision:        snapshot.Task.Revision,
		Steps:           make([]stepView, 0, len(snapshot.Steps)),
	}
	for _, step := range snapshot.Steps {
		if !validOpaqueID(step.StepID, 128) || step.TaskID != snapshot.Task.TaskID || !validExecution(step.ExecutionStatus) || !validOutcome(step.OutcomeStatus) || step.Attempt < 0 || step.Revision < 1 {
			return statusView{}, ErrInvalidPortResponse
		}
		view.Steps = append(view.Steps, stepView{
			StepID: step.StepID, ExecutionStatus: step.ExecutionStatus, OutcomeStatus: step.OutcomeStatus, Attempt: step.Attempt, Revision: step.Revision,
		})
	}
	return view, nil
}

type recipeDraftView struct {
	Ready  bool             `json:"ready"`
	Digest string           `json:"digest,omitempty"`
	Recipe *recipe.RecipeV1 `json:"recipe,omitempty"`
}

func recipeDraftViewFromSnapshot(snapshot RecipeDraft, binding Binding) (recipeDraftView, error) {
	if !snapshot.Ready {
		return recipeDraftView{Ready: false}, nil
	}
	if snapshot.Recipe.RecipeID != binding.RecipeID || snapshot.Recipe.Maturity != recipe.MaturityExperimental {
		return recipeDraftView{}, ErrInvalidPortResponse
	}
	if err := snapshot.Recipe.Validate(); err != nil {
		return recipeDraftView{}, ErrInvalidPortResponse
	}
	digest, err := snapshot.Recipe.Digest()
	if err != nil {
		return recipeDraftView{}, ErrInvalidPortResponse
	}
	return recipeDraftView{Ready: true, Digest: digest, Recipe: &snapshot.Recipe}, nil
}

type planDraftView struct {
	TaskID            string               `json:"task_id"`
	ExecutionStatus   task.ExecutionStatus `json:"execution_status"`
	OutcomeStatus     task.OutcomeStatus   `json:"outcome_status"`
	TaskRevision      int64                `json:"task_revision"`
	RecipeDigest      string               `json:"recipe_digest"`
	RecipeRevision    int64                `json:"recipe_revision"`
	QuoteState        string               `json:"quote_state"`
	CandidateRevision int64                `json:"candidate_revision"`
	Candidates        []CandidateSummary   `json:"candidates"`
}

func planDraftViewFromResult(result SubmitPlanDraftResult, binding Binding) (planDraftView, error) {
	if _, err := uuid.Parse(result.TaskID); err != nil || result.TaskRevision < 1 || result.RecipeRevision < 1 || result.CandidateRevision < 1 ||
		result.ExecutionStatus != task.ExecutionFinished || result.OutcomeStatus != task.OutcomeSucceeded ||
		(result.QuoteState != QuoteStateAwaitingConnection && result.QuoteState != QuoteStateAwaitingQuote) ||
		(binding.ConnectionID == "" && result.QuoteState != QuoteStateAwaitingConnection) ||
		(binding.ConnectionID != "" && result.QuoteState != QuoteStateAwaitingQuote) || recipe.ValidateDigest(result.RecipeDigest) != nil {
		return planDraftView{}, ErrInvalidPortResponse
	}
	wantTiers := []string{"economy", "recommended", "performance"}
	if len(result.Candidates) != len(wantTiers) {
		return planDraftView{}, ErrInvalidPortResponse
	}
	for index, candidate := range result.Candidates {
		if candidate.Tier != wantTiers[index] || !recipe.ValidArchitecture(candidate.Architecture) ||
			candidate.VCPU == 0 || candidate.MemoryMiB == 0 || candidate.DiskGiB == 0 ||
			(!candidate.GPURequired && candidate.GPUMemoryMiB != 0) || (candidate.GPURequired && candidate.GPUMemoryMiB == 0) {
			return planDraftView{}, ErrInvalidPortResponse
		}
	}
	return planDraftView{
		TaskID: result.TaskID, ExecutionStatus: result.ExecutionStatus, OutcomeStatus: result.OutcomeStatus,
		TaskRevision: result.TaskRevision, RecipeDigest: result.RecipeDigest, RecipeRevision: result.RecipeRevision,
		QuoteState: result.QuoteState, CandidateRevision: result.CandidateRevision,
		Candidates: append([]CandidateSummary(nil), result.Candidates...),
	}, nil
}

func validTaskProjection(value task.Task, binding Binding) bool {
	if _, err := uuid.Parse(value.TaskID); err != nil {
		return false
	}
	return value.OwnerID == binding.OwnerID && value.RetentionPolicy == binding.Retention && value.Revision >= 1 && validExecution(value.ExecutionStatus) && validOutcome(value.OutcomeStatus)
}

func validExecution(value task.ExecutionStatus) bool {
	switch value {
	case task.ExecutionDraft, task.ExecutionPlanning, task.ExecutionAwaitingApproval, task.ExecutionQueued, task.ExecutionRunning, task.ExecutionWaitingUser, task.ExecutionVerifying, task.ExecutionFinished:
		return true
	default:
		return false
	}
}

func validOutcome(value task.OutcomeStatus) bool {
	switch value {
	case task.OutcomePending, task.OutcomeSucceeded, task.OutcomeFailed, task.OutcomeCanceled, task.OutcomeTimedOut, task.OutcomeInterrupted:
		return true
	default:
		return false
	}
}

func encodeResult(value any) (runtimeapi.ToolResult, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return runtimeapi.ToolResult{}, ErrInvalidPortResponse
	}
	if len(encoded) > maxModelVisibleResultBytes {
		return runtimeapi.ToolResult{}, ErrModelVisibleResultTooLarge
	}
	return runtimeapi.ToolResult{Content: string(encoded)}, nil
}

func encodeTaskResult(value any, taskID string) (runtimeapi.ToolResult, error) {
	if _, err := uuid.Parse(taskID); err != nil {
		return runtimeapi.ToolResult{}, ErrInvalidPortResponse
	}
	result, err := encodeResult(value)
	if err != nil {
		return runtimeapi.ToolResult{}, err
	}
	result.RelatedTaskIDs = []string{taskID}
	return result, nil
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
