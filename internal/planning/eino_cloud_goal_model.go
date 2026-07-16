package planning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agent/cloudskill"
	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/publicweb"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/runtimeapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

const (
	cloudGoalModelVersion       = "cloud-goal-planning-model-v1"
	cloudGoalModelRequestLease  = 4 * time.Minute
	cloudGoalModelMaxSteps      = 24
	cloudGoalModelMaxCapture    = 256 << 10
	captureOfficialSourcesTool  = "capture_official_sources"
	captureExperimentalPlanTool = "capture_experimental_plan"
)

var ErrCloudGoalModelUnavailable = errors.New("durable cloud Goal planning model is unavailable")

// CloudGoalModelStore owns the durable, synthetic model request used by each
// planning stage. The request ID is derived from the Task and stage, so it can
// replay across a fenced Task lease without colliding with the user chat that
// created the Goal.
type CloudGoalModelStore interface {
	LoadRuntimeConfig(context.Context, string) (runtimeapi.RuntimeConfig, error)
	BeginRuntimeRequest(context.Context, runtimeapi.MutationScope, runtimeapi.RuntimeRequestCommand) (runtimeapi.RuntimeRequestClaim, error)
	BindRuntimeRequestMemoryMode(context.Context, runtimeapi.MutationScope, runtimeapi.BindRuntimeRequestMemoryModeCommand) (bool, error)
	RenewRuntimeRequest(context.Context, runtimeapi.MutationScope, runtimeapi.RenewRuntimeRequestCommand) (time.Time, error)
	ReleaseRuntimeRequest(context.Context, runtimeapi.MutationScope, runtimeapi.ReleaseRuntimeRequestCommand) error
	CompleteRuntimeRequest(context.Context, runtimeapi.MutationScope, runtimeapi.CompleteRuntimeRequestCommand) (runtimeapi.RuntimeResponseSnapshot, error)
}

// CloudGoalModelTools is implemented by runtimeapp.DurableToolProvider. Scope
// and the parent runtime lease are supplied by trusted code, never model JSON.
type CloudGoalModelTools interface {
	ToolsWithLease(context.Context, runtimeapi.MutationScope, int64, runtimeapi.ToolRequest) ([]runtimeapi.Tool, error)
}

type EinoCloudGoalPlanningModel struct {
	store        CloudGoalModelStore
	engine       runtimeapi.Engine
	models       runtimeapi.ModelFactory
	secrets      runtimeapi.SecretResolver
	tools        CloudGoalModelTools
	requestLease time.Duration
}

var _ CloudGoalPlanningModel = (*EinoCloudGoalPlanningModel)(nil)

func NewEinoCloudGoalPlanningModel(
	store CloudGoalModelStore,
	engine runtimeapi.Engine,
	models runtimeapi.ModelFactory,
	secrets runtimeapi.SecretResolver,
	tools CloudGoalModelTools,
) (*EinoCloudGoalPlanningModel, error) {
	if store == nil || engine == nil || models == nil || secrets == nil || tools == nil {
		return nil, ErrCloudGoalModelUnavailable
	}
	return &EinoCloudGoalPlanningModel{
		store: store, engine: engine, models: models, secrets: secrets, tools: tools,
		requestLease: cloudGoalModelRequestLease,
	}, nil
}

func (model *EinoCloudGoalPlanningModel) ResearchOfficialSources(ctx context.Context, input CloudGoalResearchInput) ([]recipe.SourceV1, error) {
	prompt, err := encodeCloudGoalModelPrompt("research_official_sources", input.Request, struct{}{})
	if err != nil {
		return nil, ErrCloudGoalModelUnavailable
	}
	raw, err := model.runCapture(ctx, input.Request, prompt, captureOfficialSourcesTool, cloudskill.OfficialSourceDraftInputSchema(), true,
		func(raw json.RawMessage, fetched map[string]publicweb.Evidence, replay bool) error {
			sources, decodeErr := cloudskill.DecodeOfficialSourceDraft(raw)
			if decodeErr != nil || validateOfficialSourceClaims(sources) != nil {
				return ErrCloudGoalModelUnavailable
			}
			if !replay && !sourcesMatchFetchedEvidence(sources, fetched) {
				return ErrCloudGoalModelUnavailable
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	return cloudskill.DecodeOfficialSourceDraft(raw)
}

func (model *EinoCloudGoalPlanningModel) DraftExperimentalRecipe(ctx context.Context, input CloudGoalRecipeInput) (recipe.RecipeV1, error) {
	prompt, err := encodeCloudGoalModelPrompt("draft_experimental_recipe", input.Request, struct {
		Evidence []OfficialSourceEvidence `json:"official_source_evidence"`
	}{Evidence: input.Evidence.Evidence})
	if err != nil {
		return recipe.RecipeV1{}, ErrCloudGoalModelUnavailable
	}
	binding := cloudSkillBinding(input.Request.Binding)
	raw, err := model.runCapture(ctx, input.Request, prompt, captureExperimentalPlanTool, cloudskill.PlanningDraftInputSchema(), true,
		func(raw json.RawMessage, fetched map[string]publicweb.Evidence, replay bool) error {
			decoded, decodeErr := cloudskill.DecodePlanningDraft(raw, binding)
			if decodeErr != nil || validateRecipeForEvidence(input.Request.Binding, decoded.Recipe, input.Evidence) != nil {
				return ErrCloudGoalModelUnavailable
			}
			if !replay && !boundEvidenceWasFetched(input.Evidence, fetched) {
				return ErrCloudGoalModelUnavailable
			}
			return nil
		})
	if err != nil {
		return recipe.RecipeV1{}, err
	}
	decoded, err := cloudskill.DecodePlanningDraft(raw, binding)
	if err != nil {
		return recipe.RecipeV1{}, ErrCloudGoalModelUnavailable
	}
	return decoded.Recipe, nil
}

func (model *EinoCloudGoalPlanningModel) ProposeResourceCandidates(ctx context.Context, input CloudGoalCandidateInput) ([]ResourceCandidateV1, error) {
	prompt, err := encodeCloudGoalModelPrompt("propose_resource_candidates", input.Request, struct {
		Recipe recipe.RecipeV1 `json:"experimental_recipe"`
	}{Recipe: input.Draft.Recipe})
	if err != nil {
		return nil, ErrCloudGoalModelUnavailable
	}
	binding := cloudSkillBinding(input.Request.Binding)
	raw, err := model.runCapture(ctx, input.Request, prompt, captureExperimentalPlanTool, cloudskill.PlanningDraftInputSchema(), false,
		func(raw json.RawMessage, _ map[string]publicweb.Evidence, _ bool) error {
			decoded, decodeErr := cloudskill.DecodePlanningDraft(raw, binding)
			if decodeErr != nil {
				return ErrCloudGoalModelUnavailable
			}
			digest, digestErr := decoded.Recipe.Digest()
			if digestErr != nil || digest != input.Draft.Digest || !reflect.DeepEqual(decoded.Recipe, input.Draft.Recipe) {
				return ErrCloudGoalModelUnavailable
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	decoded, err := cloudskill.DecodePlanningDraft(raw, binding)
	if err != nil {
		return nil, ErrCloudGoalModelUnavailable
	}
	result := make([]ResourceCandidateV1, 0, len(decoded.Candidates))
	for _, candidate := range decoded.Candidates {
		result = append(result, ResourceCandidateV1{
			Tier: CandidateTier(candidate.Tier), Architecture: candidate.Architecture,
			VCPU: candidate.VCPU, MemoryMiB: candidate.MemoryMiB, DiskGiB: candidate.DiskGiB,
			GPURequired: candidate.GPURequired, GPUMemoryMiB: candidate.GPUMemoryMiB,
			GPUFamily: candidate.GPUFamily, Rationale: candidate.Rationale,
		})
	}
	if ValidateCandidatesAgainstRecipe(result, input.Draft.Recipe.Requirements) != nil {
		return nil, ErrCloudGoalModelUnavailable
	}
	return result, nil
}

type captureValidator func(json.RawMessage, map[string]publicweb.Evidence, bool) error

func (model *EinoCloudGoalPlanningModel) runCapture(
	ctx context.Context,
	request CloudGoalStageRequest,
	prompt string,
	captureName string,
	captureSchema map[string]any,
	withOfficialFetch bool,
	validate captureValidator,
) (json.RawMessage, error) {
	if model == nil || ctx == nil || validate == nil || validateCloudGoalModelStageRequest(request) != nil ||
		strings.TrimSpace(prompt) == "" || strings.TrimSpace(captureName) == "" || len(captureSchema) == 0 {
		return nil, ErrCloudGoalModelUnavailable
	}
	modelRequestID, err := CloudGoalModelRequestID(request.Binding, request.Attempt.TaskID, request.Step.Name)
	if err != nil {
		return nil, ErrCloudGoalModelUnavailable
	}
	runtimeScope := runtimeapi.MutationScope{ClientID: request.Caller.ClientID, CredentialID: request.Caller.CredentialID}
	chatRequest := runtimeapi.ChatRequest{
		RequestID: modelRequestID, OwnerID: request.Binding.OwnerID, ConversationID: request.Binding.ConversationID,
		Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: prompt}}, MemoryDisabled: true,
	}
	requestLease := model.requestLease
	if requestLease <= 0 {
		requestLease = cloudGoalModelRequestLease
	}
	claim, err := model.store.BeginRuntimeRequest(ctx, runtimeScope, runtimeapi.RuntimeRequestCommand{Request: chatRequest, LeaseDuration: requestLease})
	if err != nil {
		return nil, ErrCloudGoalModelUnavailable
	}
	if claim.Completed {
		raw := json.RawMessage(claim.Response.Result.Message.Content)
		if validate(raw, nil, true) != nil {
			return nil, ErrCloudGoalModelUnavailable
		}
		return append(json.RawMessage(nil), raw...), nil
	}
	completed := false
	defer func() {
		if completed {
			return
		}
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_ = model.store.ReleaseRuntimeRequest(releaseCtx, runtimeScope, runtimeapi.ReleaseRuntimeRequestCommand{RequestID: modelRequestID, LeaseEpoch: claim.LeaseEpoch})
	}()
	executionCtx, leaseGuard := runtimeapp.StartLeaseRenewalGuard(ctx, requestLease, func(renewCtx context.Context, extension time.Duration) error {
		_, renewErr := model.store.RenewRuntimeRequest(renewCtx, runtimeScope, runtimeapi.RenewRuntimeRequestCommand{
			RequestID: modelRequestID, LeaseEpoch: claim.LeaseEpoch, LeaseDuration: extension,
		})
		return renewErr
	})
	defer func() {
		if leaseGuard != nil {
			_ = leaseGuard.Stop()
		}
	}()
	bound, err := model.store.BindRuntimeRequestMemoryMode(executionCtx, runtimeScope, runtimeapi.BindRuntimeRequestMemoryModeCommand{
		RequestID: modelRequestID, LeaseEpoch: claim.LeaseEpoch, MemoryDisabled: true,
	})
	if err != nil || !bound {
		return nil, ErrCloudGoalModelUnavailable
	}
	config, err := model.store.LoadRuntimeConfig(executionCtx, request.Binding.OwnerID)
	if err != nil || runtimeapi.ValidateRuntimeConfig(config) != nil {
		return nil, ErrCloudGoalModelUnavailable
	}
	client, err := model.models.CreateModel(executionCtx, config.ModelProfile, model.secrets)
	if err != nil || client == nil {
		return nil, ErrCloudGoalModelUnavailable
	}

	toolRequest := runtimeapi.ToolRequest{RequestID: modelRequestID, OwnerID: request.Binding.OwnerID, ConversationID: request.Binding.ConversationID}
	available := make(map[string]runtimeapi.Tool)
	definitions := make([]modelapi.Tool, 0, 2)
	if withOfficialFetch {
		tools, toolErr := model.tools.ToolsWithLease(executionCtx, runtimeScope, claim.LeaseEpoch, toolRequest)
		if toolErr != nil || len(tools) != 1 || tools[0].Definition.Name != publicweb.ToolName || tools[0].Run == nil {
			return nil, ErrCloudGoalModelUnavailable
		}
		available[publicweb.ToolName] = tools[0]
		definitions = append(definitions, tools[0].Definition)
	}
	capture := &planningCapture{}
	definitions = append(definitions, modelapi.Tool{
		Name: captureName, Description: "Submit the complete validated planning output exactly once after using every required official-source tool.", InputSchema: captureSchema,
	})
	fetched := make(map[string]publicweb.Evidence)
	result, err := model.engine.Generate(executionCtx, runtimeapi.EngineRequest{
		Client: client,
		Messages: []modelapi.Message{
			{Role: modelapi.RoleSystem, Content: cloudGoalPlanningSystemPrompt(captureName, withOfficialFetch)},
			{Role: modelapi.RoleUser, Content: prompt},
		},
		Tools: definitions, MaxSteps: min(config.MaxSteps, cloudGoalModelMaxSteps),
		InvokeTool: func(runCtx context.Context, call modelapi.ToolCall) (runtimeapi.ToolExecution, error) {
			return invokeCloudGoalModelTool(runCtx, toolRequest, call, captureName, capture, available, fetched)
		},
	})
	executionErr := executionCtx.Err()
	renewErr := leaseGuard.Stop()
	leaseGuard = nil
	if renewErr != nil || executionErr != nil || err != nil || result.Message.Role != modelapi.RoleAssistant {
		return nil, ErrCloudGoalModelUnavailable
	}
	raw, ok := capture.value()
	if !ok || validate(raw, fetched, false) != nil {
		return nil, ErrCloudGoalModelUnavailable
	}
	canonical := modelapi.Message{Role: modelapi.RoleAssistant, Content: string(raw)}
	snapshot, err := model.store.CompleteRuntimeRequest(ctx, runtimeScope, runtimeapi.CompleteRuntimeRequestCommand{
		RequestID: modelRequestID, LeaseEpoch: claim.LeaseEpoch, Result: runtimeapi.ChatResult{Message: canonical},
	})
	if err != nil || snapshot.Result.Message.Content != canonical.Content {
		return nil, ErrCloudGoalModelUnavailable
	}
	completed = true
	return append(json.RawMessage(nil), raw...), nil
}

type planningCapture struct {
	mu  sync.Mutex
	raw json.RawMessage
}

func (capture *planningCapture) set(raw string) error {
	if capture == nil || len(raw) == 0 || len(raw) > cloudGoalModelMaxCapture || !json.Valid([]byte(raw)) || security.ContainsLikelySecret(raw) {
		return ErrCloudGoalModelUnavailable
	}
	compact := &bytes.Buffer{}
	if err := json.Compact(compact, []byte(raw)); err != nil {
		return ErrCloudGoalModelUnavailable
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if len(capture.raw) != 0 {
		return ErrCloudGoalModelUnavailable
	}
	capture.raw = append(json.RawMessage(nil), compact.Bytes()...)
	return nil
}

func (capture *planningCapture) value() (json.RawMessage, bool) {
	if capture == nil {
		return nil, false
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append(json.RawMessage(nil), capture.raw...), len(capture.raw) != 0
}

func invokeCloudGoalModelTool(
	ctx context.Context,
	request runtimeapi.ToolRequest,
	call modelapi.ToolCall,
	captureName string,
	capture *planningCapture,
	available map[string]runtimeapi.Tool,
	fetched map[string]publicweb.Evidence,
) (runtimeapi.ToolExecution, error) {
	name := strings.TrimSpace(call.Function.Name)
	if strings.TrimSpace(call.ID) == "" || len(call.ID) > 255 || security.ContainsLikelySecret(call.ID) || name == "" || !json.Valid([]byte(call.Function.Arguments)) {
		return runtimeapi.ToolExecution{}, ErrCloudGoalModelUnavailable
	}
	if name == captureName {
		if err := capture.set(call.Function.Arguments); err != nil {
			return runtimeapi.ToolExecution{}, err
		}
		return runtimeapi.ToolExecution{ToolCallID: call.ID, Name: name, Content: `{"accepted":true}`}, nil
	}
	tool, ok := available[name]
	if !ok || tool.Run == nil {
		return runtimeapi.ToolExecution{}, ErrCloudGoalModelUnavailable
	}
	result, err := tool.Run(ctx, runtimeapi.ToolInvocation{
		RequestID: request.RequestID, OwnerID: request.OwnerID, ConversationID: request.ConversationID,
		ToolCallID: call.ID, Name: name, Arguments: json.RawMessage(call.Function.Arguments),
	})
	if err != nil || result.IsError {
		return runtimeapi.ToolExecution{}, ErrCloudGoalModelUnavailable
	}
	evidence, err := publicweb.ParseEvidenceResult(result.Content)
	if err != nil {
		return runtimeapi.ToolExecution{}, ErrCloudGoalModelUnavailable
	}
	if prior, exists := fetched[evidence.URL]; exists && prior != evidence {
		return runtimeapi.ToolExecution{}, ErrCloudGoalModelUnavailable
	}
	fetched[evidence.URL] = evidence
	return runtimeapi.ToolExecution{
		ToolCallID: call.ID, Name: name, Content: result.Content,
		RelatedTaskIDs: append([]string(nil), result.RelatedTaskIDs...), RelatedPlanIDs: append([]string(nil), result.RelatedPlanIDs...),
	}, nil
}

func CloudGoalModelRequestID(binding Binding, taskID, stage string) (string, error) {
	requestID, requestErr := uuid.Parse(binding.RequestID)
	taskUUID, taskErr := uuid.Parse(taskID)
	if requestErr != nil || requestID == uuid.Nil || taskErr != nil || taskUUID == uuid.Nil || !validCloudGoalStageName(stage) {
		return "", ErrCloudGoalModelUnavailable
	}
	return uuid.NewSHA1(requestID, []byte(cloudGoalModelVersion+"\x00"+taskUUID.String()+"\x00"+stage)).String(), nil
}

func encodeCloudGoalModelPrompt(stage string, request CloudGoalStageRequest, input any) (string, error) {
	payload := struct {
		SchemaVersion string `json:"schema_version"`
		Stage         string `json:"stage"`
		Goal          string `json:"goal"`
		RecipeID      string `json:"recipe_id"`
		Input         any    `json:"input"`
	}{cloudGoalModelVersion, stage, request.Goal, request.Binding.RecipeID, input}
	encoded, err := json.Marshal(payload)
	if err != nil || security.ContainsLikelySecret(string(encoded)) {
		return "", ErrCloudGoalModelUnavailable
	}
	return string(encoded), nil
}

func cloudGoalPlanningSystemPrompt(captureName string, withOfficialFetch bool) string {
	fetchInstruction := "Do not call network or filesystem tools."
	if withOfficialFetch {
		fetchInstruction = "Use official_source_fetch for every official URL whose content supports the answer; never claim an unfetched source."
	}
	return "You are Dirextalk's provider-neutral background planning model. " + fetchInstruction +
		" Never request or emit credentials, never approve spending, never provision resources, and never emit shell commands outside typed Recipe action fields. " +
		"Call " + captureName + " exactly once with the complete result. All identity, Region, price, network and retention decisions remain server-owned."
}

func cloudSkillBinding(binding Binding) cloudskill.Binding {
	return cloudskill.Binding{
		RequestID: binding.RequestID, OwnerID: binding.OwnerID, ConversationID: binding.ConversationID,
		ConnectionID: binding.ConnectionID, RecipeID: binding.RecipeID, Retention: binding.Retention,
	}
}

func sourcesMatchFetchedEvidence(sources []recipe.SourceV1, fetched map[string]publicweb.Evidence) bool {
	if len(sources) == 0 || len(fetched) == 0 {
		return false
	}
	for _, source := range sources {
		evidence, ok := fetched[source.URL]
		if !ok || source.ContentDigest != evidence.ContentDigest || !source.RetrievedAt.Equal(evidence.RetrievedAt) {
			return false
		}
	}
	return true
}

func boundEvidenceWasFetched(bound OfficialSourceEvidenceSet, fetched map[string]publicweb.Evidence) bool {
	if len(bound.Evidence) == 0 || len(fetched) == 0 {
		return false
	}
	for _, item := range bound.Evidence {
		evidence, ok := fetched[item.URL]
		if !ok || evidence.ContentDigest != item.ContentDigest {
			return false
		}
	}
	return true
}

func validateCloudGoalModelStageRequest(request CloudGoalStageRequest) error {
	if request.Binding.Validate() != nil || request.Caller.Validate() != nil || strings.TrimSpace(request.Goal) == "" ||
		request.Step.TaskID != request.Attempt.TaskID || request.Step.StepID != request.Attempt.StepID || request.Step.Name == "" ||
		request.Attempt.LeaseEpoch < 1 || request.Attempt.ExecutionStatus != task.ExecutionRunning {
		return ErrCloudGoalModelUnavailable
	}
	return nil
}
