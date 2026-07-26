package planning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agent/cloudskill"
	"github.com/YingSuiAI/dirextalk-agent/internal/knowledgeprofile"
	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/publicweb"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/runtimeapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerprofile"
	"github.com/google/uuid"
)

const (
	cloudGoalModelVersion         = "cloud-goal-planning-model-v5"
	cloudGoalModelRequestLease    = 4 * time.Minute
	cloudGoalModelMaxSteps        = 24
	cloudGoalModelMaxCapture      = 256 << 10
	cloudGoalModelMaxSubmissions  = 3
	captureOfficialSourcesTool    = "capture_official_sources"
	captureExperimentalRecipeTool = "capture_experimental_recipe"
	captureResourceCandidatesTool = "capture_resource_candidates"
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
	officialProfiles := serverOwnedResearchHints(input.Request.Binding.RecipeID)
	prompt, err := encodeCloudGoalModelPrompt("research_official_sources", input.Request, struct {
		OfficialProfiles []serverOwnedResearchHint `json:"official_profiles,omitempty"`
	}{OfficialProfiles: officialProfiles})
	if err != nil {
		return nil, ErrCloudGoalModelUnavailable
	}
	if len(officialProfiles) > 0 {
		return model.researchServerOwnedProfile(ctx, input.Request, prompt, officialProfiles)
	}
	raw, err := model.runCapture(ctx, input.Request, prompt, captureOfficialSourcesTool, cloudskill.OfficialSourceDraftInputSchema(), true,
		func(raw json.RawMessage, fetched map[string]publicweb.Evidence, replay bool) error {
			sources, decodeErr := cloudskill.DecodeOfficialSourceDraft(raw)
			if decodeErr != nil {
				return captureValidationFailure("official_sources_schema_invalid")
			}
			if validateOfficialSourceClaims(sources) != nil {
				return captureValidationFailure("official_sources_claims_invalid")
			}
			if !replay && !sourcesMatchFetchedEvidence(sources, fetched) {
				return captureValidationFailure("official_sources_evidence_mismatch")
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	return cloudskill.DecodeOfficialSourceDraft(raw)
}

type serverOwnedResearchHint struct {
	SourceID       string                       `json:"source_id"`
	ResearchURL    string                       `json:"research_url"`
	ArtifactURL    string                       `json:"artifact_url"`
	ArtifactDigest string                       `json:"artifact_digest"`
	Version        string                       `json:"version"`
	Commit         string                       `json:"commit"`
	License        string                       `json:"license"`
	Kind           recipe.SourceKind            `json:"kind"`
	Repository     *recipe.RepositoryIdentityV1 `json:"repository,omitempty"`
}

func serverOwnedResearchHints(recipeID string) []serverOwnedResearchHint {
	var result []serverOwnedResearchHint
	switch {
	case knowledgeprofile.IsRetainedRecipeID(recipeID):
		for _, hint := range knowledgeprofile.ResearchHints() {
			result = append(result, serverOwnedResearchHint{
				SourceID: hint.SourceID, ResearchURL: hint.ResearchURL, ArtifactURL: hint.ArtifactURL,
				ArtifactDigest: hint.ArtifactDigest, Version: hint.Version, Commit: hint.Commit,
				License: hint.License, Kind: hint.Kind,
			})
		}
	case workerprofile.IsDiagnosticRecipeID(recipeID):
		for _, hint := range workerprofile.ResearchHints() {
			result = append(result, serverOwnedResearchHint{
				SourceID: hint.SourceID, ResearchURL: hint.ResearchURL, ArtifactURL: hint.ArtifactURL,
				ArtifactDigest: hint.ArtifactDigest, Version: hint.Version, Commit: hint.Commit,
				License: hint.License, Kind: hint.Kind, Repository: hint.Repository,
			})
		}
	}
	return result
}

func (model *EinoCloudGoalPlanningModel) researchServerOwnedProfile(
	ctx context.Context,
	request CloudGoalStageRequest,
	prompt string,
	hints []serverOwnedResearchHint,
) ([]recipe.SourceV1, error) {
	if model == nil || ctx == nil || validateCloudGoalModelStageRequest(request) != nil ||
		strings.TrimSpace(prompt) == "" || len(hints) == 0 {
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
	claim, err := model.store.BeginRuntimeRequest(ctx, runtimeScope, runtimeapi.RuntimeRequestCommand{
		Request: chatRequest, LeaseDuration: requestLease,
	})
	if err != nil {
		reportCloudGoalModelFailure(request, "profile_request_claim_failed")
		return nil, ErrCloudGoalModelUnavailable
	}
	if claim.Completed {
		sources, decodeErr := cloudskill.DecodeOfficialSourceDraft(json.RawMessage(claim.Response.Result.Message.Content))
		if decodeErr != nil || validateOfficialSourceClaims(sources) != nil ||
			!sourcesMatchServerOwnedHints(sources, hints) {
			reportCloudGoalModelFailure(request, "completed_profile_capture_invalid")
			return nil, ErrCloudGoalModelUnavailable
		}
		return sources, nil
	}

	completed := false
	defer func() {
		if completed {
			return
		}
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_ = model.store.ReleaseRuntimeRequest(releaseCtx, runtimeScope, runtimeapi.ReleaseRuntimeRequestCommand{
			RequestID: modelRequestID, LeaseEpoch: claim.LeaseEpoch,
		})
	}()
	executionCtx, leaseGuard := runtimeapp.StartLeaseRenewalGuard(ctx, requestLease, func(renewCtx context.Context, extension time.Duration) error {
		_, renewErr := model.store.RenewRuntimeRequest(renewCtx, runtimeScope, runtimeapi.RenewRuntimeRequestCommand{
			RequestID: modelRequestID, LeaseEpoch: claim.LeaseEpoch, LeaseDuration: extension,
		})
		return renewErr
	})
	if leaseGuard == nil {
		reportCloudGoalModelFailure(request, "profile_lease_guard_unavailable")
		return nil, ErrCloudGoalModelUnavailable
	}
	defer func() {
		if leaseGuard != nil {
			_ = leaseGuard.Stop()
		}
	}()
	bound, err := model.store.BindRuntimeRequestMemoryMode(executionCtx, runtimeScope, runtimeapi.BindRuntimeRequestMemoryModeCommand{
		RequestID: modelRequestID, LeaseEpoch: claim.LeaseEpoch, MemoryDisabled: true,
	})
	if err != nil || !bound {
		reportCloudGoalModelFailure(request, "profile_memory_mode_binding_failed")
		return nil, ErrCloudGoalModelUnavailable
	}
	toolRequest := runtimeapi.ToolRequest{
		RequestID: modelRequestID, OwnerID: request.Binding.OwnerID, ConversationID: request.Binding.ConversationID,
	}
	tools, err := model.tools.ToolsWithLease(executionCtx, runtimeScope, claim.LeaseEpoch, toolRequest)
	if err != nil || len(tools) != 1 || tools[0].Definition.Name != publicweb.ToolName || tools[0].Run == nil {
		reportCloudGoalModelFailure(request, "profile_official_fetch_unavailable")
		return nil, ErrCloudGoalModelUnavailable
	}
	namespace, err := uuid.Parse(modelRequestID)
	if err != nil {
		return nil, ErrCloudGoalModelUnavailable
	}
	sources := make([]recipe.SourceV1, 0, len(hints))
	fetched := make(map[string]publicweb.Evidence, len(hints))
	for _, hint := range hints {
		arguments, marshalErr := json.Marshal(struct {
			URL string `json:"url"`
		}{URL: hint.ResearchURL})
		if marshalErr != nil {
			return nil, ErrCloudGoalModelUnavailable
		}
		toolCallID := uuid.NewSHA1(namespace, []byte("server-profile-source\x00"+hint.ResearchURL)).String()
		result, runErr := tools[0].Run(executionCtx, runtimeapi.ToolInvocation{
			RequestID: modelRequestID, OwnerID: request.Binding.OwnerID, ConversationID: request.Binding.ConversationID,
			ToolCallID: toolCallID, Name: publicweb.ToolName, Arguments: arguments,
		})
		if runErr != nil || result.IsError {
			reportCloudGoalModelFailure(request, "profile_official_fetch_failed")
			return nil, ErrCloudGoalModelUnavailable
		}
		evidence, parseErr := publicweb.ParseEvidenceResult(result.Content)
		if parseErr != nil || evidence.URL != hint.ResearchURL {
			reportCloudGoalModelFailure(request, "profile_official_fetch_invalid")
			return nil, ErrCloudGoalModelUnavailable
		}
		fetched[evidence.URL] = evidence
		sources = append(sources, recipe.SourceV1{
			ID: hint.SourceID, URL: hint.ResearchURL, ArtifactURL: hint.ArtifactURL,
			Version: hint.Version, Commit: hint.Commit, ArtifactDigest: hint.ArtifactDigest,
			ContentDigest: evidence.ContentDigest, License: hint.License, RetrievedAt: evidence.RetrievedAt,
			Official: true, Kind: hint.Kind, Repository: hint.Repository,
		})
	}
	executionErr := executionCtx.Err()
	renewErr := leaseGuard.Stop()
	leaseGuard = nil
	if renewErr != nil || executionErr != nil || validateOfficialSourceClaims(sources) != nil ||
		!sourcesMatchFetchedEvidence(sources, fetched) || !sourcesMatchServerOwnedHints(sources, hints) {
		reportCloudGoalModelFailure(request, "profile_capture_invalid")
		return nil, ErrCloudGoalModelUnavailable
	}
	raw, err := json.Marshal(struct {
		Sources []recipe.SourceV1 `json:"sources"`
	}{Sources: sources})
	if err != nil || len(raw) > cloudGoalModelMaxCapture || security.ContainsLikelySecret(string(raw)) {
		return nil, ErrCloudGoalModelUnavailable
	}
	canonical := modelapi.Message{Role: modelapi.RoleAssistant, Content: string(raw)}
	snapshot, err := model.store.CompleteRuntimeRequest(ctx, runtimeScope, runtimeapi.CompleteRuntimeRequestCommand{
		RequestID: modelRequestID, LeaseEpoch: claim.LeaseEpoch, Result: runtimeapi.ChatResult{Message: canonical},
	})
	if err != nil || snapshot.Result.Message.Content != canonical.Content {
		reportCloudGoalModelFailure(request, "profile_capture_persistence_failed")
		return nil, ErrCloudGoalModelUnavailable
	}
	completed = true
	return sources, nil
}

func sourcesMatchServerOwnedHints(sources []recipe.SourceV1, hints []serverOwnedResearchHint) bool {
	if len(sources) != len(hints) {
		return false
	}
	for index, source := range sources {
		hint := hints[index]
		if source.ID != hint.SourceID || source.URL != hint.ResearchURL || source.ArtifactURL != hint.ArtifactURL ||
			source.Version != hint.Version || source.Commit != hint.Commit || source.ArtifactDigest != hint.ArtifactDigest ||
			source.License != hint.License || source.Kind != hint.Kind || !source.Official ||
			source.RetrievedAt.IsZero() || recipe.ValidateDigest(source.ContentDigest) != nil ||
			!sameRepositoryIdentity(source.Repository, hint.Repository) {
			return false
		}
	}
	return true
}

func sameRepositoryIdentity(left, right *recipe.RepositoryIdentityV1) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func (model *EinoCloudGoalPlanningModel) DraftExperimentalRecipe(ctx context.Context, input CloudGoalRecipeInput) (recipe.RecipeV1, error) {
	profileRecipe, profileMatched := serverProfileRecipe(input.Request.Binding.RecipeID, input.Evidence)
	if profileMatched {
		return profileRecipe, nil
	}
	if validateEvidenceSet(input.Request.Attempt.TaskID, input.Evidence) != nil ||
		len(input.Evidence.Sources) != len(input.Evidence.Evidence) {
		return recipe.RecipeV1{}, ErrCloudGoalModelUnavailable
	}
	prompt, err := encodeCloudGoalModelPrompt("draft_experimental_recipe", input.Request, struct {
		Evidence []OfficialSourceEvidence `json:"official_source_evidence"`
		Sources  []recipe.SourceV1        `json:"server_bound_sources"`
		Actions  []string                 `json:"supported_install_actions"`
	}{
		Evidence: input.Evidence.Evidence,
		Sources:  input.Evidence.Sources,
		Actions:  []string{"worker.noop", "installer.execute"},
	})
	if err != nil {
		return recipe.RecipeV1{}, ErrCloudGoalModelUnavailable
	}
	binding := cloudSkillBinding(input.Request.Binding)
	raw, err := model.runCapture(ctx, input.Request, prompt, captureExperimentalRecipeTool, cloudskill.RecipeBehaviorDraftInputSchema(), true,
		func(raw json.RawMessage, fetched map[string]publicweb.Evidence, replay bool) error {
			decoded, decodeErr := cloudskill.DecodeRecipeBehaviorDraft(raw, binding, input.Evidence.Sources)
			if decodeErr != nil {
				switch {
				case errors.Is(decodeErr, cloudskill.ErrPlanningDraftSchemaInvalid):
					return captureValidationFailure("planning_recipe_schema_invalid")
				default:
					return captureValidationFailure("planning_recipe_invalid")
				}
			}
			if validateRecipeForEvidence(input.Request.Binding, decoded, input.Evidence) != nil {
				return captureValidationFailure("recipe_evidence_binding_invalid")
			}
			if !replay && !boundEvidenceWasFetched(input.Evidence, fetched) {
				return captureValidationFailure("required_evidence_not_fetched")
			}
			return nil
		})
	if err != nil {
		return recipe.RecipeV1{}, err
	}
	decoded, err := cloudskill.DecodeRecipeBehaviorDraft(raw, binding, input.Evidence.Sources)
	if err != nil {
		return recipe.RecipeV1{}, ErrCloudGoalModelUnavailable
	}
	return decoded, nil
}

func serverProfileRecipe(recipeID string, evidence OfficialSourceEvidenceSet) (recipe.RecipeV1, bool) {
	if value, matched := workerProfileRecipe(recipeID, evidence); matched {
		return value, true
	}
	return knowledgeProfileRecipe(recipeID, evidence)
}

func workerProfileRecipe(recipeID string, evidence OfficialSourceEvidenceSet) (recipe.RecipeV1, bool) {
	if !workerprofile.IsDiagnosticRecipeID(recipeID) {
		return recipe.RecipeV1{}, false
	}
	values := make([]workerprofile.Evidence, 0, len(evidence.Evidence))
	for _, item := range evidence.Evidence {
		values = append(values, workerprofile.Evidence{
			URL: item.URL, RetrievedAt: item.RetrievedAt, ContentDigest: item.ContentDigest,
		})
	}
	return workerprofile.BindExperimentalRecipe(recipeID, values)
}

func knowledgeProfileRecipe(recipeID string, evidence OfficialSourceEvidenceSet) (recipe.RecipeV1, bool) {
	if !knowledgeprofile.IsRetainedRecipeID(recipeID) {
		return recipe.RecipeV1{}, false
	}
	values := make([]knowledgeprofile.Evidence, 0, len(evidence.Evidence))
	for _, item := range evidence.Evidence {
		values = append(values, knowledgeprofile.Evidence{
			URL: item.URL, RetrievedAt: item.RetrievedAt, ContentDigest: item.ContentDigest,
		})
	}
	return knowledgeprofile.BindExperimentalRecipe(recipeID, values)
}

func (model *EinoCloudGoalPlanningModel) ProposeResourceCandidates(ctx context.Context, input CloudGoalCandidateInput) ([]ResourceCandidateV1, error) {
	digest, digestErr := input.Draft.Recipe.Digest()
	if input.Draft.Revision < 1 || input.Draft.Recipe.Validate() != nil || digestErr != nil ||
		digest != input.Draft.Digest {
		return nil, ErrCloudGoalModelUnavailable
	}
	if fixed, matched := workerprofile.ResourceCandidates(input.Draft.Recipe); matched {
		result := make([]ResourceCandidateV1, 0, len(fixed))
		for _, candidate := range fixed {
			result = append(result, ResourceCandidateV1{
				Tier: CandidateTier(candidate.Tier), Architecture: candidate.Architecture,
				VCPU: candidate.VCPU, MemoryMiB: candidate.MemoryMiB, DiskGiB: candidate.DiskGiB,
				Rationale: candidate.Rationale,
			})
		}
		if ValidateCandidatesAgainstRecipe(result, input.Draft.Recipe.Requirements) != nil {
			return nil, ErrCloudGoalModelUnavailable
		}
		return result, nil
	}
	prompt, err := encodeCloudGoalModelPrompt("propose_resource_candidates", input.Request, struct {
		RecipeDigest string                        `json:"recipe_digest"`
		Requirements recipe.ResourceRequirementsV1 `json:"requirements"`
	}{
		RecipeDigest: input.Draft.Digest,
		Requirements: input.Draft.Recipe.Requirements,
	})
	if err != nil {
		return nil, ErrCloudGoalModelUnavailable
	}
	raw, err := model.runCapture(ctx, input.Request, prompt, captureResourceCandidatesTool, cloudskill.ResourceCandidateDraftInputSchema(), false,
		func(raw json.RawMessage, _ map[string]publicweb.Evidence, _ bool) error {
			decoded, decodeErr := cloudskill.DecodeResourceCandidateDraft(raw, input.Draft.Recipe.Requirements)
			if decodeErr != nil {
				switch {
				case errors.Is(decodeErr, cloudskill.ErrPlanningDraftSchemaInvalid):
					return captureValidationFailure("resource_candidates_schema_invalid")
				default:
					return captureValidationFailure("resource_candidates_invalid")
				}
			}
			if len(decoded) != 3 {
				return captureValidationFailure("resource_candidates_invalid")
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	decoded, err := cloudskill.DecodeResourceCandidateDraft(raw, input.Draft.Recipe.Requirements)
	if err != nil {
		return nil, ErrCloudGoalModelUnavailable
	}
	result := make([]ResourceCandidateV1, 0, len(decoded))
	for _, candidate := range decoded {
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

type captureValidationFailure string

func (failure captureValidationFailure) Error() string {
	return string(failure)
}

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
		reportCloudGoalModelFailure(request, "request_claim_failed")
		return nil, ErrCloudGoalModelUnavailable
	}
	if claim.Completed {
		raw := json.RawMessage(claim.Response.Result.Message.Content)
		if validate(raw, nil, true) != nil {
			reportCloudGoalModelFailure(request, "completed_capture_invalid")
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
		reportCloudGoalModelFailure(request, "memory_mode_binding_failed")
		return nil, ErrCloudGoalModelUnavailable
	}
	config, err := model.store.LoadRuntimeConfig(executionCtx, request.Binding.OwnerID)
	if err != nil || runtimeapi.ValidateRuntimeConfig(config) != nil {
		reportCloudGoalModelFailure(request, "runtime_config_invalid")
		return nil, ErrCloudGoalModelUnavailable
	}
	client, err := model.models.CreateModel(executionCtx, config.ModelProfile, model.secrets)
	if err != nil || client == nil {
		reportCloudGoalModelFailure(request, "model_client_unavailable")
		return nil, ErrCloudGoalModelUnavailable
	}

	toolRequest := runtimeapi.ToolRequest{RequestID: modelRequestID, OwnerID: request.Binding.OwnerID, ConversationID: request.Binding.ConversationID}
	available := make(map[string]runtimeapi.Tool)
	definitions := make([]modelapi.Tool, 0, 2)
	if withOfficialFetch {
		tools, toolErr := model.tools.ToolsWithLease(executionCtx, runtimeScope, claim.LeaseEpoch, toolRequest)
		if toolErr != nil || len(tools) != 1 || tools[0].Definition.Name != publicweb.ToolName || tools[0].Run == nil {
			reportCloudGoalModelFailure(request, "official_fetch_tool_unavailable")
			return nil, ErrCloudGoalModelUnavailable
		}
		available[publicweb.ToolName] = tools[0]
		definitions = append(definitions, tools[0].Definition)
	}
	capture := &planningCapture{}
	definitions = append(definitions, modelapi.Tool{
		Name: captureName,
		Description: "Submit the complete planning output after using every required official-source tool. " +
			"If the server rejects it, correct the full output and resubmit until accepted.",
		InputSchema: captureSchema,
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
			return invokeCloudGoalModelTool(runCtx, toolRequest, call, captureName, capture, available, fetched, validate)
		},
	})
	executionErr := executionCtx.Err()
	renewErr := leaseGuard.Stop()
	leaseGuard = nil
	failureReason := ""
	switch {
	case renewErr != nil:
		failureReason = "request_lease_renewal_failed"
	case executionErr != nil:
		failureReason = "model_execution_context_failed"
	case errors.Is(err, runtimeapi.ErrStepLimit):
		failureReason = "model_step_limit_exceeded"
	case err != nil:
		failureReason = "model_generation_failed"
	case result.Message.Role != modelapi.RoleAssistant:
		failureReason = "model_response_role_invalid"
	}
	if failureReason != "" {
		reportCloudGoalModelFailure(request, capture.failureReason(failureReason))
		return nil, ErrCloudGoalModelUnavailable
	}
	raw, ok := capture.value()
	if !ok {
		reportCloudGoalModelFailure(request, capture.failureReason("capture_missing"))
		return nil, ErrCloudGoalModelUnavailable
	}
	if validate(raw, fetched, false) != nil {
		reportCloudGoalModelFailure(request, "accepted_capture_became_invalid")
		return nil, ErrCloudGoalModelUnavailable
	}
	canonical := modelapi.Message{Role: modelapi.RoleAssistant, Content: string(raw)}
	snapshot, err := model.store.CompleteRuntimeRequest(ctx, runtimeScope, runtimeapi.CompleteRuntimeRequestCommand{
		RequestID: modelRequestID, LeaseEpoch: claim.LeaseEpoch, Result: runtimeapi.ChatResult{Message: canonical},
	})
	if err != nil || snapshot.Result.Message.Content != canonical.Content {
		reportCloudGoalModelFailure(request, "capture_persistence_failed")
		return nil, ErrCloudGoalModelUnavailable
	}
	completed = true
	return append(json.RawMessage(nil), raw...), nil
}

func reportCloudGoalModelFailure(request CloudGoalStageRequest, reason string) {
	slog.Warn(
		"cloud Goal planning model failed",
		"task_id", request.Attempt.TaskID,
		"step_id", request.Step.StepID,
		"stage", request.Step.Name,
		"reason", reason,
	)
}

type planningCapture struct {
	mu            sync.Mutex
	raw           json.RawMessage
	submissions   int
	lastRejection string
}

func (capture *planningCapture) submit(
	raw string,
	fetched map[string]publicweb.Evidence,
	validate captureValidator,
) (bool, string, error) {
	if capture == nil || len(raw) == 0 || len(raw) > cloudGoalModelMaxCapture || !json.Valid([]byte(raw)) || security.ContainsLikelySecret(raw) {
		return false, "", ErrCloudGoalModelUnavailable
	}
	compact := &bytes.Buffer{}
	if err := json.Compact(compact, []byte(raw)); err != nil {
		return false, "", ErrCloudGoalModelUnavailable
	}
	canonical := append(json.RawMessage(nil), compact.Bytes()...)
	validationErr := validate(canonical, fetched, false)
	rejection := captureValidationFailureCode(validationErr)

	capture.mu.Lock()
	defer capture.mu.Unlock()
	if len(capture.raw) != 0 || capture.submissions >= cloudGoalModelMaxSubmissions {
		return false, "", ErrCloudGoalModelUnavailable
	}
	capture.submissions++
	if validationErr != nil {
		capture.lastRejection = rejection
		return false, rejection, nil
	}
	capture.raw = canonical
	return true, "", nil
}

func (capture *planningCapture) value() (json.RawMessage, bool) {
	if capture == nil {
		return nil, false
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append(json.RawMessage(nil), capture.raw...), len(capture.raw) != 0
}

func (capture *planningCapture) failureReason(fallback string) string {
	if capture == nil {
		return fallback
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if capture.lastRejection == "" {
		return fallback
	}
	return fallback + "_after_" + capture.lastRejection
}

func captureValidationFailureCode(err error) string {
	if err == nil {
		return ""
	}
	var failure captureValidationFailure
	if errors.As(err, &failure) {
		switch failure {
		case "official_sources_schema_invalid",
			"official_sources_claims_invalid",
			"official_sources_evidence_mismatch",
			"planning_draft_schema_invalid",
			"planning_recipe_schema_invalid",
			"planning_recipe_invalid",
			"planning_candidates_invalid",
			"recipe_evidence_binding_invalid",
			"required_evidence_not_fetched",
			"resource_candidates_schema_invalid",
			"resource_candidates_invalid",
			"approved_recipe_invalid",
			"approved_recipe_changed":
			return failure.Error()
		}
	}
	return "capture_contract_invalid"
}

func invokeCloudGoalModelTool(
	ctx context.Context,
	request runtimeapi.ToolRequest,
	call modelapi.ToolCall,
	captureName string,
	capture *planningCapture,
	available map[string]runtimeapi.Tool,
	fetched map[string]publicweb.Evidence,
	validate captureValidator,
) (runtimeapi.ToolExecution, error) {
	name := strings.TrimSpace(call.Function.Name)
	if strings.TrimSpace(call.ID) == "" || len(call.ID) > 255 || security.ContainsLikelySecret(call.ID) || name == "" || !json.Valid([]byte(call.Function.Arguments)) {
		return runtimeapi.ToolExecution{}, ErrCloudGoalModelUnavailable
	}
	if name == captureName {
		accepted, rejection, err := capture.submit(call.Function.Arguments, fetched, validate)
		if err != nil {
			return runtimeapi.ToolExecution{}, err
		}
		if !accepted {
			content, marshalErr := json.Marshal(struct {
				Accepted    bool   `json:"accepted"`
				Error       string `json:"error"`
				Instruction string `json:"instruction"`
			}{
				Accepted: false,
				Error:    rejection,
				Instruction: "Correct the complete output against the tool schema and exact prompt evidence, " +
					"then submit it again.",
			})
			if marshalErr != nil {
				return runtimeapi.ToolExecution{}, ErrCloudGoalModelUnavailable
			}
			return runtimeapi.ToolExecution{ToolCallID: call.ID, Name: name, Content: string(content), IsError: true}, nil
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
		"Call " + captureName + " with the complete result. Stop only after it returns accepted=true; when it returns accepted=false, correct the full output and resubmit. " +
		"All identity, Region, price, network and retention decisions remain server-owned."
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
