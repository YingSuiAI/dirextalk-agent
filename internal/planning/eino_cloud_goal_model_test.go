package planning

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agent/cloudskill"
	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/publicweb"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestEinoCloudGoalPlanningModelDurablyReplaysOfficialResearchRecipeAndCandidates(t *testing.T) {
	recipeValue := validRecipe()
	recipeValue.RecipeID = "recipe-model-1"
	planRaw := planningModelPlanRaw(t, recipeValue)
	store := &cloudGoalModelStoreFake{config: planningModelRuntimeConfig(), completed: make(map[string]runtimeapi.RuntimeResponseSnapshot)}
	engine := &cloudGoalModelEngineFake{source: recipeValue.Sources[0], planRaw: planRaw}
	tools := &cloudGoalModelToolsFake{source: recipeValue.Sources[0]}
	model, err := NewEinoCloudGoalPlanningModel(store, engine, runtimeapi.ModelFactoryFunc(func(context.Context, modelapi.Profile, runtimeapi.SecretResolver) (modelapi.Client, error) {
		return cloudGoalModelClientFake{}, nil
	}), runtimeapi.SecretResolver(runtimeapiSecretResolverFake{}), tools)
	if err != nil {
		t.Fatal(err)
	}

	research := planningModelStage(cloudskill.StepResearchOfficialSources, recipeValue.RecipeID)
	sources, err := model.ResearchOfficialSources(t.Context(), CloudGoalResearchInput{Request: research})
	if err != nil || len(sources) != 1 || sources[0].ContentDigest != recipeValue.Sources[0].ContentDigest {
		t.Fatalf("research sources=%#v err=%v", sources, err)
	}
	modelCalls := engine.calls
	replayed, err := model.ResearchOfficialSources(t.Context(), CloudGoalResearchInput{Request: research})
	if err != nil || len(replayed) != 1 || engine.calls != modelCalls {
		t.Fatalf("research replay sources=%#v err=%v model_calls=%d", replayed, err, engine.calls)
	}
	researchRequestID, err := CloudGoalModelRequestID(research.Binding, research.Attempt.TaskID, research.Step.Name)
	if err != nil || researchRequestID == research.Binding.RequestID || store.requests[0].Request.RequestID != researchRequestID {
		t.Fatalf("research request id=%q original=%q stored=%q err=%v", researchRequestID, research.Binding.RequestID, store.requests[0].Request.RequestID, err)
	}
	if tools.scope.ClientID != research.Caller.ClientID || tools.scope.CredentialID != research.Caller.CredentialID || tools.parentLease != 1 || tools.request.RequestID != researchRequestID {
		t.Fatalf("trusted tool scope drifted: %#v epoch=%d request=%#v", tools.scope, tools.parentLease, tools.request)
	}

	evidence, err := BuildOfficialSourceEvidenceSet(research.Attempt.TaskID, []OfficialSourceEvidence{{
		TaskID: research.Attempt.TaskID, ToolCallID: "official-fetch-1", URL: sources[0].URL,
		RetrievedAt: sources[0].RetrievedAt, ContentDigest: sources[0].ContentDigest,
	}})
	if err != nil {
		t.Fatal(err)
	}
	draftRequest := planningModelStage(cloudskill.StepDraftRecipe, recipeValue.RecipeID)
	draftRequest.Binding.RequestID = research.Binding.RequestID
	draftRequest.Binding.ConversationID = research.Binding.ConversationID
	draftRequest.Attempt.TaskID, draftRequest.Step.TaskID = research.Attempt.TaskID, research.Attempt.TaskID
	drafted, err := model.DraftExperimentalRecipe(t.Context(), CloudGoalRecipeInput{Request: draftRequest, Evidence: evidence})
	if err != nil || drafted.RecipeID != recipeValue.RecipeID || drafted.Maturity != recipe.MaturityExperimental {
		t.Fatalf("drafted recipe=%#v err=%v", drafted, err)
	}
	digest, err := drafted.Digest()
	if err != nil {
		t.Fatal(err)
	}
	candidateRequest := planningModelStage(cloudskill.StepPrepareResourceCandidates, recipeValue.RecipeID)
	candidateRequest.Binding.RequestID = research.Binding.RequestID
	candidateRequest.Binding.ConversationID = research.Binding.ConversationID
	candidateRequest.Attempt.TaskID, candidateRequest.Step.TaskID = research.Attempt.TaskID, research.Attempt.TaskID
	candidates, err := model.ProposeResourceCandidates(t.Context(), CloudGoalCandidateInput{
		Request: candidateRequest, Draft: RecipeDraft{RecipeID: drafted.RecipeID, Recipe: drafted, Digest: digest, Revision: 1},
	})
	if err != nil || len(candidates) != 3 || candidates[0].Tier != TierEconomy || candidates[2].Tier != TierPerformance ||
		ValidateCandidatesAgainstRecipe(candidates, drafted.Requirements) != nil {
		t.Fatalf("candidates=%#v err=%v", candidates, err)
	}
	if len(store.completed) != 3 || store.releaseCalls != 0 || engine.calls != 3 {
		t.Fatalf("durable model state completed=%d releases=%d calls=%d", len(store.completed), store.releaseCalls, engine.calls)
	}
}

func TestEinoCloudGoalPlanningModelRejectsUnfetchedAndSecretBearingCapture(t *testing.T) {
	recipeValue := validRecipe()
	recipeValue.RecipeID = "recipe-model-2"
	store := &cloudGoalModelStoreFake{config: planningModelRuntimeConfig(), completed: make(map[string]runtimeapi.RuntimeResponseSnapshot)}
	engine := &cloudGoalModelEngineFake{source: recipeValue.Sources[0], planRaw: planningModelPlanRaw(t, recipeValue), skipFetch: true}
	model, err := NewEinoCloudGoalPlanningModel(store, engine, runtimeapi.ModelFactoryFunc(func(context.Context, modelapi.Profile, runtimeapi.SecretResolver) (modelapi.Client, error) {
		return cloudGoalModelClientFake{}, nil
	}), runtimeapi.SecretResolver(runtimeapiSecretResolverFake{}), &cloudGoalModelToolsFake{source: recipeValue.Sources[0]})
	if err != nil {
		t.Fatal(err)
	}
	_, err = model.ResearchOfficialSources(t.Context(), CloudGoalResearchInput{Request: planningModelStage(cloudskill.StepResearchOfficialSources, recipeValue.RecipeID)})
	if !errors.Is(err, ErrCloudGoalModelUnavailable) || store.releaseCalls != 1 || len(store.completed) != 0 {
		t.Fatalf("unfetched source error=%v releases=%d completed=%d", err, store.releaseCalls, len(store.completed))
	}

	engine.skipFetch = false
	engine.source.License = "sk-" + strings.Repeat("Z", 40)
	_, err = model.ResearchOfficialSources(t.Context(), CloudGoalResearchInput{Request: planningModelStage(cloudskill.StepResearchOfficialSources, recipeValue.RecipeID)})
	if !errors.Is(err, ErrCloudGoalModelUnavailable) || len(store.completed) != 0 {
		t.Fatalf("secret capture error=%v completed=%d", err, len(store.completed))
	}
}

func TestEinoCloudGoalPlanningModelRenewsSyntheticRequestAcrossSlowModelAndTool(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		modelWait time.Duration
		toolWait  time.Duration
	}{
		{name: "slow model", modelWait: 140 * time.Millisecond},
		{name: "slow tool", toolWait: 140 * time.Millisecond},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			recipeValue := validRecipe()
			recipeValue.RecipeID = "recipe-model-lease-" + strings.ReplaceAll(testCase.name, " ", "-")
			store := &cloudGoalModelStoreFake{
				config:    planningModelRuntimeConfig(),
				completed: make(map[string]runtimeapi.RuntimeResponseSnapshot),
			}
			engine := &cloudGoalModelEngineFake{
				source: recipeValue.Sources[0], planRaw: planningModelPlanRaw(t, recipeValue), delay: testCase.modelWait,
			}
			tools := &cloudGoalModelToolsFake{source: recipeValue.Sources[0], delay: testCase.toolWait}
			model, err := NewEinoCloudGoalPlanningModel(store, engine, runtimeapi.ModelFactoryFunc(func(context.Context, modelapi.Profile, runtimeapi.SecretResolver) (modelapi.Client, error) {
				return cloudGoalModelClientFake{}, nil
			}), runtimeapi.SecretResolver(runtimeapiSecretResolverFake{}), tools)
			if err != nil {
				t.Fatal(err)
			}
			model.requestLease = 45 * time.Millisecond
			request := planningModelStage(cloudskill.StepResearchOfficialSources, recipeValue.RecipeID)

			if _, err := model.ResearchOfficialSources(t.Context(), CloudGoalResearchInput{Request: request}); err != nil {
				t.Fatalf("slow planning stage failed: %v", err)
			}
			if renewals := store.renewCalls.Load(); renewals < 2 {
				t.Fatalf("runtime request renewals=%d, want at least 2", renewals)
			}
			if len(store.requests) != 1 || store.requests[0].LeaseDuration != model.requestLease ||
				time.Duration(store.lastRenewLease.Load()) != model.requestLease {
				t.Fatalf("request/renew lease drift: requests=%#v renewed=%s", store.requests, time.Duration(store.lastRenewLease.Load()))
			}
			if store.lastCompleteEpoch != 1 || len(store.completed) != 1 || engine.calls != 1 {
				t.Fatalf("completion fence=%d completed=%d model_calls=%d", store.lastCompleteEpoch, len(store.completed), engine.calls)
			}

			if _, err := model.ResearchOfficialSources(t.Context(), CloudGoalResearchInput{Request: request}); err != nil {
				t.Fatalf("durable replay failed: %v", err)
			}
			if engine.calls != 1 {
				t.Fatalf("completed request repeated billable model call: %d", engine.calls)
			}
		})
	}
}

func TestEinoCloudGoalPlanningModelRenewalFailureCancelsAndNeverCompletes(t *testing.T) {
	const renewalCanary = "renewal-sk-should-not-leak"
	recipeValue := validRecipe()
	recipeValue.RecipeID = "recipe-model-renew-failure"
	canceled := make(chan struct{})
	store := &cloudGoalModelStoreFake{
		config: planningModelRuntimeConfig(), completed: make(map[string]runtimeapi.RuntimeResponseSnapshot),
		renewErr: errors.New(renewalCanary),
	}
	engine := &cloudGoalModelEngineFake{
		source: recipeValue.Sources[0], planRaw: planningModelPlanRaw(t, recipeValue),
		delay: time.Second, canceled: canceled,
	}
	model, err := NewEinoCloudGoalPlanningModel(store, engine, runtimeapi.ModelFactoryFunc(func(context.Context, modelapi.Profile, runtimeapi.SecretResolver) (modelapi.Client, error) {
		return cloudGoalModelClientFake{}, nil
	}), runtimeapi.SecretResolver(runtimeapiSecretResolverFake{}), &cloudGoalModelToolsFake{source: recipeValue.Sources[0]})
	if err != nil {
		t.Fatal(err)
	}
	model.requestLease = 45 * time.Millisecond

	_, err = model.ResearchOfficialSources(t.Context(), CloudGoalResearchInput{Request: planningModelStage(cloudskill.StepResearchOfficialSources, recipeValue.RecipeID)})
	if !errors.Is(err, ErrCloudGoalModelUnavailable) || strings.Contains(err.Error(), renewalCanary) {
		t.Fatalf("renewal failure was not stable and redacted: %v", err)
	}
	select {
	case <-canceled:
	default:
		t.Fatal("runtime request renewal failure did not cancel model execution")
	}
	if store.renewCalls.Load() != 1 || len(store.completed) != 0 || store.releaseCalls != 1 {
		t.Fatalf("renewals=%d completed=%d releases=%d", store.renewCalls.Load(), len(store.completed), store.releaseCalls)
	}
}

type cloudGoalModelStoreFake struct {
	config            runtimeapi.RuntimeConfig
	requests          []runtimeapi.RuntimeRequestCommand
	completed         map[string]runtimeapi.RuntimeResponseSnapshot
	releaseCalls      int
	renewCalls        atomic.Int32
	lastRenewLease    atomic.Int64
	renewErr          error
	lastCompleteEpoch int64
}

func (fake *cloudGoalModelStoreFake) LoadRuntimeConfig(context.Context, string) (runtimeapi.RuntimeConfig, error) {
	return fake.config, nil
}

func (fake *cloudGoalModelStoreFake) BeginRuntimeRequest(_ context.Context, _ runtimeapi.MutationScope, command runtimeapi.RuntimeRequestCommand) (runtimeapi.RuntimeRequestClaim, error) {
	if snapshot, ok := fake.completed[command.Request.RequestID]; ok {
		return runtimeapi.RuntimeRequestClaim{RequestID: command.Request.RequestID, Completed: true, Response: snapshot}, nil
	}
	fake.requests = append(fake.requests, command)
	return runtimeapi.RuntimeRequestClaim{RequestID: command.Request.RequestID, LeaseEpoch: 1, LeaseExpiresAt: time.Now().Add(time.Minute)}, nil
}

func (*cloudGoalModelStoreFake) BindRuntimeRequestMemoryMode(context.Context, runtimeapi.MutationScope, runtimeapi.BindRuntimeRequestMemoryModeCommand) (bool, error) {
	return true, nil
}

func (fake *cloudGoalModelStoreFake) RenewRuntimeRequest(_ context.Context, _ runtimeapi.MutationScope, command runtimeapi.RenewRuntimeRequestCommand) (time.Time, error) {
	fake.renewCalls.Add(1)
	fake.lastRenewLease.Store(int64(command.LeaseDuration))
	if fake.renewErr != nil {
		return time.Time{}, fake.renewErr
	}
	return time.Now().Add(command.LeaseDuration), nil
}

func (fake *cloudGoalModelStoreFake) ReleaseRuntimeRequest(context.Context, runtimeapi.MutationScope, runtimeapi.ReleaseRuntimeRequestCommand) error {
	fake.releaseCalls++
	return nil
}

func (fake *cloudGoalModelStoreFake) CompleteRuntimeRequest(_ context.Context, _ runtimeapi.MutationScope, command runtimeapi.CompleteRuntimeRequestCommand) (runtimeapi.RuntimeResponseSnapshot, error) {
	fake.lastCompleteEpoch = command.LeaseEpoch
	snapshot := runtimeapi.RuntimeResponseSnapshot{SchemaVersion: runtimeapi.RuntimeResponseSnapshotSchemaV1, Result: command.Result}
	fake.completed[command.RequestID] = snapshot
	return snapshot, nil
}

type cloudGoalModelToolsFake struct {
	source      recipe.SourceV1
	scope       runtimeapi.MutationScope
	parentLease int64
	request     runtimeapi.ToolRequest
	delay       time.Duration
}

func (fake *cloudGoalModelToolsFake) ToolsWithLease(_ context.Context, scope runtimeapi.MutationScope, parentLease int64, request runtimeapi.ToolRequest) ([]runtimeapi.Tool, error) {
	fake.scope, fake.parentLease, fake.request = scope, parentLease, request
	return []runtimeapi.Tool{{
		Definition: modelapi.Tool{Name: publicweb.ToolName, InputSchema: map[string]any{"type": "object"}},
		Run: func(ctx context.Context, _ runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
			if fake.delay > 0 {
				select {
				case <-ctx.Done():
					return runtimeapi.ToolResult{}, ctx.Err()
				case <-time.After(fake.delay):
				}
			}
			encoded, _ := json.Marshal(map[string]string{
				"url": fake.source.URL, "retrieved_at": fake.source.RetrievedAt.Format(time.RFC3339Nano),
				"content_digest": fake.source.ContentDigest, "content": "official source content",
			})
			return runtimeapi.ToolResult{Content: string(encoded)}, nil
		},
	}}, nil
}

type cloudGoalModelEngineFake struct {
	source    recipe.SourceV1
	planRaw   json.RawMessage
	skipFetch bool
	calls     int
	delay     time.Duration
	canceled  chan struct{}
}

func (fake *cloudGoalModelEngineFake) Generate(ctx context.Context, request runtimeapi.EngineRequest) (runtimeapi.EngineResult, error) {
	fake.calls++
	if fake.delay > 0 {
		select {
		case <-ctx.Done():
			if fake.canceled != nil {
				close(fake.canceled)
			}
			return runtimeapi.EngineResult{}, ctx.Err()
		case <-time.After(fake.delay):
		}
	}
	captureName := request.Tools[len(request.Tools)-1].Name
	if !fake.skipFetch && len(request.Tools) == 2 {
		_, err := request.InvokeTool(ctx, modelapi.ToolCall{ID: "official-fetch-1", Type: "function", Function: modelapi.FunctionCall{
			Name: publicweb.ToolName, Arguments: `{"url":"` + fake.source.URL + `"}`,
		}})
		if err != nil {
			return runtimeapi.EngineResult{}, err
		}
	}
	raw := fake.planRaw
	if captureName == captureOfficialSourcesTool {
		encoded, _ := json.Marshal(map[string]any{"sources": []recipe.SourceV1{fake.source}})
		raw = encoded
	}
	_, err := request.InvokeTool(ctx, modelapi.ToolCall{ID: "capture-1", Type: "function", Function: modelapi.FunctionCall{Name: captureName, Arguments: string(raw)}})
	if err != nil {
		return runtimeapi.EngineResult{}, err
	}
	return runtimeapi.EngineResult{Message: modelapi.Message{Role: modelapi.RoleAssistant, Content: "captured"}}, nil
}

func (*cloudGoalModelEngineFake) Stream(context.Context, runtimeapi.EngineRequest, runtimeapi.StreamEmitter) (runtimeapi.EngineResult, error) {
	return runtimeapi.EngineResult{}, errors.New("unexpected stream")
}

type cloudGoalModelClientFake struct{}

func (cloudGoalModelClientFake) Generate(context.Context, modelapi.CompletionRequest) (modelapi.Completion, error) {
	return modelapi.Completion{}, errors.New("engine fake owns generation")
}

func (cloudGoalModelClientFake) Stream(context.Context, modelapi.CompletionRequest) (modelapi.Stream, error) {
	return nil, errors.New("engine fake owns generation")
}

type runtimeapiSecretResolverFake struct{}

func (runtimeapiSecretResolverFake) ResolveSecret(context.Context, string) ([]byte, error) {
	return nil, errors.New("not used")
}

func planningModelRuntimeConfig() runtimeapi.RuntimeConfig {
	return runtimeapi.RuntimeConfig{
		ModelProfile:        modelapi.Profile{ProfileID: "deepseek-v4", Provider: modelapi.ProviderDeepSeek, Model: "deepseekv4-pro", SecretRef: "mounted:deepseek-token", ContextWindow: 65536, MaxOutputTokens: 8192},
		ContextMessageLimit: 32, MemoryMessageLimit: 32, MaxSteps: 12, MemoryDisabled: true, Revision: 1,
	}
}

func planningModelStage(stage, recipeID string) CloudGoalStageRequest {
	taskID, stepID := uuid.NewString(), uuid.NewString()
	return CloudGoalStageRequest{
		Binding: Binding{RequestID: uuid.NewString(), OwnerID: "owner-model", ConversationID: "cloud-goal-model", ConnectionID: uuid.NewString(), RecipeID: recipeID, Retention: task.RetentionEphemeralAutoDestroy},
		Caller:  task.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()}, Goal: "Deploy an official knowledge service",
		Step:                 task.Step{TaskID: taskID, StepID: stepID, Name: stage, ExecutorKind: task.ExecutorControlPlane, ExecutionStatus: task.ExecutionRunning, OutcomeStatus: task.OutcomePending, Revision: 2},
		Attempt:              task.Attempt{TaskID: taskID, StepID: stepID, Attempt: 1, LeaseEpoch: 1, WorkerID: "agent-control", LeaseExpiresAt: time.Now().Add(time.Minute), ExecutionStatus: task.ExecutionRunning, OutcomeStatus: task.OutcomePending},
		OutputIdempotencyKey: uuid.NewString(),
	}
}

func planningModelPlanRaw(t *testing.T, value recipe.RecipeV1) json.RawMessage {
	t.Helper()
	recipeInput := cloudskill.RecipeDraftInputV1{
		Name: value.Name, Sources: value.Sources, Requirements: value.Requirements, Install: value.Install,
		Health: value.Health, Lifecycle: value.Lifecycle, VolumeSlots: value.VolumeSlots, DataSlots: value.DataSlots,
		SecretSlots: value.SecretSlots, Restart: value.Restart, Network: value.Network, Pairing: value.Pairing, Integrations: value.Integrations,
	}
	candidates := validCandidates()
	candidate := func(value ResourceCandidateV1) map[string]any {
		return map[string]any{
			"architecture": value.Architecture, "vcpu": value.VCPU, "memory_mib": value.MemoryMiB, "disk_gib": value.DiskGiB,
			"gpu_required": value.GPURequired, "rationale": value.Rationale,
		}
	}
	encoded, err := json.Marshal(map[string]any{
		"recipe": recipeInput, "economy": candidate(candidates[0]), "recommended": candidate(candidates[1]), "performance": candidate(candidates[2]),
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
