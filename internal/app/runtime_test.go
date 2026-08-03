package app

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agent/cloudskill"
	"github.com/YingSuiAI/dirextalk-agent/internal/mcphttp"
	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/searchprofile"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerprofile"
	"github.com/google/uuid"
)

func TestScopedCloudProviderDerivesStableServerOwnedRecipeScope(t *testing.T) {
	var captured cloudskill.ResearchRequest
	skill, err := cloudskill.New(cloudskill.Dependencies{
		Research: cloudskill.ResearchPortFunc(func(_ context.Context, request cloudskill.ResearchRequest) (task.Task, error) {
			captured = request
			return task.Task{
				TaskID: uuid.NewString(), OwnerID: request.Create.OwnerID, Goal: request.Create.Goal,
				ExecutionStatus: task.ExecutionQueued, OutcomeStatus: task.OutcomePending,
				RetentionPolicy: request.Create.Retention, Revision: 1,
			}, nil
		}),
		Status: cloudskill.StatusPortFunc(func(context.Context, cloudskill.StatusRequest) (cloudskill.ResearchStatus, error) {
			return cloudskill.ResearchStatus{}, nil
		}),
		RecipeDraft: cloudskill.RecipeDraftPortFunc(func(context.Context, cloudskill.RecipeDraftRequest) (cloudskill.RecipeDraft, error) {
			return cloudskill.RecipeDraft{Ready: false}, nil
		}),
		PlanDraft: cloudskill.PlanDraftPortFunc(func(context.Context, cloudskill.SubmitPlanDraftRequest) (cloudskill.SubmitPlanDraftResult, error) {
			return cloudskill.SubmitPlanDraftResult{}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	namespace := uuid.New()
	provider := &scopedCloudProvider{namespace: namespace, provider: skill}
	stateless, err := provider.Tools(context.Background(), runtimeapi.ToolRequest{RequestID: uuid.NewString(), OwnerID: "owner-1"})
	if err != nil || len(stateless) != 0 {
		t.Fatalf("stateless chat cloud tools = %#v, %v", stateless, err)
	}
	request := runtimeapi.ToolRequest{RequestID: uuid.NewString(), OwnerID: "owner-1", ConversationID: "conversation-1"}
	tools, err := provider.Tools(context.Background(), request)
	if err != nil {
		t.Fatalf("Tools() error = %v", err)
	}
	var research runtimeapi.Tool
	for _, tool := range tools {
		if tool.Definition.Name == cloudskill.ToolResearch {
			research = tool
		}
	}
	if research.Run == nil {
		t.Fatal("cloud dispatcher research tool is unavailable")
	}
	_, err = research.Run(context.Background(), runtimeapi.ToolInvocation{
		RequestID: request.RequestID, OwnerID: request.OwnerID, ConversationID: request.ConversationID,
		ToolCallID: "call-1", Name: cloudskill.ToolResearch, Arguments: json.RawMessage("{\"goal\":\"research official project documentation\"}"),
	})
	if err != nil {
		t.Fatalf("research tool error = %v", err)
	}
	wantRecipeID := uuid.NewSHA1(namespace, []byte("owner-1\x00conversation-1")).String()
	wantPlanningConversation, conversationErr := cloudskill.PlanningConversationID(request.RequestID)
	if conversationErr != nil || captured.RecipeID != wantRecipeID || captured.ConnectionID != "" ||
		captured.ConversationID != wantPlanningConversation {
		t.Fatalf("captured trusted planning scope = %#v", captured)
	}

	connectionID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	cloudRequest := runtimeapi.ToolRequest{
		RequestID: uuid.NewString(), OwnerID: "owner-1", ConversationID: "conversation-2",
		LatestUserMessage: "启动一个云端 Worker 执行诊断任务",
		CloudDialogue:     &runtimeapi.CloudDialogueScope{ConnectionID: connectionID},
	}
	cloudTools, err := provider.Tools(context.Background(), cloudRequest)
	if err != nil {
		t.Fatalf("cloud Tools() error = %v", err)
	}
	for _, tool := range cloudTools {
		if tool.Definition.Name != cloudskill.ToolResearch {
			continue
		}
		properties, _ := tool.Definition.InputSchema["properties"].(map[string]any)
		if len(properties) != 1 || properties["goal"] == nil || tool.Definition.InputSchema["additionalProperties"] != false {
			t.Fatalf("cloud dialogue model arguments are not goal-only: %#v", tool.Definition.InputSchema)
		}
		_, err = tool.Run(context.Background(), runtimeapi.ToolInvocation{
			RequestID: cloudRequest.RequestID, OwnerID: cloudRequest.OwnerID, ConversationID: cloudRequest.ConversationID,
			ToolCallID: "call-2", Name: cloudskill.ToolResearch, Arguments: json.RawMessage("{\"goal\":\"research an official cloud service\"}"),
		})
		break
	}
	wantProfileID, ok := workerprofile.RecipeIDForRequest(cloudRequest.RequestID)
	wantPlanningConversation, conversationErr = cloudskill.PlanningConversationID(cloudRequest.RequestID)
	if !ok || err != nil || conversationErr != nil || captured.ConnectionID != connectionID ||
		captured.ConversationID != wantPlanningConversation ||
		captured.RecipeID != wantProfileID {
		t.Fatalf("cloud diagnostic scope was not server-bound: captured=%#v err=%v", captured, err)
	}
}

func TestSelectedMCPProviderContactsOnlyConfiguredRuntimeServers(t *testing.T) {
	calls := 0
	provider := &selectedMCPProvider{providers: map[string]runtimeapi.ToolProvider{
		"docs": runtimeapi.ToolProviderFunc(func(context.Context, runtimeapi.ToolRequest) ([]runtimeapi.Tool, error) {
			calls++
			return []runtimeapi.Tool{{Definition: modelapi.Tool{Name: "mcp__docs__search"}, Run: func(context.Context, runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
				return runtimeapi.ToolResult{}, nil
			}}}, nil
		}),
	}}
	if tools, err := provider.Tools(context.Background(), runtimeapi.ToolRequest{}); err != nil || len(tools) != 0 || calls != 0 {
		t.Fatalf("empty MCP selection = %#v, %v, calls=%d", tools, err, calls)
	}
	if _, err := provider.Tools(context.Background(), runtimeapi.ToolRequest{MCPServerIDs: []string{"unknown"}}); !errors.Is(err, mcphttp.ErrInvalidConfig) || calls != 0 {
		t.Fatalf("unknown MCP selection error = %v, calls=%d", err, calls)
	}
	tools, err := provider.Tools(context.Background(), runtimeapi.ToolRequest{MCPServerIDs: []string{"docs", "docs"}})
	if err != nil || len(tools) != 1 || calls != 1 {
		t.Fatalf("selected MCP tools = %#v, %v, calls=%d", tools, err, calls)
	}
}

func TestCatalogModelFactoryRejectsTamperedEndpointBeforeSecretOrProviderAccess(t *testing.T) {
	catalog, err := modelapi.NewProfileCatalog([]modelapi.Profile{{
		ProfileID: "deepseek-v4", Provider: modelapi.ProviderDeepSeek, Model: "deepseekv4-pro",
		BaseURL: "https://api.deepseek.example/v1", SecretRef: "mounted:deepseek-token",
		ContextWindow: 65536, MaxOutputTokens: 8192,
	}})
	if err != nil {
		t.Fatal(err)
	}
	providerCalls := 0
	secretCalls := 0
	delegate := runtimeapi.ModelFactoryFunc(func(ctx context.Context, _ modelapi.Profile, resolver runtimeapi.SecretResolver) (modelapi.Client, error) {
		providerCalls++
		_, _ = resolver.ResolveSecret(ctx, "mounted:deepseek-token")
		return nil, nil
	})
	factory, err := newCatalogModelFactory(catalog, delegate)
	if err != nil {
		t.Fatal(err)
	}
	resolver := modelapi.SecretResolverFunc(func(context.Context, string) ([]byte, error) {
		secretCalls++
		return []byte("must-not-be-read"), nil
	})
	_, err = factory.CreateModel(context.Background(), modelapi.Profile{
		ProfileID: "deepseek-v4", Provider: modelapi.ProviderDeepSeek, Model: "deepseekv4-pro",
		BaseURL: "https://attacker.example/v1", SecretRef: "mounted:deepseek-token",
		ContextWindow: 65536, MaxOutputTokens: 8192,
	}, resolver)
	if !errors.Is(err, modelapi.ErrInvalidProfile) {
		t.Fatalf("CreateModel() error = %v", err)
	}
	if providerCalls != 0 || secretCalls != 0 {
		t.Fatalf("tampered profile reached provider=%d secret_resolver=%d", providerCalls, secretCalls)
	}
}

func TestWithTeamPlanCompilerRejectsMissingOrUninitializedCompiler(t *testing.T) {
	t.Parallel()
	for label, compiler := range map[string]*teamplan.CatalogCompiler{
		"missing":       nil,
		"uninitialized": {},
	} {
		t.Run(label, func(t *testing.T) {
			var options runtimeCompositionOptions
			if err := WithTeamPlanCompiler(compiler)(&options); err == nil ||
				options.teamPlans != nil {
				t.Fatalf("WithTeamPlanCompiler(%s) options=%#v error=%v", label, options, err)
			}
		})
	}
}

func TestWithTeamPolicyResolverRejectsMissingResolver(t *testing.T) {
	t.Parallel()
	var options runtimeCompositionOptions
	if err := WithTeamPolicyResolver(nil)(&options); err == nil ||
		options.teamPolicies != nil {
		t.Fatalf(
			"WithTeamPolicyResolver(nil) options=%#v error=%v",
			options,
			err,
		)
	}
	resolver, err := teamorchestration.NewStaticPolicyResolver(
		teamplan.Policy{
			MaxWorkers:                1,
			MaxConcurrentWorkers:      1,
			MaxRoleDuration:           time.Minute,
			MaxVCPUPerWorker:          2,
			MaxMemoryMiBPerWorker:     2048,
			MaxDiskGiBPerWorker:       20,
			MaxPlanCostMicros:         1_000_000,
			SafetyMarginBasisPoints:   2000,
			FixedWorkerOverheadMicros: 10_000,
			AllowedRuntimeFamilies: []teamplan.RuntimeFamily{
				teamplan.RuntimeCodex,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := WithTeamPolicyResolver(resolver)(&options); err != nil ||
		options.teamPolicies != resolver {
		t.Fatalf(
			"WithTeamPolicyResolver() options=%#v error=%v",
			options,
			err,
		)
	}
}

func TestWithTeamOfferBuilderAndLoadedProfilesRejectMissingDependencies(
	t *testing.T,
) {
	t.Parallel()
	var options runtimeCompositionOptions
	if err := WithTeamOfferBuilder(nil)(&options); err == nil ||
		options.teamOffers != nil {
		t.Fatalf(
			"WithTeamOfferBuilder(nil) options=%#v error=%v",
			options,
			err,
		)
	}
	builder := runtimeTeamOfferSourceFixture{}
	if err := WithTeamOfferBuilder(builder)(&options); err != nil ||
		options.teamOffers == nil {
		t.Fatalf(
			"WithTeamOfferBuilder() options=%#v error=%v",
			options,
			err,
		)
	}
	if err := WithLoadedModelProfiles(nil)(&options); err == nil ||
		options.modelProfiles != nil {
		t.Fatalf(
			"WithLoadedModelProfiles(nil) options=%#v error=%v",
			options,
			err,
		)
	}
	profiles, err := modelapi.NewProfileCatalog([]modelapi.Profile{{
		ProfileID:       "deepseek-v4",
		Provider:        modelapi.ProviderDeepSeek,
		Model:           "deepseekv4-pro",
		BaseURL:         "https://api.deepseek.example/v1",
		SecretRef:       "mounted:deepseek-token",
		ContextWindow:   65_536,
		MaxOutputTokens: 8_192,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := WithLoadedModelProfiles(profiles)(&options); err != nil ||
		options.modelProfiles != profiles {
		t.Fatalf(
			"WithLoadedModelProfiles() options=%#v error=%v",
			options,
			err,
		)
	}
	if err := WithLoadedSearchProfiles(nil)(&options); err == nil ||
		options.searchProfiles != nil {
		t.Fatalf(
			"WithLoadedSearchProfiles(nil) options=%#v error=%v",
			options,
			err,
		)
	}
	searchProfiles, err := searchprofile.NewCatalog([]searchprofile.Profile{{
		ProfileID: "tavily-default", Provider: searchprofile.ProviderTavily,
		BaseURL:   "https://api.tavily.com/search",
		SecretRef: "mounted:tavily-token", MaxResults: 10,
		TimeoutSeconds: 15,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := WithLoadedSearchProfiles(searchProfiles)(&options); err != nil ||
		options.searchProfiles != searchProfiles {
		t.Fatalf(
			"WithLoadedSearchProfiles() options=%#v error=%v",
			options,
			err,
		)
	}
}

func TestWithTeamLaunchAuthorizationBuilderRejectsMissingDependency(
	t *testing.T,
) {
	t.Parallel()
	var options runtimeCompositionOptions
	if err := WithTeamLaunchAuthorizationBuilder(nil)(&options); err == nil ||
		options.teamLaunches != nil {
		t.Fatalf(
			"WithTeamLaunchAuthorizationBuilder(nil) options=%#v error=%v",
			options,
			err,
		)
	}
	builder := runtimeTeamLaunchBuilderFixture{}
	if err := WithTeamLaunchAuthorizationBuilder(builder)(&options); err != nil ||
		options.teamLaunches == nil {
		t.Fatalf(
			"WithTeamLaunchAuthorizationBuilder() options=%#v error=%v",
			options,
			err,
		)
	}
}

type runtimeTeamOfferSourceFixture struct{}

func (runtimeTeamOfferSourceFixture) BuildForConnection(
	context.Context,
	string,
	string,
) (*teamplan.OfferSnapshot, error) {
	return nil, teamorchestration.ErrInvalid
}

func (runtimeTeamOfferSourceFixture) VerifyCurrentOffer(
	context.Context,
	string,
	*teamplan.OfferSnapshot,
) error {
	return nil
}

var _ teamorchestration.TrustedOfferSource = runtimeTeamOfferSourceFixture{}

type runtimeTeamLaunchBuilderFixture struct{}

func (runtimeTeamLaunchBuilderFixture) BuildForPlan(
	context.Context,
	teamplan.Plan,
	string,
	time.Time,
) (teamlaunch.AuthorizationV1, error) {
	return teamlaunch.AuthorizationV1{}, teamorchestration.ErrInvalid
}

var _ teamorchestration.TrustedLaunchAuthorizationBuilder = runtimeTeamLaunchBuilderFixture{}
