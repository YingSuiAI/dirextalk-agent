package rpcapi

import (
	"context"
	"strings"
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestRuntimeServiceCapabilitiesFailClosedWithoutCoordinator(t *testing.T) {
	response, err := NewRuntimeService(nil, RuntimeFeatures{Skills: []string{"cloud-dispatcher"}, Knowledge: true, MCPHTTP: true, CloudWorker: true}).GetCapabilities(context.Background(), nil)
	if err != nil {
		t.Fatalf("GetCapabilities() error = %v", err)
	}
	capabilities := response.GetCapabilities()
	if capabilities.GetChat() || capabilities.GetStreamChat() || capabilities.GetRuntimeConfig() || capabilities.GetKnowledge() || capabilities.GetMcpHttp() {
		t.Fatalf("unavailable runtime advertised executable capabilities: %#v", capabilities)
	}
	if !capabilities.GetCloudWorker() {
		t.Fatal("independently configured Cloud Worker capability was lost")
	}
}

func TestRuntimeServiceFailsClosedWithoutServerModelCatalog(t *testing.T) {
	coordinator := &runtimeCoordinatorStub{}
	service := NewRuntimeService(coordinator)
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
	_, err := service.PutRuntimeConfig(ctx, &agentv1.PutRuntimeConfigRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: "owner-1",
		Spec: &agentv1.RuntimeConfigSpec{ModelProfile: &agentv1.ModelProfile{ProfileId: "any"}},
	})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("PutRuntimeConfig without catalog code = %s", status.Code(err))
	}
	_, err = service.Chat(ctx, &agentv1.ChatRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: "owner-1", ConversationId: "conversation-1", Message: "hello",
	})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("Chat without catalog code = %s", status.Code(err))
	}
	if coordinator.saveCalls != 0 {
		t.Fatal("catalog-less runtime reached coordinator")
	}
}

func TestPutRuntimeConfigMapsAuthenticatedScopeAndOpaqueReferences(t *testing.T) {
	credentialID := uuid.NewString()
	coordinator := &runtimeCoordinatorStub{}
	profiles := runtimeServiceTestProfiles(t)
	service := NewRuntimeService(coordinator, RuntimeFeatures{ModelProfiles: profiles})
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: credentialID})
	temperature := 0.4
	request := &agentv1.PutRuntimeConfigRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: "project-owner", ExpectedRevision: 0,
		Spec: &agentv1.RuntimeConfigSpec{
			ModelProfile:   &agentv1.ModelProfile{ProfileId: "deepseek-v4", Temperature: &temperature, MaxOutputTokens: 4096},
			ProjectProfile: "A general project agent.", ContextMessageLimit: 64, MemoryMessageLimit: 32, MaxSteps: 12,
			EnabledTools: []string{"cloud_dispatcher_research"}, KnowledgeRefs: []string{"knowledge:docs"}, McpServerIds: []string{"official-docs"}, RecipeIds: []string{"recipe-private"},
		},
	}
	response, err := service.PutRuntimeConfig(ctx, request)
	if err != nil {
		t.Fatalf("PutRuntimeConfig() error = %v", err)
	}
	if coordinator.savedScope.ClientID != "message-server" || coordinator.savedScope.CredentialID != credentialID {
		t.Fatalf("mutation scope = %#v", coordinator.savedScope)
	}
	got := coordinator.savedCommand.Config
	if got.ProjectProfile != request.GetSpec().GetProjectProfile() || got.ModelProfile.ProfileID != "deepseek-v4" || got.ModelProfile.SecretRef != "mounted:deepseek-token" || got.KnowledgeRefs[0] != "knowledge:docs" || got.MCPServerIDs[0] != "official-docs" || got.RecipeIDs[0] != "recipe-private" {
		t.Fatalf("mapped runtime config = %#v", got)
	}
	if response.GetConfig().GetRevision() != 1 || response.GetConfig().GetSpec().GetModelProfile().GetTemperature() != temperature || response.GetConfig().GetSpec().GetModelProfile().GetSecretRef() != "" {
		t.Fatalf("response config = %#v", response.GetConfig())
	}
}

func TestPutRuntimeConfigRejectsProfileTamperingBeforeCoordinator(t *testing.T) {
	coordinator := &runtimeCoordinatorStub{}
	service := NewRuntimeService(coordinator, RuntimeFeatures{ModelProfiles: runtimeServiceTestProfiles(t)})
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
	base := &agentv1.PutRuntimeConfigRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: "project-owner",
		Spec: &agentv1.RuntimeConfigSpec{
			ModelProfile:        &agentv1.ModelProfile{ProfileId: "deepseek-v4"},
			ContextMessageLimit: 64, MemoryMessageLimit: 32, MaxSteps: 12,
		},
	}

	base.Spec.ModelProfile.BaseUrl = "https://attacker.example/v1"
	base.Spec.ModelProfile.SecretRef = "mounted:deepseek-token"
	if _, err := service.PutRuntimeConfig(ctx, base); err == nil {
		t.Fatal("malicious endpoint and credential binding unexpectedly succeeded")
	}
	base.Spec.ModelProfile.BaseUrl = ""
	base.Spec.ModelProfile.SecretRef = ""
	base.Spec.ModelProfile.ProfileId = "unknown"
	base.IdempotencyKey = uuid.NewString()
	if _, err := service.PutRuntimeConfig(ctx, base); err == nil {
		t.Fatal("unknown profile unexpectedly succeeded")
	}
	if coordinator.saveCalls != 0 {
		t.Fatalf("coordinator was called %d times before profile validation", coordinator.saveCalls)
	}
}

func TestRuntimeResponsesNeverExposeReasoningToolArgumentsOrToolResults(t *testing.T) {
	const canary = "sk-secret-canary-abcdefghijklmnopqrstuvwxyz"
	requestID := uuid.NewString()
	result := runtimeapi.ChatResult{
		Message:              modelapi.Message{Role: modelapi.RoleAssistant, Content: "safe answer", ReasoningContent: canary},
		ConversationRevision: 2,
		RelatedTaskIDs:       []string{"task-b", "task-a", "task-b"},
		RelatedPlanIDs:       []string{"plan-z", "plan-a"},
		Steps: []runtimeapi.Step{
			{Kind: runtimeapi.StepToolCall, ToolCall: modelapi.ToolCall{ID: "call-1", Function: modelapi.FunctionCall{Name: "lookup", Arguments: `{"token":"` + canary + `"}`}}},
			{Kind: runtimeapi.StepToolResult, ToolResult: runtimeapi.ToolExecution{ToolCallID: "call-1", Name: "lookup", Content: canary, IsError: true}},
		},
	}
	response := runtimeChatResponse(requestID, "conversation-1", result)
	encoded, err := protojson.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), canary) || strings.Contains(string(encoded), "token") {
		t.Fatalf("public chat response exposed private model/tool data: %s", encoded)
	}
	if response.GetSteps()[0].GetToolName() != "lookup" || response.GetSteps()[1].GetIsError() != true {
		t.Fatalf("de-secreted tool summaries were lost: %#v", response.GetSteps())
	}
	if strings.Join(response.GetRelatedTaskIds(), ",") != "task-a,task-b" || strings.Join(response.GetRelatedPlanIds(), ",") != "plan-a,plan-z" {
		t.Fatalf("related entity IDs are not stable: tasks=%v plans=%v", response.GetRelatedTaskIds(), response.GetRelatedPlanIds())
	}

	if event := runtimeStreamResponse(requestID, "conversation-1", runtimeapi.StreamEvent{Kind: runtimeapi.StreamEventDelta, Delta: modelapi.Delta{ReasoningContent: canary}}); event != nil {
		t.Fatalf("reasoning-only stream event must be suppressed: %#v", event)
	}
	toolEvent := runtimeStreamResponse(requestID, "conversation-1", runtimeapi.StreamEvent{Kind: runtimeapi.StreamEventToolCall, ToolCall: result.Steps[0].ToolCall})
	toolEncoded, err := protojson.Marshal(toolEvent)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(toolEncoded), canary) || strings.Contains(string(toolEncoded), "token") {
		t.Fatalf("public stream exposed tool arguments: %s", toolEncoded)
	}
	progress := runtimeStreamResponse(requestID, "conversation-1", runtimeapi.StreamEvent{
		Kind: runtimeapi.StreamEventToolResult,
		ToolResult: runtimeapi.ToolExecution{
			ToolCallID: "call-1", Name: "lookup", RelatedTaskIDs: []string{"task-a"}, RelatedPlanIDs: []string{"plan-a"},
		},
	})
	progressEncoded, err := protojson.Marshal(progress)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(progressEncoded), "task-a") || strings.Contains(string(progressEncoded), "plan-a") {
		t.Fatalf("stream progress exposed related entity IDs before Done: %s", progressEncoded)
	}
	done := runtimeStreamResponse(requestID, "conversation-1", runtimeapi.StreamEvent{Kind: runtimeapi.StreamEventDone, Result: &result})
	if done.GetDone() == nil || strings.Join(done.GetDone().GetResponse().GetRelatedTaskIds(), ",") != "task-a,task-b" || strings.Join(done.GetDone().GetResponse().GetRelatedPlanIds(), ",") != "plan-a,plan-z" {
		t.Fatalf("stream Done lost stable related IDs: %#v", done)
	}
}

type runtimeCoordinatorStub struct {
	savedScope   runtimeapi.MutationScope
	savedCommand runtimeapi.SaveRuntimeConfigCommand
	saveCalls    int
}

func (*runtimeCoordinatorStub) LoadRuntimeConfig(context.Context, string) (runtimeapi.RuntimeConfig, error) {
	return runtimeapi.RuntimeConfig{}, runtimeapi.ErrRuntimeConfigNotFound
}

func (stub *runtimeCoordinatorStub) SaveRuntimeConfig(_ context.Context, scope runtimeapi.MutationScope, command runtimeapi.SaveRuntimeConfigCommand) (runtimeapi.RuntimeConfig, error) {
	stub.saveCalls++
	stub.savedScope = scope
	stub.savedCommand = command
	command.Config.Revision = 1
	return command.Config, nil
}

func runtimeServiceTestProfiles(t *testing.T) *modelapi.ProfileCatalog {
	t.Helper()
	catalog, err := modelapi.NewProfileCatalog([]modelapi.Profile{{
		ProfileID: "deepseek-v4", Provider: modelapi.ProviderDeepSeek, Model: "deepseekv4-pro",
		BaseURL: "https://api.deepseek.example/v1", SecretRef: "mounted:deepseek-token",
		ContextWindow: 65536, MaxOutputTokens: 8192,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func (*runtimeCoordinatorStub) Chat(context.Context, runtimeapi.MutationScope, runtimeapi.ChatRequest) (runtimeapi.ChatResult, error) {
	return runtimeapi.ChatResult{}, nil
}

func (*runtimeCoordinatorStub) Stream(context.Context, runtimeapi.MutationScope, runtimeapi.ChatRequest, runtimeapi.StreamEmitter) error {
	return nil
}
