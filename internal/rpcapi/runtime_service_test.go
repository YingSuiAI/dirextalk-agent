package rpcapi

import (
	"context"
	"strings"
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/runtimeapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/searchprofile"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
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

func TestRuntimeServiceSynthesizesVerifiedTeamCompletion(t *testing.T) {
	t.Parallel()
	sourceEventID := uuid.NewString()
	coordinator := &runtimeCoordinatorStub{
		completionResult: runtimeapp.TeamCompletionResult{
			SourceEventID:  sourceEventID,
			ConversationID: "conversation-1",
			RequestID:      uuid.NewString(),
			Chat: runtimeapi.ChatResult{
				Message: modelapi.Message{
					Role:    modelapi.RoleAssistant,
					Content: "Team execution finished; final.json is available.",
				},
				ConversationRevision: 8,
			},
		},
	}
	service := NewRuntimeService(
		coordinator,
		RuntimeFeatures{ModelProfiles: runtimeServiceTestProfiles(t)},
	)
	credentialID := uuid.NewString()
	ctx := auth.ContextWithPrincipal(
		context.Background(),
		auth.Principal{
			ClientID:     "message-server",
			CredentialID: credentialID,
		},
	)
	response, err := service.SynthesizeTeamCompletion(
		ctx,
		&agentv1.SynthesizeTeamCompletionRequest{
			OwnerId:       "owner-1",
			SourceEventId: sourceEventID,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if coordinator.completionOwnerID != "owner-1" ||
		coordinator.completionSourceEventID != sourceEventID ||
		coordinator.completionScope.ClientID != "message-server" ||
		coordinator.completionScope.CredentialID != credentialID ||
		response.GetSourceEventId() != sourceEventID ||
		response.GetConversationId() != "conversation-1" ||
		response.GetConversationRevision() != 8 ||
		response.GetMessage().GetMessageId() == "" ||
		response.GetMessage().GetContent() !=
			"Team execution finished; final.json is available." {
		t.Fatalf("completion response = %#v", response)
	}
}

func TestRuntimeServiceReadsAuthoritativeConversationRevision(t *testing.T) {
	t.Parallel()
	coordinator := &runtimeCoordinatorStub{
		conversation: runtimeapi.Conversation{
			OwnerID:        "owner-1",
			ConversationID: "conversation-1",
			Revision:       11,
		},
		conversationFound: true,
	}
	service := NewRuntimeService(coordinator)
	response, err := service.GetConversationState(
		context.Background(),
		&agentv1.GetConversationStateRequest{
			OwnerId:        "owner-1",
			ConversationId: "conversation-1",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !response.GetFound() || response.GetConversationRevision() != 11 ||
		coordinator.conversationOwnerID != "owner-1" ||
		coordinator.conversationID != "conversation-1" {
		t.Fatalf("conversation state response = %#v", response)
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

func TestRuntimeServiceSearchProfileIsCatalogBoundAndSecretFree(t *testing.T) {
	coordinator := &runtimeCoordinatorStub{}
	searchProfiles := runtimeServiceTestSearchProfiles(t)
	service := NewRuntimeService(coordinator, RuntimeFeatures{
		ModelProfiles:  runtimeServiceTestProfiles(t),
		SearchProfiles: searchProfiles,
	})
	capabilities, err := service.GetCapabilities(context.Background(), nil)
	if err != nil || strings.Join(capabilities.GetCapabilities().GetSearchProfileIds(), ",") != "brave-default" {
		t.Fatalf("GetCapabilities() = %#v, %v", capabilities, err)
	}
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
	request := &agentv1.PutRuntimeConfigRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: "project-owner",
		Spec: &agentv1.RuntimeConfigSpec{
			ModelProfile:        &agentv1.ModelProfile{ProfileId: "deepseek-v4"},
			ContextMessageLimit: 64, MemoryMessageLimit: 32, MaxSteps: 12,
			SearchProfile: &agentv1.SearchProfile{
				ProfileId: "brave-default", MaxResults: 6, TimeoutSeconds: 10,
			},
		},
	}
	response, err := service.PutRuntimeConfig(ctx, request)
	if err != nil {
		t.Fatalf("PutRuntimeConfig() error = %v", err)
	}
	saved := coordinator.savedCommand.Config.SearchProfile
	returned := response.GetConfig().GetSpec().GetSearchProfile()
	if saved == nil || saved.SecretRef != "mounted:brave-search-token" || saved.MaxResults != 6 || saved.TimeoutSeconds != 10 {
		t.Fatalf("saved search profile = %#v", saved)
	}
	if !containsString(coordinator.savedCommand.Config.EnabledTools, runtimeapi.SearchToolName) ||
		!containsString(response.GetConfig().GetSpec().GetEnabledTools(), runtimeapi.SearchToolName) {
		t.Fatalf("search tool was not persisted with the selected profile: %#v", coordinator.savedCommand.Config.EnabledTools)
	}
	if returned == nil || returned.GetProfileId() != "brave-default" || returned.GetProvider() != agentv1.SearchProvider_SEARCH_PROVIDER_BRAVE || returned.GetSecretRef() != "" {
		t.Fatalf("public search profile = %#v", returned)
	}

	request.IdempotencyKey = uuid.NewString()
	request.Spec.SearchProfile.BaseUrl = "https://attacker.invalid/search"
	if _, err := service.PutRuntimeConfig(ctx, request); status.Code(err) != codes.InvalidArgument || coordinator.saveCalls != 1 {
		t.Fatalf("tampered search profile crossed coordinator: calls=%d err=%v", coordinator.saveCalls, err)
	}
}

func TestDeepSeekNativeSearchProviderProtoMappingIsStable(t *testing.T) {
	t.Parallel()
	provider, ok := searchProviderFromProto(agentv1.SearchProvider_SEARCH_PROVIDER_DEEPSEEK_NATIVE)
	if !ok || provider != searchprofile.ProviderDeepSeekNative ||
		searchProviderToProto(provider) != agentv1.SearchProvider_SEARCH_PROVIDER_DEEPSEEK_NATIVE {
		t.Fatalf("DeepSeek native provider mapping = %q, %v", provider, ok)
	}
}

func TestRuntimeServiceAutomaticallyAttachesCatalogBoundNativeSearch(t *testing.T) {
	t.Parallel()
	coordinator := &runtimeCoordinatorStub{}
	searchProfiles, err := searchprofile.NewCatalogWithAutoBindings([]searchprofile.Profile{{
		ProfileID: "deepseek-native-default", Provider: searchprofile.ProviderDeepSeekNative,
		BaseURL:   "https://api.deepseek.com/anthropic/v1/messages",
		SecretRef: "mounted:deepseek-token", MaxResults: 8, TimeoutSeconds: 45,
	}}, map[string][]string{
		"deepseek-native-default": {"deepseek-v4"},
	})
	if err != nil {
		t.Fatal(err)
	}
	service := NewRuntimeService(coordinator, RuntimeFeatures{
		ModelProfiles: runtimeServiceTestProfiles(t), SearchProfiles: searchProfiles,
	})
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{
		ClientID: "message-server", CredentialID: uuid.NewString(),
	})
	response, err := service.PutRuntimeConfig(ctx, &agentv1.PutRuntimeConfigRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: "project-owner",
		Spec: &agentv1.RuntimeConfigSpec{
			ModelProfile:        &agentv1.ModelProfile{ProfileId: "deepseek-v4"},
			ContextMessageLimit: 64, MemoryMessageLimit: 32, MaxSteps: 12,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	saved := coordinator.savedCommand.Config.SearchProfile
	public := response.GetConfig().GetSpec().GetSearchProfile()
	if saved == nil || saved.ProfileID != "deepseek-native-default" ||
		saved.SecretRef != "mounted:deepseek-token" ||
		public == nil || public.GetProfileId() != saved.ProfileID || public.GetSecretRef() != "" ||
		!containsString(response.GetConfig().GetSpec().GetEnabledTools(), runtimeapi.SearchToolName) {
		t.Fatalf("automatic native search = saved=%#v public=%#v", saved, public)
	}
}

func TestRuntimeServiceRejectsNativeSearchCredentialAudienceMismatch(t *testing.T) {
	t.Parallel()
	coordinator := &runtimeCoordinatorStub{}
	searchProfiles, err := searchprofile.NewCatalogWithAutoBindings([]searchprofile.Profile{{
		ProfileID: "deepseek-native-default", Provider: searchprofile.ProviderDeepSeekNative,
		BaseURL:   "https://api.deepseek.com/anthropic/v1/messages",
		SecretRef: "mounted:other-token", MaxResults: 8, TimeoutSeconds: 45,
	}}, map[string][]string{
		"deepseek-native-default": {"deepseek-v4"},
	})
	if err != nil {
		t.Fatal(err)
	}
	service := NewRuntimeService(coordinator, RuntimeFeatures{
		ModelProfiles: runtimeServiceTestProfiles(t), SearchProfiles: searchProfiles,
	})
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{
		ClientID: "message-server", CredentialID: uuid.NewString(),
	})
	_, err = service.PutRuntimeConfig(ctx, &agentv1.PutRuntimeConfigRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: "project-owner",
		Spec: &agentv1.RuntimeConfigSpec{
			ModelProfile:        &agentv1.ModelProfile{ProfileId: "deepseek-v4"},
			ContextMessageLimit: 64, MemoryMessageLimit: 32, MaxSteps: 12,
		},
	})
	if status.Code(err) != codes.FailedPrecondition || coordinator.saveCalls != 0 {
		t.Fatalf("credential audience mismatch calls=%d error=%v", coordinator.saveCalls, err)
	}
}

func TestRuntimeServiceCloudDialogueResolvesOwnedCanonicalConnection(t *testing.T) {
	connectionID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	coordinator := &runtimeCoordinatorStub{}
	reader := &cloudDialogueConnectionReaderStub{connection: cloudstatus.Connection{ConnectionID: connectionID, OwnerID: "owner-a", Status: "active"}}
	service := NewRuntimeServiceWithCloudDialogue(coordinator, RuntimeFeatures{ModelProfiles: runtimeServiceTestProfiles(t)}, reader)
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
	request := &agentv1.ChatRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: "owner-a", ConversationId: "conversation-a", Message: "Research an official service.",
		CloudDialogueScope: &agentv1.CloudDialogueScopeV1{CloudConnectionId: connectionID},
	}
	if _, err := service.Chat(ctx, request); err != nil {
		t.Fatalf("Chat() error = %v", err)
	}
	if reader.calls != 1 || reader.ownerID != "owner-a" || reader.connectionID != connectionID {
		t.Fatalf("connection ownership read = %#v", reader)
	}
	if coordinator.chatCalls != 1 || coordinator.chatRequest.CloudDialogue == nil || coordinator.chatRequest.CloudDialogue.ConnectionID != connectionID {
		t.Fatalf("trusted cloud dialogue scope was not forwarded: %#v", coordinator.chatRequest)
	}

	normal := &agentv1.ChatRequest{IdempotencyKey: uuid.NewString(), OwnerId: "owner-a", ConversationId: "conversation-b", Message: "hello"}
	serviceWithoutResolver := NewRuntimeService(coordinator, RuntimeFeatures{ModelProfiles: runtimeServiceTestProfiles(t)})
	if _, err := serviceWithoutResolver.Chat(ctx, normal); err != nil || coordinator.chatRequest.CloudDialogue != nil {
		t.Fatalf("ordinary Chat compatibility changed: request=%#v err=%v", coordinator.chatRequest, err)
	}
}

func TestRuntimeServiceCloudDialogueFailsClosedBeforeCoordinator(t *testing.T) {
	connectionID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
	base := &agentv1.ChatRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: "owner-a", ConversationId: "conversation-a", Message: "Research an official service.",
		CloudDialogueScope: &agentv1.CloudDialogueScopeV1{CloudConnectionId: connectionID},
	}
	tests := []struct {
		name       string
		request    *agentv1.ChatRequest
		reader     CloudDialogueConnectionReader
		wantStatus codes.Code
	}{
		{name: "missing connection", request: func() *agentv1.ChatRequest {
			value := proto.Clone(base).(*agentv1.ChatRequest)
			value.CloudDialogueScope = &agentv1.CloudDialogueScopeV1{}
			return value
		}(), reader: &cloudDialogueConnectionReaderStub{}, wantStatus: codes.InvalidArgument},
		{name: "non canonical connection", request: func() *agentv1.ChatRequest {
			value := proto.Clone(base).(*agentv1.ChatRequest)
			value.CloudDialogueScope = &agentv1.CloudDialogueScopeV1{CloudConnectionId: strings.ToUpper(connectionID)}
			return value
		}(), reader: &cloudDialogueConnectionReaderStub{}, wantStatus: codes.InvalidArgument},
		{name: "resolver unavailable", request: base, wantStatus: codes.FailedPrecondition},
		{name: "foreign connection", request: base, reader: &cloudDialogueConnectionReaderStub{err: cloudstatus.ErrNotFound}, wantStatus: codes.NotFound},
		{name: "invalid read back", request: base, reader: &cloudDialogueConnectionReaderStub{connection: cloudstatus.Connection{ConnectionID: connectionID, OwnerID: "owner-b"}}, wantStatus: codes.Internal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator := &runtimeCoordinatorStub{}
			service := NewRuntimeServiceWithCloudDialogue(coordinator, RuntimeFeatures{ModelProfiles: runtimeServiceTestProfiles(t)}, test.reader)
			_, err := service.Chat(ctx, test.request)
			if status.Code(err) != test.wantStatus || coordinator.chatCalls != 0 {
				t.Fatalf("Chat code=%s calls=%d err=%v", status.Code(err), coordinator.chatCalls, err)
			}
		})
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

func TestRuntimeCapacityExhaustionIsRetryableAndRedacted(t *testing.T) {
	err := publicRuntimeError(runtimeapp.ErrCapacityExhausted)
	if status.Code(err) != codes.ResourceExhausted || strings.Contains(err.Error(), "memory") || strings.Contains(err.Error(), "limit") {
		t.Fatalf("capacity error=%v code=%s", err, status.Code(err))
	}
}

func TestRuntimeProviderFailuresUseStablePublicCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		code codes.Code
	}{
		{name: "credential", err: modelapi.ErrProviderCredential, code: codes.PermissionDenied},
		{name: "request", err: modelapi.ErrProviderRequest, code: codes.FailedPrecondition},
		{name: "rate limited", err: modelapi.ErrProviderRateLimited, code: codes.ResourceExhausted},
		{name: "unavailable", err: modelapi.ErrProviderUnavailable, code: codes.Unavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := publicRuntimeError(test.err)
			if status.Code(got) != test.code {
				t.Fatalf("publicRuntimeError(%v) code = %s, want %s", test.err, status.Code(got), test.code)
			}
		})
	}
}

func TestRuntimeServiceListModelsMapsTransientBindingAndSanitizedResponse(t *testing.T) {
	credentialID := uuid.NewString()
	coordinator := &runtimeCoordinatorStub{listedModels: []modelapi.Descriptor{{
		ID: "gpt-test", Name: "GPT Test", Provider: "openai_compatible",
		ContextWindow: 128000, MaxOutputTokens: 8192, ReasoningModes: []string{"low", "high"},
	}}}
	service := NewRuntimeService(coordinator)
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: credentialID})
	requestID := uuid.NewString()
	response, err := service.ListModels(ctx, &agentv1.ListModelsRequest{
		RequestId: requestID, OwnerId: "owner-1",
		TransientModel: &agentv1.TransientModelInvocation{
			Profile: &agentv1.ModelProfile{
				ProfileId: "model-discovery", Provider: agentv1.ModelProvider_MODEL_PROVIDER_OPENAI_COMPATIBLE,
				Model: "model-discovery", BaseUrl: "https://api.openai.com/v1",
				ContextWindow: 65536, MaxOutputTokens: 4096,
			},
			CredentialSessionId: uuid.NewString(), CredentialSessionRevision: 2,
			CredentialSha256: make([]byte, 32),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if coordinator.listRequest.RequestID != requestID || coordinator.listRequest.OwnerID != "owner-1" ||
		coordinator.listRequest.BootstrapClientID != "message-server" || coordinator.listScope.CredentialID != credentialID {
		t.Fatalf("list request=%#v scope=%#v", coordinator.listRequest, coordinator.listScope)
	}
	models := response.GetModels()
	if len(models) != 1 || models[0].GetId() != "gpt-test" || models[0].GetContextWindow() != 128000 ||
		strings.Join(models[0].GetReasoningModes(), ",") != "low,high" {
		t.Fatalf("models = %#v", models)
	}
}

type runtimeCoordinatorStub struct {
	savedScope              runtimeapi.MutationScope
	savedCommand            runtimeapi.SaveRuntimeConfigCommand
	saveCalls               int
	chatRequest             runtimeapi.ChatRequest
	chatCalls               int
	listRequest             runtimeapi.ModelListRequest
	listScope               runtimeapi.MutationScope
	listedModels            []modelapi.Descriptor
	completionResult        runtimeapp.TeamCompletionResult
	completionScope         runtimeapi.MutationScope
	completionOwnerID       string
	completionSourceEventID string
	conversation            runtimeapi.Conversation
	conversationFound       bool
	conversationOwnerID     string
	conversationID          string
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

func runtimeServiceTestSearchProfiles(t *testing.T) *searchprofile.Catalog {
	t.Helper()
	catalog, err := searchprofile.NewCatalog([]searchprofile.Profile{{
		ProfileID: "brave-default", Provider: searchprofile.ProviderBrave,
		BaseURL:   "https://api.search.brave.com/res/v1/web/search",
		SecretRef: "mounted:brave-search-token", MaxResults: 10, TimeoutSeconds: 20,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func (stub *runtimeCoordinatorStub) Chat(_ context.Context, _ runtimeapi.MutationScope, request runtimeapi.ChatRequest) (runtimeapi.ChatResult, error) {
	stub.chatCalls++
	stub.chatRequest = request
	return runtimeapi.ChatResult{}, nil
}

func (stub *runtimeCoordinatorStub) ListModels(_ context.Context, scope runtimeapi.MutationScope, request runtimeapi.ModelListRequest) ([]modelapi.Descriptor, error) {
	stub.listScope = scope
	stub.listRequest = request
	return append([]modelapi.Descriptor(nil), stub.listedModels...), nil
}

func (*runtimeCoordinatorStub) Stream(context.Context, runtimeapi.MutationScope, runtimeapi.ChatRequest, runtimeapi.StreamEmitter) error {
	return nil
}

func (stub *runtimeCoordinatorStub) SynthesizeTeamCompletion(
	_ context.Context,
	scope runtimeapi.MutationScope,
	ownerID string,
	sourceEventID string,
) (runtimeapp.TeamCompletionResult, error) {
	stub.completionScope = scope
	stub.completionOwnerID = ownerID
	stub.completionSourceEventID = sourceEventID
	return stub.completionResult, nil
}

func (stub *runtimeCoordinatorStub) ConversationState(
	_ context.Context,
	ownerID string,
	conversationID string,
) (runtimeapi.Conversation, bool, error) {
	stub.conversationOwnerID = ownerID
	stub.conversationID = conversationID
	return stub.conversation, stub.conversationFound, nil
}

type cloudDialogueConnectionReaderStub struct {
	connection   cloudstatus.Connection
	err          error
	ownerID      string
	connectionID string
	calls        int
}

func (stub *cloudDialogueConnectionReaderStub) GetConnection(_ context.Context, ownerID, connectionID string) (cloudstatus.Connection, error) {
	stub.calls++
	stub.ownerID = ownerID
	stub.connectionID = connectionID
	if stub.err != nil {
		return cloudstatus.Connection{}, stub.err
	}
	return stub.connection, nil
}
