package rpcapi

import (
	"context"
	"errors"
	"sort"
	"strings"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/runtimeapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/searchprofile"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type RuntimeFeatures struct {
	Skills      []string
	Knowledge   bool
	MCPHTTP     bool
	CloudWorker bool
	// ModelProfiles is trusted server configuration, not a caller capability.
	// A runtime without it fails closed for config mutation and chat.
	ModelProfiles *modelapi.ProfileCatalog
	// SearchProfiles is optional trusted configuration. An absent catalog keeps
	// search configuration unavailable without disabling the core runtime.
	SearchProfiles *searchprofile.Catalog
}

type RuntimeCoordinator interface {
	LoadRuntimeConfig(context.Context, string) (runtimeapi.RuntimeConfig, error)
	SaveRuntimeConfig(context.Context, runtimeapi.MutationScope, runtimeapi.SaveRuntimeConfigCommand) (runtimeapi.RuntimeConfig, error)
	Chat(context.Context, runtimeapi.MutationScope, runtimeapi.ChatRequest) (runtimeapi.ChatResult, error)
	Stream(context.Context, runtimeapi.MutationScope, runtimeapi.ChatRequest, runtimeapi.StreamEmitter) error
}

type runtimeModelDiscoverer interface {
	ListModels(context.Context, runtimeapi.MutationScope, runtimeapi.ModelListRequest) ([]modelapi.Descriptor, error)
}

type RuntimeService struct {
	agentv1.UnimplementedRuntimeServiceServer
	coordinator              RuntimeCoordinator
	features                 RuntimeFeatures
	cloudDialogueConnections CloudDialogueConnectionReader
}

// CloudDialogueConnectionReader is the smallest read-only ownership seam
// required by RuntimeService. It does not copy cloud facts into runtime state.
type CloudDialogueConnectionReader interface {
	GetConnection(context.Context, string, string) (cloudstatus.Connection, error)
}

func NewRuntimeService(coordinator RuntimeCoordinator, features ...RuntimeFeatures) *RuntimeService {
	service := &RuntimeService{coordinator: coordinator}
	if len(features) > 0 {
		service.features = features[0]
		service.features.Skills = append([]string(nil), features[0].Skills...)
	}
	return service
}

func NewRuntimeServiceWithCloudDialogue(coordinator RuntimeCoordinator, features RuntimeFeatures, connections CloudDialogueConnectionReader) *RuntimeService {
	service := NewRuntimeService(coordinator, features)
	service.cloudDialogueConnections = connections
	return service
}

func (service *RuntimeService) GetCapabilities(context.Context, *agentv1.RuntimeServiceGetCapabilitiesRequest) (*agentv1.RuntimeServiceGetCapabilitiesResponse, error) {
	available := service != nil && service.coordinator != nil && service.features.ModelProfiles != nil
	capabilities := &agentv1.RuntimeCapabilities{
		Chat: available, StreamChat: available, RuntimeConfig: available,
		CloudWorker: service != nil && service.features.CloudWorker,
		Knowledge:   available && service.features.Knowledge,
		McpHttp:     available && service.features.MCPHTTP,
	}
	if available {
		capabilities.Skills = append([]string(nil), service.features.Skills...)
		capabilities.ModelProfileIds = service.features.ModelProfiles.IDs()
		if service.features.SearchProfiles != nil {
			capabilities.SearchProfileIds = service.features.SearchProfiles.IDs()
		}
	}
	return &agentv1.RuntimeServiceGetCapabilitiesResponse{Capabilities: capabilities}, nil
}

func (service *RuntimeService) GetRuntimeConfig(ctx context.Context, request *agentv1.GetRuntimeConfigRequest) (*agentv1.GetRuntimeConfigResponse, error) {
	if service == nil || service.coordinator == nil || service.features.ModelProfiles == nil {
		return nil, status.Error(codes.Unimplemented, "runtime configuration is unavailable")
	}
	config, err := service.coordinator.LoadRuntimeConfig(ctx, request.GetOwnerId())
	if err != nil {
		return nil, publicRuntimeError(err)
	}
	canonical, err := service.features.ModelProfiles.ResolvePersisted(config.ModelProfile)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "stored model profile is not available")
	}
	config.ModelProfile = canonical
	if config.SearchProfile != nil {
		if service.features.SearchProfiles == nil {
			return nil, status.Error(codes.FailedPrecondition, "stored search profile is not available")
		}
		search, resolveErr := service.features.SearchProfiles.ResolvePersisted(*config.SearchProfile)
		if resolveErr != nil {
			return nil, status.Error(codes.FailedPrecondition, "stored search profile is not available")
		}
		if !service.features.SearchProfiles.AllowsModelProfile(search.ProfileID, canonical.ProfileID) ||
			!searchProfileMatchesModel(search, canonical) {
			return nil, status.Error(codes.FailedPrecondition, "stored search profile is not compatible with model profile")
		}
		config.SearchProfile = &search
	}
	return &agentv1.GetRuntimeConfigResponse{Config: runtimeConfigToProto(request.GetOwnerId(), config)}, nil
}

func (service *RuntimeService) PutRuntimeConfig(ctx context.Context, request *agentv1.PutRuntimeConfigRequest) (*agentv1.PutRuntimeConfigResponse, error) {
	if service == nil || service.coordinator == nil || service.features.ModelProfiles == nil {
		return nil, status.Error(codes.Unimplemented, "runtime configuration is unavailable")
	}
	scope, err := runtimeMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	config, err := runtimeConfigFromProto(
		request.GetSpec(), request.GetExpectedRevision(),
		service.features.ModelProfiles, service.features.SearchProfiles,
	)
	if err != nil {
		return nil, err
	}
	saved, err := service.coordinator.SaveRuntimeConfig(ctx, scope, runtimeapi.SaveRuntimeConfigCommand{
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(),
		ExpectedRevision: request.GetExpectedRevision(), Config: config,
	})
	if err != nil {
		return nil, publicRuntimeError(err)
	}
	return &agentv1.PutRuntimeConfigResponse{Config: runtimeConfigToProto(request.GetOwnerId(), saved)}, nil
}

func (service *RuntimeService) ListModels(ctx context.Context, request *agentv1.ListModelsRequest) (*agentv1.ListModelsResponse, error) {
	if service == nil || service.coordinator == nil {
		return nil, status.Error(codes.Unimplemented, "model discovery is unavailable")
	}
	discoverer, ok := service.coordinator.(runtimeModelDiscoverer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "model discovery is unavailable")
	}
	scope, err := runtimeMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	transient, err := transientModelFromProto(request.GetTransientModel())
	if err != nil || transient == nil {
		return nil, status.Error(codes.InvalidArgument, "transient model invocation is required")
	}
	models, err := discoverer.ListModels(ctx, scope, runtimeapi.ModelListRequest{
		RequestID: request.GetRequestId(), OwnerID: request.GetOwnerId(),
		BootstrapClientID: scope.ClientID, TransientModel: transient,
	})
	if err != nil {
		return nil, publicRuntimeError(err)
	}
	response := &agentv1.ListModelsResponse{Models: make([]*agentv1.ModelDescriptor, 0, len(models))}
	for _, model := range models {
		response.Models = append(response.Models, &agentv1.ModelDescriptor{
			Id: model.ID, Name: model.Name, Provider: model.Provider,
			ContextWindow: model.ContextWindow, MaxOutputTokens: model.MaxOutputTokens,
			ReasoningModes: append([]string(nil), model.ReasoningModes...),
		})
	}
	return response, nil
}

func (service *RuntimeService) Chat(ctx context.Context, request *agentv1.ChatRequest) (*agentv1.ChatResponse, error) {
	if service == nil || service.coordinator == nil || service.features.ModelProfiles == nil {
		return nil, status.Error(codes.Unimplemented, "chat runtime is unavailable")
	}
	scope, err := runtimeMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	cloudDialogue, err := service.resolveCloudDialogueScope(ctx, request.GetOwnerId(), request.GetCloudDialogueScope())
	if err != nil {
		return nil, err
	}
	command := chatCommand(request.GetIdempotencyKey(), request.GetOwnerId(), request.GetConversationId(), request.GetMessage(), request.GetMemoryDisabled(), request.GetExpectedConversationRevision(), cloudDialogue)
	command.TransientModel, err = transientModelFromProto(request.GetTransientModel())
	if err != nil {
		return nil, err
	}
	if command.TransientModel != nil {
		command.BootstrapClientID = scope.ClientID
	}
	result, err := service.coordinator.Chat(ctx, scope, command)
	if err != nil {
		return nil, publicRuntimeError(err)
	}
	return runtimeChatResponse(request.GetIdempotencyKey(), request.GetConversationId(), result), nil
}

func (service *RuntimeService) StreamChat(request *agentv1.StreamChatRequest, stream agentv1.RuntimeService_StreamChatServer) error {
	if service == nil || service.coordinator == nil || service.features.ModelProfiles == nil {
		return status.Error(codes.Unimplemented, "chat runtime is unavailable")
	}
	scope, err := runtimeMutationScope(stream.Context())
	if err != nil {
		return err
	}
	cloudDialogue, err := service.resolveCloudDialogueScope(stream.Context(), request.GetOwnerId(), request.GetCloudDialogueScope())
	if err != nil {
		return err
	}
	command := chatCommand(request.GetIdempotencyKey(), request.GetOwnerId(), request.GetConversationId(), request.GetMessage(), request.GetMemoryDisabled(), request.GetExpectedConversationRevision(), cloudDialogue)
	command.TransientModel, err = transientModelFromProto(request.GetTransientModel())
	if err != nil {
		return err
	}
	if command.TransientModel != nil {
		command.BootstrapClientID = scope.ClientID
	}
	err = service.coordinator.Stream(stream.Context(), scope, command, func(event runtimeapi.StreamEvent) error {
		response := runtimeStreamResponse(request.GetIdempotencyKey(), request.GetConversationId(), event)
		if response == nil {
			return nil
		}
		return stream.Send(response)
	})
	if err != nil {
		return publicRuntimeError(err)
	}
	return nil
}

func transientModelFromProto(invocation *agentv1.TransientModelInvocation) (*runtimeapi.TransientModelInvocation, error) {
	if invocation == nil {
		return nil, nil
	}
	profile := invocation.GetProfile()
	provider, ok := modelProviderFromProto(profile.GetProvider())
	if profile == nil || !ok || strings.TrimSpace(profile.GetSecretRef()) != "" ||
		len(invocation.GetCredentialSha256()) != 32 || invocation.GetCredentialSessionRevision() != 2 {
		return nil, status.Error(codes.InvalidArgument, "transient model invocation is invalid")
	}
	result := &runtimeapi.TransientModelInvocation{
		Profile: modelapi.Profile{
			ProfileID: profile.GetProfileId(), Provider: provider, Model: profile.GetModel(),
			BaseURL: profile.GetBaseUrl(), MaxOutputTokens: int(profile.GetMaxOutputTokens()),
			ContextWindow: int(profile.GetContextWindow()), ReasoningEffort: profile.GetReasoningEffort(),
		},
		CredentialSessionID:       invocation.GetCredentialSessionId(),
		CredentialSessionRevision: uint64(invocation.GetCredentialSessionRevision()),
	}
	copy(result.CredentialSHA256[:], invocation.GetCredentialSha256())
	if profile.Temperature != nil {
		value := profile.GetTemperature()
		result.Profile.Temperature = &value
	}
	if profile.TopP != nil {
		value := profile.GetTopP()
		result.Profile.TopP = &value
	}
	return result, nil
}

func runtimeMutationScope(ctx context.Context) (runtimeapi.MutationScope, error) {
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok {
		return runtimeapi.MutationScope{}, status.Error(codes.Unauthenticated, "authenticated caller is required")
	}
	scope := runtimeapi.MutationScope{ClientID: principal.ClientID, CredentialID: principal.CredentialID}
	if err := scope.Validate(); err != nil {
		return runtimeapi.MutationScope{}, status.Error(codes.Unauthenticated, "authenticated caller identity is invalid")
	}
	return scope, nil
}

func chatCommand(requestID, ownerID, conversationID, message string, memoryDisabled bool, expectedRevision int64, cloudDialogue *runtimeapi.CloudDialogueScope) runtimeapi.ChatRequest {
	return runtimeapi.ChatRequest{
		RequestID: requestID, OwnerID: ownerID, ConversationID: conversationID,
		ExpectedConversationRevision: expectedRevision,
		Messages:                     []modelapi.Message{{Role: modelapi.RoleUser, Content: message}}, MemoryDisabled: memoryDisabled,
		CloudDialogue: cloudDialogue,
	}
}

func (service *RuntimeService) resolveCloudDialogueScope(ctx context.Context, ownerID string, scope *agentv1.CloudDialogueScopeV1) (*runtimeapi.CloudDialogueScope, error) {
	if scope == nil {
		return nil, nil
	}
	trusted, err := runtimeapi.NewCloudDialogueScope(scope.GetCloudConnectionId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "cloud dialogue scope is invalid")
	}
	ownerID = strings.TrimSpace(ownerID)
	if err := cloudstatus.ValidateOwnerID(ownerID); err != nil {
		return nil, status.Error(codes.InvalidArgument, "cloud dialogue owner is invalid")
	}
	if service == nil || service.cloudDialogueConnections == nil {
		return nil, status.Error(codes.FailedPrecondition, "cloud dialogue connection resolver is unavailable")
	}
	connection, err := service.cloudDialogueConnections.GetConnection(ctx, ownerID, trusted.ConnectionID)
	if err != nil {
		return nil, publicError(err)
	}
	if connection.ConnectionID != trusted.ConnectionID || connection.OwnerID != ownerID {
		return nil, status.Error(codes.Internal, "cloud dialogue connection ownership read-back is invalid")
	}
	return trusted, nil
}

func runtimeConfigFromProto(
	spec *agentv1.RuntimeConfigSpec,
	revision int64,
	profiles *modelapi.ProfileCatalog,
	searchProfiles *searchprofile.Catalog,
) (runtimeapi.RuntimeConfig, error) {
	if spec == nil || spec.GetModelProfile() == nil {
		return runtimeapi.RuntimeConfig{}, status.Error(codes.InvalidArgument, "model_profile is required")
	}
	profile := spec.GetModelProfile()
	provider := modelapi.Provider("")
	if profile.GetProvider() != agentv1.ModelProvider_MODEL_PROVIDER_UNSPECIFIED {
		var ok bool
		provider, ok = modelProviderFromProto(profile.GetProvider())
		if !ok {
			return runtimeapi.RuntimeConfig{}, status.Error(codes.InvalidArgument, "model provider is invalid")
		}
	}
	if profiles == nil {
		return runtimeapi.RuntimeConfig{}, status.Error(codes.FailedPrecondition, "model profile catalog is unavailable")
	}
	selected := modelapi.Profile{
		ProfileID: profile.GetProfileId(), Provider: provider, Model: profile.GetModel(), BaseURL: profile.GetBaseUrl(), SecretRef: profile.GetSecretRef(),
		MaxOutputTokens: int(profile.GetMaxOutputTokens()), ContextWindow: int(profile.GetContextWindow()), ReasoningEffort: profile.GetReasoningEffort(),
	}
	if profile.Temperature != nil {
		value := profile.GetTemperature()
		selected.Temperature = &value
	}
	if profile.TopP != nil {
		value := profile.GetTopP()
		selected.TopP = &value
	}
	canonical, err := profiles.ResolveSelection(selected)
	if err != nil {
		return runtimeapi.RuntimeConfig{}, status.Error(codes.InvalidArgument, "model profile selection is invalid")
	}
	result := runtimeapi.RuntimeConfig{
		Revision:       revision,
		ModelProfile:   canonical,
		ProjectProfile: spec.GetProjectProfile(), ContextMessageLimit: int(spec.GetContextMessageLimit()),
		MemoryMessageLimit: int(spec.GetMemoryMessageLimit()), MaxSteps: int(spec.GetMaxSteps()), MemoryDisabled: spec.GetMemoryDisabled(),
		EnabledTools: append([]string(nil), spec.GetEnabledTools()...), KnowledgeRefs: append([]string(nil), spec.GetKnowledgeRefs()...),
		MCPServerIDs: append([]string(nil), spec.GetMcpServerIds()...), RecipeIDs: append([]string(nil), spec.GetRecipeIds()...),
	}
	if requested := spec.GetSearchProfile(); requested != nil {
		if searchProfiles == nil {
			return runtimeapi.RuntimeConfig{}, status.Error(codes.FailedPrecondition, "search profile catalog is unavailable")
		}
		provider, ok := searchProviderFromProto(requested.GetProvider())
		if requested.GetProvider() != agentv1.SearchProvider_SEARCH_PROVIDER_UNSPECIFIED && !ok {
			return runtimeapi.RuntimeConfig{}, status.Error(codes.InvalidArgument, "search provider is invalid")
		}
		selected, resolveErr := searchProfiles.ResolveSelection(searchprofile.Profile{
			ProfileID: requested.GetProfileId(), Provider: provider,
			BaseURL: requested.GetBaseUrl(), SecretRef: requested.GetSecretRef(),
			MaxResults:     int(requested.GetMaxResults()),
			TimeoutSeconds: int(requested.GetTimeoutSeconds()),
		})
		if resolveErr != nil {
			return runtimeapi.RuntimeConfig{}, status.Error(codes.InvalidArgument, "search profile selection is invalid")
		}
		if !searchProfiles.AllowsModelProfile(selected.ProfileID, canonical.ProfileID) ||
			!searchProfileMatchesModel(selected, canonical) {
			return runtimeapi.RuntimeConfig{}, status.Error(codes.InvalidArgument, "search profile is not compatible with model profile")
		}
		result.SearchProfile = &selected
	} else if searchProfiles != nil {
		if automatic, ok := searchProfiles.DefaultForModelProfile(canonical.ProfileID); ok {
			if !searchProfileMatchesModel(automatic, canonical) {
				return runtimeapi.RuntimeConfig{}, status.Error(codes.FailedPrecondition, "automatic search profile binding is invalid")
			}
			result.SearchProfile = &automatic
		}
	}
	if result.SearchProfile != nil {
		if !containsString(result.EnabledTools, runtimeapi.SearchToolName) {
			result.EnabledTools = append(result.EnabledTools, runtimeapi.SearchToolName)
		}
	} else {
		result.EnabledTools = withoutString(result.EnabledTools, runtimeapi.SearchToolName)
	}
	if err := runtimeapi.ValidateRuntimeConfig(result); err != nil {
		return runtimeapi.RuntimeConfig{}, publicRuntimeError(err)
	}
	return result, nil
}

func searchProfileMatchesModel(search searchprofile.Profile, model modelapi.Profile) bool {
	if search.Provider != searchprofile.ProviderDeepSeekNative {
		return true
	}
	return model.Provider == modelapi.ProviderDeepSeek &&
		strings.TrimSpace(search.SecretRef) != "" &&
		strings.TrimSpace(search.SecretRef) == strings.TrimSpace(model.SecretRef)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}

func withoutString(values []string, target string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != target {
			result = append(result, value)
		}
	}
	return result
}

func runtimeConfigToProto(ownerID string, config runtimeapi.RuntimeConfig) *agentv1.RuntimeConfig {
	profile := &agentv1.ModelProfile{
		ProfileId: config.ModelProfile.ProfileID,
		Provider:  modelProviderToProto(config.ModelProfile.Provider), Model: config.ModelProfile.Model,
		BaseUrl:         config.ModelProfile.BaseURL,
		MaxOutputTokens: int32(config.ModelProfile.MaxOutputTokens), ContextWindow: int32(config.ModelProfile.ContextWindow),
		ReasoningEffort: config.ModelProfile.ReasoningEffort,
	}
	if config.ModelProfile.Temperature != nil {
		value := *config.ModelProfile.Temperature
		profile.Temperature = &value
	}
	if config.ModelProfile.TopP != nil {
		value := *config.ModelProfile.TopP
		profile.TopP = &value
	}
	var searchProfile *agentv1.SearchProfile
	if search := config.SearchProfile; search != nil {
		searchProfile = &agentv1.SearchProfile{
			ProfileId:      search.ProfileID,
			Provider:       searchProviderToProto(search.Provider),
			BaseUrl:        search.BaseURL,
			MaxResults:     int32(search.MaxResults),
			TimeoutSeconds: int32(search.TimeoutSeconds),
		}
	}
	return &agentv1.RuntimeConfig{
		OwnerId: strings.TrimSpace(ownerID), Revision: config.Revision,
		Spec: &agentv1.RuntimeConfigSpec{
			ModelProfile: profile, ProjectProfile: config.ProjectProfile,
			ContextMessageLimit: int32(config.ContextMessageLimit), MemoryMessageLimit: int32(config.MemoryMessageLimit), MaxSteps: int32(config.MaxSteps),
			MemoryDisabled: config.MemoryDisabled, EnabledTools: append([]string(nil), config.EnabledTools...),
			KnowledgeRefs: append([]string(nil), config.KnowledgeRefs...), McpServerIds: append([]string(nil), config.MCPServerIDs...), RecipeIds: append([]string(nil), config.RecipeIDs...),
			SearchProfile: searchProfile,
		},
	}
}

func modelProviderFromProto(provider agentv1.ModelProvider) (modelapi.Provider, bool) {
	switch provider {
	case agentv1.ModelProvider_MODEL_PROVIDER_OPENAI_COMPATIBLE:
		return modelapi.ProviderOpenAICompatible, true
	case agentv1.ModelProvider_MODEL_PROVIDER_DEEPSEEK:
		return modelapi.ProviderDeepSeek, true
	case agentv1.ModelProvider_MODEL_PROVIDER_ANTHROPIC:
		return modelapi.ProviderAnthropic, true
	default:
		return "", false
	}
}

func modelProviderToProto(provider modelapi.Provider) agentv1.ModelProvider {
	switch provider {
	case modelapi.ProviderOpenAICompatible:
		return agentv1.ModelProvider_MODEL_PROVIDER_OPENAI_COMPATIBLE
	case modelapi.ProviderDeepSeek:
		return agentv1.ModelProvider_MODEL_PROVIDER_DEEPSEEK
	case modelapi.ProviderAnthropic:
		return agentv1.ModelProvider_MODEL_PROVIDER_ANTHROPIC
	default:
		return agentv1.ModelProvider_MODEL_PROVIDER_UNSPECIFIED
	}
}

func searchProviderFromProto(provider agentv1.SearchProvider) (searchprofile.Provider, bool) {
	switch provider {
	case agentv1.SearchProvider_SEARCH_PROVIDER_TAVILY:
		return searchprofile.ProviderTavily, true
	case agentv1.SearchProvider_SEARCH_PROVIDER_BRAVE:
		return searchprofile.ProviderBrave, true
	case agentv1.SearchProvider_SEARCH_PROVIDER_EXA:
		return searchprofile.ProviderExa, true
	case agentv1.SearchProvider_SEARCH_PROVIDER_SERPER:
		return searchprofile.ProviderSerper, true
	case agentv1.SearchProvider_SEARCH_PROVIDER_DEEPSEEK_NATIVE:
		return searchprofile.ProviderDeepSeekNative, true
	default:
		return "", false
	}
}

func searchProviderToProto(provider searchprofile.Provider) agentv1.SearchProvider {
	switch provider {
	case searchprofile.ProviderTavily:
		return agentv1.SearchProvider_SEARCH_PROVIDER_TAVILY
	case searchprofile.ProviderBrave:
		return agentv1.SearchProvider_SEARCH_PROVIDER_BRAVE
	case searchprofile.ProviderExa:
		return agentv1.SearchProvider_SEARCH_PROVIDER_EXA
	case searchprofile.ProviderSerper:
		return agentv1.SearchProvider_SEARCH_PROVIDER_SERPER
	case searchprofile.ProviderDeepSeekNative:
		return agentv1.SearchProvider_SEARCH_PROVIDER_DEEPSEEK_NATIVE
	default:
		return agentv1.SearchProvider_SEARCH_PROVIDER_UNSPECIFIED
	}
}

func runtimeChatResponse(requestID, conversationID string, result runtimeapi.ChatResult) *agentv1.ChatResponse {
	return &agentv1.ChatResponse{
		ConversationId:       conversationID,
		Message:              &agentv1.RuntimeAssistantMessage{MessageId: assistantMessageID(requestID), Content: result.Message.Content},
		ConversationRevision: result.ConversationRevision,
		Steps:                runtimeStepsToProto(result.Steps),
		RelatedTaskIds:       stableRelatedIDs(result.RelatedTaskIDs),
		RelatedPlanIds:       stableRelatedIDs(result.RelatedPlanIDs),
	}
}

func stableRelatedIDs(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func runtimeStepsToProto(steps []runtimeapi.Step) []*agentv1.RuntimeStepSummary {
	result := make([]*agentv1.RuntimeStepSummary, 0, len(steps))
	for _, step := range steps {
		summary := &agentv1.RuntimeStepSummary{}
		switch step.Kind {
		case runtimeapi.StepModel:
			summary.Kind = agentv1.RuntimeStepKind_RUNTIME_STEP_KIND_MODEL
		case runtimeapi.StepToolCall:
			summary.Kind = agentv1.RuntimeStepKind_RUNTIME_STEP_KIND_TOOL_CALL
			summary.ToolCallId = step.ToolCall.ID
			summary.ToolName = step.ToolCall.Function.Name
		case runtimeapi.StepToolResult:
			summary.Kind = agentv1.RuntimeStepKind_RUNTIME_STEP_KIND_TOOL_RESULT
			summary.ToolCallId = step.ToolResult.ToolCallID
			summary.ToolName = step.ToolResult.Name
			summary.IsError = step.ToolResult.IsError
		default:
			continue
		}
		result = append(result, summary)
	}
	return result
}

func runtimeStreamResponse(requestID, conversationID string, event runtimeapi.StreamEvent) *agentv1.StreamChatResponse {
	switch event.Kind {
	case runtimeapi.StreamEventDelta:
		if event.Delta.Content == "" {
			return nil
		}
		return &agentv1.StreamChatResponse{Event: &agentv1.StreamChatResponse_Delta{Delta: &agentv1.ChatDelta{MessageId: assistantMessageID(requestID), Content: event.Delta.Content}}}
	case runtimeapi.StreamEventToolCall:
		return &agentv1.StreamChatResponse{Event: &agentv1.StreamChatResponse_Tool{Tool: &agentv1.ToolExecutionSummary{ToolCallId: event.ToolCall.ID, ToolName: event.ToolCall.Function.Name}}}
	case runtimeapi.StreamEventToolResult:
		return &agentv1.StreamChatResponse{Event: &agentv1.StreamChatResponse_Tool{Tool: &agentv1.ToolExecutionSummary{ToolCallId: event.ToolResult.ToolCallID, ToolName: event.ToolResult.Name, Finished: true, IsError: event.ToolResult.IsError}}}
	case runtimeapi.StreamEventDone:
		if event.Result == nil {
			return nil
		}
		return &agentv1.StreamChatResponse{Event: &agentv1.StreamChatResponse_Done{Done: &agentv1.ChatDone{Response: runtimeChatResponse(requestID, conversationID, *event.Result)}}}
	default:
		return nil
	}
}

func assistantMessageID(requestID string) string {
	parsed, err := uuid.Parse(requestID)
	if err != nil {
		return ""
	}
	return uuid.NewSHA1(parsed, []byte("assistant-message")).String()
}

func publicRuntimeError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "request canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "request deadline exceeded")
	case errors.Is(err, runtimeapi.ErrInvalidRequest), errors.Is(err, runtimeapi.ErrInvalidConversation), errors.Is(err, runtimeapi.ErrRuntimePersistence),
		errors.Is(err, runtimeapi.ErrRuntimeRawSecret), errors.Is(err, runtimeapi.ErrInvalidModelResponse), errors.Is(err, runtimeapi.ErrInvalidToolCall):
		return status.Error(codes.InvalidArgument, "runtime request is invalid")
	case errors.Is(err, runtimeapi.ErrRuntimeConfigNotFound), errors.Is(err, runtimeapi.ErrRuntimeRequestNotFound):
		return status.Error(codes.NotFound, "runtime entity was not found")
	case errors.Is(err, idempotency.ErrConflict):
		return status.Error(codes.AlreadyExists, "idempotency key conflicts with an earlier request")
	case errors.Is(err, runtimeapi.ErrRuntimeRevisionConflict), errors.Is(err, runtimeapi.ErrRuntimeStaleLease):
		return status.Error(codes.Aborted, "expected revision or lease does not match")
	case errors.Is(err, runtimeapi.ErrRuntimeRequestInFlight), errors.Is(err, runtimeapi.ErrStepLimit):
		return status.Error(codes.FailedPrecondition, "runtime request cannot continue in its current state")
	case errors.Is(err, modelapi.ErrProviderUnavailable), errors.Is(err, modelapi.ErrSecretUnavailable):
		return status.Error(codes.Unavailable, "model provider is unavailable")
	case errors.Is(err, modelapi.ErrProviderCredential):
		return status.Error(codes.PermissionDenied, "model provider rejected the supplied credential")
	case errors.Is(err, modelapi.ErrProviderRequest):
		return status.Error(codes.FailedPrecondition, "model provider rejected the selected model or request")
	case errors.Is(err, modelapi.ErrProviderRateLimited):
		return status.Error(codes.ResourceExhausted, "model provider rate limit is temporarily exhausted")
	case errors.Is(err, modelapi.ErrModelListRejected):
		return status.Error(codes.PermissionDenied, "model provider rejected the supplied credential")
	case errors.Is(err, modelapi.ErrModelListUnsupported):
		return status.Error(codes.FailedPrecondition, "model provider does not expose a compatible model list")
	case errors.Is(err, runtimeapp.ErrCapacityExhausted):
		return status.Error(codes.ResourceExhausted, "local Agent capacity is temporarily exhausted")
	default:
		return status.Error(codes.Internal, "runtime operation failed")
	}
}
