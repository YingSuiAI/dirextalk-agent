package runtime

import (
	"context"
	"fmt"
	"strings"
	"time"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
)

const (
	defaultMaxSteps = 24
	maximumMaxSteps = 120
)

type Runtime struct {
	engine        Engine
	models        ModelFactory
	tools         ToolProvider
	configs       RuntimeConfigRepository
	conversations ConversationRepository
	secrets       SecretResolver
	now           Clock
}

type runState struct {
	config            RuntimeConfig
	client            modelapi.Client
	tools             toolSet
	conversation      Conversation
	expectedRevision  int64
	memoryDisabled    bool
	requestMessages   []modelapi.Message
	history           []modelapi.Message
	contextByteBudget int64
}

// contextBoundModelClient is the final outbound guard. The engine's message
// rewriter performs normal per-round compaction, while this wrapper guarantees
// that a custom or future engine cannot bypass the same profile budget before
// a provider network call.
type contextBoundModelClient struct {
	delegate     modelapi.Client
	profile      modelapi.Profile
	messageLimit int
}

func (c contextBoundModelClient) Generate(ctx context.Context, request modelapi.CompletionRequest) (modelapi.Completion, error) {
	compacted, err := c.compact(request)
	if err != nil {
		return modelapi.Completion{}, err
	}
	return c.delegate.Generate(ctx, compacted)
}

func (c contextBoundModelClient) Stream(ctx context.Context, request modelapi.CompletionRequest) (modelapi.Stream, error) {
	compacted, err := c.compact(request)
	if err != nil {
		return nil, err
	}
	return c.delegate.Stream(ctx, compacted)
}

func (c contextBoundModelClient) compact(request modelapi.CompletionRequest) (modelapi.CompletionRequest, error) {
	byteBudget, ok := modelInputByteBudget(c.profile, request.Tools)
	if !ok {
		return modelapi.CompletionRequest{}, contextWindowInputError()
	}
	messages, ok := compactModelMessages(request.Messages, c.messageLimit, byteBudget)
	if !ok {
		return modelapi.CompletionRequest{}, contextWindowInputError()
	}
	request.Messages = messages
	return request, nil
}

func contextWindowInputError() error {
	return fmt.Errorf("%w: model context window cannot fit required input", ErrInvalidRequest)
}

func New(dependencies Dependencies) (*Runtime, error) {
	if dependencies.Engine == nil || dependencies.Models == nil || dependencies.Configs == nil || dependencies.Conversations == nil || dependencies.Secrets == nil {
		return nil, ErrInvalidDependencies
	}
	if dependencies.Clock == nil {
		dependencies.Clock = time.Now
	}
	return &Runtime{
		engine:        dependencies.Engine,
		models:        dependencies.Models,
		tools:         dependencies.Tools,
		configs:       dependencies.Configs,
		conversations: dependencies.Conversations,
		secrets:       dependencies.Secrets,
		now:           dependencies.Clock,
	}, nil
}

func (r *Runtime) Chat(ctx context.Context, request ChatRequest) (ChatResult, error) {
	state, err := r.prepare(ctx, request)
	if err != nil {
		return ChatResult{}, err
	}
	engineResult, err := r.engine.Generate(ctx, runtimeEngineRequest(state))
	if err != nil {
		return ChatResult{}, err
	}
	engineResult, err = normalizeEngineResult(engineResult)
	if err != nil {
		return ChatResult{}, err
	}
	result, err := chatResultFromEngine(engineResult)
	if err != nil {
		return ChatResult{}, err
	}
	result.PendingConversation, result.ExpectedConversationRevision = r.pendingConversation(&state, engineResult.Produced)
	return result, nil
}

func (r *Runtime) Stream(ctx context.Context, request ChatRequest, emit StreamEmitter) (ChatResult, error) {
	if emit == nil {
		return ChatResult{}, ErrInvalidRequest
	}
	state, err := r.prepare(ctx, request)
	if err != nil {
		return ChatResult{}, err
	}
	engineResult, err := r.engine.Stream(ctx, runtimeEngineRequest(state), publicStreamEmitter(emit))
	if err != nil {
		return ChatResult{}, err
	}
	engineResult, err = normalizeEngineResult(engineResult)
	if err != nil {
		return ChatResult{}, err
	}
	result, err := chatResultFromEngine(engineResult)
	if err != nil {
		return ChatResult{}, err
	}
	result.PendingConversation, result.ExpectedConversationRevision = r.pendingConversation(&state, engineResult.Produced)
	return result, nil
}

func chatResultFromEngine(engineResult EngineResult) (ChatResult, error) {
	taskIDs, planIDs, err := collectRelatedEntityIDs(engineResult.Steps)
	if err != nil {
		return ChatResult{}, fmt.Errorf("%w: invalid related entity reference", ErrInvalidModelResponse)
	}
	return ChatResult{
		Message: engineResult.Message, Steps: engineResult.Steps,
		RelatedTaskIDs: taskIDs, RelatedPlanIDs: planIDs,
	}, nil
}

func runtimeEngineRequest(state runState) EngineRequest {
	return EngineRequest{
		Client:   state.client,
		Messages: cloneMessages(state.history),
		Tools:    append([]modelapi.Tool(nil), state.tools.definitions...),
		MaxSteps: state.config.MaxSteps,
		InvokeTool: func(ctx context.Context, call modelapi.ToolCall) (ToolExecution, error) {
			if err := validateToolCalls([]modelapi.ToolCall{call}); err != nil {
				return ToolExecution{}, err
			}
			return runTool(ctx, call, state.tools), nil
		},
		RewriteMessages: func(messages []modelapi.Message) []modelapi.Message {
			compacted, ok := compactModelMessages(messages, state.config.ContextMessageLimit, state.contextByteBudget)
			if !ok {
				// prepare verifies the immutable system/latest-user minimum before
				// any provider call. Later rounds can only add assistant/tool groups,
				// so this is a defensive fail-closed guard for engine violations.
				return nil
			}
			return compacted
		},
	}
}

func normalizeEngineResult(result EngineResult) (EngineResult, error) {
	message, err := normalizeAssistantMessage(result.Message)
	if err != nil || len(message.ToolCalls) > 0 {
		return EngineResult{}, fmt.Errorf("%w: engine did not return a final assistant response", ErrInvalidModelResponse)
	}
	message.ReasoningContent = ""
	produced := cloneMessages(result.Produced)
	for index := range produced {
		if produced[index].Role == modelapi.RoleAssistant {
			produced[index].ReasoningContent = ""
		}
	}
	sanitized := sanitizePairedMessages(produced, false)
	if len(sanitized) != len(produced) || len(produced) == 0 {
		return EngineResult{}, fmt.Errorf("%w: engine returned incomplete produced messages", ErrInvalidModelResponse)
	}
	last := produced[len(produced)-1]
	if last.Role != modelapi.RoleAssistant || len(last.ToolCalls) != 0 || last.Content != message.Content {
		return EngineResult{}, fmt.Errorf("%w: engine final message mismatch", ErrInvalidModelResponse)
	}
	result.Message = message
	result.Produced = produced
	result.Steps = append([]Step(nil), result.Steps...)
	for index := range result.Steps {
		if result.Steps[index].Kind == StepToolCall {
			result.Steps[index].ToolCall.Function.Arguments = "{}"
		}
		result.Steps[index].ToolResult.Content = ""
	}
	return result, nil
}

func publicStreamEmitter(emit StreamEmitter) StreamEmitter {
	return func(event StreamEvent) error {
		switch event.Kind {
		case StreamEventDelta:
			if event.Delta.Content == "" {
				return nil
			}
			return emit(StreamEvent{Kind: StreamEventDelta, Delta: modelapi.Delta{Content: event.Delta.Content}})
		case StreamEventToolCall:
			return emit(StreamEvent{Kind: StreamEventToolCall, ToolCall: modelapi.ToolCall{
				ID: event.ToolCall.ID, Type: event.ToolCall.Type,
				Function: modelapi.FunctionCall{Name: event.ToolCall.Function.Name},
			}})
		case StreamEventToolResult:
			return emit(StreamEvent{Kind: StreamEventToolResult, ToolResult: ToolExecution{
				ToolCallID: event.ToolResult.ToolCallID,
				Name:       event.ToolResult.Name,
				IsError:    event.ToolResult.IsError,
			}})
		default:
			return fmt.Errorf("%w: unsupported engine stream event", ErrInvalidModelResponse)
		}
	}
}

func (r *Runtime) prepare(ctx context.Context, request ChatRequest) (runState, error) {
	request.RequestID = strings.TrimSpace(request.RequestID)
	request.OwnerID = strings.TrimSpace(request.OwnerID)
	request.ConversationID = strings.TrimSpace(request.ConversationID)
	if !validRuntimeID(request.RequestID, false) || !validRuntimeID(request.OwnerID, false) || !validRuntimeID(request.ConversationID, true) || request.ExpectedConversationRevision < 0 {
		return runState{}, ErrInvalidRequest
	}
	requestMessages := sanitizePairedMessages(request.Messages, false)
	if !hasUserMessage(requestMessages) {
		return runState{}, ErrInvalidRequest
	}
	config, err := r.configs.LoadRuntimeConfig(ctx, request.OwnerID)
	if err != nil {
		return runState{}, err
	}
	config = normalizedRuntimeConfig(config)
	state := runState{
		config:          config,
		requestMessages: requestMessages,
	}
	if request.MemoryModeBound {
		state.memoryDisabled = request.MemoryDisabled
	} else {
		state.memoryDisabled = config.MemoryDisabled || request.MemoryDisabled || request.ConversationID == ""
	}
	if state.memoryDisabled && request.ExpectedConversationRevision != 0 {
		return runState{}, ErrRuntimeRevisionConflict
	}
	if !state.memoryDisabled {
		conversation, found, loadErr := r.conversations.LoadConversation(ctx, request.OwnerID, request.ConversationID)
		if loadErr != nil {
			return runState{}, loadErr
		}
		if found {
			if conversation.OwnerID != request.OwnerID || conversation.ConversationID != request.ConversationID || conversation.Revision < 0 {
				return runState{}, ErrInvalidConversation
			}
			if conversation.Revision != request.ExpectedConversationRevision {
				return runState{}, ErrRuntimeRevisionConflict
			}
			conversation.Messages = sanitizePairedMessages(conversation.Messages, false)
			state.conversation = conversation
			state.expectedRevision = request.ExpectedConversationRevision
		} else {
			if request.ExpectedConversationRevision != 0 {
				return runState{}, ErrRuntimeRevisionConflict
			}
			state.conversation = Conversation{OwnerID: request.OwnerID, ConversationID: request.ConversationID}
		}
	}
	history := make([]modelapi.Message, 0, len(state.conversation.Messages)+len(requestMessages)+1)
	history = append(history, state.conversation.Messages...)
	history = append(history, requestMessages...)
	preflightBudget, ok := modelInputByteBudget(config.ModelProfile, nil)
	if !ok {
		return runState{}, contextWindowInputError()
	}
	if _, ok = modelMessages(config.ProjectProfile, state.conversation.Summary, history, config.ContextMessageLimit, preflightBudget); !ok {
		// Do this before tool discovery: MCP providers may initialize/list tools
		// over the network, and an intrinsically oversized system/latest-user
		// input can never become valid after those definitions are loaded.
		return runState{}, contextWindowInputError()
	}
	tools, err := loadToolSet(ctx, r.tools, ToolRequest{
		RequestID:      request.RequestID,
		OwnerID:        request.OwnerID,
		ConversationID: request.ConversationID,
		EnabledNames:   append([]string(nil), config.EnabledTools...),
		KnowledgeRefs:  append([]string(nil), config.KnowledgeRefs...),
		MCPServerIDs:   append([]string(nil), config.MCPServerIDs...),
		RecipeIDs:      append([]string(nil), config.RecipeIDs...),
	})
	if err != nil {
		return runState{}, err
	}
	contextByteBudget, ok := modelInputByteBudget(config.ModelProfile, tools.definitions)
	if !ok {
		return runState{}, contextWindowInputError()
	}
	state.history, ok = modelMessages(config.ProjectProfile, state.conversation.Summary, history, config.ContextMessageLimit, contextByteBudget)
	if !ok {
		return runState{}, contextWindowInputError()
	}
	state.contextByteBudget = contextByteBudget
	client, err := r.models.CreateModel(ctx, config.ModelProfile, r.secrets)
	if err != nil {
		return runState{}, err
	}
	if client == nil {
		return runState{}, ErrInvalidDependencies
	}
	if config.ModelProfile.ContextWindow > 0 {
		client = contextBoundModelClient{delegate: client, profile: config.ModelProfile, messageLimit: config.ContextMessageLimit}
	}
	state.client = client
	state.tools = tools
	return state, nil
}

func (r *Runtime) pendingConversation(state *runState, produced []modelapi.Message) (*Conversation, int64) {
	if state.memoryDisabled {
		return nil, 0
	}
	conversation := cloneConversation(state.conversation)
	conversation.Messages = append(conversation.Messages, cloneMessages(state.requestMessages)...)
	conversation.Messages = append(conversation.Messages, cloneMessages(produced)...)
	conversation = compactConversation(conversation, state.config.MemoryMessageLimit, r.now())
	conversation.Revision = state.expectedRevision
	return &conversation, state.expectedRevision
}

func normalizeAssistantMessage(message modelapi.Message) (modelapi.Message, error) {
	if message.Role == "" {
		message.Role = modelapi.RoleAssistant
	}
	if message.Role != modelapi.RoleAssistant || (strings.TrimSpace(message.Content) == "" && len(message.ToolCalls) == 0) {
		return modelapi.Message{}, fmt.Errorf("%w: expected a non-empty assistant message", ErrInvalidModelResponse)
	}
	message = cloneMessage(message)
	return message, nil
}

func normalizedRuntimeConfig(config RuntimeConfig) RuntimeConfig {
	if config.ContextMessageLimit <= 0 {
		config.ContextMessageLimit = defaultContextMessageLimit
	}
	if config.MemoryMessageLimit <= 0 {
		config.MemoryMessageLimit = defaultMemoryMessageLimit
	}
	if config.MaxSteps <= 0 {
		config.MaxSteps = defaultMaxSteps
	}
	if config.MaxSteps > maximumMaxSteps {
		config.MaxSteps = maximumMaxSteps
	}
	return config
}

func validRuntimeID(value string, optional bool) bool {
	if value == "" {
		return optional
	}
	return len(value) <= 256 && !strings.ContainsAny(value, "\r\n\t")
}

func hasUserMessage(messages []modelapi.Message) bool {
	for _, message := range messages {
		if message.Role == modelapi.RoleUser && strings.TrimSpace(message.Content) != "" {
			return true
		}
	}
	return false
}
