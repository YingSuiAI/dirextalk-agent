package runtime

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
)

func TestChatDelegatesToEngineWithImmutablePolicyAndScopedTool(t *testing.T) {
	t.Parallel()
	const relatedTaskID = "99a88e43-ab03-48cb-a917-334f126a303e"

	type contextKey string
	const requestContext contextKey = "request"
	ctx := context.WithValue(context.Background(), requestContext, "trusted")
	conversationRepo := &recordingConversationRepository{}
	client := inertModelClient{}
	factory := &recordingModelFactory{client: client}
	var invocation ToolInvocation
	engine := &scriptedEngine{generate: func(engineCtx context.Context, request EngineRequest) (EngineResult, error) {
		if engineCtx.Value(requestContext) != "trusted" {
			t.Fatal("engine lost the authenticated request context")
		}
		if request.Client != client || request.MaxSteps != 4 || len(request.Tools) != 1 || request.Tools[0].Name != "lookup" {
			t.Fatalf("unexpected engine request: %#v", request)
		}
		if len(request.Messages) != 2 || request.Messages[0].Role != modelapi.RoleSystem ||
			!strings.Contains(request.Messages[0].Content, immutableBasePolicy) ||
			!strings.Contains(request.Messages[0].Content, "Project profile:\nproject policy") ||
			request.Messages[1].Content != "find x" {
			t.Fatalf("immutable policy/project profile were not composed: %#v", request.Messages)
		}
		call := modelapi.ToolCall{ID: "call-1", Type: "function", Function: modelapi.FunctionCall{Name: "lookup", Arguments: `{"q":"x"}`}}
		execution, err := request.InvokeTool(engineCtx, call)
		if err != nil {
			return EngineResult{}, err
		}
		return EngineResult{
			Message: modelapi.Message{Role: modelapi.RoleAssistant, Content: "finished", ReasoningContent: "raw final reasoning"},
			Produced: []modelapi.Message{
				{Role: modelapi.RoleAssistant, ReasoningContent: "raw tool reasoning", ToolCalls: []modelapi.ToolCall{call}},
				{Role: modelapi.RoleTool, Content: execution.Content, Name: execution.Name, ToolCallID: execution.ToolCallID},
				{Role: modelapi.RoleAssistant, Content: "finished", ReasoningContent: "raw final reasoning"},
			},
			Steps: []Step{{Kind: StepModel}, {Kind: StepToolCall, ToolCall: call}, {Kind: StepToolResult, ToolResult: execution}, {Kind: StepModel}},
		}, nil
	}}
	runtime, err := New(Dependencies{
		Engine: engine,
		Models: factory,
		Tools: ToolProviderFunc(func(toolCtx context.Context, request ToolRequest) ([]Tool, error) {
			if toolCtx.Value(requestContext) != "trusted" || request.RequestID != "request-1" || request.OwnerID != "owner-1" || request.ConversationID != "conversation-1" {
				t.Fatalf("tool provider lost trusted scope: %#v", request)
			}
			return []Tool{{
				Definition: modelapi.Tool{Name: "lookup", InputSchema: map[string]any{"type": "object"}},
				Run: func(runCtx context.Context, got ToolInvocation) (ToolResult, error) {
					if runCtx.Value(requestContext) != "trusted" {
						t.Fatal("tool execution lost request context")
					}
					invocation = got
					return ToolResult{Content: `{"value":"found"}`, RelatedTaskIDs: []string{relatedTaskID}}, nil
				},
			}}, nil
		}),
		Configs: staticConfigRepository{config: RuntimeConfig{
			ModelProfile:        modelapi.Profile{Provider: modelapi.ProviderDeepSeek, Model: "test-model", SecretRef: "secret:model"},
			ProjectProfile:      "project policy",
			ContextMessageLimit: 32,
			MemoryMessageLimit:  12,
			MaxSteps:            4,
			EnabledTools:        []string{"lookup"},
		}},
		Conversations: conversationRepo,
		Secrets:       inertSecretResolver{},
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := runtime.Chat(ctx, ChatRequest{
		RequestID:      "request-1",
		OwnerID:        "owner-1",
		ConversationID: "conversation-1",
		Messages:       []modelapi.Message{{Role: modelapi.RoleUser, Content: "find x"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Message.Content != "finished" || result.Message.ReasoningContent != "" || result.ConversationRevision != 0 || result.PendingConversation == nil || result.ExpectedConversationRevision != 0 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if invocation.RequestID != "request-1" || invocation.OwnerID != "owner-1" || invocation.ConversationID != "conversation-1" || invocation.ToolCallID != "call-1" || invocation.Name != "lookup" {
		t.Fatalf("unexpected tool invocation scope: %#v", invocation)
	}
	if factory.secretResolver == nil || factory.profile.SecretRef != "secret:model" {
		t.Fatal("runtime did not pass the opaque secret resolver/profile to the model factory")
	}
	if conversationRepo.saveCalls != 0 || len(result.PendingConversation.Messages) != 4 || result.PendingConversation.Messages[1].ReasoningContent != "" || result.PendingConversation.Messages[3].ReasoningContent != "" {
		t.Fatalf("conversation was independently saved, incomplete, or retained raw reasoning: saves=%d pending=%#v", conversationRepo.saveCalls, result.PendingConversation)
	}
	if result.Steps[1].ToolCall.Function.Arguments != "{}" || result.Steps[2].ToolResult.Content != "" {
		t.Fatalf("chat result exposed raw tool data: %#v", result.Steps)
	}
	if len(result.RelatedTaskIDs) != 1 || result.RelatedTaskIDs[0] != relatedTaskID || len(result.RelatedPlanIDs) != 0 {
		t.Fatalf("chat result lost structured related entities: %#v", result)
	}
}

func TestChatRejectsMissingRequestIDBeforeEngineOrPersistence(t *testing.T) {
	t.Parallel()

	engine := &scriptedEngine{}
	conversations := &recordingConversationRepository{}
	runtime := mustTestRuntime(t, testDependencies(engine, conversations, validTestConfig()))
	_, err := runtime.Chat(context.Background(), ChatRequest{
		OwnerID: "owner-1", ConversationID: "conversation-1",
		Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "hello"}},
	})
	if !errors.Is(err, ErrInvalidRequest) || engine.generateCalls != 0 || conversations.saveCalls != 0 {
		t.Fatalf("invalid request crossed runtime boundary: err=%v engine=%d saves=%d", err, engine.generateCalls, conversations.saveCalls)
	}
}

func TestChatDropsOrphanAndIncompleteToolMessagesBeforeEngine(t *testing.T) {
	t.Parallel()

	engine := &scriptedEngine{generate: func(_ context.Context, request EngineRequest) (EngineResult, error) {
		messages := request.Messages
		if len(messages) != 5 || messages[0].Role != modelapi.RoleSystem || messages[1].Content != "keep" || messages[2].ToolCalls[0].ID != "paired" || messages[3].ToolCallID != "paired" || messages[4].Content != "latest" {
			t.Fatalf("unexpected sanitized messages: %#v", messages)
		}
		return finalEngineResult("ok"), nil
	}}
	config := validTestConfig()
	config.MemoryDisabled = true
	runtime := mustTestRuntime(t, testDependencies(engine, &recordingConversationRepository{}, config))
	_, err := runtime.Chat(context.Background(), ChatRequest{
		RequestID: "request-2", OwnerID: "owner-1",
		Messages: []modelapi.Message{
			{Role: modelapi.RoleTool, ToolCallID: "orphan", Content: "must drop"},
			{Role: modelapi.RoleAssistant, ToolCalls: []modelapi.ToolCall{{ID: "missing", Function: modelapi.FunctionCall{Name: "lookup"}}}},
			{Role: modelapi.RoleUser, Content: "keep"},
			{Role: modelapi.RoleAssistant, ToolCalls: []modelapi.ToolCall{{ID: "paired", Function: modelapi.FunctionCall{Name: "lookup"}}}},
			{Role: modelapi.RoleTool, ToolCallID: "paired", Name: "lookup", Content: "paired result"},
			{Role: modelapi.RoleUser, Content: "latest"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestChatBuildsPendingConversationWithoutIndependentSave(t *testing.T) {
	t.Parallel()

	saveErr := errors.New("save failed")
	conversations := &recordingConversationRepository{
		found: true,
		loaded: Conversation{
			OwnerID: "owner-1", ConversationID: "conversation-1", Revision: 7, Summary: "previous summary",
			Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "old question"}, {Role: modelapi.RoleAssistant, Content: "old answer"}, {Role: modelapi.RoleUser, Content: "recent question"}},
		},
		saveErr: saveErr,
	}
	engine := &scriptedEngine{generate: func(context.Context, EngineRequest) (EngineResult, error) {
		return finalEngineResult("new answer"), nil
	}}
	config := validTestConfig()
	config.MemoryMessageLimit = 2
	runtime := mustTestRuntime(t, testDependencies(engine, conversations, config))
	result, err := runtime.Chat(context.Background(), ChatRequest{
		RequestID: "request-3", OwnerID: "owner-1", ConversationID: "conversation-1",
		ExpectedConversationRevision: 7,
		Messages:                     []modelapi.Message{{Role: modelapi.RoleUser, Content: "new question"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if conversations.saveCalls != 0 || result.PendingConversation == nil || result.ExpectedConversationRevision != 7 || result.PendingConversation.Revision != 7 || len(result.PendingConversation.Messages) > 2 {
		t.Fatalf("unexpected pending commit: saves=%d result=%#v", conversations.saveCalls, result)
	}
	if !strings.Contains(result.PendingConversation.Summary, "previous summary") || !strings.Contains(result.PendingConversation.Summary, "old question") {
		t.Fatalf("summary lost compacted history: %q", result.PendingConversation.Summary)
	}
}

func TestStreamRedactsEngineEventsAndDoesNotPersistEmitterFailure(t *testing.T) {
	t.Parallel()

	conversations := &recordingConversationRepository{}
	engine := &scriptedEngine{stream: func(_ context.Context, _ EngineRequest, emit StreamEmitter) (EngineResult, error) {
		if err := emit(StreamEvent{Kind: StreamEventDelta, Delta: modelapi.Delta{Content: "finished", ReasoningContent: "private reasoning", ToolCalls: []modelapi.ToolCall{{ID: "raw", Function: modelapi.FunctionCall{Arguments: `{"secret":"value"}`}}}}}); err != nil {
			return EngineResult{}, err
		}
		if err := emit(StreamEvent{Kind: StreamEventToolCall, ToolCall: modelapi.ToolCall{ID: "call-1", Type: "function", Function: modelapi.FunctionCall{Name: "lookup", Arguments: `{"q":"secret"}`}}}); err != nil {
			return EngineResult{}, err
		}
		if err := emit(StreamEvent{Kind: StreamEventToolResult, ToolResult: ToolExecution{ToolCallID: "call-1", Name: "lookup", Content: "raw result"}}); err != nil {
			return EngineResult{}, err
		}
		return EngineResult{
			Message:  modelapi.Message{Role: modelapi.RoleAssistant, Content: "finished", ReasoningContent: "private reasoning"},
			Produced: []modelapi.Message{{Role: modelapi.RoleAssistant, Content: "finished", ReasoningContent: "private reasoning"}},
			Steps:    []Step{{Kind: StepModel}},
		}, nil
	}}
	runtime := mustTestRuntime(t, testDependencies(engine, conversations, validTestConfig()))
	var events []StreamEvent
	result, err := runtime.Stream(context.Background(), ChatRequest{
		RequestID: "request-4", OwnerID: "owner-1", ConversationID: "conversation-1",
		Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "hello"}},
	}, func(event StreamEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[0].Delta.Content != "finished" || events[0].Delta.ReasoningContent != "" || len(events[0].Delta.ToolCalls) != 0 ||
		events[1].ToolCall.Function.Arguments != "" || events[2].ToolResult.Content != "" {
		t.Fatalf("public stream leaked internal data: %#v", events)
	}
	if conversations.saveCalls != 0 || result.PendingConversation == nil || len(result.PendingConversation.Messages) != 2 || result.PendingConversation.Messages[1].ReasoningContent != "" {
		t.Fatalf("stream execution independently persisted or returned unsafe pending data: saves=%d result=%#v", conversations.saveCalls, result)
	}

	emitErr := errors.New("client disconnected")
	failingRepo := &recordingConversationRepository{}
	failingEngine := &scriptedEngine{stream: func(_ context.Context, _ EngineRequest, emit StreamEmitter) (EngineResult, error) {
		err := emit(StreamEvent{Kind: StreamEventDelta, Delta: modelapi.Delta{Content: "partial"}})
		return EngineResult{}, err
	}}
	failingRuntime := mustTestRuntime(t, testDependencies(failingEngine, failingRepo, validTestConfig()))
	_, err = failingRuntime.Stream(context.Background(), ChatRequest{
		RequestID: "request-5", OwnerID: "owner-1", ConversationID: "conversation-2",
		Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "hello"}},
	}, func(StreamEvent) error { return emitErr })
	if !errors.Is(err, emitErr) || failingRepo.saveCalls != 0 {
		t.Fatalf("partial stream was persisted: err=%v saves=%d", err, failingRepo.saveCalls)
	}
}

func TestToolOutputIsRedactedEvenWhenProviderViolatesContract(t *testing.T) {
	t.Parallel()

	sensitive := "sk-" + generatedSensitiveDetail(t)
	conversations := &recordingConversationRepository{}
	engine := &scriptedEngine{generate: func(ctx context.Context, request EngineRequest) (EngineResult, error) {
		call := modelapi.ToolCall{ID: "call-1", Type: "function", Function: modelapi.FunctionCall{Name: "lookup", Arguments: `{}`}}
		execution, err := request.InvokeTool(ctx, call)
		if err != nil {
			return EngineResult{}, err
		}
		if strings.Contains(execution.Content, sensitive) || !strings.Contains(execution.Content, "[redacted]") {
			t.Fatalf("tool output was not redacted: %q", execution.Content)
		}
		return EngineResult{
			Message: modelapi.Message{Role: modelapi.RoleAssistant, Content: "handled"},
			Produced: []modelapi.Message{
				{Role: modelapi.RoleAssistant, ToolCalls: []modelapi.ToolCall{call}},
				{Role: modelapi.RoleTool, Content: execution.Content, Name: execution.Name, ToolCallID: execution.ToolCallID},
				{Role: modelapi.RoleAssistant, Content: "handled"},
			},
		}, nil
	}}
	config := validTestConfig()
	config.EnabledTools = []string{"lookup"}
	deps := testDependencies(engine, conversations, config)
	deps.Tools = ToolProviderFunc(func(context.Context, ToolRequest) ([]Tool, error) {
		return []Tool{{
			Definition: modelapi.Tool{Name: "lookup", InputSchema: map[string]any{"type": "object"}},
			Run: func(context.Context, ToolInvocation) (ToolResult, error) {
				return ToolResult{Content: `{"token":"` + sensitive + `"}`}, nil
			},
		}}, nil
	})
	runtime := mustTestRuntime(t, deps)
	result, err := runtime.Chat(context.Background(), ChatRequest{
		RequestID: "request-6", OwnerID: "owner-1", ConversationID: "conversation-1",
		Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "run"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	saved, _ := json.Marshal(result.PendingConversation)
	if strings.Contains(string(saved), sensitive) {
		t.Fatal("provider tool output canary entered durable conversation")
	}
}

func TestToolFailureUsesStableModelVisibleError(t *testing.T) {
	t.Parallel()

	sensitive := generatedSensitiveDetail(t)
	engine := &scriptedEngine{generate: func(ctx context.Context, request EngineRequest) (EngineResult, error) {
		call := modelapi.ToolCall{ID: "call-1", Type: "function", Function: modelapi.FunctionCall{Name: "lookup", Arguments: `{}`}}
		execution, err := request.InvokeTool(ctx, call)
		if err != nil {
			return EngineResult{}, err
		}
		if !execution.IsError || execution.Content != `{"error":"tool execution failed"}` {
			t.Fatalf("unexpected model-visible failure: %#v", execution)
		}
		return EngineResult{
			Message: modelapi.Message{Role: modelapi.RoleAssistant, Content: "handled"},
			Produced: []modelapi.Message{
				{Role: modelapi.RoleAssistant, ToolCalls: []modelapi.ToolCall{call}},
				{Role: modelapi.RoleTool, Content: execution.Content, Name: execution.Name, ToolCallID: execution.ToolCallID},
				{Role: modelapi.RoleAssistant, Content: "handled"},
			},
		}, nil
	}}
	config := validTestConfig()
	config.EnabledTools = []string{"lookup"}
	deps := testDependencies(engine, &recordingConversationRepository{}, config)
	deps.Tools = ToolProviderFunc(func(context.Context, ToolRequest) ([]Tool, error) {
		return []Tool{{
			Definition: modelapi.Tool{Name: "lookup", InputSchema: map[string]any{"type": "object"}},
			Run: func(context.Context, ToolInvocation) (ToolResult, error) {
				return ToolResult{}, errors.New("backend detail " + sensitive)
			},
		}}, nil
	})
	runtime := mustTestRuntime(t, deps)
	result, err := runtime.Chat(context.Background(), ChatRequest{
		RequestID: "request-tool-failure", OwnerID: "owner-1", ConversationID: "conversation-1",
		Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "run"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result.PendingConversation)
	if strings.Contains(string(encoded), sensitive) {
		t.Fatal("tool backend error entered pending durable conversation")
	}
}

func TestEngineFailureDoesNotPersist(t *testing.T) {
	t.Parallel()

	conversations := &recordingConversationRepository{}
	engine := &scriptedEngine{generate: func(context.Context, EngineRequest) (EngineResult, error) {
		return EngineResult{}, ErrStepLimit
	}}
	runtime := mustTestRuntime(t, testDependencies(engine, conversations, validTestConfig()))
	_, err := runtime.Chat(context.Background(), ChatRequest{
		RequestID: "request-7", OwnerID: "owner-1", ConversationID: "conversation-1",
		Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "loop"}},
	})
	if !errors.Is(err, ErrStepLimit) || conversations.saveCalls != 0 {
		t.Fatalf("incomplete engine result was persisted: err=%v saves=%d", err, conversations.saveCalls)
	}
}

func TestChatRejectsStaleConversationRevisionBeforeEngine(t *testing.T) {
	t.Parallel()

	conversations := &recordingConversationRepository{
		found:  true,
		loaded: Conversation{OwnerID: "owner-1", ConversationID: "conversation-1", Revision: 2},
	}
	engine := &scriptedEngine{}
	runtime := mustTestRuntime(t, testDependencies(engine, conversations, validTestConfig()))
	_, err := runtime.Chat(context.Background(), ChatRequest{
		RequestID: "request-stale", OwnerID: "owner-1", ConversationID: "conversation-1",
		ExpectedConversationRevision: 1,
		Messages:                     []modelapi.Message{{Role: modelapi.RoleUser, Content: "hello"}},
	})
	if !errors.Is(err, ErrRuntimeRevisionConflict) || engine.generateCalls != 0 || conversations.saveCalls != 0 {
		t.Fatalf("stale revision crossed execution boundary: err=%v engine=%d saves=%d", err, engine.generateCalls, conversations.saveCalls)
	}
}

func TestRuntimeRequestDigestBindsExpectedConversationRevision(t *testing.T) {
	t.Parallel()

	command := RuntimeRequestCommand{
		Request: ChatRequest{
			RequestID: "request-digest", OwnerID: "owner-1", ConversationID: "conversation-1",
			Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "hello"}},
		},
		LeaseDuration: minimumPersistenceLease,
	}
	first, err := command.Digest()
	if err != nil {
		t.Fatal(err)
	}
	command.Request.ExpectedConversationRevision = 1
	second, err := command.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("request digest did not bind expected_conversation_revision")
	}
}

func TestRuntimeRequestCloudDialogueScopeIsCanonicalAndIdempotencyBound(t *testing.T) {
	t.Parallel()
	command := RuntimeRequestCommand{
		Request: ChatRequest{
			RequestID: "request-cloud-digest", OwnerID: "owner-1", ConversationID: "conversation-1",
			Messages:      []modelapi.Message{{Role: modelapi.RoleUser, Content: "research official documentation"}},
			CloudDialogue: &CloudDialogueScope{ConnectionID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
		},
		LeaseDuration: minimumPersistenceLease,
	}
	first, err := command.Digest()
	if err != nil {
		t.Fatal(err)
	}
	command.Request.CloudDialogue.ConnectionID = "22222222-2222-4222-8222-222222222222"
	second, err := command.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("idempotency digest did not bind trusted Cloud Dialogue connection")
	}
	command.Request.CloudDialogue.ConnectionID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	command.Request.CloudDialogue.ConnectionID = strings.ToUpper(command.Request.CloudDialogue.ConnectionID)
	if _, err := command.Validated(); !errors.Is(err, ErrRuntimePersistence) {
		t.Fatalf("non-canonical Cloud Connection error = %v", err)
	}
	secret := "sk-" + strings.Repeat("Z", 40)
	command.Request.CloudDialogue.ConnectionID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	command.Request.Messages = []modelapi.Message{{Role: modelapi.RoleUser, Content: "deploy with " + secret}}
	if _, err := command.Validated(); !errors.Is(err, ErrRuntimeRawSecret) || strings.Contains(err.Error(), secret) {
		t.Fatalf("secret-bearing Cloud Dialogue error = %v", err)
	}
}

func TestCloudDialogueUsesFixedToolAllowlistAndDropsOrdinaryCapabilityRefs(t *testing.T) {
	t.Parallel()
	connectionID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	config := validTestConfig()
	config.MemoryDisabled = true
	config.EnabledTools = []string{"dangerous_runtime_mutation"}
	config.KnowledgeRefs = []string{"knowledge-private"}
	config.MCPServerIDs = []string{"network-mcp"}
	config.RecipeIDs = []string{"caller-recipe"}
	var toolRequest ToolRequest
	engine := &scriptedEngine{generate: func(_ context.Context, request EngineRequest) (EngineResult, error) {
		got := make(map[string]struct{}, len(request.Tools))
		for _, tool := range request.Tools {
			got[tool.Name] = struct{}{}
		}
		for _, name := range CloudDialogueToolNames() {
			if _, ok := got[name]; !ok {
				t.Fatalf("cloud dialogue allowlist omitted %q: %#v", name, request.Tools)
			}
		}
		if _, ok := got["dangerous_runtime_mutation"]; ok || len(got) != len(CloudDialogueToolNames()) {
			t.Fatalf("cloud dialogue exposed configured capabilities: %#v", request.Tools)
		}
		return finalEngineResult("planning only"), nil
	}}
	dependencies := testDependencies(engine, &recordingConversationRepository{}, config)
	dependencies.Tools = ToolProviderFunc(func(_ context.Context, request ToolRequest) ([]Tool, error) {
		toolRequest = request
		names := append(CloudDialogueToolNames(), "dangerous_runtime_mutation")
		tools := make([]Tool, 0, len(names))
		for _, name := range names {
			tools = append(tools, Tool{Definition: modelapi.Tool{Name: name, InputSchema: map[string]any{"type": "object"}}, Run: func(context.Context, ToolInvocation) (ToolResult, error) { return ToolResult{}, nil }})
		}
		return tools, nil
	})
	runtime := mustTestRuntime(t, dependencies)
	_, err := runtime.Chat(context.Background(), ChatRequest{
		RequestID: "cloud-dialogue-request", OwnerID: "owner-1", ConversationID: "conversation-1", MemoryDisabled: true,
		Messages:      []modelapi.Message{{Role: modelapi.RoleUser, Content: "research official documentation"}},
		CloudDialogue: &CloudDialogueScope{ConnectionID: connectionID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if toolRequest.CloudDialogue == nil || toolRequest.CloudDialogue.ConnectionID != connectionID || len(toolRequest.KnowledgeRefs) != 0 || len(toolRequest.MCPServerIDs) != 0 || len(toolRequest.RecipeIDs) != 0 {
		t.Fatalf("trusted cloud tool scope drifted: %#v", toolRequest)
	}
}

func TestRuntimeConfigDigestBindsServerModelProfileID(t *testing.T) {
	config := RuntimeConfig{
		ModelProfile: modelapi.Profile{
			ProfileID: "deepseek-v4", Provider: modelapi.ProviderDeepSeek, Model: "deepseekv4-pro",
			BaseURL: "https://api.deepseek.example/v1", SecretRef: "mounted:deepseek-token",
			ContextWindow: 65536, MaxOutputTokens: 4096,
		},
		ContextMessageLimit: 32, MemoryMessageLimit: 16, MaxSteps: 8,
	}
	command := SaveRuntimeConfigCommand{
		IdempotencyKey: "d3ab9cb6-0c90-4484-bbaf-62d27035f9f5", OwnerID: "owner-1", Config: config,
	}
	first, err := command.Digest()
	if err != nil {
		t.Fatal(err)
	}
	command.Config.ModelProfile.ProfileID = "deepseek-v4-alt"
	second, err := command.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("runtime config digest did not bind profile_id")
	}
}

func TestToolSelectionFailsClosedWhenNoToolsAreEnabled(t *testing.T) {
	t.Parallel()

	providerCalled := false
	set, err := loadToolSet(context.Background(), ToolProviderFunc(func(context.Context, ToolRequest) ([]Tool, error) {
		providerCalled = true
		return []Tool{{Definition: modelapi.Tool{Name: "dangerous"}, Run: func(context.Context, ToolInvocation) (ToolResult, error) { return ToolResult{}, nil }}}, nil
	}), ToolRequest{OwnerID: "owner-1"})
	if err != nil {
		t.Fatal(err)
	}
	if providerCalled || len(set.definitions) != 0 || len(set.byName) != 0 {
		t.Fatalf("empty allowlist exposed tools: called=%v set=%#v", providerCalled, set)
	}
}

func TestRuntimeCapabilityReferencesNormalizeDeterministically(t *testing.T) {
	t.Parallel()

	config := validTestConfig()
	config.EnabledTools = []string{" z ", "a", "a"}
	config.KnowledgeRefs = []string{" knowledge:b ", "knowledge:a", "knowledge:a"}
	config.MCPServerIDs = []string{"mcp-2", "mcp-1", "mcp-2"}
	config.RecipeIDs = []string{"recipe:b", "recipe:a", "recipe:a"}
	normalized := normalizePersistedRuntimeConfig(config)
	if strings.Join(normalized.EnabledTools, ",") != "a,z" || strings.Join(normalized.KnowledgeRefs, ",") != "knowledge:a,knowledge:b" ||
		strings.Join(normalized.MCPServerIDs, ",") != "mcp-1,mcp-2" || strings.Join(normalized.RecipeIDs, ",") != "recipe:a,recipe:b" {
		t.Fatalf("runtime refs were not normalized: %#v", normalized)
	}
}

type inertSecretResolver struct{}

func (inertSecretResolver) ResolveSecret(context.Context, string) ([]byte, error) {
	return nil, errors.New("not used by inert model")
}

type inertModelClient struct{}

func (inertModelClient) Generate(context.Context, modelapi.CompletionRequest) (modelapi.Completion, error) {
	return modelapi.Completion{}, errors.New("model must be called only by the injected engine")
}

func (inertModelClient) Stream(context.Context, modelapi.CompletionRequest) (modelapi.Stream, error) {
	return nil, errors.New("model must be called only by the injected engine")
}

type scriptedEngine struct {
	mu            sync.Mutex
	generate      func(context.Context, EngineRequest) (EngineResult, error)
	stream        func(context.Context, EngineRequest, StreamEmitter) (EngineResult, error)
	generateCalls int
	streamCalls   int
}

func (s *scriptedEngine) Generate(ctx context.Context, request EngineRequest) (EngineResult, error) {
	s.mu.Lock()
	s.generateCalls++
	fn := s.generate
	s.mu.Unlock()
	if fn == nil {
		return EngineResult{}, errors.New("unexpected Generate")
	}
	return fn(ctx, request)
}

func (s *scriptedEngine) Stream(ctx context.Context, request EngineRequest, emit StreamEmitter) (EngineResult, error) {
	s.mu.Lock()
	s.streamCalls++
	fn := s.stream
	s.mu.Unlock()
	if fn == nil {
		return EngineResult{}, errors.New("unexpected Stream")
	}
	return fn(ctx, request, emit)
}

type staticConfigRepository struct {
	config RuntimeConfig
	err    error
}

func (s staticConfigRepository) LoadRuntimeConfig(context.Context, string) (RuntimeConfig, error) {
	return s.config, s.err
}

type recordingConversationRepository struct {
	loaded           Conversation
	found            bool
	loadErr          error
	saved            Conversation
	expectedRevision int64
	saveErr          error
	saveCalls        int
}

func (r *recordingConversationRepository) LoadConversation(context.Context, string, string) (Conversation, bool, error) {
	return cloneConversation(r.loaded), r.found, r.loadErr
}

func (r *recordingConversationRepository) SaveConversation(_ context.Context, conversation Conversation, expectedRevision int64) (Conversation, error) {
	r.saveCalls++
	r.saved = cloneConversation(conversation)
	r.expectedRevision = expectedRevision
	if r.saveErr != nil {
		return Conversation{}, r.saveErr
	}
	conversation.Revision = expectedRevision + 1
	return conversation, nil
}

type recordingModelFactory struct {
	client         modelapi.Client
	profile        modelapi.Profile
	secretResolver SecretResolver
}

func (r *recordingModelFactory) CreateModel(_ context.Context, profile modelapi.Profile, secrets SecretResolver) (modelapi.Client, error) {
	r.profile = profile
	r.secretResolver = secrets
	return r.client, nil
}

func testDependencies(engine Engine, conversations ConversationRepository, config RuntimeConfig) Dependencies {
	return Dependencies{
		Engine:        engine,
		Models:        &recordingModelFactory{client: inertModelClient{}},
		Tools:         ToolProviderFunc(func(context.Context, ToolRequest) ([]Tool, error) { return nil, nil }),
		Configs:       staticConfigRepository{config: config},
		Conversations: conversations,
		Secrets:       inertSecretResolver{},
		Clock:         func() time.Time { return time.Unix(10, 0).UTC() },
	}
}

func validTestConfig() RuntimeConfig {
	return RuntimeConfig{
		ModelProfile:        modelapi.Profile{Provider: modelapi.ProviderDeepSeek, Model: "test-model", SecretRef: "secret:model"},
		ContextMessageLimit: 32,
		MemoryMessageLimit:  12,
		MaxSteps:            4,
	}
}

func finalEngineResult(content string) EngineResult {
	message := modelapi.Message{Role: modelapi.RoleAssistant, Content: content}
	return EngineResult{Message: message, Produced: []modelapi.Message{message}, Steps: []Step{{Kind: StepModel}}}
}

func mustTestRuntime(t *testing.T, dependencies Dependencies) *Runtime {
	t.Helper()
	runtime, err := New(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func generatedSensitiveDetail(t *testing.T) string {
	t.Helper()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}
