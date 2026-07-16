package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
)

func TestChatTrimsOversizedHistoryToProfileContextBudget(t *testing.T) {
	t.Parallel()

	config := validTestConfig()
	config.ModelProfile.ContextWindow = 2048
	config.ModelProfile.MaxOutputTokens = 256
	conversation := &recordingConversationRepository{
		found: true,
		loaded: Conversation{
			OwnerID: "owner-1", ConversationID: "conversation-1", Revision: 3,
			Messages: []modelapi.Message{
				{Role: modelapi.RoleUser, Content: "old question " + strings.Repeat("x", 4000)},
				{Role: modelapi.RoleAssistant, Content: "old answer " + strings.Repeat("y", 4000)},
			},
		},
	}
	engine := &scriptedEngine{generate: func(_ context.Context, request EngineRequest) (EngineResult, error) {
		budget, ok := modelInputByteBudget(config.ModelProfile, request.Tools)
		if !ok || modelMessagesBytes(request.Messages) > budget {
			t.Fatalf("messages exceeded profile context budget: bytes=%d budget=%d", modelMessagesBytes(request.Messages), budget)
		}
		if len(request.Messages) >= 4 || request.Messages[0].Role != modelapi.RoleSystem || request.Messages[len(request.Messages)-1].Role != modelapi.RoleUser || request.Messages[len(request.Messages)-1].Content != "latest question" {
			t.Fatalf("runtime did not trim history while preserving system/latest-user input: %#v", request.Messages)
		}
		for _, message := range request.Messages {
			if strings.HasPrefix(message.Content, "old question ") {
				t.Fatalf("oldest oversized history survived context compaction: %#v", request.Messages)
			}
		}
		return finalEngineResult("ok"), nil
	}}
	runtime := mustTestRuntime(t, testDependencies(engine, conversation, config))

	_, err := runtime.Chat(context.Background(), ChatRequest{
		RequestID: "context-budget-1", OwnerID: "owner-1", ConversationID: "conversation-1",
		ExpectedConversationRevision: 3,
		Messages:                     []modelapi.Message{{Role: modelapi.RoleUser, Content: "latest question"}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCompactModelMessagesKeepsOrDropsCompleteToolGroups(t *testing.T) {
	t.Parallel()

	calls := []modelapi.ToolCall{
		{ID: "call-a", Type: "function", Function: modelapi.FunctionCall{Name: "first", Arguments: `{}`}},
		{ID: "call-b", Type: "function", Function: modelapi.FunctionCall{Name: "second", Arguments: `{}`}},
	}
	messages := []modelapi.Message{
		{Role: modelapi.RoleSystem, Content: immutableBasePolicy},
		{Role: modelapi.RoleUser, Content: "older"},
		{Role: modelapi.RoleAssistant, ToolCalls: calls},
		{Role: modelapi.RoleTool, ToolCallID: "call-a", Name: "first", Content: "a"},
		{Role: modelapi.RoleTool, ToolCallID: "call-b", Name: "second", Content: "b"},
		{Role: modelapi.RoleUser, Content: "latest"},
	}

	kept, ok := compactModelMessages(messages, 4, 0)
	if !ok || len(kept) != 5 || kept[1].Role != modelapi.RoleAssistant || len(kept[1].ToolCalls) != 2 || kept[2].ToolCallID != "call-a" || kept[3].ToolCallID != "call-b" || kept[4].Content != "latest" {
		t.Fatalf("complete tool group was not retained atomically: ok=%v messages=%#v", ok, kept)
	}

	dropped, ok := compactModelMessages(messages, 3, 0)
	if !ok || len(dropped) != 2 || dropped[0].Role != modelapi.RoleSystem || dropped[1].Role != modelapi.RoleUser || dropped[1].Content != "latest" {
		t.Fatalf("oversized tool group was not dropped atomically: ok=%v messages=%#v", ok, dropped)
	}
}

func TestChatRejectsRequiredInputThatCannotFitBeforeModelCreation(t *testing.T) {
	t.Parallel()

	config := validTestConfig()
	config.MemoryDisabled = true
	config.ModelProfile.ContextWindow = 512
	config.ModelProfile.MaxOutputTokens = 128
	config.EnabledTools = []string{"network-tool"}
	engine := &scriptedEngine{}
	factory := &recordingModelFactory{client: inertModelClient{}}
	dependencies := testDependencies(engine, &recordingConversationRepository{}, config)
	dependencies.Models = factory
	toolProviderCalls := 0
	dependencies.Tools = ToolProviderFunc(func(context.Context, ToolRequest) ([]Tool, error) {
		toolProviderCalls++
		return nil, errors.New("must not discover network tools")
	})
	runtime := mustTestRuntime(t, dependencies)

	_, err := runtime.Chat(context.Background(), ChatRequest{
		RequestID: "context-budget-2", OwnerID: "owner-1",
		Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: strings.Repeat("z", 4000)}},
	})
	if !errors.Is(err, ErrInvalidRequest) || !strings.Contains(err.Error(), "context window") {
		t.Fatalf("oversized mandatory input did not fail closed: %v", err)
	}
	if engine.generateCalls != 0 || factory.secretResolver != nil || toolProviderCalls != 0 {
		t.Fatalf("oversized input crossed an outbound boundary: engine=%d model_created=%v tool_discovery=%d", engine.generateCalls, factory.secretResolver != nil, toolProviderCalls)
	}
}

func TestRewriteMessagesReappliesByteBudgetWithoutOrphanedToolOutput(t *testing.T) {
	t.Parallel()

	config := validTestConfig()
	config.MemoryDisabled = true
	config.ModelProfile.ContextWindow = 2048
	config.ModelProfile.MaxOutputTokens = 256
	engine := &scriptedEngine{generate: func(_ context.Context, request EngineRequest) (EngineResult, error) {
		call := modelapi.ToolCall{
			ID: "large-call", Type: "function",
			Function: modelapi.FunctionCall{Name: "lookup", Arguments: `{"payload":"` + strings.Repeat("a", 6000) + `"}`},
		}
		round := append(cloneMessages(request.Messages),
			modelapi.Message{Role: modelapi.RoleAssistant, ToolCalls: []modelapi.ToolCall{call}},
			modelapi.Message{Role: modelapi.RoleTool, ToolCallID: call.ID, Name: "lookup", Content: strings.Repeat("b", 6000)},
		)
		rewritten := request.RewriteMessages(round)
		budget, ok := modelInputByteBudget(config.ModelProfile, request.Tools)
		if !ok || modelMessagesBytes(rewritten) > budget {
			t.Fatalf("rewritten round exceeded budget: bytes=%d budget=%d", modelMessagesBytes(rewritten), budget)
		}
		if len(rewritten) != 2 || rewritten[0].Role != modelapi.RoleSystem || rewritten[1].Role != modelapi.RoleUser || rewritten[1].Content != "latest" {
			t.Fatalf("secondary rewrite retained an orphan or lost mandatory input: %#v", rewritten)
		}
		return finalEngineResult("ok"), nil
	}}
	runtime := mustTestRuntime(t, testDependencies(engine, &recordingConversationRepository{}, config))

	_, err := runtime.Chat(context.Background(), ChatRequest{
		RequestID: "context-budget-3", OwnerID: "owner-1",
		Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "latest"}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestContextBoundModelClientRejectsMissingRequiredSystemBeforeProvider(t *testing.T) {
	t.Parallel()

	provider := &countingProviderClient{}
	client := contextBoundModelClient{
		delegate: provider,
		profile: modelapi.Profile{
			ContextWindow:   2048,
			MaxOutputTokens: 256,
		},
		messageLimit: 8,
	}
	_, err := client.Generate(context.Background(), modelapi.CompletionRequest{
		Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "engine removed the immutable system prompt"}},
	})
	if !errors.Is(err, ErrInvalidRequest) || provider.calls != 0 {
		t.Fatalf("invalid rewritten input crossed provider boundary: err=%v calls=%d", err, provider.calls)
	}
}

type countingProviderClient struct {
	calls int
}

func (c *countingProviderClient) Generate(context.Context, modelapi.CompletionRequest) (modelapi.Completion, error) {
	c.calls++
	return modelapi.Completion{}, nil
}

func (c *countingProviderClient) Stream(context.Context, modelapi.CompletionRequest) (modelapi.Stream, error) {
	c.calls++
	return nil, nil
}
