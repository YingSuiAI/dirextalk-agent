package coreruntime

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

type toolCallFormatCompletionClient struct {
	completion coremodel.Completion
}

func (c *toolCallFormatCompletionClient) Generate(context.Context, coremodel.CompletionRequest) (coremodel.Completion, error) {
	return c.completion, nil
}

func (*toolCallFormatCompletionClient) Stream(context.Context, coremodel.CompletionRequest) (coremodel.Stream, error) {
	return nil, errors.New("stream must not be used")
}

func modelToolProtocolTestRequest() coreconversation.ModelRunRequest {
	const profileID = "00000000-0000-4000-8000-000000000071"
	return coreconversation.ModelRunRequest{
		Snapshot: coremodel.SnapshotFromProfile(coremodel.Profile{
			ID: profileID, DisplayName: "protocol", Provider: coremodel.ProviderOpenAICompatible,
			RequestDialect: coremodel.DialectOpenAICompatibleChatV1,
			BaseURL:        "https://example.test/v1", Model: "model", APIKey: "secret", Revision: 1, CredentialVersion: 1,
		}),
		Conversation: coreconversation.Conversation{Messages: []coreconversation.Message{{Role: coreconversation.RoleUser, Content: "inspect"}}},
		Extensions: []coreconversation.ResolvedExtension{{
			Selection: coreconversation.ExtensionSelection{Kind: coreconversation.ExtensionMCP},
			Tools: []coremodel.Tool{{
				Name: "lookup", Description: "read", InputSchema: map[string]any{"type": "object", "additionalProperties": false},
			}},
		}},
	}
}

func TestModelRunnerQuarantinesTextEncodedToolCall(t *testing.T) {
	client := &streamClient{stream: &fakeStream{deltas: []coremodel.Delta{
		{Content: " \n<｜｜DSML｜｜tool_"},
		{Content: "calls>\n<｜｜DSML｜｜invoke name=\"lookup\">\n"},
		{Content: "<｜｜DSML｜｜parameter name=\"path\" string=\"true\">docs</｜｜DSML｜｜parameter>"},
	}}}
	runner, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	var public strings.Builder
	result, err := runner.Stream(context.Background(), modelToolProtocolTestRequest(), func(delta coreconversation.ModelDelta) error {
		public.WriteString(delta.Text)
		return nil
	})
	if !errors.Is(err, coremodel.ErrModelToolCallFormatInvalid) || public.Len() != 0 ||
		result.Message.ID != "" || len(result.ToolCalls) != 0 || result.Done || result.Continue {
		t.Fatalf("result=%+v err=%v public=%q", result, err, public.String())
	}
}

func TestModelRunnerQuarantinesNonStreamingTextEncodedToolCall(t *testing.T) {
	client := &toolCallFormatCompletionClient{completion: coremodel.Completion{Message: coremodel.Message{
		Role:    coremodel.RoleAssistant,
		Content: dsmlToolCallsEnvelope + "\n" + dsmlInvokePrefix + " name=\"lookup\">",
	}}}
	runner, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	result, err := runner.Run(context.Background(), modelToolProtocolTestRequest())
	if !errors.Is(err, coremodel.ErrModelToolCallFormatInvalid) || result.Message.ID != "" || len(result.ToolCalls) != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestModelRunnerDoesNotTreatRepositoryTextAsToolProtocol(t *testing.T) {
	for _, content := range []string{
		"Repository fixture contains " + dsmlToolCallsEnvelope + " as plain text.",
		"```text\n" + dsmlToolCallsEnvelope + "\n" + dsmlInvokePrefix + " name=\"lookup\">\n```",
	} {
		t.Run(content[:4], func(t *testing.T) {
			client := &streamClient{stream: &fakeStream{deltas: []coremodel.Delta{{Content: content}}}}
			runner, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
			var public strings.Builder
			result, err := runner.Stream(context.Background(), modelToolProtocolTestRequest(), func(delta coreconversation.ModelDelta) error {
				public.WriteString(delta.Text)
				return nil
			})
			if err != nil || !result.Done || result.Message.Content != content || public.String() != content {
				t.Fatalf("result=%+v err=%v public=%q", result, err, public.String())
			}
		})
	}
}

func TestModelRunnerKeepsStructuredCallsAuthoritative(t *testing.T) {
	client := &streamClient{stream: &fakeStream{deltas: []coremodel.Delta{
		{Content: dsmlToolCallsEnvelope + "\n" + dsmlInvokePrefix + " name=\"lookup\">"},
		{ToolCalls: []coremodel.ToolCall{{Index: 0, ID: "call-1", Type: "function", Function: coremodel.FunctionCall{Name: "lookup", Arguments: `{}`}}}},
	}}}
	runner, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	var public strings.Builder
	result, err := runner.Stream(context.Background(), modelToolProtocolTestRequest(), func(delta coreconversation.ModelDelta) error {
		public.WriteString(delta.Text)
		return nil
	})
	if err != nil || result.Done || result.Message.Content != "" || len(result.ToolCalls) != 1 || result.ToolCalls[0].Name != "lookup" || public.Len() != 0 {
		t.Fatalf("result=%+v err=%v public=%q", result, err, public.String())
	}
}

func TestModelRunnerAddsFixedRecoveryInstruction(t *testing.T) {
	request := modelToolProtocolTestRequest()
	request.ToolCallFormatRecovery = true
	request.Snapshot.SystemPrompt = "base policy"
	var captured coremodel.Profile
	client := &streamClient{stream: &fakeStream{deltas: []coremodel.Delta{{Content: "normal answer"}}}}
	runner, _ := NewModelRunner(func(profile coremodel.Profile) (coremodel.Client, error) {
		captured = profile
		return client, nil
	})
	result, err := runner.Stream(context.Background(), request, nil)
	if err != nil || !result.Done || !strings.HasPrefix(captured.SystemPrompt, "base policy\n\n") ||
		!strings.Contains(captured.SystemPrompt, "standard OpenAI-compatible message.tool_calls") ||
		!strings.Contains(captured.SystemPrompt, "Do not put DSML") {
		t.Fatalf("result=%+v err=%v system_prompt=%q", result, err, captured.SystemPrompt)
	}
}
