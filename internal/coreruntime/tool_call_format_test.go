package coreruntime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

type toolCallFormatCompletionClient struct {
	completion coremodel.Completion
}

type toolCallFormatRequestClient struct {
	stream  coremodel.Stream
	request coremodel.CompletionRequest
}

func (c *toolCallFormatCompletionClient) Generate(context.Context, coremodel.CompletionRequest) (coremodel.Completion, error) {
	return c.completion, nil
}

func (*toolCallFormatCompletionClient) Stream(context.Context, coremodel.CompletionRequest) (coremodel.Stream, error) {
	return nil, errors.New("stream must not be used")
}

func (*toolCallFormatRequestClient) Generate(context.Context, coremodel.CompletionRequest) (coremodel.Completion, error) {
	return coremodel.Completion{}, errors.New("generate must not be used")
}

func (c *toolCallFormatRequestClient) Stream(_ context.Context, request coremodel.CompletionRequest) (coremodel.Stream, error) {
	c.request = request
	return c.stream, nil
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

func TestModelRunnerQuarantinesPrefixedTextEncodedToolCall(t *testing.T) {
	client := &streamClient{stream: &fakeStream{deltas: []coremodel.Delta{
		{Content: "再看关键文档和代码结构，然后给你总结。\n\n"},
		{Content: dsmlToolCallsEnvelope + "\n"},
		{Content: dsmlInvokePrefix + " name=\"lookup\">\n"},
	}}}
	runner, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	var public strings.Builder
	result, err := runner.Stream(context.Background(), modelToolProtocolTestRequest(), func(delta coreconversation.ModelDelta) error {
		public.WriteString(delta.Text)
		return nil
	})
	if !errors.Is(err, coremodel.ErrModelToolCallFormatInvalid) || public.Len() != 0 ||
		result.Message.ID != "" || len(result.ToolCalls) != 0 {
		t.Fatalf("result=%+v err=%v public=%q", result, err, public.String())
	}
}

func TestModelRunnerQuarantinesTruncatedBareEnvelopeAfterPreface(t *testing.T) {
	client := &streamClient{stream: &fakeStream{deltas: []coremodel.Delta{
		{Content: "I will inspect another file.\n\n"},
		{Content: dsmlToolCallsEnvelope + "\nprovider stream ended"},
	}}}
	runner, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	var public strings.Builder
	result, err := runner.Stream(context.Background(), modelToolProtocolTestRequest(), func(delta coreconversation.ModelDelta) error {
		public.WriteString(delta.Text)
		return nil
	})
	if !errors.Is(err, coremodel.ErrModelToolCallFormatInvalid) || public.Len() != 0 || result.Message.ID != "" {
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

func TestModelRunnerQuarantinesNonStreamingPrefixedTextEncodedToolCall(t *testing.T) {
	client := &toolCallFormatCompletionClient{completion: coremodel.Completion{Message: coremodel.Message{
		Role:    coremodel.RoleAssistant,
		Content: "I will inspect one more file.\n\n" + dsmlToolCallsEnvelope + "\n" + dsmlInvokePrefix + " name=\"lookup\">",
	}}}
	runner, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	result, err := runner.Run(context.Background(), modelToolProtocolTestRequest())
	if !errors.Is(err, coremodel.ErrModelToolCallFormatInvalid) || result.Message.ID != "" || len(result.ToolCalls) != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestModelRunnerKeepsGuardDuringToolFreeFinalization(t *testing.T) {
	request := modelToolProtocolTestRequest()
	request.Extensions = nil
	request.GuardTextToolCallEnvelope = true
	client := &streamClient{stream: &fakeStream{deltas: []coremodel.Delta{
		{Content: "\n" + dsmlToolCallsEnvelope},
		{Content: "\n" + dsmlInvokePrefix + " name=\"lookup\">"},
	}}}
	runner, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	var public strings.Builder
	result, err := runner.Stream(context.Background(), request, func(delta coreconversation.ModelDelta) error {
		public.WriteString(delta.Text)
		return nil
	})
	if !errors.Is(err, coremodel.ErrModelToolCallFormatInvalid) || public.Len() != 0 ||
		result.Message.ID != "" || len(result.ToolCalls) != 0 {
		t.Fatalf("result=%+v err=%v public=%q", result, err, public.String())
	}
}

func TestModelRunnerToolFreeGuardDoesNotHideOrdinaryRepositoryText(t *testing.T) {
	content := "Final summary: repository fixture contains " + dsmlToolCallsEnvelope + " as plain text."
	request := modelToolProtocolTestRequest()
	request.Extensions = nil
	request.GuardTextToolCallEnvelope = true
	client := &streamClient{stream: &fakeStream{deltas: []coremodel.Delta{{Content: content}}}}
	runner, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	var public strings.Builder
	result, err := runner.Stream(context.Background(), request, func(delta coreconversation.ModelDelta) error {
		public.WriteString(delta.Text)
		return nil
	})
	if err != nil || !result.Done || result.Message.Content != content || public.String() != content {
		t.Fatalf("result=%+v err=%v public=%q", result, err, public.String())
	}
}

func TestModelRunnerDoesNotTreatRepositoryTextAsToolProtocol(t *testing.T) {
	for _, content := range []string{
		"Repository fixture contains " + dsmlToolCallsEnvelope + " as plain text.",
		"```text\n" + dsmlToolCallsEnvelope + "\n" + dsmlInvokePrefix + " name=\"lookup\">\n```",
		"~~~text\n" + dsmlToolCallsEnvelope + "\n" + dsmlInvokePrefix + " name=\"lookup\">\n~~~",
		"> " + dsmlToolCallsEnvelope + "\n> " + dsmlInvokePrefix + " name=\"lookup\">",
		"Repository token `" + dsmlToolCallsEnvelope + "` followed by `" + dsmlInvokePrefix + "` is documentation.",
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

func TestModelRunnerPublishesOnlyValidatedFinalText(t *testing.T) {
	client := &streamClient{stream: &fakeStream{deltas: []coremodel.Delta{
		{Content: "validated "},
		{Content: "answer"},
	}}}
	runner, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	var public []string
	privateProgress := 0
	result, err := runner.Stream(context.Background(), modelToolProtocolTestRequest(), func(delta coreconversation.ModelDelta) error {
		if delta.PrivateProgress {
			privateProgress++
		}
		if delta.Text != "" {
			public = append(public, delta.Text)
		}
		return nil
	})
	if err != nil || !result.Done || result.Message.Content != "validated answer" ||
		privateProgress != 2 || len(public) != 1 || public[0] != "validated answer" {
		t.Fatalf("result=%+v err=%v private_progress=%d public=%q", result, err, privateProgress, public)
	}
}

func TestModelRunnerAppliesDeepSeekStructuredToolProtocolBeforeFirstCall(t *testing.T) {
	request := modelToolProtocolTestRequest()
	request.Snapshot.BaseURL = "https://api.deepseek.com/v1"
	request.Snapshot.Model = "deepseek-v4-flash"
	request.Snapshot.SystemPrompt = "base policy"
	client := &toolCallFormatRequestClient{stream: &fakeStream{deltas: []coremodel.Delta{{Content: "normal answer"}}}}
	var captured coremodel.Profile
	runner, _ := NewModelRunner(func(profile coremodel.Profile) (coremodel.Client, error) {
		captured = profile
		return client, nil
	})
	result, err := runner.Stream(context.Background(), request, nil)
	if err != nil || !result.Done || client.request.ToolChoice != coremodel.ToolChoiceAuto ||
		!strings.Contains(captured.SystemPrompt, "OpenAI-compatible structured tool protocol") ||
		!strings.Contains(captured.SystemPrompt, "Never emit DSML") {
		t.Fatalf("result=%+v err=%v tool_choice=%q system_prompt=%q", result, err, client.request.ToolChoice, captured.SystemPrompt)
	}
}

func TestModelRunnerRecognizesDeepSeekBehindCompatibleGateway(t *testing.T) {
	request := modelToolProtocolTestRequest()
	request.Snapshot.Model = "deepseek/deepseek-v4-pro"
	client := &toolCallFormatRequestClient{stream: &fakeStream{deltas: []coremodel.Delta{{Content: "normal answer"}}}}
	var captured coremodel.Profile
	runner, _ := NewModelRunner(func(profile coremodel.Profile) (coremodel.Client, error) {
		captured = profile
		return client, nil
	})
	result, err := runner.Stream(context.Background(), request, nil)
	if err != nil || !result.Done || client.request.ToolChoice != coremodel.ToolChoiceAuto ||
		!strings.Contains(captured.SystemPrompt, "OpenAI-compatible structured tool protocol") {
		t.Fatalf("result=%+v err=%v tool_choice=%q system_prompt=%q", result, err, client.request.ToolChoice, captured.SystemPrompt)
	}
}

func TestModelRunnerOmitsToolChoiceForDeepSeekThinkingMode(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovery=%t", recovery), func(t *testing.T) {
			request := modelToolProtocolTestRequest()
			request.Snapshot.BaseURL = "https://api.deepseek.com/v1"
			request.Snapshot.Model = "deepseek-v4-pro"
			request.Snapshot.RequestDialect = coremodel.DialectOpenAIReasoningChatV1
			request.ToolCallFormatRecovery = recovery
			client := &toolCallFormatRequestClient{stream: &fakeStream{deltas: []coremodel.Delta{{Content: "normal answer"}}}}
			var captured coremodel.Profile
			runner, _ := NewModelRunner(func(profile coremodel.Profile) (coremodel.Client, error) {
				captured = profile
				return client, nil
			})
			result, err := runner.Stream(context.Background(), request, nil)
			if err != nil || !result.Done || client.request.ToolChoice != "" ||
				!strings.Contains(captured.SystemPrompt, "OpenAI-compatible structured tool protocol") {
				t.Fatalf("result=%+v err=%v request=%+v system_prompt=%q", result, err, client.request, captured.SystemPrompt)
			}
			if recovery && !strings.Contains(captured.SystemPrompt, "standard OpenAI-compatible message.tool_calls") {
				t.Fatalf("recovery guidance missing: %q", captured.SystemPrompt)
			}
		})
	}
}

func TestModelRunnerKeepsNamedToolChoiceStrongerThanDeepSeekMode(t *testing.T) {
	request := modelToolProtocolTestRequest()
	request.Snapshot.BaseURL = "https://api.deepseek.com/v1"
	request.Snapshot.Model = "deepseek-v4-flash"
	request.ForcedToolName = "lookup"
	client := &toolCallFormatRequestClient{stream: &fakeStream{deltas: []coremodel.Delta{{
		ToolCalls: []coremodel.ToolCall{{Index: 0, ID: "call-1", Type: "function", Function: coremodel.FunctionCall{Name: "lookup", Arguments: `{}`}}},
	}}}}
	runner, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	result, err := runner.Stream(context.Background(), request, nil)
	if err != nil || result.Done || client.request.ToolChoice != "" || client.request.ForcedToolName != "lookup" || len(result.ToolCalls) != 1 {
		t.Fatalf("result=%+v err=%v request=%+v", result, err, client.request)
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

func TestModelRunnerKeepsToolStepNarrationPrivate(t *testing.T) {
	const narration = "I will inspect the repository now."
	client := &streamClient{stream: &fakeStream{deltas: []coremodel.Delta{
		{Content: narration},
		{ToolCalls: []coremodel.ToolCall{{Index: 0, ID: "call-1", Type: "function", Function: coremodel.FunctionCall{Name: "lookup", Arguments: `{}`}}}},
	}}}
	runner, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	var public strings.Builder
	result, err := runner.Stream(context.Background(), modelToolProtocolTestRequest(), func(delta coreconversation.ModelDelta) error {
		public.WriteString(delta.Text)
		return nil
	})
	if err != nil || result.Done || result.Message.Content != narration || len(result.ToolCalls) != 1 ||
		result.ToolCalls[0].Name != "lookup" || public.Len() != 0 {
		t.Fatalf("result=%+v err=%v public=%q", result, err, public.String())
	}
}

func TestModelRunnerKeepsNonStreamingToolStepNarrationPrivate(t *testing.T) {
	const narration = "I will inspect the repository now."
	client := &toolCallFormatCompletionClient{completion: coremodel.Completion{Message: coremodel.Message{
		Role:    coremodel.RoleAssistant,
		Content: narration,
		ToolCalls: []coremodel.ToolCall{{
			ID: "call-1", Type: "function", Function: coremodel.FunctionCall{Name: "lookup", Arguments: `{}`},
		}},
	}}}
	runner, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	result, err := runner.Run(context.Background(), modelToolProtocolTestRequest())
	if err != nil || result.Done || result.Message.Content != narration || len(result.ToolCalls) != 1 || result.ToolCalls[0].Name != "lookup" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestModelRunnerKeepsTruncatedToolStepNarrationPrivate(t *testing.T) {
	const narration = "I will inspect the repository now."
	client := &streamClient{stream: &fakeStream{deltas: []coremodel.Delta{{
		Content: narration,
		ToolCalls: []coremodel.ToolCall{{
			Index: 0, ID: "call-1", Type: "function", Function: coremodel.FunctionCall{Name: "lookup", Arguments: `{"path":"cut`},
		}},
	}}, err: coremodel.ErrOutputLimitReached}}
	runner, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	var public strings.Builder
	result, err := runner.Stream(context.Background(), modelToolProtocolTestRequest(), func(delta coreconversation.ModelDelta) error {
		public.WriteString(delta.Text)
		return nil
	})
	if err != nil || !result.Continue || result.Done || result.Message.Content != narration ||
		len(result.ToolCalls) != 0 || len(result.Message.ToolCalls) != 0 || public.Len() != 0 {
		t.Fatalf("result=%+v err=%v public=%q", result, err, public.String())
	}
}

func TestModelRunnerAddsFixedRecoveryInstruction(t *testing.T) {
	request := modelToolProtocolTestRequest()
	request.ToolCallFormatRecovery = true
	request.Snapshot.SystemPrompt = "base policy"
	var captured coremodel.Profile
	client := &toolCallFormatRequestClient{stream: &fakeStream{deltas: []coremodel.Delta{{Content: "normal answer"}}}}
	runner, _ := NewModelRunner(func(profile coremodel.Profile) (coremodel.Client, error) {
		captured = profile
		return client, nil
	})
	result, err := runner.Stream(context.Background(), request, nil)
	if err != nil || !result.Done || client.request.ToolChoice != coremodel.ToolChoiceRequired ||
		!strings.HasPrefix(captured.SystemPrompt, "base policy\n\n") ||
		!strings.Contains(captured.SystemPrompt, "standard OpenAI-compatible message.tool_calls") ||
		!strings.Contains(captured.SystemPrompt, "Do not put DSML") {
		t.Fatalf("result=%+v err=%v tool_choice=%q system_prompt=%q", result, err, client.request.ToolChoice, captured.SystemPrompt)
	}
}

func TestModelRunnerAddsToolFreeRecoveryInstructionWithoutRestoringAuthority(t *testing.T) {
	request := modelToolProtocolTestRequest()
	request.Extensions = nil
	request.GuardTextToolCallEnvelope = true
	request.ToolCallFormatRecovery = true
	request.Snapshot.SystemPrompt = "base policy"
	var captured coremodel.Profile
	client := &toolCallFormatRequestClient{stream: &fakeStream{deltas: []coremodel.Delta{{Content: "normal final answer"}}}}
	runner, _ := NewModelRunner(func(profile coremodel.Profile) (coremodel.Client, error) {
		captured = profile
		return client, nil
	})
	result, err := runner.Stream(context.Background(), request, nil)
	if err != nil || !result.Done || len(client.request.Tools) != 0 ||
		!strings.Contains(captured.SystemPrompt, "tools are disabled for this final response") ||
		!strings.Contains(captured.SystemPrompt, "Do not put DSML") {
		t.Fatalf("result=%+v err=%v tools=%+v system_prompt=%q", result, err, client.request.Tools, captured.SystemPrompt)
	}
}
