package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

func (c *client) openAIRequestPayload(request CompletionRequest, stream bool) (map[string]any, error) {
	messages := make([]map[string]any, 0, len(request.Messages))
	for _, message := range request.Messages {
		if !validRole(message.Role) {
			return nil, fmt.Errorf("invalid model message role %q", message.Role)
		}
		encoded := map[string]any{"role": string(message.Role)}
		if message.Content != "" || len(message.ToolCalls) == 0 {
			encoded["content"] = message.Content
		}
		if message.Name != "" {
			encoded["name"] = message.Name
		}
		if message.ToolCallID != "" {
			encoded["tool_call_id"] = message.ToolCallID
		}
		if len(message.ToolCalls) > 0 {
			encoded["tool_calls"] = openAIToolCalls(message.ToolCalls)
		}
		messages = append(messages, encoded)
	}
	payload := map[string]any{
		"model":    c.profile.Model,
		"messages": messages,
	}
	if stream {
		payload["stream"] = true
	}
	if c.profile.MaxOutputTokens > 0 {
		payload["max_tokens"] = c.profile.MaxOutputTokens
	}
	if c.profile.Temperature != nil {
		payload["temperature"] = *c.profile.Temperature
	}
	if c.profile.TopP != nil {
		payload["top_p"] = *c.profile.TopP
	}
	if c.profile.ReasoningEffort != "" {
		payload["reasoning_effort"] = c.profile.ReasoningEffort
	}
	if len(request.Tools) > 0 {
		payload["tools"] = openAITools(request.Tools)
	}
	return payload, nil
}

func openAITools(tools []Tool) []map[string]any {
	result := make([]map[string]any, 0, len(tools))
	for _, tool := range tools {
		schema := tool.InputSchema
		if schema == nil {
			schema = map[string]any{"type": "object"}
		}
		result = append(result, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        tool.Name,
				"description": tool.Description,
				"parameters":  schema,
			},
		})
	}
	return result
}

func openAIToolCalls(calls []ToolCall) []map[string]any {
	result := make([]map[string]any, 0, len(calls))
	for _, call := range calls {
		callType := call.Type
		if callType == "" {
			callType = "function"
		}
		result = append(result, map[string]any{
			"id":   call.ID,
			"type": callType,
			"function": map[string]any{
				"name":      call.Function.Name,
				"arguments": call.Function.Arguments,
			},
		})
	}
	return result
}

func (c *client) decodeOpenAICompletion(body []byte) (Completion, error) {
	var response struct {
		Choices []struct {
			Message openAIResponseMessage `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return Completion{}, fmt.Errorf("decode model provider response: %w", err)
	}
	if len(response.Choices) == 0 {
		return Completion{}, fmt.Errorf("model provider returned no completion choices")
	}
	return Completion{
		Message: response.Choices[0].Message.message(),
		Usage: Usage{
			InputTokens:  response.Usage.PromptTokens,
			OutputTokens: response.Usage.CompletionTokens,
			TotalTokens:  response.Usage.TotalTokens,
		},
	}, nil
}

type openAIResponseMessage struct {
	Role             Role             `json:"role"`
	Content          json.RawMessage  `json:"content"`
	ReasoningContent string           `json:"reasoning_content"`
	ToolCalls        []openAIToolCall `json:"tool_calls"`
}

type openAIToolCall struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

func (message openAIResponseMessage) message() Message {
	role := message.Role
	if role == "" {
		role = RoleAssistant
	}
	return Message{
		Role:             role,
		Content:          rawText(message.Content),
		ReasoningContent: message.ReasoningContent,
		ToolCalls:        decodedOpenAIToolCalls(message.ToolCalls),
	}
}

func decodedOpenAIToolCalls(calls []openAIToolCall) []ToolCall {
	result := make([]ToolCall, 0, len(calls))
	for _, call := range calls {
		callType := call.Type
		if callType == "" {
			callType = "function"
		}
		result = append(result, ToolCall{
			Index: call.Index,
			ID:    call.ID,
			Type:  callType,
			Function: FunctionCall{
				Name:      call.Function.Name,
				Arguments: rawArguments(call.Function.Arguments),
			},
		})
	}
	return result
}

func (c *client) decodeOpenAIDelta(data json.RawMessage) (Delta, bool, error) {
	var response struct {
		Error   json.RawMessage `json:"error"`
		Choices []struct {
			Delta openAIResponseMessage `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return Delta{}, false, fmt.Errorf("decode model provider stream: %w", err)
	}
	if len(response.Error) > 0 && string(response.Error) != "null" {
		return Delta{}, false, ErrProviderUnavailable
	}
	if len(response.Choices) == 0 {
		return Delta{}, false, nil
	}
	message := response.Choices[0].Delta
	delta := Delta{
		Content:          rawText(message.Content),
		ReasoningContent: message.ReasoningContent,
		ToolCalls:        decodedOpenAIToolCalls(message.ToolCalls),
	}
	return delta, delta.Content != "" || delta.ReasoningContent != "" || len(delta.ToolCalls) > 0, nil
}

func rawText(value json.RawMessage) string {
	if len(value) == 0 || string(value) == "null" {
		return ""
	}
	var text string
	if json.Unmarshal(value, &text) == nil {
		return text
	}
	var blocks []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(value, &blocks) == nil {
		var result strings.Builder
		for _, block := range blocks {
			result.WriteString(block.Text)
		}
		return result.String()
	}
	return ""
}

func rawArguments(value json.RawMessage) string {
	if len(value) == 0 || string(value) == "null" {
		return ""
	}
	var arguments string
	if json.Unmarshal(value, &arguments) == nil {
		return arguments
	}
	return string(value)
}

func validRole(role Role) bool {
	switch role {
	case RoleSystem, RoleUser, RoleAssistant, RoleTool:
		return true
	default:
		return false
	}
}
