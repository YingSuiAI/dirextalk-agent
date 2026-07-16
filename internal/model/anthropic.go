package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

const anthropicVersion = "2023-06-01"

func (c *client) anthropicRequestPayload(request CompletionRequest, stream bool) (map[string]any, error) {
	var system []string
	messages := make([]map[string]any, 0, len(request.Messages))
	for _, message := range request.Messages {
		if !validRole(message.Role) {
			return nil, fmt.Errorf("invalid model message role %q", message.Role)
		}
		if message.Role == RoleSystem {
			if strings.TrimSpace(message.Content) != "" {
				system = append(system, strings.TrimSpace(message.Content))
			}
			continue
		}
		if message.Role == RoleTool {
			messages = append(messages, map[string]any{
				"role": "user",
				"content": []map[string]any{{
					"type":        "tool_result",
					"tool_use_id": message.ToolCallID,
					"content":     message.Content,
				}},
			})
			continue
		}
		content := make([]map[string]any, 0, len(message.ToolCalls)+1)
		if message.Content != "" {
			content = append(content, map[string]any{"type": "text", "text": message.Content})
		}
		for _, call := range message.ToolCalls {
			var input any = map[string]any{}
			if strings.TrimSpace(call.Function.Arguments) != "" {
				if err := json.Unmarshal([]byte(call.Function.Arguments), &input); err != nil {
					return nil, fmt.Errorf("invalid tool call arguments for %q", call.Function.Name)
				}
			}
			content = append(content, map[string]any{
				"type":  "tool_use",
				"id":    call.ID,
				"name":  call.Function.Name,
				"input": input,
			})
		}
		if len(content) == 0 {
			content = append(content, map[string]any{"type": "text", "text": ""})
		}
		messages = append(messages, map[string]any{"role": string(message.Role), "content": content})
	}

	maxTokens := c.profile.MaxOutputTokens
	if maxTokens <= 0 {
		maxTokens = 2048
	}
	payload := map[string]any{
		"model":      c.profile.Model,
		"messages":   messages,
		"max_tokens": maxTokens,
	}
	if len(system) > 0 {
		payload["system"] = strings.Join(system, "\n\n")
	}
	if stream {
		payload["stream"] = true
	}
	if c.profile.Temperature != nil {
		payload["temperature"] = *c.profile.Temperature
	}
	if c.profile.TopP != nil {
		payload["top_p"] = *c.profile.TopP
	}
	if len(request.Tools) > 0 {
		tools := make([]map[string]any, 0, len(request.Tools))
		for _, tool := range request.Tools {
			schema := tool.InputSchema
			if schema == nil {
				schema = map[string]any{"type": "object"}
			}
			tools = append(tools, map[string]any{
				"name":         tool.Name,
				"description":  tool.Description,
				"input_schema": schema,
			})
		}
		payload["tools"] = tools
	}
	return payload, nil
}

func (c *client) decodeAnthropicCompletion(body []byte) (Completion, error) {
	var response struct {
		Content []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return Completion{}, fmt.Errorf("decode model provider response: %w", err)
	}
	message := Message{Role: RoleAssistant}
	var content strings.Builder
	for _, block := range response.Content {
		switch block.Type {
		case "text":
			content.WriteString(block.Text)
		case "tool_use":
			message.ToolCalls = append(message.ToolCalls, ToolCall{
				ID:   block.ID,
				Type: "function",
				Function: FunctionCall{
					Name:      block.Name,
					Arguments: rawArguments(block.Input),
				},
			})
		}
	}
	message.Content = content.String()
	return Completion{
		Message: message,
		Usage: Usage{
			InputTokens:  response.Usage.InputTokens,
			OutputTokens: response.Usage.OutputTokens,
			TotalTokens:  response.Usage.InputTokens + response.Usage.OutputTokens,
		},
	}, nil
}

func (c *client) decodeAnthropicDelta(data json.RawMessage) (Delta, bool, error) {
	var event struct {
		Type         string          `json:"type"`
		Index        int             `json:"index"`
		Error        json.RawMessage `json:"error"`
		ContentBlock *struct {
			Type  string          `json:"type"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content_block"`
		Delta *struct {
			Type        string `json:"type"`
			Text        string `json:"text"`
			Thinking    string `json:"thinking"`
			PartialJSON string `json:"partial_json"`
		} `json:"delta"`
	}
	if err := json.Unmarshal(data, &event); err != nil {
		return Delta{}, false, fmt.Errorf("decode model provider stream: %w", err)
	}
	if event.Type == "error" || (len(event.Error) > 0 && string(event.Error) != "null") {
		return Delta{}, false, ErrProviderUnavailable
	}
	switch event.Type {
	case "content_block_start":
		if event.ContentBlock == nil || event.ContentBlock.Type != "tool_use" {
			return Delta{}, false, nil
		}
		return Delta{ToolCalls: []ToolCall{{
			Index: event.Index,
			ID:    event.ContentBlock.ID,
			Type:  "function",
			Function: FunctionCall{
				Name:      event.ContentBlock.Name,
				Arguments: rawArguments(event.ContentBlock.Input),
			},
		}}}, true, nil
	case "content_block_delta":
		if event.Delta == nil {
			return Delta{}, false, nil
		}
		switch event.Delta.Type {
		case "text_delta":
			return Delta{Content: event.Delta.Text}, event.Delta.Text != "", nil
		case "thinking_delta":
			return Delta{ReasoningContent: event.Delta.Thinking}, event.Delta.Thinking != "", nil
		case "input_json_delta":
			return Delta{ToolCalls: []ToolCall{{Index: event.Index, Type: "function", Function: FunctionCall{Arguments: event.Delta.PartialJSON}}}}, event.Delta.PartialJSON != "", nil
		}
	}
	return Delta{}, false, nil
}
