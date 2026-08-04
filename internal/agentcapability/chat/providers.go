package chat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/cloudwego/eino/schema"
)

// ModelProvider manages different LLM providers
type ModelProvider struct {
	httpClient *http.Client
}

func NewModelProvider() *ModelProvider {
	return &ModelProvider{
		httpClient: &http.Client{},
	}
}

// AnthropicProvider implements Anthropic Claude API
func (p *ModelProvider) CallAnthropic(ctx context.Context, profile *ModelProfile, messages []*schema.Message) (*schema.Message, error) {
	endpoint := "https://api.anthropic.com/v1/messages"

	// Convert messages to Anthropic format
	anthropicMessages := make([]map[string]interface{}, 0, len(messages))
	for _, msg := range messages {
		anthropicMessages = append(anthropicMessages, map[string]interface{}{
			"role":    msg.Role,
			"content": msg.Content,
		})
	}

	reqBody := map[string]interface{}{
		"model":       profile.Model,
		"messages":    anthropicMessages,
		"max_tokens":  profile.MaxTokens,
		"temperature": profile.Temperature,
	}

	reqJSON, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(string(reqJSON)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", profile.Config["api_key"].(string))
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("anthropic API error: %d - %s", resp.StatusCode, string(body))
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Role string `json:"role"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	content := ""
	if len(result.Content) > 0 {
		content = result.Content[0].Text
	}

	return &schema.Message{
		Role:    result.Role,
		Content: content,
	}, nil
}

// StreamAnthropic implements streaming for Anthropic
func (p *ModelProvider) StreamAnthropic(ctx context.Context, profile *ModelProfile, messages []*schema.Message) (<-chan *MessageChunk, error) {
	endpoint := "https://api.anthropic.com/v1/messages"

	anthropicMessages := make([]map[string]interface{}, 0, len(messages))
	for _, msg := range messages {
		anthropicMessages = append(anthropicMessages, map[string]interface{}{
			"role":    msg.Role,
			"content": msg.Content,
		})
	}

	reqBody := map[string]interface{}{
		"model":       profile.Model,
		"messages":    anthropicMessages,
		"max_tokens":  profile.MaxTokens,
		"temperature": profile.Temperature,
		"stream":      true,
	}

	reqJSON, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(string(reqJSON)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", profile.Config["api_key"].(string))
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	outChan := make(chan *MessageChunk, 10)
	go func() {
		defer close(outChan)
		defer resp.Body.Close()

		decoder := json.NewDecoder(resp.Body)
		for {
			var event map[string]interface{}
			if err := decoder.Decode(&event); err != nil {
				if err != io.EOF {
					outChan <- &MessageChunk{Error: err}
				}
				break
			}

			if eventType := event["type"].(string); eventType == "content_block_delta" {
				if delta, ok := event["delta"].(map[string]interface{}); ok {
					if text, ok := delta["text"].(string); ok {
						outChan <- &MessageChunk{Content: text}
					}
				}
			}
		}
	}()

	return outChan, nil
}

// CallOpenAI implements OpenAI API
func (p *ModelProvider) CallOpenAI(ctx context.Context, profile *ModelProfile, messages []*schema.Message) (*schema.Message, error) {
	endpoint := "https://api.openai.com/v1/chat/completions"

	openaiMessages := make([]map[string]interface{}, 0, len(messages))
	for _, msg := range messages {
		openaiMessages = append(openaiMessages, map[string]interface{}{
			"role":    msg.Role,
			"content": msg.Content,
		})
	}

	reqBody := map[string]interface{}{
		"model":       profile.Model,
		"messages":    openaiMessages,
		"max_tokens":  profile.MaxTokens,
		"temperature": profile.Temperature,
	}

	reqJSON, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(string(reqJSON)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+profile.Config["api_key"].(string))

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("no choices returned from OpenAI")
	}

	return &schema.Message{
		Role:    result.Choices[0].Message.Role,
		Content: result.Choices[0].Message.Content,
	}, nil
}

// CallGemini implements Google Gemini API
func (p *ModelProvider) CallGemini(ctx context.Context, profile *ModelProfile, messages []*schema.Message) (*schema.Message, error) {
	apiKey := profile.Config["api_key"].(string)
	endpoint := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", profile.Model, apiKey)

	// Convert to Gemini format
	contents := make([]map[string]interface{}, 0, len(messages))
	for _, msg := range messages {
		role := msg.Role
		if role == "assistant" {
			role = "model"
		}
		contents = append(contents, map[string]interface{}{
			"role": role,
			"parts": []map[string]interface{}{
				{"text": msg.Content},
			},
		})
	}

	reqBody := map[string]interface{}{
		"contents": contents,
		"generationConfig": map[string]interface{}{
			"temperature":   profile.Temperature,
			"maxOutputTokens": profile.MaxTokens,
		},
	}

	reqJSON, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(string(reqJSON)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Candidates) == 0 || len(result.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("no response from Gemini")
	}

	return &schema.Message{
		Role:    "assistant",
		Content: result.Candidates[0].Content.Parts[0].Text,
	}, nil
}
