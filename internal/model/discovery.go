package model

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const maximumDiscoveredModels = 10_000

// ListModels performs provider model discovery with the same endpoint policy
// and request-local secret resolver used by inference calls.
func ListModels(ctx context.Context, profile Profile, resolver SecretResolver, options ...Option) ([]Descriptor, error) {
	created, err := NewClient(profile, resolver, options...)
	if err != nil {
		return nil, err
	}
	providerClient, ok := created.(*client)
	if !ok {
		return nil, ErrProviderUnavailable
	}
	if providerClient.endpointPolicy != nil {
		if err := providerClient.endpointPolicy.preflight(ctx); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, ErrProviderUnavailable
		}
	}
	credential, err := resolver.ResolveSecret(ctx, profile.SecretRef)
	if err != nil || len(credential) == 0 {
		zeroBytes(credential)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, ErrSecretUnavailable
	}
	defer zeroBytes(credential)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, modelListEndpoint(providerClient), nil)
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	request.Header.Set("Accept", "application/json")
	if profile.Provider == ProviderAnthropic {
		request.Header.Set("x-api-key", string(credential))
		request.Header.Set("anthropic-version", anthropicVersion)
	} else {
		request.Header.Set("Authorization", "Bearer "+string(credential))
	}
	response, err := providerClient.http.Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, ErrProviderUnavailable
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, ErrModelListRejected
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return nil, ErrModelListUnsupported
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, ErrProviderUnavailable
	}
	body, err := readLimited(response.Body, responseBodyLimit)
	if err != nil {
		return nil, err
	}
	return decodeModelList(body, string(profile.Provider), credential)
}

func modelListEndpoint(client *client) string {
	baseURL := strings.TrimRight(client.baseURL, "/")
	if client.profile.Provider == ProviderAnthropic && !strings.HasSuffix(baseURL, "/v1") {
		return baseURL + "/v1/models"
	}
	return baseURL + "/models"
}

func decodeModelList(body []byte, provider string, credential []byte) ([]Descriptor, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var payload struct {
		Data   []map[string]any `json:"data"`
		Models []map[string]any `json:"models"`
	}
	if err := decoder.Decode(&payload); err != nil {
		return nil, ErrProviderUnavailable
	}
	rawModels := payload.Data
	if len(rawModels) == 0 {
		rawModels = payload.Models
	}
	if len(rawModels) == 0 {
		return nil, ErrModelListUnsupported
	}
	seen := make(map[string]struct{}, len(rawModels))
	models := make([]Descriptor, 0, min(len(rawModels), maximumDiscoveredModels))
	for _, raw := range rawModels {
		if len(models) == maximumDiscoveredModels {
			break
		}
		id := discoveryID(credential, raw["id"], raw["model"], raw["name"])
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		name := firstSafeDiscoveryString(credential, raw["display_name"], raw["name"])
		if name == "" {
			name = id
		}
		models = append(models, Descriptor{
			ID: id, Name: name, Provider: provider,
			ContextWindow:   firstPositiveInt64(raw["context_window"], raw["context_length"], raw["max_context_length"]),
			MaxOutputTokens: firstPositiveInt64(raw["max_output_tokens"], raw["max_completion_tokens"]),
			ReasoningModes:  safeDiscoveryStrings(credential, raw["reasoning_modes"]),
		})
	}
	if len(models) == 0 {
		return nil, ErrModelListUnsupported
	}
	sort.Slice(models, func(i, j int) bool { return models[i].ID < models[j].ID })
	return models, nil
}

func discoveryID(credential []byte, values ...any) string {
	for _, value := range values {
		text, ok := value.(string)
		text = strings.TrimSpace(text)
		if !ok || text == "" {
			continue
		}
		if len(text) > 512 || strings.ContainsAny(text, "\x00\r\n\t") || containsCredential(text, credential) {
			return ""
		}
		return text
	}
	return ""
}

func firstSafeDiscoveryString(credential []byte, values ...any) string {
	for _, value := range values {
		text, ok := value.(string)
		text = strings.TrimSpace(text)
		if !ok || text == "" || len(text) > 512 || strings.ContainsAny(text, "\x00\r\n\t") || containsCredential(text, credential) {
			continue
		}
		return text
	}
	return ""
}

func safeDiscoveryStrings(credential []byte, value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	result := make([]string, 0, min(len(items), 32))
	for _, item := range items {
		text := firstSafeDiscoveryString(credential, item)
		if text == "" {
			continue
		}
		if _, exists := seen[text]; exists {
			continue
		}
		seen[text] = struct{}{}
		result = append(result, text)
		if len(result) == 32 {
			break
		}
	}
	return result
}

func containsCredential(value string, credential []byte) bool {
	return len(credential) >= 8 && bytes.Contains([]byte(value), credential)
}

func firstPositiveInt64(values ...any) int64 {
	for _, value := range values {
		var parsed int64
		var err error
		switch typed := value.(type) {
		case json.Number:
			parsed, err = typed.Int64()
		case float64:
			parsed = int64(typed)
		case string:
			parsed, err = strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		default:
			continue
		}
		if err == nil && parsed > 0 {
			return parsed
		}
	}
	return 0
}
