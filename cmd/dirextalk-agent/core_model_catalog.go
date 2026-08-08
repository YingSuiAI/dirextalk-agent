package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

const (
	coreModelCatalogTimeout      = 15 * time.Second
	coreModelCatalogResponseMax  = 4 << 20
	coreModelCatalogModelsMax    = 4096
	coreModelCatalogDefaultAgent = "openai_compatible"
	coreModelCatalogAnthropicVer = "2023-06-01"
)

var (
	errCoreModelCatalogUnavailable = coremodel.ErrProviderUnavailable
	errCoreModelCatalogResponse    = errors.New("model provider returned an invalid response")
	errCoreModelCatalogTimeout     = context.DeadlineExceeded
)

// coreModelCatalog is the request-scoped provider discovery implementation
// behind agent.info.v1:list_models. The profile service is optional in tests,
// but production injects it so model_profile_id can only resolve through the
// durable Core model store.
type coreModelCatalog struct {
	profiles *coremodel.Service
	client   *http.Client
	timeout  time.Duration
}

func newCoreModelCatalog(profiles *coremodel.Service) *coreModelCatalog {
	return newCoreModelCatalogWithHTTPClient(profiles, nil, coreModelCatalogTimeout)
}

func newCoreModelCatalogWithHTTPClient(profiles *coremodel.Service, client *http.Client, timeout time.Duration) *coreModelCatalog {
	if timeout <= 0 {
		timeout = coreModelCatalogTimeout
	}
	if client == nil {
		client = &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &coreModelCatalog{profiles: profiles, client: client, timeout: timeout}
}

func (c *coreModelCatalog) ListModels(ctx context.Context, request agentcapability.ModelCatalogRequest) (agentcapability.ModelCatalogResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	kind := normalizeCatalogModelKind(request.ModelKind)
	if kind == "" {
		return agentcapability.ModelCatalogResult{}, errors.New("model_kind must be conversation, embedding, or speech")
	}
	modelProfileID := strings.TrimSpace(request.ModelProfileID)
	clientModelProfileID := strings.TrimSpace(request.ClientModelProfileID)
	if modelProfileID != "" && clientModelProfileID != "" && modelProfileID != clientModelProfileID {
		return agentcapability.ModelCatalogResult{}, errors.New("model_profile_id and client_model_profile_id are ambiguous")
	}

	provider := strings.ToLower(strings.TrimSpace(request.Provider))
	baseURL := strings.TrimSpace(request.BaseURL)
	apiKey := strings.TrimSpace(request.APIKey)
	if modelProfileID != "" || clientModelProfileID != "" {
		if apiKey != "" {
			return agentcapability.ModelCatalogResult{}, errors.New("api_key must not be provided with a model profile ID")
		}
		if c == nil || c.profiles == nil {
			return agentcapability.ModelCatalogResult{}, errors.New("model profile lookup is unavailable")
		}
		var profile coremodel.Profile
		var err error
		if modelProfileID != "" {
			profile, err = c.profiles.ResolveProfile(ctx, modelProfileID)
		} else {
			profile, err = c.profiles.ResolveClientProfile(ctx, clientModelProfileID)
		}
		if err != nil {
			return agentcapability.ModelCatalogResult{}, errors.New("model profile lookup failed")
		}
		// A stored profile is a write-only credential source for its provider,
		// while kind selects the catalog being discovered. Keeping those roles
		// independent lets a first OpenRouter conversation profile discover the
		// embedding catalog before an embedding profile exists.
		profileProvider := strings.ToLower(strings.TrimSpace(string(profile.Provider)))
		if provider != "" && !catalogProvidersMatch(provider, profileProvider, profile.BaseURL) {
			return agentcapability.ModelCatalogResult{}, fmt.Errorf("provider %q does not match model profile provider %q", provider, profileProvider)
		}
		if baseURL != "" {
			storedOrigin, err := catalogURLOrigin(profile.BaseURL)
			if err != nil {
				return agentcapability.ModelCatalogResult{}, errors.New("stored model profile base_url is invalid")
			}
			overrideOrigin, err := catalogURLOrigin(baseURL)
			if err != nil || overrideOrigin != storedOrigin {
				return agentcapability.ModelCatalogResult{}, errors.New("base_url override must use the stored model profile origin")
			}
		} else {
			baseURL = strings.TrimSpace(profile.BaseURL)
		}
		provider = profileProvider
		apiKey = strings.TrimSpace(profile.APIKey)
	}

	result := coreModelCatalogMetadata()
	if provider == "" {
		return result, nil
	}
	provider = normalizeCatalogProvider(provider)
	if !catalogProviderSupported(provider) {
		return agentcapability.ModelCatalogResult{}, fmt.Errorf("model list is not supported for provider %q", provider)
	}
	if baseURL == "" {
		return agentcapability.ModelCatalogResult{}, fmt.Errorf("base_url is required to fetch %s models", provider)
	}
	if apiKey == "" {
		return agentcapability.ModelCatalogResult{}, fmt.Errorf("api_key is required to fetch %s models", provider)
	}
	if kind == coremodel.ModelKindSpeech {
		return agentcapability.ModelCatalogResult{}, fmt.Errorf("model list kind %q is not supported for provider %q", kind, provider)
	}

	// Core model validation stores OpenRouter/OpenAI aliases as
	// openai_compatible. Infer the well-known OpenRouter host so a profile ID
	// still reaches the dedicated embedding endpoint and text-output filter.
	effectiveProvider := provider
	if provider == coreModelCatalogDefaultAgent && isOpenRouterBaseURL(baseURL) {
		effectiveProvider = "openrouter"
	}
	if kind == coremodel.ModelKindEmbedding && effectiveProvider != "openrouter" {
		return agentcapability.ModelCatalogResult{}, fmt.Errorf("model list kind %q is not supported for provider %q", kind, provider)
	}

	endpoint, err := catalogModelsURL(effectiveProvider, baseURL, kind)
	if err != nil {
		return agentcapability.ModelCatalogResult{}, errors.New("model provider base_url is invalid")
	}
	models, err := c.fetch(ctx, endpoint, effectiveProvider, kind, apiKey)
	if err != nil {
		return agentcapability.ModelCatalogResult{}, err
	}
	result.Models = models
	return result, nil
}

func (c *coreModelCatalog) fetch(ctx context.Context, endpoint, provider, kind, apiKey string) ([]map[string]any, error) {
	if c == nil || c.client == nil {
		return nil, errCoreModelCatalogUnavailable
	}
	timeout := c.timeout
	if timeout <= 0 {
		timeout = coreModelCatalogTimeout
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errCoreModelCatalogUnavailable
	}
	req.Header.Set("Accept", "application/json")
	switch provider {
	case "anthropic":
		req.Header.Set("x-api-key", apiKey)
		req.Header.Set("anthropic-version", coreModelCatalogAnthropicVer)
	case "gemini":
		req.Header.Set("x-goog-api-key", apiKey)
	default:
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if requestCtx.Err() != nil {
			return nil, errCoreModelCatalogTimeout
		}
		return nil, errCoreModelCatalogUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("model provider returned status %d", resp.StatusCode)
	}
	if resp.ContentLength > coreModelCatalogResponseMax {
		return nil, errors.New("model provider response exceeds size limit")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, coreModelCatalogResponseMax+1))
	if err != nil {
		return nil, errCoreModelCatalogUnavailable
	}
	if len(body) > coreModelCatalogResponseMax {
		return nil, errors.New("model provider response exceeds size limit")
	}
	var payload struct {
		Data   []map[string]any `json:"data"`
		Models []map[string]any `json:"models"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, errCoreModelCatalogResponse
	}
	rawModels := payload.Data
	if len(rawModels) == 0 {
		rawModels = payload.Models
	}
	if len(rawModels) > coreModelCatalogModelsMax {
		return nil, errors.New("model provider returned too many models")
	}
	filtered := filterCatalogModels(kind, rawModels)
	models := normalizeCatalogModelsWithSecret(provider, filtered, apiKey)
	if len(models) > coreModelCatalogModelsMax {
		return nil, errors.New("model provider returned too many models")
	}
	if len(models) == 0 {
		return nil, errors.New("model provider returned no models")
	}
	return models, nil
}

func coreModelCatalogMetadata() agentcapability.ModelCatalogResult {
	providers := []agentcapability.ModelCatalogProviderInfo{
		{Provider: "openai", DefaultBaseURL: "https://api.openai.com/v1", RequiresAPIKey: true, DynamicModels: true},
		{Provider: "anthropic", DefaultBaseURL: "https://api.anthropic.com/v1", RequiresAPIKey: true, DynamicModels: true},
		{Provider: "deepseek", DefaultBaseURL: "https://api.deepseek.com/v1", RequiresAPIKey: true, DynamicModels: true},
		{Provider: "gemini", DefaultBaseURL: "https://generativelanguage.googleapis.com/v1beta", RequiresAPIKey: true, DynamicModels: true},
		{Provider: "xai", DefaultBaseURL: "https://api.x.ai/v1", RequiresAPIKey: true, DynamicModels: true},
		{Provider: coreModelCatalogDefaultAgent, DefaultBaseURL: "http://localhost:4000/v1", RequiresAPIKey: true, DynamicModels: true},
		{Provider: "openrouter", DefaultBaseURL: "https://openrouter.ai/api/v1", RequiresAPIKey: true, DynamicModels: true},
	}
	return agentcapability.ModelCatalogResult{Models: []map[string]any{}, Providers: providers}
}

func normalizeCatalogModelKind(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", coremodel.ModelKindConversation:
		return coremodel.ModelKindConversation
	case coremodel.ModelKindEmbedding:
		return coremodel.ModelKindEmbedding
	case coremodel.ModelKindSpeech:
		return coremodel.ModelKindSpeech
	default:
		return ""
	}
}

func normalizeCatalogProvider(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "openrouter", "openai", "deepseek", "xai":
		return value
	default:
		return value
	}
}

func catalogProviderSupported(provider string) bool {
	for _, supported := range coreSupportedModelProviders {
		if provider == supported {
			return true
		}
	}
	return false
}

func catalogProvidersMatch(requested, profile, baseURL string) bool {
	requested = normalizeCatalogProvider(requested)
	profile = normalizeCatalogProvider(profile)
	if requested == profile {
		return true
	}
	if profile == coreModelCatalogDefaultAgent && requested == "openrouter" && isOpenRouterBaseURL(baseURL) {
		return true
	}
	if profile == coreModelCatalogDefaultAgent && requested == "openai" && isOpenAIBaseURL(baseURL) {
		return true
	}
	if profile == coreModelCatalogDefaultAgent && requested == "deepseek" && isDeepSeekBaseURL(baseURL) {
		return true
	}
	if profile == coreModelCatalogDefaultAgent && requested == "xai" && isXAIBaseURL(baseURL) {
		return true
	}
	return profile == "openrouter" && requested == coreModelCatalogDefaultAgent
}

func catalogModelsURL(provider, rawBaseURL, kind string) (string, error) {
	base, err := catalogProviderBaseURL(provider, rawBaseURL)
	if err != nil {
		return "", err
	}
	suffix := "models"
	if provider == "openrouter" && kind == coremodel.ModelKindEmbedding {
		suffix = "embeddings/models"
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/" + suffix
	base.RawPath = ""
	if provider == "openrouter" && kind == coremodel.ModelKindConversation {
		query := base.Query()
		query.Set("output_modalities", "text")
		base.RawQuery = query.Encode()
	} else if provider == coreModelCatalogDefaultAgent && isSiliconFlowBaseURL(rawBaseURL) {
		query := base.Query()
		query.Set("type", "text")
		query.Set("sub_type", "chat")
		base.RawQuery = query.Encode()
	}
	return base.String(), nil
}

func catalogProviderBaseURL(provider, rawBaseURL string) (*url.URL, error) {
	base, err := parseCatalogURL(rawBaseURL)
	if err != nil {
		return nil, err
	}
	path := strings.TrimRight(base.Path, "/")
	switch provider {
	case "anthropic":
		if !strings.HasSuffix(path, "/v1") {
			path += "/v1"
		}
	case "gemini":
		if path == "" {
			path = "/v1beta"
		}
	default:
		if path == "" && provider != "deepseek" {
			path = "/v1"
		}
	}
	base.Path = path
	base.RawPath = ""
	base.RawQuery = ""
	base.Fragment = ""
	return base, nil
}

func parseCatalogURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, errors.New("invalid URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || !u.IsAbs() || u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("invalid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("invalid URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(u.Host, "\r\n\x00") || strings.ContainsAny(u.Path, "\r\n\x00") {
		return nil, errors.New("invalid URL")
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("invalid URL")
	}
	if port := u.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return nil, errors.New("invalid URL")
		}
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

func catalogURLOrigin(raw string) (string, error) {
	u, err := parseCatalogURL(raw)
	if err != nil {
		return "", err
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return u.Scheme + "://" + strings.ToLower(u.Hostname()) + ":" + port, nil
}

func isOpenRouterBaseURL(raw string) bool {
	u, err := parseCatalogURL(raw)
	return err == nil && strings.EqualFold(u.Hostname(), "openrouter.ai")
}

func isOpenAIBaseURL(raw string) bool {
	u, err := parseCatalogURL(raw)
	return err == nil && strings.EqualFold(u.Hostname(), "api.openai.com")
}

func isDeepSeekBaseURL(raw string) bool {
	u, err := parseCatalogURL(raw)
	return err == nil && strings.EqualFold(u.Hostname(), "api.deepseek.com")
}

func isXAIBaseURL(raw string) bool {
	u, err := parseCatalogURL(raw)
	return err == nil && strings.EqualFold(u.Hostname(), "api.x.ai")
}

func isSiliconFlowBaseURL(raw string) bool {
	u, err := parseCatalogURL(raw)
	return err == nil && (strings.EqualFold(u.Hostname(), "api.siliconflow.cn") || strings.EqualFold(u.Hostname(), "api.siliconflow.com"))
}

func filterCatalogModels(kind string, rawModels []map[string]any) []map[string]any {
	filtered := make([]map[string]any, 0, len(rawModels))
	for _, raw := range rawModels {
		if raw == nil {
			continue
		}
		if kind == coremodel.ModelKindEmbedding {
			if modalities, present := catalogOutputModalities(raw); present && !catalogContains(modalities, "embedding") && !catalogContains(modalities, "embeddings") {
				continue
			}
		} else if catalogModelIsNonConversation(raw) {
			continue
		}
		filtered = append(filtered, raw)
	}
	return filtered
}

func catalogModelIsNonConversation(raw map[string]any) bool {
	for _, key := range []string{"type", "model_type", "kind"} {
		switch strings.ToLower(catalogStringValue(raw[key])) {
		case "embedding", "embeddings", "rerank", "speech", "transcription", "image_generation", "moderation":
			return true
		}
	}
	if methods, present := catalogStringList(raw["supportedGenerationMethods"]); present {
		for _, method := range methods {
			if method == "generatecontent" || method == "generate_content" {
				return false
			}
		}
		return true
	}
	if modalities, present := catalogOutputModalities(raw); present {
		return !catalogContains(modalities, "text")
	}
	if architecture, ok := raw["architecture"].(map[string]any); ok {
		modality := strings.ToLower(catalogStringValue(architecture["modality"]))
		for _, marker := range []string{"->embedding", "->rerank", "->image", "->audio", "->speech", "->moderation"} {
			if strings.Contains(modality, marker) {
				return true
			}
		}
	}
	id := strings.ToLower(firstCatalogString(raw["id"], raw["name"], raw["model"]))
	for _, marker := range []string{"text-embedding", "embedding-", "/embedding", "rerank", "tts", "speech", "whisper", "transcrib", "dall-e", "gpt-image", "stable-diffusion", "flux", "moderation"} {
		if strings.Contains(id, marker) {
			return true
		}
	}
	return false
}

func normalizeCatalogModels(provider string, rawModels []map[string]any) []map[string]any {
	return normalizeCatalogModelsWithSecret(provider, rawModels, "")
}

// normalizeCatalogModelsWithSecret projects provider responses to the closed
// model shape and drops a whole entry if the provider reflected the request
// credential in any output field.  A provider may legally echo credentials in
// an id, name, metadata alias, or a nested/list value; dropping the entry is
// safer than trying to redact arbitrary strings after projection.
func normalizeCatalogModelsWithSecret(provider string, rawModels []map[string]any, apiKey string) []map[string]any {
	seen := make(map[string]struct{}, len(rawModels))
	models := make([]map[string]any, 0, len(rawModels))
	for _, raw := range rawModels {
		id := firstCatalogString(raw["id"], raw["name"], raw["model"])
		if provider == "gemini" {
			id = strings.TrimPrefix(id, "models/")
		}
		if id == "" {
			continue
		}
		name := firstCatalogString(raw["display_name"], raw["displayName"], raw["name"], id)
		model := map[string]any{"id": id, "name": name, "provider": provider}
		for _, key := range []string{"object", "created", "created_at", "owned_by", "type", "context_length", "context_window", "max_input_tokens", "max_output_tokens", "max_tokens", "input_token_limit", "output_token_limit"} {
			if value, ok := safeCatalogValue(key, raw[key]); ok {
				model[key] = value
			}
		}
		if modalities, present := catalogInputModalities(raw); present && len(modalities) > 0 {
			model["input_modalities"] = modalities
		}
		if modalities, present := catalogOutputModalities(raw); present && len(modalities) > 0 {
			model["output_modalities"] = modalities
		}
		if catalogValueContainsSecret(model, apiKey) {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		models = append(models, model)
	}
	return models
}

// catalogValueContainsSecret recursively checks every string in a projected
// value.  It intentionally checks for the literal credential as a substring
// so wrappers such as "Bearer <key>" are rejected too; it does not perform
// arbitrary string masking or case-folding.
func catalogValueContainsSecret(value any, secret string) bool {
	if secret == "" || value == nil {
		return false
	}
	switch typed := value.(type) {
	case string:
		return strings.Contains(typed, secret)
	case []byte:
		return strings.Contains(string(typed), secret)
	case []string:
		for _, item := range typed {
			if strings.Contains(item, secret) {
				return true
			}
		}
		return false
	case []any:
		for _, item := range typed {
			if catalogValueContainsSecret(item, secret) {
				return true
			}
		}
		return false
	case map[string]any:
		for key, item := range typed {
			if strings.Contains(key, secret) || catalogValueContainsSecret(item, secret) {
				return true
			}
		}
		return false
	default:
		// JSON decoding currently yields the concrete cases above, but keep the
		// invariant for typed maps/slices introduced by future adapters too.
		reflected := reflect.ValueOf(value)
		switch reflected.Kind() {
		case reflect.Map:
			if reflected.Type().Key().Kind() == reflect.String {
				iter := reflected.MapRange()
				for iter.Next() {
					if strings.Contains(iter.Key().String(), secret) || catalogValueContainsSecret(iter.Value().Interface(), secret) {
						return true
					}
				}
			}
		case reflect.Slice, reflect.Array:
			for index := 0; index < reflected.Len(); index++ {
				if catalogValueContainsSecret(reflected.Index(index).Interface(), secret) {
					return true
				}
			}
		}
		return false
	}
}

func catalogOutputModalities(raw map[string]any) ([]string, bool) {
	value, present := raw["output_modalities"]
	if !present {
		architecture, ok := raw["architecture"].(map[string]any)
		if !ok {
			return nil, false
		}
		value, present = architecture["output_modalities"]
	}
	if !present {
		return nil, false
	}
	modalities, valid := catalogOutputModalityList(value)
	if !valid {
		// Keep malformed output metadata present-but-empty so the existing
		// conversation/embedding filters reject that catalog item rather than
		// silently falling back to a guessed modality.
		return nil, true
	}
	return normalizeCatalogOutputModalities(modalities), true
}

func catalogOutputModalityList(value any) ([]string, bool) {
	var values []any
	switch typed := value.(type) {
	case []any:
		values = typed
	case []string:
		values = make([]any, len(typed))
		for i := range typed {
			values[i] = typed[i]
		}
	default:
		return nil, false
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		typed, ok := item.(string)
		if !ok {
			return nil, false
		}
		value := strings.TrimSpace(catalogStringValue(typed))
		if value == "" {
			return nil, false
		}
		result = append(result, value)
	}
	return result, true
}

func normalizeCatalogOutputModalities(values []string) []string {
	return agentcapability.CanonicalModelCatalogOutputModalities(values)
}

func catalogInputModalities(raw map[string]any) ([]string, bool) {
	value, present := raw["input_modalities"]
	if !present {
		architecture, ok := raw["architecture"].(map[string]any)
		if !ok {
			return nil, false
		}
		value, present = architecture["input_modalities"]
	}
	if !present {
		return nil, false
	}
	modalities, valid := catalogInputModalityList(value)
	if !valid {
		return nil, false
	}
	known := map[string]struct{}{"text": {}, "image": {}}
	seen := make(map[string]struct{}, len(modalities))
	result := make([]string, 0, len(modalities))
	for _, modality := range modalities {
		if _, ok := known[modality]; !ok {
			continue
		}
		if _, ok := seen[modality]; ok {
			continue
		}
		seen[modality] = struct{}{}
		result = append(result, modality)
	}
	return result, true
}

func catalogInputModalityList(value any) ([]string, bool) {
	var values []any
	switch typed := value.(type) {
	case []any:
		values = typed
	case []string:
		values = make([]any, len(typed))
		for i := range typed {
			values[i] = typed[i]
		}
	default:
		return nil, false
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		typed, ok := item.(string)
		if !ok {
			return nil, false
		}
		value := strings.ToLower(strings.TrimSpace(catalogStringValue(typed)))
		if value == "" {
			return nil, false
		}
		result = append(result, value)
	}
	return result, true
}

func catalogStringList(value any) ([]string, bool) {
	var values []any
	switch typed := value.(type) {
	case []any:
		values = typed
	case []string:
		values = make([]any, len(typed))
		for i := range typed {
			values[i] = typed[i]
		}
	default:
		return nil, false
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		value := strings.ToLower(strings.TrimSpace(catalogStringValue(item)))
		if value != "" {
			result = append(result, value)
		}
	}
	return result, true
}

func catalogContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func firstCatalogString(values ...any) string {
	for _, value := range values {
		if result := strings.TrimSpace(catalogStringValue(value)); result != "" {
			return result
		}
	}
	return ""
}

func catalogStringValue(value any) string {
	typed, ok := value.(string)
	if !ok || strings.ContainsAny(typed, "\r\n\x00") {
		return ""
	}
	if len(typed) > 4096 {
		return typed[:4096]
	}
	return typed
}

func safeCatalogValue(field string, value any) (any, bool) {
	switch field {
	case "object", "created_at", "owned_by", "type":
		value, ok := value.(string)
		if !ok {
			return nil, false
		}
		value = catalogStringValue(value)
		return value, value != ""
	case "created":
		return catalogNumberValue(value)
	case "context_length", "context_window", "max_input_tokens", "max_output_tokens", "max_tokens", "input_token_limit", "output_token_limit":
		return catalogIntegerValue(value)
	default:
		return nil, false
	}
}

func catalogNumberValue(value any) (any, bool) {
	switch typed := value.(type) {
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return nil, false
		}
		return typed, true
	case float32:
		return catalogNumberValue(float64(typed))
	case json.Number:
		number, err := typed.Float64()
		if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
			return nil, false
		}
		return number, true
	case int:
		return float64(typed), true
	case int8:
		return float64(typed), true
	case int16:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case uint:
		return float64(typed), true
	case uint8:
		return float64(typed), true
	case uint16:
		return float64(typed), true
	case uint32:
		return float64(typed), true
	case uint64:
		return float64(typed), true
	default:
		return nil, false
	}
}

func catalogIntegerValue(value any) (any, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int8:
		return int64(typed), true
	case int16:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case int64:
		return typed, true
	case uint:
		if uint64(typed) > uint64(^uint64(0)>>1) {
			return nil, false
		}
		return int64(typed), true
	case uint8:
		return int64(typed), true
	case uint16:
		return int64(typed), true
	case uint32:
		return int64(typed), true
	case uint64:
		if typed > uint64(^uint64(0)>>1) {
			return nil, false
		}
		return int64(typed), true
	case float32:
		return catalogIntegerFloat(float64(typed))
	case float64:
		return catalogIntegerFloat(typed)
	case json.Number:
		return catalogIntegerNumber(typed)
	default:
		return nil, false
	}
}

func catalogIntegerFloat(value float64) (any, bool) {
	const minInteger = -float64(uint64(1) << 63)
	const maxIntegerExclusive = float64(uint64(1) << 63)
	if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || value < minInteger || value >= maxIntegerExclusive {
		return nil, false
	}
	return int64(value), true
}

func catalogIntegerNumber(value json.Number) (any, bool) {
	rational, ok := new(big.Rat).SetString(value.String())
	if !ok || !rational.IsInt() {
		return nil, false
	}
	minimum := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 63))
	maximum := new(big.Int).Lsh(big.NewInt(1), 63)
	numerator := rational.Num()
	if numerator.Cmp(minimum) < 0 || numerator.Cmp(maximum) >= 0 {
		return nil, false
	}
	return numerator.Int64(), true
}
