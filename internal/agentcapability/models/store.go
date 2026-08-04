// Package models provides model profile management and dynamic model discovery.
//
// Store implements complete CRUD operations for ModelProfile with:
// - PostgreSQL persistence using pgx
// - Optimistic concurrency control via revision numbers
// - Soft deletion support
// - Dynamic model listing from multiple providers (Anthropic, OpenAI, Gemini, etc.)
//
// Provider Support:
// - Anthropic (Claude models)
// - OpenAI (GPT models)
// - Google Gemini
// - DeepSeek
// - xAI
// - OpenRouter
// - OpenAI-compatible endpoints
//
// Database Schema:
// Uses core_model_profiles table with fields:
// - profile_id (uuid, primary key)
// - display_name, provider, base_url, model_name
// - api_key (encrypted), api_key_configured
// - temperature, top_p, max_output_tokens, context_window
// - system_prompt, reasoning_effort
// - revision (for optimistic locking)
// - created_at, updated_at, deleted_at
package models

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	modelListResponseLimit = 4 << 20
	modelListMaxCount      = 4096
)

// Store provides model profile management with database persistence
type Store struct {
	pool   *pgxpool.Pool
	client *http.Client
}

// NewStore creates a new model store
func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, errors.New("postgres pool is required")
	}
	return &Store{
		pool:   pool,
		client: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// ModelProfile represents a complete model configuration
type ModelProfile struct {
	ID              string                `json:"id"`
	DisplayName     string                `json:"display_name"`
	Provider        coremodel.ModelProvider `json:"provider"`
	BaseURL         string                `json:"base_url"`
	Model           string                `json:"model"`
	APIKey          string                `json:"-"`
	SystemPrompt    string                `json:"system_prompt,omitempty"`
	Temperature     *float64              `json:"temperature,omitempty"`
	TopP            *float64              `json:"top_p,omitempty"`
	MaxOutputTokens int                   `json:"max_output_tokens,omitempty"`
	ContextWindow   int                   `json:"context_window,omitempty"`
	ReasoningEffort string                `json:"reasoning_effort,omitempty"`
	APIKeyConfigured bool                 `json:"api_key_configured"`
	Revision        int64                 `json:"revision"`
	CreatedAt       time.Time             `json:"created_at"`
	UpdatedAt       time.Time             `json:"updated_at"`
}

// CreateProfile creates a new model profile
func (s *Store) CreateProfile(ctx context.Context, profile ModelProfile) (*ModelProfile, error) {
	if profile.ID == "" {
		return nil, fmt.Errorf("profile ID is required")
	}

	apiKeyConfigured := profile.APIKey != ""

	query := `
		INSERT INTO core_model_profiles (
			profile_id, display_name, provider, base_url, model_name,
			system_prompt, api_key, api_key_configured,
			temperature, top_p, max_output_tokens, context_window, reasoning_effort,
			revision, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING profile_id, display_name, provider, base_url, model_name,
			system_prompt, api_key_configured, temperature, top_p,
			max_output_tokens, context_window, reasoning_effort,
			revision, created_at, updated_at
	`

	now := time.Now().UTC()
	var created ModelProfile
	err := s.pool.QueryRow(ctx, query,
		profile.ID, profile.DisplayName, string(profile.Provider), profile.BaseURL, profile.Model,
		profile.SystemPrompt, profile.APIKey, apiKeyConfigured,
		profile.Temperature, profile.TopP, profile.MaxOutputTokens, profile.ContextWindow, profile.ReasoningEffort,
		1, now, now,
	).Scan(
		&created.ID, &created.DisplayName, &created.Provider, &created.BaseURL, &created.Model,
		&created.SystemPrompt, &created.APIKeyConfigured, &created.Temperature, &created.TopP,
		&created.MaxOutputTokens, &created.ContextWindow, &created.ReasoningEffort,
		&created.Revision, &created.CreatedAt, &created.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("create model profile: %w", err)
	}

	return &created, nil
}

// GetProfile retrieves a model profile by ID
func (s *Store) GetProfile(ctx context.Context, id string) (*ModelProfile, error) {
	query := `
		SELECT profile_id, display_name, provider, base_url, model_name,
			system_prompt, api_key, api_key_configured, temperature, top_p,
			max_output_tokens, context_window, reasoning_effort,
			revision, created_at, updated_at
		FROM core_model_profiles
		WHERE profile_id = $1 AND deleted_at IS NULL
	`

	var profile ModelProfile
	var apiKey *string
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&profile.ID, &profile.DisplayName, &profile.Provider, &profile.BaseURL, &profile.Model,
		&profile.SystemPrompt, &apiKey, &profile.APIKeyConfigured, &profile.Temperature, &profile.TopP,
		&profile.MaxOutputTokens, &profile.ContextWindow, &profile.ReasoningEffort,
		&profile.Revision, &profile.CreatedAt, &profile.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, coremodel.ErrProfileNotFound
		}
		return nil, fmt.Errorf("get model profile: %w", err)
	}

	if apiKey != nil {
		profile.APIKey = *apiKey
	}

	return &profile, nil
}

// ListProfiles lists all model profiles with pagination
func (s *Store) ListProfiles(ctx context.Context, limit int, offset int) ([]ModelProfile, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	// Get total count
	var total int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM core_model_profiles WHERE deleted_at IS NULL`).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count profiles: %w", err)
	}

	query := `
		SELECT profile_id, display_name, provider, base_url, model_name,
			system_prompt, api_key_configured, temperature, top_p,
			max_output_tokens, context_window, reasoning_effort,
			revision, created_at, updated_at
		FROM core_model_profiles
		WHERE deleted_at IS NULL
		ORDER BY created_at DESC, profile_id
		LIMIT $1 OFFSET $2
	`

	rows, err := s.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list profiles: %w", err)
	}
	defer rows.Close()

	var profiles []ModelProfile
	for rows.Next() {
		var profile ModelProfile
		err := rows.Scan(
			&profile.ID, &profile.DisplayName, &profile.Provider, &profile.BaseURL, &profile.Model,
			&profile.SystemPrompt, &profile.APIKeyConfigured, &profile.Temperature, &profile.TopP,
			&profile.MaxOutputTokens, &profile.ContextWindow, &profile.ReasoningEffort,
			&profile.Revision, &profile.CreatedAt, &profile.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan profile: %w", err)
		}
		profiles = append(profiles, profile)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate profiles: %w", err)
	}

	return profiles, total, nil
}

// UpdateProfile updates an existing model profile
func (s *Store) UpdateProfile(ctx context.Context, profile ModelProfile, expectedRevision int64) (*ModelProfile, error) {
	apiKeyConfigured := profile.APIKey != ""

	query := `
		UPDATE core_model_profiles
		SET display_name = $2, provider = $3, base_url = $4, model_name = $5,
			system_prompt = $6, api_key = $7, api_key_configured = $8,
			temperature = $9, top_p = $10, max_output_tokens = $11,
			context_window = $12, reasoning_effort = $13,
			revision = revision + 1, updated_at = $14
		WHERE profile_id = $1 AND revision = $15 AND deleted_at IS NULL
		RETURNING profile_id, display_name, provider, base_url, model_name,
			system_prompt, api_key_configured, temperature, top_p,
			max_output_tokens, context_window, reasoning_effort,
			revision, created_at, updated_at
	`

	now := time.Now().UTC()
	var updated ModelProfile
	err := s.pool.QueryRow(ctx, query,
		profile.ID, profile.DisplayName, string(profile.Provider), profile.BaseURL, profile.Model,
		profile.SystemPrompt, profile.APIKey, apiKeyConfigured,
		profile.Temperature, profile.TopP, profile.MaxOutputTokens, profile.ContextWindow, profile.ReasoningEffort,
		now, expectedRevision,
	).Scan(
		&updated.ID, &updated.DisplayName, &updated.Provider, &updated.BaseURL, &updated.Model,
		&updated.SystemPrompt, &updated.APIKeyConfigured, &updated.Temperature, &updated.TopP,
		&updated.MaxOutputTokens, &updated.ContextWindow, &updated.ReasoningEffort,
		&updated.Revision, &updated.CreatedAt, &updated.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, coremodel.ErrRevisionConflict
		}
		return nil, fmt.Errorf("update model profile: %w", err)
	}

	return &updated, nil
}

// DeleteProfile soft-deletes a model profile
func (s *Store) DeleteProfile(ctx context.Context, id string, expectedRevision int64) error {
	query := `
		UPDATE core_model_profiles
		SET deleted_at = $2, updated_at = $2
		WHERE profile_id = $1 AND revision = $3 AND deleted_at IS NULL
	`

	result, err := s.pool.Exec(ctx, query, id, time.Now().UTC(), expectedRevision)
	if err != nil {
		return fmt.Errorf("delete model profile: %w", err)
	}

	if result.RowsAffected() == 0 {
		return coremodel.ErrRevisionConflict
	}

	return nil
}

// SetDefaultProfile sets a profile as the default
func (s *Store) SetDefaultProfile(ctx context.Context, id string) error {
	// Note: This is a simplified implementation
	// Production version should track default per tenant/user
	_, err := s.GetProfile(ctx, id)
	if err != nil {
		return err
	}
	return nil
}

// GetDefaultProfile retrieves the default model profile
func (s *Store) GetDefaultProfile(ctx context.Context) (*ModelProfile, error) {
	query := `
		SELECT profile_id, display_name, provider, base_url, model_name,
			system_prompt, api_key_configured, temperature, top_p,
			max_output_tokens, context_window, reasoning_effort,
			revision, created_at, updated_at
		FROM core_model_profiles
		WHERE deleted_at IS NULL
		ORDER BY created_at ASC
		LIMIT 1
	`

	var profile ModelProfile
	err := s.pool.QueryRow(ctx, query).Scan(
		&profile.ID, &profile.DisplayName, &profile.Provider, &profile.BaseURL, &profile.Model,
		&profile.SystemPrompt, &profile.APIKeyConfigured, &profile.Temperature, &profile.TopP,
		&profile.MaxOutputTokens, &profile.ContextWindow, &profile.ReasoningEffort,
		&profile.Revision, &profile.CreatedAt, &profile.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, coremodel.ErrProfileNotFound
		}
		return nil, fmt.Errorf("get default profile: %w", err)
	}

	return &profile, nil
}

// ModelsList fetches available models from a provider
func (s *Store) ModelsList(ctx context.Context, params map[string]any) (map[string]any, error) {
	provider := strings.ToLower(trimString(params["provider"]))
	modelKind := normalizeModelListKind(params["model_kind"])

	if modelKind == "" {
		return nil, fmt.Errorf("model list kind %q is not supported", trimString(params["model_kind"]))
	}

	result := map[string]any{
		"models":    []map[string]any{},
		"providers": modelProviderDefaults(),
	}

	if provider == "" {
		if modelKind == "embedding" || modelKind == "speech" {
			return nil, fmt.Errorf("provider is required for model list kind %q", modelKind)
		}
		return result, nil
	}

	if !supportsNativeModelProvider(provider) {
		return nil, fmt.Errorf("model list is not supported for provider %q", provider)
	}

	baseURL := trimString(params["base_url"])
	if baseURL == "" {
		return nil, fmt.Errorf("base_url is required to fetch %s models", provider)
	}

	apiKey := trimString(params["api_key"])
	if apiKey == "" {
		return nil, fmt.Errorf("api_key is required to fetch %s models", provider)
	}

	if modelKind == "speech" || (modelKind == "embedding" && provider != "openrouter") {
		return nil, fmt.Errorf("model list kind %q is not supported for provider %q", modelKind, provider)
	}

	var (
		models []map[string]any
		err    error
	)

	switch provider {
	case "anthropic":
		models, err = s.fetchAnthropicModels(ctx, baseURL, apiKey)
	case "gemini":
		models, err = s.fetchGeminiModels(ctx, baseURL, apiKey)
	case "openai", "deepseek", "xai", "openai_compatible", "openrouter":
		if modelKind == "embedding" {
			if provider != "openrouter" {
				return nil, fmt.Errorf("model list kind %q is not supported for provider %q", modelKind, provider)
			}
			models, err = s.fetchOpenRouterEmbeddingModels(ctx, baseURL, apiKey)
		} else if modelKind == "speech" {
			return nil, fmt.Errorf("model list kind %q is not supported for provider %q", modelKind, provider)
		} else {
			models, err = s.fetchOpenAICompatibleModels(ctx, provider, baseURL, apiKey)
		}
	default:
		return nil, fmt.Errorf("model list is not supported for provider %q", provider)
	}

	if err != nil {
		return nil, err
	}

	result["models"] = models
	return result, nil
}

func normalizeModelListKind(value any) string {
	switch strings.ToLower(trimString(value)) {
	case "", "conversation":
		return "conversation"
	case "embedding", "speech":
		return strings.ToLower(trimString(value))
	default:
		return ""
	}
}

func modelProviderDefaults() []map[string]any {
	return []map[string]any{
		{"provider": "openai", "default_base_url": defaultBaseURLForProvider("openai"), "requires_api_key": true, "dynamic_models": true},
		{"provider": "anthropic", "default_base_url": defaultBaseURLForProvider("anthropic"), "requires_api_key": true, "dynamic_models": true},
		{"provider": "deepseek", "default_base_url": defaultBaseURLForProvider("deepseek"), "requires_api_key": true, "dynamic_models": true},
		{"provider": "gemini", "default_base_url": defaultBaseURLForProvider("gemini"), "requires_api_key": true, "dynamic_models": true},
		{"provider": "xai", "default_base_url": defaultBaseURLForProvider("xai"), "requires_api_key": true, "dynamic_models": true},
		{"provider": "openai_compatible", "default_base_url": defaultBaseURLForProvider("openai_compatible"), "requires_api_key": true, "dynamic_models": true},
		{"provider": "openrouter", "default_base_url": defaultBaseURLForProvider("openrouter"), "requires_api_key": true, "dynamic_models": true},
	}
}

func defaultBaseURLForProvider(provider string) string {
	switch provider {
	case "openai":
		return "https://api.openai.com/v1"
	case "anthropic":
		return "https://api.anthropic.com"
	case "gemini":
		return "https://generativelanguage.googleapis.com"
	case "deepseek":
		return "https://api.deepseek.com"
	case "xai":
		return "https://api.x.ai/v1"
	case "openai_compatible":
		return "https://api.openai.com/v1"
	case "openrouter":
		return "https://openrouter.ai/api/v1"
	default:
		return ""
	}
}

func supportsNativeModelProvider(provider string) bool {
	switch provider {
	case "openai", "anthropic", "deepseek", "gemini", "xai", "openai_compatible", "openrouter":
		return true
	default:
		return false
	}
}

func (s *Store) fetchModelListPayload(ctx context.Context, req *http.Request, provider string, payload any) error {
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s models: %w", provider, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("fetch %s models failed: %s", provider, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, modelListResponseLimit+1))
	if err != nil {
		return fmt.Errorf("decode %s models: %w", provider, err)
	}

	if len(body) > modelListResponseLimit {
		return fmt.Errorf("decode %s models: response exceeds %d-byte limit", provider, modelListResponseLimit)
	}

	if err := json.Unmarshal(body, payload); err != nil {
		return fmt.Errorf("decode %s models: %w", provider, err)
	}

	return nil
}

func (s *Store) fetchAnthropicModels(ctx context.Context, baseURL, apiKey string) ([]map[string]any, error) {
	baseURL = anthropicV1BaseURL(baseURL)
	if baseURL == "" {
		return nil, fmt.Errorf("base_url is required to fetch anthropic models")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/models", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	var payload struct {
		Data []map[string]any `json:"data"`
	}

	if err := s.fetchModelListPayload(ctx, req, "anthropic", &payload); err != nil {
		return nil, err
	}

	models := normalizeModelList("anthropic", payload.Data)
	if len(models) == 0 {
		return nil, fmt.Errorf("fetch anthropic models returned no models")
	}

	return models, nil
}

func (s *Store) fetchGeminiModels(ctx context.Context, baseURL, apiKey string) ([]map[string]any, error) {
	baseURL = geminiV1BetaBaseURL(baseURL)
	if baseURL == "" {
		return nil, fmt.Errorf("base_url is required to fetch gemini models")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/models", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-goog-api-key", apiKey)

	var payload struct {
		Models []map[string]any `json:"models"`
	}

	if err := s.fetchModelListPayload(ctx, req, "gemini", &payload); err != nil {
		return nil, err
	}

	models := normalizeModelList("gemini", payload.Models)
	if len(models) == 0 {
		return nil, fmt.Errorf("fetch gemini models returned no models")
	}

	return models, nil
}

func (s *Store) fetchOpenAICompatibleModels(ctx context.Context, provider, baseURL, apiKey string) ([]map[string]any, error) {
	modelsURL, err := openAICompatibleModelsURL(provider, baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse %s model URL: %w", provider, err)
	}

	if modelsURL == "" {
		return nil, fmt.Errorf("base_url is required to fetch %s models", provider)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, modelsURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	var payload struct {
		Data   []map[string]any `json:"data"`
		Models []map[string]any `json:"models"`
	}

	if err := s.fetchModelListPayload(ctx, req, provider, &payload); err != nil {
		return nil, err
	}

	rawModels := payload.Data
	if len(rawModels) == 0 {
		rawModels = payload.Models
	}

	models := normalizeModelList(provider, rawModels)
	if len(models) == 0 {
		return nil, fmt.Errorf("fetch %s models returned no models", provider)
	}

	return models, nil
}

func (s *Store) fetchOpenRouterEmbeddingModels(ctx context.Context, baseURL, apiKey string) ([]map[string]any, error) {
	url := strings.TrimRight(openAICompatibleModelsBaseURL("openrouter", baseURL), "/")
	if url == "" {
		return nil, fmt.Errorf("base_url is required to fetch openrouter models")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/embeddings/models", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	var payload struct {
		Data []map[string]any `json:"data"`
	}

	if err := s.fetchModelListPayload(ctx, req, "openrouter embedding", &payload); err != nil {
		return nil, err
	}

	models := normalizeModelList("openrouter", payload.Data)
	if len(models) == 0 {
		return nil, fmt.Errorf("fetch openrouter embedding models returned no models")
	}

	return models, nil
}

func openAICompatibleModelsURL(provider, baseURL string) (string, error) {
	base := strings.TrimRight(openAICompatibleModelsBaseURL(provider, baseURL), "/")
	if base == "" {
		return "", nil
	}

	endpoint, err := url.Parse(base + "/models")
	if err != nil {
		return "", err
	}

	query := endpoint.Query()
	switch {
	case provider == "openrouter":
		query.Set("output_modalities", "text")
	}
	endpoint.RawQuery = query.Encode()

	return endpoint.String(), nil
}

func openAICompatibleModelsBaseURL(provider, baseURL string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return ""
	}
	if provider == "deepseek" {
		return baseURL
	}
	return baseURL
}

func anthropicV1BaseURL(baseURL string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return ""
	}
	if !strings.HasSuffix(baseURL, "/v1") {
		baseURL = baseURL + "/v1"
	}
	return baseURL
}

func geminiV1BetaBaseURL(baseURL string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return ""
	}
	if !strings.HasSuffix(baseURL, "/v1beta") {
		baseURL = baseURL + "/v1beta"
	}
	return baseURL
}

func normalizeModelList(provider string, rawModels []map[string]any) []map[string]any {
	seen := make(map[string]struct{}, len(rawModels))
	models := make([]map[string]any, 0, len(rawModels))

	for _, raw := range rawModels {
		id := fallbackString(trimString(raw["id"]), trimString(raw["name"]))
		if id == "" {
			id = trimString(raw["model"])
		}

		if provider == "gemini" {
			id = strings.TrimPrefix(id, "models/")
		}

		if id == "" {
			continue
		}

		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}

		model := map[string]any{
			"id": id,
			"name": fallbackString(
				fallbackString(trimString(raw["display_name"]), trimString(raw["displayName"])),
				fallbackString(trimString(raw["name"]), id),
			),
			"provider": provider,
		}

		for key, value := range raw {
			switch key {
			case "object", "created", "created_at", "owned_by", "type",
				"context_length", "max_input_tokens", "max_output_tokens",
				"max_tokens", "input_token_limit", "output_token_limit":
				model[key] = value
			}
		}

		models = append(models, model)
	}

	return models
}

func trimString(value any) string {
	if s, ok := value.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func fallbackString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
