package models

import (
	"context"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestStoreCreation(t *testing.T) {
	_, err := NewStore(nil)
	if err == nil {
		t.Fatal("expected error when creating store with nil pool")
	}
}

func TestModelProfile(t *testing.T) {
	// Skip if no database available
	if testing.Short() {
		t.Skip("skipping database test in short mode")
	}

	ctx := context.Background()
	pool, err := setupTestDB(ctx)
	if err != nil {
		t.Skipf("skipping test: %v", err)
		return
	}
	defer pool.Close()

	store, err := NewStore(pool)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	// Test Create
	profile := ModelProfile{
		ID:              uuid.New().String(),
		DisplayName:     "Test Profile",
		Provider:        coremodel.ProviderAnthropic,
		BaseURL:         "https://api.anthropic.com",
		Model:           "claude-3-5-sonnet-20241022",
		APIKey:          "test-api-key",
		SystemPrompt:    "You are a helpful assistant",
		MaxOutputTokens: 4096,
		ContextWindow:   200000,
	}

	created, err := store.CreateProfile(ctx, profile)
	if err != nil {
		t.Fatalf("failed to create profile: %v", err)
	}

	if created.ID != profile.ID {
		t.Errorf("expected ID %s, got %s", profile.ID, created.ID)
	}

	if !created.APIKeyConfigured {
		t.Error("expected api_key_configured to be true")
	}

	// Test Get
	retrieved, err := store.GetProfile(ctx, profile.ID)
	if err != nil {
		t.Fatalf("failed to get profile: %v", err)
	}

	if retrieved.ID != profile.ID {
		t.Errorf("expected ID %s, got %s", profile.ID, retrieved.ID)
	}

	if retrieved.DisplayName != profile.DisplayName {
		t.Errorf("expected DisplayName %s, got %s", profile.DisplayName, retrieved.DisplayName)
	}

	// Test List
	profiles, total, err := store.ListProfiles(ctx, 10, 0)
	if err != nil {
		t.Fatalf("failed to list profiles: %v", err)
	}

	if total < 1 {
		t.Error("expected at least 1 profile")
	}

	if len(profiles) < 1 {
		t.Error("expected at least 1 profile in list")
	}

	// Test Update
	temp := 0.7
	retrieved.Temperature = &temp
	retrieved.DisplayName = "Updated Profile"

	updated, err := store.UpdateProfile(ctx, *retrieved, retrieved.Revision)
	if err != nil {
		t.Fatalf("failed to update profile: %v", err)
	}

	if updated.DisplayName != "Updated Profile" {
		t.Errorf("expected DisplayName 'Updated Profile', got %s", updated.DisplayName)
	}

	if updated.Temperature == nil || *updated.Temperature != 0.7 {
		t.Error("expected Temperature to be 0.7")
	}

	if updated.Revision != retrieved.Revision+1 {
		t.Errorf("expected Revision %d, got %d", retrieved.Revision+1, updated.Revision)
	}

	// Test Delete
	err = store.DeleteProfile(ctx, profile.ID, updated.Revision)
	if err != nil {
		t.Fatalf("failed to delete profile: %v", err)
	}

	// Verify deletion
	_, err = store.GetProfile(ctx, profile.ID)
	if err != coremodel.ErrProfileNotFound {
		t.Errorf("expected ErrProfileNotFound, got %v", err)
	}
}

func TestModelsList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping API test in short mode")
	}

	ctx := context.Background()
	pool, err := setupTestDB(ctx)
	if err != nil {
		t.Skipf("skipping test: %v", err)
		return
	}
	defer pool.Close()

	store, err := NewStore(pool)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	// Test provider defaults
	params := map[string]any{
		"model_kind": "conversation",
	}

	result, err := store.ModelsList(ctx, params)
	if err != nil {
		t.Fatalf("failed to list models: %v", err)
	}

	providers, ok := result["providers"].([]map[string]any)
	if !ok {
		t.Fatal("expected providers to be []map[string]any")
	}

	if len(providers) < 5 {
		t.Errorf("expected at least 5 providers, got %d", len(providers))
	}

	// Verify provider defaults
	for _, provider := range providers {
		name, _ := provider["provider"].(string)
		if name == "" {
			t.Error("provider name is empty")
		}

		defaultURL, _ := provider["default_base_url"].(string)
		if defaultURL == "" {
			t.Errorf("default_base_url is empty for provider %s", name)
		}
	}
}

func TestRevisionConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database test in short mode")
	}

	ctx := context.Background()
	pool, err := setupTestDB(ctx)
	if err != nil {
		t.Skipf("skipping test: %v", err)
		return
	}
	defer pool.Close()

	store, err := NewStore(pool)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	profile := ModelProfile{
		ID:          uuid.New().String(),
		DisplayName: "Conflict Test",
		Provider:    coremodel.ProviderAnthropic,
		BaseURL:     "https://api.anthropic.com",
		Model:       "claude-3-5-sonnet-20241022",
		APIKey:      "test-key",
	}

	created, err := store.CreateProfile(ctx, profile)
	if err != nil {
		t.Fatalf("failed to create profile: %v", err)
	}

	// Try to update with wrong revision
	created.DisplayName = "Should Fail"
	_, err = store.UpdateProfile(ctx, *created, 999)
	if err != coremodel.ErrRevisionConflict {
		t.Errorf("expected ErrRevisionConflict, got %v", err)
	}

	// Try to delete with wrong revision
	err = store.DeleteProfile(ctx, created.ID, 999)
	if err != coremodel.ErrRevisionConflict {
		t.Errorf("expected ErrRevisionConflict, got %v", err)
	}

	// Clean up
	_ = store.DeleteProfile(ctx, created.ID, created.Revision)
}

func setupTestDB(ctx context.Context) (*pgxpool.Pool, error) {
	// This would normally use a test database URL from environment
	// For now, we skip if not available
	dbURL := "postgres://dirextalk_agent_runtime:change_me@localhost/dirextalk_agent_test"

	config, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return nil, err
	}

	config.ConnConfig.ConnectTimeout = 2 * time.Second
	config.MaxConns = 5

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return pool, nil
}
