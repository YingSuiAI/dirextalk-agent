package model

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfileCatalogBindsCredentialAudienceAndSamplingLimits(t *testing.T) {
	catalog := testProfileCatalog(t)
	temperature := 0.4
	resolved, err := catalog.ResolveSelection(Profile{ProfileID: "deepseek-v4", Temperature: &temperature, MaxOutputTokens: 2048})
	if err != nil {
		t.Fatalf("ResolveSelection() error = %v", err)
	}
	if resolved.BaseURL != "https://api.deepseek.example/v1" || resolved.SecretRef != "mounted:deepseek-token" || resolved.MaxOutputTokens != 2048 {
		t.Fatalf("resolved profile = %#v", resolved)
	}

	for _, selection := range []Profile{
		{ProfileID: "unknown"},
		{ProfileID: "deepseek-v4", BaseURL: "https://attacker.example/v1", SecretRef: "mounted:deepseek-token"},
		{ProfileID: "deepseek-v4", BaseURL: "https://api.deepseek.example/v1", SecretRef: "mounted:other-token"},
		{ProfileID: "deepseek-v4", MaxOutputTokens: 8193},
	} {
		if _, err := catalog.ResolveSelection(selection); err == nil {
			t.Fatalf("ResolveSelection(%#v) unexpectedly succeeded", selection)
		}
	}
}

func TestLoadProfileCatalogIsStrictAndSecretFree(t *testing.T) {
	valid := `{"schema_version":1,"profiles":[{"profile_id":"deepseek-v4","provider":"deepseek","model":"deepseekv4-pro","base_url":"https://api.deepseek.example/v1","secret_ref":"mounted:deepseek-token","context_window":65536,"max_output_tokens":8192}]}`
	path := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog, err := LoadProfileCatalog(path)
	if err != nil {
		t.Fatalf("LoadProfileCatalog() error = %v", err)
	}
	if _, err := catalog.ResolveSelection(Profile{ProfileID: "deepseek-v4"}); err != nil {
		t.Fatalf("loaded catalog cannot resolve profile: %v", err)
	}

	for _, content := range []string{
		strings.Replace(valid, `"max_output_tokens":8192`, `"max_output_tokens":8192,"token":"not-allowed"`, 1),
		strings.Replace(valid, `mounted:deepseek-token`, `sk-123456789012345678901234567890`, 1),
		strings.Replace(valid, `https://api.deepseek.example/v1`, `http://api.deepseek.example/v1`, 1),
		valid + `{}`,
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadProfileCatalog(path); !errors.Is(err, ErrInvalidProfileCatalog) {
			t.Fatalf("LoadProfileCatalog(%q) error = %v", content, err)
		}
	}
}

func testProfileCatalog(t *testing.T) *ProfileCatalog {
	t.Helper()
	catalog, err := NewProfileCatalog([]Profile{{
		ProfileID: "deepseek-v4", Provider: ProviderDeepSeek, Model: "deepseekv4-pro",
		BaseURL: "https://api.deepseek.example/v1", SecretRef: "mounted:deepseek-token",
		ContextWindow: 65536, MaxOutputTokens: 8192,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}
