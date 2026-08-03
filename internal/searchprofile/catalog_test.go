package searchprofile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogBindsSearchEndpointCredentialAudienceAndLimits(t *testing.T) {
	catalog, err := NewCatalog([]Profile{{
		ProfileID: "tavily-default", Provider: ProviderTavily,
		BaseURL: "https://api.tavily.com/search", SecretRef: "mounted:tavily-token",
		MaxResults: 10, TimeoutSeconds: 20,
	}})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := catalog.ResolveSelection(Profile{
		ProfileID: "tavily-default", MaxResults: 5, TimeoutSeconds: 12,
	})
	if err != nil || selected.MaxResults != 5 || selected.TimeoutSeconds != 12 ||
		selected.SecretRef != "mounted:tavily-token" {
		t.Fatalf("ResolveSelection() = %#v, %v", selected, err)
	}
	for _, invalid := range []Profile{
		{ProfileID: "missing"},
		{ProfileID: "tavily-default", BaseURL: "https://attacker.invalid/search"},
		{ProfileID: "tavily-default", SecretRef: "mounted:other"},
		{ProfileID: "tavily-default", MaxResults: 11},
	} {
		if _, err := catalog.ResolveSelection(invalid); err == nil {
			t.Fatalf("ResolveSelection(%#v) unexpectedly succeeded", invalid)
		}
	}
}

func TestCatalogAcceptsOnlyReviewedOfficialProviderEndpoints(t *testing.T) {
	t.Parallel()
	for provider, endpoint := range map[Provider]string{
		ProviderTavily:         "https://api.tavily.com/search",
		ProviderBrave:          "https://api.search.brave.com/res/v1/web/search",
		ProviderExa:            "https://api.exa.ai/search",
		ProviderSerper:         "https://google.serper.dev/search",
		ProviderDeepSeekNative: "https://api.deepseek.com/anthropic/v1/messages",
	} {
		if _, err := NewCatalog([]Profile{{
			ProfileID: string(provider) + "-default", Provider: provider,
			BaseURL: endpoint, SecretRef: "mounted:" + string(provider) + "-token",
			MaxResults: 10, TimeoutSeconds: 20,
		}}); err != nil {
			t.Fatalf("official %s endpoint was rejected: %v", provider, err)
		}
		if _, err := NewCatalog([]Profile{{
			ProfileID: string(provider) + "-default", Provider: provider,
			BaseURL: endpoint + "/redirect", SecretRef: "mounted:" + string(provider) + "-token",
			MaxResults: 10, TimeoutSeconds: 20,
		}}); !errors.Is(err, ErrInvalidCatalog) {
			t.Fatalf("unreviewed %s endpoint error = %v", provider, err)
		}
	}
}

func TestLoadCatalogIsStrictAndSecretFree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "search-profiles.json")
	valid := `{"schema_version":1,"profiles":[{"profile_id":"deepseek-native-default","provider":"deepseek_native","base_url":"https://api.deepseek.com/anthropic/v1/messages","secret_ref":"mounted:model-token","max_results":8,"timeout_seconds":45,"auto_model_profile_ids":["deepseek-v4-pro"]}]}`
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog, err := LoadCatalog(path)
	if err != nil || len(catalog.IDs()) != 1 || catalog.IDs()[0] != "deepseek-native-default" {
		t.Fatalf("LoadCatalog() = %#v, %v", catalog, err)
	}
	automatic, ok := catalog.DefaultForModelProfile("deepseek-v4-pro")
	if !ok || automatic.ProfileID != "deepseek-native-default" ||
		!catalog.AllowsModelProfile(automatic.ProfileID, "deepseek-v4-pro") ||
		catalog.AllowsModelProfile(automatic.ProfileID, "other-model") {
		t.Fatalf("automatic model binding = %#v, %v", automatic, ok)
	}
	for _, invalid := range []string{
		`{"schema_version":1,"profiles":[]}`,
		`{"schema_version":1,"profiles":[{"profile_id":"x","provider":"brave","base_url":"http://api.example/search","secret_ref":"mounted:key","max_results":10,"timeout_seconds":15}]}`,
		`{"schema_version":1,"profiles":[{"profile_id":"x","provider":"brave","base_url":"https://api.example/search","secret_ref":"sk-abcdefghijklmnopqrstuvwxyz","max_results":10,"timeout_seconds":15}]}`,
		valid + `{}`,
		strings.Replace(valid, `["deepseek-v4-pro"]`, `["deepseek-v4-pro","deepseek-v4-pro"]`, 1),
	} {
		if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCatalog(path); !errors.Is(err, ErrInvalidCatalog) {
			t.Fatalf("LoadCatalog(%q) error = %v", invalid, err)
		}
	}
}

func TestCatalogRejectsMultipleAutomaticSearchProfilesForOneModel(t *testing.T) {
	t.Parallel()
	profiles := []Profile{
		{
			ProfileID: "deepseek-native-a", Provider: ProviderDeepSeekNative,
			BaseURL:   "https://api.deepseek.com/anthropic/v1/messages",
			SecretRef: "mounted:model-token", MaxResults: 8, TimeoutSeconds: 45,
		},
		{
			ProfileID: "deepseek-native-b", Provider: ProviderDeepSeekNative,
			BaseURL:   "https://api.deepseek.com/anthropic/v1/messages",
			SecretRef: "mounted:model-token", MaxResults: 6, TimeoutSeconds: 30,
		},
	}
	_, err := NewCatalogWithAutoBindings(profiles, map[string][]string{
		"deepseek-native-a": {"deepseek-v4-pro"},
		"deepseek-native-b": {"deepseek-v4-pro"},
	})
	if !errors.Is(err, ErrInvalidCatalog) {
		t.Fatalf("ambiguous automatic binding error = %v", err)
	}
}
