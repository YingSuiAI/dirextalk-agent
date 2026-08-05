package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

func TestCoreModelCatalogWithoutProviderReturnsMetadataOnly(t *testing.T) {
	catalog := newCoreModelCatalog(nil)
	result, err := catalog.ListModels(context.Background(), agentcapability.ModelCatalogRequest{ModelKind: coremodel.ModelKindConversation})
	if err != nil {
		t.Fatalf("metadata catalog: %v", err)
	}
	if len(result.Models) != 0 {
		t.Fatalf("metadata catalog returned models: %#v", result.Models)
	}
	if len(result.Providers) != len(coreSupportedModelProviders) {
		t.Fatalf("provider metadata count = %d, want %d", len(result.Providers), len(coreSupportedModelProviders))
	}
	for _, provider := range result.Providers {
		if provider.DefaultBaseURL == "" || !provider.RequiresAPIKey || !provider.DynamicModels {
			t.Fatalf("incomplete provider metadata: %#v", provider)
		}
	}
}

func TestCoreModelCatalogOpenRouterConversationUsesTextFilterAndSafeNormalization(t *testing.T) {
	var gotPath, gotQuery, gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery, gotAuth = r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"openai/gpt-4o","name":"GPT-4o","architecture":{"output_modalities":["text"],"input_modalities":[" TEXT ","image","IMAGE","audio"]},"context_length":128000,"api_key":"upstream-key","authorization":"Bearer upstream-key","metadata":{"api_key":"nested-key"}},{"id":"prefix/request-key","name":"must-drop-id"},{"id":"must-drop-name","displayName":"alias/request-key","owned_by":"owner/request-key"},{"id":"openai/text-embedding-3-small","architecture":{"output_modalities":["embedding"]}},{"id":"openai/gpt-image-1","architecture":{"output_modalities":["image"]}},{"id":"openai/gpt-4o","name":"duplicate"}]}`))
	}))
	defer server.Close()

	result, err := newCoreModelCatalog(nil).ListModels(context.Background(), agentcapability.ModelCatalogRequest{
		Provider: "openrouter", BaseURL: server.URL + "/v1", APIKey: "request-key", ModelKind: coremodel.ModelKindConversation,
	})
	if err != nil {
		t.Fatalf("OpenRouter conversation catalog: %v", err)
	}
	if gotPath != "/v1/models" || gotQuery != "output_modalities=text" || gotAuth != "Bearer request-key" {
		t.Fatalf("provider request path=%q query=%q auth=%q", gotPath, gotQuery, gotAuth)
	}
	if len(result.Models) != 1 || result.Models[0]["id"] != "openai/gpt-4o" || result.Models[0]["name"] != "GPT-4o" {
		t.Fatalf("unexpected conversation models: %#v", result.Models)
	}
	if got, want := result.Models[0]["input_modalities"], []string{"text", "image"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("input modalities = %#v, want %#v", got, want)
	}
	encoded, _ := json.Marshal(result)
	for _, secret := range []string{"request-key", "upstream-key", "nested-key"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("catalog response leaked %q: %s", secret, encoded)
		}
	}
}

func TestNormalizeCatalogModelsDropsSecretBearingEntriesAndKeepsNormalEntries(t *testing.T) {
	const secret = "CanaryKey-42"
	raw := []map[string]any{
		{"id": "prefix/" + secret, "name": "drop by id"},
		{"id": "drop-by-name", "displayName": "alias/" + secret},
		{"id": "drop-by-owned-by", "owned_by": "Bearer " + secret},
		{"id": "normal", "name": "Normal model", "owned_by": "provider"},
	}
	models := normalizeCatalogModelsWithSecret("openrouter", raw, secret)
	if len(models) != 1 {
		t.Fatalf("secret-bearing model entries were not dropped: %#v", models)
	}
	if got := models[0]["id"]; got != "normal" {
		t.Fatalf("normal model was not retained: %#v", models)
	}
}

func TestCatalogValueContainsSecretRecursesMapsListsAndAliases(t *testing.T) {
	const secret = "CanaryKey-42"
	value := map[string]any{
		"Metadata": []any{
			map[string]any{"Authorization": "Bearer " + secret},
			[]any{"safe", map[string]any{"alias": "prefix/" + secret}},
		},
	}
	if !catalogValueContainsSecret(value, secret) {
		t.Fatal("nested map/list secret was not detected")
	}
	if catalogValueContainsSecret(value, "different-case-canarykey-42") {
		t.Fatal("non-literal credential unexpectedly matched")
	}
	typedValue := map[string][]map[string]string{
		"Aliases": {{"Name": "prefix/" + secret}},
	}
	if !catalogValueContainsSecret(typedValue, secret) {
		t.Fatal("typed nested map/list secret was not detected")
	}
}

func TestCoreModelCatalogFailsClosedWhenAllEntriesEchoAPIKey(t *testing.T) {
	const secret = "CanaryKey-42"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"prefix/CanaryKey-42"},{"id":"other","name":"Bearer CanaryKey-42"}]}`))
	}))
	defer server.Close()

	_, err := newCoreModelCatalog(nil).ListModels(context.Background(), agentcapability.ModelCatalogRequest{
		Provider: "openrouter", BaseURL: server.URL + "/v1", APIKey: secret, ModelKind: coremodel.ModelKindConversation,
	})
	if err == nil || !strings.Contains(err.Error(), "returned no models") {
		t.Fatalf("all-secret catalog error = %v, want safe no-models failure", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("safe failure leaked API key: %v", err)
	}
}

func TestCoreModelCatalogOpenRouterEmbeddingUsesDedicatedEndpoint(t *testing.T) {
	var genericRequests int
	var gotPath, gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/models" {
			genericRequests++
			_, _ = w.Write([]byte(`{"data":[{"id":"chat-should-not-appear"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"openai/text-embedding-3-small","architecture":{"output_modalities":["embeddings"]}},{"id":"openai/gpt-4o","architecture":{"output_modalities":["text"]}}]}`))
	}))
	defer server.Close()

	result, err := newCoreModelCatalog(nil).ListModels(context.Background(), agentcapability.ModelCatalogRequest{
		Provider: "openrouter", BaseURL: server.URL + "/v1", APIKey: "embedding-key", ModelKind: coremodel.ModelKindEmbedding,
	})
	if err != nil {
		t.Fatalf("OpenRouter embedding catalog: %v", err)
	}
	if gotPath != "/v1/embeddings/models" || gotAuth != "Bearer embedding-key" || genericRequests != 0 {
		t.Fatalf("embedding request path=%q auth=%q generic requests=%d", gotPath, gotAuth, genericRequests)
	}
	if len(result.Models) != 1 || result.Models[0]["id"] != "openai/text-embedding-3-small" {
		t.Fatalf("unexpected embedding models: %#v", result.Models)
	}
}

func TestCoreModelCatalogRejectsRedirectAndRedactsProviderFailure(t *testing.T) {
	var redirectedRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			http.Redirect(w, r, "/v1/redirected", http.StatusFound)
		case "/v1/redirected":
			redirectedRequests++
			_, _ = w.Write([]byte(`{"data":[{"id":"must-not-be-fetched"}]}`))
		default:
			http.Error(w, "provider-body request-key", http.StatusBadGateway)
		}
	}))
	defer server.Close()

	_, err := newCoreModelCatalog(nil).ListModels(context.Background(), agentcapability.ModelCatalogRequest{
		Provider: "openrouter", BaseURL: server.URL + "/v1", APIKey: "request-key", ModelKind: coremodel.ModelKindConversation,
	})
	if err == nil || !strings.Contains(err.Error(), "status 302") {
		t.Fatalf("redirect error = %v, want status-only error", err)
	}
	if strings.Contains(err.Error(), "request-key") || strings.Contains(err.Error(), "provider-body") {
		t.Fatalf("provider error leaked secret/body: %v", err)
	}
	if redirectedRequests != 0 {
		t.Fatalf("catalog followed redirect: %d redirected requests", redirectedRequests)
	}
}

func TestCoreModelCatalogRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bytes.Repeat([]byte("x"), coreModelCatalogResponseMax+1))
	}))
	defer server.Close()

	_, err := newCoreModelCatalog(nil).ListModels(context.Background(), agentcapability.ModelCatalogRequest{
		Provider: "openrouter", BaseURL: server.URL + "/v1", APIKey: "request-key", ModelKind: coremodel.ModelKindConversation,
	})
	if err == nil || !strings.Contains(err.Error(), "response exceeds size limit") {
		t.Fatalf("oversized response error = %v", err)
	}
}

func TestCoreModelCatalogProfileIDUsesDurableProfileSecret(t *testing.T) {
	repo := coremodel.NewMemoryProfileRepository()
	profiles, err := coremodel.NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	const profileID = "11111111-1111-4111-8111-111111111111"
	key := "stored-profile-key"
	if _, err := profiles.Create(context.Background(), coremodel.CreateProfileCommand{
		IdempotencyKey: "22222222-2222-4222-8222-222222222222",
		Spec:           coremodel.ProfileSpec{ID: profileID, DisplayName: "Catalog", Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindConversation, BaseURL: "https://models.example/v1", Model: "chat", APIKey: &key},
	}); err != nil {
		t.Fatal(err)
	}
	catalog := newCoreModelCatalogWithHTTPClient(profiles, &http.Client{Transport: catalogRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://models.example/v1/models" || r.Header.Get("Authorization") != "Bearer "+key {
			t.Fatalf("profile request url=%q auth=%q", r.URL, r.Header.Get("Authorization"))
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":[{"id":"profile-model"}]}`))}, nil
	})}, 0)
	result, err := catalog.ListModels(context.Background(), agentcapability.ModelCatalogRequest{ModelProfileID: profileID, ModelKind: coremodel.ModelKindConversation})
	if err != nil {
		t.Fatalf("profile catalog: %v", err)
	}
	if len(result.Models) != 1 || result.Models[0]["id"] != "profile-model" {
		t.Fatalf("profile models = %#v", result.Models)
	}
}

func TestCoreModelCatalogClientProfileIDUsesDurableProfileSecret(t *testing.T) {
	repo := coremodel.NewMemoryProfileRepository()
	profiles, err := coremodel.NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	const key = "stored-client-profile-key"
	if _, err := profiles.Sync(context.Background(), coremodel.SyncProfileCommand{
		IdempotencyKey:         "33333333-3333-4333-8333-333333333333",
		DefaultClientProfileID: "chat",
		Entries: []coremodel.SyncProfileEntry{{
			ClientProfileID: "chat", DisplayName: "Chat", Provider: coremodel.ProviderOpenAICompatible,
			ModelKind: coremodel.ModelKindConversation, BaseURL: "https://models.example/v1", Model: "chat", APIKey: stringPtrCatalog(key),
		}},
	}); err != nil {
		t.Fatal(err)
	}
	catalog := newCoreModelCatalogWithHTTPClient(profiles, &http.Client{Transport: catalogRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://models.example/v1/models" || r.Header.Get("Authorization") != "Bearer "+key {
			t.Fatalf("client profile request url=%q auth=%q", r.URL, r.Header.Get("Authorization"))
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":[{"id":"client-profile-model"}]}`))}, nil
	})}, 0)
	result, err := catalog.ListModels(context.Background(), agentcapability.ModelCatalogRequest{ClientModelProfileID: "chat", ModelKind: coremodel.ModelKindConversation})
	if err != nil {
		t.Fatalf("client profile catalog: %v", err)
	}
	if len(result.Models) != 1 || result.Models[0]["id"] != "client-profile-model" {
		t.Fatalf("client profile models = %#v", result.Models)
	}
}

func stringPtrCatalog(value string) *string {
	return &value
}

type catalogRoundTripFunc func(*http.Request) (*http.Response, error)

func (f catalogRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
