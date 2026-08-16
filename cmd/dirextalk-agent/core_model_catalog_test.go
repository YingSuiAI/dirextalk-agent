package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

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
		_, _ = w.Write([]byte(`{"data":[{"id":"openai/gpt-4o","name":"GPT-4o","architecture":{"output_modalities":[" TEXT ","text"," IMAGE ","text"],"input_modalities":[" TEXT ","image","IMAGE","audio"]},"context_length":128000,"top_provider":{"max_completion_tokens":131072},"api_key":"upstream-key","authorization":"Bearer upstream-key","metadata":{"api_key":"nested-key"}},{"id":"anthropic/claude-sonnet","name":"Claude Sonnet","architecture":{"output_modalities":["text"],"input_modalities":["text"]},"max_completion_tokens":65536,"top_provider":{"max_completion_tokens":32768}},{"id":"prefix/request-key","name":"must-drop-id"},{"id":"must-drop-name","displayName":"alias/request-key","owned_by":"owner/request-key"},{"id":"openai/text-embedding-3-small","architecture":{"output_modalities":["embedding"]}},{"id":"openai/gpt-image-1","architecture":{"output_modalities":["image"]}},{"id":"openai/gpt-4o","name":"duplicate"}]}`))
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
	if len(result.Models) != 2 || result.Models[0]["id"] != "openai/gpt-4o" || result.Models[0]["name"] != "GPT-4o" {
		t.Fatalf("unexpected conversation models: %#v", result.Models)
	}
	if got := result.Models[0]["max_completion_tokens"]; got != int64(131072) {
		t.Fatalf("nested OpenRouter max_completion_tokens = %#v, want 131072", got)
	}
	if result.Models[1]["id"] != "anthropic/claude-sonnet" || result.Models[1]["max_completion_tokens"] != int64(65536) {
		t.Fatalf("direct OpenRouter max_completion_tokens did not take precedence: %#v", result.Models[1])
	}
	if got, want := result.Models[0]["input_modalities"], []string{"text", "image"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("input modalities = %#v, want %#v", got, want)
	}
	if got, want := result.Models[0]["output_modalities"], []string{"image", "text"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("output modalities = %#v, want %#v", got, want)
	}
	encoded, _ := json.Marshal(result)
	for _, secret := range []string{"request-key", "upstream-key", "nested-key"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("catalog response leaked %q: %s", secret, encoded)
		}
	}
}

func TestCoreModelCatalogMalformedScalarTypesMatchClosedDescriptor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"typed-model","object":123,"created":"1700000000","created_at":1700000000,"owned_by":true,"type":[],"context_length":"128000","context_window":64000.5,"max_input_tokens":4096.0,"max_output_tokens":"8192","max_tokens":8192,"input_token_limit":null,"output_token_limit":"16384","output_modalities":["text"],"input_modalities":["text"]}]}`))
	}))
	defer server.Close()

	result, err := newCoreModelCatalog(nil).ListModels(context.Background(), agentcapability.ModelCatalogRequest{
		Provider: "openrouter", BaseURL: server.URL + "/v1", APIKey: "request-key", ModelKind: coremodel.ModelKindConversation,
	})
	if err != nil {
		t.Fatalf("malformed scalar catalog: %v", err)
	}
	if len(result.Models) != 1 {
		t.Fatalf("malformed scalar models = %#v", result.Models)
	}
	model := result.Models[0]
	for _, field := range []string{"object", "created", "created_at", "owned_by", "type", "context_length", "context_window", "max_output_tokens", "input_token_limit", "output_token_limit"} {
		if _, ok := model[field]; ok {
			t.Fatalf("mismatched scalar field %q was projected: %#v", field, model[field])
		}
	}
	if _, ok := model["max_input_tokens"].(int64); !ok {
		t.Fatalf("valid integer scalar was not normalized to int64: %#v", model["max_input_tokens"])
	}
	if _, ok := model["max_tokens"].(int64); !ok {
		t.Fatalf("valid integer scalar was not normalized to int64: %#v", model["max_tokens"])
	}

	var schemaJSON string
	for _, operation := range agentcapability.NewInfoCapability(agentcapability.InfoProviderFunc{}).Descriptor().GetOperations() {
		if operation.GetOperationId() == "list_models" {
			schemaJSON = operation.GetResultSchemaJson()
			break
		}
	}
	var schema map[string]any
	if err := json.Unmarshal([]byte(schemaJSON), &schema); err != nil {
		t.Fatal(err)
	}
	modelSchema := schema["properties"].(map[string]any)["models"].(map[string]any)["items"].(map[string]any)
	properties := modelSchema["properties"].(map[string]any)
	for field, value := range model {
		property, ok := properties[field].(map[string]any)
		if !ok {
			t.Fatalf("projected field %q is outside descriptor schema: %#v", field, model)
		}
		typeName, _ := property["type"].(string)
		switch typeName {
		case "string":
			if _, ok := value.(string); !ok {
				t.Fatalf("field %q value=%T violates string schema", field, value)
			}
		case "integer":
			kind := reflect.ValueOf(value).Kind()
			if kind < reflect.Int || kind > reflect.Uint64 {
				t.Fatalf("field %q value=%T violates integer schema", field, value)
			}
		case "number":
			kind := reflect.ValueOf(value).Kind()
			if kind != reflect.Float32 && kind != reflect.Float64 && (kind < reflect.Int || kind > reflect.Uint64) {
				t.Fatalf("field %q value=%T violates number schema", field, value)
			}
		case "array":
			if reflect.ValueOf(value).Kind() != reflect.Slice {
				t.Fatalf("field %q value=%T violates array schema", field, value)
			}
		default:
			t.Fatalf("descriptor field %q has unsupported test type %q", field, typeName)
		}
	}
}

func TestCatalogIntegerValueKeepsExactIntegerBounds(t *testing.T) {
	maxInt64 := int64(^uint64(0) >> 1)
	minFloat := -float64(uint64(1) << 63)
	maxFloat := float64(uint64(1) << 63)
	for _, testCase := range []struct {
		name  string
		value any
		want  any
		ok    bool
	}{
		{name: "signed concrete", value: int64(-7), want: int64(-7), ok: true},
		{name: "unsigned concrete", value: uint64(maxInt64), want: maxInt64, ok: true},
		{name: "unsigned overflow", value: uint64(maxInt64) + 1, ok: false},
		{name: "minimum float", value: minFloat, want: int64(-1 << 63), ok: true},
		{name: "exclusive maximum float", value: maxFloat, ok: false},
		{name: "number maximum", value: json.Number("9223372036854775807"), want: maxInt64, ok: true},
		{name: "number maximum decimal", value: json.Number("9223372036854775807.0"), want: maxInt64, ok: true},
		{name: "number exclusive maximum", value: json.Number("9223372036854775808"), ok: false},
		{name: "number fraction", value: json.Number("7.5"), ok: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := catalogIntegerValue(testCase.value)
			if ok != testCase.ok || (ok && got != testCase.want) {
				t.Fatalf("catalogIntegerValue(%v) = (%v, %v), want (%v, %v)", testCase.value, got, ok, testCase.want, testCase.ok)
			}
		})
	}
}

func TestCatalogInputModalitiesRejectsMalformedListAsWholeField(t *testing.T) {
	if modalities, present := catalogInputModalities(map[string]any{"input_modalities": []any{"text", 1}}); present || modalities != nil {
		t.Fatalf("malformed direct input modalities = %#v, present=%v", modalities, present)
	}
	if modalities, present := catalogInputModalities(map[string]any{"architecture": map[string]any{"input_modalities": []any{"image", ""}}}); present || modalities != nil {
		t.Fatalf("malformed architecture input modalities = %#v, present=%v", modalities, present)
	}
}

func TestNormalizeCatalogModelsKeepsOnlyCanonicalOutputModalities(t *testing.T) {
	const secret = "CanaryKey-42"
	models := normalizeCatalogModelsWithSecret("openrouter", []map[string]any{
		{"id": "direct", "output_modalities": []any{" TEXT ", "text", " IMAGE ", "text"}},
		{"id": "architecture", "architecture": map[string]any{"output_modalities": []any{" Embedding ", "embedding"}}},
		{"id": "unknown-mixed", "output_modalities": []any{"text", secret, "audio"}},
		{"id": "empty", "output_modalities": []any{}},
		{"id": "invalid", "output_modalities": "text"},
	}, "")
	if len(models) != 5 {
		t.Fatalf("normalized models = %#v", models)
	}
	if got, want := models[0]["output_modalities"], []string{"image", "text"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("direct output modalities = %#v, want %#v", got, want)
	}
	if got, want := models[1]["output_modalities"], []string{"embedding"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("architecture output modalities = %#v, want %#v", got, want)
	}
	if got, want := models[2]["output_modalities"], []string{"audio", "text"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unknown output modalities were not filtered: %#v, want %#v", got, want)
	}
	if strings.Contains(string(mustJSON(models[2])), secret) {
		t.Fatalf("secret-like output modality leaked: %#v", models[2])
	}
	if _, ok := models[3]["output_modalities"]; ok {
		t.Fatalf("empty output modalities should be omitted: %#v", models[3])
	}
	if _, ok := models[4]["output_modalities"]; ok {
		t.Fatalf("invalid output modalities should be omitted: %#v", models[4])
	}
}

func mustJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
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

func TestCoreModelCatalogClassifiesNetworkAndTimeoutFailures(t *testing.T) {
	tests := []struct {
		name    string
		client  *http.Client
		timeout time.Duration
		want    error
	}{
		{
			name: "network unavailable",
			client: &http.Client{Transport: catalogRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("private network detail")
			})},
			timeout: time.Second,
			want:    coremodel.ErrProviderUnavailable,
		},
		{
			name: "provider timeout",
			client: &http.Client{Transport: catalogRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				<-request.Context().Done()
				return nil, request.Context().Err()
			})},
			timeout: 10 * time.Millisecond,
			want:    context.DeadlineExceeded,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			catalog := newCoreModelCatalogWithHTTPClient(nil, test.client, test.timeout)
			_, err := catalog.ListModels(context.Background(), agentcapability.ModelCatalogRequest{
				Provider: "openrouter", BaseURL: "https://example.test/v1", APIKey: "request-key", ModelKind: coremodel.ModelKindConversation,
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), "private network detail") || strings.Contains(err.Error(), "request-key") {
				t.Fatalf("classified error leaked private detail: %v", err)
			}
		})
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

func TestCoreModelCatalogConversationProfileCanDiscoverOpenRouterEmbeddings(t *testing.T) {
	repo := coremodel.NewMemoryProfileRepository()
	profiles, err := coremodel.NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	const profileID = "44444444-4444-4444-8444-444444444444"
	key := "stored-openrouter-key"
	if _, err := profiles.Create(context.Background(), coremodel.CreateProfileCommand{
		IdempotencyKey: "55555555-5555-4555-8555-555555555555",
		Spec: coremodel.ProfileSpec{
			ID:          profileID,
			DisplayName: "OpenRouter chat",
			Provider:    coremodel.ModelProvider("openrouter"),
			ModelKind:   coremodel.ModelKindConversation,
			BaseURL:     "https://openrouter.ai/api/v1",
			Model:       "openai/gpt-4o-mini",
			APIKey:      &key,
		},
	}); err != nil {
		t.Fatal(err)
	}
	catalog := newCoreModelCatalogWithHTTPClient(profiles, &http.Client{Transport: catalogRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://openrouter.ai/api/v1/embeddings/models" || r.Header.Get("Authorization") != "Bearer "+key {
			t.Fatalf("embedding credential request url=%q auth=%q", r.URL, r.Header.Get("Authorization"))
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":[{"id":"openai/text-embedding-3-small","architecture":{"output_modalities":["embeddings"]}}]}`))}, nil
	})}, 0)
	result, err := catalog.ListModels(context.Background(), agentcapability.ModelCatalogRequest{
		ModelProfileID: profileID,
		ModelKind:      coremodel.ModelKindEmbedding,
	})
	if err != nil {
		t.Fatalf("embedding catalog via conversation credential: %v", err)
	}
	if len(result.Models) != 1 || result.Models[0]["id"] != "openai/text-embedding-3-small" {
		t.Fatalf("embedding models = %#v", result.Models)
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
		IdempotencyKey:               "33333333-3333-4333-8333-333333333333",
		DefaultConversationProfileID: "chat",
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
