package model

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListModelsReturnsOnlySanitizedMetadata(t *testing.T) {
	const credential = "sk-discovery-secret-1234567890"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/models" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer "+credential {
			t.Fatal("missing model discovery authorization")
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":[
			{"id":"z-model","name":"Z","context_length":131072,"api_key":"must-not-cross"},
			{"id":"a-model","display_name":"A","max_output_tokens":"8192","reasoning_modes":["low","high"]},
			{"id":"a-model","name":"duplicate"},
			{"id":"` + credential + `","name":"credential echo"}
		]}`))
	}))
	defer server.Close()

	models, err := ListModels(context.Background(), Profile{
		ProfileID: "discovery", Provider: ProviderOpenAICompatible,
		Model: "model-discovery", BaseURL: server.URL + "/v1",
		SecretRef: "transient:test", AllowInsecureHTTP: true,
	}, SecretResolverFunc(func(context.Context, string) ([]byte, error) {
		return []byte(credential), nil
	}), WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 2 || models[0].ID != "a-model" || models[1].ID != "z-model" {
		t.Fatalf("models = %#v", models)
	}
	if models[0].MaxOutputTokens != 8192 || strings.Join(models[0].ReasoningModes, ",") != "low,high" || models[1].ContextWindow != 131072 {
		t.Fatalf("sanitized metadata = %#v", models)
	}
}

func TestListModelsUsesAnthropicHeadersAndEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/models" || request.Header.Get("x-api-key") != "anthropic-key-123456" || request.Header.Get("anthropic-version") == "" {
			t.Fatalf("request path=%q headers=%v", request.URL.Path, request.Header)
		}
		_, _ = writer.Write([]byte(`{"data":[{"id":"claude-test","display_name":"Claude Test"}]}`))
	}))
	defer server.Close()

	models, err := ListModels(context.Background(), Profile{
		ProfileID: "discovery", Provider: ProviderAnthropic, Model: "model-discovery",
		BaseURL: server.URL, SecretRef: "transient:test", AllowInsecureHTTP: true,
	}, SecretResolverFunc(func(context.Context, string) ([]byte, error) {
		return []byte("anthropic-key-123456"), nil
	}), WithHTTPClient(server.Client()))
	if err != nil || len(models) != 1 || models[0].Name != "Claude Test" {
		t.Fatalf("models=%#v err=%v", models, err)
	}
}
