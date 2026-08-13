package agentcapability

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

func capabilityTestContext() context.Context {
	return capabilityclient.WithCallContext(context.Background(), &capv1.CallContext{ChainId: "00000000-0000-4000-8000-000000000001", RootOperationId: "00000000-0000-4000-8000-000000000002", Route: "ms→agent"}, &capv1.PermissionContext{AuthenticatedOwnerId: "owner-1", AccountGeneration: 1})
}

func TestInfoCapabilityUsesAuthenticatedContextAndNormalizesOutput(t *testing.T) {
	capability := NewInfoCapability(InfoProviderFunc{
		BackendsFunc: func(context.Context) (BackendsSnapshot, error) {
			return BackendsSnapshot{Embedded: BackendInfo{Status: "READY", Capabilities: []string{"memory.server", "memory.server", "agent.info"}}, Core: BackendInfo{Status: "future-secret-status", ReleaseVersion: " v1.0.0 ", Capabilities: []string{"z", "a"}}}, nil
		},
		ModelsFunc: func(_ context.Context, request ModelCatalogRequest) (ModelCatalogResult, error) {
			if request.ModelKind != "conversation" || (request.Provider != "" && request.APIKey != "secret-key") {
				t.Fatalf("catalog request = %#v", request)
			}
			return ModelCatalogResult{Models: []map[string]any{{"id": "gpt", "provider": "openrouter", "api_key": "upstream-key", "base_url": "https://openrouter.ai/api/v1"}}, Providers: []ModelCatalogProviderInfo{{Provider: "openrouter", RequiresAPIKey: true}}}, nil
		},
	})
	var catalogSchema string
	for _, operation := range capability.Descriptor().GetOperations() {
		if operation.GetOperationId() == "list_models" {
			catalogSchema = operation.GetInputSchemaJson()
		}
	}
	if !strings.Contains(catalogSchema, `"writeOnly":true`) || strings.Contains(catalogSchema, `"write_only"`) {
		t.Fatalf("model catalog API key schema is not standard writeOnly: %s", catalogSchema)
	}
	result, err := capability.HandleOperation(capabilityTestContext(), "get_backends", []byte(`{}`))
	if err != nil {
		t.Fatalf("get_backends: %v", err)
	}
	var value BackendsSnapshot
	if err := json.Unmarshal(result, &value); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if value.Embedded.Status != "ready" || strings.Join(value.Embedded.Capabilities, ",") != "agent.info,memory.server" {
		t.Fatalf("normalized backend = %#v", value.Embedded)
	}
	if value.Core.Status != "unknown" || value.Core.ReleaseVersion != "v1.0.0" {
		t.Fatalf("unknown status was not fail-closed: %#v", value.Core)
	}
	if _, err := capability.HandleOperation(capabilityTestContext(), "get_backends", []byte(`{"owner_id":"attacker"}`)); err == nil {
		t.Fatal("caller-supplied owner field must be rejected")
	}
	if _, err := capability.HandleOperation(context.Background(), "get_backends", []byte(`{}`)); err == nil {
		t.Fatal("missing authenticated context must be rejected")
	}
	models, err := capability.HandleOperation(capabilityTestContext(), "list_models", []byte(`{"model_kind":"conversation","provider":"openrouter","base_url":"https://openrouter.ai/api/v1","api_key":"secret-key"}`))
	if err != nil {
		t.Fatalf("list_models: %v", err)
	}
	if strings.Contains(string(models), "secret-key") || strings.Contains(string(models), "upstream-key") || !strings.Contains(string(models), "openrouter") {
		t.Fatalf("catalog leaked credential or omitted provider: %s", models)
	}
	if _, err := capability.HandleOperation(capabilityTestContext(), "list_models", []byte(`{}`)); err != nil {
		t.Fatalf("default conversation model catalog: %v", err)
	}
}

func TestInfoCapabilitySanitizesClosedCatalogConsumerProjection(t *testing.T) {
	const requestAPIKey = "request-key"
	var gotRequest ModelCatalogRequest
	capability := NewInfoCapability(InfoProviderFunc{
		BackendsFunc: func(context.Context) (BackendsSnapshot, error) { return BackendsSnapshot{}, nil },
		ModelsFunc: func(_ context.Context, request ModelCatalogRequest) (ModelCatalogResult, error) {
			gotRequest = request
			return ModelCatalogResult{
				Models: []map[string]any{
					{
						"ID":                 "valid-model",
						"PROVIDER":           "OpenRouter",
						"NAME":               "Valid model",
						"OBJECT":             "model",
						"CREATED":            float64(1700000000),
						"CREATED_AT":         "2023-11-14T22:13:20Z",
						"OWNED_BY":           "provider",
						"TYPE":               "chat",
						"INPUT_MODALITIES":   []any{"TEXT", "image"},
						"OUTPUT_MODALITIES":  []any{"TEXT", "image", "audio"},
						"MAX_INPUT_TOKENS":   float64(4096),
						"MAX_OUTPUT_TOKENS":  float64(8192),
						"MAX_TOKENS":         float64(16384),
						"INPUT_TOKEN_LIMIT":  float64(32768),
						"OUTPUT_TOKEN_LIMIT": float64(65536),
						"metadata":           map[string]any{"safe": "drop"},
						"access_token":       "drop",
					},
					{
						"id":                 "malformed-model",
						"provider":           "openrouter",
						"name":               42,
						"input_modalities":   []any{"text", 1},
						"output_modalities":  []any{"text", ""},
						"max_input_tokens":   1.5,
						"max_output_tokens":  json.Number("9223372036854775808"),
						"max_tokens":         json.Number("8192.0"),
						"input_token_limit":  json.Number("32768"),
						"output_token_limit": json.Number("65536"),
					},
					{"id": requestAPIKey + "/model", "provider": "openrouter"},
					{"id": "secret-in-name", "name": "Bearer " + requestAPIKey, "provider": "openrouter"},
					{"id": "secret-in-provider", "provider": "provider/" + requestAPIKey},
					{"id": "secret-in-nested", "provider": "openrouter", "metadata": map[string]any{"harmless": requestAPIKey}},
				},
				Providers: []ModelCatalogProviderInfo{
					{Provider: "OPENROUTER", DefaultBaseURL: "https://openrouter.ai/api/v1", RequiresAPIKey: true, DynamicModels: true},
					{Provider: "DEEPSEEK", DefaultBaseURL: "https://api.deepseek.com/v1", RequiresAPIKey: true, DynamicModels: true},
					{Provider: requestAPIKey, DefaultBaseURL: "https://invalid.example", RequiresAPIKey: true, DynamicModels: true},
				},
			}, nil
		},
	})

	result, err := capability.HandleOperation(capabilityTestContext(), "list_models", []byte(`{"model_kind":"conversation","api_key":"request-key"}`))
	if err != nil {
		t.Fatalf("list_models: %v", err)
	}
	if gotRequest.APIKey != requestAPIKey || gotRequest.ModelKind != "conversation" {
		t.Fatalf("provider received request = %#v, want API key and kind", gotRequest)
	}

	var payload struct {
		Models    []map[string]any `json:"models"`
		Providers []map[string]any `json:"providers"`
	}
	if err := json.Unmarshal(result, &payload); err != nil {
		t.Fatalf("decode list_models result: %v", err)
	}
	if len(payload.Models) != 3 {
		t.Fatalf("models = %#v, want valid entries including one whose discarded metadata echoed the request key", payload.Models)
	}
	if len(payload.Providers) != 2 {
		t.Fatalf("providers = %#v, want credential-bearing provider omitted", payload.Providers)
	}

	wantModelKeys := map[string]struct{}{
		"id": {}, "provider": {}, "name": {}, "object": {}, "created": {}, "created_at": {}, "owned_by": {}, "type": {},
		"input_modalities": {}, "output_modalities": {}, "max_input_tokens": {}, "max_output_tokens": {}, "max_tokens": {},
		"input_token_limit": {}, "output_token_limit": {},
	}
	valid := payload.Models[0]
	if valid["id"] != "valid-model" {
		t.Fatalf("valid model = %#v", valid)
	}
	for key := range valid {
		if _, ok := wantModelKeys[key]; !ok {
			t.Fatalf("unknown/non-canonical model key %q survived: %#v", key, valid)
		}
		if key != strings.ToLower(key) {
			t.Fatalf("model key %q was not canonical lowercase", key)
		}
	}
	for key, want := range map[string]float64{
		"max_input_tokens":   4096,
		"max_output_tokens":  8192,
		"max_tokens":         16384,
		"input_token_limit":  32768,
		"output_token_limit": 65536,
	} {
		if got, ok := valid[key].(float64); !ok || got != want {
			t.Fatalf("valid numeric field %q = %#v, want %v", key, valid[key], want)
		}
	}
	if got, want := valid["input_modalities"], []any{"text", "image"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("input modalities = %#v, want %#v", got, want)
	}
	if got, want := valid["output_modalities"], []any{"audio", "image", "text"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("output modalities = %#v, want %#v", got, want)
	}
	for _, key := range []string{"metadata", "access_token"} {
		if _, ok := valid[key]; ok {
			t.Fatalf("unknown field %q survived: %#v", key, valid)
		}
	}

	malformed := payload.Models[1]
	for _, key := range []string{"name", "input_modalities", "output_modalities", "max_input_tokens", "max_output_tokens"} {
		if _, ok := malformed[key]; ok {
			t.Fatalf("malformed field %q survived: %#v", key, malformed)
		}
	}
	for key, want := range map[string]float64{"max_tokens": 8192, "input_token_limit": 32768, "output_token_limit": 65536} {
		if got, ok := malformed[key].(float64); !ok || got != want {
			t.Fatalf("valid malformed-model numeric field %q = %#v, want %v", key, malformed[key], want)
		}
	}

	metadataEcho := payload.Models[2]
	if metadataEcho["id"] != "secret-in-nested" || metadataEcho["provider"] != "openrouter" {
		t.Fatalf("metadata-echo model = %#v", metadataEcho)
	}
	if _, ok := metadataEcho["metadata"]; ok {
		t.Fatalf("discarded provider metadata survived: %#v", metadataEcho)
	}

	wantProviderKeys := map[string]struct{}{"provider": {}, "default_base_url": {}, "requires_api_key": {}, "dynamic_models": {}}
	for _, provider := range payload.Providers {
		if provider["provider"] == requestAPIKey {
			t.Fatalf("credential-bearing provider survived: %#v", provider)
		}
		for key := range provider {
			if _, ok := wantProviderKeys[key]; !ok {
				t.Fatalf("unknown provider key %q survived: %#v", key, provider)
			}
		}
	}
	if strings.Contains(string(result), requestAPIKey) {
		t.Fatalf("request API key leaked in consumer result: %s", result)
	}
}

func TestInfoCapabilityRetainsClosedModelNumericTokenFields(t *testing.T) {
	capability := NewInfoCapability(InfoProviderFunc{
		BackendsFunc: func(context.Context) (BackendsSnapshot, error) { return BackendsSnapshot{}, nil },
		ModelsFunc: func(context.Context, ModelCatalogRequest) (ModelCatalogResult, error) {
			return ModelCatalogResult{Models: []map[string]any{{
				"id":                 "typed-model",
				"provider":           "openrouter",
				"max_input_tokens":   int64(4096),
				"max_output_tokens":  int64(8192),
				"max_tokens":         int64(16384),
				"input_token_limit":  int64(32768),
				"output_token_limit": int64(65536),
				"access_token":       "must-drop",
				"token":              "must-drop",
			}}}, nil
		},
	})
	result, err := capability.HandleOperation(capabilityTestContext(), "list_models", []byte(`{"model_kind":"conversation"}`))
	if err != nil {
		t.Fatalf("list_models: %v", err)
	}
	var payload struct {
		Models []map[string]any `json:"models"`
	}
	if err := json.Unmarshal(result, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Models) != 1 {
		t.Fatalf("models = %#v", payload.Models)
	}
	model := payload.Models[0]
	for field, want := range map[string]float64{
		"max_input_tokens":   4096,
		"max_output_tokens":  8192,
		"max_tokens":         16384,
		"input_token_limit":  32768,
		"output_token_limit": 65536,
	} {
		if got, ok := model[field].(float64); !ok || got != want {
			t.Fatalf("numeric field %q = %#v, want %v", field, model[field], want)
		}
	}
	for _, field := range []string{"access_token", "token"} {
		if _, ok := model[field]; ok {
			t.Fatalf("secret token field %q survived sanitizer: %#v", field, model)
		}
	}
}

func TestModelCatalogResultSchemaClosesModelProjection(t *testing.T) {
	capability := NewInfoCapability(InfoProviderFunc{})
	var schemaJSON string
	for _, operation := range capability.Descriptor().GetOperations() {
		if operation.GetOperationId() == "list_models" {
			schemaJSON = operation.GetResultSchemaJson()
			break
		}
	}
	var schema map[string]any
	if err := json.Unmarshal([]byte(schemaJSON), &schema); err != nil {
		t.Fatal(err)
	}
	properties := schema["properties"].(map[string]any)
	models := properties["models"].(map[string]any)
	model := models["items"].(map[string]any)
	if model["additionalProperties"] != false {
		t.Fatalf("model schema is not closed: %s", schemaJSON)
	}
	modelProperties := model["properties"].(map[string]any)
	outputModalities, ok := modelProperties["output_modalities"].(map[string]any)
	if !ok || outputModalities["type"] != "array" {
		t.Fatalf("output_modalities missing from model schema: %s", schemaJSON)
	}
	items := outputModalities["items"].(map[string]any)
	var wantEnum []any
	if err := json.Unmarshal([]byte(ModelCatalogOutputModalitiesJSON), &wantEnum); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(items["enum"], wantEnum) {
		t.Fatalf("output modality enum=%#v, want %#v", items["enum"], wantEnum)
	}
	for _, secretField := range []string{"api_key", "authorization", "password", "secret", "token"} {
		if _, exists := modelProperties[secretField]; exists {
			t.Fatalf("secret field %q appeared in model schema: %s", secretField, schemaJSON)
		}
	}
	for _, required := range model["required"].([]any) {
		if required == "output_modalities" {
			t.Fatal("output_modalities must remain optional")
		}
	}
}

func TestInfoCapabilityKeepsProfileAndEmptyAPIKeyErrorsIntact(t *testing.T) {
	providerError := errors.New("provider profile lookup failed")
	capability := NewInfoCapability(InfoProviderFunc{
		BackendsFunc: func(context.Context) (BackendsSnapshot, error) { return BackendsSnapshot{}, nil },
		ModelsFunc: func(context.Context, ModelCatalogRequest) (ModelCatalogResult, error) {
			return ModelCatalogResult{}, providerError
		},
	})
	for _, input := range []string{
		`{"model_profile_id":"profile-without-request-key"}`,
		`{}`,
	} {
		_, err := capability.HandleOperation(capabilityTestContext(), "list_models", []byte(input))
		if err == nil || err.Error() != providerError.Error() {
			t.Fatalf("catalog input %s error=%v, want unchanged provider error", input, err)
		}
	}
}

func TestRedactSecretErrorDoesNotReplaceEmptySecret(t *testing.T) {
	err := errors.New("provider request failed")
	if got := redactSecretError(err, ""); got == nil || got.Error() != err.Error() {
		t.Fatalf("empty-secret error = %v, want original message", got)
	}
}

type runtimePortFake struct {
	install RuntimeInstallRequest
	run     RuntimeRunRequest
}

func (p *runtimePortFake) Inspect(context.Context) (RuntimeInspection, error) {
	return RuntimeInspection{Ready: true, Configured: true, Capabilities: []string{"runtime"}, Tools: []string{"echo"}}, nil
}
func (p *runtimePortFake) Install(_ context.Context, request RuntimeInstallRequest) (RuntimeInstallResult, error) {
	p.install = request
	return RuntimeInstallResult{Installed: true, Target: request.Target, Status: "ready"}, nil
}
func (p *runtimePortFake) Which(context.Context, string) (RuntimeWhichResult, error) {
	return RuntimeWhichResult{Found: true, Name: "echo", Path: "/agent/runtime/bin/echo", Version: "1"}, nil
}
func (p *runtimePortFake) Run(_ context.Context, request RuntimeRunRequest) (RuntimeRunResult, error) {
	p.run = request
	return RuntimeRunResult{Tool: request.Tool, ExitCode: 0, Stdout: "ok\x00\n", Stderr: ""}, nil
}
func TestRuntimeCapabilityRejectsShell(t *testing.T) {
	port := &runtimePortFake{}
	capability := NewRuntimeCapability(port)
	if _, err := capability.HandleOperation(capabilityTestContext(), "install", []byte(`{"target":"echo","command":"echo pwned"}`)); err == nil {
		t.Fatal("runtime install accepted a shell command")
	}
	if _, err := capability.HandleOperation(capabilityTestContext(), "run", []byte(`{"tool":"echo","command":"echo pwned"}`)); err == nil {
		t.Fatal("runtime run accepted a shell command")
	}
	if _, err := capability.HandleOperation(capabilityTestContext(), "run", []byte(`{"tool":"echo","argv":["ok"]}`)); err != nil {
		t.Fatalf("argv run: %v", err)
	}
	if string(port.run.Argv[0]) != "ok" {
		t.Fatalf("argv was not forwarded: %#v", port.run)
	}
}

func TestRegisterMiscCapabilitiesDoesNotPublishUnavailableRuntime(t *testing.T) {
	r := NewRegistry()
	if err := RegisterMiscCapabilities(r, MiscBindings{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, ok := r.Get(configCapabilityID); ok {
		t.Fatal("unconfigured config capability was published")
	}
	if _, ok := r.Get(infoCapabilityID); ok {
		t.Fatal("unconfigured info capability was published")
	}
	if _, ok := r.Get(runtimeCapabilityID); ok {
		t.Fatal("unconfigured runtime capability was published")
	}
}

func TestMiscDescriptorsCarrySchemaDigests(t *testing.T) {
	for _, capability := range []Capability{NewInfoCapability(InfoProviderFunc{}), NewRuntimeCapability(&runtimePortFake{})} {
		for _, operation := range capability.Descriptor().GetOperations() {
			if len(operation.GetInputSchemaDigest()) != 32 || len(operation.GetResultSchemaDigest()) != 32 {
				t.Fatalf("missing schema digest for %s/%s", capability.Descriptor().GetCapabilityId(), operation.GetOperationId())
			}
		}
	}
}

func TestNativeConfigUsesOnlyModeSpecificIdentity(t *testing.T) {
	capability := NewConfigCapability(releaseConfigStore{})
	descriptor := capability.Descriptor()
	for _, operation := range descriptor.GetOperations() {
		if strings.Contains(operation.GetInputSchemaJson(), `"display_name"`) &&
			!strings.Contains(operation.GetInputSchemaJson(), `"native_agent_identity"`) {
			t.Fatalf("%s retains a flat identity input: %s", operation.GetOperationId(), operation.GetInputSchemaJson())
		}
		if strings.Contains(operation.GetResultSchemaJson(), `"required":["revision","display_name"`) {
			t.Fatalf("%s retains flat identity result fields: %s", operation.GetOperationId(), operation.GetResultSchemaJson())
		}
	}
	if _, err := capability.HandleOperation(capabilityTestContext(), "update", []byte(`{"idempotency_key":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","display_name":"old"}`)); err == nil {
		t.Fatal("flat display_name update was accepted")
	}
}
