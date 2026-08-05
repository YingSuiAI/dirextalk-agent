package agentcapability

import (
	"context"
	"encoding/json"
	"errors"
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
			return BackendsSnapshot{Embedded: BackendInfo{Status: "READY", Capabilities: []string{"memory.server", "memory.server", "agent.info"}}, Core: BackendInfo{Status: "future-secret-status", Capabilities: []string{"z", "a"}}}, nil
		},
		StatusFunc: func(context.Context) (BackendInfo, error) { return BackendInfo{Status: "ready"}, nil },
		ModelsFunc: func(_ context.Context, request ModelCatalogRequest) (ModelCatalogResult, error) {
			if request.ModelKind != "conversation" || (request.Provider != "" && request.APIKey != "secret-key") {
				t.Fatalf("catalog request = %#v", request)
			}
			return ModelCatalogResult{Models: []map[string]any{{"id": "gpt", "provider": "openrouter", "api_key": "secret-key", "base_url": "https://openrouter.ai/api/v1"}}, Providers: []ModelCatalogProviderInfo{{Provider: "openrouter", RequiresAPIKey: true}}}, nil
		},
	})
	var catalogSchema string
	for _, operation := range capability.Descriptor().GetOperations() {
		if operation.GetOperationId() == "list_models" {
			catalogSchema = operation.GetInputSchemaJson()
			break
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
	if value.Core.Status != "unknown" {
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
	if strings.Contains(string(models), "secret-key") || !strings.Contains(string(models), "openrouter") {
		t.Fatalf("catalog leaked credential or omitted provider: %s", models)
	}
	if _, err := capability.HandleOperation(capabilityTestContext(), "list_models", []byte(`{}`)); err != nil {
		t.Fatalf("default conversation model catalog: %v", err)
	}
}

func TestInfoCapabilityKeepsProfileAndEmptyAPIKeyErrorsIntact(t *testing.T) {
	providerError := errors.New("provider profile lookup failed")
	capability := NewInfoCapability(InfoProviderFunc{
		BackendsFunc: func(context.Context) (BackendsSnapshot, error) { return BackendsSnapshot{}, nil },
		StatusFunc:   func(context.Context) (BackendInfo, error) { return BackendInfo{}, nil },
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

func TestConfigProposalIsConfirmationBoundAndDoesNotApply(t *testing.T) {
	capability := NewConfigCapability(nil)
	result, err := capability.HandleOperation(capabilityTestContext(), "propose_patch", []byte(`{"kind":"skill","skill":{"name":"safe","source":"registry","args":["--help"]}}`))
	if err != nil {
		t.Fatalf("proposal: %v", err)
	}
	var value ConfigPatchResult
	if err := json.Unmarshal(result, &value); err != nil {
		t.Fatalf("decode proposal: %v", err)
	}
	if !value.RequiresConfirmation || value.ConfigPatch["skills_add"] == nil {
		t.Fatalf("proposal = %#v", value)
	}
	if _, err := capability.HandleOperation(capabilityTestContext(), "propose_patch", []byte(`{"kind":"mcp_server","mcp_server":{"name":"unsafe","api_key":"secret"}}`)); err == nil {
		t.Fatal("secret-bearing config proposal was accepted")
	}
	if _, err := capability.HandleOperation(capabilityTestContext(), "propose_patch", []byte(`{"kind":"mcp_server","mcp_server":{"name":"unsafe","command":"sh -c pwned"}}`)); err == nil {
		t.Fatal("shell command proposal was accepted")
	}
	if _, err := capability.HandleOperation(capabilityTestContext(), "propose_patch", []byte(`{"kind":"mcp_server","mcp_server":{"name":"unsafe","command":["sh","-c","pwned"]}}`)); err == nil {
		t.Fatal("shell interpreter proposal was accepted")
	}
}

func TestRegisterMiscCapabilitiesDoesNotPublishUnavailableRuntime(t *testing.T) {
	r := NewRegistry()
	if err := RegisterMiscCapabilities(r, MiscBindings{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, ok := r.Get(configCapabilityID); !ok {
		t.Fatal("config proposal capability missing")
	}
	if _, ok := r.Get(infoCapabilityID); ok {
		t.Fatal("unconfigured info capability was published")
	}
	if _, ok := r.Get(runtimeCapabilityID); ok {
		t.Fatal("unconfigured runtime capability was published")
	}
}

func TestMiscDescriptorsCarrySchemaDigests(t *testing.T) {
	for _, capability := range []Capability{NewInfoCapability(InfoProviderFunc{}), NewRuntimeCapability(&runtimePortFake{}), NewConfigCapability(nil)} {
		for _, operation := range capability.Descriptor().GetOperations() {
			if len(operation.GetInputSchemaDigest()) != 32 || len(operation.GetResultSchemaDigest()) != 32 {
				t.Fatalf("missing schema digest for %s/%s", capability.Descriptor().GetCapabilityId(), operation.GetOperationId())
			}
		}
	}
}
