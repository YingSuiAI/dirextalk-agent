package agentcapability

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/corewebsearch"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
)

type capabilityWebSearchRepo struct {
	owner      string
	generation int64
	resolved   corewebsearch.ResolvedConfig
}

func (r *capabilityWebSearchRepo) Get(_ context.Context, owner string, generation int64) (corewebsearch.Config, error) {
	r.owner = owner
	r.generation = generation
	return r.resolved.Config, nil
}
func (r *capabilityWebSearchRepo) Resolve(_ context.Context, owner string, generation int64) (corewebsearch.ResolvedConfig, error) {
	r.owner = owner
	r.generation = generation
	return r.resolved, nil
}
func (r *capabilityWebSearchRepo) ResolveForDispatch(_ context.Context, owner string, generation int64, _ corewebsearch.ResolvedConfig) (corewebsearch.ResolvedConfig, func() error, error) {
	r.owner = owner
	r.generation = generation
	value := r.resolved
	value.OwnerID = owner
	value.AccountGeneration = generation
	return value, func() error { return nil }, nil
}
func (r *capabilityWebSearchRepo) Update(_ context.Context, mutation corewebsearch.Mutation) (corewebsearch.Config, error) {
	r.owner = mutation.OwnerID
	r.generation = mutation.AccountGeneration
	return r.resolved.Config, nil
}
func (r *capabilityWebSearchRepo) MarkTested(_ context.Context, owner string, generation, _ int64, at time.Time) (corewebsearch.Config, error) {
	r.owner = owner
	r.generation = generation
	value := r.resolved.Config
	value.TestedAt = &at
	return value, nil
}

type capabilityWebSearcher struct{}

func (capabilityWebSearcher) Search(context.Context, string, string, int) (corewebsearch.SearchResult, error) {
	return corewebsearch.SearchResult{Provider: corewebsearch.ProviderTavily, Results: []corewebsearch.SearchItem{{URL: "https://example.test"}}}, nil
}

func TestWebSearchCapabilityUsesAuthenticatedOwnerAndExactSchemas(t *testing.T) {
	config := corewebsearch.Config{Enabled: true, Provider: corewebsearch.ProviderTavily, APIKeyConfigured: true, Revision: 2}
	repository := &capabilityWebSearchRepo{resolved: corewebsearch.ResolvedConfig{Config: config, APIKey: "tvly-secret", CredentialVersion: 1}}
	service, err := corewebsearch.NewService(repository, capabilityWebSearcher{})
	if err != nil {
		t.Fatal(err)
	}
	capability := NewCoreWebSearchCapability(service)
	descriptor := capability.Descriptor()
	if descriptor.GetCapabilityId() != "agent.web_search.v1" || len(descriptor.GetOperations()) != 3 {
		t.Fatalf("descriptor=%#v", descriptor)
	}
	operations := map[string]*capv1.OperationDescriptor{}
	for _, operation := range descriptor.GetOperations() {
		operations[operation.GetOperationId()] = operation
	}
	if operations["test"].GetOperationType() != capv1.OperationType_OPERATION_TYPE_MUTATION {
		t.Fatal("test writes tested_at and must use mutation operation semantics")
	}
	if !strings.Contains(operations["update_config"].GetInputSchemaJson(), `"writeOnly":true`) {
		t.Fatal("update schema did not mark api_key write-only")
	}
	result, err := capability.HandleOperation(capabilityTestContext(), "get_config", []byte(`{}`))
	if err != nil || repository.owner != "owner-1" || repository.generation != 1 || strings.Contains(string(result), "tvly-secret") {
		t.Fatalf("get result=%s owner=%q generation=%d err=%v", result, repository.owner, repository.generation, err)
	}
	enabled := true
	update, _ := json.Marshal(map[string]any{"idempotency_key": uuid.NewString(), "expected_revision": 2, "enabled": enabled, "provider": "tavily", "api_key": "tvly-rotate"})
	result, err = capability.HandleOperation(capabilityTestContext(), "update_config", update)
	if err != nil || repository.owner != "owner-1" || repository.generation != 1 || strings.Contains(string(result), "tvly-") {
		t.Fatalf("update result=%s owner=%q generation=%d err=%v", result, repository.owner, repository.generation, err)
	}
	result, err = capability.HandleOperation(capabilityTestContext(), "test", []byte(`{}`))
	if err != nil || repository.owner != "owner-1" || repository.generation != 1 || strings.Contains(string(result), "tvly-secret") || !strings.Contains(string(result), `"result_count":1`) {
		t.Fatalf("test result=%s owner=%q generation=%d err=%v", result, repository.owner, repository.generation, err)
	}
}

func TestWebSearchCapabilityRejectsBodyIdentitySecretsAndMissingContext(t *testing.T) {
	config := corewebsearch.Config{Enabled: true, Provider: corewebsearch.ProviderTavily, APIKeyConfigured: true, Revision: 1}
	repository := &capabilityWebSearchRepo{resolved: corewebsearch.ResolvedConfig{Config: config, APIKey: "key", CredentialVersion: 1}}
	service, _ := corewebsearch.NewService(repository, capabilityWebSearcher{})
	capability := NewCoreWebSearchCapability(service)
	for _, input := range []string{`{"owner_id":"attacker"}`, `{"api_key":"request-secret"}`, `{"request_secret":{}}`} {
		if _, err := capability.HandleOperation(capabilityTestContext(), "test", []byte(input)); err == nil {
			t.Fatalf("test accepted forbidden input %s", input)
		}
	}
	if _, err := capability.HandleOperation(context.Background(), "get_config", []byte(`{}`)); err == nil {
		t.Fatal("missing authenticated context was accepted")
	}
}
