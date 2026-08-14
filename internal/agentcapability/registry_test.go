package agentcapability

import (
	"context"
	"errors"
	"strings"
	"testing"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	capabilityoperation "github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretexttool"
	"github.com/YingSuiAI/dirextalk-agent/internal/corewebsearch"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

type registryErrorCapability struct{ err error }

type registryWorkerCapability struct{}

func (registryWorkerCapability) Descriptor() *capv1.CapabilityDescriptor {
	return &capv1.CapabilityDescriptor{CapabilityId: "agent.worker.v1", Readiness: true}
}
func (registryWorkerCapability) HandleOperation(context.Context, string, []byte) ([]byte, error) {
	return []byte(`{}`), nil
}

type registryCloudWorkerPort struct{}

func (registryCloudWorkerPort) GetPlan(context.Context, coreexecutionv2.CloudWorkerPlanGetRequest) (coreexecutionv2.CloudWorkerObject, error) {
	return nil, nil
}
func (registryCloudWorkerPort) ListPlans(context.Context, coreexecutionv2.CloudWorkerListRequest) (coreexecutionv2.CloudWorkerPage, error) {
	return coreexecutionv2.CloudWorkerPage{}, nil
}
func (registryCloudWorkerPort) GetRun(context.Context, coreexecutionv2.CloudWorkerRunGetRequest) (coreexecutionv2.CloudWorkerObject, error) {
	return nil, nil
}
func (registryCloudWorkerPort) ListRuns(context.Context, coreexecutionv2.CloudWorkerListRequest) (coreexecutionv2.CloudWorkerPage, error) {
	return coreexecutionv2.CloudWorkerPage{}, nil
}
func (registryCloudWorkerPort) CancelRun(context.Context, coreexecutionv2.CloudWorkerRunCancelRequest) (coreexecutionv2.CloudWorkerObject, error) {
	return nil, nil
}
func (registryCloudWorkerPort) RunEvents(context.Context, coreexecutionv2.CloudWorkerRunEventsRequest) (coreexecutionv2.CloudWorkerEventPage, error) {
	return coreexecutionv2.CloudWorkerEventPage{}, nil
}
func (registryCloudWorkerPort) GetArtifact(context.Context, coreexecutionv2.CloudWorkerArtifactGetRequest) (coreexecutionv2.CloudWorkerObject, error) {
	return nil, nil
}
func (registryCloudWorkerPort) DownloadArtifact(context.Context, coreexecutionv2.CloudWorkerArtifactDownloadRequest) (coreexecutionv2.CloudWorkerArtifactChunk, error) {
	return coreexecutionv2.CloudWorkerArtifactChunk{}, nil
}
func (registryCloudWorkerPort) DeleteArtifact(context.Context, coreexecutionv2.CloudWorkerArtifactDeleteRequest) (coreexecutionv2.CloudWorkerObject, error) {
	return nil, nil
}

func (c registryErrorCapability) Descriptor() *capv1.CapabilityDescriptor {
	return &capv1.CapabilityDescriptor{CapabilityId: "test.error.v1"}
}

func (c registryErrorCapability) HandleOperation(context.Context, string, []byte) ([]byte, error) {
	return nil, c.err
}

func TestNewRegistryIsEmptyUntilExplicitlyComposed(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	if descriptors := r.List(); len(descriptors) != 0 {
		t.Fatalf("uncomposed registry published %d capabilities", len(descriptors))
	}
}

func TestRegistryClassifiesDomainErrorsWithRedactedPublicMessage(t *testing.T) {
	r := NewRegistry()
	r.Register(registryErrorCapability{err: coreconversation.ErrInvalid})
	capability, ok := r.Get("test.error.v1")
	if !ok {
		t.Fatal("registered capability missing")
	}
	_, err := capability.HandleOperation(context.Background(), "read", []byte(`{}`))
	code, message, classified := capabilityoperation.FailureDetails(err)
	if !classified || code != "INVALID_ARGUMENT" || message != "Agent request is invalid" || !errors.Is(err, coreconversation.ErrInvalid) {
		t.Fatalf("code=%q message=%q classified=%v err=%v", code, message, classified, err)
	}
}

func TestRegistryRedactsUnclassifiedCapabilityErrors(t *testing.T) {
	sentinel := errors.New("upstream response contained secret-sentinel")
	r := NewRegistry()
	r.Register(registryErrorCapability{err: sentinel})
	capability, ok := r.Get("test.error.v1")
	if !ok {
		t.Fatal("registered capability missing")
	}
	_, err := capability.HandleOperation(context.Background(), "read", []byte(`{}`))
	code, message, classified := capabilityoperation.FailureDetails(err)
	if !classified || code != "UPSTREAM_FAILED" || message != "Agent operation failed" || !errors.Is(err, sentinel) {
		t.Fatalf("code=%q message=%q classified=%v err=%v", code, message, classified, err)
	}
	if strings.Contains(message, "secret-sentinel") {
		t.Fatalf("classified message leaked upstream detail: %q", message)
	}
}

func TestRegistryClassifiesTextToolAndWebSearchDomainErrors(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantCode    string
		wantMessage string
	}{
		{name: "text tool invalid", err: coretexttool.ErrInvalid, wantCode: "INVALID_ARGUMENT", wantMessage: "Agent request is invalid"},
		{name: "text tool not found", err: coretexttool.ErrNotFound, wantCode: "NOT_FOUND", wantMessage: "Agent resource was not found"},
		{name: "text tool conflict", err: coretexttool.ErrRevisionConflict, wantCode: "CONFLICT", wantMessage: "Agent state changed; refresh and retry"},
		{name: "text tool disabled", err: coretexttool.ErrDisabled, wantCode: "PRECONDITION_FAILED", wantMessage: "Agent configuration is not ready"},
		{name: "text tool model missing", err: errors.Join(coretexttool.ErrModelNotConfigured, coremodel.ErrProfileNotFound), wantCode: "PRECONDITION_FAILED", wantMessage: "Agent configuration is not ready"},
		{name: "text tool model upstream", err: coretexttool.ErrModel, wantCode: "UPSTREAM_FAILED", wantMessage: "Agent operation failed"},
		{name: "text tool model repository", err: errors.Join(coretexttool.ErrModel, coremodel.ErrProfileRepository), wantCode: "UNAVAILABLE", wantMessage: "Agent dependency is unavailable"},
		{name: "text tool repository", err: coretexttool.ErrRepository, wantCode: "UNAVAILABLE", wantMessage: "Agent dependency is unavailable"},
		{name: "web search not configured", err: corewebsearch.ErrNotConfigured, wantCode: "PRECONDITION_FAILED", wantMessage: "Agent configuration is not ready"},
		{name: "web search disabled", err: corewebsearch.ErrDisabled, wantCode: "PRECONDITION_FAILED", wantMessage: "Agent configuration is not ready"},
		{name: "web search conflict", err: corewebsearch.ErrIdempotencyConflict, wantCode: "CONFLICT", wantMessage: "Agent state changed; refresh and retry"},
		{name: "web search repository", err: corewebsearch.ErrRepository, wantCode: "UNAVAILABLE", wantMessage: "Agent dependency is unavailable"},
		{name: "web search provider", err: corewebsearch.ErrProvider, wantCode: "UNAVAILABLE", wantMessage: "Agent dependency is unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := NewRegistry()
			r.Register(registryErrorCapability{err: test.err})
			capability, ok := r.Get("test.error.v1")
			if !ok {
				t.Fatal("registered capability missing")
			}
			_, err := capability.HandleOperation(context.Background(), "execute", []byte(`{}`))
			code, message, classified := capabilityoperation.FailureDetails(err)
			if !classified || code != test.wantCode || message != test.wantMessage || !errors.Is(err, test.err) {
				t.Fatalf("code=%q message=%q classified=%v err=%v", code, message, classified, err)
			}
		})
	}
}

func TestCoreRegistryDoesNotPublishUnboundOrLegacyCapabilities(t *testing.T) {
	r := NewCoreRegistry(CoreBindings{})
	if _, ok := r.Get("agent.chat.v1"); ok {
		t.Fatal("unbound chat capability was published")
	}
	if _, ok := r.Get("agent.models.v1"); ok {
		t.Fatal("unbound model capability was published")
	}
	if _, ok := r.Get("agent.tasks.v1"); ok {
		t.Fatal("unbound task capability was published")
	}
	if _, ok := r.Get("agent.knowledge.v1"); ok {
		t.Fatal("unbound knowledge capability was published")
	}
	for _, descriptor := range r.List() {
		for _, operation := range descriptor.GetOperations() {
			text := strings.ToLower(operation.GetDescription() + " " + operation.GetDisplayName())
			if strings.Contains(text, "not implemented") {
				t.Fatalf("production descriptor advertises an unimplemented operation: %s/%s", descriptor.GetCapabilityId(), operation.GetOperationId())
			}
		}
	}
}

func TestCoreRegistryPublishesWorkerOnlyWhenComposed(t *testing.T) {
	if _, ok := NewCoreRegistry(CoreBindings{}).Get("agent.worker.v1"); ok {
		t.Fatal("unbound Worker capability was published")
	}
	if _, ok := NewCoreRegistry(CoreBindings{Worker: registryWorkerCapability{}}).Get("agent.worker.v1"); !ok {
		t.Fatal("composed Worker capability was not published")
	}
}

func TestCloudWorkerExecutionV2CoexistsWithLocalSkillsAndMCP(t *testing.T) {
	domain, err := coreexecutionv2.NewService(registryCloudWorkerPort{})
	if err != nil {
		t.Fatal(err)
	}
	r := NewCoreRegistry(CoreBindings{
		ExecutionV2: domain,
		Extensions:  coreextension.NewService(nil, nil, nil),
	})
	if _, ok := r.Get(coreexecutionv2.CapabilityID); !ok {
		t.Fatal("Cloud Worker Execution V2 capability was not published")
	}
	if _, ok := r.Get("agent.skills.v1"); !ok {
		t.Fatal("Cloud Worker publication displaced the local Skills/MCP capability")
	}
}

func TestProductOnlyRegistryPublishesTheCompleteSkillsCapability(t *testing.T) {
	r := NewCoreRegistry(CoreBindings{Product: &capabilityclient.Client{}})
	capability, ok := r.Get("agent.skills.v1")
	if !ok {
		t.Fatal("product-only registry did not publish agent.skills.v1")
	}

	operations := map[string]bool{}
	for _, operation := range capability.Descriptor().GetOperations() {
		operations[operation.GetOperationId()] = true
	}
	for _, operation := range []string{"discover_skill", "list_mcp", "execute_mcp", "invoke_product"} {
		if !operations[operation] {
			t.Fatalf("complete agent.skills.v1 descriptor is missing %s", operation)
		}
	}
	if _, err := capability.HandleOperation(context.Background(), "discover_skill", []byte(`{}`)); !errors.Is(err, coreextension.ErrNotFound) {
		t.Fatalf("unbound extension operation err=%v, want ErrNotFound", err)
	}
}
