package agentcapability

import (
	"context"
	"errors"
	"strings"
	"testing"

	capabilityoperation "github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

type registryErrorCapability struct{ err error }

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

func TestCoreRegistryDoesNotPublishExecutionV2WithoutTypedProvider(t *testing.T) {
	domain, err := coreexecutionv2.NewService(coreexecutionv2.Config{Store: coreexecutionv2.NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	r := NewCoreRegistry(CoreBindings{ExecutionV2: domain})
	if _, ok := r.Get(coreexecutionv2.CapabilityID); ok {
		t.Fatal("execution.v2 published without a typed provider readiness proof")
	}
}

func TestCloudWorkerExecutionV2CoexistsWithLocalSkillsAndMCP(t *testing.T) {
	domain, err := coreexecutionv2.NewServiceWithProviderInterfacesAndCloudWorker(
		coreexecutionv2.NewMemoryStore(), coreexecutionv2.ProviderInterfaces{}, registryCloudWorkerPort{}, nil,
	)
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
