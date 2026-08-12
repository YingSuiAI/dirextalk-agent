package agentcapability

import (
	"context"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

// Registry manages all agent capabilities
type Registry struct {
	capabilities map[string]Capability
}

// Capability interface that all agent capabilities must implement
type Capability interface {
	Descriptor() *capv1.CapabilityDescriptor
	HandleOperation(ctx context.Context, operationID string, inputJSON []byte) ([]byte, error)
}

// NewRegistry creates an empty registry for explicit composition.
//
// Production must use NewCoreRegistry, which only advertises capabilities
// whose Core service has been wired and passed its readiness gate.  Keeping
// this constructor empty prevents stale in-memory/test capabilities from
// being exposed accidentally by a caller that has not composed Core.
func NewRegistry() *Registry {
	return &Registry{
		capabilities: make(map[string]Capability),
	}
}

// Register adds a capability to the registry
func (r *Registry) Register(cap Capability) {
	if r == nil || cap == nil || cap.Descriptor() == nil {
		return
	}
	desc := cap.Descriptor()
	if _, classified := cap.(*errorClassifyingCapability); !classified {
		cap = &errorClassifyingCapability{inner: cap}
	}
	r.capabilities[desc.CapabilityId] = cap
}

// Get retrieves a capability by ID
func (r *Registry) Get(capabilityID string) (Capability, bool) {
	cap, ok := r.capabilities[capabilityID]
	return cap, ok
}

// List returns descriptors for all capabilities
func (r *Registry) List() []*capv1.CapabilityDescriptor {
	descriptors := make([]*capv1.CapabilityDescriptor, 0, len(r.capabilities))
	for _, cap := range r.capabilities {
		descriptors = append(descriptors, cap.Descriptor())
	}
	return descriptors
}
