package agentcapability

import (
	"context"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability/chat"
	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability/knowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability/models"
	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability/skills"
	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability/tasks"
	"github.com/YingSuiAI/dirextalk-agent/internal/capability/server"
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

// NewRegistry creates and registers all agent capabilities
func NewRegistry() *Registry {
	r := &Registry{
		capabilities: make(map[string]Capability),
	}

	// Register all capabilities
	r.Register(chat.NewCapability())
	r.Register(models.NewCapability())
	r.Register(tasks.NewCapability())
	r.Register(skills.NewCapability())
	r.Register(knowledge.NewCapability())

	return r
}

// Register adds a capability to the registry
func (r *Registry) Register(cap Capability) {
	desc := cap.Descriptor()
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

// IntegrateWithServer integrates the registry with the capability server
func (r *Registry) IntegrateWithServer(s *server.Server) {
	// TODO: Connect registry to server handlers
}
