package agentcapability

import "context"

// GroupExtensionBindings keeps which third-party MCP installations one group may
// use. An installation is never implicitly shared with a group: the owner binds
// it explicitly, and only read-only MCP tools are exposed to the group.
type GroupExtensionBindings interface {
	ListGroupExtensionBindings(ctx context.Context, ownerID string, accountGeneration uint64, roomID string) ([]string, error)
	SetGroupExtensionBinding(ctx context.Context, ownerID string, accountGeneration uint64, roomID, installationID string) error
	ClearGroupExtensionBinding(ctx context.Context, ownerID string, accountGeneration uint64, roomID, installationID string) error
}
