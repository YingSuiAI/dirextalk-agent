package agentcapability

import "context"

// GroupModelBinding is one group's chosen conversation model. An absent binding
// means the group inherits the owner's default conversation model.
type GroupModelBinding struct {
	RoomID    string
	ProfileID string
	Revision  int64
}

// GroupModelBindings stores the per-group conversation model choice. It keeps
// only a pointer to an existing model profile: credentials stay in that
// profile's own encrypted envelope and are never copied into a group scope.
//
// The bool result of GetGroupModelBinding reports whether the owner configured a
// model for that group; false means the group inherits the owner's default.
type GroupModelBindings interface {
	GetGroupModelBinding(ctx context.Context, ownerID string, accountGeneration uint64, roomID string) (GroupModelBinding, bool, error)
	SetGroupModelBinding(ctx context.Context, ownerID string, accountGeneration uint64, roomID, profileID string, expectedRevision int64) (GroupModelBinding, error)
	DeleteGroupModelBinding(ctx context.Context, ownerID string, accountGeneration uint64, roomID string, expectedRevision int64) error
}
