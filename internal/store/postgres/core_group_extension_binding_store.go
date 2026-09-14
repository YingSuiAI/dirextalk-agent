package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrGroupExtensionBindingInvalid rejects a malformed room or installation.
	ErrGroupExtensionBindingInvalid = errors.New("invalid group extension binding")
	// ErrGroupExtensionBindingMissing reports that no binding exists.
	ErrGroupExtensionBindingMissing = errors.New("group extension binding is not configured")
	// ErrGroupExtensionBindingStore reports a persistence failure.
	ErrGroupExtensionBindingStore = errors.New("group extension binding store unavailable")
)

// CoreGroupExtensionBindingStore keeps which third-party MCP installations one
// group may use. An installation is never implicitly shared with a group.
type CoreGroupExtensionBindingStore struct {
	store *Store
}

func NewCoreGroupExtensionBindingStore(store *Store) *CoreGroupExtensionBindingStore {
	return &CoreGroupExtensionBindingStore{store: store}
}

func validGroupExtensionBindingIdentity(ownerID string, accountGeneration uint64, roomID string) bool {
	ownerID = strings.TrimSpace(ownerID)
	roomID = strings.TrimSpace(roomID)
	return ownerID != "" && len(ownerID) <= 512 && accountGeneration > 0 &&
		strings.HasPrefix(roomID, "!") && len(roomID) <= 1024 && !strings.ContainsAny(roomID, "\x00\r\n\t ")
}

// ListGroupExtensionBindings returns the installations bound to one group.
func (s *CoreGroupExtensionBindingStore) ListGroupExtensionBindings(ctx context.Context, ownerID string, accountGeneration uint64, roomID string) ([]string, error) {
	if s == nil || s.store == nil || !validGroupExtensionBindingIdentity(ownerID, accountGeneration, roomID) {
		return nil, ErrGroupExtensionBindingInvalid
	}
	rows, err := s.store.pool.Query(ctx, `SELECT installation_id::text FROM core_group_extension_bindings WHERE owner_id=$1 AND account_generation=$2 AND room_id=$3 ORDER BY installation_id`,
		strings.TrimSpace(ownerID), accountGeneration, strings.TrimSpace(roomID))
	if err != nil {
		return nil, ErrGroupExtensionBindingStore
	}
	defer rows.Close()
	out := make([]string, 0, 4)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, ErrGroupExtensionBindingStore
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, ErrGroupExtensionBindingStore
	}
	return out, nil
}

// GroupExtensionBound reports whether one installation serves this group.
func (s *CoreGroupExtensionBindingStore) GroupExtensionBound(ctx context.Context, ownerID string, accountGeneration uint64, roomID, installationID string) (bool, error) {
	if s == nil || s.store == nil || !validGroupExtensionBindingIdentity(ownerID, accountGeneration, roomID) {
		return false, ErrGroupExtensionBindingInvalid
	}
	installationID = strings.TrimSpace(installationID)
	if _, err := uuid.Parse(installationID); err != nil {
		return false, ErrGroupExtensionBindingInvalid
	}
	var bound bool
	if err := s.store.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM core_group_extension_bindings WHERE owner_id=$1 AND account_generation=$2 AND room_id=$3 AND installation_id=$4)`,
		strings.TrimSpace(ownerID), accountGeneration, strings.TrimSpace(roomID), installationID).Scan(&bound); err != nil {
		return false, ErrGroupExtensionBindingStore
	}
	return bound, nil
}

// SetGroupExtensionBinding binds one installation to one group (idempotent).
func (s *CoreGroupExtensionBindingStore) SetGroupExtensionBinding(ctx context.Context, ownerID string, accountGeneration uint64, roomID, installationID string) error {
	if s == nil || s.store == nil || !validGroupExtensionBindingIdentity(ownerID, accountGeneration, roomID) {
		return ErrGroupExtensionBindingInvalid
	}
	installationID = strings.TrimSpace(installationID)
	if _, err := uuid.Parse(installationID); err != nil {
		return ErrGroupExtensionBindingInvalid
	}
	_, err := s.store.pool.Exec(ctx, `INSERT INTO core_group_extension_bindings(owner_id,account_generation,room_id,installation_id,revision,updated_at) VALUES($1,$2,$3,$4,1,$5) ON CONFLICT (owner_id,account_generation,room_id,installation_id) DO NOTHING`,
		strings.TrimSpace(ownerID), accountGeneration, strings.TrimSpace(roomID), installationID, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		// A missing installation is reported as invalid so the client refreshes
		// its installation list instead of guessing.
		return ErrGroupExtensionBindingInvalid
	}
	return nil
}

// ClearGroupExtensionBinding removes the binding, which immediately stops the
// group from using that installation.
func (s *CoreGroupExtensionBindingStore) ClearGroupExtensionBinding(ctx context.Context, ownerID string, accountGeneration uint64, roomID, installationID string) error {
	if s == nil || s.store == nil || !validGroupExtensionBindingIdentity(ownerID, accountGeneration, roomID) {
		return ErrGroupExtensionBindingInvalid
	}
	installationID = strings.TrimSpace(installationID)
	if _, err := uuid.Parse(installationID); err != nil {
		return ErrGroupExtensionBindingInvalid
	}
	if _, err := s.store.pool.Exec(ctx, `DELETE FROM core_group_extension_bindings WHERE owner_id=$1 AND account_generation=$2 AND room_id=$3 AND installation_id=$4`,
		strings.TrimSpace(ownerID), accountGeneration, strings.TrimSpace(roomID), installationID); err != nil {
		return ErrGroupExtensionBindingStore
	}
	return nil
}
