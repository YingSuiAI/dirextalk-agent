package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	// ErrGroupModelBindingInvalid rejects a malformed room, identity or profile.
	ErrGroupModelBindingInvalid = errors.New("invalid group model binding")
	// ErrGroupModelBindingConflict reports a missing/stale expected revision.
	ErrGroupModelBindingConflict = errors.New("group model binding revision conflict")
	// ErrGroupModelBindingStore reports a persistence failure.
	ErrGroupModelBindingStore = errors.New("group model binding store unavailable")
)

// GroupModelBinding is one group's chosen conversation model. An absent binding
// means the group inherits the owner's default conversation model.
type GroupModelBinding struct {
	OwnerID           string
	AccountGeneration uint64
	RoomID            string
	ProfileID         string
	Revision          int64
	UpdatedAt         time.Time
}

// CoreGroupModelBindingStore keeps the per-group model choice. It stores only a
// pointer to a profile: credentials stay in the profile's own encrypted
// envelope and are never copied into a group scope.
type CoreGroupModelBindingStore struct {
	store *Store
}

func NewCoreGroupModelBindingStore(store *Store) *CoreGroupModelBindingStore {
	return &CoreGroupModelBindingStore{store: store}
}

func validGroupModelBindingIdentity(ownerID string, accountGeneration uint64, roomID string) bool {
	ownerID = strings.TrimSpace(ownerID)
	roomID = strings.TrimSpace(roomID)
	return ownerID != "" && len(ownerID) <= 512 && accountGeneration > 0 &&
		strings.HasPrefix(roomID, "!") && len(roomID) <= 1024 && !strings.ContainsAny(roomID, "\x00\r\n\t ")
}

// ResolveGroupConversationModel returns the group's own conversation profile id
// when the owner configured one. ok=false means inherit the owner's default.
func (s *CoreGroupModelBindingStore) ResolveGroupConversationModel(ctx context.Context, ownerID string, accountGeneration uint64, roomID string) (string, bool, error) {
	binding, err := s.GetGroupConversationModel(ctx, ownerID, accountGeneration, roomID)
	if errors.Is(err, ErrGroupModelBindingMissing) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return binding.ProfileID, true, nil
}

var ErrGroupModelBindingMissing = errors.New("group model binding is not configured")

// GetGroupConversationModel reads the group's binding. It reports
// ErrGroupModelBindingMissing when the group inherits the owner's default.
func (s *CoreGroupModelBindingStore) GetGroupConversationModel(ctx context.Context, ownerID string, accountGeneration uint64, roomID string) (GroupModelBinding, error) {
	if s == nil || s.store == nil || !validGroupModelBindingIdentity(ownerID, accountGeneration, roomID) {
		return GroupModelBinding{}, ErrGroupModelBindingInvalid
	}
	var out GroupModelBinding
	err := s.store.pool.QueryRow(ctx, `SELECT owner_id,account_generation,room_id,profile_id,revision,updated_at FROM core_group_model_bindings WHERE owner_id=$1 AND account_generation=$2 AND room_id=$3`,
		strings.TrimSpace(ownerID), accountGeneration, strings.TrimSpace(roomID)).
		Scan(&out.OwnerID, &out.AccountGeneration, &out.RoomID, &out.ProfileID, &out.Revision, &out.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return GroupModelBinding{}, ErrGroupModelBindingMissing
	}
	if err != nil {
		return GroupModelBinding{}, ErrGroupModelBindingStore
	}
	return out, nil
}

// SetGroupConversationModel writes the group's model choice under a revision
// CAS: expectedRevision 0 creates the binding, an existing revision replaces it.
func (s *CoreGroupModelBindingStore) SetGroupConversationModel(ctx context.Context, ownerID string, accountGeneration uint64, roomID, profileID string, expectedRevision int64) (GroupModelBinding, error) {
	ownerID = strings.TrimSpace(ownerID)
	roomID = strings.TrimSpace(roomID)
	profileID = strings.TrimSpace(profileID)
	if s == nil || s.store == nil || !validGroupModelBindingIdentity(ownerID, accountGeneration, roomID) || expectedRevision < 0 {
		return GroupModelBinding{}, ErrGroupModelBindingInvalid
	}
	parsed, err := uuid.Parse(profileID)
	if err != nil || parsed == uuid.Nil || parsed.String() != profileID {
		return GroupModelBinding{}, ErrGroupModelBindingInvalid
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	var out GroupModelBinding
	if expectedRevision == 0 {
		err = s.store.pool.QueryRow(ctx, `INSERT INTO core_group_model_bindings(owner_id,account_generation,room_id,profile_id,revision,updated_at) VALUES($1,$2,$3,$4,1,$5)
			ON CONFLICT (owner_id,account_generation,room_id) DO NOTHING
			RETURNING owner_id,account_generation,room_id,profile_id,revision,updated_at`,
			ownerID, accountGeneration, roomID, profileID, now).
			Scan(&out.OwnerID, &out.AccountGeneration, &out.RoomID, &out.ProfileID, &out.Revision, &out.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return GroupModelBinding{}, ErrGroupModelBindingConflict
		}
	} else {
		err = s.store.pool.QueryRow(ctx, `UPDATE core_group_model_bindings SET profile_id=$5,revision=revision+1,updated_at=$6
			WHERE owner_id=$1 AND account_generation=$2 AND room_id=$3 AND revision=$4
			RETURNING owner_id,account_generation,room_id,profile_id,revision,updated_at`,
			ownerID, accountGeneration, roomID, expectedRevision, profileID, now).
			Scan(&out.OwnerID, &out.AccountGeneration, &out.RoomID, &out.ProfileID, &out.Revision, &out.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return GroupModelBinding{}, ErrGroupModelBindingConflict
		}
	}
	if err != nil {
		// A missing profile is reported as a conflict so the caller can refresh
		// the model list instead of guessing.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return GroupModelBinding{}, ErrGroupModelBindingInvalid
		}
		return GroupModelBinding{}, ErrGroupModelBindingStore
	}
	return out, nil
}

// DeleteGroupConversationModel removes the group's choice, which returns the
// group to inheriting the owner's default conversation model.
func (s *CoreGroupModelBindingStore) DeleteGroupConversationModel(ctx context.Context, ownerID string, accountGeneration uint64, roomID string, expectedRevision int64) error {
	ownerID = strings.TrimSpace(ownerID)
	roomID = strings.TrimSpace(roomID)
	if s == nil || s.store == nil || !validGroupModelBindingIdentity(ownerID, accountGeneration, roomID) || expectedRevision <= 0 {
		return ErrGroupModelBindingInvalid
	}
	tag, err := s.store.pool.Exec(ctx, `DELETE FROM core_group_model_bindings WHERE owner_id=$1 AND account_generation=$2 AND room_id=$3 AND revision=$4`,
		ownerID, accountGeneration, roomID, expectedRevision)
	if err != nil {
		return ErrGroupModelBindingStore
	}
	if tag.RowsAffected() != 1 {
		return ErrGroupModelBindingConflict
	}
	return nil
}
