// Package coreconfig owns the owner-scoped Native Agent configuration
// projection.  Online Matrix identity is deliberately absent: that product
// state remains in message-server.
package coreconfig

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
)

const (
	MaxDisplayNameBytes   = 256
	MaxAvatarURLBytes     = 2048
	MaxBlockedRoomIDs     = 512
	MaxBlockedRoomIDBytes = 256
)

var (
	ErrInvalid  = errors.New("invalid native agent config")
	ErrConflict = errors.New("native agent config revision or idempotency conflict")
	ErrNotFound = errors.New("native agent config not found")
)

// Identity is the Native Agent display identity. It is not the Matrix Online
// Agent identity and must never be populated from message-server's online
// fields.
type Identity struct {
	DisplayName string `json:"display_name"`
	AvatarURL   string `json:"avatar_url"`
}

// Config is the public, secret-free Native Agent configuration projection.
type Config struct {
	Revision          int64    `json:"revision"`
	NativeIdentity    Identity `json:"native_agent_identity"`
	Enabled           bool     `json:"enabled"`
	MCPBlockedRoomIDs []string `json:"mcp_blocked_room_ids"`
}

// Update is the bounded mutation input. idempotency_key is required so a
// lost response can be retried without repeating the write.
type Update struct {
	IdempotencyKey    string    `json:"idempotency_key"`
	ExpectedRevision  int64     `json:"expected_revision"`
	NativeIdentity    *Identity `json:"native_agent_identity,omitempty"`
	Enabled           *bool     `json:"enabled,omitempty"`
	MCPBlockedRoomIDs *[]string `json:"mcp_blocked_room_ids,omitempty"`
}

type Store interface {
	Get(context.Context, string) (Config, error)
	Update(context.Context, string, Update) (Config, error)
}

func Default() Config {
	return Config{Revision: 0, NativeIdentity: Identity{DisplayName: "Agent"}, Enabled: true}
}

func (c Config) Normalize() Config {
	c.NativeIdentity.DisplayName = strings.TrimSpace(c.NativeIdentity.DisplayName)
	c.NativeIdentity.AvatarURL = strings.TrimSpace(c.NativeIdentity.AvatarURL)
	if c.NativeIdentity.DisplayName == "" {
		c.NativeIdentity.DisplayName = "Agent"
	}
	if c.MCPBlockedRoomIDs == nil {
		c.MCPBlockedRoomIDs = []string{}
	}
	c.MCPBlockedRoomIDs = normalizeRoomIDs(c.MCPBlockedRoomIDs)
	return c
}

func ValidateUpdate(update Update) error {
	if _, err := uuid.Parse(strings.TrimSpace(update.IdempotencyKey)); err != nil {
		return fmt.Errorf("%w: idempotency_key must be a UUID", ErrInvalid)
	}
	if update.ExpectedRevision < 0 {
		return fmt.Errorf("%w: expected_revision must be non-negative", ErrInvalid)
	}
	if update.NativeIdentity != nil {
		if len([]byte(strings.TrimSpace(update.NativeIdentity.DisplayName))) > MaxDisplayNameBytes || len([]byte(strings.TrimSpace(update.NativeIdentity.AvatarURL))) > MaxAvatarURLBytes {
			return fmt.Errorf("%w: native_agent_identity is too long", ErrInvalid)
		}
	}
	if update.MCPBlockedRoomIDs != nil {
		if len(*update.MCPBlockedRoomIDs) > MaxBlockedRoomIDs {
			return fmt.Errorf("%w: too many blocked room ids", ErrInvalid)
		}
		for _, roomID := range *update.MCPBlockedRoomIDs {
			if len([]byte(strings.TrimSpace(roomID))) > MaxBlockedRoomIDBytes {
				return fmt.Errorf("%w: blocked room id is too long", ErrInvalid)
			}
		}
	}
	return nil
}

func Apply(current Config, update Update) Config {
	next := current.Normalize()
	if update.NativeIdentity != nil {
		next.NativeIdentity = Identity{DisplayName: strings.TrimSpace(update.NativeIdentity.DisplayName), AvatarURL: strings.TrimSpace(update.NativeIdentity.AvatarURL)}
	}
	if update.Enabled != nil {
		next.Enabled = *update.Enabled
	}
	if update.MCPBlockedRoomIDs != nil {
		next.MCPBlockedRoomIDs = normalizeRoomIDs(*update.MCPBlockedRoomIDs)
	}
	return next.Normalize()
}

func normalizeRoomIDs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func MutationDigest(owner string, update Update) ([32]byte, error) {
	if err := ValidateUpdate(update); err != nil {
		return [32]byte{}, err
	}
	request := map[string]any{
		"owner_id": owner, "expected_revision": update.ExpectedRevision,
		"native_agent_identity": update.NativeIdentity, "enabled": update.Enabled,
		"mcp_blocked_room_ids": update.MCPBlockedRoomIDs,
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return [32]byte{}, err
	}
	canonical, err := capv1.CanonicalizeJSON(raw)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}
