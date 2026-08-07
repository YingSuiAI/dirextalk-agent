package corememory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound            = errors.New("corememory: not found")
	ErrConflict            = errors.New("corememory: conflict")
	ErrRevisionConflict    = errors.New("corememory: revision conflict")
	ErrIdempotencyConflict = errors.New("corememory: idempotency conflict")
)

type SlotKey struct {
	Scope          Scope  `json:"scope"`
	CanonicalKey   string `json:"canonical_key"`
	ConversationID string `json:"conversation_id,omitempty"`
}

func (k SlotKey) Normalize() SlotKey {
	k.CanonicalKey = strings.ToLower(strings.TrimSpace(k.CanonicalKey))
	k.ConversationID = strings.TrimSpace(k.ConversationID)
	return k
}

func (k SlotKey) Validate() error {
	k = k.Normalize()
	if !validScope(k.Scope) || !canonicalKeyPattern.MatchString(k.CanonicalKey) || len([]byte(k.CanonicalKey)) > MaxCanonicalKeyBytes {
		return ErrInvalid
	}
	if k.Scope == ScopeOwner && k.ConversationID != "" {
		return ErrInvalid
	}
	if k.Scope == ScopeConversation {
		if _, err := uuid.Parse(k.ConversationID); err != nil {
			return ErrInvalid
		}
	}
	return nil
}

type Slot struct {
	ID                     string `json:"memory_id"`
	SlotKey                `json:"slot"`
	Type                   MemoryType  `json:"type"`
	Sensitivity            Sensitivity `json:"sensitivity"`
	CurrentSourceID        string      `json:"current_source_id,omitempty"`
	CurrentSourceRevision  int64       `json:"current_source_revision,omitempty"`
	CurrentTextDigest      string      `json:"current_text_digest,omitempty"`
	Revision               int64       `json:"revision"`
	Deleted                bool        `json:"deleted"`
	Confidence             float64     `json:"confidence"`
	Importance             float64     `json:"importance"`
	CandidateSchemaVersion int         `json:"candidate_schema_version"`
	PolicyVersion          int         `json:"policy_version"`
	SourceConversationID   string      `json:"source_conversation_id,omitempty"`
	SourceTurnID           string      `json:"source_turn_id,omitempty"`
	CreatedAt              time.Time   `json:"created_at"`
	UpdatedAt              time.Time   `json:"updated_at"`
}

type ApplyCommand struct {
	IdempotencyKey         string       `json:"idempotency_key"`
	Action                 ChangeAction `json:"action"`
	Slot                   SlotKey      `json:"slot"`
	ExpectedRevision       int64        `json:"expected_revision,omitempty"`
	SourceID               string       `json:"source_id,omitempty"`
	SourceRevision         int64        `json:"source_revision,omitempty"`
	TextDigest             string       `json:"text_digest,omitempty"`
	Type                   MemoryType   `json:"type"`
	Sensitivity            Sensitivity  `json:"sensitivity"`
	Confidence             float64      `json:"confidence"`
	Importance             float64      `json:"importance"`
	CandidateSchemaVersion int          `json:"candidate_schema_version"`
	PolicyVersion          int          `json:"policy_version"`
	SourceConversationID   string       `json:"source_conversation_id,omitempty"`
	SourceTurnID           string       `json:"source_turn_id,omitempty"`
}

func (c ApplyCommand) Normalize() ApplyCommand {
	c.IdempotencyKey = strings.TrimSpace(c.IdempotencyKey)
	c.Slot = c.Slot.Normalize()
	c.SourceID = strings.TrimSpace(c.SourceID)
	c.TextDigest = strings.ToLower(strings.TrimSpace(c.TextDigest))
	c.SourceConversationID = strings.TrimSpace(c.SourceConversationID)
	c.SourceTurnID = strings.TrimSpace(c.SourceTurnID)
	return c
}

func (c ApplyCommand) Validate() error {
	c = c.Normalize()
	if _, err := uuid.Parse(c.IdempotencyKey); err != nil || c.Slot.Validate() != nil || !validMemoryType(c.Type) || !validSensitivity(c.Sensitivity) || c.Sensitivity == SensitivitySecret || c.CandidateSchemaVersion != CandidateSchemaVersion || c.PolicyVersion != PolicyVersion || math.IsNaN(c.Confidence) || math.IsInf(c.Confidence, 0) || c.Confidence < 0 || c.Confidence > 1 || math.IsNaN(c.Importance) || math.IsInf(c.Importance, 0) || c.Importance < 0 || c.Importance > 1 {
		return ErrInvalid
	}
	if (c.SourceConversationID == "") != (c.SourceTurnID == "") {
		return ErrInvalid
	}
	if c.SourceConversationID != "" {
		if _, err := uuid.Parse(c.SourceConversationID); err != nil {
			return ErrInvalid
		}
		if _, err := uuid.Parse(c.SourceTurnID); err != nil {
			return ErrInvalid
		}
	}
	if c.Slot.Scope == ScopeConversation && c.SourceConversationID != "" && c.SourceConversationID != c.Slot.ConversationID {
		return ErrInvalid
	}
	switch c.Action {
	case ChangeCreate:
		if c.ExpectedRevision != 0 || c.SourceRevision < 1 || !validUUIDAndDigest(c.SourceID, c.TextDigest) {
			return ErrInvalid
		}
	case ChangeUpdate:
		if c.ExpectedRevision < 1 || c.SourceRevision < 1 || !validUUIDAndDigest(c.SourceID, c.TextDigest) {
			return ErrInvalid
		}
	case ChangeDelete:
		if c.ExpectedRevision < 1 || c.SourceID != "" || c.SourceRevision != 0 || c.TextDigest != "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (c ApplyCommand) RequestDigest() (string, error) {
	c = c.Normalize()
	if err := c.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", ErrInvalid
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

type Repository interface {
	Get(context.Context, SlotKey) (Slot, error)
	List(context.Context, Scope, string, bool, int) ([]Slot, error)
	Apply(context.Context, ApplyCommand) (Slot, error)
}

func validUUIDAndDigest(id, digest string) bool {
	if _, err := uuid.Parse(id); err != nil || len(digest) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}
