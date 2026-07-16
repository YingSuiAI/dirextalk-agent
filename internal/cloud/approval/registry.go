package approval

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

var (
	ErrDeviceNotFound    = errors.New("approval device key not found")
	ErrChallengeNotFound = errors.New("approval challenge not found")
	ErrChallengeConsumed = errors.New("approval challenge already consumed")
	ErrRevisionConflict  = errors.New("approval challenge revision conflict")
)

type DeviceKeyStatus string

const (
	DeviceKeyActive  DeviceKeyStatus = "active"
	DeviceKeyRevoked DeviceKeyStatus = "revoked"
)

type DeviceKeyV1 struct {
	KeyID           string
	AgentInstanceID string
	OwnerID         string
	Revision        uint64
	Status          DeviceKeyStatus
	PublicKey       ed25519.PublicKey
	NotBefore       time.Time
	ExpiresAt       time.Time
	RevokedAt       *time.Time
}

func (d DeviceKeyV1) ValidateAt(now time.Time) error {
	if err := validateIdentifier("device.key_id", d.KeyID); err != nil {
		return err
	}
	if err := validateIdentifier("device.agent_instance_id", d.AgentInstanceID); err != nil {
		return err
	}
	if err := validateIdentifier("device.owner_id", d.OwnerID); err != nil {
		return err
	}
	if d.Revision == 0 || len(d.PublicKey) != ed25519.PublicKeySize || d.NotBefore.IsZero() || d.ExpiresAt.IsZero() || !d.NotBefore.Before(d.ExpiresAt) {
		return fmt.Errorf("device key revision, Ed25519 public key, and validity window are required")
	}
	if now.IsZero() {
		return fmt.Errorf("current time is required")
	}
	switch d.Status {
	case DeviceKeyActive:
		if d.RevokedAt != nil {
			return fmt.Errorf("active device key cannot have revoked_at")
		}
		if now.Before(d.NotBefore) || !now.Before(d.ExpiresAt) {
			return fmt.Errorf("device key is not currently valid")
		}
	case DeviceKeyRevoked:
		if d.RevokedAt == nil || d.RevokedAt.IsZero() {
			return fmt.Errorf("revoked device key requires revoked_at")
		}
		return fmt.Errorf("device key is revoked")
	default:
		return fmt.Errorf("device key status is invalid")
	}
	return nil
}

type ChallengeV1 struct {
	ChallengeID      string
	Revision         uint64
	AgentInstanceID  string
	OwnerID          string
	PlanID           string
	PlanRevision     uint64
	PlanHash         string
	ConnectionID     string
	RecipeDigest     string
	QuoteID          string
	QuoteDigest      string
	QuoteScopeDigest string
	QuoteCandidateID string
	SignerKeyID      string
	IssuedAt         time.Time
	ExpiresAt        time.Time
	ConsumedAt       *time.Time
}

type DeviceKeyRepository interface {
	GetDeviceKey(context.Context, string) (DeviceKeyV1, error)
}

type ChallengeRepository interface {
	CreateChallenge(context.Context, ChallengeV1) error
	GetChallenge(context.Context, string) (ChallengeV1, error)
	ConsumeChallenge(context.Context, string, uint64, time.Time) error
}
