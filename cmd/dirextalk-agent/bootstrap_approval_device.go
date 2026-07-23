package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/google/uuid"
)

const approvalDeviceBootstrapTimeout = 30 * time.Second

var ed25519SubjectPublicKeyInfoPrefix = []byte{
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
}

func bootstrapApprovalDevice(cfg config.Config) error {
	if err := config.ValidateCommon(&cfg); err != nil {
		return err
	}
	common := cfg.Common
	command, err := approvalDeviceBootstrapCommand(cfg, common.InstanceID, time.Now().UTC())
	if err != nil {
		return err
	}
	defer clear(command.Device.PublicKey)

	ctx, cancel := context.WithTimeout(context.Background(), approvalDeviceBootstrapTimeout)
	defer cancel()
	pool, err := postgres.Open(ctx, common.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := postgres.VerifySchema(ctx, pool, common.InstanceID); err != nil {
		return err
	}
	store, err := postgres.New(pool, common.InstanceID)
	if err != nil {
		return err
	}
	device, err := store.BootstrapFirstApprovalDevice(ctx, command)
	if err != nil {
		if errors.Is(err, postgres.ErrApprovalDeviceAlreadyBootstrapped) {
			return fmt.Errorf("bootstrap approval device: owner already has an approval device")
		}
		return fmt.Errorf("bootstrap approval device: %w", err)
	}
	defer clear(device.PublicKey)
	slog.Info("first approval device is ready", "owner_id", device.OwnerID, "key_id", device.KeyID, "revision", device.Revision)
	return nil
}

func approvalDeviceBootstrapCommand(cfg config.Config, instanceID string, now time.Time) (postgres.RegisterApprovalDeviceCommand, error) {
	parsedInstanceID, err := uuid.Parse(instanceID)
	if err != nil || parsedInstanceID == uuid.Nil || parsedInstanceID.String() != instanceID {
		return postgres.RegisterApprovalDeviceCommand{}, errors.New("instance_id must be a canonical UUID")
	}
	ownerID := cfg.ApprovalDeviceOwnerID
	keyID := cfg.ApprovalDeviceKeyID
	if !validApprovalDeviceBootstrapIdentifier(ownerID, 255) || !validApprovalDeviceBootstrapIdentifier(keyID, 128) {
		return postgres.RegisterApprovalDeviceCommand{}, errors.New("approval_device_owner_id and approval_device_key_id must be canonical non-control identifiers")
	}
	idempotencyKey := cfg.ApprovalDeviceIdempotencyKey
	parsedIdempotencyKey, err := uuid.Parse(idempotencyKey)
	if err != nil || parsedIdempotencyKey == uuid.Nil || parsedIdempotencyKey.String() != idempotencyKey {
		return postgres.RegisterApprovalDeviceCommand{}, errors.New("approval_device_idempotency_key must be a canonical UUID")
	}
	if now.IsZero() {
		return postgres.RegisterApprovalDeviceCommand{}, errors.New("approval-device bootstrap clock is invalid")
	}
	now = now.UTC()
	expiresAt, err := time.Parse(time.RFC3339, cfg.ApprovalDeviceExpiresAt)
	if err != nil || !now.Before(expiresAt) {
		return postgres.RegisterApprovalDeviceCommand{}, errors.New("approval_device_expires_at must be a future RFC3339 timestamp")
	}
	publicKeyFile := strings.TrimSpace(cfg.ApprovalDevicePublicKeyFile)
	publicKeyMaterial, err := config.ReadKeyMaterial(publicKeyFile)
	if err != nil {
		return postgres.RegisterApprovalDeviceCommand{}, errors.New("could not read mounted approval-device public key")
	}
	defer clear(publicKeyMaterial)
	publicKey, err := approvalDevicePublicKey(publicKeyMaterial)
	if err != nil {
		return postgres.RegisterApprovalDeviceCommand{}, err
	}
	canonicalKeyID := approvalDeviceKeyID(publicKey)
	if keyID != canonicalKeyID {
		clear(publicKey)
		return postgres.RegisterApprovalDeviceCommand{}, errors.New("approval_device_key_id does not match the canonical Ed25519 public-key identity")
	}
	return postgres.RegisterApprovalDeviceCommand{
		IdempotencyKey: idempotencyKey,
		Device: cloudapproval.DeviceKeyV1{
			KeyID: keyID, AgentInstanceID: instanceID, OwnerID: ownerID,
			Revision: 1, Status: cloudapproval.DeviceKeyActive,
			PublicKey: publicKey,
			NotBefore: now.Add(-time.Minute), ExpiresAt: expiresAt.UTC(),
		},
	}, nil
}

func approvalDeviceKeyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return "cloud-device-" + hex.EncodeToString(digest[:])[:24]
}

// approvalDevicePublicKey accepts the raw Ed25519 key used internally and the
// exact RFC 8410 SubjectPublicKeyInfo exported by the Flutter approval-key
// store. The strict prefix rejects another algorithm, parameters, trailing
// fields, and private-key material instead of relying on a permissive ASN.1
// decoder at this one-time trust boundary.
func approvalDevicePublicKey(material []byte) (ed25519.PublicKey, error) {
	switch {
	case len(material) == ed25519.PublicKeySize:
		return append(ed25519.PublicKey(nil), material...), nil
	case len(material) == len(ed25519SubjectPublicKeyInfoPrefix)+ed25519.PublicKeySize &&
		bytes.Equal(material[:len(ed25519SubjectPublicKeyInfoPrefix)], ed25519SubjectPublicKeyInfoPrefix):
		return append(ed25519.PublicKey(nil), material[len(ed25519SubjectPublicKeyInfoPrefix):]...), nil
	default:
		return nil, errors.New("mounted approval-device public key must contain a raw 32-byte Ed25519 key or strict RFC 8410 Ed25519 SubjectPublicKeyInfo")
	}
}

func validApprovalDeviceBootstrapIdentifier(value string, limit int) bool {
	if value == "" || value != strings.TrimSpace(value) || utf8.RuneCountInString(value) > limit {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
