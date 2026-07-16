package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"os"
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

func bootstrapApprovalDevice() error {
	common, err := config.LoadCommon()
	if err != nil {
		return err
	}
	command, err := approvalDeviceBootstrapCommandFromEnvironment(common.InstanceID, time.Now().UTC())
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

func approvalDeviceBootstrapCommandFromEnvironment(instanceID string, now time.Time) (postgres.RegisterApprovalDeviceCommand, error) {
	parsedInstanceID, err := uuid.Parse(instanceID)
	if err != nil || parsedInstanceID == uuid.Nil || parsedInstanceID.String() != instanceID {
		return postgres.RegisterApprovalDeviceCommand{}, errors.New("AGENT_INSTANCE_ID must be a canonical UUID")
	}
	ownerID := os.Getenv("AGENT_APPROVAL_DEVICE_OWNER_ID")
	keyID := os.Getenv("AGENT_APPROVAL_DEVICE_KEY_ID")
	if !validApprovalDeviceBootstrapIdentifier(ownerID, 255) || !validApprovalDeviceBootstrapIdentifier(keyID, 128) {
		return postgres.RegisterApprovalDeviceCommand{}, errors.New("AGENT_APPROVAL_DEVICE_OWNER_ID and AGENT_APPROVAL_DEVICE_KEY_ID must be canonical non-control identifiers")
	}
	idempotencyKey := os.Getenv("AGENT_APPROVAL_DEVICE_IDEMPOTENCY_KEY")
	parsedIdempotencyKey, err := uuid.Parse(idempotencyKey)
	if err != nil || parsedIdempotencyKey == uuid.Nil || parsedIdempotencyKey.String() != idempotencyKey {
		return postgres.RegisterApprovalDeviceCommand{}, errors.New("AGENT_APPROVAL_DEVICE_IDEMPOTENCY_KEY must be a canonical UUID")
	}
	if now.IsZero() {
		return postgres.RegisterApprovalDeviceCommand{}, errors.New("approval-device bootstrap clock is invalid")
	}
	now = now.UTC()
	expiresAt, err := time.Parse(time.RFC3339, os.Getenv("AGENT_APPROVAL_DEVICE_EXPIRES_AT"))
	if err != nil || !now.Before(expiresAt) {
		return postgres.RegisterApprovalDeviceCommand{}, errors.New("AGENT_APPROVAL_DEVICE_EXPIRES_AT must be a future RFC3339 timestamp")
	}
	publicKeyFile := strings.TrimSpace(os.Getenv("AGENT_APPROVAL_DEVICE_PUBLIC_KEY_FILE"))
	publicKeyMaterial, err := config.ReadKeyMaterial(publicKeyFile)
	if err != nil {
		return postgres.RegisterApprovalDeviceCommand{}, errors.New("could not read mounted approval-device public key")
	}
	defer clear(publicKeyMaterial)
	if len(publicKeyMaterial) != ed25519.PublicKeySize {
		return postgres.RegisterApprovalDeviceCommand{}, errors.New("mounted approval-device public key must contain exactly 32 Ed25519 public-key bytes")
	}
	return postgres.RegisterApprovalDeviceCommand{
		IdempotencyKey: idempotencyKey,
		Device: cloudapproval.DeviceKeyV1{
			KeyID: keyID, AgentInstanceID: instanceID, OwnerID: ownerID,
			Revision: 1, Status: cloudapproval.DeviceKeyActive,
			PublicKey: append(ed25519.PublicKey(nil), publicKeyMaterial...),
			NotBefore: now.Add(-time.Minute), ExpiresAt: expiresAt.UTC(),
		},
	}, nil
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
