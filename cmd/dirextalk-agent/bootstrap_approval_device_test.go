package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/google/uuid"
)

func approvalDeviceBootstrapCommandFixture(instanceID string, now time.Time) (postgres.RegisterApprovalDeviceCommand, error) {
	cfg := config.Config{ApprovalDeviceOwnerID: os.Getenv("AGENT_APPROVAL_DEVICE_OWNER_ID"), ApprovalDeviceKeyID: os.Getenv("AGENT_APPROVAL_DEVICE_KEY_ID"), ApprovalDevicePublicKeyFile: os.Getenv("AGENT_APPROVAL_DEVICE_PUBLIC_KEY_FILE"), ApprovalDeviceIdempotencyKey: os.Getenv("AGENT_APPROVAL_DEVICE_IDEMPOTENCY_KEY"), ApprovalDeviceExpiresAt: os.Getenv("AGENT_APPROVAL_DEVICE_EXPIRES_AT")}
	return approvalDeviceBootstrapCommand(cfg, instanceID, now)
}

func TestApprovalDeviceBootstrapCommandReadsOnlyMountedPublicKey(t *testing.T) {
	now := time.Date(2026, time.July, 16, 10, 0, 0, 0, time.UTC)
	publicKey := ed25519.PublicKey(bytes.Repeat([]byte{0x41}, ed25519.PublicKeySize))
	path := filepath.Join(t.TempDir(), "approval-device.pub")
	if err := os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(publicKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	instanceID, idempotencyKey := uuid.NewString(), uuid.NewString()
	t.Setenv("AGENT_APPROVAL_DEVICE_OWNER_ID", "owner-bootstrap")
	t.Setenv("AGENT_APPROVAL_DEVICE_KEY_ID", approvalDeviceKeyID(publicKey))
	t.Setenv("AGENT_APPROVAL_DEVICE_PUBLIC_KEY_FILE", path)
	t.Setenv("AGENT_APPROVAL_DEVICE_IDEMPOTENCY_KEY", idempotencyKey)
	t.Setenv("AGENT_APPROVAL_DEVICE_EXPIRES_AT", now.Add(24*time.Hour).Format(time.RFC3339))

	command, err := approvalDeviceBootstrapCommandFixture(instanceID, now)
	if err != nil {
		t.Fatal(err)
	}
	if command.IdempotencyKey != idempotencyKey || command.Device.AgentInstanceID != instanceID ||
		command.Device.OwnerID != "owner-bootstrap" || command.Device.KeyID != approvalDeviceKeyID(publicKey) ||
		!bytes.Equal(command.Device.PublicKey, publicKey) || command.Device.Revision != 1 ||
		!command.Device.NotBefore.Equal(now.Add(-time.Minute)) || !command.Device.ExpiresAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("bootstrap command=%#v", command)
	}
	clear(command.Device.PublicKey)
}

func TestApprovalDeviceBootstrapCommandAcceptsFlutterRFC8410SPKI(t *testing.T) {
	now := time.Date(2026, time.July, 16, 10, 0, 0, 0, time.UTC)
	publicKey := ed25519.PublicKey(bytes.Repeat([]byte{0x41}, ed25519.PublicKeySize))
	// RFC 8410 Ed25519 SubjectPublicKeyInfo, matching the public format
	// exported by the Flutter approval-key store.
	spki := append([]byte{
		0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
	}, publicKey...)
	path := filepath.Join(t.TempDir(), "approval-device.spki")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(spki)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setValidApprovalDeviceBootstrapEnvironment(t, path, now, publicKey)

	command, err := approvalDeviceBootstrapCommandFixture(uuid.NewString(), now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(command.Device.PublicKey)
	if !bytes.Equal(command.Device.PublicKey, publicKey) {
		t.Fatal("mounted Flutter SPKI did not resolve to the exact raw Ed25519 public key")
	}
}

func TestApprovalDeviceBootstrapCommandRejectsNonEd25519SPKI(t *testing.T) {
	now := time.Date(2026, time.July, 16, 10, 0, 0, 0, time.UTC)
	publicKey := ed25519.PublicKey(bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize))
	validPrefix := []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

	tests := []struct {
		name   string
		prefix []byte
	}{
		{name: "wrong algorithm", prefix: append(append([]byte(nil), validPrefix[:8]...), 0x71, 0x03, 0x21, 0x00)},
		{name: "algorithm parameters", prefix: []byte{0x30, 0x2c, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00, 0x03, 0x21, 0x00}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "approval-device.spki")
			encoded := base64.StdEncoding.EncodeToString(append(test.prefix, publicKey...))
			if err := os.WriteFile(path, []byte(encoded+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			setValidApprovalDeviceBootstrapEnvironment(t, path, now, publicKey)
			if _, err := approvalDeviceBootstrapCommandFixture(uuid.NewString(), now); err == nil {
				t.Fatal("non-Ed25519 SubjectPublicKeyInfo was accepted")
			}
		})
	}
}

func TestApprovalDeviceBootstrapCommandRejectsUntrustedShape(t *testing.T) {
	now := time.Date(2026, time.July, 16, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "approval-device.pub")
	if err := os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize))), 0o600); err != nil {
		t.Fatal(err)
	}
	publicKey := ed25519.PublicKey(bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize))
	setValidApprovalDeviceBootstrapEnvironment(t, path, now, publicKey)
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "owner whitespace", key: "AGENT_APPROVAL_DEVICE_OWNER_ID", value: " owner-bootstrap"},
		{name: "key id alias", key: "AGENT_APPROVAL_DEVICE_KEY_ID", value: "device-bootstrap"},
		{name: "noncanonical idempotency", key: "AGENT_APPROVAL_DEVICE_IDEMPOTENCY_KEY", value: "550E8400-E29B-41D4-A716-446655440000"},
		{name: "expired device", key: "AGENT_APPROVAL_DEVICE_EXPIRES_AT", value: now.Add(-time.Second).Format(time.RFC3339)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.key, test.value)
			if _, err := approvalDeviceBootstrapCommandFixture(uuid.NewString(), now); err == nil {
				t.Fatal("invalid approval-device bootstrap input was accepted")
			}
		})
	}
}

func setValidApprovalDeviceBootstrapEnvironment(t *testing.T, path string, now time.Time, publicKey ed25519.PublicKey) {
	t.Helper()
	t.Setenv("AGENT_APPROVAL_DEVICE_OWNER_ID", "owner-bootstrap")
	t.Setenv("AGENT_APPROVAL_DEVICE_KEY_ID", approvalDeviceKeyID(publicKey))
	t.Setenv("AGENT_APPROVAL_DEVICE_PUBLIC_KEY_FILE", path)
	t.Setenv("AGENT_APPROVAL_DEVICE_IDEMPOTENCY_KEY", uuid.NewString())
	t.Setenv("AGENT_APPROVAL_DEVICE_EXPIRES_AT", now.Add(time.Hour).Format(time.RFC3339))
}
