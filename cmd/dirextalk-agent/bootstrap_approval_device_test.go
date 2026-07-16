package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestApprovalDeviceBootstrapCommandReadsOnlyMountedPublicKey(t *testing.T) {
	now := time.Date(2026, time.July, 16, 10, 0, 0, 0, time.UTC)
	publicKey := bytes.Repeat([]byte{0x41}, ed25519.PublicKeySize)
	path := filepath.Join(t.TempDir(), "approval-device.pub")
	if err := os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(publicKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	instanceID, idempotencyKey := uuid.NewString(), uuid.NewString()
	t.Setenv("AGENT_APPROVAL_DEVICE_OWNER_ID", "owner-bootstrap")
	t.Setenv("AGENT_APPROVAL_DEVICE_KEY_ID", "device-bootstrap")
	t.Setenv("AGENT_APPROVAL_DEVICE_PUBLIC_KEY_FILE", path)
	t.Setenv("AGENT_APPROVAL_DEVICE_IDEMPOTENCY_KEY", idempotencyKey)
	t.Setenv("AGENT_APPROVAL_DEVICE_EXPIRES_AT", now.Add(24*time.Hour).Format(time.RFC3339))

	command, err := approvalDeviceBootstrapCommandFromEnvironment(instanceID, now)
	if err != nil {
		t.Fatal(err)
	}
	if command.IdempotencyKey != idempotencyKey || command.Device.AgentInstanceID != instanceID ||
		command.Device.OwnerID != "owner-bootstrap" || command.Device.KeyID != "device-bootstrap" ||
		!bytes.Equal(command.Device.PublicKey, publicKey) || command.Device.Revision != 1 ||
		!command.Device.NotBefore.Equal(now.Add(-time.Minute)) || !command.Device.ExpiresAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("bootstrap command=%#v", command)
	}
	clear(command.Device.PublicKey)
}

func TestApprovalDeviceBootstrapCommandRejectsUntrustedShape(t *testing.T) {
	now := time.Date(2026, time.July, 16, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "approval-device.pub")
	if err := os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize))), 0o600); err != nil {
		t.Fatal(err)
	}
	setValidApprovalDeviceBootstrapEnvironment(t, path, now)
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "owner whitespace", key: "AGENT_APPROVAL_DEVICE_OWNER_ID", value: " owner-bootstrap"},
		{name: "noncanonical idempotency", key: "AGENT_APPROVAL_DEVICE_IDEMPOTENCY_KEY", value: "550E8400-E29B-41D4-A716-446655440000"},
		{name: "expired device", key: "AGENT_APPROVAL_DEVICE_EXPIRES_AT", value: now.Add(-time.Second).Format(time.RFC3339)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.key, test.value)
			if _, err := approvalDeviceBootstrapCommandFromEnvironment(uuid.NewString(), now); err == nil {
				t.Fatal("invalid approval-device bootstrap input was accepted")
			}
		})
	}
}

func setValidApprovalDeviceBootstrapEnvironment(t *testing.T, path string, now time.Time) {
	t.Helper()
	t.Setenv("AGENT_APPROVAL_DEVICE_OWNER_ID", "owner-bootstrap")
	t.Setenv("AGENT_APPROVAL_DEVICE_KEY_ID", "device-bootstrap")
	t.Setenv("AGENT_APPROVAL_DEVICE_PUBLIC_KEY_FILE", path)
	t.Setenv("AGENT_APPROVAL_DEVICE_IDEMPOTENCY_KEY", uuid.NewString())
	t.Setenv("AGENT_APPROVAL_DEVICE_EXPIRES_AT", now.Add(time.Hour).Format(time.RFC3339))
}
