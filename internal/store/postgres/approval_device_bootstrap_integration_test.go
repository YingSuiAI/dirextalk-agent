package postgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestBootstrapFirstApprovalDeviceIsOwnerScopedAtomicAndIdempotent(t *testing.T) {
	_, store, instanceID := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Second)
	command := bootstrapApprovalDeviceCommand(instanceID, "owner-bootstrap", "device-bootstrap-a", uuid.NewString(), now, 0x11)

	created, err := store.BootstrapFirstApprovalDevice(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := store.BootstrapFirstApprovalDevice(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.KeyID != created.KeyID || replayed.OwnerID != created.OwnerID || replayed.Revision != created.Revision ||
		!bytes.Equal(replayed.PublicKey, created.PublicKey) {
		t.Fatalf("bootstrap replay changed the persisted device: %#v", replayed)
	}

	conflict := command
	conflict.Device.KeyID = "device-bootstrap-conflict"
	conflict.Device.PublicKey = bytes.Repeat([]byte{0x22}, ed25519.PublicKeySize)
	if _, err := store.BootstrapFirstApprovalDevice(ctx, conflict); !errors.Is(err, task.ErrIdempotencyConflict) {
		t.Fatalf("changed bootstrap replay error=%v", err)
	}

	second := bootstrapApprovalDeviceCommand(instanceID, command.Device.OwnerID, "device-bootstrap-b", uuid.NewString(), now, 0x33)
	if _, err := store.BootstrapFirstApprovalDevice(ctx, second); !errors.Is(err, postgres.ErrApprovalDeviceAlreadyBootstrapped) {
		t.Fatalf("second owner device error=%v", err)
	}

	otherOwner := bootstrapApprovalDeviceCommand(instanceID, "owner-bootstrap-other", "device-bootstrap-other", uuid.NewString(), now, 0x44)
	if _, err := store.BootstrapFirstApprovalDevice(ctx, otherOwner); err != nil {
		t.Fatalf("independent owner bootstrap failed: %v", err)
	}

	concurrentOwner := "owner-bootstrap-concurrent"
	commands := []postgres.RegisterApprovalDeviceCommand{
		bootstrapApprovalDeviceCommand(instanceID, concurrentOwner, "device-bootstrap-concurrent-a", uuid.NewString(), now, 0x55),
		bootstrapApprovalDeviceCommand(instanceID, concurrentOwner, "device-bootstrap-concurrent-b", uuid.NewString(), now, 0x66),
	}
	start := make(chan struct{})
	errorsByAttempt := make([]error, len(commands))
	var group sync.WaitGroup
	for index := range commands {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			<-start
			_, errorsByAttempt[index] = store.BootstrapFirstApprovalDevice(ctx, commands[index])
		}(index)
	}
	close(start)
	group.Wait()
	var succeeded, rejected int
	for _, attemptErr := range errorsByAttempt {
		switch {
		case attemptErr == nil:
			succeeded++
		case errors.Is(attemptErr, postgres.ErrApprovalDeviceAlreadyBootstrapped):
			rejected++
		default:
			t.Fatalf("unexpected concurrent bootstrap error=%v", attemptErr)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("concurrent bootstrap succeeded=%d rejected=%d", succeeded, rejected)
	}
}

func bootstrapApprovalDeviceCommand(instanceID, ownerID, keyID, idempotencyKey string, now time.Time, keyByte byte) postgres.RegisterApprovalDeviceCommand {
	return postgres.RegisterApprovalDeviceCommand{
		IdempotencyKey: idempotencyKey,
		Device: cloudapproval.DeviceKeyV1{
			KeyID: keyID, AgentInstanceID: instanceID, OwnerID: ownerID,
			Revision: 1, Status: cloudapproval.DeviceKeyActive,
			PublicKey: bytes.Repeat([]byte{keyByte}, ed25519.PublicKeySize),
			NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(24 * time.Hour),
		},
	}
}
