package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestTeamApprovalSignerRegistrarRegistersOwnerSigner(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.July, 30, 9, 0, 0, 0, time.UTC)
	store := &teamApprovalSignerStoreFake{getErr: cloudapproval.ErrDeviceNotFound}
	registrar := teamApprovalSignerRegistrarForTest(store, now)
	command := teamApprovalDeviceBootstrapCommandForTest(0x31)
	scope := teamApprovalSignerScopeForTest()

	device, err := registrar.RegisterTeamApprovalSigner(
		context.Background(),
		scope,
		command,
	)
	if err != nil {
		t.Fatal(err)
	}
	if store.registerCalls != 1 || store.scope != scope ||
		store.command.IdempotencyKey != command.IdempotencyKey ||
		store.command.Device.KeyID != command.KeyID ||
		store.command.Device.OwnerID != command.OwnerID ||
		store.command.Device.AgentInstanceID != registrar.agentInstanceID ||
		store.command.Device.Revision != 1 ||
		store.command.Device.Status != cloudapproval.DeviceKeyActive ||
		!bytes.Equal(store.command.Device.PublicKey, command.PublicKey) ||
		!store.command.Device.NotBefore.Equal(now.Add(-time.Minute)) ||
		!store.command.Device.ExpiresAt.Equal(now.Add(teamApprovalDeviceValidity)) ||
		device.KeyID != command.KeyID {
		t.Fatalf(
			"device=%#v command=%#v calls=%d",
			device,
			store.command,
			store.registerCalls,
		)
	}
}

func TestTeamApprovalSignerRegistrarReplaysExactSigner(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.July, 30, 9, 0, 0, 0, time.UTC)
	command := teamApprovalDeviceBootstrapCommandForTest(0x42)
	store := &teamApprovalSignerStoreFake{
		device: teamApprovalDeviceForTest(
			command,
			"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			now,
		),
	}
	registrar := teamApprovalSignerRegistrarForTest(store, now)

	device, err := registrar.RegisterTeamApprovalSigner(
		context.Background(),
		teamApprovalSignerScopeForTest(),
		command,
	)
	if err != nil {
		t.Fatal(err)
	}
	if store.registerCalls != 0 || device.KeyID != command.KeyID ||
		!bytes.Equal(device.PublicKey, command.PublicKey) {
		t.Fatalf("device=%#v register_calls=%d", device, store.registerCalls)
	}
}

func TestTeamApprovalSignerRegistrarRejectsKeyIdentityConflict(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.July, 30, 9, 0, 0, 0, time.UTC)
	command := teamApprovalDeviceBootstrapCommandForTest(0x53)
	other := command
	other.OwnerID = "another-owner"
	store := &teamApprovalSignerStoreFake{
		device: teamApprovalDeviceForTest(
			other,
			"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			now,
		),
	}
	registrar := teamApprovalSignerRegistrarForTest(store, now)

	_, err := registrar.RegisterTeamApprovalSigner(
		context.Background(),
		teamApprovalSignerScopeForTest(),
		command,
	)
	if !errors.Is(err, rpcapi.ErrTeamApprovalDeviceAlreadyBootstrapped) ||
		store.registerCalls != 0 {
		t.Fatalf("error=%v register_calls=%d", err, store.registerCalls)
	}
}

func TestTeamApprovalSignerRegistrarAcceptsExactConcurrentWinner(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.July, 30, 9, 0, 0, 0, time.UTC)
	command := teamApprovalDeviceBootstrapCommandForTest(0x75)
	store := &teamApprovalSignerStoreFake{
		getErr:      cloudapproval.ErrDeviceNotFound,
		registerErr: postgres.ErrCloudFactRevision,
		afterRegister: teamApprovalDeviceForTest(
			command,
			"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			now,
		),
	}
	registrar := teamApprovalSignerRegistrarForTest(store, now)

	device, err := registrar.RegisterTeamApprovalSigner(
		context.Background(),
		teamApprovalSignerScopeForTest(),
		command,
	)
	if err != nil || store.registerCalls != 1 || store.getCalls != 2 ||
		device.KeyID != command.KeyID {
		t.Fatalf(
			"device=%#v error=%v get_calls=%d register_calls=%d",
			device,
			err,
			store.getCalls,
			store.registerCalls,
		)
	}
}

type teamApprovalSignerStoreFake struct {
	device        cloudapproval.DeviceKeyV1
	getErr        error
	afterRegister cloudapproval.DeviceKeyV1
	registerErr   error
	command       postgres.RegisterApprovalDeviceCommand
	scope         task.MutationScope
	getCalls      int
	registerCalls int
}

func (store *teamApprovalSignerStoreFake) GetDeviceKey(
	context.Context,
	string,
) (cloudapproval.DeviceKeyV1, error) {
	store.getCalls++
	if store.getCalls > 1 && store.afterRegister.KeyID != "" {
		return cloneTeamApprovalDevice(store.afterRegister), nil
	}
	return cloneTeamApprovalDevice(store.device), store.getErr
}

func (store *teamApprovalSignerStoreFake) RegisterApprovalDevice(
	_ context.Context,
	scope task.MutationScope,
	command postgres.RegisterApprovalDeviceCommand,
) (cloudapproval.DeviceKeyV1, error) {
	store.registerCalls++
	store.scope = scope
	store.command = command
	store.command.Device = cloneTeamApprovalDevice(command.Device)
	if store.registerErr != nil {
		return cloudapproval.DeviceKeyV1{}, store.registerErr
	}
	return cloneTeamApprovalDevice(command.Device), nil
}

func teamApprovalSignerRegistrarForTest(
	store teamApprovalSignerStore,
	now time.Time,
) *teamApprovalSignerRegistrar {
	registrar := newTeamApprovalSignerRegistrar(
		store,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
	)
	registrar.now = func() time.Time { return now }
	return registrar
}

func teamApprovalSignerScopeForTest() task.MutationScope {
	return task.MutationScope{
		ClientID:     "message-server",
		CredentialID: uuid.NewString(),
	}
}

func teamApprovalDeviceBootstrapCommandForTest(
	keyByte byte,
) rpcapi.TeamApprovalDeviceBootstrapCommand {
	return rpcapi.TeamApprovalDeviceBootstrapCommand{
		IdempotencyKey: uuid.NewString(),
		OwnerID:        "owner-team-bootstrap",
		KeyID:          "cloud-device-test",
		PublicKey:      bytes.Repeat([]byte{keyByte}, ed25519.PublicKeySize),
	}
}

func teamApprovalDeviceForTest(
	command rpcapi.TeamApprovalDeviceBootstrapCommand,
	agentInstanceID string,
	now time.Time,
) cloudapproval.DeviceKeyV1 {
	return cloudapproval.DeviceKeyV1{
		KeyID:           command.KeyID,
		AgentInstanceID: agentInstanceID,
		OwnerID:         command.OwnerID,
		Revision:        1,
		Status:          cloudapproval.DeviceKeyActive,
		PublicKey: append(
			ed25519.PublicKey(nil),
			command.PublicKey...,
		),
		NotBefore: now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
	}
}
