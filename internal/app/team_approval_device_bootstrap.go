package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
)

const teamApprovalDeviceValidity = 365 * 24 * time.Hour

type teamApprovalSignerStore interface {
	GetDeviceKey(context.Context, string) (cloudapproval.DeviceKeyV1, error)
	RegisterApprovalDevice(
		context.Context,
		task.MutationScope,
		postgres.RegisterApprovalDeviceCommand,
	) (cloudapproval.DeviceKeyV1, error)
}

type teamApprovalSignerRegistrar struct {
	store           teamApprovalSignerStore
	agentInstanceID string
	now             func() time.Time
}

func newTeamApprovalSignerRegistrar(
	store teamApprovalSignerStore,
	agentInstanceID string,
) *teamApprovalSignerRegistrar {
	return &teamApprovalSignerRegistrar{
		store:           store,
		agentInstanceID: agentInstanceID,
		now:             time.Now,
	}
}

func (registrar *teamApprovalSignerRegistrar) RegisterTeamApprovalSigner(
	ctx context.Context,
	scope task.MutationScope,
	command rpcapi.TeamApprovalDeviceBootstrapCommand,
) (cloudapproval.DeviceKeyV1, error) {
	if registrar == nil || registrar.store == nil || registrar.now == nil {
		return cloudapproval.DeviceKeyV1{}, errors.New(
			"Team approval signer registration is unavailable",
		)
	}
	if err := scope.Validate(); err != nil {
		return cloudapproval.DeviceKeyV1{}, err
	}
	now := registrar.now().UTC()
	current, err := registrar.store.GetDeviceKey(ctx, command.KeyID)
	switch {
	case err == nil:
		defer clear(current.PublicKey)
		if !sameTeamApprovalDevice(
			current,
			registrar.agentInstanceID,
			command,
			now,
		) {
			return cloudapproval.DeviceKeyV1{},
				rpcapi.ErrTeamApprovalDeviceAlreadyBootstrapped
		}
		return cloneTeamApprovalDevice(current), nil
	case !errors.Is(err, cloudapproval.ErrDeviceNotFound):
		return cloudapproval.DeviceKeyV1{}, err
	}

	publicKey := append(
		ed25519.PublicKey(nil),
		command.PublicKey...,
	)
	defer clear(publicKey)
	device, err := registrar.store.RegisterApprovalDevice(
		ctx,
		scope,
		postgres.RegisterApprovalDeviceCommand{
			IdempotencyKey: command.IdempotencyKey,
			Device: cloudapproval.DeviceKeyV1{
				KeyID:           command.KeyID,
				AgentInstanceID: registrar.agentInstanceID,
				OwnerID:         command.OwnerID,
				Revision:        1,
				Status:          cloudapproval.DeviceKeyActive,
				PublicKey:       publicKey,
				NotBefore:       now.Add(-time.Minute),
				ExpiresAt:       now.Add(teamApprovalDeviceValidity),
			},
		},
	)
	if err == nil {
		return device, nil
	}
	if !errors.Is(err, postgres.ErrCloudFactRevision) {
		return cloudapproval.DeviceKeyV1{}, err
	}

	// A concurrent exact registration is a state-level replay even when its
	// idempotency key differs. Re-read the deterministic key identity.
	current, readErr := registrar.store.GetDeviceKey(ctx, command.KeyID)
	if readErr != nil {
		if errors.Is(readErr, cloudapproval.ErrDeviceNotFound) {
			return cloudapproval.DeviceKeyV1{},
				rpcapi.ErrTeamApprovalDeviceAlreadyBootstrapped
		}
		return cloudapproval.DeviceKeyV1{}, readErr
	}
	defer clear(current.PublicKey)
	if !sameTeamApprovalDevice(
		current,
		registrar.agentInstanceID,
		command,
		now,
	) {
		return cloudapproval.DeviceKeyV1{},
			rpcapi.ErrTeamApprovalDeviceAlreadyBootstrapped
	}
	return cloneTeamApprovalDevice(current), nil
}

func sameTeamApprovalDevice(
	device cloudapproval.DeviceKeyV1,
	agentInstanceID string,
	command rpcapi.TeamApprovalDeviceBootstrapCommand,
	now time.Time,
) bool {
	return device.KeyID == command.KeyID &&
		device.AgentInstanceID == agentInstanceID &&
		device.OwnerID == command.OwnerID &&
		device.Revision == 1 &&
		bytes.Equal(device.PublicKey, command.PublicKey) &&
		device.ValidateAt(now) == nil
}

func cloneTeamApprovalDevice(
	device cloudapproval.DeviceKeyV1,
) cloudapproval.DeviceKeyV1 {
	device.PublicKey = append(
		ed25519.PublicKey(nil),
		device.PublicKey...,
	)
	if device.RevokedAt != nil {
		revokedAt := *device.RevokedAt
		device.RevokedAt = &revokedAt
	}
	return device
}
