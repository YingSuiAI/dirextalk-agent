package rpcapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var ErrTeamApprovalDeviceAlreadyBootstrapped = errors.New(
	"another approval device is already linked",
)

type TeamApprovalDeviceBootstrapCommand struct {
	IdempotencyKey string
	OwnerID        string
	KeyID          string
	PublicKey      ed25519.PublicKey
}

type TeamApprovalDeviceBootstrapper interface {
	RegisterTeamApprovalSigner(
		context.Context,
		task.MutationScope,
		TeamApprovalDeviceBootstrapCommand,
	) (cloudapproval.DeviceKeyV1, error)
}

func (service *TeamPlanService) WithApprovalDeviceBootstrap(
	bootstrapper TeamApprovalDeviceBootstrapper,
) *TeamPlanService {
	if service != nil {
		service.deviceBootstrap = bootstrapper
	}
	return service
}

func (service *TeamPlanService) BootstrapFirstTeamApprovalDeviceV3(
	ctx context.Context,
	request *agentv1.BootstrapFirstTeamApprovalDeviceV3Request,
) (*agentv1.BootstrapFirstTeamApprovalDeviceV3Response, error) {
	scope, err := mutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service == nil || service.deviceBootstrap == nil {
		return nil, teamPlanUnavailable()
	}
	if request == nil ||
		!canonicalTeamBootstrapUUID(request.GetIdempotencyKey()) ||
		!validTeamBootstrapIdentifier(request.GetOwnerId(), 255) ||
		!validTeamBootstrapIdentifier(request.GetKeyId(), 128) ||
		len(request.GetPublicKey()) != ed25519.PublicKeySize {
		return nil, invalidTeamRequest(
			"valid idempotency_key, owner_id, key_id, and Ed25519 public_key are required",
		)
	}
	publicKey := append(
		ed25519.PublicKey(nil),
		request.GetPublicKey()...,
	)
	defer clear(publicKey)
	digest := sha256.Sum256(publicKey)
	expectedKeyID := "cloud-device-" +
		hex.EncodeToString(digest[:])[:24]
	if request.GetKeyId() != expectedKeyID {
		return nil, invalidTeamRequest(
			"key_id does not match the Ed25519 public key",
		)
	}
	device, err := service.deviceBootstrap.
		RegisterTeamApprovalSigner(
			ctx,
			scope,
			TeamApprovalDeviceBootstrapCommand{
				IdempotencyKey: request.GetIdempotencyKey(),
				OwnerID:        request.GetOwnerId(),
				KeyID:          request.GetKeyId(),
				PublicKey:      publicKey,
			},
		)
	if err != nil {
		return nil, publicError(err)
	}
	defer clear(device.PublicKey)
	now := time.Now().UTC()
	if device.KeyID != request.GetKeyId() ||
		device.OwnerID != request.GetOwnerId() ||
		device.Revision != 1 ||
		!bytes.Equal(device.PublicKey, publicKey) ||
		device.ValidateAt(now) != nil {
		return nil, invalidTeamProjection()
	}
	return &agentv1.BootstrapFirstTeamApprovalDeviceV3Response{
		KeyId:     device.KeyID,
		Revision:  int64(device.Revision),
		ExpiresAt: timestamppb.New(device.ExpiresAt),
	}, nil
}

func canonicalTeamBootstrapUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil &&
		parsed != uuid.Nil &&
		parsed.String() == value
}

func validTeamBootstrapIdentifier(value string, limit int) bool {
	if value == "" ||
		value != strings.TrimSpace(value) ||
		utf8.RuneCountInString(value) > limit {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
