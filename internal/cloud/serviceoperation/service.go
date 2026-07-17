package serviceoperation

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"time"

	"github.com/google/uuid"
)

type Service struct {
	agentInstanceID string
	repository      Repository
	devices         DeviceRepository
	scopes          ScopeBuilder
	now             func() time.Time
}

func NewService(agentInstanceID string, repository Repository, devices DeviceRepository, scopes ScopeBuilder, now func() time.Time) (*Service, error) {
	if !validUUID(agentInstanceID) || repository == nil || devices == nil || scopes == nil || now == nil {
		return nil, ErrInvalid
	}
	return &Service{agentInstanceID, repository, devices, scopes, now}, nil
}

type PrepareCommand struct {
	ClientID                   string
	CredentialID               string
	IdempotencyKey             string
	OwnerID                    string
	DeploymentID               string
	SignerKeyID                string
	ExpectedDeploymentRevision int64
	CostAlertAmountMinor       int64
}

func (service *Service) Prepare(ctx context.Context, command PrepareCommand) (ChallengeV1, error) {
	if ctx == nil || !validRef(command.ClientID) || !validUUID(command.CredentialID) ||
		!validUUID(command.IdempotencyKey) || !validRef(command.OwnerID) || !validUUID(command.DeploymentID) ||
		!validRef(command.SignerKeyID) || command.ExpectedDeploymentRevision < 1 || command.CostAlertAmountMinor < 1 {
		return ChallengeV1{}, ErrInvalid
	}
	hash, err := RequestHash(command)
	if err != nil {
		return ChallengeV1{}, err
	}
	mutation := Mutation{command.ClientID, command.CredentialID, command.IdempotencyKey, hash}
	// Exact replay wins before device, deployment, or other mutable checks.
	if replay, replayErr := service.repository.FindServiceOperationChallengeReplay(ctx, mutation); replayErr == nil {
		return replay, nil
	} else if !errors.Is(replayErr, ErrNotFound) {
		return ChallengeV1{}, replayErr
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	device, err := service.devices.GetDeviceKey(ctx, command.SignerKeyID)
	if err != nil || device.KeyID != command.SignerKeyID || device.AgentInstanceID != service.agentInstanceID ||
		device.OwnerID != command.OwnerID || device.ValidateAt(now) != nil || len(device.PublicKey) != ed25519.PublicKeySize {
		return ChallengeV1{}, ErrApprovalRequired
	}
	operationID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(service.agentInstanceID+":managed-preparation:"+command.ClientID+":"+command.IdempotencyKey)).String()
	scope, err := service.scopes.BuildManagedPreparationScope(ctx, command.OwnerID, command.DeploymentID, operationID, command.CostAlertAmountMinor)
	if err != nil {
		return ChallengeV1{}, err
	}
	scope = cloneScope(scope)
	if scope.AgentInstanceID != service.agentInstanceID || scope.OwnerID != command.OwnerID ||
		scope.PreparationOperationID != operationID || scope.DeploymentID != command.DeploymentID ||
		scope.DeploymentRevision != command.ExpectedDeploymentRevision ||
		scope.Validate() != nil {
		return ChallengeV1{}, ErrRevisionConflict
	}
	challenge := ChallengeV1{
		SchemaVersion: ChallengeSchemaV1,
		ChallengeID:   uuid.NewSHA1(uuid.NameSpaceOID, []byte(operationID+":challenge")).String(),
		OperationID:   operationID, SignerKeyID: command.SignerKeyID, Scope: scope,
		IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	challenge.ScopeDigest, err = SigningPayloadDigest(challenge)
	if err != nil {
		return ChallengeV1{}, err
	}
	return service.repository.CreateServiceOperationChallenge(ctx, mutation, challenge)
}

type ApproveCommand struct {
	ClientID         string
	CredentialID     string
	IdempotencyKey   string
	OwnerID          string
	OperationID      string
	DeploymentID     string
	ScopeDigest      string
	ExpectedRevision int64
	Signature        SignatureV1
}

func (service *Service) Approve(ctx context.Context, command ApproveCommand) (OperationV1, error) {
	if ctx == nil || !validRef(command.ClientID) || !validUUID(command.CredentialID) ||
		!validUUID(command.IdempotencyKey) || !validRef(command.OwnerID) || !validUUID(command.OperationID) ||
		!validUUID(command.DeploymentID) || !validDigest(command.ScopeDigest) || command.ExpectedRevision != 1 {
		return OperationV1{}, ErrInvalid
	}
	hash, err := RequestHash(command)
	if err != nil {
		return OperationV1{}, err
	}
	mutation := Mutation{command.ClientID, command.CredentialID, command.IdempotencyKey, hash}
	// Exact replay wins even after the challenge expires or live facts move.
	if replay, replayErr := service.repository.FindServiceOperationApprovalReplay(ctx, mutation); replayErr == nil {
		return replay, nil
	} else if !errors.Is(replayErr, ErrNotFound) {
		return OperationV1{}, replayErr
	}
	challenge, err := service.repository.GetServiceOperationChallenge(ctx, command.OwnerID, command.Signature.ChallengeID)
	if err != nil {
		return OperationV1{}, err
	}
	if command.OperationID != challenge.OperationID || command.DeploymentID != challenge.Scope.DeploymentID ||
		command.ScopeDigest != challenge.ScopeDigest {
		return OperationV1{}, ErrRevisionConflict
	}
	current, err := service.scopes.BuildManagedPreparationScope(ctx, command.OwnerID, command.DeploymentID,
		challenge.OperationID, challenge.Scope.CostAlertAmountMinor)
	if err != nil {
		return OperationV1{}, err
	}
	current = cloneScope(current)
	if current.Validate() != nil || !reflect.DeepEqual(current, challenge.Scope) {
		return OperationV1{}, ErrRevisionConflict
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	device, err := service.devices.GetDeviceKey(ctx, command.Signature.SignerKeyID)
	if err != nil || device.AgentInstanceID != service.agentInstanceID || device.OwnerID != command.OwnerID ||
		device.ValidateAt(now) != nil || signatureValid(challenge, command.Signature, device.PublicKey, now) != nil {
		return OperationV1{}, ErrApprovalRequired
	}
	return service.repository.ApproveServiceOperation(ctx, mutation, command.Signature, now)
}

func (service *Service) Get(ctx context.Context, ownerID, operationID string) (OperationV1, error) {
	if ctx == nil || !validRef(ownerID) || !validUUID(operationID) {
		return OperationV1{}, ErrInvalid
	}
	return service.repository.GetServiceOperation(ctx, ownerID, operationID)
}
