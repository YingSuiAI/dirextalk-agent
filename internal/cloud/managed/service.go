package managed

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/google/uuid"
)

const maxManagedHealthAge = 5 * time.Minute

type Service struct {
	agentInstanceID string
	repository      Repository
	devices         DeviceRepository
	scopes          ScopeBuilder
	processor       Processor
	now             func() time.Time
}

func NewService(agentID string, repository Repository, devices DeviceRepository, scopes ScopeBuilder, processor Processor, now func() time.Time) (*Service, error) {
	if !validUUID(agentID) || repository == nil || devices == nil || scopes == nil || processor == nil || now == nil {
		return nil, ErrInvalid
	}
	return &Service{agentID, repository, devices, scopes, processor, now}, nil
}

type PrepareCommand struct {
	ClientID, CredentialID, IdempotencyKey, OwnerID, DeploymentID, SignerKeyID string
	ExpectedDeploymentRevision                                                 int64
}

func (s *Service) Prepare(ctx context.Context, command PrepareCommand) (ChallengeV1, error) {
	if ctx == nil || !validSafeRef(command.ClientID) || !validUUID(command.CredentialID) || !validUUID(command.IdempotencyKey) ||
		!validSafeRef(command.OwnerID) || !validUUID(command.DeploymentID) || !validSafeRef(command.SignerKeyID) || command.ExpectedDeploymentRevision < 1 {
		return ChallengeV1{}, ErrInvalid
	}
	hash, err := requestHash(command)
	if err != nil {
		return ChallengeV1{}, err
	}
	mutation := Mutation{command.ClientID, command.CredentialID, command.IdempotencyKey, hash}
	if replay, replayErr := s.repository.FindManagedAcceptanceChallengeReplay(ctx, mutation); replayErr == nil {
		return replay, nil
	} else if !errors.Is(replayErr, ErrNotFound) {
		return ChallengeV1{}, replayErr
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	device, err := s.devices.GetDeviceKey(ctx, command.SignerKeyID)
	if err != nil || device.KeyID != command.SignerKeyID || device.AgentInstanceID != s.agentInstanceID || device.OwnerID != command.OwnerID ||
		device.ValidateAt(now) != nil || len(device.PublicKey) != ed25519.PublicKeySize {
		return ChallengeV1{}, ErrApprovalRequired
	}
	approvalID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(s.agentInstanceID+":managed-approval:"+command.ClientID+":"+command.IdempotencyKey)).String()
	snapshot, err := s.scopes.BuildManagedAcceptanceSnapshot(ctx, command.OwnerID, command.DeploymentID, approvalID)
	if err != nil {
		return ChallengeV1{}, err
	}
	scope := snapshot.Scope
	scope.AgentInstanceID, scope.AcceptanceID = s.agentInstanceID, approvalID
	if scope.OwnerID != command.OwnerID || scope.DeploymentID != command.DeploymentID ||
		scope.DeploymentRevision != command.ExpectedDeploymentRevision ||
		scope.HealthObservedAt.After(now) || now.Sub(scope.HealthObservedAt) > maxManagedHealthAge {
		return ChallengeV1{}, ErrRevisionConflict
	}
	challenge := ChallengeV1{SchemaVersion: ChallengeSchemaV1, ChallengeID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(approvalID+":challenge")).String(),
		ApprovalID: approvalID, SignerKeyID: device.KeyID, Scope: scope, Service: snapshot.Service, Recipe: snapshot.Recipe, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	digest, err := SigningPayloadDigest(challenge)
	if err != nil {
		return ChallengeV1{}, err
	}
	challenge.ScopeDigest = digest
	return s.repository.CreateManagedAcceptanceChallenge(ctx, mutation, challenge)
}

type ApproveCommand struct {
	ClientID, CredentialID, IdempotencyKey, OwnerID, OperationID, DeploymentID, ScopeDigest string
	ExpectedRevision                                                                        int64
	Signature                                                                               SignatureV1
}

func (s *Service) Approve(ctx context.Context, command ApproveCommand) (OperationV1, error) {
	if ctx == nil || !validSafeRef(command.ClientID) || !validUUID(command.CredentialID) || !validUUID(command.IdempotencyKey) ||
		!validSafeRef(command.OwnerID) || !validUUID(command.OperationID) || !validUUID(command.DeploymentID) || command.ExpectedRevision != 1 {
		return OperationV1{}, ErrInvalid
	}
	hash, err := requestHash(command)
	if err != nil {
		return OperationV1{}, err
	}
	mutation := Mutation{command.ClientID, command.CredentialID, command.IdempotencyKey, hash}
	if replay, replayErr := s.repository.FindManagedAcceptanceApprovalReplay(ctx, mutation); replayErr == nil {
		return replay, nil
	} else if !errors.Is(replayErr, ErrNotFound) {
		return OperationV1{}, replayErr
	}
	challenge, err := s.repository.GetManagedAcceptanceChallenge(ctx, command.OwnerID, command.Signature.ChallengeID)
	if err != nil {
		return OperationV1{}, err
	}
	if command.OperationID != challenge.ApprovalID || command.DeploymentID != challenge.Scope.DeploymentID || command.ScopeDigest != challenge.ScopeDigest {
		return OperationV1{}, ErrRevisionConflict
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	current, err := s.scopes.BuildManagedAcceptanceSnapshot(ctx, command.OwnerID, command.DeploymentID, challenge.ApprovalID)
	if err != nil {
		return OperationV1{}, err
	}
	current.Scope.AgentInstanceID, current.Scope.AcceptanceID = s.agentInstanceID, challenge.ApprovalID
	if current.Scope.HealthObservedAt.After(now) || now.Sub(current.Scope.HealthObservedAt) > maxManagedHealthAge {
		return OperationV1{}, ErrRevisionConflict
	}
	currentDigest, err := ScopeDigest(current.Scope)
	challengeDigest, challengeErr := ScopeDigest(challenge.Scope)
	if err != nil || challengeErr != nil || currentDigest != challengeDigest ||
		!reflect.DeepEqual(current.Service, challenge.Service) || !reflect.DeepEqual(current.Recipe, challenge.Recipe) {
		return OperationV1{}, ErrRevisionConflict
	}
	device, err := s.devices.GetDeviceKey(ctx, command.Signature.SignerKeyID)
	if err != nil || device.AgentInstanceID != s.agentInstanceID || device.OwnerID != command.OwnerID ||
		device.ValidateAt(now) != nil || signatureValid(challenge, command.Signature, device.PublicKey, now) != nil {
		return OperationV1{}, ErrApprovalRequired
	}
	operation, err := s.repository.ApproveManagedAcceptance(ctx, mutation, command.Signature, now)
	if err != nil {
		return OperationV1{}, err
	}
	s.processor.NotifyManagedAcceptance()
	return s.processor.ExecuteManagedAcceptance(ctx, operation)
}

func (s *Service) Get(ctx context.Context, ownerID, operationID string) (OperationV1, error) {
	if ctx == nil || !validSafeRef(ownerID) || !validUUID(operationID) {
		return OperationV1{}, fmt.Errorf("%w: owner and operation are required", ErrInvalid)
	}
	return s.repository.GetManagedAcceptanceOperation(ctx, ownerID, operationID)
}
