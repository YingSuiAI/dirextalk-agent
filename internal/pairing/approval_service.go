package pairing

import (
	"bytes"
	"context"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/google/uuid"
)

type Resumer interface {
	Resume(context.Context, ResumeCommand) (SessionV1, error)
}

type ApprovalService struct {
	agentInstanceID string
	challenges      ChallengeRepository
	devices         DeviceRepository
	scopes          ResumeScopeBuilder
	resumer         Resumer
	now             func() time.Time
}

func NewApprovalService(agentInstanceID string, challenges ChallengeRepository, devices DeviceRepository,
	scopes ResumeScopeBuilder, resumer Resumer, now func() time.Time) (*ApprovalService, error) {
	if !validUUID(agentInstanceID) || challenges == nil || devices == nil || scopes == nil || resumer == nil || now == nil {
		return nil, ErrInvalid
	}
	return &ApprovalService{agentInstanceID: agentInstanceID, challenges: challenges, devices: devices, scopes: scopes, resumer: resumer, now: now}, nil
}

type PrepareResumeCommand struct {
	OwnerID, IdempotencyKey, PairingID, DeploymentID, SignerKeyID string
	ExpectedPairingRevision                                       int64
}

func (service *ApprovalService) Prepare(ctx context.Context, command PrepareResumeCommand) (ResumeChallengeV1, error) {
	if service == nil || ctx == nil || !validRef(command.OwnerID) || !validUUID(command.IdempotencyKey) ||
		!validUUID(command.PairingID) || !validUUID(command.DeploymentID) ||
		(command.SignerKeyID != "" && !validRef(command.SignerKeyID)) || command.ExpectedPairingRevision < 1 {
		return ResumeChallengeV1{}, ErrInvalid
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	var device DeviceKeyV1
	var err error
	if command.SignerKeyID == "" {
		current, ok := service.devices.(CurrentDeviceRepository)
		if !ok {
			return ResumeChallengeV1{}, ErrApprovalRequired
		}
		device, err = current.GetCurrentPairingDeviceKey(ctx, command.OwnerID, now)
	} else {
		device, err = service.devices.GetPairingDeviceKey(ctx, command.SignerKeyID)
	}
	if err != nil || (command.SignerKeyID != "" && device.KeyID != command.SignerKeyID) || device.AgentInstanceID != service.agentInstanceID ||
		device.OwnerID != command.OwnerID || !device.ValidAt(now) {
		return ResumeChallengeV1{}, ErrApprovalRequired
	}
	scope, err := service.scopes.BuildPairingResumeScope(ctx, command.OwnerID, command.PairingID)
	if err != nil || scope.PairingID != command.PairingID || scope.OwnerID != command.OwnerID ||
		scope.DeploymentID != command.DeploymentID || scope.PairingRevision != command.ExpectedPairingRevision || scope.Validate() != nil {
		return ResumeChallengeV1{}, ErrRevisionConflict
	}
	approvalID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(service.agentInstanceID+":pairing-resume:"+command.OwnerID+":"+command.IdempotencyKey)).String()
	challenge := ResumeChallengeV1{
		SchemaVersion: ResumeChallengeSchemaV1,
		ChallengeID:   uuid.NewSHA1(uuid.MustParse(approvalID), []byte("challenge")).String(),
		ApprovalID:    approvalID, SignerKeyID: device.KeyID, Scope: scope,
		IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	challenge.ScopeDigest, err = canonical.Digest(scope)
	if err != nil || challenge.Validate() != nil {
		return ResumeChallengeV1{}, ErrInvalid
	}
	digest, err := canonical.Digest(struct {
		Operation string            `json:"operation"`
		Challenge ResumeChallengeV1 `json:"challenge"`
	}{"pairing.prepare_resume", challenge})
	if err != nil {
		return ResumeChallengeV1{}, ErrInvalid
	}
	return service.challenges.CreateResumeChallenge(ctx,
		Mutation{OwnerID: command.OwnerID, IdempotencyKey: command.IdempotencyKey, RequestDigest: digest}, challenge)
}

type ApproveResumeCommand struct {
	OwnerID, IdempotencyKey, PairingID, DeploymentID, ScopeDigest string
	ExpectedPairingRevision                                       int64
	Signature                                                     ApprovalSignatureV1
}

func (service *ApprovalService) Approve(ctx context.Context, command ApproveResumeCommand) (SessionV1, error) {
	if service == nil || ctx == nil || !validRef(command.OwnerID) || !validUUID(command.IdempotencyKey) ||
		!validUUID(command.PairingID) || !validUUID(command.DeploymentID) ||
		command.ExpectedPairingRevision < 1 || !validUUID(command.Signature.ChallengeID) || !validRef(command.Signature.SignerKeyID) {
		return SessionV1{}, ErrInvalid
	}
	challenge, err := service.challenges.GetResumeChallenge(ctx, command.OwnerID, command.Signature.ChallengeID)
	if err != nil {
		return SessionV1{}, err
	}
	if challenge.Scope.PairingID != command.PairingID || challenge.Scope.DeploymentID != command.DeploymentID ||
		challenge.Scope.PairingRevision != command.ExpectedPairingRevision ||
		(command.ScopeDigest != "" && challenge.ScopeDigest != command.ScopeDigest) {
		return SessionV1{}, ErrRevisionConflict
	}
	current, err := service.scopes.BuildPairingResumeScope(ctx, command.OwnerID, command.PairingID)
	if err != nil || !SameResumeScope(current, challenge.Scope) {
		approved, approvedErr := service.challenges.GetResumeApproval(ctx, command.OwnerID, challenge.ChallengeID)
		if approvedErr != nil || approved.Challenge != challenge ||
			approved.Signature.ChallengeID != command.Signature.ChallengeID ||
			approved.Signature.SignerKeyID != command.Signature.SignerKeyID ||
			!bytes.Equal(approved.Signature.Signature, command.Signature.Signature) {
			return SessionV1{}, ErrRevisionConflict
		}
		return service.resumeApproved(ctx, command, challenge)
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	device, err := service.devices.GetPairingDeviceKey(ctx, command.Signature.SignerKeyID)
	if err != nil || device.KeyID != challenge.SignerKeyID || device.AgentInstanceID != service.agentInstanceID ||
		device.OwnerID != command.OwnerID || !device.ValidAt(now) || VerifyResumeSignature(challenge, command.Signature, device.PublicKey, now) != nil {
		return SessionV1{}, ErrApprovalRequired
	}
	digest, err := canonical.Digest(struct {
		Operation string              `json:"operation"`
		Challenge ResumeChallengeV1   `json:"challenge"`
		Signature ApprovalSignatureV1 `json:"signature"`
	}{"pairing.approve_resume", challenge, command.Signature})
	if err != nil {
		return SessionV1{}, ErrInvalid
	}
	if _, err := service.challenges.RecordResumeApproval(ctx,
		Mutation{OwnerID: command.OwnerID, IdempotencyKey: command.IdempotencyKey, RequestDigest: digest},
		challenge, command.Signature, now); err != nil {
		return SessionV1{}, err
	}
	return service.resumeApproved(ctx, command, challenge)
}

func (service *ApprovalService) resumeApproved(ctx context.Context, command ApproveResumeCommand, challenge ResumeChallengeV1) (SessionV1, error) {
	resumeKey := uuid.NewSHA1(uuid.MustParse(challenge.ApprovalID), []byte("resume:"+strings.TrimSpace(command.IdempotencyKey))).String()
	return service.resumer.Resume(ctx, ResumeCommand{
		OwnerID: command.OwnerID, IdempotencyKey: resumeKey, SessionID: command.PairingID,
		DeploymentID: command.DeploymentID, ExpectedRevision: command.ExpectedPairingRevision,
	})
}
