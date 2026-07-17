package foundation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/google/uuid"
)

type Service struct {
	agentInstanceID string
	repository      Repository
	devices         cloudapproval.DeviceKeyRepository
	snapshots       SnapshotReader
	notifier        Notifier
	now             func() time.Time
}

func NewService(agentInstanceID string, repository Repository, devices cloudapproval.DeviceKeyRepository, snapshots SnapshotReader, notifier Notifier, now func() time.Time) (*Service, error) {
	if !validUUID(agentInstanceID) || repository == nil || devices == nil || snapshots == nil || notifier == nil || now == nil {
		return nil, ErrInvalid
	}
	return &Service{agentInstanceID: agentInstanceID, repository: repository, devices: devices, snapshots: snapshots, notifier: notifier, now: now}, nil
}

type PrepareCommand struct {
	Caller                    MutationScope
	IdempotencyKey            string
	OwnerID                   string
	Action                    Action
	ConnectionID              string
	BootstrapSessionID        string
	ExpectedBootstrapRevision uint64
	SignerKeyID               string
}

type ApproveCommand struct {
	Caller           MutationScope
	IdempotencyKey   string
	OwnerID          string
	OperationID      string
	ExpectedRevision int64
	ConnectionID     string
	Action           Action
	ScopeDigest      string
	Signature        SignatureV1
}

func (service *Service) Prepare(ctx context.Context, command PrepareCommand) (ChallengeV1, error) {
	if service == nil || ctx == nil || command.Caller.Validate() != nil || !validUUID(command.IdempotencyKey) ||
		strings.TrimSpace(command.OwnerID) == "" || !validUUID(command.ConnectionID) || !validUUID(command.BootstrapSessionID) ||
		command.ExpectedBootstrapRevision == 0 || strings.TrimSpace(command.SignerKeyID) == "" {
		return ChallengeV1{}, ErrInvalid
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	device, err := service.devices.GetDeviceKey(ctx, command.SignerKeyID)
	if err != nil || device.AgentInstanceID != service.agentInstanceID || device.OwnerID != command.OwnerID || device.ValidateAt(now) != nil {
		return ChallengeV1{}, ErrApprovalRequired
	}
	snapshot, err := service.snapshots.SnapshotFoundation(ctx, command.Caller, command.OwnerID, command.Action, command.ConnectionID, command.BootstrapSessionID, command.ExpectedBootstrapRevision)
	if err != nil {
		return ChallengeV1{}, err
	}
	if snapshot.Scope.AgentInstanceID != service.agentInstanceID || snapshot.Scope.OwnerID != command.OwnerID || snapshot.Scope.Action != command.Action ||
		snapshot.Scope.ConnectionID != command.ConnectionID || snapshot.Scope.BootstrapSessionID != command.BootstrapSessionID ||
		snapshot.Scope.ExpectedBootstrapRevision != command.ExpectedBootstrapRevision || snapshot.Scope.Validate() != nil ||
		snapshot.SessionUploadedAt.IsZero() || snapshot.SessionExpiresAt.IsZero() || snapshot.SessionUploadedAt.After(now) || !now.Before(snapshot.SessionExpiresAt) {
		return ChallengeV1{}, ErrRevisionConflict
	}
	mutation, err := prepareMutation(command)
	if err != nil {
		return ChallengeV1{}, err
	}
	challenge := ChallengeV1{
		OperationID: deterministicID(service.agentInstanceID, "foundation-operation", command.Caller, command.IdempotencyKey),
		ChallengeID: deterministicID(service.agentInstanceID, "foundation-challenge", command.Caller, command.IdempotencyKey),
		ApprovalID:  deterministicID(service.agentInstanceID, "foundation-approval", command.Caller, command.IdempotencyKey),
		SignerKeyID: command.SignerKeyID, Scope: snapshot.Scope, IssuedAt: now, ExpiresAt: now.Add(ChallengeValidity), Revision: 1,
	}
	challenge.ScopeDigest, err = ScopeDigest(challenge.Scope)
	if err != nil {
		return ChallengeV1{}, ErrInvalid
	}
	challenge.SigningCBOR, err = challenge.SigningPayload()
	if err != nil {
		return ChallengeV1{}, ErrInvalid
	}
	return service.repository.CreateChallenge(ctx, mutation, challenge)
}

func (service *Service) Approve(ctx context.Context, command ApproveCommand) (OperationV1, error) {
	if service == nil || ctx == nil || command.Caller.Validate() != nil || !validUUID(command.IdempotencyKey) || strings.TrimSpace(command.OwnerID) == "" ||
		!validUUID(command.OperationID) || command.ExpectedRevision != 1 || !validUUID(command.ConnectionID) || !digestPattern.MatchString(command.ScopeDigest) || command.Signature.Validate() != nil {
		return OperationV1{}, ErrInvalid
	}
	challenge, err := service.repository.GetChallenge(ctx, command.OwnerID, command.Signature.ChallengeID)
	if err != nil {
		return OperationV1{}, err
	}
	if challenge.OperationID != command.OperationID || challenge.Revision != command.ExpectedRevision || challenge.Scope.ConnectionID != command.ConnectionID ||
		challenge.Scope.Action != command.Action || challenge.ScopeDigest != command.ScopeDigest {
		return OperationV1{}, ErrRevisionConflict
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	if challenge.ApprovalID != command.Signature.ApprovalID || challenge.SignerKeyID != command.Signature.SignerKeyID ||
		!challenge.ExpiresAt.Equal(command.Signature.ExpiresAt) || !now.Before(challenge.ExpiresAt) {
		return OperationV1{}, ErrApprovalRequired
	}
	device, err := service.devices.GetDeviceKey(ctx, command.Signature.SignerKeyID)
	if err != nil || device.AgentInstanceID != service.agentInstanceID || device.OwnerID != command.OwnerID || device.ValidateAt(now) != nil {
		return OperationV1{}, ErrApprovalRequired
	}
	payload, err := challenge.SigningPayload()
	if err != nil || !ed25519.Verify(device.PublicKey, payload, command.Signature.Signature) {
		return OperationV1{}, ErrApprovalRequired
	}
	current, err := service.snapshots.SnapshotFoundation(ctx, command.Caller, command.OwnerID, challenge.Scope.Action, challenge.Scope.ConnectionID, challenge.Scope.BootstrapSessionID, challenge.Scope.ExpectedBootstrapRevision)
	if err != nil {
		return OperationV1{}, err
	}
	digest, err := ScopeDigest(current.Scope)
	if err != nil || digest != challenge.ScopeDigest || !now.Before(current.SessionExpiresAt) {
		return OperationV1{}, ErrRevisionConflict
	}
	mutation, err := approveMutation(command)
	if err != nil {
		return OperationV1{}, err
	}
	operation, err := service.repository.Approve(ctx, mutation, command.Signature, now)
	if err != nil {
		return OperationV1{}, err
	}
	service.notifier.NotifyFoundationOperation()
	return operation, nil
}

func (service *Service) Get(ctx context.Context, ownerID, operationID string) (OperationV1, error) {
	if service == nil || ctx == nil || strings.TrimSpace(ownerID) == "" || !validUUID(operationID) {
		return OperationV1{}, ErrInvalid
	}
	return service.repository.GetOperation(ctx, ownerID, operationID)
}

func prepareMutation(command PrepareCommand) (Mutation, error) {
	encoded, err := canonical.Marshal(struct {
		SchemaVersion             string `json:"schema_version"`
		OwnerID                   string `json:"owner_id"`
		Action                    Action `json:"action"`
		ConnectionID              string `json:"connection_id"`
		BootstrapSessionID        string `json:"bootstrap_session_id"`
		ExpectedBootstrapRevision uint64 `json:"expected_bootstrap_revision"`
		SignerKeyID               string `json:"signer_key_id"`
	}{ScopeSchemaV1, command.OwnerID, command.Action, command.ConnectionID, command.BootstrapSessionID, command.ExpectedBootstrapRevision, command.SignerKeyID})
	if err != nil {
		return Mutation{}, ErrInvalid
	}
	return Mutation{Caller: command.Caller, OwnerID: command.OwnerID, IdempotencyKey: command.IdempotencyKey, RequestHash: sha256.Sum256(encoded)}, nil
}

func approveMutation(command ApproveCommand) (Mutation, error) {
	encoded, err := canonical.Marshal(struct {
		SchemaVersion    string    `json:"schema_version"`
		OwnerID          string    `json:"owner_id"`
		OperationID      string    `json:"operation_id"`
		ExpectedRevision int64     `json:"expected_revision"`
		ConnectionID     string    `json:"connection_id"`
		Action           Action    `json:"action"`
		ScopeDigest      string    `json:"scope_digest"`
		ApprovalID       string    `json:"approval_id"`
		ChallengeID      string    `json:"challenge_id"`
		SignerKeyID      string    `json:"signer_key_id"`
		ExpiresAt        time.Time `json:"expires_at"`
		Signature        []byte    `json:"signature"`
	}{SigningPayloadV1, command.OwnerID, command.OperationID, command.ExpectedRevision, command.ConnectionID, command.Action, command.ScopeDigest,
		command.Signature.ApprovalID, command.Signature.ChallengeID, command.Signature.SignerKeyID, command.Signature.ExpiresAt.UTC(), command.Signature.Signature})
	if err != nil {
		return Mutation{}, ErrInvalid
	}
	return Mutation{Caller: command.Caller, OwnerID: command.OwnerID, IdempotencyKey: command.IdempotencyKey, RequestHash: sha256.Sum256(encoded)}, nil
}

func deterministicID(agentInstanceID, purpose string, caller MutationScope, key string) string {
	hash := sha256.New()
	for _, value := range []string{agentInstanceID, purpose, caller.ClientID, caller.CredentialID, key} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	digest := hash.Sum(nil)
	identifier, err := uuid.FromBytes(digest[:16])
	if err != nil {
		panic(err)
	}
	return identifier.String()
}
