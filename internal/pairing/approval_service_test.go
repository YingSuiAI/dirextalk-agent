package pairing

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPairingResumeApprovalBindsCurrentScopeAndDevice(t *testing.T) {
	now := time.Date(2026, 7, 17, 13, 0, 0, 0, time.UTC)
	agentID, ownerID, signerID := uuid.NewString(), "owner-a", "device-a"
	publicKey, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scope := validResumeScope()
	repository := &memoryChallengeRepository{}
	devices := pairingDeviceRepositoryFake{key: DeviceKeyV1{KeyID: signerID, AgentInstanceID: agentID, OwnerID: ownerID, PublicKey: publicKey, Active: true, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}}
	scopes := &pairingScopeBuilderFake{scope: scope}
	resumer := &pairingResumerFake{session: SessionV1{SchemaVersion: SchemaV1, SessionID: scope.PairingID, OwnerID: ownerID,
		DeploymentID: scope.DeploymentID, DeploymentRevision: scope.DeploymentRevision, PlanID: scope.PlanID, ConnectionID: scope.ConnectionID, TaskID: scope.TaskID, StepID: scope.StepID,
		RecipeID: "recipe-a", RecipeDigest: scope.RecipeDigest, RecipeRevision: 1, ExecutionManifestDigest: scope.ExecutionManifestDigest,
		BeginCommand: "pairing-begin", ResumeCommand: "pairing-resume", Status: StatusSucceeded, ExpiresAt: now.Add(time.Hour),
		Revision: 4, CreatedAt: now.Add(-time.Minute), UpdatedAt: now}}
	service, err := NewApprovalService(agentID, repository, devices, scopes, resumer, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := service.Prepare(context.Background(), PrepareResumeCommand{
		OwnerID: ownerID, IdempotencyKey: uuid.NewString(), PairingID: scope.PairingID,
		DeploymentID: scope.DeploymentID, ExpectedPairingRevision: scope.PairingRevision,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ResumeSigningBytes(challenge)
	if err != nil {
		t.Fatal(err)
	}
	signature := ApprovalSignatureV1{ChallengeID: challenge.ChallengeID, SignerKeyID: signerID, Signature: ed25519.Sign(privateKey, payload)}
	clear(payload)
	approved, err := service.Approve(context.Background(), ApproveResumeCommand{
		OwnerID: ownerID, IdempotencyKey: uuid.NewString(), PairingID: scope.PairingID, DeploymentID: scope.DeploymentID,
		ScopeDigest: challenge.ScopeDigest, ExpectedPairingRevision: scope.PairingRevision, Signature: signature,
	})
	if err != nil || approved.Status != StatusSucceeded || resumer.calls != 1 || repository.approval.Revision != 1 {
		t.Fatalf("approval = %#v calls=%d persisted=%#v err=%v", approved, resumer.calls, repository.approval, err)
	}

	scopes.scope.PairingRevision++
	if recovered, err := service.Approve(context.Background(), ApproveResumeCommand{
		OwnerID: ownerID, IdempotencyKey: uuid.NewString(), PairingID: scope.PairingID, DeploymentID: scope.DeploymentID,
		ScopeDigest: challenge.ScopeDigest, ExpectedPairingRevision: scope.PairingRevision, Signature: signature,
	}); err != nil || recovered.Status != StatusSucceeded || resumer.calls != 2 {
		t.Fatalf("approved response-loss recovery = %#v calls=%d err=%v", recovered, resumer.calls, err)
	}
	tampered := signature
	tampered.Signature = append([]byte(nil), signature.Signature...)
	tampered.Signature[0] ^= 1
	if _, err := service.Approve(context.Background(), ApproveResumeCommand{
		OwnerID: ownerID, IdempotencyKey: uuid.NewString(), PairingID: scope.PairingID, DeploymentID: scope.DeploymentID,
		ExpectedPairingRevision: scope.PairingRevision, Signature: tampered,
	}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("scope drift with unrecorded signature error = %v", err)
	}
}

func validResumeScope() ResumeScopeV1 {
	return ResumeScopeV1{SchemaVersion: ResumeScopeSchemaV1, Intent: ResumeIntent, PairingID: uuid.NewString(), OwnerID: "owner-a",
		DeploymentID: uuid.NewString(), DeploymentRevision: 8, PlanID: uuid.NewString(), ConnectionID: uuid.NewString(),
		TaskID: uuid.NewString(), StepID: uuid.NewString(), RecipeDigest: digest("a"), ExecutionManifestDigest: digest("b"), PairingRevision: 2}
}

type pairingDeviceRepositoryFake struct{ key DeviceKeyV1 }

func (repository pairingDeviceRepositoryFake) GetPairingDeviceKey(context.Context, string) (DeviceKeyV1, error) {
	return repository.key, nil
}
func (repository pairingDeviceRepositoryFake) GetCurrentPairingDeviceKey(context.Context, string, time.Time) (DeviceKeyV1, error) {
	return repository.key, nil
}

type pairingScopeBuilderFake struct{ scope ResumeScopeV1 }

func (builder *pairingScopeBuilderFake) BuildPairingResumeScope(context.Context, string, string) (ResumeScopeV1, error) {
	return builder.scope, nil
}

type pairingResumerFake struct {
	session SessionV1
	calls   int
}

func (resumer *pairingResumerFake) Resume(context.Context, ResumeCommand) (SessionV1, error) {
	resumer.calls++
	return resumer.session, nil
}

type memoryChallengeRepository struct {
	challenge ResumeChallengeV1
	approval  ResumeApprovalV1
}

func (repository *memoryChallengeRepository) CreateResumeChallenge(_ context.Context, _ Mutation, value ResumeChallengeV1) (ResumeChallengeV1, error) {
	repository.challenge = value
	return value, nil
}
func (repository *memoryChallengeRepository) GetResumeChallenge(_ context.Context, ownerID, challengeID string) (ResumeChallengeV1, error) {
	if repository.challenge.Scope.OwnerID != ownerID || repository.challenge.ChallengeID != challengeID {
		return ResumeChallengeV1{}, ErrNotFound
	}
	return repository.challenge, nil
}
func (repository *memoryChallengeRepository) GetResumeApproval(_ context.Context, ownerID, challengeID string) (ResumeApprovalV1, error) {
	if repository.approval.Challenge.Scope.OwnerID != ownerID || repository.approval.Challenge.ChallengeID != challengeID {
		return ResumeApprovalV1{}, ErrNotFound
	}
	return repository.approval, nil
}
func (repository *memoryChallengeRepository) RecordResumeApproval(_ context.Context, _ Mutation, challenge ResumeChallengeV1,
	signature ApprovalSignatureV1, at time.Time) (ResumeApprovalV1, error) {
	repository.approval = ResumeApprovalV1{Challenge: challenge, Signature: signature, ApprovedAt: at, Revision: 1}
	return repository.approval, nil
}
