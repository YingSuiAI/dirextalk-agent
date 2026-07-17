package rpcapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/pairing"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CloudPairingCoordinator is deliberately narrower than the pairing runtime.
// Ensure may materialize the deterministic deployment-bound session, while
// Retrieve returns only root-helper-encrypted payload material.
type CloudPairingCoordinator interface {
	Ensure(context.Context, string, string) (pairing.SessionV1, error)
	Retrieve(context.Context, pairing.RetrieveCommand) (pairing.SessionV1, pairing.PayloadResult, error)
}

type CloudPairingApprovalCoordinator interface {
	Prepare(context.Context, pairing.PrepareResumeCommand) (pairing.ResumeChallengeV1, error)
	Approve(context.Context, pairing.ApproveResumeCommand) (pairing.SessionV1, error)
}

func (service *CloudControlService) GetCloudPairing(ctx context.Context, request *agentv1.GetCloudPairingRequest) (*agentv1.GetCloudPairingResponse, error) {
	if _, err := cloudMutationScope(ctx); err != nil {
		return nil, err
	}
	if service.pairing == nil {
		return nil, cloudUnavailable()
	}
	if request == nil || strings.TrimSpace(request.GetOwnerId()) == "" ||
		strings.TrimSpace(request.GetDeploymentId()) == "" {
		return nil, pairingPublicError(pairing.ErrInvalid)
	}
	value, err := service.pairing.Ensure(ctx, request.GetOwnerId(), request.GetDeploymentId())
	if err != nil {
		return nil, pairingPublicError(err)
	}
	if !pairingMatchesRequest(value, request.GetOwnerId(), value.SessionID, request.GetDeploymentId()) ||
		(request.GetPairingId() != "" && value.SessionID != request.GetPairingId()) {
		return nil, status.Error(codes.Internal, "stored pairing session is invalid")
	}
	return &agentv1.GetCloudPairingResponse{Pairing: cloudPairingToProto(value)}, nil
}

func (service *CloudControlService) RetrieveCloudPairingPayload(ctx context.Context, request *agentv1.RetrieveCloudPairingPayloadRequest) (*agentv1.RetrieveCloudPairingPayloadResponse, error) {
	if _, err := cloudMutationScope(ctx); err != nil {
		return nil, err
	}
	if service.pairing == nil {
		return nil, cloudUnavailable()
	}
	if request == nil || request.GetExpectedRevision() < 1 {
		return nil, pairingPublicError(pairing.ErrInvalid)
	}
	value, payload, err := service.pairing.Retrieve(ctx, pairing.RetrieveCommand{
		OwnerID: request.GetOwnerId(), IdempotencyKey: request.GetIdempotencyKey(),
		SessionID: request.GetPairingId(), DeploymentID: request.GetDeploymentId(),
		ExpectedRevision: request.GetExpectedRevision(), RecipientPublicKey: request.GetRecipientPublicKey(),
	})
	if err != nil {
		return nil, pairingPublicError(err)
	}
	if !pairingMatchesRequest(value, request.GetOwnerId(), request.GetPairingId(), request.GetDeploymentId()) ||
		value.Envelope == nil || value.PayloadDigest != payload.PayloadDigest ||
		value.Envelope != nil && *value.Envelope != payload.Envelope ||
		!bytes.Equal(value.AssociatedDataCBOR, payload.AssociatedDataCBOR) {
		return nil, status.Error(codes.Internal, "stored encrypted pairing payload is invalid")
	}
	return &agentv1.RetrieveCloudPairingPayloadResponse{
		Pairing: cloudPairingToProto(value),
		Payload: &agentv1.EncryptedPairingPayload{
			SchemaVersion: payload.Envelope.SchemaVersion, ServerPublicKey: payload.Envelope.ServerPublicKey,
			Nonce: payload.Envelope.Nonce, Ciphertext: payload.Envelope.Ciphertext,
			AssociatedDataCbor: append([]byte(nil), payload.AssociatedDataCBOR...),
			PayloadDigest:      payload.PayloadDigest, ExpiresAt: timestamppb.New(value.ExpiresAt),
		},
	}, nil
}

func (service *CloudControlService) CreateCloudPairingResumeChallenge(ctx context.Context, request *agentv1.CreateCloudPairingResumeChallengeRequest) (*agentv1.CreateCloudPairingResumeChallengeResponse, error) {
	if _, err := cloudMutationScope(ctx); err != nil {
		return nil, err
	}
	if service.pairingApprovals == nil {
		return nil, cloudUnavailable()
	}
	if request == nil || request.GetExpectedPairingRevision() < 1 {
		return nil, pairingPublicError(pairing.ErrInvalid)
	}
	value, err := service.pairingApprovals.Prepare(ctx, pairing.PrepareResumeCommand{
		OwnerID: request.GetOwnerId(), IdempotencyKey: request.GetIdempotencyKey(), PairingID: request.GetPairingId(),
		DeploymentID: request.GetDeploymentId(), ExpectedPairingRevision: request.GetExpectedPairingRevision(),
		SignerKeyID: request.GetSignerKeyId(),
	})
	if err != nil {
		return nil, pairingPublicError(err)
	}
	if value.Scope.OwnerID != request.GetOwnerId() || value.Scope.PairingID != request.GetPairingId() ||
		value.Scope.DeploymentID != request.GetDeploymentId() || value.Scope.PairingRevision != request.GetExpectedPairingRevision() {
		return nil, status.Error(codes.Internal, "stored pairing resume challenge is invalid")
	}
	result, err := cloudPairingResumeChallengeToProto(value)
	if err != nil {
		return nil, status.Error(codes.Internal, "stored pairing resume challenge is invalid")
	}
	return &agentv1.CreateCloudPairingResumeChallengeResponse{Challenge: result}, nil
}

func (service *CloudControlService) ApproveCloudPairingResume(ctx context.Context, request *agentv1.ApproveCloudPairingResumeRequest) (*agentv1.ApproveCloudPairingResumeResponse, error) {
	if _, err := cloudMutationScope(ctx); err != nil {
		return nil, err
	}
	if service.pairingApprovals == nil {
		return nil, cloudUnavailable()
	}
	approval := request.GetApproval()
	if request == nil || request.GetExpectedPairingRevision() < 1 || approval == nil ||
		strings.TrimSpace(approval.GetApprovalId()) == "" || approval.GetExpiresAt() == nil ||
		!approval.GetExpiresAt().IsValid() || approval.GetExpiresAt().AsTime().IsZero() ||
		len(approval.GetSignature()) != ed25519.SignatureSize {
		return nil, pairingPublicError(pairing.ErrInvalid)
	}
	value, err := service.pairingApprovals.Approve(ctx, pairing.ApproveResumeCommand{
		OwnerID: request.GetOwnerId(), IdempotencyKey: request.GetIdempotencyKey(), PairingID: request.GetPairingId(),
		DeploymentID: request.GetDeploymentId(), ExpectedPairingRevision: request.GetExpectedPairingRevision(),
		ScopeDigest: request.GetScopeDigest(), Signature: pairing.ApprovalSignatureV1{
			ChallengeID: approval.GetChallengeId(), SignerKeyID: approval.GetSignerKeyId(),
			Signature: append([]byte(nil), approval.GetSignature()...),
		},
	})
	if err != nil {
		return nil, pairingPublicError(err)
	}
	if !pairingMatchesRequest(value, request.GetOwnerId(), request.GetPairingId(), request.GetDeploymentId()) {
		return nil, status.Error(codes.Internal, "stored pairing session is invalid")
	}
	return &agentv1.ApproveCloudPairingResumeResponse{Pairing: cloudPairingToProto(value)}, nil
}

func pairingMatchesRequest(value pairing.SessionV1, ownerID, pairingID, deploymentID string) bool {
	return value.Validate() == nil && value.OwnerID == ownerID && value.SessionID == pairingID && value.DeploymentID == deploymentID
}

func cloudPairingToProto(value pairing.SessionV1) *agentv1.CloudPairingSession {
	return &agentv1.CloudPairingSession{
		PairingId: value.SessionID, OwnerId: value.OwnerID, DeploymentId: value.DeploymentID,
		DeploymentRevision: value.DeploymentRevision,
		TaskId:             value.TaskID, StepId: value.StepID, PlanId: value.PlanID, ConnectionId: value.ConnectionID,
		RecipeId: value.RecipeID, RecipeDigest: value.RecipeDigest, RecipeRevision: value.RecipeRevision,
		BeginCommandId: value.BeginCommand, ResumeCommandId: value.ResumeCommand,
		ExecutionManifestDigest: value.ExecutionManifestDigest, Status: cloudPairingStatusToProto(value.Status),
		PayloadReady: value.Envelope != nil, Revision: value.Revision, ExpiresAt: timestamppb.New(value.ExpiresAt),
		PayloadScopeRevision: value.PayloadScopeRevision,
		CreatedAt:            timestamppb.New(value.CreatedAt), UpdatedAt: timestamppb.New(value.UpdatedAt),
	}
}

func cloudPairingStatusToProto(value pairing.Status) agentv1.CloudPairingStatus {
	return map[pairing.Status]agentv1.CloudPairingStatus{
		pairing.StatusWaitingPayload: agentv1.CloudPairingStatus_CLOUD_PAIRING_STATUS_WAITING_PAYLOAD,
		pairing.StatusPayloadReady:   agentv1.CloudPairingStatus_CLOUD_PAIRING_STATUS_PAYLOAD_READY,
		pairing.StatusWaitingUser:    agentv1.CloudPairingStatus_CLOUD_PAIRING_STATUS_WAITING_USER,
		pairing.StatusResuming:       agentv1.CloudPairingStatus_CLOUD_PAIRING_STATUS_RESUMING,
		pairing.StatusSucceeded:      agentv1.CloudPairingStatus_CLOUD_PAIRING_STATUS_SUCCEEDED,
		pairing.StatusTimedOut:       agentv1.CloudPairingStatus_CLOUD_PAIRING_STATUS_TIMED_OUT,
		pairing.StatusFailed:         agentv1.CloudPairingStatus_CLOUD_PAIRING_STATUS_FAILED,
	}[value]
}

func cloudPairingResumeChallengeToProto(value pairing.ResumeChallengeV1) (*agentv1.CloudPairingResumeChallenge, error) {
	if value.Validate() != nil {
		return nil, pairing.ErrInvalid
	}
	signing, err := pairing.ResumeSigningBytes(value)
	if err != nil {
		return nil, err
	}
	return &agentv1.CloudPairingResumeChallenge{
		SchemaVersion: value.SchemaVersion, ChallengeId: value.ChallengeID, ApprovalId: value.ApprovalID,
		SignerKeyId: value.SignerKeyID, Scope: &agentv1.CloudPairingResumeScope{
			SchemaVersion: value.Scope.SchemaVersion, Intent: value.Scope.Intent, PairingId: value.Scope.PairingID,
			OwnerId: value.Scope.OwnerID, DeploymentId: value.Scope.DeploymentID, DeploymentRevision: value.Scope.DeploymentRevision,
			PlanId: value.Scope.PlanID, ConnectionId: value.Scope.ConnectionID, TaskId: value.Scope.TaskID, StepId: value.Scope.StepID,
			RecipeDigest: value.Scope.RecipeDigest, ExecutionManifestDigest: value.Scope.ExecutionManifestDigest,
			PairingRevision: value.Scope.PairingRevision,
		}, ScopeDigest: value.ScopeDigest, IssuedAt: timestamppb.New(value.IssuedAt), ExpiresAt: timestamppb.New(value.ExpiresAt),
		SigningPayloadCbor: signing,
	}, nil
}
