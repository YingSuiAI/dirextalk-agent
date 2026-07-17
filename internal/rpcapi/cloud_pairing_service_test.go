package rpcapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/pairing"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type pairingCoordinatorFake struct {
	session          pairing.SessionV1
	payload          pairing.PayloadResult
	ensureOwner      string
	ensureDeployment string
	retrieve         pairing.RetrieveCommand
	err              error
}

func (fake *pairingCoordinatorFake) Ensure(_ context.Context, ownerID, deploymentID string) (pairing.SessionV1, error) {
	fake.ensureOwner, fake.ensureDeployment = ownerID, deploymentID
	return fake.session, fake.err
}

func (fake *pairingCoordinatorFake) Retrieve(_ context.Context, command pairing.RetrieveCommand) (pairing.SessionV1, pairing.PayloadResult, error) {
	fake.retrieve = command
	return fake.session, fake.payload, fake.err
}

type pairingApprovalCoordinatorFake struct {
	challenge pairing.ResumeChallengeV1
	session   pairing.SessionV1
	prepare   pairing.PrepareResumeCommand
	approve   pairing.ApproveResumeCommand
	err       error
}

func (fake *pairingApprovalCoordinatorFake) Prepare(_ context.Context, command pairing.PrepareResumeCommand) (pairing.ResumeChallengeV1, error) {
	fake.prepare = command
	return fake.challenge, fake.err
}

func (fake *pairingApprovalCoordinatorFake) Approve(_ context.Context, command pairing.ApproveResumeCommand) (pairing.SessionV1, error) {
	fake.approve = command
	return fake.session, fake.err
}

func TestCloudPairingRPCsRequireAuthenticatedCaller(t *testing.T) {
	service := NewCloudControlService(nil, uuid.NewString()).WithPairing(&pairingCoordinatorFake{}, &pairingApprovalCoordinatorFake{})
	calls := []func() error{
		func() error {
			_, err := service.GetCloudPairing(context.Background(), &agentv1.GetCloudPairingRequest{})
			return err
		},
		func() error {
			_, err := service.RetrieveCloudPairingPayload(context.Background(), &agentv1.RetrieveCloudPairingPayloadRequest{})
			return err
		},
		func() error {
			_, err := service.CreateCloudPairingResumeChallenge(context.Background(), &agentv1.CreateCloudPairingResumeChallengeRequest{})
			return err
		},
		func() error {
			_, err := service.ApproveCloudPairingResume(context.Background(), &agentv1.ApproveCloudPairingResumeRequest{})
			return err
		},
	}
	for index, call := range calls {
		if code := status.Code(call()); code != codes.Unauthenticated {
			t.Fatalf("call %d code=%s, want unauthenticated", index, code)
		}
	}
}

func TestCloudPairingGetAndRetrieveMapExactOwnerBoundCiphertext(t *testing.T) {
	session := validRPCPairingSession(t, pairing.StatusWaitingUser)
	payload := pairing.PayloadResult{
		Envelope: *session.Envelope, AssociatedDataCBOR: append([]byte(nil), session.AssociatedDataCBOR...),
		PayloadDigest: session.PayloadDigest,
	}
	coordinator := &pairingCoordinatorFake{session: session, payload: payload}
	service := NewCloudControlService(nil, uuid.NewString()).WithPairing(coordinator, nil)
	ctx := pairingRPCContext()

	got, err := service.GetCloudPairing(ctx, &agentv1.GetCloudPairingRequest{
		OwnerId: session.OwnerID, PairingId: session.SessionID, DeploymentId: session.DeploymentID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if coordinator.ensureOwner != session.OwnerID || coordinator.ensureDeployment != session.DeploymentID ||
		got.GetPairing().GetPairingId() != session.SessionID ||
		got.GetPairing().GetStatus() != agentv1.CloudPairingStatus_CLOUD_PAIRING_STATUS_WAITING_USER ||
		!got.GetPairing().GetPayloadReady() {
		t.Fatalf("get pairing mapping=%+v coordinator=%+v", got.GetPairing(), coordinator)
	}

	idempotencyKey := uuid.NewString()
	response, err := service.RetrieveCloudPairingPayload(ctx, &agentv1.RetrieveCloudPairingPayloadRequest{
		IdempotencyKey: idempotencyKey, OwnerId: session.OwnerID, PairingId: session.SessionID,
		DeploymentId: session.DeploymentID, ExpectedRevision: session.PayloadScopeRevision,
		RecipientPublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if coordinator.retrieve.OwnerID != session.OwnerID || coordinator.retrieve.IdempotencyKey != idempotencyKey ||
		coordinator.retrieve.SessionID != session.SessionID || coordinator.retrieve.DeploymentID != session.DeploymentID ||
		coordinator.retrieve.ExpectedRevision != session.PayloadScopeRevision ||
		response.GetPayload().GetSchemaVersion() != secretbootstrap.RecipientEnvelopeSchemaV1 ||
		response.GetPayload().GetPayloadDigest() != session.PayloadDigest ||
		string(response.GetPayload().GetAssociatedDataCbor()) != string(session.AssociatedDataCBOR) ||
		!response.GetPayload().GetExpiresAt().AsTime().Equal(session.ExpiresAt) {
		t.Fatalf("retrieve mapping command=%+v response=%+v", coordinator.retrieve, response)
	}
}

func TestCloudPairingRejectsMismatchedCoordinatorProjection(t *testing.T) {
	session := validRPCPairingSession(t, pairing.StatusWaitingUser)
	coordinator := &pairingCoordinatorFake{session: session}
	service := NewCloudControlService(nil, uuid.NewString()).WithPairing(coordinator, nil)
	_, err := service.GetCloudPairing(pairingRPCContext(), &agentv1.GetCloudPairingRequest{
		OwnerId: session.OwnerID, PairingId: uuid.NewString(), DeploymentId: session.DeploymentID,
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("mismatched pairing projection code=%s err=%v", status.Code(err), err)
	}
}

func TestCloudPairingResumeChallengeAndApprovalUseExactSignedScope(t *testing.T) {
	session := validRPCPairingSession(t, pairing.StatusSucceeded)
	challenge := validRPCPairingChallenge(t, session)
	approvals := &pairingApprovalCoordinatorFake{challenge: challenge, session: session}
	service := NewCloudControlService(nil, uuid.NewString()).WithPairing(nil, approvals)
	ctx := pairingRPCContext()

	prepared, err := service.CreateCloudPairingResumeChallenge(ctx, &agentv1.CreateCloudPairingResumeChallengeRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: session.OwnerID, PairingId: session.SessionID,
		DeploymentId: session.DeploymentID, ExpectedPairingRevision: challenge.Scope.PairingRevision,
		SignerKeyId: challenge.SignerKeyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	// This protects the current Agent proto/domain mapping only. The public
	// Message Server compatibility signature is flattened and will be aligned
	// at the cross-repository contract boundary before this stage closes.
	wantSigning, err := pairing.ResumeSigningBytes(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.GetChallenge().GetScopeDigest() != challenge.ScopeDigest ||
		string(prepared.GetChallenge().GetSigningPayloadCbor()) != string(wantSigning) ||
		prepared.GetChallenge().GetScope().GetExecutionManifestDigest() != session.ExecutionManifestDigest {
		t.Fatalf("challenge mapping=%+v", prepared.GetChallenge())
	}

	signature := make([]byte, ed25519.SignatureSize)
	_, err = service.ApproveCloudPairingResume(ctx, &agentv1.ApproveCloudPairingResumeRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: session.OwnerID, PairingId: session.SessionID,
		DeploymentId: session.DeploymentID, ExpectedPairingRevision: challenge.Scope.PairingRevision,
		ScopeDigest: challenge.ScopeDigest, Approval: &agentv1.DeviceApprovalSignature{
			ApprovalId: challenge.ApprovalID, ChallengeId: challenge.ChallengeID, SignerKeyId: challenge.SignerKeyID,
			ExpiresAt: timestamppb.New(challenge.ExpiresAt), Signature: signature,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if approvals.approve.PairingID != session.SessionID || approvals.approve.ScopeDigest != challenge.ScopeDigest ||
		approvals.approve.Signature.ChallengeID != challenge.ChallengeID ||
		approvals.approve.Signature.SignerKeyID != challenge.SignerKeyID ||
		string(approvals.approve.Signature.Signature) != string(signature) {
		t.Fatalf("approve mapping=%+v", approvals.approve)
	}
}

func TestCloudPairingPublicErrorsAndInvalidApproval(t *testing.T) {
	tests := []struct {
		err  error
		code codes.Code
	}{
		{pairing.ErrInvalid, codes.InvalidArgument},
		{pairing.ErrNotFound, codes.NotFound},
		{pairing.ErrRevisionConflict, codes.Aborted},
		{pairing.ErrApprovalRequired, codes.PermissionDenied},
		{errors.New("private storage detail"), codes.Internal},
	}
	for _, test := range tests {
		if code := status.Code(pairingPublicError(test.err)); code != test.code {
			t.Fatalf("pairingPublicError(%v)=%s, want %s", test.err, code, test.code)
		}
	}

	approvals := &pairingApprovalCoordinatorFake{}
	service := NewCloudControlService(nil, uuid.NewString()).WithPairing(nil, approvals)
	_, err := service.ApproveCloudPairingResume(pairingRPCContext(), &agentv1.ApproveCloudPairingResumeRequest{
		ExpectedPairingRevision: 1, Approval: &agentv1.DeviceApprovalSignature{Signature: make([]byte, ed25519.SignatureSize-1)},
	})
	if status.Code(err) != codes.InvalidArgument || approvals.approve.PairingID != "" {
		t.Fatalf("invalid approval code=%s coordinator=%+v", status.Code(err), approvals.approve)
	}
}

func pairingRPCContext() context.Context {
	return auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
}

func validRPCPairingSession(t *testing.T, statusValue pairing.Status) pairing.SessionV1 {
	t.Helper()
	now := time.Date(2026, time.July, 17, 9, 0, 0, 0, time.UTC)
	envelope := &secretbootstrap.RecipientEnvelopeV1{
		SchemaVersion:   secretbootstrap.RecipientEnvelopeSchemaV1,
		ServerPublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		Nonce:           base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		Ciphertext:      base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
	value := pairing.SessionV1{
		SchemaVersion: pairing.SchemaV1, SessionID: uuid.NewString(), OwnerID: "owner-a", DeploymentID: uuid.NewString(), DeploymentRevision: 7,
		PlanID: uuid.NewString(), ConnectionID: uuid.NewString(), TaskID: uuid.NewString(), StepID: uuid.NewString(),
		RecipeID: "recipe-a", RecipeDigest: rpcPairingDigest("1"), RecipeRevision: 3,
		ExecutionManifestDigest: rpcPairingDigest("2"), BeginCommand: "pairing.begin", ResumeCommand: "pairing.resume",
		Status: statusValue, RecipientKeyDigest: rpcPairingDigest("3"), Envelope: envelope,
		AssociatedDataCBOR: []byte{0xa1, 0x01, 0x01}, PayloadDigest: rpcPairingDigest("4"), PayloadScopeRevision: 1,
		ExpiresAt: now.Add(time.Hour), Revision: 2, CreatedAt: now, UpdatedAt: now.Add(time.Minute),
	}
	if statusValue == pairing.StatusSucceeded {
		started, completed := now.Add(2*time.Minute), now.Add(3*time.Minute)
		value.ResumeStartedAt, value.CompletedAt, value.Revision = &started, &completed, 4
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v (%+v)", err, value)
	}
	return value
}

func validRPCPairingChallenge(t *testing.T, session pairing.SessionV1) pairing.ResumeChallengeV1 {
	t.Helper()
	issued := session.CreatedAt.Add(90 * time.Second)
	value := pairing.ResumeChallengeV1{
		SchemaVersion: pairing.ResumeChallengeSchemaV1, ChallengeID: uuid.NewString(), ApprovalID: uuid.NewString(),
		SignerKeyID: "device-a", IssuedAt: issued, ExpiresAt: issued.Add(5 * time.Minute),
		Scope: pairing.ResumeScopeV1{
			SchemaVersion: pairing.ResumeScopeSchemaV1, Intent: pairing.ResumeIntent, PairingID: session.SessionID,
			OwnerID: session.OwnerID, DeploymentID: session.DeploymentID, DeploymentRevision: 7,
			PlanID: session.PlanID, ConnectionID: session.ConnectionID, TaskID: session.TaskID, StepID: session.StepID,
			RecipeDigest: session.RecipeDigest, ExecutionManifestDigest: session.ExecutionManifestDigest, PairingRevision: 2,
		},
	}
	var err error
	value.ScopeDigest, err = canonical.Digest(value.Scope)
	if err != nil || value.Validate() != nil {
		t.Fatalf("challenge fixture invalid: %v", err)
	}
	return value
}

func rpcPairingDigest(seed string) string {
	const zeros = "0000000000000000000000000000000000000000000000000000000000000000"
	return "sha256:" + seed + zeros[1:]
}
