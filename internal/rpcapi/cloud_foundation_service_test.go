package rpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	cloudfoundation "github.com/YingSuiAI/dirextalk-agent/internal/cloud/foundation"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestFoundationLifecycleRPCPreservesExactIndependentSigningPayload(t *testing.T) {
	now := time.Date(2026, 7, 17, 6, 30, 0, 0, time.UTC)
	scope := cloudfoundation.ScopeV1{SchemaVersion: cloudfoundation.ScopeSchemaV1, AgentInstanceID: uuid.NewString(), OwnerID: "owner-foundation-rpc",
		Action: cloudfoundation.ActionEstablish, ConnectionID: uuid.NewString(), AccountID: "123456789012", Region: "ap-south-1", BootstrapSessionID: uuid.NewString(), ExpectedBootstrapRevision: 2,
		IdentityObservedAt: now.Add(-time.Minute), IdentityExpiresAt: now.Add(time.Minute), FoundationTemplateDigest: "sha256:" + strings.Repeat("a", 64),
		ReaperImageURI: "repo/reaper:v2.0.0-rc.1@sha256:" + strings.Repeat("b", 64), ReleaseEnvironment: cloudfoundation.ReleaseEnvironmentV1{PrivateSubnetCIDR: "10.255.0.0/26", ZeroIngress: true,
			ArtifactBucket: "dtx-agent-123456789012-ap-south-1-test", KMSAlias: "alias/dtx-agent-test-foundation", BucketVersioned: true, BucketSSEKMS: true}}
	challenge := cloudfoundation.ChallengeV1{OperationID: uuid.NewString(), ChallengeID: uuid.NewString(), ApprovalID: uuid.NewString(), SignerKeyID: "device-foundation-rpc",
		Scope: scope, ScopeDigest: "sha256:" + strings.Repeat("c", 64), IssuedAt: now, ExpiresAt: now.Add(time.Minute), SigningCBOR: []byte{0xa1, 0x01}, Revision: 1}
	approvedAt := now.Add(time.Second)
	operation := cloudfoundation.OperationV1{Challenge: challenge, Status: cloudfoundation.StatusApproved, Revision: 2, CreatedAt: now, UpdatedAt: approvedAt, ApprovedAt: &approvedAt}
	stub := &foundationCoordinatorStub{challenge: challenge, operation: operation}
	service := NewCloudControlService(nil, scope.AgentInstanceID).WithFoundation(stub)
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
	prepared, err := service.CreateAwsFoundationOperationChallenge(ctx, &agentv1.CreateAwsFoundationOperationChallengeRequest{IdempotencyKey: uuid.NewString(), OwnerId: scope.OwnerID,
		Action: agentv1.AwsFoundationOperationAction_AWS_FOUNDATION_OPERATION_ACTION_ESTABLISH, ConnectionId: scope.ConnectionID, BootstrapSessionId: scope.BootstrapSessionID,
		ExpectedBootstrapRevision: 2, SignerKeyId: challenge.SignerKeyID})
	if err != nil {
		t.Fatal(err)
	}
	got := prepared.GetChallenge()
	if got.GetOperationId() != challenge.OperationID || string(got.GetSigningPayloadCbor()) != string(challenge.SigningCBOR) || got.GetScope().GetReleaseEnvironment().GetZeroIngress() != true ||
		got.GetScope().GetFoundationTemplateDigest() != scope.FoundationTemplateDigest || stub.prepare.Caller.ClientID != "message-server" {
		t.Fatalf("prepare=%#v command=%#v", got, stub.prepare)
	}
	approved, err := service.ApproveAwsFoundationOperation(ctx, &agentv1.ApproveAwsFoundationOperationRequest{IdempotencyKey: uuid.NewString(), OwnerId: scope.OwnerID,
		OperationId: challenge.OperationID, ExpectedRevision: challenge.Revision, ConnectionId: scope.ConnectionID, Action: agentv1.AwsFoundationOperationAction_AWS_FOUNDATION_OPERATION_ACTION_ESTABLISH, ScopeDigest: challenge.ScopeDigest,
		Approval: &agentv1.DeviceApprovalSignature{ApprovalId: challenge.ApprovalID, ChallengeId: challenge.ChallengeID, SignerKeyId: challenge.SignerKeyID, ExpiresAt: timestamppb.New(challenge.ExpiresAt), Signature: make([]byte, 64)}})
	if err != nil {
		t.Fatal(err)
	}
	if approved.GetOperation().GetStatus() != agentv1.AwsFoundationOperationStatus_AWS_FOUNDATION_OPERATION_STATUS_APPROVED || stub.approve.Signature.ChallengeID != challenge.ChallengeID {
		t.Fatalf("approve=%#v command=%#v", approved, stub.approve)
	}
}

type foundationCoordinatorStub struct {
	prepare   cloudfoundation.PrepareCommand
	approve   cloudfoundation.ApproveCommand
	challenge cloudfoundation.ChallengeV1
	operation cloudfoundation.OperationV1
}

func (stub *foundationCoordinatorStub) Prepare(_ context.Context, command cloudfoundation.PrepareCommand) (cloudfoundation.ChallengeV1, error) {
	stub.prepare = command
	return stub.challenge, nil
}
func (stub *foundationCoordinatorStub) Approve(_ context.Context, command cloudfoundation.ApproveCommand) (cloudfoundation.OperationV1, error) {
	stub.approve = command
	return stub.operation, nil
}
func (stub *foundationCoordinatorStub) Get(context.Context, string, string) (cloudfoundation.OperationV1, error) {
	return stub.operation, nil
}
