package rpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	clouddestroy "github.com/YingSuiAI/dirextalk-agent/internal/cloud/destroy"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type cloudDestroyCoordinatorStub struct {
	prepareCommand clouddestroy.PrepareCommand
	approveCommand clouddestroy.ApproveCommand
	challenge      clouddestroy.ChallengeV1
	operation      clouddestroy.OperationV1
}

func (stub *cloudDestroyCoordinatorStub) Prepare(_ context.Context, command clouddestroy.PrepareCommand) (clouddestroy.ChallengeV1, error) {
	stub.prepareCommand = command
	return stub.challenge, nil
}
func (stub *cloudDestroyCoordinatorStub) Approve(_ context.Context, command clouddestroy.ApproveCommand) (clouddestroy.OperationV1, error) {
	stub.approveCommand = command
	return stub.operation, nil
}
func (stub *cloudDestroyCoordinatorStub) Get(context.Context, string, string) (clouddestroy.OperationV1, error) {
	return stub.operation, nil
}

func TestCloudDestroyRPCPreservesExactSigningPayloadAndReturnsDurableOperation(t *testing.T) {
	now := time.Date(2026, 7, 17, 3, 0, 0, 0, time.UTC)
	ownerID, deploymentID, taskID, planID, connectionID := "owner-a", uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	resourceID, approvalID := uuid.NewString(), uuid.NewString()
	scope := clouddestroy.ScopeV1{SchemaVersion: clouddestroy.ScopeSchemaV1, AgentInstanceID: uuid.NewString(), OwnerID: ownerID,
		DeploymentID: deploymentID, DeploymentRevision: 9, TaskID: taskID, PlanID: planID, PlanHash: "sha256:" + strings.Repeat("a", 64), ConnectionID: connectionID,
		Resources: []clouddestroy.ResourceScopeV1{{ResourceID: resourceID, Type: resource.TypeSG, ProviderID: "sg-0123456789abcdef0", Revision: 3,
			Retention: task.RetentionEphemeralAutoDestroy, State: resource.StateActive, Region: "us-east-1", SpecDigest: "sha256:spec", ApprovedPlanHash: "sha256:plan",
			OriginalApprovalID: uuid.NewString(), ReadBack: clouddestroy.ReadBackScopeV1{Observed: true, Exists: true, ProviderID: "sg-0123456789abcdef0", ObservedAt: now},
			DestroyDeadline: now.Add(time.Hour), AutoDestroyApproved: true}}}
	challenge := clouddestroy.ChallengeV1{OperationID: uuid.NewString(), ChallengeID: uuid.NewString(), ApprovalID: approvalID, SignerKeyID: "device-a",
		Scope: scope, ScopeDigest: "sha256:scope", IssuedAt: now, ExpiresAt: now.Add(time.Minute), SigningCBOR: []byte{0xa1, 0x01}, Revision: 1}
	approvedAt := now.Add(time.Second)
	operation := clouddestroy.OperationV1{Challenge: challenge, Status: clouddestroy.StatusApproved, Signature: make([]byte, 64), Revision: 2, CreatedAt: now, UpdatedAt: approvedAt, ApprovedAt: &approvedAt}
	destroyer := &cloudDestroyCoordinatorStub{challenge: challenge, operation: operation}
	statusReader := &cloudStatusReaderStub{ownerID: ownerID, deployment: cloudstatus.Deployment{Worker: worker.Deployment{
		DeploymentID: deploymentID, OwnerID: ownerID, TaskID: taskID, StepID: uuid.NewString(), WorkerID: uuid.NewString(), Revision: 4, CreatedAt: now, UpdatedAt: now,
	}, PlanID: planID, ConnectionID: connectionID}}
	service := NewCloudControlServiceWithDestroy(nil, scope.AgentInstanceID, statusReader, destroyer)
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
	prepare, err := service.CreateCloudDeploymentDestroyChallenge(ctx, &agentv1.CreateCloudDeploymentDestroyChallengeRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: ownerID, DeploymentId: deploymentID, ExpectedRevision: 9, SignerKeyId: "device-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := prepare.GetChallenge(); got.GetOperationId() != challenge.OperationID || string(got.GetSigningPayloadCbor()) != string(challenge.SigningCBOR) ||
		len(got.GetScope().GetResources()) != 1 || got.GetScope().GetResources()[0].GetType() != agentv1.CloudResourceType_CLOUD_RESOURCE_TYPE_SECURITY_GROUP {
		t.Fatalf("destroy challenge projection=%#v", got)
	}
	approve, err := service.ApproveCloudDeploymentDestroy(ctx, &agentv1.ApproveCloudDeploymentDestroyRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: ownerID, DeploymentId: deploymentID, ExpectedRevision: 9,
		Approval: &agentv1.DeviceApprovalSignature{ApprovalId: approvalID, ChallengeId: challenge.ChallengeID, SignerKeyId: challenge.SignerKeyID,
			ExpiresAt: timestamppb.New(challenge.ExpiresAt), Signature: make([]byte, 64)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if approve.GetOperation().GetStatus() != agentv1.CloudDestroyOperationStatus_CLOUD_DESTROY_OPERATION_STATUS_APPROVED || approve.GetDeployment().GetDeploymentId() != deploymentID ||
		destroyer.approveCommand.Caller.ClientID != "message-server" {
		t.Fatalf("destroy approval response=%#v command=%#v", approve, destroyer.approveCommand)
	}
}
