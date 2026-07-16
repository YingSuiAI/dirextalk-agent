package rpcapi

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type cloudCoordinatorStub struct {
	quoteCommand  cloudapp.CreateQuoteCommand
	mutationScope cloudapp.MutationScope
	approveCalls  int
	previewScope  cloudapp.MutationScope
	connection    cloudapp.Connection
}

func (stub *cloudCoordinatorStub) Capabilities(context.Context) cloudapp.Capabilities {
	return cloudapp.Capabilities{AWS: true, DirectSTS: true, Worker: true, Reaper: true}
}
func (stub *cloudCoordinatorStub) PreviewAWSIdentity(_ context.Context, scope cloudapp.MutationScope, _ string, _ uint64, _ string) (cloudapp.AWSIdentity, error) {
	stub.previewScope = scope
	return cloudapp.AWSIdentity{AccountID: "123456789012", Region: "us-east-1"}, nil
}
func (stub *cloudCoordinatorStub) CreateQuote(_ context.Context, scope cloudapp.MutationScope, command cloudapp.CreateQuoteCommand) (cloudquote.QuoteV1, error) {
	stub.mutationScope, stub.quoteCommand = scope, command
	return cloudquote.QuoteV1{QuoteID: uuid.NewString()}, nil
}
func (*cloudCoordinatorStub) GetQuote(context.Context, string, string) (cloudquote.QuoteV1, error) {
	return cloudquote.QuoteV1{}, nil
}
func (*cloudCoordinatorStub) CreatePlan(context.Context, cloudapp.MutationScope, cloudapp.CreatePlanCommand) (cloudapproval.PlanV1, error) {
	return cloudapproval.PlanV1{}, nil
}
func (*cloudCoordinatorStub) GetPlan(context.Context, string, string) (cloudapproval.PlanV1, error) {
	return cloudapproval.PlanV1{}, nil
}
func (*cloudCoordinatorStub) CreateApprovalChallenge(context.Context, cloudapp.MutationScope, cloudapp.CreateChallengeCommand) (cloudapp.Challenge, error) {
	return cloudapp.Challenge{}, nil
}
func (stub *cloudCoordinatorStub) ApprovePlan(context.Context, cloudapp.MutationScope, cloudapp.ApprovePlanCommand) (cloudapproval.PlanV1, error) {
	stub.approveCalls++
	return cloudapproval.PlanV1{}, nil
}
func (stub *cloudCoordinatorStub) EstablishAWSConnection(context.Context, cloudapp.MutationScope, cloudapp.EstablishConnectionCommand) (cloudapp.Connection, error) {
	return stub.connection, nil
}

func TestCloudControlServiceMapsCallerAndKeepsAgentInstanceServerOwned(t *testing.T) {
	stub := &cloudCoordinatorStub{}
	instanceID := uuid.NewString()
	service := NewCloudControlService(stub, instanceID)
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
	_, err := service.CreateCloudQuote(ctx, &agentv1.CreateCloudQuoteRequest{
		IdempotencyKey: uuid.NewString(), Scopes: []*agentv1.CloudQuoteScope{{
			OwnerId: "owner-a", ConnectionId: uuid.NewString(),
			Recipe: &agentv1.CloudRecipeBinding{RecipeId: "recipe-a", Digest: "sha256:placeholder", Maturity: "experimental"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stub.mutationScope.ClientID != "message-server" || len(stub.quoteCommand.Scopes) != 1 || stub.quoteCommand.Scopes[0].AgentInstanceID != instanceID {
		t.Fatalf("cloud mutation binding=%#v command=%#v", stub.mutationScope, stub.quoteCommand)
	}
	if _, err := service.PreviewAwsIdentity(ctx, &agentv1.PreviewAwsIdentityRequest{
		BootstrapSessionId: uuid.NewString(), ExpectedSessionRevision: 2, Region: "us-east-1",
	}); err != nil || stub.previewScope.ClientID != "message-server" {
		t.Fatalf("preview caller scope=%#v err=%v", stub.previewScope, err)
	}
}

func TestCloudControlServiceCannotApproveWithoutDeviceSignature(t *testing.T) {
	stub := &cloudCoordinatorStub{}
	service := NewCloudControlService(stub, uuid.NewString())
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
	request := &agentv1.ApproveCloudPlanRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: "owner-a", PlanId: uuid.NewString(), ExpectedRevision: 1,
	}
	if _, err := service.ApproveCloudPlan(ctx, request); status.Code(err) != codes.InvalidArgument || stub.approveCalls != 0 {
		t.Fatalf("unsigned approval code=%v calls=%d", status.Code(err), stub.approveCalls)
	}
	request.Approval = &agentv1.DeviceApprovalSignature{
		ApprovalId: uuid.NewString(), ChallengeId: "challenge_test", SignerKeyId: "device_test",
		ExpiresAt: timestamppb.New(time.Now().UTC().Add(time.Minute)), Signature: make([]byte, 64),
	}
	if _, err := service.ApproveCloudPlan(ctx, request); err != nil || stub.approveCalls != 1 {
		t.Fatalf("signed approval error=%v calls=%d", err, stub.approveCalls)
	}
}

func TestCloudCapabilitiesFailClosedWithoutCoordinator(t *testing.T) {
	response, err := NewCloudControlService(nil, uuid.NewString()).GetCapabilities(context.Background(), &agentv1.CloudControlServiceGetCapabilitiesRequest{})
	if err != nil || response.GetCapabilities().GetAws() || response.GetCapabilities().GetWorker() {
		t.Fatalf("nil coordinator capabilities=%#v err=%v", response.GetCapabilities(), err)
	}
}

func TestEstablishAWSConnectionReturnsPersistedConnectionReadModel(t *testing.T) {
	createdAt := time.Date(2026, 7, 16, 8, 0, 0, 123000000, time.UTC)
	connection := cloudstatus.Connection{
		ConnectionID: uuid.NewString(), OwnerID: "owner-a", AccountID: "123456789012", Region: "us-east-1",
		ControlRoleARN: "arn:aws:iam::123456789012:role/dirextalk-control", FoundationStackID: "foundation-stack",
		CredentialGeneration: 3, Status: "active", Revision: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
	}
	coordinator := &cloudCoordinatorStub{connection: cloudapp.Connection{ConnectionID: connection.ConnectionID, OwnerID: connection.OwnerID}}
	reader := &cloudStatusReaderStub{ownerID: connection.OwnerID, connection: connection}
	service := NewCloudControlService(coordinator, uuid.NewString(), reader)
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
	response, err := service.EstablishAwsConnection(ctx, &agentv1.EstablishAwsConnectionRequest{
		IdempotencyKey: uuid.NewString(), BootstrapSessionId: uuid.NewString(), ExpectedSessionRevision: 2,
		PlanId: uuid.NewString(), ExpectedPlanRevision: 3, OwnerId: connection.OwnerID,
		Approval: &agentv1.DeviceApprovalSignature{
			ApprovalId: uuid.NewString(), ChallengeId: "challenge-test", SignerKeyId: "device-test",
			ExpiresAt: timestamppb.New(time.Now().UTC().Add(time.Minute)), Signature: make([]byte, 64),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := response.GetConnection()
	if got.GetConnectionId() != connection.ConnectionID || got.GetCredentialGeneration() != 3 || got.GetRevision() != 1 ||
		!got.GetCreatedAt().AsTime().Equal(createdAt) || !got.GetUpdatedAt().AsTime().Equal(createdAt) {
		t.Fatalf("establishment returned non-durable connection facts: %+v", got)
	}
}
