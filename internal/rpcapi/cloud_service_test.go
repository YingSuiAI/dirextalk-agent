package rpcapi

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
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
	previewValue  cloudapp.AWSIdentityEvidence
	connection    cloudapp.Connection
	plan          cloudapproval.PlanV1
	challenge     cloudapp.Challenge
}

type stagedRPCIdentity struct{}

func (stagedRPCIdentity) PreviewIdentity(context.Context, string, string, uint64, string) (cloudapp.AWSIdentityEvidence, error) {
	return cloudapp.AWSIdentityEvidence{}, nil
}

func (stub *cloudCoordinatorStub) Capabilities(context.Context) cloudapp.Capabilities {
	return cloudapp.Capabilities{AWS: true, DirectSTS: true, Worker: true, Reaper: true}
}
func (stub *cloudCoordinatorStub) PreviewAWSIdentity(_ context.Context, scope cloudapp.MutationScope, sessionID string, revision uint64, region string) (cloudapp.AWSIdentityEvidence, error) {
	stub.previewScope = scope
	if stub.previewValue.BootstrapSessionID != "" {
		return stub.previewValue, nil
	}
	observedAt := time.Date(2026, time.July, 16, 8, 0, 0, 123000000, time.UTC)
	return cloudapp.AWSIdentityEvidence{
		BootstrapSessionID: sessionID, SessionRevision: revision, OwnerID: "owner-a", TargetID: uuid.NewString(),
		Identity: cloudapp.AWSIdentity{
			AccountID: "123456789012", PrincipalARN: "arn:aws:iam::123456789012:root",
			PrincipalID: "123456789012", Region: region, RootIdentity: true,
		},
		ObservedAt: observedAt, ExpiresAt: observedAt.Add(5 * time.Minute),
	}, nil
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
func (stub *cloudCoordinatorStub) GetPlan(context.Context, string, string) (cloudapproval.PlanV1, error) {
	return stub.plan, nil
}
func (stub *cloudCoordinatorStub) CreateApprovalChallenge(context.Context, cloudapp.MutationScope, cloudapp.CreateChallengeCommand) (cloudapp.Challenge, error) {
	return stub.challenge, nil
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
	sessionID := uuid.NewString()
	response, err := service.PreviewAwsIdentity(ctx, &agentv1.PreviewAwsIdentityRequest{
		BootstrapSessionId: sessionID, ExpectedSessionRevision: 2, Region: "us-east-1",
	})
	if err != nil || stub.previewScope.ClientID != "message-server" {
		t.Fatalf("preview caller scope=%#v err=%v", stub.previewScope, err)
	}
	if response.GetBootstrapSessionId() != sessionID || response.GetSessionRevision() != 2 || response.GetOwnerId() != "owner-a" ||
		response.GetTargetId() == "" || response.GetIdentity().GetRegion() != "us-east-1" ||
		response.GetObservedAt().AsTime().Nanosecond() != 123000000 || !response.GetObservedAt().AsTime().Before(response.GetExpiresAt().AsTime()) {
		t.Fatalf("preview evidence response=%#v", response)
	}
}

func TestStagedWorkerControlCapabilityFailsClosedAcrossCloudMutationSurfaces(t *testing.T) {
	coordinator, err := cloudapp.NewStagedAWSService(uuid.NewString(), stagedRPCIdentity{})
	if err != nil {
		t.Fatal(err)
	}
	service := NewCloudControlService(coordinator, uuid.NewString())
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
	operations := []struct {
		name string
		call func() error
	}{
		{name: "quote", call: func() error {
			_, err := service.CreateCloudQuote(ctx, &agentv1.CreateCloudQuoteRequest{})
			return err
		}},
		{name: "plan", call: func() error {
			_, err := service.CreateCloudPlan(ctx, &agentv1.CreateCloudPlanRequest{})
			return err
		}},
		{name: "cloud Goal plan", call: func() error {
			_, err := service.CreateCloudGoal(ctx, &agentv1.CreateCloudGoalRequest{})
			return err
		}},
		{name: "approval", call: func() error {
			_, err := service.ApproveCloudPlan(ctx, &agentv1.ApproveCloudPlanRequest{})
			return err
		}},
		{name: "Foundation", call: func() error {
			_, err := service.CreateAwsFoundationOperationChallenge(ctx, &agentv1.CreateAwsFoundationOperationChallengeRequest{})
			return err
		}},
		{name: "Managed preparation", call: func() error {
			_, err := service.CreateCloudManagedPreparation(ctx, &agentv1.CreateCloudManagedPreparationRequest{})
			return err
		}},
		{name: "Managed acceptance", call: func() error {
			_, err := service.CreateCloudManagedAcceptanceChallenge(ctx, &agentv1.CreateCloudManagedAcceptanceChallengeRequest{})
			return err
		}},
		{name: "Managed lifecycle", call: func() error {
			_, err := service.PrepareManagedKnowledgeLifecycle(ctx, &agentv1.PrepareManagedKnowledgeLifecycleRequest{})
			return err
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			err := operation.call()
			if status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != "worker-control PrivateLink capability is not ready" {
				t.Fatalf("error=%v, want stable capability-not-ready FailedPrecondition", err)
			}
		})
	}
}

func TestPreviewAWSIdentityRejectsUnboundOrInvalidPersistedEvidence(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	sessionID := uuid.NewString()
	valid := cloudapp.AWSIdentityEvidence{
		BootstrapSessionID: sessionID, SessionRevision: 2, OwnerID: "owner-a", TargetID: uuid.NewString(),
		Identity: cloudapp.AWSIdentity{
			AccountID: "123456789012", PrincipalARN: "arn:aws:iam::123456789012:root",
			PrincipalID: "123456789012", Region: "us-east-1", RootIdentity: true,
		},
		ObservedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	tests := map[string]func(*cloudapp.AWSIdentityEvidence){
		"session":  func(value *cloudapp.AWSIdentityEvidence) { value.BootstrapSessionID = uuid.NewString() },
		"revision": func(value *cloudapp.AWSIdentityEvidence) { value.SessionRevision++ },
		"region":   func(value *cloudapp.AWSIdentityEvidence) { value.Identity.Region = "eu-west-1" },
		"owner":    func(value *cloudapp.AWSIdentityEvidence) { value.OwnerID = "" },
		"target":   func(value *cloudapp.AWSIdentityEvidence) { value.TargetID = "" },
		"time":     func(value *cloudapp.AWSIdentityEvidence) { value.ExpiresAt = value.ObservedAt },
	}
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
	request := &agentv1.PreviewAwsIdentityRequest{BootstrapSessionId: sessionID, ExpectedSessionRevision: 2, Region: "us-east-1"}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := valid
			mutate(&value)
			service := NewCloudControlService(&cloudCoordinatorStub{previewValue: value}, uuid.NewString())
			if _, err := service.PreviewAwsIdentity(ctx, request); status.Code(err) != codes.Internal {
				t.Fatalf("code=%v, want Internal", status.Code(err))
			}
		})
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

func TestApprovalChallengeMapsCompleteStructuredSigningBindings(t *testing.T) {
	instanceID := uuid.NewString()
	plan := rpcApprovalPlan(t, instanceID)
	challenge := rpcApprovalChallenge(t, plan)
	stub := &cloudCoordinatorStub{plan: plan, challenge: challenge}
	service := NewCloudControlService(stub, instanceID)
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})

	response, err := service.CreateApprovalChallenge(ctx, &agentv1.CreateApprovalChallengeRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: plan.OwnerID, PlanId: plan.PlanID,
		ExpectedRevision: int64(plan.Revision), SignerKeyId: challenge.Challenge.SignerKeyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := response.GetChallenge()
	if got.GetApprovalId() != challenge.ApprovalID || got.GetChallengeId() != challenge.Challenge.ChallengeID ||
		got.GetAgentInstanceId() != plan.AgentInstanceID || got.GetOwnerId() != plan.OwnerID ||
		got.GetPlanId() != plan.PlanID || got.GetPlanRevision() != int64(plan.Revision) ||
		got.GetPlanHash() != challenge.Challenge.PlanHash || got.GetConnectionId() != plan.ConnectionID ||
		got.GetRecipeDigest() != plan.Recipe.Digest || got.GetQuoteId() != plan.Quote.QuoteID ||
		got.GetQuoteDigest() != plan.Quote.Digest || got.GetQuoteScopeDigest() != plan.Quote.ScopeDigest ||
		got.GetQuoteCandidateId() != plan.Quote.CandidateID || !bytes.Equal(got.GetSigningPayloadCbor(), challenge.SigningCBOR) {
		t.Fatalf("structured approval challenge lost a signed binding: %+v", got)
	}
}

func TestApprovalChallengeRejectsCoordinatorBindingOrPayloadTampering(t *testing.T) {
	instanceID := uuid.NewString()
	basePlan := rpcApprovalPlan(t, instanceID)
	tests := map[string]func(*cloudapp.Challenge){
		"agent instance": func(value *cloudapp.Challenge) { value.Challenge.AgentInstanceID = uuid.NewString() },
		"owner":          func(value *cloudapp.Challenge) { value.Challenge.OwnerID = "owner-other" },
		"connection":     func(value *cloudapp.Challenge) { value.Challenge.ConnectionID = uuid.NewString() },
		"recipe":         func(value *cloudapp.Challenge) { value.Challenge.RecipeDigest = rpcApprovalDigest("9") },
		"quote id":       func(value *cloudapp.Challenge) { value.Challenge.QuoteID = uuid.NewString() },
		"quote digest":   func(value *cloudapp.Challenge) { value.Challenge.QuoteDigest = rpcApprovalDigest("8") },
		"quote scope":    func(value *cloudapp.Challenge) { value.Challenge.QuoteScopeDigest = rpcApprovalDigest("7") },
		"quote candidate": func(value *cloudapp.Challenge) {
			value.Challenge.QuoteCandidateID = string(cloudquote.CandidatePerformance)
		},
		"opaque payload": func(value *cloudapp.Challenge) {
			value.SigningCBOR = append([]byte(nil), value.SigningCBOR...)
			value.SigningCBOR[len(value.SigningCBOR)-1] ^= 1
		},
	}
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			challenge := rpcApprovalChallenge(t, basePlan)
			mutate(&challenge)
			service := NewCloudControlService(&cloudCoordinatorStub{plan: basePlan, challenge: challenge}, instanceID)
			_, err := service.CreateApprovalChallenge(ctx, &agentv1.CreateApprovalChallengeRequest{
				IdempotencyKey: uuid.NewString(), OwnerId: basePlan.OwnerID, PlanId: basePlan.PlanID,
				ExpectedRevision: int64(basePlan.Revision), SignerKeyId: challenge.Challenge.SignerKeyID,
			})
			if status.Code(err) != codes.Internal {
				t.Fatalf("tampered challenge code=%v, want Internal", status.Code(err))
			}
		})
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

type failOnceConnectionReader struct {
	*cloudStatusReaderStub
	err error
}

func (reader *failOnceConnectionReader) GetConnection(ctx context.Context, ownerID, connectionID string) (cloudstatus.Connection, error) {
	if reader.err != nil {
		err := reader.err
		reader.err = nil
		return cloudstatus.Connection{}, err
	}
	return reader.cloudStatusReaderStub.GetConnection(ctx, ownerID, connectionID)
}

func TestEstablishAWSConnectionUnknownResponseCanReadBackCanonicalConnection(t *testing.T) {
	connectionID := uuid.NewString()
	connection := cloudstatus.Connection{
		ConnectionID: connectionID, OwnerID: "owner-a", AccountID: "123456789012", Region: "us-east-1",
		ControlRoleARN: "arn:aws:iam::123456789012:role/dirextalk-control", FoundationStackID: "foundation-stack",
		CredentialGeneration: 1, Status: "active", Revision: 1,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	reader := &failOnceConnectionReader{
		cloudStatusReaderStub: &cloudStatusReaderStub{ownerID: connection.OwnerID, connection: connection},
		err:                   cloudapp.ErrUnavailable,
	}
	service := NewCloudControlService(
		&cloudCoordinatorStub{connection: cloudapp.Connection{ConnectionID: connectionID, OwnerID: connection.OwnerID}},
		uuid.NewString(), reader,
	)
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
	request := &agentv1.EstablishAwsConnectionRequest{
		IdempotencyKey: uuid.NewString(), BootstrapSessionId: uuid.NewString(), ExpectedSessionRevision: 2,
		PlanId: uuid.NewString(), ExpectedPlanRevision: 2, OwnerId: connection.OwnerID,
		Approval: &agentv1.DeviceApprovalSignature{
			ApprovalId: uuid.NewString(), ChallengeId: "challenge-test", SignerKeyId: "device-test",
			ExpiresAt: timestamppb.New(time.Now().UTC().Add(time.Minute)), Signature: make([]byte, 64),
		},
	}
	if _, err := service.EstablishAwsConnection(ctx, request); status.Code(err) != codes.Unavailable {
		t.Fatalf("lost establish response code=%v, want Unavailable", status.Code(err))
	}
	recovered, err := service.GetCloudConnection(ctx, &agentv1.GetCloudConnectionRequest{OwnerId: connection.OwnerID, ConnectionId: connectionID})
	if err != nil || recovered.GetConnection().GetConnectionId() != connectionID {
		t.Fatalf("connection read-back=%#v err=%v", recovered.GetConnection(), err)
	}
}

func rpcApprovalPlan(t *testing.T, instanceID string) cloudapproval.PlanV1 {
	t.Helper()
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	plan := cloudapproval.PlanV1{
		SchemaVersion: cloudapproval.PlanSchemaV1, AgentInstanceID: instanceID, OwnerID: "owner-a",
		PlanID: uuid.NewString(), Revision: 7, Status: cloudapproval.PlanReadyForConfirmation, ConnectionID: uuid.NewString(),
		Recipe: cloudapproval.RecipeBindingV1{RecipeID: "recipe-a", Digest: rpcApprovalDigest("a"), Maturity: recipe.MaturityExperimental},
		Quote: cloudapproval.QuoteBindingV1{
			QuoteID: uuid.NewString(), Digest: rpcApprovalDigest("b"), CandidateID: string(cloudquote.CandidateRecommended), ValidUntil: now.Add(15 * time.Minute),
		},
		ResourceScope: cloudapproval.ResourceScopeV1{
			Region: "us-east-1", AvailabilityZones: []string{"us-east-1a", "us-east-1b"}, InstanceType: "m7i.xlarge",
			InstanceCount: 1, Architecture: recipe.ArchitectureAMD64, VCPU: 4, MemoryMiB: 16384,
			DiskGiB: 80, VolumeType: "gp3", VolumeEncrypted: true, PurchaseOption: cloudapproval.PurchaseOnDemand,
			WorkerImageID: "ami-0123456789abcdef0", WorkerImageDigest: rpcApprovalDigest("c"),
		},
		NetworkScope:   cloudapproval.NetworkScopeV1{VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0", SecurityGroupID: "sg-0123456789abcdef0", EntryPoint: cloudapproval.EntryPointNone},
		SecretScope:    []cloudapproval.SecretReferenceV1{{SecretRef: "secret_ref:plan/model-token", Purpose: "model access", Delivery: recipe.SecretDeliveryFile}},
		RetentionScope: cloudapproval.RetentionScopeV1{Class: cloudapproval.RetentionEphemeral, AutoDestroy: true, GracePeriodSeconds: 1800, MaxLifetimeSeconds: 86400},
	}
	var err error
	plan.Quote.ScopeDigest, err = plan.PricingScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func rpcApprovalChallenge(t *testing.T, plan cloudapproval.PlanV1) cloudapp.Challenge {
	t.Helper()
	issuedAt := time.Date(2026, time.July, 16, 8, 0, 1, 0, time.UTC)
	planHash, err := plan.Hash()
	if err != nil {
		t.Fatal(err)
	}
	challenge := cloudapproval.ChallengeV1{
		ChallengeID: "challenge_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Revision: 1,
		AgentInstanceID: plan.AgentInstanceID, OwnerID: plan.OwnerID, PlanID: plan.PlanID, PlanRevision: plan.Revision,
		PlanHash: planHash, ConnectionID: plan.ConnectionID, RecipeDigest: plan.Recipe.Digest,
		QuoteID: plan.Quote.QuoteID, QuoteDigest: plan.Quote.Digest, QuoteScopeDigest: plan.Quote.ScopeDigest,
		QuoteCandidateID: plan.Quote.CandidateID, SignerKeyID: "cloud-device-test", IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(5 * time.Minute),
	}
	approvalID := uuid.NewString()
	unsigned, err := cloudapproval.NewApprovalV1(plan, approvalID, challenge.ChallengeID, challenge.SignerKeyID, challenge.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := unsigned.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	return cloudapp.Challenge{ApprovalID: approvalID, Challenge: challenge, ExpiresAt: challenge.ExpiresAt, SigningCBOR: payload}
}

func rpcApprovalDigest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }
