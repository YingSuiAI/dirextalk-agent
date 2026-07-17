package rpcapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type cloudEntryCoordinatorStub struct {
	plan      entrypoint.PlanV1
	challenge entrypoint.ChallengeV1
	operation entrypoint.OperationV1

	createCommand  entrypoint.CreatePlanCommand
	prepareCommand entrypoint.PrepareCommand
	approveCommand entrypoint.ApproveCommand
	planReads      []cloudEntryPlanRead
	operationReads []cloudEntryOperationRead

	createCalls  int
	prepareCalls int
	approveCalls int

	createErr  error
	getPlanErr error
	prepareErr error
	approveErr error
	getErr     error
}

type cloudEntryPlanRead struct {
	ownerID     string
	entryPlanID string
}

type cloudEntryOperationRead struct {
	ownerID     string
	operationID string
}

func (stub *cloudEntryCoordinatorStub) CreatePlan(_ context.Context, command entrypoint.CreatePlanCommand) (entrypoint.PlanV1, error) {
	stub.createCalls++
	stub.createCommand = command
	if stub.createErr != nil {
		return entrypoint.PlanV1{}, stub.createErr
	}
	return stub.plan, nil
}

func (stub *cloudEntryCoordinatorStub) GetPlan(_ context.Context, ownerID, entryPlanID string) (entrypoint.PlanV1, error) {
	stub.planReads = append(stub.planReads, cloudEntryPlanRead{ownerID: ownerID, entryPlanID: entryPlanID})
	if stub.getPlanErr != nil {
		return entrypoint.PlanV1{}, stub.getPlanErr
	}
	return stub.plan, nil
}

func (stub *cloudEntryCoordinatorStub) Prepare(_ context.Context, command entrypoint.PrepareCommand) (entrypoint.ChallengeV1, error) {
	stub.prepareCalls++
	stub.prepareCommand = command
	if stub.prepareErr != nil {
		return entrypoint.ChallengeV1{}, stub.prepareErr
	}
	return stub.challenge, nil
}

func (stub *cloudEntryCoordinatorStub) Approve(_ context.Context, command entrypoint.ApproveCommand) (entrypoint.OperationV1, error) {
	stub.approveCalls++
	stub.approveCommand = command
	if stub.approveErr != nil {
		return entrypoint.OperationV1{}, stub.approveErr
	}
	return stub.operation, nil
}

func (stub *cloudEntryCoordinatorStub) Get(_ context.Context, ownerID, operationID string) (entrypoint.OperationV1, error) {
	stub.operationReads = append(stub.operationReads, cloudEntryOperationRead{ownerID: ownerID, operationID: operationID})
	if stub.getErr != nil {
		return entrypoint.OperationV1{}, stub.getErr
	}
	return stub.operation, nil
}

type cloudEntryRPCFixture struct {
	scope     entrypoint.ScopeV1
	plan      entrypoint.PlanV1
	challenge entrypoint.ChallengeV1
	signature entrypoint.SignatureV1
	operation entrypoint.OperationV1
}

func TestCloudEntryRPCMapsAuthenticatedMutationCommandsAndProjectsSafeScope(t *testing.T) {
	fixture := newCloudEntryRPCFixture(t)
	draft, expectedDraft := cloudEntryRPCDraft(t)
	coordinator := &cloudEntryCoordinatorStub{plan: fixture.plan, challenge: fixture.challenge, operation: fixture.operation}
	service := NewCloudControlServiceWithGoals(nil, fixture.scope.AgentInstanceID, nil, nil, nil, coordinator)
	principal := auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()}
	ctx := auth.ContextWithPrincipal(context.Background(), principal)

	createRequest := &agentv1.CreateCloudDeploymentEntryPlanRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: fixture.scope.OwnerID, DeploymentId: fixture.scope.Worker.DeploymentID,
		ExpectedRevision: fixture.scope.Worker.DeploymentRevision, Draft: draft,
	}
	created, err := service.CreateCloudDeploymentEntryPlan(ctx, createRequest)
	if err != nil {
		t.Fatal(err)
	}
	if got := coordinator.createCommand; got.Caller != (task.MutationScope{ClientID: principal.ClientID, CredentialID: principal.CredentialID}) ||
		got.IdempotencyKey != createRequest.GetIdempotencyKey() || got.OwnerID != createRequest.GetOwnerId() ||
		got.DeploymentID != createRequest.GetDeploymentId() || got.ExpectedDeploymentRevision != createRequest.GetExpectedRevision() ||
		!reflect.DeepEqual(got.Draft, expectedDraft) {
		t.Fatalf("entry plan command lost caller/request bindings: %#v", got)
	}
	if reflect.TypeOf(coordinator.createCommand.Draft).NumField() != 9 {
		t.Fatalf("entry plan draft gained caller-controlled fields: %#v", coordinator.createCommand.Draft)
	}
	assertCloudEntryPlanProjection(t, created.GetPlan(), fixture.plan)
	assertCloudEntryProjectionIsDeSensitized(t, created)

	readPlan, err := service.GetCloudEntryPlan(ctx, &agentv1.GetCloudEntryPlanRequest{OwnerId: fixture.scope.OwnerID, EntryPlanId: fixture.plan.EntryPlanID})
	if err != nil {
		t.Fatal(err)
	}
	assertCloudEntryPlanProjection(t, readPlan.GetPlan(), fixture.plan)
	assertCloudEntryProjectionIsDeSensitized(t, readPlan)

	prepareRequest := &agentv1.CreateCloudDeploymentEntryChallengeRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: fixture.scope.OwnerID, EntryPlanId: fixture.plan.EntryPlanID,
		ExpectedRevision: int64(fixture.plan.Revision), SignerKeyId: fixture.challenge.SignerKeyID,
	}
	prepared, err := service.CreateCloudDeploymentEntryChallenge(ctx, prepareRequest)
	if err != nil {
		t.Fatal(err)
	}
	if got := coordinator.prepareCommand; got.Caller != (task.MutationScope{ClientID: principal.ClientID, CredentialID: principal.CredentialID}) ||
		got.IdempotencyKey != prepareRequest.GetIdempotencyKey() || got.OwnerID != prepareRequest.GetOwnerId() ||
		got.EntryPlanID != prepareRequest.GetEntryPlanId() || got.ExpectedRevision != uint64(prepareRequest.GetExpectedRevision()) ||
		got.SignerKeyID != prepareRequest.GetSignerKeyId() {
		t.Fatalf("entry challenge command lost caller/request bindings: %#v", got)
	}
	assertCloudEntryChallengeProjection(t, prepared.GetChallenge(), fixture.challenge, fixture.plan.Scope)
	assertCloudEntryProjectionIsDeSensitized(t, prepared)

	approveRequest := &agentv1.ApproveCloudDeploymentEntryRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: fixture.scope.OwnerID, EntryPlanId: fixture.plan.EntryPlanID,
		ExpectedRevision: int64(fixture.plan.Revision), Approval: cloudEntrySignatureToProto(fixture.signature),
	}
	approved, err := service.ApproveCloudDeploymentEntry(ctx, approveRequest)
	if err != nil {
		t.Fatal(err)
	}
	if got := coordinator.approveCommand; got.Caller != (task.MutationScope{ClientID: principal.ClientID, CredentialID: principal.CredentialID}) ||
		got.IdempotencyKey != approveRequest.GetIdempotencyKey() || got.OwnerID != approveRequest.GetOwnerId() ||
		got.EntryPlanID != approveRequest.GetEntryPlanId() || got.ExpectedRevision != uint64(approveRequest.GetExpectedRevision()) ||
		!reflect.DeepEqual(got.Signature, fixture.signature) {
		t.Fatalf("entry approval command lost caller/request bindings: %#v", got)
	}
	assertCloudEntryOperationProjection(t, approved.GetOperation(), fixture.operation, fixture.plan)
	assertCloudEntryProjectionIsDeSensitized(t, approved)

	readOperation, err := service.GetCloudEntryOperation(ctx, &agentv1.GetCloudEntryOperationRequest{OwnerId: fixture.scope.OwnerID, OperationId: fixture.operation.Challenge.OperationID})
	if err != nil {
		t.Fatal(err)
	}
	assertCloudEntryOperationProjection(t, readOperation.GetOperation(), fixture.operation, fixture.plan)
	assertCloudEntryProjectionIsDeSensitized(t, readOperation)

	for _, read := range coordinator.planReads {
		if read.ownerID != fixture.scope.OwnerID || read.entryPlanID != fixture.plan.EntryPlanID {
			t.Fatalf("entry plan read lost owner/plan binding: %#v", read)
		}
	}
	if len(coordinator.operationReads) != 1 || coordinator.operationReads[0] != (cloudEntryOperationRead{ownerID: fixture.scope.OwnerID, operationID: fixture.operation.Challenge.OperationID}) {
		t.Fatalf("entry operation read lost owner/operation binding: %#v", coordinator.operationReads)
	}
}

func TestCloudEntryRPCRejectsInvalidApprovalSignatures(t *testing.T) {
	fixture := newCloudEntryRPCFixture(t)
	coordinator := &cloudEntryCoordinatorStub{plan: fixture.plan, challenge: fixture.challenge, operation: fixture.operation}
	service := NewCloudControlServiceWithGoals(nil, fixture.scope.AgentInstanceID, nil, nil, nil, coordinator)
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
	base := &agentv1.ApproveCloudDeploymentEntryRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: fixture.scope.OwnerID, EntryPlanId: fixture.plan.EntryPlanID,
		ExpectedRevision: int64(fixture.plan.Revision), Approval: cloudEntrySignatureToProto(fixture.signature),
	}

	tests := map[string]func(*agentv1.ApproveCloudDeploymentEntryRequest){
		"missing": func(request *agentv1.ApproveCloudDeploymentEntryRequest) {
			request.Approval = nil
		},
		"expired": func(request *agentv1.ApproveCloudDeploymentEntryRequest) {
			request.Approval.ExpiresAt = timestamppb.New(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC))
		},
		"short signature": func(request *agentv1.ApproveCloudDeploymentEntryRequest) {
			request.Approval.Signature = make([]byte, ed25519.SignatureSize-1)
		},
		"long signature": func(request *agentv1.ApproveCloudDeploymentEntryRequest) {
			request.Approval.Signature = make([]byte, ed25519.SignatureSize+1)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := proto.Clone(base).(*agentv1.ApproveCloudDeploymentEntryRequest)
			mutate(request)
			if _, err := service.ApproveCloudDeploymentEntry(ctx, request); status.Code(err) != codes.InvalidArgument || coordinator.approveCalls != 0 {
				t.Fatalf("code=%s approve calls=%d err=%v", status.Code(err), coordinator.approveCalls, err)
			}
		})
	}
}

func TestCloudEntryRPCMapsDomainErrorsWithoutLeakingDetails(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		code    codes.Code
		message string
	}{
		{name: "approval required", err: entrypoint.ErrApprovalRequired, code: codes.PermissionDenied, message: "valid device approval is required"},
		{name: "revision conflict", err: entrypoint.ErrRevisionConflict, code: codes.Aborted, message: "cloud entrypoint scope revision does not match"},
		{name: "read back required", err: entrypoint.ErrReadBackRequired, code: codes.FailedPrecondition, message: "cloud entrypoint approval scope is no longer valid"},
		{name: "unknown", err: errors.New("opaque internal entry failure"), code: codes.Internal, message: "agent persistence operation failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator := &cloudEntryCoordinatorStub{createErr: test.err}
			service := NewCloudControlServiceWithGoals(nil, uuid.NewString(), nil, nil, nil, coordinator)
			ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
			_, err := service.CreateCloudDeploymentEntryPlan(ctx, &agentv1.CreateCloudDeploymentEntryPlanRequest{
				IdempotencyKey: uuid.NewString(), OwnerId: "owner-rpc-test", DeploymentId: uuid.NewString(), ExpectedRevision: 1,
			})
			if status.Code(err) != test.code || status.Convert(err).Message() != test.message || strings.Contains(err.Error(), test.err.Error()) {
				t.Fatalf("code=%s message=%q err=%v", status.Code(err), status.Convert(err).Message(), err)
			}
		})
	}
}

func newCloudEntryRPCFixture(t *testing.T) cloudEntryRPCFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	deadline := now.Add(30 * time.Minute)
	scope := entrypoint.ScopeV1{
		SchemaVersion:   entrypoint.ScopeSchemaV1,
		Kind:            entrypoint.EntryKindALB,
		AgentInstanceID: uuid.NewString(),
		OwnerID:         "owner-rpc-test",
		ConnectionID:    uuid.NewString(),
		Region:          "ap-south-1",
		Worker: entrypoint.WorkerReadBackScopeV1{
			DeploymentID: uuid.NewString(), DeploymentRevision: 9, TaskID: uuid.NewString(), OriginalPlanID: uuid.NewString(),
			OriginalPlanHash: cloudEntryRPCDigest("1"), OriginalApprovalID: uuid.NewString(), WorkerResourceID: uuid.NewString(),
			WorkerResourceRevision: 5, WorkerSpecDigest: cloudEntryRPCDigest("2"), InstanceID: "i-12345678", VPCID: "vpc-12345678",
			SubnetID: "subnet-12345678", SecurityGroupID: "sg-12345678", ExecutionOutcome: entrypoint.WorkerOutcomeSucceeded,
			SucceededAt: now.Add(-3 * time.Second),
			ReadBack:    entrypoint.AWSReadBackV1{Observed: true, Exists: true, State: entrypoint.EC2InstanceRunning, ObservedAt: now.Add(-2 * time.Second), TagDigest: cloudEntryRPCDigest("3")},
			Retention:   entrypoint.RetentionScopeV1{Class: entrypoint.RetentionEphemeral, AutoDestroy: true, DestroyDeadline: deadline},
		},
		Recipe: entrypoint.RecipeHealthBindingV1{RecipeDigest: cloudEntryRPCDigest("4"), HealthContractDigest: cloudEntryRPCDigest("5"), AuthenticationContractDigest: cloudEntryRPCDigest("6")},
		Certificate: entrypoint.CertificateScopeV1{
			CertificateARN: "arn:aws:acm:ap-south-1:000000000000:certificate/" + uuid.NewString(), Region: "ap-south-1", Hostname: "service.example.invalid",
			SubjectAlternativeNames: []string{"service.example.invalid", "*.example.invalid"}, Status: entrypoint.CertificateStatusIssued,
			ReadBackDigest: cloudEntryRPCDigest("7"), ObservedAt: now.Add(-time.Second),
		},
		ALB: entrypoint.ALBScopeV1{
			Scheme: entrypoint.ALBSchemeInternetFacing, ListenerPort: entrypoint.HTTPSPort, ListenerProtocol: entrypoint.ListenerProtocolHTTPS,
			TLSPolicy: entrypoint.TLSPolicyTLS13_2021_06, IngressCIDRs: []string{"0.0.0.0/0"}, TargetProtocol: entrypoint.TargetProtocolHTTP,
			TargetPort: 8080, TargetSource: entrypoint.TargetSourceApprovedWorkerReadBack, WorkerPublicIPv4: false, EIPRequested: false,
			PublicSubnets: []entrypoint.PublicSubnetScopeV1{
				{SubnetID: "subnet-23456789", VPCID: "vpc-12345678", AvailabilityZone: "ap-south-1a", Public: true, ReadBackDigest: cloudEntryRPCDigest("8"), ObservedAt: now.Add(-time.Second)},
				{SubnetID: "subnet-3456789a", VPCID: "vpc-12345678", AvailabilityZone: "ap-south-1b", Public: true, ReadBackDigest: cloudEntryRPCDigest("9"), ObservedAt: now.Add(-time.Second)},
			},
		},
		Health:         entrypoint.HealthRouteScopeV1{Path: "/ready", ExpectedStatusCode: 200, EvidenceDigest: cloudEntryRPCDigest("5"), NoCredentialRoute: true},
		Authentication: entrypoint.AuthenticationScopeV1{Required: true, ContractDigest: cloudEntryRPCDigest("6")},
		Cost: entrypoint.EntryCostScopeV1{
			QuoteID: uuid.NewString(), QuoteDigest: cloudEntryRPCDigest("a"), Currency: "USD", QuotedAt: now.Add(-time.Minute), ValidUntil: now.Add(14 * time.Minute),
			ALBHourlyEstimateMicros: 12000, LCUHourlyEstimateMicros: 9000, EstimatedLCUMilliUnits: 1000, EstimatedEgressMiB: 1024,
			TrafficEstimateMicros: 1000, MaximumLaunchAmountMicros: 30000, AssumptionsDigest: cloudEntryRPCDigest("b"),
		},
		Retention: entrypoint.RetentionScopeV1{Class: entrypoint.RetentionEphemeral, AutoDestroy: true, DestroyDeadline: deadline},
	}
	plan, err := entrypoint.NewPlanV1(uuid.NewString(), 7, entrypoint.PlanReadyForApproval, scope)
	if err != nil {
		t.Fatalf("build valid entry plan: %v", err)
	}
	challenge, err := entrypoint.NewChallengeV1(plan, uuid.NewString(), uuid.NewString(), uuid.NewString(), "device-rpc-test", now, now.Add(4*time.Minute))
	if err != nil {
		t.Fatalf("build valid entry challenge: %v", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test signing key: %v", err)
	}
	payload, err := challenge.SigningPayload()
	if err != nil {
		t.Fatalf("build entry signing payload: %v", err)
	}
	signature := entrypoint.SignatureV1{
		ApprovalID: challenge.ApprovalID, ChallengeID: challenge.ChallengeID, EntryPlanID: challenge.EntryPlanID,
		EntryPlanRevision: challenge.EntryPlanRevision, PlanHash: challenge.PlanHash, ScopeDigest: challenge.ScopeDigest,
		SignerKeyID: challenge.SignerKeyID, ExpiresAt: challenge.ExpiresAt, Signature: ed25519.Sign(privateKey, payload),
	}
	approvedAt := now
	operation := entrypoint.OperationV1{
		Challenge: challenge, Status: entrypoint.StatusApproved, Signature: &signature, Revision: 2,
		CreatedAt: now, UpdatedAt: now, ApprovedAt: &approvedAt,
	}
	if err := operation.Validate(); err != nil {
		t.Fatalf("build valid entry operation: %v", err)
	}
	return cloudEntryRPCFixture{scope: plan.Scope, plan: plan, challenge: challenge, signature: signature, operation: operation}
}

func cloudEntryRPCDraft(t *testing.T) (*agentv1.CloudEntryPlanDraft, entrypoint.DraftV1) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	quotedAt := now.Add(-time.Minute)
	validUntil := now.Add(14 * time.Minute)
	certificateARN := "arn:aws:acm:ap-south-1:000000000000:certificate/" + uuid.NewString()
	quoteID := uuid.NewString()
	draft := &agentv1.CloudEntryPlanDraft{
		Hostname: "requested.example.invalid", CertificateArn: certificateARN,
		PublicSubnetIds: []string{"subnet-fedcba98", "subnet-abcdef12"}, TargetPort: 9090, HealthPath: "/requested-health",
		ExpectedHealthStatusCode: 200, RecipeHealthContractDigest: cloudEntryRPCDigest("c"), RecipeAuthenticationDigest: cloudEntryRPCDigest("d"),
		Cost: &agentv1.CloudEntryCostScope{
			QuoteId: quoteID, QuoteDigest: cloudEntryRPCDigest("e"), Currency: "USD", QuotedAt: timestamppb.New(quotedAt), ValidUntil: timestamppb.New(validUntil),
			AlbHourlyEstimateMicros: 22000, LcuHourlyEstimateMicros: 11000, EstimatedLcuMilliUnits: 2000, EstimatedEgressMib: 2048,
			TrafficEstimateMicros: 2000, MaximumLaunchAmountMicros: 44000, AssumptionsDigest: cloudEntryRPCDigest("f"),
		},
	}
	return draft, entrypoint.DraftV1{
		Hostname: draft.Hostname, CertificateARN: draft.CertificateArn, PublicSubnetIDs: append([]string(nil), draft.PublicSubnetIds...),
		TargetPort: draft.TargetPort, HealthPath: draft.HealthPath, ExpectedHealthStatusCode: draft.ExpectedHealthStatusCode,
		RecipeHealthContractDigest: draft.RecipeHealthContractDigest, RecipeAuthenticationDigest: draft.RecipeAuthenticationDigest,
		Cost: entrypoint.EntryCostScopeV1{
			QuoteID: quoteID, QuoteDigest: cloudEntryRPCDigest("e"), Currency: "USD", QuotedAt: quotedAt, ValidUntil: validUntil,
			ALBHourlyEstimateMicros: 22000, LCUHourlyEstimateMicros: 11000, EstimatedLCUMilliUnits: 2000, EstimatedEgressMiB: 2048,
			TrafficEstimateMicros: 2000, MaximumLaunchAmountMicros: 44000, AssumptionsDigest: cloudEntryRPCDigest("f"),
		},
	}
}

func assertCloudEntryPlanProjection(t *testing.T, got *agentv1.CloudEntryPlan, plan entrypoint.PlanV1) {
	t.Helper()
	hash, err := plan.Hash()
	if err != nil {
		t.Fatal(err)
	}
	want := &agentv1.CloudEntryPlan{
		SchemaVersion: plan.SchemaVersion, EntryPlanId: plan.EntryPlanID, Status: agentv1.CloudEntryPlanStatus_CLOUD_ENTRY_PLAN_STATUS_READY_FOR_APPROVAL,
		Scope: cloudEntryExpectedScope(plan.Scope), ScopeDigest: plan.ScopeDigest, Revision: int64(plan.Revision), PlanHash: hash,
	}
	if !proto.Equal(got, want) {
		t.Fatalf("entry plan projection=%s want=%s", protojson.Format(got), protojson.Format(want))
	}
}

func assertCloudEntryChallengeProjection(t *testing.T, got *agentv1.CloudEntryApprovalChallenge, challenge entrypoint.ChallengeV1, scope entrypoint.ScopeV1) {
	t.Helper()
	want := &agentv1.CloudEntryApprovalChallenge{
		OperationId: challenge.OperationID, ChallengeId: challenge.ChallengeID, ApprovalId: challenge.ApprovalID,
		EntryPlanId: challenge.EntryPlanID, EntryPlanRevision: int64(challenge.EntryPlanRevision), PlanHash: challenge.PlanHash,
		ScopeDigest: challenge.ScopeDigest, SignerKeyId: challenge.SignerKeyID, IssuedAt: timestamppb.New(challenge.IssuedAt),
		ExpiresAt: timestamppb.New(challenge.ExpiresAt), SigningPayloadCbor: challenge.SigningCBOR, Revision: challenge.Revision,
		Scope: cloudEntryExpectedScope(scope),
	}
	if !proto.Equal(got, want) {
		t.Fatalf("entry challenge projection=%s want=%s", protojson.Format(got), protojson.Format(want))
	}
}

func assertCloudEntryOperationProjection(t *testing.T, got *agentv1.CloudEntryOperation, operation entrypoint.OperationV1, plan entrypoint.PlanV1) {
	t.Helper()
	want := &agentv1.CloudEntryOperation{
		OperationId: operation.Challenge.OperationID, OwnerId: plan.Scope.OwnerID, DeploymentId: plan.Scope.Worker.DeploymentID,
		EntryPlanId: operation.Challenge.EntryPlanID, ApprovalId: operation.Challenge.ApprovalID, PlanHash: operation.Challenge.PlanHash,
		ScopeDigest: operation.Challenge.ScopeDigest, Status: agentv1.CloudEntryOperationStatus_CLOUD_ENTRY_OPERATION_STATUS_APPROVED,
		ErrorCode: agentv1.CloudEntryErrorCode_CLOUD_ENTRY_ERROR_CODE_UNSPECIFIED, Revision: operation.Revision,
		CreatedAt: timestamppb.New(operation.CreatedAt), UpdatedAt: timestamppb.New(operation.UpdatedAt),
	}
	if !proto.Equal(got, want) {
		t.Fatalf("entry operation projection=%s want=%s", protojson.Format(got), protojson.Format(want))
	}
}

func cloudEntryExpectedScope(scope entrypoint.ScopeV1) *agentv1.CloudEntryApprovalScope {
	publicSubnets := make([]*agentv1.CloudEntryPublicSubnetScope, 0, len(scope.ALB.PublicSubnets))
	for _, subnet := range scope.ALB.PublicSubnets {
		publicSubnets = append(publicSubnets, &agentv1.CloudEntryPublicSubnetScope{
			SubnetId: subnet.SubnetID, VpcId: subnet.VPCID, AvailabilityZone: subnet.AvailabilityZone, Public: subnet.Public,
			ReadBackDigest: subnet.ReadBackDigest, ObservedAt: timestamppb.New(subnet.ObservedAt),
		})
	}
	return &agentv1.CloudEntryApprovalScope{
		SchemaVersion: scope.SchemaVersion, Kind: agentv1.CloudEntryKind_CLOUD_ENTRY_KIND_ALB, AgentInstanceId: scope.AgentInstanceID,
		OwnerId: scope.OwnerID, ConnectionId: scope.ConnectionID, Region: scope.Region,
		Worker: &agentv1.CloudEntryWorkerReadBackScope{
			DeploymentId: scope.Worker.DeploymentID, DeploymentRevision: scope.Worker.DeploymentRevision, TaskId: scope.Worker.TaskID,
			OriginalPlanId: scope.Worker.OriginalPlanID, OriginalPlanHash: scope.Worker.OriginalPlanHash, OriginalApprovalId: scope.Worker.OriginalApprovalID,
			WorkerResourceId: scope.Worker.WorkerResourceID, WorkerResourceRevision: scope.Worker.WorkerResourceRevision, WorkerSpecDigest: scope.Worker.WorkerSpecDigest,
			InstanceId: scope.Worker.InstanceID, VpcId: scope.Worker.VPCID, SubnetId: scope.Worker.SubnetID, SecurityGroupId: scope.Worker.SecurityGroupID,
			ExecutionOutcome: agentv1.OutcomeStatus_OUTCOME_STATUS_SUCCEEDED, SucceededAt: timestamppb.New(scope.Worker.SucceededAt),
			ReadBack: &agentv1.CloudEntryAWSReadBack{Observed: scope.Worker.ReadBack.Observed, Exists: scope.Worker.ReadBack.Exists,
				State: agentv1.CloudEntryEC2State_CLOUD_ENTRY_EC2_STATE_RUNNING, ObservedAt: timestamppb.New(scope.Worker.ReadBack.ObservedAt), TagDigest: scope.Worker.ReadBack.TagDigest},
			RetentionPolicy: agentv1.RetentionPolicy_RETENTION_POLICY_EPHEMERAL_AUTO_DESTROY, AutoDestroyApproved: scope.Worker.Retention.AutoDestroy,
			DestroyDeadline: timestamppb.New(scope.Worker.Retention.DestroyDeadline),
		},
		Recipe: &agentv1.CloudEntryRecipeHealthBinding{RecipeDigest: scope.Recipe.RecipeDigest, HealthContractDigest: scope.Recipe.HealthContractDigest, AuthenticationContractDigest: scope.Recipe.AuthenticationContractDigest},
		Certificate: &agentv1.CloudEntryCertificateScope{CertificateArn: scope.Certificate.CertificateARN, Region: scope.Certificate.Region, Hostname: scope.Certificate.Hostname,
			SubjectAlternativeNames: append([]string(nil), scope.Certificate.SubjectAlternativeNames...), Status: agentv1.CloudEntryCertificateStatus_CLOUD_ENTRY_CERTIFICATE_STATUS_ISSUED,
			ReadBackDigest: scope.Certificate.ReadBackDigest, ObservedAt: timestamppb.New(scope.Certificate.ObservedAt)},
		Alb: &agentv1.CloudEntryALBScope{Scheme: agentv1.CloudEntryALBScheme_CLOUD_ENTRY_ALB_SCHEME_INTERNET_FACING, ListenerPort: scope.ALB.ListenerPort,
			ListenerProtocol: agentv1.CloudEntryListenerProtocol_CLOUD_ENTRY_LISTENER_PROTOCOL_HTTPS, TlsPolicy: scope.ALB.TLSPolicy,
			IngressCidrs: append([]string(nil), scope.ALB.IngressCIDRs...), TargetProtocol: agentv1.CloudEntryTargetProtocol_CLOUD_ENTRY_TARGET_PROTOCOL_HTTP,
			TargetPort: scope.ALB.TargetPort, TargetSource: agentv1.CloudEntryTargetSource_CLOUD_ENTRY_TARGET_SOURCE_APPROVED_WORKER_READ_BACK,
			PublicSubnets: publicSubnets, WorkerPrivateOnly: true, ElasticIpProhibited: true},
		Health: &agentv1.CloudEntryHealthRouteScope{Path: scope.Health.Path, ExpectedStatusCode: scope.Health.ExpectedStatusCode,
			EvidenceDigest: scope.Health.EvidenceDigest, NoCredentialRoute: scope.Health.NoCredentialRoute},
		Authentication: &agentv1.CloudEntryAuthenticationScope{Required: scope.Authentication.Required, ContractDigest: scope.Authentication.ContractDigest},
		Cost:           cloudEntryExpectedCost(scope.Cost),
		Retention: &agentv1.CloudEntryRetentionScope{RetentionPolicy: agentv1.RetentionPolicy_RETENTION_POLICY_EPHEMERAL_AUTO_DESTROY,
			AutoDestroyApproved: scope.Retention.AutoDestroy, DestroyDeadline: timestamppb.New(scope.Retention.DestroyDeadline)},
	}
}

func cloudEntryExpectedCost(cost entrypoint.EntryCostScopeV1) *agentv1.CloudEntryCostScope {
	return &agentv1.CloudEntryCostScope{
		QuoteId: cost.QuoteID, QuoteDigest: cost.QuoteDigest, Currency: cost.Currency, QuotedAt: timestamppb.New(cost.QuotedAt), ValidUntil: timestamppb.New(cost.ValidUntil),
		AlbHourlyEstimateMicros: cost.ALBHourlyEstimateMicros, LcuHourlyEstimateMicros: cost.LCUHourlyEstimateMicros,
		EstimatedLcuMilliUnits: cost.EstimatedLCUMilliUnits, EstimatedEgressMib: cost.EstimatedEgressMiB,
		TrafficEstimateMicros: cost.TrafficEstimateMicros, MaximumLaunchAmountMicros: cost.MaximumLaunchAmountMicros, AssumptionsDigest: cost.AssumptionsDigest,
	}
}

func cloudEntrySignatureToProto(signature entrypoint.SignatureV1) *agentv1.CloudEntryApprovalSignature {
	return &agentv1.CloudEntryApprovalSignature{
		ApprovalId: signature.ApprovalID, ChallengeId: signature.ChallengeID, EntryPlanId: signature.EntryPlanID,
		EntryPlanRevision: int64(signature.EntryPlanRevision), PlanHash: signature.PlanHash, ScopeDigest: signature.ScopeDigest,
		SignerKeyId: signature.SignerKeyID, ExpiresAt: timestamppb.New(signature.ExpiresAt), Signature: append([]byte(nil), signature.Signature...),
	}
}

func assertCloudEntryProjectionIsDeSensitized(t *testing.T, message proto.Message) {
	t.Helper()
	encoded, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"://", "worker_url", "worker_ip", "vpc_endpoint", "secret_ref", "authorization_header", "request_headers", "response_body"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("entry response leaked %q: %s", forbidden, encoded)
		}
	}
}

func cloudEntryRPCDigest(value string) string {
	return "sha256:" + strings.Repeat(value, 64)
}
