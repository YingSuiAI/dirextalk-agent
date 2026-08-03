package teamorchestration

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamapproval"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
)

const orchestrationTaskID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"

func TestServiceGatesPlanChallengeApprovalAndExecution(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	offers := orchestrationOfferFixture(t, now)
	policy := orchestrationPolicyFixture()
	repository := newOrchestrationRepositoryFixture()
	compiler := &orchestrationCompilerFixture{
		revision: "sha256:" + strings.Repeat("c", 64),
	}
	resolver := &orchestrationPolicyResolverFixture{policy: policy}
	offerVerifier := &orchestrationOfferVerifierFixture{}
	launchBuilder := &orchestrationLaunchAuthorizationBuilderFixture{
		agentInstanceID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
	}
	service, err := NewService(
		compiler,
		resolver,
		repository,
		func() time.Time { return now },
		WithTrustedOfferVerifier(offerVerifier),
		WithTrustedLaunchAuthorizationBuilder(launchBuilder),
	)
	if err != nil {
		t.Fatal(err)
	}
	offerBuilder := &orchestrationOfferBuilderFixture{offers: offers}
	preparation, err := NewPreparationService(service, offerBuilder)
	if err != nil {
		t.Fatal(err)
	}
	scope := task.MutationScope{
		ClientID:     "team-orchestration-test",
		CredentialID: uuid.NewString(),
	}
	request := PreparePlanRequest{
		IdempotencyKey: uuid.NewString(),
		OwnerID:        "owner-team",
		TaskID:         orchestrationTaskID,
		ConnectionID:   offers.ProviderScope().ConnectionID,
		PlanID:         uuid.NewString(),
		Revision:       1,
		GoalDigest:     "sha256:" + strings.Repeat("d", 64),
		TaskInput: orchestrationInputBinding(
			"owner-team",
			orchestrationTaskID,
			"sha256:"+strings.Repeat("d", 64),
		),
		Proposal: orchestrationProposalFixture(),
	}
	planFact, err := preparation.PreparePlan(
		context.Background(),
		scope,
		request,
	)
	if err != nil {
		t.Fatal(err)
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if planFact.Status != PlanReadyForConfirmation ||
		planFact.Plan.PolicyRevision != policyDigest ||
		compiler.compileCalls != 1 ||
		compiler.verifyCalls != 1 ||
		resolver.calls != 1 ||
		offerBuilder.calls != 1 ||
		offerBuilder.ownerID != request.OwnerID ||
		offerBuilder.connectionID != request.ConnectionID ||
		repository.findCalls != 1 ||
		repository.prepareCalls != 1 ||
		repository.prepareKey != request.IdempotencyKey {
		t.Fatalf(
			"prepared=%#v compiler=%d/%d policy=%d offers=%d/%q/%q repository=%d/%d key=%q",
			planFact,
			compiler.compileCalls,
			compiler.verifyCalls,
			resolver.calls,
			offerBuilder.calls,
			offerBuilder.ownerID,
			offerBuilder.connectionID,
			repository.findCalls,
			repository.prepareCalls,
			repository.prepareKey,
		)
	}
	readPlan, err := service.GetPlan(
		context.Background(),
		request.OwnerID,
		request.PlanID,
		request.Revision,
	)
	if err != nil ||
		readPlan.PlanDigest != planFact.PlanDigest ||
		readPlan.RecordRevision != planFact.RecordRevision {
		t.Fatalf("GetPlan() plan=%#v error=%v", readPlan, err)
	}
	replayedPlan, err := preparation.PreparePlan(
		context.Background(),
		scope,
		request,
	)
	if err != nil ||
		replayedPlan.PlanDigest != planFact.PlanDigest ||
		compiler.compileCalls != 1 ||
		compiler.verifyCalls != 1 ||
		resolver.calls != 1 ||
		offerBuilder.calls != 1 ||
		repository.findCalls != 2 ||
		repository.prepareCalls != 1 {
		t.Fatalf(
			"replayed=%#v error=%v compiler=%d/%d policy=%d offers=%d repository=%d/%d",
			replayedPlan,
			err,
			compiler.compileCalls,
			compiler.verifyCalls,
			resolver.calls,
			offerBuilder.calls,
			repository.findCalls,
			repository.prepareCalls,
		)
	}
	changedConnection := request
	changedConnection.ConnectionID = uuid.NewString()
	if _, err := preparation.PreparePlan(
		context.Background(),
		scope,
		changedConnection,
	); !errors.Is(err, ErrFactMismatch) ||
		offerBuilder.calls != 1 ||
		compiler.compileCalls != 1 ||
		repository.prepareCalls != 1 {
		t.Fatalf(
			"changed Connection error=%v offers=%d compiler=%d prepare=%d",
			err,
			offerBuilder.calls,
			compiler.compileCalls,
			repository.prepareCalls,
		)
	}
	if _, err := service.VerifyApprovedPlan(
		context.Background(),
		request.OwnerID,
		request.PlanID,
		1,
	); !errors.Is(err, ErrNotReady) {
		t.Fatalf("unapproved execution verification error=%v", err)
	}

	challengeRequest := ChallengeRequest{
		IdempotencyKey:             uuid.NewString(),
		OwnerID:                    request.OwnerID,
		PlanID:                     request.PlanID,
		PlanRevision:               1,
		ExpectedPlanRecordRevision: 1,
		ApprovalID:                 uuid.NewString(),
		ChallengeID:                uuid.NewString(),
		SignerKeyID:                "team-device-1",
	}
	compiler.verifyErr = teamplan.ErrPolicyChanged
	if _, err := service.CreateChallenge(
		context.Background(),
		scope,
		challengeRequest,
	); !errors.Is(err, teamplan.ErrPolicyChanged) ||
		repository.challengeCalls != 0 {
		t.Fatalf(
			"policy-drift challenge error=%v calls=%d",
			err,
			repository.challengeCalls,
		)
	}
	compiler.verifyErr = nil
	challengeFact, err := service.CreateChallenge(
		context.Background(),
		scope,
		challengeRequest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if challengeFact.Challenge.PolicyRevision != policyDigest ||
		challengeFact.Authorization == nil ||
		launchBuilder.calls != 1 ||
		launchBuilder.approvalID != challengeRequest.ApprovalID ||
		repository.challengeFinds != 1 ||
		repository.challengeCalls != 1 {
		t.Fatalf(
			"challenge=%#v launch=%d/%q finds/calls=%d/%d",
			challengeFact,
			launchBuilder.calls,
			launchBuilder.approvalID,
			repository.challengeFinds,
			repository.challengeCalls,
		)
	}
	now = now.Add(30 * time.Second)
	replayedChallenge, err := service.CreateChallenge(
		context.Background(),
		scope,
		challengeRequest,
	)
	if err != nil ||
		replayedChallenge.Challenge != challengeFact.Challenge ||
		replayedChallenge.Authorization == nil ||
		launchBuilder.calls != 1 ||
		repository.challengeFinds != 2 ||
		repository.challengeCalls != 1 {
		t.Fatalf(
			"replayed challenge=%#v error=%v launch=%d finds/calls=%d/%d",
			replayedChallenge,
			err,
			launchBuilder.calls,
			repository.challengeFinds,
			repository.challengeCalls,
		)
	}
	signature := teamapproval.SignatureV1{
		SchemaVersion:             teamapproval.SignatureSchemaV2,
		ApprovalID:                challengeFact.Challenge.ApprovalID,
		ChallengeID:               challengeFact.Challenge.ChallengeID,
		PlanID:                    challengeFact.Challenge.PlanID,
		PlanRevision:              challengeFact.Challenge.PlanRevision,
		PlanDigest:                challengeFact.Challenge.PlanDigest,
		LaunchAuthorizationID:     challengeFact.Challenge.LaunchAuthorizationID,
		LaunchAuthorizationDigest: challengeFact.Challenge.LaunchAuthorizationDigest,
		SignerKeyID:               challengeFact.Challenge.SignerKeyID,
		SignatureBase64URL: strings.Repeat(
			"A",
			86,
		),
	}
	resolver.policy.FixedWorkerOverheadMicros++
	if _, err := service.ApprovePlan(
		context.Background(),
		scope,
		ApprovalRequest{
			IdempotencyKey:                  uuid.NewString(),
			OwnerID:                         request.OwnerID,
			ExpectedPlanRecordRevision:      1,
			ExpectedChallengeRecordRevision: 1,
			Signature:                       signature,
		},
	); !errors.Is(err, teamplan.ErrPolicyChanged) ||
		repository.approvalCalls != 0 {
		t.Fatalf(
			"changed-policy approval error=%v calls=%d",
			err,
			repository.approvalCalls,
		)
	}
	resolver.policy = policy
	approvalRequest := ApprovalRequest{
		IdempotencyKey:                  uuid.NewString(),
		OwnerID:                         request.OwnerID,
		ExpectedPlanRecordRevision:      1,
		ExpectedChallengeRecordRevision: 1,
		Signature:                       signature,
	}
	approved, err := service.ApprovePlan(
		context.Background(),
		scope,
		approvalRequest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != PlanApproved ||
		approved.RecordRevision != 2 ||
		repository.approvalCalls != 1 {
		t.Fatalf("approved=%#v calls=%d", approved, repository.approvalCalls)
	}
	resolver.policy.FixedWorkerOverheadMicros++
	offerVerifier.err = teamplan.ErrPricingChanged
	replayedApproval, err := service.ApprovePlan(
		context.Background(),
		scope,
		approvalRequest,
	)
	if err != nil ||
		replayedApproval.Status != PlanApproved ||
		replayedApproval.RecordRevision != approved.RecordRevision ||
		repository.approvalCalls != 1 {
		t.Fatalf(
			"approval replay=%#v error=%v calls=%d",
			replayedApproval,
			err,
			repository.approvalCalls,
		)
	}
	resolver.policy = policy
	offerVerifier.err = nil
	validApproval := repository.approval
	repository.approval.Signature.PlanDigest = "sha256:" +
		strings.Repeat("f", 64)
	if _, err := service.VerifyApprovedPlan(
		context.Background(),
		request.OwnerID,
		request.PlanID,
		1,
	); !errors.Is(err, ErrFactMismatch) {
		t.Fatalf("substituted approval verification error=%v", err)
	}
	repository.approval = validApproval
	repository.connectionErr = ErrFactMismatch
	if _, err := service.VerifyApprovedPlan(
		context.Background(),
		request.OwnerID,
		request.PlanID,
		1,
	); !errors.Is(err, ErrFactMismatch) {
		t.Fatalf("changed Connection verification error=%v", err)
	}
	repository.connectionErr = nil
	offerVerifier.err = teamplan.ErrPricingChanged
	if _, err := service.VerifyApprovedPlan(
		context.Background(),
		request.OwnerID,
		request.PlanID,
		1,
	); !errors.Is(err, teamplan.ErrPricingChanged) {
		t.Fatalf("changed offer configuration error=%v", err)
	}
	materializationAuthorization, err :=
		service.GetApprovedPlanForMaterialization(
			context.Background(),
			request.OwnerID,
			request.PlanID,
			1,
		)
	if err != nil ||
		materializationAuthorization.Plan.PlanDigest !=
			approved.PlanDigest ||
		materializationAuthorization.Approval.Signature.ApprovalID !=
			challengeFact.Challenge.ApprovalID {
		t.Fatalf(
			"historical materialization authorization=%#v error=%v",
			materializationAuthorization,
			err,
		)
	}
	offerVerifier.err = nil
	verified, err := service.VerifyApprovedPlan(
		context.Background(),
		request.OwnerID,
		request.PlanID,
		1,
	)
	if err != nil ||
		verified.PlanDigest != approved.PlanDigest {
		t.Fatalf("execution verification=%#v error=%v", verified, err)
	}
	authorization, err := service.VerifyApprovedPlanForExecution(
		context.Background(),
		request.OwnerID,
		request.PlanID,
		1,
	)
	if err != nil ||
		authorization.Plan.PlanDigest != approved.PlanDigest ||
		authorization.Approval.Signature.ApprovalID !=
			challengeFact.Challenge.ApprovalID {
		t.Fatalf(
			"execution authorization=%#v error=%v",
			authorization,
			err,
		)
	}
}

func TestPreparationServiceRejectsOfferForAnotherConnection(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	offers := orchestrationOfferFixture(t, now)
	compiler := &orchestrationCompilerFixture{
		revision: "sha256:" + strings.Repeat("c", 64),
	}
	repository := newOrchestrationRepositoryFixture()
	plans, err := NewService(
		compiler,
		&orchestrationPolicyResolverFixture{
			policy: orchestrationPolicyFixture(),
		},
		repository,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	builder := &orchestrationOfferBuilderFixture{offers: offers}
	service, err := NewPreparationService(plans, builder)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.PreparePlan(
		context.Background(),
		task.MutationScope{
			ClientID:     "team-orchestration-test",
			CredentialID: uuid.NewString(),
		},
		PreparePlanRequest{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        "owner-team",
			TaskID:         orchestrationTaskID,
			ConnectionID:   uuid.NewString(),
			PlanID:         uuid.NewString(),
			Revision:       1,
			GoalDigest:     "sha256:" + strings.Repeat("d", 64),
			TaskInput: orchestrationInputBinding(
				"owner-team",
				orchestrationTaskID,
				"sha256:"+strings.Repeat("d", 64),
			),
			Proposal: orchestrationProposalFixture(),
		},
	)
	if !errors.Is(err, ErrFactMismatch) ||
		builder.calls != 1 ||
		compiler.compileCalls != 0 ||
		repository.prepareCalls != 0 {
		t.Fatalf(
			"substituted offer error=%v builder=%d compile=%d prepare=%d",
			err,
			builder.calls,
			compiler.compileCalls,
			repository.prepareCalls,
		)
	}
}

func TestPreparationServiceRejectsInvalidProposalBeforeOfferRead(
	t *testing.T,
) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	offers := orchestrationOfferFixture(t, now)
	repository := newOrchestrationRepositoryFixture()
	resolver := &orchestrationPolicyResolverFixture{
		policy: orchestrationPolicyFixture(),
	}
	plans, err := NewService(
		&orchestrationCompilerFixture{
			revision: "sha256:" + strings.Repeat("c", 64),
		},
		resolver,
		repository,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	builder := &orchestrationOfferBuilderFixture{offers: offers}
	preparation, err := NewPreparationService(plans, builder)
	if err != nil {
		t.Fatal(err)
	}
	proposal := orchestrationProposalFixture()
	proposal.Roles[0].Tokens = teamplan.TokenEstimate{}
	_, err = preparation.PreparePlan(
		context.Background(),
		task.MutationScope{
			ClientID:     "team-orchestration-test",
			CredentialID: uuid.NewString(),
		},
		PreparePlanRequest{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        "owner-team",
			TaskID:         orchestrationTaskID,
			ConnectionID:   offers.ProviderScope().ConnectionID,
			PlanID:         uuid.NewString(),
			Revision:       1,
			GoalDigest:     "sha256:" + strings.Repeat("d", 64),
			TaskInput: orchestrationInputBinding(
				"owner-team",
				orchestrationTaskID,
				"sha256:"+strings.Repeat("d", 64),
			),
			Proposal: proposal,
		},
	)
	if !errors.Is(err, teamplan.ErrInvalid) ||
		builder.calls != 0 ||
		repository.prepareCalls != 0 ||
		resolver.calls != 1 {
		t.Fatalf(
			"invalid proposal error=%v builder=%d prepare=%d policy=%d",
			err,
			builder.calls,
			repository.prepareCalls,
			resolver.calls,
		)
	}
}

func TestPreparationServiceRejectsInvalidIdentityBeforeRepositoryOrOfferRead(
	t *testing.T,
) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	offers := orchestrationOfferFixture(t, now)
	base := PreparePlanRequest{
		IdempotencyKey: uuid.NewString(),
		OwnerID:        "owner-team",
		TaskID:         orchestrationTaskID,
		ConnectionID:   offers.ProviderScope().ConnectionID,
		PlanID:         uuid.NewString(),
		Revision:       1,
		GoalDigest:     "sha256:" + strings.Repeat("d", 64),
		TaskInput: orchestrationInputBinding(
			"owner-team",
			orchestrationTaskID,
			"sha256:"+strings.Repeat("d", 64),
		),
		Proposal: orchestrationProposalFixture(),
	}
	tests := []struct {
		name   string
		mutate func(*PreparePlanRequest)
	}{
		{
			name: "idempotency key",
			mutate: func(request *PreparePlanRequest) {
				request.IdempotencyKey = "not-a-uuid"
			},
		},
		{
			name: "owner",
			mutate: func(request *PreparePlanRequest) {
				request.OwnerID = "owner\nteam"
			},
		},
		{
			name: "task",
			mutate: func(request *PreparePlanRequest) {
				request.TaskID = "not-a-uuid"
			},
		},
		{
			name: "connection",
			mutate: func(request *PreparePlanRequest) {
				request.ConnectionID = "not-a-uuid"
			},
		},
		{
			name: "plan",
			mutate: func(request *PreparePlanRequest) {
				request.PlanID = "not-a-uuid"
			},
		},
		{
			name: "zero revision",
			mutate: func(request *PreparePlanRequest) {
				request.Revision = 0
			},
		},
		{
			name: "revision overflow",
			mutate: func(request *PreparePlanRequest) {
				request.Revision = uint64(1) << 63
			},
		},
		{
			name: "first revision predecessor",
			mutate: func(request *PreparePlanRequest) {
				request.ExpectedPreviousRevision = 1
			},
		},
		{
			name: "later revision predecessor",
			mutate: func(request *PreparePlanRequest) {
				request.Revision = 2
			},
		},
		{
			name: "goal digest",
			mutate: func(request *PreparePlanRequest) {
				request.GoalDigest = "sha256:not-a-digest"
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			repository := newOrchestrationRepositoryFixture()
			resolver := &orchestrationPolicyResolverFixture{
				policy: orchestrationPolicyFixture(),
			}
			compiler := &orchestrationCompilerFixture{
				revision: "sha256:" + strings.Repeat("c", 64),
			}
			plans, err := NewService(
				compiler,
				resolver,
				repository,
				func() time.Time { return now },
			)
			if err != nil {
				t.Fatal(err)
			}
			builder := &orchestrationOfferBuilderFixture{offers: offers}
			preparation, err := NewPreparationService(plans, builder)
			if err != nil {
				t.Fatal(err)
			}
			request := base
			test.mutate(&request)
			_, err = preparation.PreparePlan(
				context.Background(),
				task.MutationScope{
					ClientID:     "team-orchestration-test",
					CredentialID: uuid.NewString(),
				},
				request,
			)
			if !errors.Is(err, ErrInvalid) ||
				repository.findCalls != 0 ||
				repository.prepareCalls != 0 ||
				resolver.calls != 0 ||
				builder.calls != 0 ||
				compiler.compileCalls != 0 {
				t.Fatalf(
					"error=%v repository=%d/%d policy=%d offers=%d compile=%d",
					err,
					repository.findCalls,
					repository.prepareCalls,
					resolver.calls,
					builder.calls,
					compiler.compileCalls,
				)
			}
		})
	}
}

func TestServiceGetPlanRejectsInvalidIdentityBeforeRepositoryRead(
	t *testing.T,
) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	repository := newOrchestrationRepositoryFixture()
	service, err := NewService(
		&orchestrationCompilerFixture{
			revision: "sha256:" + strings.Repeat("c", 64),
		},
		&orchestrationPolicyResolverFixture{
			policy: orchestrationPolicyFixture(),
		},
		repository,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name         string
		ownerID      string
		planID       string
		planRevision uint64
	}{
		{
			name:         "owner",
			ownerID:      "owner\nteam",
			planID:       uuid.NewString(),
			planRevision: 1,
		},
		{
			name:         "plan",
			ownerID:      "owner-team",
			planID:       "not-a-uuid",
			planRevision: 1,
		},
		{
			name:         "zero revision",
			ownerID:      "owner-team",
			planID:       uuid.NewString(),
			planRevision: 0,
		},
		{
			name:         "revision overflow",
			ownerID:      "owner-team",
			planID:       uuid.NewString(),
			planRevision: uint64(1) << 63,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			_, err := service.GetPlan(
				context.Background(),
				test.ownerID,
				test.planID,
				test.planRevision,
			)
			if !errors.Is(err, ErrInvalid) || repository.getCalls != 0 {
				t.Fatalf(
					"GetPlan() error=%v repository calls=%d",
					err,
					repository.getCalls,
				)
			}
		})
	}
}

func TestServiceRejectsInvalidChallengeBeforeCurrentFactReads(
	t *testing.T,
) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	base := ChallengeRequest{
		IdempotencyKey:             uuid.NewString(),
		OwnerID:                    "owner-team",
		PlanID:                     uuid.NewString(),
		PlanRevision:               1,
		ExpectedPlanRecordRevision: 1,
		ApprovalID:                 uuid.NewString(),
		ChallengeID:                uuid.NewString(),
		SignerKeyID:                "owner-device-1",
	}
	tests := []struct {
		name   string
		mutate func(*ChallengeRequest)
	}{
		{
			name: "signer",
			mutate: func(request *ChallengeRequest) {
				request.SignerKeyID = "not a key"
			},
		},
		{
			name: "approval",
			mutate: func(request *ChallengeRequest) {
				request.ApprovalID = "not-a-uuid"
			},
		},
		{
			name: "plan revision overflow",
			mutate: func(request *ChallengeRequest) {
				request.PlanRevision = uint64(1) << 63
			},
		},
		{
			name: "record revision overflow",
			mutate: func(request *ChallengeRequest) {
				request.ExpectedPlanRecordRevision = uint64(1) << 63
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			repository := newOrchestrationRepositoryFixture()
			resolver := &orchestrationPolicyResolverFixture{
				policy: orchestrationPolicyFixture(),
			}
			verifier := &orchestrationOfferVerifierFixture{}
			service, err := NewService(
				&orchestrationCompilerFixture{
					revision: "sha256:" + strings.Repeat("c", 64),
				},
				resolver,
				repository,
				func() time.Time { return now },
				WithTrustedOfferVerifier(verifier),
			)
			if err != nil {
				t.Fatal(err)
			}
			request := base
			test.mutate(&request)
			_, err = service.CreateChallenge(
				context.Background(),
				task.MutationScope{
					ClientID:     "team-orchestration-test",
					CredentialID: uuid.NewString(),
				},
				request,
			)
			if !errors.Is(err, ErrInvalid) ||
				resolver.calls != 0 ||
				repository.getCalls != 0 ||
				repository.challengeCalls != 0 ||
				verifier.calls != 0 {
				t.Fatalf(
					"error=%v policy=%d plan=%d challenge=%d offer=%d",
					err,
					resolver.calls,
					repository.getCalls,
					repository.challengeCalls,
					verifier.calls,
				)
			}
		})
	}
}

func TestServiceRejectsInvalidApprovalBeforeCurrentFactReads(
	t *testing.T,
) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	base := ApprovalRequest{
		IdempotencyKey:                  uuid.NewString(),
		OwnerID:                         "owner-team",
		ExpectedPlanRecordRevision:      1,
		ExpectedChallengeRecordRevision: 1,
		Signature: teamapproval.SignatureV1{
			SchemaVersion:      teamapproval.SignatureSchemaV1,
			ApprovalID:         uuid.NewString(),
			ChallengeID:        uuid.NewString(),
			PlanID:             uuid.NewString(),
			PlanRevision:       1,
			PlanDigest:         "sha256:" + strings.Repeat("d", 64),
			SignerKeyID:        "owner-device-1",
			SignatureBase64URL: base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
		},
	}
	tests := []struct {
		name   string
		mutate func(*ApprovalRequest)
	}{
		{
			name: "plan digest",
			mutate: func(request *ApprovalRequest) {
				request.Signature.PlanDigest = "sha256:not-a-digest"
			},
		},
		{
			name: "signature encoding",
			mutate: func(request *ApprovalRequest) {
				request.Signature.SignatureBase64URL = "not-a-signature"
			},
		},
		{
			name: "plan revision overflow",
			mutate: func(request *ApprovalRequest) {
				request.Signature.PlanRevision = uint64(1) << 63
			},
		},
		{
			name: "challenge record revision overflow",
			mutate: func(request *ApprovalRequest) {
				request.ExpectedChallengeRecordRevision = uint64(1) << 63
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			repository := newOrchestrationRepositoryFixture()
			resolver := &orchestrationPolicyResolverFixture{
				policy: orchestrationPolicyFixture(),
			}
			verifier := &orchestrationOfferVerifierFixture{}
			service, err := NewService(
				&orchestrationCompilerFixture{
					revision: "sha256:" + strings.Repeat("c", 64),
				},
				resolver,
				repository,
				func() time.Time { return now },
				WithTrustedOfferVerifier(verifier),
			)
			if err != nil {
				t.Fatal(err)
			}
			request := base
			test.mutate(&request)
			_, err = service.ApprovePlan(
				context.Background(),
				task.MutationScope{
					ClientID:     "team-orchestration-test",
					CredentialID: uuid.NewString(),
				},
				request,
			)
			if !errors.Is(err, ErrInvalid) ||
				resolver.calls != 0 ||
				repository.getCalls != 0 ||
				repository.approvalCalls != 0 ||
				verifier.calls != 0 {
				t.Fatalf(
					"error=%v policy=%d plan=%d approval=%d offer=%d",
					err,
					resolver.calls,
					repository.getCalls,
					repository.approvalCalls,
					verifier.calls,
				)
			}
		})
	}
}

func TestServiceFailsClosedWithoutCurrentOfferVerifier(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	offers := orchestrationOfferFixture(t, now)
	repository := newOrchestrationRepositoryFixture()
	service, err := NewService(
		&orchestrationCompilerFixture{
			revision: "sha256:" + strings.Repeat("c", 64),
		},
		&orchestrationPolicyResolverFixture{
			policy: orchestrationPolicyFixture(),
		},
		repository,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := NewPreparationService(
		service,
		&orchestrationOfferBuilderFixture{offers: offers},
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := task.MutationScope{
		ClientID:     "team-orchestration-test",
		CredentialID: uuid.NewString(),
	}
	request := PreparePlanRequest{
		IdempotencyKey: uuid.NewString(),
		OwnerID:        "owner-team",
		TaskID:         orchestrationTaskID,
		ConnectionID:   offers.ProviderScope().ConnectionID,
		PlanID:         uuid.NewString(),
		Revision:       1,
		GoalDigest:     "sha256:" + strings.Repeat("d", 64),
		TaskInput: orchestrationInputBinding(
			"owner-team",
			orchestrationTaskID,
			"sha256:"+strings.Repeat("d", 64),
		),
		Proposal: orchestrationProposalFixture(),
	}
	if _, err := preparation.PreparePlan(
		context.Background(),
		scope,
		request,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateChallenge(
		context.Background(),
		scope,
		ChallengeRequest{
			IdempotencyKey:             uuid.NewString(),
			OwnerID:                    request.OwnerID,
			PlanID:                     request.PlanID,
			PlanRevision:               request.Revision,
			ExpectedPlanRecordRevision: 1,
			ApprovalID:                 uuid.NewString(),
			ChallengeID:                uuid.NewString(),
			SignerKeyID:                "team-device-1",
		},
	); !errors.Is(err, ErrOfferVerificationUnavailable) ||
		repository.challengeCalls != 0 {
		t.Fatalf(
			"CreateChallenge() error=%v calls=%d",
			err,
			repository.challengeCalls,
		)
	}
}

func TestPreparePlanRejectsRepositoryFactSubstitution(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	repository := newOrchestrationRepositoryFixture()
	repository.tamperPlan = true
	service, err := NewService(
		&orchestrationCompilerFixture{
			revision: "sha256:" + strings.Repeat("c", 64),
		},
		&orchestrationPolicyResolverFixture{
			policy: orchestrationPolicyFixture(),
		},
		repository,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	offers := orchestrationOfferFixture(t, now)
	preparation, err := NewPreparationService(
		service,
		&orchestrationOfferBuilderFixture{offers: offers},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = preparation.PreparePlan(
		context.Background(),
		task.MutationScope{
			ClientID:     "team-orchestration-test",
			CredentialID: uuid.NewString(),
		},
		PreparePlanRequest{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        "owner-team",
			TaskID:         orchestrationTaskID,
			ConnectionID:   offers.ProviderScope().ConnectionID,
			PlanID:         uuid.NewString(),
			Revision:       1,
			GoalDigest:     "sha256:" + strings.Repeat("d", 64),
			TaskInput: orchestrationInputBinding(
				"owner-team",
				orchestrationTaskID,
				"sha256:"+strings.Repeat("d", 64),
			),
			Proposal: orchestrationProposalFixture(),
		},
	)
	if !errors.Is(err, ErrFactMismatch) {
		t.Fatalf("PreparePlan() error = %v, want ErrFactMismatch", err)
	}
}

type orchestrationCompilerFixture struct {
	revision     string
	compileCalls int
	verifyCalls  int
	verifyErr    error
}

func (compiler *orchestrationCompilerFixture) CatalogRevision() string {
	return compiler.revision
}

func (compiler *orchestrationCompilerFixture) Compile(
	request teamplan.CatalogCompileRequest,
) (teamplan.Plan, error) {
	compiler.compileCalls++
	return orchestrationPlanFixture(request, compiler.revision)
}

func (compiler *orchestrationCompilerFixture) VerifyPlan(
	plan teamplan.Plan,
	offers *teamplan.OfferSnapshot,
	policy teamplan.Policy,
	now time.Time,
) error {
	compiler.verifyCalls++
	if compiler.verifyErr != nil {
		return compiler.verifyErr
	}
	digest, err := policy.Digest()
	if err != nil {
		return err
	}
	if plan.PolicyRevision != digest {
		return teamplan.ErrPolicyChanged
	}
	if offers == nil ||
		plan.CatalogRevision != compiler.revision ||
		plan.PricingSnapshotDigest != offers.Digest() ||
		now.IsZero() {
		return ErrFactMismatch
	}
	return nil
}

type orchestrationPolicyResolverFixture struct {
	policy teamplan.Policy
	calls  int
}

func (resolver *orchestrationPolicyResolverFixture) ResolveTeamPolicy(
	_ context.Context,
	_ string,
) (teamplan.Policy, error) {
	resolver.calls++
	return resolver.policy, nil
}

type orchestrationRepositoryFixture struct {
	offer           OfferFact
	plan            PlanFact
	prepareKey      string
	connectionID    string
	findCalls       int
	getCalls        int
	prepareCalls    int
	challengeFinds  int
	challengeCalls  int
	approvalCalls   int
	approvalFinds   int
	connectionCalls int
	connectionErr   error
	tamperPlan      bool
	approval        ApprovalFact
	authorization   *teamlaunch.AuthorizationV1
	challengeKey    string
	challengeFact   ChallengeFact
	approvalKey     string
	approvedPlan    PlanFact
}

func (repository *orchestrationRepositoryFixture) VerifyConnectionScope(
	_ context.Context,
	ownerID string,
	scope teamplan.ProviderScope,
	region string,
) error {
	repository.connectionCalls++
	if repository.connectionErr != nil {
		return repository.connectionErr
	}
	if ownerID != repository.plan.Plan.OwnerID ||
		scope != repository.plan.Plan.ProviderScope ||
		region != repository.plan.Plan.Region {
		return ErrFactMismatch
	}
	return nil
}

func newOrchestrationRepositoryFixture() *orchestrationRepositoryFixture {
	return &orchestrationRepositoryFixture{}
}

func (repository *orchestrationRepositoryFixture) FindPreparedPlan(
	_ context.Context,
	_ task.MutationScope,
	command FindPreparedPlanCommand,
) (PreparedPlanFact, bool, error) {
	repository.findCalls++
	if repository.plan.RecordRevision == 0 {
		return PreparedPlanFact{}, false, nil
	}
	if command.IdempotencyKey != repository.prepareKey ||
		command.Intent.OwnerID != repository.plan.Plan.OwnerID ||
		command.Intent.ConnectionID != repository.connectionID ||
		command.Intent.PlanID != repository.plan.Plan.PlanID ||
		command.Intent.Revision != repository.plan.Plan.Revision {
		return PreparedPlanFact{}, false, ErrFactMismatch
	}
	return PreparedPlanFact{
		Offer:    repository.offer,
		Plan:     repository.plan,
		Replayed: true,
	}, true, nil
}

func (repository *orchestrationRepositoryFixture) PersistPreparedPlan(
	_ context.Context,
	_ task.MutationScope,
	command PersistPreparedPlanCommand,
) (PreparedPlanFact, error) {
	repository.prepareCalls++
	repository.prepareKey = command.IdempotencyKey
	repository.connectionID = command.Intent.ConnectionID
	repository.offer = OfferFact{
		OwnerID:  command.Intent.OwnerID,
		Document: command.Offers.Document(),
		Digest:   command.Offers.Digest(),
		CreatedAt: command.Offers.
			CapturedAt(),
	}
	digest, err := command.Plan.Digest()
	if err != nil {
		return PreparedPlanFact{}, err
	}
	repository.plan = PlanFact{
		TaskID:         command.Intent.TaskID,
		Plan:           command.Plan,
		PlanDigest:     digest,
		Status:         PlanReadyForConfirmation,
		RecordRevision: 1,
		CreatedAt:      command.Plan.QuotedAt,
		UpdatedAt:      command.Plan.QuotedAt,
	}
	result := repository.plan
	if repository.tamperPlan {
		result.Plan.Assignments = append(
			[]teamplan.WorkerAssignment(nil),
			result.Plan.Assignments...,
		)
		result.Plan.Assignments[0].Objective = "substituted objective"
	}
	return PreparedPlanFact{
		Offer: repository.offer,
		Plan:  result,
	}, nil
}

type orchestrationOfferBuilderFixture struct {
	offers       *teamplan.OfferSnapshot
	err          error
	calls        int
	ownerID      string
	connectionID string
}

type orchestrationLaunchAuthorizationBuilderFixture struct {
	agentInstanceID string
	err             error
	calls           int
	approvalID      string
}

type orchestrationOfferVerifierFixture struct {
	err   error
	calls int
}

func (verifier *orchestrationOfferVerifierFixture) VerifyCurrentOffer(
	_ context.Context,
	_ string,
	_ *teamplan.OfferSnapshot,
) error {
	verifier.calls++
	return verifier.err
}

func (builder *orchestrationOfferBuilderFixture) BuildForConnection(
	_ context.Context,
	ownerID,
	connectionID string,
) (*teamplan.OfferSnapshot, error) {
	builder.calls++
	builder.ownerID = ownerID
	builder.connectionID = connectionID
	return builder.offers, builder.err
}

func (builder *orchestrationLaunchAuthorizationBuilderFixture) BuildForPlan(
	_ context.Context,
	plan teamplan.Plan,
	approvalID string,
	issuedAt time.Time,
) (teamlaunch.AuthorizationV1, error) {
	builder.calls++
	builder.approvalID = approvalID
	if builder.err != nil {
		return teamlaunch.AuthorizationV1{}, builder.err
	}
	return orchestrationLaunchAuthorizationFixture(
		plan,
		builder.agentInstanceID,
		approvalID,
		issuedAt,
	)
}

func (repository *orchestrationRepositoryFixture) GetOffer(
	_ context.Context,
	ownerID,
	snapshotID string,
) (OfferFact, error) {
	if repository.offer.OwnerID != ownerID ||
		repository.offer.Document.SnapshotID != snapshotID {
		return OfferFact{}, ErrFactMismatch
	}
	return repository.offer, nil
}

func (repository *orchestrationRepositoryFixture) GetPlan(
	_ context.Context,
	ownerID,
	planID string,
	planRevision uint64,
) (PlanFact, error) {
	repository.getCalls++
	if repository.plan.Plan.OwnerID != ownerID ||
		repository.plan.Plan.PlanID != planID ||
		repository.plan.Plan.Revision != planRevision {
		return PlanFact{}, ErrFactMismatch
	}
	return repository.plan, nil
}

func (repository *orchestrationRepositoryFixture) FindChallenge(
	_ context.Context,
	_ task.MutationScope,
	command FindChallengeCommand,
) (ChallengeFact, bool, error) {
	repository.challengeFinds++
	if repository.challengeKey == "" {
		return ChallengeFact{}, false, nil
	}
	challenge := repository.challengeFact.Challenge
	if command.IdempotencyKey != repository.challengeKey ||
		command.OwnerID != challenge.OwnerID ||
		command.PlanID != challenge.PlanID ||
		command.PlanRevision != challenge.PlanRevision ||
		command.ExpectedPlanRecordRevision !=
			repository.plan.RecordRevision ||
		command.ApprovalID != challenge.ApprovalID ||
		command.ChallengeID != challenge.ChallengeID ||
		command.SignerKeyID != challenge.SignerKeyID {
		return ChallengeFact{}, false, ErrFactMismatch
	}
	fact := repository.challengeFact
	if fact.Authorization != nil {
		authorization := *fact.Authorization
		fact.Authorization = &authorization
	}
	return fact, true, nil
}

func (repository *orchestrationRepositoryFixture) PersistChallenge(
	_ context.Context,
	_ task.MutationScope,
	command PersistChallengeCommand,
) (ChallengeFact, error) {
	repository.challengeCalls++
	authorization := command.Authorization
	challenge, err := teamapproval.NewChallengeV2(
		repository.plan.Plan,
		authorization,
		authorization.AgentInstanceID,
		command.ApprovalID,
		command.ChallengeID,
		command.SignerKeyID,
		authorization.LaunchNotBefore,
	)
	if err != nil {
		return ChallengeFact{}, err
	}
	repository.authorization = &authorization
	repository.challengeKey = command.IdempotencyKey
	repository.challengeFact = ChallengeFact{
		Challenge:      challenge,
		Authorization:  &authorization,
		RecordRevision: 1,
		CreatedAt:      challenge.IssuedAt,
		UpdatedAt:      challenge.IssuedAt,
	}
	return repository.challengeFact, nil
}

func (repository *orchestrationRepositoryFixture) PersistApproval(
	_ context.Context,
	_ task.MutationScope,
	command PersistApprovalCommand,
) (PlanFact, error) {
	repository.approvalCalls++
	repository.approvalKey = command.IdempotencyKey
	var authorization *teamlaunch.AuthorizationV1
	if repository.authorization != nil {
		value := *repository.authorization
		authorization = &value
	}
	repository.approval = ApprovalFact{
		Signature:     command.Signature,
		Authorization: authorization,
		ApprovedAt:    repository.plan.Plan.QuotedAt.Add(2 * time.Minute),
		CreatedAt:     repository.plan.Plan.QuotedAt.Add(2 * time.Minute),
	}
	repository.plan.Status = PlanApproved
	repository.plan.RecordRevision++
	repository.plan.UpdatedAt = repository.plan.UpdatedAt.Add(time.Second)
	repository.approvedPlan = repository.plan
	return repository.plan, nil
}

func (repository *orchestrationRepositoryFixture) FindApproval(
	_ context.Context,
	_ task.MutationScope,
	command PersistApprovalCommand,
) (PlanFact, bool, error) {
	repository.approvalFinds++
	if repository.approvalKey == "" ||
		command.IdempotencyKey != repository.approvalKey {
		return PlanFact{}, false, nil
	}
	if command.Signature != repository.approval.Signature ||
		command.OwnerID != repository.approvedPlan.Plan.OwnerID {
		return PlanFact{}, false, ErrFactMismatch
	}
	return repository.approvedPlan, true, nil
}

func (repository *orchestrationRepositoryFixture) GetApprovalForPlan(
	_ context.Context,
	ownerID,
	planID string,
	planRevision uint64,
) (ApprovalFact, error) {
	if repository.plan.Plan.OwnerID != ownerID ||
		repository.approval.Signature.PlanID != planID ||
		repository.approval.Signature.PlanRevision != planRevision {
		return ApprovalFact{}, ErrFactMismatch
	}
	return repository.approval, nil
}

func orchestrationLaunchAuthorizationFixture(
	plan teamplan.Plan,
	agentInstanceID,
	approvalID string,
	issuedAt time.Time,
) (teamlaunch.AuthorizationV1, error) {
	planDigest, err := plan.Digest()
	if err != nil {
		return teamlaunch.AuthorizationV1{}, err
	}
	authorizationID, err := teamlaunch.AuthorizationID(
		plan.PlanID,
		plan.Revision,
		approvalID,
	)
	if err != nil {
		return teamlaunch.AuthorizationV1{}, err
	}
	foundation, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{
		AgentInstanceID: agentInstanceID,
		Partition:       "aws",
		AccountID:       plan.ProviderScope.AccountID,
		Region:          plan.Region,
	})
	if err != nil {
		return teamlaunch.AuthorizationV1{}, err
	}
	kmsAlias, err := awsfoundation.KMSAliasForAgent(agentInstanceID)
	if err != nil {
		return teamlaunch.AuthorizationV1{}, err
	}
	maximumCosts := make(
		map[string]uint64,
		len(plan.Cost.Roles),
	)
	for _, cost := range plan.Cost.Roles {
		maximumCosts[cost.RoleID] = cost.TotalMaximumMicros
	}
	roles := make(
		[]teamlaunch.RoleLaunchV1,
		0,
		len(plan.Assignments),
	)
	for _, assignment := range plan.Assignments {
		maximumCost, found := maximumCosts[assignment.RoleID]
		if !found {
			return teamlaunch.AuthorizationV1{}, teamlaunch.ErrInvalid
		}
		roles = append(roles, teamlaunch.RoleLaunchV1{
			RoleID:                    assignment.RoleID,
			RuntimeReleaseID:          assignment.RuntimeReleaseID,
			RuntimeImageDigest:        assignment.RuntimeImageDigest,
			RuntimeInstallationDigest: "sha256:" + strings.Repeat("6", 64),
			RuntimeExecutableDigest:   "sha256:" + strings.Repeat("7", 64),
			ComputeOfferID:            assignment.ComputeOfferID,
			InstanceType:              assignment.InstanceType,
			Architecture:              assignment.Resources.Arch,
			VCPU:                      assignment.Resources.VCPU,
			MemoryMiB:                 assignment.Resources.MemoryMiB,
			PurchaseOption:            teamlaunch.PurchaseOnDemand,
			InstanceProfileName:       foundation.WorkerProfileName,
			EBSOptimized:              true,
			RequireIMDSv2:             true,
			MetadataResponseHopLimit:  1,
			ShutdownBehavior:          teamlaunch.ShutdownTerminate,
			RootStorage: teamlaunch.RootStorageV1{
				DeviceName:          "/dev/sda1",
				SizeGiB:             assignment.Resources.DiskGiB,
				VolumeType:          "gp3",
				IOPS:                3000,
				ThroughputMiBPS:     125,
				KMSKeyID:            kmsAlias,
				Encrypted:           true,
				DeleteOnTermination: true,
			},
			WorkerImage: teamlaunch.WorkerImageV1{
				PublicationDigest:     "sha256:" + strings.Repeat("8", 64),
				AgentInstanceID:       agentInstanceID,
				AccountID:             plan.ProviderScope.AccountID,
				Region:                plan.Region,
				Architecture:          assignment.Resources.Arch,
				ImageID:               "ami-0123456789abcdef0",
				ImageDigest:           "sha256:" + strings.Repeat("9", 64),
				RootSnapshotID:        "snap-0123456789abcdef0",
				ReleaseManifestDigest: "sha256:" + strings.Repeat("a", 64),
				WorkerRootFSDigest:    "sha256:" + strings.Repeat("b", 64),
				WorkerBinaryDigest:    "sha256:" + strings.Repeat("c", 64),
				ObservedAt: issuedAt.
					Add(-time.Hour).
					UTC().
					Truncate(time.Microsecond),
			},
			MaximumApprovedCostMicros: maximumCost,
		})
	}
	authorization := teamlaunch.AuthorizationV1{
		SchemaVersion:   teamlaunch.SchemaV1,
		AuthorizationID: authorizationID,
		AgentInstanceID: agentInstanceID,
		OwnerID:         plan.OwnerID,
		PlanID:          plan.PlanID,
		PlanRevision:    plan.Revision,
		PlanDigest:      planDigest,
		ApprovalID:      approvalID,
		ProviderScope:   plan.ProviderScope,
		Region:          plan.Region,
		Network: teamlaunch.NetworkV1{
			ConnectivityMode:     teamlaunch.ConnectivityDirectPublicTLSV1,
			VPCID:                "vpc-0123456789abcdef0",
			SubnetID:             "subnet-0123456789abcdef0",
			AvailabilityZone:     plan.Region + "a",
			SecurityGroupMode:    teamlaunch.SecurityGroupDedicatedNoIngress,
			PublicIPv4:           true,
			ControlPlaneEndpoint: "grpcs://worker-control.demo2.dirextalk.ai:7443",
			Egress: []teamlaunch.EgressRuleV1{
				{
					Protocol: "tcp",
					FromPort: 443,
					ToPort:   443,
					CIDRv4:   "0.0.0.0/0",
				},
				{
					Protocol: "tcp",
					FromPort: 7443,
					ToPort:   7443,
					CIDRv4:   "0.0.0.0/0",
				},
				{
					Protocol: "udp",
					FromPort: 53,
					ToPort:   53,
					CIDRv4:   "169.254.169.253/32",
				},
			},
		},
		Retention: teamlaunch.RetentionV1{
			Class:                  teamlaunch.RetentionEphemeralAutoDestroy,
			AutoDestroy:            true,
			MaximumLifetimeSeconds: 2 * 60 * 60,
			DestroyGraceSeconds:    5 * 60,
		},
		WorkerCount:                  plan.WorkerCount,
		MaxConcurrentBillableWorkers: plan.MaxConcurrentWorkers,
		Currency:                     plan.Cost.Currency,
		HardBudgetMicros:             plan.Cost.HardBudgetMicros,
		RequiresFreshQuote:           true,
		MaximumQuoteAgeSeconds:       15 * 60,
		LaunchNotBefore:              issuedAt.UTC().Truncate(time.Microsecond),
		LaunchNotAfter:               plan.ValidUntil,
		Roles:                        roles,
	}
	if err := authorization.ValidateAgainst(plan); err != nil {
		return teamlaunch.AuthorizationV1{}, err
	}
	return authorization, nil
}

func orchestrationInputBinding(
	ownerID,
	taskID,
	goalDigest string,
) taskinput.BindingV2 {
	input, err := taskinput.NewEmptyInput(ownerID, taskID, goalDigest)
	if err != nil {
		panic(err)
	}
	binding, err := input.Binding()
	if err != nil {
		panic(err)
	}
	return binding
}

func orchestrationPolicyFixture() teamplan.Policy {
	return teamplan.Policy{
		MaxWorkers:                1,
		MaxConcurrentWorkers:      1,
		MaxRoleDuration:           3 * time.Minute,
		MaxVCPUPerWorker:          2,
		MaxMemoryMiBPerWorker:     8192,
		MaxDiskGiBPerWorker:       40,
		MaxPlanCostMicros:         1_000_000,
		SafetyMarginBasisPoints:   2000,
		FixedWorkerOverheadMicros: 10_000,
		AllowedRuntimeFamilies: []teamplan.RuntimeFamily{
			teamplan.RuntimeCodex,
		},
	}
}

func orchestrationProposalFixture() teamplan.TeamProposal {
	return teamplan.TeamProposal{
		Confidence: 90,
		Rationale:  "One isolated implementation Worker is sufficient.",
		Roles: []teamplan.RoleProposal{{
			RoleID:    "implementation",
			Title:     "Implementation",
			Objective: "Implement and verify the bounded change.",
			WorkClass: teamplan.WorkSoftwareImplementation,
			RequiredCapabilities: []teamplan.Capability{
				teamplan.CapabilityGit,
			},
			Workspace: teamplan.WorkspaceIsolated,
			Duration: teamplan.DurationEstimate{
				Minimum:  time.Minute,
				Expected: 2 * time.Minute,
				Maximum:  3 * time.Minute,
			},
			Tokens: teamplan.TokenEstimate{
				InputMinimum:   1_000,
				InputExpected:  2_000,
				InputMaximum:   3_000,
				OutputMinimum:  100,
				OutputExpected: 200,
				OutputMaximum:  300,
			},
			ModelNeed: teamplan.ModelNeed{
				MinimumQuality:       teamplan.QualityBalanced,
				MinimumContextTokens: 1024,
			},
			MinimumResources: teamplan.ResourceEnvelope{
				VCPU:      2,
				MemoryMiB: 8192,
				DiskGiB:   40,
				Arch:      recipe.ArchitectureAMD64,
			},
		}},
	}
}

func orchestrationOfferFixture(
	t *testing.T,
	now time.Time,
) *teamplan.OfferSnapshot {
	t.Helper()
	snapshot, err := teamplan.NewOfferSnapshot(
		teamplan.OfferSnapshotDocument{
			SchemaVersion: teamplan.OfferSnapshotSchemaV1,
			SnapshotID:    uuid.NewString(),
			ProviderScope: teamplan.ProviderScope{
				Provider:           teamplan.CloudProviderAWS,
				ConnectionID:       uuid.NewString(),
				ConnectionRevision: 1,
				AccountID:          "123456789012",
			},
			Region:     "us-east-1",
			Currency:   "USD",
			CapturedAt: now,
			ValidUntil: now.Add(teamplan.OfferSnapshotValidity),
			Sources: []teamplan.OfferSourceReceipt{
				{
					Kind:       teamplan.OfferSourceModelPricing,
					SourceID:   "model-pricing-test",
					Digest:     "sha256:" + strings.Repeat("1", 64),
					CapturedAt: now.Add(-time.Hour),
				},
				{
					Kind:       teamplan.OfferSourceComputePricing,
					SourceID:   "compute-pricing-test",
					Digest:     "sha256:" + strings.Repeat("2", 64),
					CapturedAt: now,
				},
				{
					Kind:       teamplan.OfferSourceComputeCapacity,
					SourceID:   "compute-capacity-test",
					Digest:     "sha256:" + strings.Repeat("3", 64),
					CapturedAt: now,
				},
				{
					Kind:       teamplan.OfferSourceComputeConfig,
					SourceID:   "agent-team-compute-catalog:us-east-1:v1",
					Digest:     "sha256:" + strings.Repeat("4", 64),
					CapturedAt: now,
				},
			},
			ModelOffers: []teamplan.ModelOffer{{
				ProfileID:              "model-balanced",
				Provider:               "openai",
				Model:                  "code-model",
				Interface:              teamplan.ModelOpenAIResponses,
				Quality:                teamplan.QualityBalanced,
				ContextTokens:          128_000,
				InputMicrosPerMillion:  1_000_000,
				OutputMicrosPerMillion: 2_000_000,
				CredentialRef:          "secret_ref:model/test",
				Enabled:                true,
				CredentialReady:        true,
			}},
			ComputeOffers: []teamplan.ComputeOffer{{
				OfferID:        uuid.NewString(),
				Region:         "us-east-1",
				InstanceType:   "m7i.large",
				Architecture:   recipe.ArchitectureAMD64,
				VCPU:           2,
				MemoryMiB:      8192,
				DiskGiB:        40,
				HourlyMicros:   3_600_000,
				PurchaseOption: "on_demand",
				CapacityPool:   "aws:ec2-quota:L-1216C47A",
				CapacityUnits:  2,
				AvailableUnits: 64,
				Available:      true,
			}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func orchestrationPlanFixture(
	request teamplan.CatalogCompileRequest,
	catalogRevision string,
) (teamplan.Plan, error) {
	policyRevision, err := request.Policy.Digest()
	if err != nil {
		return teamplan.Plan{}, err
	}
	document := request.Offers.Document()
	model := document.ModelOffers[0]
	compute := document.ComputeOffers[0]
	assignment := teamplan.WorkerAssignment{
		RoleID:    "implementation",
		Title:     "Implementation",
		Objective: "Implement and verify the bounded change.",
		WorkClass: teamplan.WorkSoftwareImplementation,
		RequiredCapabilities: []teamplan.Capability{
			teamplan.CapabilityGit,
		},
		Workspace:          teamplan.WorkspaceIsolated,
		RuntimeReleaseID:   uuid.NewSHA1(uuid.MustParse(request.PlanID), []byte("runtime")).String(),
		RuntimeFamily:      teamplan.RuntimeCodex,
		RuntimeVersion:     "1.0.0",
		RuntimeImageDigest: "sha256:" + strings.Repeat("a", 64),
		RuntimeAdapter:     teamplan.AdapterCodexV1,
		ModelProfileID:     model.ProfileID,
		ModelProvider:      model.Provider,
		Model:              model.Model,
		ModelInterface:     model.Interface,
		ModelCredentialRef: model.CredentialRef,
		ComputeOfferID:     compute.OfferID,
		InstanceType:       compute.InstanceType,
		Resources: teamplan.ResourceEnvelope{
			VCPU:      compute.VCPU,
			MemoryMiB: compute.MemoryMiB,
			DiskGiB:   compute.DiskGiB,
			Arch:      compute.Architecture,
		},
		Duration: teamplan.DurationEstimate{
			Minimum:  time.Minute,
			Expected: 2 * time.Minute,
			Maximum:  3 * time.Minute,
		},
		Tokens: teamplan.TokenEstimate{
			InputMinimum:   1_000,
			InputExpected:  2_000,
			InputMaximum:   3_000,
			OutputMinimum:  100,
			OutputExpected: 200,
			OutputMaximum:  300,
		},
	}
	plan := teamplan.Plan{
		SchemaVersion:         teamplan.SchemaV3,
		PlanID:                request.PlanID,
		Revision:              request.Revision,
		OwnerID:               request.OwnerID,
		GoalDigest:            request.GoalDigest,
		TaskInput:             request.TaskInput,
		ProviderScope:         document.ProviderScope,
		Region:                document.Region,
		CatalogRevision:       catalogRevision,
		PolicyRevision:        policyRevision,
		PricingSnapshotID:     request.Offers.SnapshotID(),
		PricingSnapshotDigest: request.Offers.Digest(),
		QuotedAt:              request.Offers.CapturedAt(),
		ValidUntil:            request.Offers.ValidUntil(),
		ProposalConfidence:    request.Proposal.Confidence,
		ProposalRationale:     request.Proposal.Rationale,
		WorkerCount:           1,
		MaxConcurrentWorkers:  1,
		Assignments:           []teamplan.WorkerAssignment{assignment},
		Schedule: teamplan.ScheduleEstimate{
			MinimumWallTime:  time.Minute,
			ExpectedWallTime: 2 * time.Minute,
			MaximumWallTime:  3 * time.Minute,
		},
		Cost: teamplan.CostEstimate{
			Currency:         "USD",
			MinimumMicros:    71_200,
			ExpectedMicros:   132_400,
			MaximumMicros:    193_600,
			HardBudgetMicros: 232_320,
			Roles: []teamplan.RoleCostEstimate{{
				RoleID:                assignment.RoleID,
				ComputeMinimumMicros:  60_000,
				ComputeExpectedMicros: 120_000,
				ComputeMaximumMicros:  180_000,
				ModelMinimumMicros:    1_200,
				ModelExpectedMicros:   2_400,
				ModelMaximumMicros:    3_600,
				TotalMinimumMicros:    71_200,
				TotalExpectedMicros:   132_400,
				TotalMaximumMicros:    193_600,
			}},
			Assumptions: []string{"on_demand_compute"},
			Exclusions:  []string{"third_party_paid_tools"},
		},
	}
	if err := plan.Validate(); err != nil {
		return teamplan.Plan{}, err
	}
	return plan, nil
}

var _ PlanCompiler = (*orchestrationCompilerFixture)(nil)
var _ PolicyResolver = (*orchestrationPolicyResolverFixture)(nil)
var _ Repository = (*orchestrationRepositoryFixture)(nil)
var _ TrustedOfferBuilder = (*orchestrationOfferBuilderFixture)(nil)
var _ TrustedOfferVerifier = (*orchestrationOfferVerifierFixture)(nil)
